# SPDX-License-Identifier: GPL-2.0-only
"""
Raw DICOM SCP (server) with socket-level control.

Rogue DICOM server for fuzzing clients. You control exactly what bytes get sent.

Example:
    from c_scare import RawSCP, ConnectionState
    from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ABORT
    from scapy.packet import raw
    
    scp = RawSCP(port=11112)
    
    @scp.on_associate_rq
    def handle_assoc(conn, pdu_bytes, pkt):
        # pkt is Scapy DICOM packet (or None if parse failed)
        # Return bytes to send, or None for no response
        ac = DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF)  # Malformed!
        return raw(ac)
    
    @scp.on_pdata
    def handle_pdata(conn, pdu_bytes, pkt):
        conn.inject(raw(DICOM() / A_ABORT()))  # Inject abort
        return None
    
    @scp.on_state(ConnectionState.ASSOCIATED)
    def on_sta6(conn):
        print(f"Sta6: {conn.address}")
    
    scp.start()
"""

import socket
import struct
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Union

__all__ = [
    'RawSCP',
    'ConnectionState', 
    'Connection',
]


class ConnectionState(Enum):
    """
    DICOM Upper Layer State Machine states (PS3.8 Section 9.2.1).
    
    Sta1  - Idle
    Sta2  - Transport open, awaiting A-ASSOCIATE-RQ
    Sta3  - Awaiting local A-ASSOCIATE response
    Sta6  - Association established
    Sta7  - Awaiting A-RELEASE-RP
    Sta13 - Awaiting transport close
    """
    IDLE = auto()                    # Sta1
    AWAITING_ASSOC = auto()          # Sta2
    AWAITING_ASSOC_RESPONSE = auto() # Sta3
    ASSOCIATED = auto()              # Sta6
    AWAITING_RELEASE = auto()        # Sta7-8
    RELEASE_COLLISION = auto()       # Sta9-12
    AWAITING_CLOSE = auto()          # Sta13
    CLOSED = auto()
    
    @property
    def sta_number(self) -> int:
        """Get DICOM State Machine number."""
        return {
            ConnectionState.IDLE: 1,
            ConnectionState.AWAITING_ASSOC: 2,
            ConnectionState.AWAITING_ASSOC_RESPONSE: 3,
            ConnectionState.ASSOCIATED: 6,
            ConnectionState.AWAITING_RELEASE: 7,
            ConnectionState.RELEASE_COLLISION: 9,
            ConnectionState.AWAITING_CLOSE: 13,
            ConnectionState.CLOSED: 1,
        }.get(self, 0)


@dataclass
class Connection:
    """Represents a client connection."""
    socket: socket.socket
    address: tuple
    state: ConnectionState = ConnectionState.AWAITING_ASSOC
    called_ae: str = ''
    calling_ae: str = ''
    
    def send(self, data: bytes):
        """Send raw bytes."""
        self.socket.sendall(data)
    
    def inject(self, data: bytes):
        """Inject bytes (alias for send)."""
        self.send(data)
    
    def close(self):
        """Close connection."""
        try:
            self.socket.close()
        except Exception:
            pass
        self.state = ConnectionState.CLOSED


# PDU types
PDU_ASSOCIATE_RQ = 0x01
PDU_ASSOCIATE_AC = 0x02
PDU_ASSOCIATE_RJ = 0x03
PDU_P_DATA_TF = 0x04
PDU_RELEASE_RQ = 0x05
PDU_RELEASE_RP = 0x06
PDU_ABORT = 0x07


def _try_parse_scapy(pdu_bytes: bytes):
    """Try to parse PDU with Scapy. Returns packet or None."""
    try:
        from .scapy_dicom import DICOM
        return DICOM(pdu_bytes)
    except Exception:
        return None


class RawSCP:
    """
    Raw DICOM SCP - rogue server for fuzzing clients.
    
    You control exactly what bytes are sent in response to any PDU.
    
    Handlers receive:
        conn: Connection object
        pdu_bytes: Raw PDU bytes
        pkt: Scapy packet (or None if parse failed)
    
    Handlers return:
        bytes: Send these bytes
        None: Don't send anything
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 11112,
                 ae_title: str = 'C_SCARE'):
        self.host = host
        self.port = port
        self.ae_title = ae_title
        
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._connections: List[Connection] = []
        
        # PDU handlers: func(conn, pdu_bytes, pkt) -> bytes | None
        self._handlers: Dict[int, Callable] = {}
        
        # State hooks: func(conn) -> bytes | None
        self._state_hooks: Dict[ConnectionState, List[Callable]] = {
            s: [] for s in ConnectionState
        }
        
        # Special handlers
        self._on_connect: Optional[Callable] = None
        self._on_disconnect: Optional[Callable] = None
        self._on_any: Optional[Callable] = None
        self._on_raw: Optional[Callable] = None
    
    # =========================================================================
    # Handler decorators
    # =========================================================================
    
    def on_connect(self, func):
        """Called when client connects. func(conn)"""
        self._on_connect = func
        return func
    
    def on_disconnect(self, func):
        """Called when client disconnects. func(conn)"""
        self._on_disconnect = func
        return func
    
    def on_associate_rq(self, func):
        """Handle A-ASSOCIATE-RQ. func(conn, pdu_bytes, pkt) -> bytes | None"""
        self._handlers[PDU_ASSOCIATE_RQ] = func
        return func
    
    def on_pdata(self, func):
        """Handle P-DATA-TF. func(conn, pdu_bytes, pkt) -> bytes | None"""
        self._handlers[PDU_P_DATA_TF] = func
        return func
    
    def on_release_rq(self, func):
        """Handle A-RELEASE-RQ. func(conn, pdu_bytes, pkt) -> bytes | None"""
        self._handlers[PDU_RELEASE_RQ] = func
        return func
    
    def on_abort(self, func):
        """Handle A-ABORT. func(conn, pdu_bytes, pkt) -> None"""
        self._handlers[PDU_ABORT] = func
        return func
    
    def on_any(self, func):
        """Called for any PDU. func(conn, pdu_type, pdu_bytes, pkt) -> bytes | None"""
        self._on_any = func
        return func
    
    def on_raw(self, func):
        """Called before parsing. func(conn, pdu_bytes) -> bytes | None"""
        self._on_raw = func
        return func
    
    def on_state(self, state: ConnectionState):
        """
        Called when entering state.
        
        @scp.on_state(ConnectionState.ASSOCIATED)
        def on_sta6(conn):
            return optional_bytes_to_send
        """
        def decorator(func):
            self._state_hooks[state].append(func)
            return func
        return decorator
    
    def handler(self, pdu_type: int):
        """
        Generic handler decorator.
        
        @scp.handler(0x01)  # A-ASSOCIATE-RQ
        def handle(conn, pdu_bytes, pkt):
            return response_bytes
        """
        def decorator(func):
            self._handlers[pdu_type] = func
            return func
        return decorator
    
    # =========================================================================
    # Server lifecycle
    # =========================================================================
    
    def start(self, blocking: bool = True):
        """Start server. Returns thread if blocking=False."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._running = True
        
        print(f"[RawSCP] Listening on {self.host}:{self.port}")
        
        if blocking:
            self._accept_loop()
        else:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
            return t
    
    def stop(self):
        """Stop server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        for conn in self._connections:
            conn.close()
        self._connections.clear()
    
    def _accept_loop(self):
        """Accept connections."""
        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                client_sock, addr = self._server_socket.accept()
                
                conn = Connection(socket=client_sock, address=addr)
                self._connections.append(conn)
                
                if self._on_connect:
                    self._on_connect(conn)
                
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True
                )
                t.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[RawSCP] Accept error: {e}")
    
    def _handle_connection(self, conn: Connection):
        """Handle single connection."""
        try:
            while conn.state != ConnectionState.CLOSED:
                pdu_bytes = self._recv_pdu(conn)
                if not pdu_bytes:
                    break
                
                # Raw handler (before parse)
                if self._on_raw:
                    result = self._on_raw(conn, pdu_bytes)
                    if result is not None:
                        conn.send(result)
                        continue
                
                # Parse with Scapy
                pkt = _try_parse_scapy(pdu_bytes)
                pdu_type = pdu_bytes[0] if pdu_bytes else 0
                
                # Update state machine
                self._update_state_for_pdu(conn, pdu_type, pdu_bytes)
                
                # Call specific handler
                response = None
                if pdu_type in self._handlers:
                    response = self._handlers[pdu_type](conn, pdu_bytes, pkt)
                
                # Call on_any
                if self._on_any:
                    any_resp = self._on_any(conn, pdu_type, pdu_bytes, pkt)
                    if any_resp is not None:
                        response = any_resp
                
                # Send response
                if response is not None:
                    conn.send(response)
                
        except Exception as e:
            print(f"[RawSCP] Error: {e}")
        finally:
            if self._on_disconnect:
                self._on_disconnect(conn)
            conn.close()
            if conn in self._connections:
                self._connections.remove(conn)
    
    def _recv_pdu(self, conn: Connection) -> bytes:
        """Receive complete PDU."""
        try:
            conn.socket.settimeout(30.0)
            
            # Read 6-byte header
            header = b''
            while len(header) < 6:
                chunk = conn.socket.recv(6 - len(header))
                if not chunk:
                    return b''
                header += chunk
            
            pdu_length = struct.unpack('!I', header[2:6])[0]
            
            # Read body
            body = b''
            while len(body) < pdu_length:
                chunk = conn.socket.recv(min(65536, pdu_length - len(body)))
                if not chunk:
                    break
                body += chunk
            
            return header + body
            
        except socket.timeout:
            return b''
        except Exception:
            return b''
    
    def _update_state_for_pdu(self, conn: Connection, pdu_type: int, pdu_bytes: bytes):
        """Update state machine based on PDU."""
        old_state = conn.state
        new_state = old_state
        
        if pdu_type == PDU_ASSOCIATE_RQ:
            new_state = ConnectionState.AWAITING_ASSOC_RESPONSE
            # Extract AE titles
            if len(pdu_bytes) > 42:
                conn.called_ae = pdu_bytes[10:26].decode('ascii', errors='replace').strip()
                conn.calling_ae = pdu_bytes[26:42].decode('ascii', errors='replace').strip()
        
        elif pdu_type == PDU_ASSOCIATE_AC:
            new_state = ConnectionState.ASSOCIATED
        
        elif pdu_type == PDU_ASSOCIATE_RJ:
            new_state = ConnectionState.CLOSED
        
        elif pdu_type == PDU_RELEASE_RQ:
            new_state = ConnectionState.AWAITING_RELEASE
        
        elif pdu_type == PDU_RELEASE_RP:
            new_state = ConnectionState.CLOSED
        
        elif pdu_type == PDU_ABORT:
            new_state = ConnectionState.CLOSED
        
        if new_state != old_state:
            conn.state = new_state
            self._fire_state_hooks(conn, new_state)
    
    def _fire_state_hooks(self, conn: Connection, state: ConnectionState):
        """Fire state transition hooks."""
        for hook in self._state_hooks.get(state, []):
            try:
                result = hook(conn)
                if result is not None:
                    conn.send(result)
            except Exception as e:
                print(f"[RawSCP] State hook error: {e}")
    
    def transition_to(self, conn: Connection, state: ConnectionState):
        """Manually transition connection state (for testing)."""
        conn.state = state
        self._fire_state_hooks(conn, state)
