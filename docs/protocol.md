# DICOM Protocol Structure Reference

This document provides byte-level structure of DICOM files and network PDUs for security researchers.

## Table of Contents

1. [C-SCARE Tool Mapping](#c-scare-tool-mapping)
2. [File Structure (Part 10)](#file-structure-part-10)
3. [Data Element Encoding](#data-element-encoding)
4. [Network PDU Structure](#network-pdu-structure)
5. [DIMSE Message Structure](#dimse-message-structure)
6. [State Machine Reference](#state-machine-reference)

---

## C-SCARE Tool Mapping

Each layer of the DICOM stack has corresponding C-SCARE modules for testing:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              C-Scare Framework                                      │
├──────────────────────────────────┬──────────────────────────────────────────────────┤
│         DICOM STACK              │              C-SCARE TOOLS                       │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Application Layer               │  attacks.py (LogicAttacks)                       │
│    IOD constraints               │    SOP class mismatch, transfer syntax mismatch  │
│    SOP Class semantics           │    SSRF via URI, file:// injection               │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Dataset Layer                   │  element.py    ─ Element.raw() byte control      │
│    Elements, Sequences, Values   │  corruptor.py  ─ pydicom surgical corruption     │
│    Part 10 Files, Pixel Data     │  file.py       ─ Part 10 file handling           │
│                                  │  pixel.py      ─ Encapsulated/fragment attacks   │
│                                  │  attacks.py (ParserAttacks, MemoryAttacks)       │
│                                  │    VR fuzzing, length overflow, sequence bombs   │
│                                  │    Buffer overflow, fragment bombs, LUT attacks  │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  DIMSE Layer                     │  scapy_dicom.py (DIMSE packets)                  │
│    C-STORE, C-FIND, C-ECHO       │    C_ECHO_RQ, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ   │
│    Command + Data                │    C_STORE_RQ_Fuzz ─ explicit group_length       │
│                                  │    fuzz() for automatic field mutation           │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  PDU Layer                       │  scapy_dicom.py (PDU packets)                    │
│    A-ASSOCIATE-RQ/AC/RJ          │    A_ASSOCIATE_RQ, A_ASSOCIATE_AC, A_ABORT       │
│    P-DATA-TF, A-RELEASE          │    P_DATA_TF, A_RELEASE_RQ/RP                    │
│    A-ABORT                       │  attacks.py (ProtocolAttacks, StateMachineAttacks)│
│                                  │    PDU malformation, AE title fuzzing            │
│                                  │    State violations (Sta1-Sta13)                 │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Transport Layer                 │  scapy_dicom.py (DICOMSocket)                    │
│    TCP segments                  │    Client with full Scapy integration            │
│                                  │  server.py (RawSCP)                              │
│                                  │    Rogue server for fuzzing DICOM clients        │
│                                  │    State machine hooks, response injection       │
│                                  │                                                  │
└──────────────────────────────────┴──────────────────────────────────────────────────┘
```

Quick reference for which tool to use:

| Target                          | Module              | Class / Function                        |
|---------------------------------|---------------------|-----------------------------------------|
| File preamble / meta header     | `file.py`           | `DicomFile`, `FileMetaInformation`       |
| Data element VR / length / value| `element.py`        | `Element.raw()`, `Dataset`              |
| Existing DICOM file corruption  | `corruptor.py`      | `Corruptor`                             |
| Encapsulated pixel data         | `pixel.py`          | `EncapsulatedPixelData`, `PixelFuzzer`  |
| Association negotiation         | `scapy_dicom.py`    | `A_ASSOCIATE_RQ`, `DICOMSocket`         |
| DIMSE commands                  | `scapy_dicom.py`    | `C_ECHO_RQ`, `C_STORE_RQ`, `N_GET_RQ`  |
| State machine violations        | `attacks.py`        | `StateMachineAttacks`                   |
| Client-side fuzzing             | `server.py`         | `RawSCP`                                |
| CVE reproductions               | `attacks.py`        | `CVEAttacks`                            |
| Corpus generation               | `attacks.py`        | `ParserAttacks.generate_corpus()`       |

---

## File Structure (Part 10)

DICOM files follow PS3.10 Media Storage format:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DICOM File Structure                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Preamble (128 bytes)                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │ 00 00 00 00 ... (128 bytes, typically zeros, application-specific)          ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────────┤
│  DICM Prefix (4 bytes)                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │ 44 49 43 4D  ("DICM" ASCII magic)                                           ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────────┤
│  File Meta Information (Group 0002) - ALWAYS Explicit VR Little Endian         │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │ (0002,0000) UL  File Meta Information Group Length                          ││
│  │ (0002,0001) OB  File Meta Information Version [00\01]                       ││
│  │ (0002,0002) UI  Media Storage SOP Class UID                                 ││
│  │ (0002,0003) UI  Media Storage SOP Instance UID                              ││
│  │ (0002,0010) UI  Transfer Syntax UID  ◄── CRITICAL: determines dataset enc.  ││
│  │ (0002,0012) UI  Implementation Class UID                                    ││
│  │ (0002,0013) SH  Implementation Version Name (optional)                      ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────────┤
│  Dataset (encoded per Transfer Syntax from 0002,0010)                           │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │ Data Element: Tag (4) + VR (0/2) + Length (2/4) + Value                     ││
│  │ Data Element: Tag (4) + VR (0/2) + Length (2/4) + Value                     ││
│  │ ...                                                                         ││
│  │ Sequence (SQ):                                                              ││
│  │   ├─ (FFFE,E000) Item delimiter                                             ││
│  │   │   └─ Nested Data Elements...                                            ││
│  │   │   └─ (FFFE,E00D) Item Delimitation Item                                 ││
│  │   └─ (FFFE,E000) Item delimiter                                             ││
│  │       └─ ...                                                                ││
│  │   └─ (FFFE,E0DD) Sequence Delimitation Item                                 ││
│  │                                                                             ││
│  │ Pixel Data (7FE0,0010):                                                     ││
│  │   Native: Raw pixel bytes                                                   ││
│  │   Encapsulated: Basic Offset Table + Fragments                              ││
│  │     ├─ (FFFE,E000) Basic Offset Table (can be empty)                        ││
│  │     ├─ (FFFE,E000) Fragment 1 (JPEG/JPEG2000/RLE frame)                     ││
│  │     ├─ (FFFE,E000) Fragment 2 ...                                           ││
│  │     └─ (FFFE,E0DD) Sequence Delimitation Item                               ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘

Attack Surface:
  ► Preamble: Executable code injection (some viewers execute)
  ► DICM prefix: Remove/corrupt to test magic validation
  ► Transfer Syntax: Mismatch declared vs actual encoding
  ► Group Length: Lie about meta header size
  ► Dataset encoding: Corrupt VR, length fields
  
Tool: file.py (DicomFile), corruptor.py (Corruptor)
```

---

## Data Element Encoding

### Explicit VR (most common)

```
Standard VRs (AE, AS, AT, CS, DA, DS, DT, FL, FD, IS, LO, LT, PN, SH, SL, SS, ST, TM, UI, UL, US):
┌──────────┬──────────┬──────────┬──────────────────────────────────────────────┐
│ Tag      │ VR       │ Length   │ Value                                        │
│ 4 bytes  │ 2 bytes  │ 2 bytes  │ Length bytes                                 │
│ LE       │ ASCII    │ LE uint16│                                              │
├──────────┼──────────┼──────────┼──────────────────────────────────────────────┤
│ 10 00    │ 50 4E    │ 08 00    │ 44 6F 65 5E 4A 6F 68 6E                      │
│ 10 00    │ "PN"     │ 8        │ "Doe^John"                                   │
│ (0010,   │          │          │                                              │
│  0010)   │          │          │                                              │
└──────────┴──────────┴──────────┴──────────────────────────────────────────────┘

Long VRs (OB, OD, OF, OL, OW, SQ, UC, UN, UR, UT):
┌──────────┬──────────┬──────────┬──────────┬───────────────────────────────────┐
│ Tag      │ VR       │ Reserved │ Length   │ Value                             │
│ 4 bytes  │ 2 bytes  │ 2 bytes  │ 4 bytes  │ Length bytes                      │
│ LE       │ ASCII    │ 00 00    │ LE uint32│                                   │
├──────────┼──────────┼──────────┼──────────┼───────────────────────────────────┤
│ E0 7F    │ 4F 57    │ 00 00    │ FF FF    │ ... pixel data ...                │
│ 10 00    │ "OW"     │          │ FF FF    │                                   │
│ (7FE0,   │          │          │ (undef)  │                                   │
│  0010)   │          │          │          │                                   │
└──────────┴──────────┴──────────┴──────────┴───────────────────────────────────┘

Undefined Length = 0xFFFFFFFF (must use delimitation items)
```

### Implicit VR Little Endian

```
All elements (VR looked up from data dictionary):
┌──────────┬──────────┬──────────────────────────────────────────────────────────┐
│ Tag      │ Length   │ Value                                                    │
│ 4 bytes  │ 4 bytes  │ Length bytes                                             │
│ LE       │ LE uint32│                                                          │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 10 00    │ 08 00    │ 44 6F 65 5E 4A 6F 68 6E                                  │
│ 10 00    │ 00 00    │ "Doe^John"                                               │
│ (0010,   │ 8        │                                                          │
│  0010)   │          │                                                          │
└──────────┴──────────┴──────────────────────────────────────────────────────────┘

Attack Surface:
  ► VR field: Invalid VR codes ('XX', 'ZZ', null bytes)
  ► Length field: Overflow (0xFFFFFFFF with data), underflow (1 with 1000 bytes)
  ► Value: Format violations, null injection, buffer overflow attempts
  ► Tag order: Out-of-order tags, duplicate tags
  ► Private tags: Missing private creator

Tool: element.py (Element.raw()), corruptor.py (set_vr, set_length)
```

---

## Network PDU Structure

### A-ASSOCIATE-RQ (Type 0x01)

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                            A-ASSOCIATE-RQ PDU                                  │
├──────────┬──────────┬──────────────────────────────────────────────────────────┤
│ Offset   │ Size     │ Field                                                    │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 0        │ 1        │ PDU Type = 0x01                                          │
│ 1        │ 1        │ Reserved = 0x00                                          │
│ 2        │ 4        │ PDU Length (big-endian, excludes first 6 bytes)          │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 6        │ 2        │ Protocol Version = 0x0001                                │
│ 8        │ 2        │ Reserved = 0x0000                                        │
│ 10       │ 16       │ Called AE Title (space-padded)                           │
│ 26       │ 16       │ Calling AE Title (space-padded)                          │
│ 42       │ 32       │ Reserved (zeros)                                         │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 74       │ var      │ Variable Items:                                          │
│          │          │   ├─ Application Context Item (0x10)                     │
│          │          │   ├─ Presentation Context Items (0x20)                   │
│          │          │   │    ├─ Abstract Syntax (0x30)                         │
│          │          │   │    └─ Transfer Syntax(es) (0x40)                     │
│          │          │   └─ User Information Item (0x50)                        │
│          │          │        ├─ Max Length (0x51)                              │
│          │          │        ├─ Implementation Class UID (0x52)                │
│          │          │        └─ Implementation Version (0x55)                  │
└──────────┴──────────┴──────────────────────────────────────────────────────────┘

Attack Surface:
  ► Protocol Version: 0xFFFF, 0x0000
  ► PDU Length: Mismatch with actual data
  ► AE Titles: Overflow, null bytes, special characters
  ► Max Length: 0, 0xFFFFFFFF
  ► Nested items: Missing, duplicate, wrong order

Tool: pdu.py (AssociateRQ), attacks.py (ProtocolAttacks)
```

### P-DATA-TF (Type 0x04) - Data Transfer

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                              P-DATA-TF PDU                                     │
├──────────┬──────────┬──────────────────────────────────────────────────────────┤
│ Offset   │ Size     │ Field                                                    │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 0        │ 1        │ PDU Type = 0x04                                          │
│ 1        │ 1        │ Reserved = 0x00                                          │
│ 2        │ 4        │ PDU Length (big-endian)                                  │
├──────────┼──────────┼──────────────────────────────────────────────────────────┤
│ 6        │ var      │ Presentation Data Value Items:                           │
│          │          │   ┌──────────────────────────────────────────────────┐   │
│          │          │   │ Item Length (4 bytes, big-endian)                │   │
│          │          │   │ Presentation Context ID (1 byte, odd 1-255)      │   │
│          │          │   │ Message Control Header (1 byte):                 │   │
│          │          │   │   Bit 0: 0=Command, 1=Data                       │   │
│          │          │   │   Bit 1: 0=More fragments, 1=Last fragment       │   │
│          │          │   │ Presentation Data Fragment (Item Length - 2)     │   │
│          │          │   └──────────────────────────────────────────────────┘   │
│          │          │   (repeat for multiple PDV items)                        │
└──────────┴──────────┴──────────────────────────────────────────────────────────┘

Message Control Header values:
  0x00 = Command, not last
  0x01 = Data, not last
  0x02 = Command, last fragment
  0x03 = Data, last fragment

Attack Surface:
  ► Context ID: Even numbers (invalid), 0, mismatched with association
  ► Fragmentation: Incomplete command, orphan data fragments
  ► Item Length: Mismatch, overflow

Tool: pdu.py (PDataTF, PDataItem), dimse.py
```

### Other PDU Types

```
┌────────┬──────────────────────────────────────────────────────────────────────┐
│ Type   │ PDU Name                                                             │
├────────┼──────────────────────────────────────────────────────────────────────┤
│ 0x01   │ A-ASSOCIATE-RQ    (Association Request)                              │
│ 0x02   │ A-ASSOCIATE-AC    (Association Accept)                               │
│ 0x03   │ A-ASSOCIATE-RJ    (Association Reject)                               │
│ 0x04   │ P-DATA-TF         (Data Transfer)                                    │
│ 0x05   │ A-RELEASE-RQ      (Release Request)                                  │
│ 0x06   │ A-RELEASE-RP      (Release Response)                                 │
│ 0x07   │ A-ABORT           (Abort)                                            │
└────────┴──────────────────────────────────────────────────────────────────────┘

A-ABORT Structure (simplest):
┌──────────┬──────────┬──────────────────────────────────────────────────────────┐
│ 0        │ 1        │ PDU Type = 0x07                                          │
│ 1        │ 1        │ Reserved = 0x00                                          │
│ 2        │ 4        │ PDU Length = 0x00000004                                  │
│ 6        │ 1        │ Reserved = 0x00                                          │
│ 7        │ 1        │ Reserved = 0x00                                          │
│ 8        │ 1        │ Source (0=UL service user, 1=reserved, 2=UL provider)   │
│ 9        │ 1        │ Reason/Diag (0-6 depending on source)                    │
└──────────┴──────────┴──────────────────────────────────────────────────────────┘

Tool: pdu.py (Abort, ReleaseRQ, ReleaseRP, AssociateRJ)
```

---

## DIMSE Message Structure

DIMSE messages are encoded as DICOM datasets inside P-DATA-TF:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           DIMSE Command Set                                    │
│                   (Implicit VR Little Endian, always)                          │
├────────────────────────────────────────────────────────────────────────────────┤
│  (0000,0000) UL  CommandGroupLength                                            │
│  (0000,0002) UI  Affected/Requested SOP Class UID                              │
│  (0000,0100) US  CommandField (type of operation)                              │
│  (0000,0110) US  MessageID                                                     │
│  (0000,0120) US  MessageIDBeingRespondedTo (responses only)                    │
│  (0000,0800) US  CommandDataSetType (0x0101=none, else=present)                │
│  (0000,0900) US  Status (responses only)                                       │
│  (0000,1000) UI  Affected SOP Instance UID                                     │
│  (0000,0700) US  Priority (0=medium, 1=high, 2=low)                            │
│  ...plus service-specific tags...                                              │
└────────────────────────────────────────────────────────────────────────────────┘

Command Field Values (0000,0100):
┌────────┬──────────────────────────────────────────────────────────────────────┐
│ Value  │ Command                                                              │
├────────┼──────────────────────────────────────────────────────────────────────┤
│ 0x0001 │ C-STORE-RQ                                                           │
│ 0x8001 │ C-STORE-RSP                                                          │
│ 0x0010 │ C-GET-RQ                                                             │
│ 0x8010 │ C-GET-RSP                                                            │
│ 0x0020 │ C-FIND-RQ                                                            │
│ 0x8020 │ C-FIND-RSP                                                           │
│ 0x0021 │ C-MOVE-RQ                                                            │
│ 0x8021 │ C-MOVE-RSP                                                           │
│ 0x0030 │ C-ECHO-RQ                                                            │
│ 0x8030 │ C-ECHO-RSP                                                           │
│ 0x0100 │ N-EVENT-REPORT-RQ                                                    │
│ 0x8100 │ N-EVENT-REPORT-RSP                                                   │
│ 0x0110 │ N-GET-RQ                                                             │
│ 0x8110 │ N-GET-RSP                                                            │
│ 0x0120 │ N-SET-RQ                                                             │
│ 0x8120 │ N-SET-RSP                                                            │
│ 0x0130 │ N-ACTION-RQ                                                          │
│ 0x8130 │ N-ACTION-RSP                                                         │
│ 0x0140 │ N-CREATE-RQ                                                          │
│ 0x8140 │ N-CREATE-RSP                                                         │
│ 0x0150 │ N-DELETE-RQ                                                          │
│ 0x8150 │ N-DELETE-RSP                                                         │
│ 0x0FFF │ C-CANCEL-RQ                                                          │
└────────┴──────────────────────────────────────────────────────────────────────┘

Attack Surface:
  ► CommandGroupLength: Mismatch with actual size
  ► CommandField: Unknown values, N-* commands to C-* servers
  ► MessageID: Duplicate, 0, 0xFFFF
  ► Status: Invalid status codes
  ► Priority: Invalid values (3+)
  ► SOP Class/Instance UID: Mismatch with association

Tool: dimse.py (CEchoRQ, CStoreRQ, etc.)
```

### C-STORE Message Flow

```
SCU                                              SCP
 │                                                │
 │  ──────── A-ASSOCIATE-RQ ────────────────────► │  (Sta1→Sta5)
 │  ◄─────── A-ASSOCIATE-AC ──────────────────── │  (Sta5→Sta6)
 │                                                │
 │  ──────── P-DATA-TF [C-STORE-RQ Command] ───► │  (Sta6)
 │  ──────── P-DATA-TF [C-STORE-RQ Data] ──────► │  (Sta6)
 │  ◄─────── P-DATA-TF [C-STORE-RSP Command] ─── │  (Sta6)
 │                                                │
 │  ──────── A-RELEASE-RQ ─────────────────────► │  (Sta6→Sta7)
 │  ◄─────── A-RELEASE-RP ──────────────────────│  (Sta7→Sta1)
 │                                                │

Attack Points:
  ► Send C-STORE-RQ before A-ASSOCIATE completes
  ► Send data before command
  ► Send to wrong presentation context
  ► Never send data after command
  ► Send more data after last fragment

Tool: attacks.py (StateMachineAttacks)
```

---

## State Machine Reference

DICOM Upper Layer State Machine (PS3.8 Chapter 9):

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DICOM State Machine                                     │
├──────────┬──────────────────────────────────────────────────────────────────────┤
│ State    │ Description                                                          │
├──────────┼──────────────────────────────────────────────────────────────────────┤
│ Sta1     │ Idle (no connection)                                                 │
│ Sta2     │ Transport connection open, awaiting A-ASSOCIATE-RQ (server)          │
│ Sta3     │ Awaiting local A-ASSOCIATE response (server deciding)                │
│ Sta4     │ Awaiting transport connection to complete (client connecting)        │
│ Sta5     │ Awaiting A-ASSOCIATE-AC/RJ (client)                                  │
│ Sta6     │ Association established - data transfer ready                        │
│ Sta7     │ Awaiting A-RELEASE-RP (requestor)                                    │
│ Sta8     │ Awaiting local A-RELEASE response                                    │
│ Sta9     │ Release collision - requestor side                                   │
│ Sta10    │ Release collision - acceptor side                                    │
│ Sta11    │ Release collision - requestor waiting                                │
│ Sta12    │ Release collision - acceptor waiting                                 │
│ Sta13    │ Awaiting transport close (after A-ABORT)                             │
└──────────┴──────────────────────────────────────────────────────────────────────┘

Valid PDU per State (simplified):
┌──────────┬───────────────────────────────────────────────────────────────────────┐
│ State    │ Valid Incoming PDUs                                                   │
├──────────┼───────────────────────────────────────────────────────────────────────┤
│ Sta1     │ (none - waiting for connection)                                       │
│ Sta2     │ A-ASSOCIATE-RQ only                                                   │
│ Sta5     │ A-ASSOCIATE-AC, A-ASSOCIATE-RJ only                                   │
│ Sta6     │ P-DATA-TF, A-RELEASE-RQ, A-ABORT                                      │
│ Sta7     │ A-RELEASE-RP, P-DATA-TF, A-ABORT                                      │
└──────────┴───────────────────────────────────────────────────────────────────────┘

State Machine Attacks:
  ► P-DATA-TF in Sta2 (before association accepted)
  ► A-ASSOCIATE-RQ in Sta6 (double association)
  ► P-DATA-TF in Sta7 (after release request)
  ► A-RELEASE-RQ in Sta2 (before association)

Tool: server.py (ConnectionState enum), attacks.py (StateMachineAttacks)
```

---

## Scapy Layer Quick Reference

The included Scapy layer (`scapy_dicom.py`) provides packet definitions for all structures above:

```python
from scapy.all import *
from dicom_hacker import install_scapy_layer

# Install layer (one-time)
install_scapy_layer()

# Import DICOM layer
from scapy.contrib.dicom import *

# Build packets with Scapy syntax
pdu = A_ASSOCIATE_RQ(
    called_ae="TARGET          ",
    calling_ae="ATTACKER        ",
    contexts=[
        PresentationContext(
            id=1,
            abstract_syntax=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            transfer_syntaxes=[DEFAULT_TRANSFER_SYNTAX_UID],
        )
    ],
)

# View packet structure
pdu.show()

# Get raw bytes
raw(pdu)

# Dissect captured traffic
pkts = rdpcap("dicom_capture.pcap")
for pkt in pkts:
    if DICOM in pkt:
        pkt[DICOM].show()
```

---

## Common Transfer Syntax UIDs

```
┌────────────────────────────────────────────┬─────────────────────────────────────┐
│ UID                                        │ Description                         │
├────────────────────────────────────────────┼─────────────────────────────────────┤
│ 1.2.840.10008.1.2                          │ Implicit VR Little Endian (default) │
│ 1.2.840.10008.1.2.1                        │ Explicit VR Little Endian           │
│ 1.2.840.10008.1.2.2                        │ Explicit VR Big Endian (retired)    │
│ 1.2.840.10008.1.2.4.50                     │ JPEG Baseline                       │
│ 1.2.840.10008.1.2.4.51                     │ JPEG Extended                       │
│ 1.2.840.10008.1.2.4.57                     │ JPEG Lossless                       │
│ 1.2.840.10008.1.2.4.70                     │ JPEG Lossless SV1                   │
│ 1.2.840.10008.1.2.4.80                     │ JPEG-LS Lossless                    │
│ 1.2.840.10008.1.2.4.81                     │ JPEG-LS Near Lossless               │
│ 1.2.840.10008.1.2.4.90                     │ JPEG 2000 Lossless                  │
│ 1.2.840.10008.1.2.4.91                     │ JPEG 2000 Lossy                     │
│ 1.2.840.10008.1.2.5                        │ RLE Lossless                        │
│ 1.2.840.10008.1.2.1.99                     │ Deflated Explicit VR LE             │
└────────────────────────────────────────────┴─────────────────────────────────────┘

Attack: Declare one transfer syntax, encode with another.
Tool: file.py (TransferSyntax), attacks.py (LogicAttacks.transfer_syntax_mismatch)
```

---

## Common SOP Class UIDs

```
┌────────────────────────────────────────────┬─────────────────────────────────────┐
│ UID                                        │ Description                         │
├────────────────────────────────────────────┼─────────────────────────────────────┤
│ 1.2.840.10008.1.1                          │ Verification (C-ECHO)               │
│ 1.2.840.10008.5.1.4.1.1.2                  │ CT Image Storage                    │
│ 1.2.840.10008.5.1.4.1.1.4                  │ MR Image Storage                    │
│ 1.2.840.10008.5.1.4.1.1.7                  │ Secondary Capture                   │
│ 1.2.840.10008.5.1.4.1.1.88.11             │ Basic Text SR                       │
│ 1.2.840.10008.5.1.4.1.1.88.22             │ Enhanced SR                         │
│ 1.2.840.10008.5.1.4.1.2.1.1               │ Patient Root Q/R Find               │
│ 1.2.840.10008.5.1.4.1.2.1.2               │ Patient Root Q/R Move               │
│ 1.2.840.10008.5.1.4.1.2.2.1               │ Study Root Q/R Find                 │
│ 1.2.840.10008.5.1.4.1.2.2.2               │ Study Root Q/R Move                 │
│ 1.2.840.10008.5.1.4.32.1                  │ Modality Worklist Find              │
└────────────────────────────────────────────┴─────────────────────────────────────┘

Attack: Send CT data with MR SOP Class, query with Store SOP Class.
Tool: attacks.py (LogicAttacks.sop_class_mismatch)
```