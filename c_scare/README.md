# Module reference

The `c_scare` package. See the [project README](../README.md) for an overview and the [docs/](../docs) guides for usage.

| Module | Purpose |
|--------|---------|
| `element.py` | Dataset/Element building with Scapy-style `/` chaining |
| `corruptor.py` | pydicom bridge — read with pydicom, re-emit *invalid* with our encoder |
| `pixel.py` | Encapsulated pixel data with fragment-level control + Scapy layers |
| `file.py` | Part 10 file handling (preamble, meta header, transfer syntax via `pydicom.uid.UID`) |
| `scapy_dicom.py` | DICOM wire-format layer — declarative Scapy `Packet` definitions for PDUs/DIMSE-C/N plus builders and dissection helpers. The `Packet`/`Field` definitions are pure and upstreamable; the module also bundles the thin TCP transport primitives (`DICOMSocket`, `read_dul_pdu`) that frame a byte stream into PDUs |
| `client.py` | `DICOMSession` — stateful SCU client (association + DIMSE), delegating transport to `scapy_dicom`'s `DICOMSocket`; plus the A-ASSOCIATE-RJ recon helpers `classify_reject` / `reject_is_called_aet_unrecognized` |
| `server.py` | `RawSCP` rogue server for fuzzing clients (SCU) |
| `attacks.py` | Static attack catalog + seed generators — classes expose `all()` iterators of `AttackResult` |
| `workflows.py` | SCU-side attack workflows (issuer) — `ae_brute()`, `cred_brute()`, `build_query()`; query/retrieve flows (`c_find`/`c_get`/`c_move`) live on `DICOMSession` |
| `responders.py` | SCP-side workflow responders (exercise an SCU client) — `accept_association()`, DIMSE RSP builders, `WorkflowResponder` |
| `deliver.py` | Black-box delivery — `send_pdu()`, `send_sequence()`, `send_cstore()` (optional `user_identity=` to authenticate first) |
| `greybox.py` | Grey-box bridge — launches AFL++/AFLNet harnesses, triages crashes to SARIF |
| `monitor.py` | Crash/anomaly detection — sanitizer, protocol and process-health monitors |
| `runner.py` | CLI (`c-scare` / `python -m c_scare`) |
