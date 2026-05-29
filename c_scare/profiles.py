# SPDX-License-Identifier: GPL-2.0-only
"""Declarative per-target grey-box fuzzing profiles.

A grey-box target (``file``, ``parse``, ``net-storescp``, ``net-dcmrecv``,
``net-dcmqrscp``, ``scu``) used to be defined in four hardcoding sites that had
to be edited in lock-step: ``greybox.TARGETS`` / ``NET_TARGETS``, the
``scripts/campaign.sh`` case statements, the per-target ``scripts/fuzz_*.sh``
harnesses, and the seed generators (``fuzz/harness/seed_serializer.py`` /
``gen_file_seeds.py``). This module makes a single ``fuzz/targets/<name>.yaml``
profile the source of truth, consumed by Python (here) and by bash (via
``scripts/profile_lib.sh``).

The DICOM identity fields are *wired into the fuzzer*, not inert metadata: a
profile's AE titles, presentation-context abstract syntaxes (SOP classes) and
transfer syntaxes flow into the A-ASSOCIATE-RQ / P-DATA-TF bytes the network
seed serializer emits (and AFLNet then mutates/replays), into the DICOM file
seeds AFL mutates, and into the rendered ``dcmqrscp.cfg``.

UID fields accept either a symbolic name resolved against a namespace
(``VERIFICATION_SOP_CLASS_UID`` against ``c_scare``; ``ExplicitVRLittleEndian``
against ``pydicom.uid``) or a raw dotted-decimal UID passed through verbatim.
"""
import glob
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

__all__ = [
    'PROFILES_DIR', 'Flow', 'Profile',
    'load_profile', 'load_profiles', 'iter_profiles',
    'resolve_cscare_uid', 'resolve_pydicom_uid', 'subst',
]

# Runtime placeholder tokens left in argv / triage server argv for the consumer
# to substitute (the harness/campaign use the declared port; Python triage uses
# a freshly allocated port). ``{{REPO_ROOT}}`` is expanded at load time.
_RUNTIME_TOKENS = ('{{PORT}}', '{{WORKDIR}}', '{{CONFIG}}',
                   '{{STORAGE}}', '{{SENDFILE}}')

_UID_RE = re.compile(r'^\d+(\.\d+)+$')


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


PROFILES_DIR = os.path.join(_repo_root(), 'fuzz', 'targets')


def resolve_cscare_uid(value: Optional[str]) -> Optional[str]:
    """Resolve a SOP-class / transfer-syntax UID against the ``c_scare`` package.

    A raw dotted-decimal UID is returned unchanged; a symbolic name (e.g.
    ``VERIFICATION_SOP_CLASS_UID``) is looked up as a ``c_scare`` attribute.
    """
    if value is None:
        return None
    s = str(value)
    if _UID_RE.match(s):
        return s
    import c_scare
    resolved = getattr(c_scare, s, None)
    if resolved is None:
        raise ValueError(f'unknown c_scare UID symbol {s!r}')
    return str(resolved)


def resolve_pydicom_uid(value: Optional[str]):
    """Resolve a transfer-syntax / SOP-class UID against ``pydicom.uid``.

    Returns a ``pydicom.uid.UID`` so callers get the exact object the seed
    generators used before profiles existed (keeping generated files
    byte-identical). A raw dotted-decimal UID is wrapped in ``UID``.
    """
    if value is None:
        return None
    from pydicom import uid as pydicom_uid
    s = str(value)
    if _UID_RE.match(s):
        return pydicom_uid.UID(s)
    resolved = getattr(pydicom_uid, s, None)
    if resolved is None:
        raise ValueError(f'unknown pydicom.uid symbol {s!r}')
    return resolved


def subst(value, repo=None, port=None, workdir=None, config=None,
          storage=None, sendfile=None):
    """Expand placeholder tokens in a string (non-strings pass through)."""
    if not isinstance(value, str):
        return value
    repls = {
        '{{REPO_ROOT}}': repo if repo is not None else _repo_root(),
        '{{PORT}}': '' if port is None else str(port),
        '{{WORKDIR}}': workdir or '',
        '{{CONFIG}}': config or '',
        '{{STORAGE}}': storage or '',
        '{{SENDFILE}}': sendfile or '',
    }
    for tok, rep in repls.items():
        value = value.replace(tok, rep)
    return value


@dataclass
class Flow:
    """One DIMSE flow → one network seed (A-ASSOCIATE-RQ || P-DATA-TF || RELEASE)."""
    name: str
    dimse: str                                   # e.g. 'C_ECHO_RQ' (getattr c_scare)
    abstract_syntax: str                         # resolved SOP-class UID
    transfer_syntaxes: List[str] = field(default_factory=list)  # resolved UIDs
    dimse_kwargs: Dict[str, object] = field(default_factory=dict)


@dataclass
class Profile:
    """A declarative grey-box fuzzing target."""
    name: str
    engine: str                                  # 'aflpp' | 'aflnet'
    kind: str                                    # 'file' | 'net-scp' | 'scu'
    harness: str                                 # scripts/<harness>
    binary: Optional[str] = None
    build_subdir: Optional[str] = None
    port: Optional[int] = None
    input_mode: str = 'file'                     # 'file' | 'network' | 'stdin-desock'
    placeholder: str = '@@'
    seeds_dir: Optional[str] = None
    seeds_glob: str = '*'
    seeds_generators: List[str] = field(default_factory=list)
    dictionary_path: Optional[str] = None
    dictionary_generator: Optional[str] = None
    output_dir: Optional[str] = None
    storage_dir: Optional[str] = None
    config_template: Optional[str] = None
    config_runtime: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    sand_enabled: bool = False
    argv: List[str] = field(default_factory=list)
    # DICOM identity (wired into seed RQ + rendered config + scu argv).
    calling_ae: Optional[str] = None
    called_ae: Optional[str] = None
    max_pdu_length: int = 16384
    peer_host: Optional[str] = None
    peer_port: Optional[int] = None
    flows: List[Flow] = field(default_factory=list)
    # File-seed identity (resolved against pydicom.uid by gen_file_seeds).
    file_baseline_sop_class: Optional[str] = None
    file_transfer_syntaxes: List[dict] = field(default_factory=list)
    # Crash-triage behavior (drives greybox._replay_net).
    triage_mode: str = 'file-arg'                # 'file-arg' | 'net-replay'
    triage_server_argv: List[str] = field(default_factory=list)
    port_wait_s: float = 5.0
    shutdown_signal: str = 'SIGINT'
    # SCU-only desocket shim hints (consumed by fuzz_scu.sh).
    desock: Optional[dict] = None

    @property
    def is_network(self) -> bool:
        return self.kind == 'net-scp' or self.engine == 'aflnet'


def _flows_from_raw(raw_flows, calling_ae) -> List[Flow]:
    flows: List[Flow] = []
    for fl in raw_flows or []:
        dimse_kwargs = dict(fl.get('dimse_kwargs') or {})
        # @calling_ae token resolves to the profile's calling AE (C-MOVE dest).
        for key, val in dimse_kwargs.items():
            if val == '@calling_ae':
                dimse_kwargs[key] = calling_ae
        flows.append(Flow(
            name=fl['name'],
            dimse=fl['dimse'],
            abstract_syntax=resolve_cscare_uid(fl['abstract_syntax']),
            transfer_syntaxes=[resolve_cscare_uid(ts)
                               for ts in (fl.get('transfer_syntaxes') or [])],
            dimse_kwargs=dimse_kwargs,
        ))
    return flows


def load_profile(name: str, repo: Optional[str] = None) -> Profile:
    """Load and validate ``fuzz/targets/<name>.yaml``.

    ``{{REPO_ROOT}}`` is expanded in path-like fields; runtime tokens
    (``{{PORT}}`` etc.) are preserved in ``argv`` / ``triage_server_argv``.
    """
    repo = repo or _repo_root()
    path = os.path.join(repo, 'fuzz', 'targets', f'{name}.yaml')
    if not os.path.isfile(path):
        raise FileNotFoundError(f'no target profile: {path}')
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}

    stem = os.path.splitext(os.path.basename(path))[0]
    declared = raw.get('name', stem)
    if declared != stem:
        raise ValueError(
            f'profile name {declared!r} does not match filename {stem!r}')

    def _s(value):
        return subst(value, repo=repo)

    inp = raw.get('input') or {}
    seeds = raw.get('seeds') or {}
    output = raw.get('output') or {}
    dictionary = raw.get('dictionary') or {}
    config = raw.get('config') or {}
    sand = raw.get('sand') or {}
    assoc = raw.get('association') or {}
    file_seeds = raw.get('file_seeds') or {}
    triage = raw.get('triage') or {}
    readiness = raw.get('readiness') or {}
    shutdown = raw.get('shutdown') or {}

    calling_ae = assoc.get('calling_ae')

    if 'engine' not in raw or 'kind' not in raw or 'harness' not in raw:
        raise ValueError(f'profile {stem!r} missing required engine/kind/harness')

    return Profile(
        name=stem,
        engine=raw['engine'],
        kind=raw['kind'],
        harness=raw['harness'],
        binary=raw.get('binary'),
        build_subdir=raw.get('build_subdir'),
        port=raw.get('port'),
        input_mode=inp.get('mode', 'file'),
        placeholder=inp.get('placeholder', '@@'),
        seeds_dir=_s(seeds.get('dir')),
        seeds_glob=seeds.get('glob', '*'),
        seeds_generators=[_s(g) for g in (seeds.get('generators') or [])],
        dictionary_path=_s(dictionary.get('path')),
        dictionary_generator=_s(dictionary.get('generator')),
        output_dir=_s(output.get('dir')),
        storage_dir=_s(output.get('storage_dir')),
        config_template=_s(config.get('template')),
        config_runtime=_s(config.get('runtime')),
        env={k: _s(v) for k, v in (raw.get('env') or {}).items()},
        sand_enabled=bool(sand.get('enabled', False)),
        argv=list(raw.get('argv') or []),
        calling_ae=calling_ae,
        called_ae=assoc.get('called_ae'),
        max_pdu_length=int(assoc.get('max_pdu_length', 16384)),
        peer_host=assoc.get('peer_host'),
        peer_port=assoc.get('peer_port'),
        flows=_flows_from_raw(raw.get('flows'), calling_ae),
        file_baseline_sop_class=file_seeds.get('baseline_sop_class'),
        file_transfer_syntaxes=list(file_seeds.get('transfer_syntaxes') or []),
        triage_mode=triage.get('mode', 'file-arg'),
        triage_server_argv=list(triage.get('server_argv') or []),
        port_wait_s=float(readiness.get('port_wait_s', 5.0)),
        shutdown_signal=shutdown.get('signal', 'SIGINT'),
        desock=raw.get('desock'),
    )


def load_profiles(repo: Optional[str] = None) -> Dict[str, Profile]:
    """Load every ``fuzz/targets/*.yaml`` profile, keyed by target name (sorted)."""
    repo = repo or _repo_root()
    pattern = os.path.join(repo, 'fuzz', 'targets', '*.yaml')
    out: Dict[str, Profile] = {}
    for p in sorted(glob.glob(pattern)):
        stem = os.path.splitext(os.path.basename(p))[0]
        out[stem] = load_profile(stem, repo)
    return out


def iter_profiles(repo: Optional[str] = None):
    """Yield profiles sorted by target name."""
    return iter(load_profiles(repo).values())
