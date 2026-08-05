# SPDX-License-Identifier: GPL-2.0-only
"""Regression tests for the CVE attack catalog.

Locks in that every CVE method is wired into ``CVEAttacks.all()``, that every
payload is non-empty bytes carrying a CVE tag, and that the cross-library CVEs
(GDCM, DCMTK, Orthanc, pydicom) we claim to cover are actually present. This is
the guard that keeps a newly added ``cve_*`` method from silently dropping out
of the delivered/seeded set.
"""
import pytest

from c_scare.attacks import CVEAttacks, AttackResult


# CVEs the catalog is expected to target (metadata['cve']). When a new CVE
# method is added, extend this set — the test then proves it reaches all().
EXPECTED_CVES = {
    # File / dataset parser (DCMTK + structural)
    'CVE-2023-32135', 'CVE-2024-24793', 'CVE-2024-24794', 'CVE-2022-2121',
    'CVE-2024-47796', 'CVE-2025-14607', 'CVE-2015-8979', 'CVE-2026-10528',
    # Polyglot (standard-level: DCMTK, pydicom, dcm4che alike)
    'CVE-2019-11687',
    # pydicom
    'CVE-2026-32711',
    # GDCM codec / parser (Talos)
    'CVE-2026-3650', 'CVE-2024-22391', 'CVE-2024-25569', 'CVE-2025-48429',
    'CVE-2024-22373', 'CVE-2025-52582', 'CVE-2025-11266', 'CVE-2015-8396',
    # DCMTK dcmpstat type confusion (Talos)
    'CVE-2024-28130',
    # Orthanc (CERT/CC VU#536588)
    'CVE-2026-5437', 'CVE-2026-5441', 'CVE-2026-5442', 'CVE-2026-5443',
    'CVE-2026-5444', 'CVE-2026-5445',
    # OFFIS DCMTK Toolkit 3.7.0 advisory, ICSMA-26-181-01
    'CVE-2026-50003', 'CVE-2026-50254', 'CVE-2026-35505', 'CVE-2026-52868',
    'CVE-2026-44628',
}


def _all_results():
    return list(CVEAttacks.all())


def test_all_payloads_are_nonempty_bytes():
    for r in _all_results():
        assert isinstance(r, AttackResult), r
        assert isinstance(r.payload, (bytes, bytearray)), r.name
        assert len(r.payload) > 0, f'empty payload: {r.name}'
        assert r.category == 'cve', r.name


def test_expected_cves_are_covered():
    covered = {r.metadata.get('cve') for r in _all_results()}
    covered.discard(None)
    missing = EXPECTED_CVES - covered
    assert not missing, f'CVE methods not reaching all(): {sorted(missing)}'


def test_every_cve_method_is_wired_into_all():
    """Each ``cve_*`` staticmethod must contribute to ``all()``."""
    method_names = [n for n in dir(CVEAttacks) if n.startswith('cve_')]
    assert method_names, 'no cve_* methods found'

    all_names = {r.name for r in _all_results()}
    for mname in method_names:
        results = getattr(CVEAttacks, mname)()
        produced = {r.name for r in results}
        assert produced, f'{mname} produced no payloads'
        assert produced & all_names, f'{mname} payloads are not yielded by all()'


@pytest.mark.parametrize('cve', sorted(EXPECTED_CVES))
def test_each_cve_payload_decodes_as_dicom_or_bytes(cve):
    """Every payload for a CVE is concrete bytes (deliverable + seedable)."""
    results = [r for r in _all_results() if r.metadata.get('cve') == cve]
    assert results, f'no payloads tagged {cve}'
    for r in results:
        assert len(r.payload) > 0
        assert r.description and r.expected_behavior


def test_readme_quantified_counts_match_the_catalog():
    """The README's headline numbers must not drift from the shipped catalog.

    These counts are how a reader sizes the framework before running it, so a
    stale number is a correctness bug in the docs.
    """
    import os
    import re
    from c_scare import greybox
    from c_scare.attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StorageSCPAbuseAttacks, CommandInjectionAttacks, PathTraversalAttacks,
        StateMachineAttacks,
    )

    catalogs = (ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
                StorageSCPAbuseAttacks, CommandInjectionAttacks,
                PathTraversalAttacks, StateMachineAttacks, CVEAttacks)
    results = [r for cls in catalogs for r in cls.all()]
    actual = {
        'attack categories': len({r.category for r in results}),
        'payloads': len(results),
        'CVEs reproduced': len(EXPECTED_CVES),
        'targets': len(greybox.TARGETS),
    }

    readme = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'README.md')
    row = next(line for line in open(readme, encoding='utf-8')
               if line.startswith('| **Quantified**'))
    for label, count in actual.items():
        assert re.search(rf'\*\*{count}\*\* {re.escape(label)}', row), (
            f'README says something other than {count} {label}:\n{row.strip()}')
