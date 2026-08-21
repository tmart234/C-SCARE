# SPDX-License-Identifier: GPL-2.0-only
"""
Real DICOM images to test ``--cstore-file`` against.

The carrier path exists so an attack can ride an object the operator's target
already accepts, which makes a synthetic one-by-one-pixel object exactly the
wrong thing to test it with. Every bug the carrier rewrite fixed showed up only
on a real file: group lengths a scanner emitted, an implicit-VR object, a
big-endian one, a UN element holding a sequence, encapsulated Pixel Data split
across fragments, an acquisition that was truncated on the way to disk.

Two sources, in order of preference.

**Bundled** -- pydicom ships a set of real scanner-derived objects inside the
package (``pydicom/data/test_files``): GE CT, Philips MR, and the same MR
re-encoded across every transfer syntax that matters. They are already a
dependency, so these run everywhere, offline, deterministically, and are the
corpus the test suite asserts against by default.

**Downloaded** -- pydicom also indexes a larger set hosted in the
``pydicom/pydicom-data`` repository, including multi-frame colour JPEG and
larger acquisitions. Those need the network, so they are opt-in
(``CSCARE_TEST_DOWNLOAD=1``) and skip themselves on any failure. A test run
must never go red because a host had no route to GitHub.

Set ``CSCARE_TEST_DOWNLOAD=1`` to pull the extra images::

    CSCARE_TEST_DOWNLOAD=1 pytest test/test_cstore_carrier.py
"""

import os
from typing import List, Optional, Tuple

__all__ = [
    'BUNDLED_IMAGES',
    'DOWNLOADABLE_IMAGES',
    'ENCODING_REPRESENTATIVES',
    'NONCONFORMANT_IMAGES',
    'TRUNCATED_IMAGES',
    'bundled_paths',
    'downloaded_paths',
    'encoding_paths',
    'corpus_paths',
    'downloads_enabled',
    'image_id',
    'is_nonconformant',
    'is_truncated',
]


#: ``(filename, what it covers)`` for the images that ship inside pydicom.
#: Chosen for encoding coverage rather than variety of anatomy: between them
#: they exercise every branch the carrier scanner has.
BUNDLED_IMAGES: Tuple[Tuple[str, str], ...] = (
    ('CT_small.dcm', 'GE CT, Explicit VR LE, ~250 elements'),
    ('MR_small.dcm', 'Philips MR, Explicit VR LE'),
    ('MR_small_implicit.dcm', 'Implicit VR LE - no VR on the wire'),
    ('MR_small_bigendian.dcm', 'Explicit VR Big Endian (retired)'),
    ('ExplVR_BigEnd.dcm', 'Big Endian carrying (gggg,0000) group lengths'),
    ('693_J2KI.dcm', 'JPEG 2000 with group lengths'),
    ('JPEG2000.dcm', 'JPEG 2000 lossy, encapsulated Pixel Data'),
    ('JPEG-lossy.dcm', 'JPEG Baseline, encapsulated Pixel Data'),
    ('JPGExtended.dcm', 'JPEG Extended'),
    ('MR_small_RLE.dcm', 'RLE Lossless'),
    ('MR_small_jpeg_ls_lossless.dcm', 'JPEG-LS Lossless'),
    ('MR_small_jp2klossless.dcm', 'JPEG 2000 Lossless'),
    ('SC_rgb_rle_2frame.dcm', 'multi-frame RGB, two encapsulated frames'),
    ('SC_ybr_full_422_uncompressed.dcm', 'YBR_FULL_422 native colour'),
    ('SC_rgb_small_odd.dcm', 'odd-length rows'),
    ('SC_rgb_small_odd_big_endian.dcm', 'odd-length rows, big endian'),
    ('MR_small_padded.dcm', 'trailing Data Set padding'),
    ('MR_truncated.dcm', 'Pixel Data truncated on disk'),
    ('badVR.dcm', 'an element whose VR is not a VR'),
    ('UN_sequence.dcm', 'UN element holding an implicit-VR sequence'),
    ('nested_priv_SQ.dcm', 'nested private sequences'),
    ('priv_SQ.dcm', 'private sequence, undefined length'),
    ('rtplan.dcm', 'RT Plan: deep sequences, Implicit VR'),
    ('reportsi.dcm', 'Structured Report, Content Sequence'),
    ('no_meta.dcm', 'no File Meta Information - encoding must be sniffed'),
    ('ExplVR_BigEndNoMeta.dcm', 'big endian with no File Meta Information'),
    ('ExplVR_LitEndNoMeta.dcm', 'little endian with no File Meta Information'),
    ('J2K_pixelrep_mismatch.dcm', 'Pixel Representation disagreeing with J2K'),
)

#: Images pydicom indexes but does not ship. Pulled over HTTPS from the
#: ``pydicom/pydicom-data`` repository when downloads are enabled.
DOWNLOADABLE_IMAGES: Tuple[Tuple[str, str], ...] = (
    ('color3d_jpeg_baseline.dcm', 'multi-frame colour JPEG Baseline'),
    ('emri_small.dcm', 'multi-frame MR, ten frames'),
    ('emri_small_big_endian.dcm', 'multi-frame MR, big endian'),
    ('emri_small_RLE.dcm', 'multi-frame MR, RLE'),
    ('emri_small_jpeg_2k_lossless.dcm', 'multi-frame MR, JPEG 2000'),
    ('emri_small_jpeg_ls_lossless.dcm', 'multi-frame MR, JPEG-LS'),
    ('gdcm-US-ALOKA-16.dcm', 'ultrasound with a large private block'),
    ('eCT_Supplemental.dcm', 'enhanced CT, per-frame functional groups'),
    ('explicit_VR-UN.dcm', 'explicit VR object carrying UN elements'),
    ('JPEG-LL.dcm', 'JPEG Lossless'),
    ('bad_sequence.dcm', 'a sequence that does not close cleanly'),
)

#: Corpus images that are genuinely incomplete on disk -- an element declares
#: more bytes than the file holds. A scan is *supposed* to stop inside these;
#: what matters is that the bytes it could not read are still delivered.
TRUNCATED_IMAGES = frozenset({
    'MR_truncated.dcm',
    'emri_small_jpeg_2k_lossless_too_short.dcm',
    'bad_sequence.dcm',
})

#: Corpus images that are not conformant DICOM on disk at all -- pydicom
#: cannot read them as ordinary objects either. They belong in the corpus
#: because an operator who hands the framework a broken file is testing what
#: their target does with a broken file, and the answer must be "it received
#: exactly the broken file". They are excluded only from the assertions about
#: the delivered object still being a readable image.
NONCONFORMANT_IMAGES = frozenset({
    'no_meta.dcm',          # a stray leading byte shifts every element by one
})

#: One image per distinct Data Set encoding, for the tests whose variable is
#: framework logic rather than the image. Sweeping the whole corpus there buys
#: nothing: whether a payload survives a splice depends on the *encoder*, and
#: the encoder has four cases, not twenty-eight. The full corpus is still swept
#: by the fidelity tests, where the image genuinely is the variable.
ENCODING_REPRESENTATIVES = (
    'CT_small.dcm',            # Explicit VR Little Endian
    'MR_small_implicit.dcm',   # Implicit VR Little Endian
    'MR_small_bigendian.dcm',  # Explicit VR Big Endian
    'JPEG2000.dcm',            # encapsulated Pixel Data
)

_DOWNLOAD_ENV = 'CSCARE_TEST_DOWNLOAD'


def is_truncated(path: str) -> bool:
    """True for a corpus image that is incomplete on disk by design."""
    return image_id(path) in TRUNCATED_IMAGES


def is_nonconformant(path: str) -> bool:
    """True for a corpus image that is not readable DICOM to begin with."""
    return image_id(path) in NONCONFORMANT_IMAGES


def image_id(path: str) -> str:
    """A short, stable pytest parameter id for one corpus image."""
    return os.path.basename(str(path))


def _bundled_dir() -> Optional[str]:
    try:
        import pydicom.data
    except ImportError:
        return None
    return os.path.join(os.path.dirname(pydicom.data.__file__), 'test_files')


def bundled_paths() -> List[str]:
    """Every image in :data:`BUNDLED_IMAGES` that this pydicom actually ships.

    Filtered rather than asserted: pydicom's bundled set has changed across
    releases, and a corpus entry that a future version drops should shrink the
    corpus, not break the suite.
    """
    directory = _bundled_dir()
    if directory is None:
        return []
    paths = []
    for name, _description in BUNDLED_IMAGES:
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate):
            paths.append(candidate)
    return paths


def downloads_enabled() -> bool:
    return os.environ.get(_DOWNLOAD_ENV, '').strip().lower() in (
        '1', 'true', 'yes', 'on')


def downloaded_paths() -> List[str]:
    """Fetch :data:`DOWNLOADABLE_IMAGES`, or return nothing.

    Returns an empty list unless ``CSCARE_TEST_DOWNLOAD`` is set, and drops any
    individual image that will not download. pydicom caches what it fetches, so
    a second run over the same corpus costs nothing.
    """
    if not downloads_enabled():
        return []
    try:
        from pydicom.data import get_testdata_file
    except ImportError:
        return []
    paths = []
    for name, _description in DOWNLOADABLE_IMAGES:
        try:
            path = get_testdata_file(name, download=True)
        except Exception:
            continue
        if path and os.path.exists(str(path)):
            paths.append(str(path))
    return paths


def corpus_paths() -> List[str]:
    """The full corpus: bundled images, plus downloaded ones when enabled."""
    return bundled_paths() + downloaded_paths()


def encoding_paths() -> List[str]:
    """One image per Data Set encoding -- see :data:`ENCODING_REPRESENTATIVES`."""
    directory = _bundled_dir()
    if directory is None:
        return []
    return [os.path.join(directory, name)
            for name in ENCODING_REPRESENTATIVES
            if os.path.exists(os.path.join(directory, name))]
