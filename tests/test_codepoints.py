# SPDX-License-Identifier: Apache-2.0
"""Every COSE code point the verifier uses, pinned to a literal with its source,
and every RFC the sources cite, on a reviewed list.

The values were checked against the IANA "COSE Header Parameters" and "COSE
Algorithms" registries, and the RFC numbers against the RFC Editor, on
27 October 2026. IANA registers the CB-AdES labels 261-268 with ETSI TS 119
152-1 V0.0.9 as the reference.
"""
from __future__ import annotations

import re
from pathlib import Path

from cbades_verify import algorithms as A
from cbades_verify import labels as L

ROOT = Path(__file__).resolve().parent.parent

HEADER_LABELS = {
    # RFC 9052 §3.1
    "HDR_ALG": 1, "HDR_CRIT": 2, "HDR_CONTENT_TYPE": 3, "HDR_KID": 4,
    # RFC 9338 §2
    "HDR_COUNTER_SIGNATURE_V2": 11, "HDR_COUNTER_SIGNATURE0_V2": 12,
    # RFC 9597 §2
    "HDR_CWT_CLAIMS": 15,
    # RFC 9360 §2
    "HDR_X5BAG": 32, "HDR_X5CHAIN": 33, "HDR_X5T": 34, "HDR_X5U": 35,
    # IANA COSE Header Parameters, TS 119 152-1 (CB-AdES)
    "HDR_X5TS": 261, "HDR_SRCMS": 262, "HDR_SIGPL": 263, "HDR_SRATS": 264,
    "HDR_ADOTST": 265, "HDR_SIGPID": 266, "HDR_SIGD": 267, "HDR_UHEADERS": 268,
}
OTHER = {
    "TAG_COSE_SIGN": 98, "TAG_COSE_SIGN1": 18,  # RFC 9052 §2
    "CWT_IAT": 6,  # RFC 8392 §3.1.6
}
SIGNATURE_ALGORITHMS = {
    "ES256": -7, "ES384": -35, "ES512": -36,  # RFC 9053 §2.1
    "EdDSA": -8,  # RFC 9053 §2.2
    "ESP256": -9, "ESP384": -51, "ESP512": -52,  # RFC 9864 §2.1
    "ESB256": -265, "ESB320": -266, "ESB384": -267, "ESB512": -268,  # RFC 9864 §2.1
    "Ed25519": -19, "Ed448": -53,  # RFC 9864 §2.2
    "PS256": -37, "PS384": -38, "PS512": -39,  # RFC 8230 §2
    "RS256": -257, "RS384": -258, "RS512": -259, "RS1": -65535,  # RFC 8812 §2
}
DIGESTS = {  # RFC 9054 §2
    "SHA-1": -14, "SHA-256/64": -15, "SHA-256": -16, "SHA-512/256": -17,
    "SHAKE128": -18, "SHA-384": -43, "SHA-512": -44, "SHAKE256": -45,
}
#: RFCs the sources may cite; each was looked up at the RFC Editor.
REVIEWED_RFCS = {3986, 5280, 6960, 8141, 8230, 8392, 8812, 8949, 9052, 9053, 9054, 9338, 9360,
                 9597, 9864}


def test_header_labels_and_tags():
    for name, value in {**HEADER_LABELS, **OTHER}.items():
        assert getattr(L, name) == value, name


def test_signature_algorithm_numbers():
    assert {v: k for k, v in SIGNATURE_ALGORITHMS.items()} == A.SIG_ALG_NAMES
    # every algorithm the verifier implements has a pinned number
    assert set(A._SIG_ALGS) <= set(SIGNATURE_ALGORITHMS.values())


def test_digest_numbers():
    assert A._DIGEST_NAMES == DIGESTS
    assert set(A._DIGESTS) == set(DIGESTS.values())
    assert {A.digest_id(name) for name in DIGESTS} == set(DIGESTS.values())


def test_every_cited_rfc_is_reviewed():
    sources = list((ROOT / "cbades_verify").glob("*.py")) + [ROOT / "README.md"]
    cited = set()
    for path in sources:
        cited |= {int(n) for n in re.findall(r"RFC\s*(\d{4})", path.read_text())}
    assert cited and cited <= REVIEWED_RFCS, sorted(cited - REVIEWED_RFCS)
