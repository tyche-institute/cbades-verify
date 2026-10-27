# SPDX-License-Identifier: Apache-2.0
"""Cross-check of the signature layer with an independent COSE library.

pycose, which the verifier does not use, decodes each positive vector,
rebuilds the RFC 9052 Sig_structure from the received protected-header bytes
and checks the signature with the signing certificate's key. pycose 1.1
cannot parse a header with the fully specified Ed25519 (-19) or Ed448 (-53),
so for those two vectors the test builds the RFC 9052 §4.4 Sig_structure
itself with cbor2 and checks the signature with the key directly. This covers
the COSE layer only, not the X.509, policy or validation-process steps.
"""
from __future__ import annotations

from collections.abc import Mapping

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from cbades_verify import vectors as V

pycose = pytest.importorskip("pycose")
from pycose.keys import CoseKey  # noqa: E402
from pycose.messages import Sign1Message, SignMessage  # noqa: E402

#: The data each signature covers when the message carries no payload.
DETACHED = {
    "P6-detached-payload": V.PAYLOAD,
    "P7-sigd-uri-hash": b"",
    "P10-sigd-uri-two-objects": V.PAYLOAD + V.PAYLOAD2,
}
FULLY_SPECIFIED_EDDSA = (-19, -53)


@pytest.fixture(scope="module")
def pki():
    return V.TestPKI()


@pytest.fixture(scope="module")
def vectors(pki):
    return V.build_vectors(pki)


def _signing_certs(pki):
    return [pki.ok, pki.rsa, pki.p384, pki.p521, pki.ed25519, pki.ed448]


def _mutable(v):
    """cbor2 6 decodes a tag's content as frozendict / tuple; pycose 1.1 wants
    dict / list. Byte strings, the protected header among them, stay as received."""
    if isinstance(v, Mapping):
        return {k: _mutable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_mutable(x) for x in v]
    return v


class _Sign1EdDSA:
    """A COSE_Sign1 with alg -19 or -53, checked without pycose."""

    def __init__(self, item):
        self.phdr_bytes, _, self.payload, self.signature = item

    def verifies(self, cert, detached) -> bool:
        payload = self.payload if self.payload is not None else detached
        tbs = cbor2.dumps(["Signature1", self.phdr_bytes, b"", payload])
        try:
            cert.public_key().verify(self.signature, tbs)
        except (InvalidSignature, TypeError, ValueError, AttributeError):
            return False
        return True


def _layers(data: bytes):
    """Objects that check one signature each: pycose messages or signers."""
    item = cbor2.loads(data)
    if isinstance(item, cbor2.CBORTag):
        item = item.value
    item = _mutable(item)
    if len(item) == 4 and isinstance(item[3], bytes):
        if cbor2.loads(item[0]).get(1) in FULLY_SPECIFIED_EDDSA:
            return [_Sign1EdDSA(item)]
        return [Sign1Message.from_cose_obj(item, True)]
    return list(SignMessage.from_cose_obj(item, True).signers)


def _verifies(layer, cert, detached) -> bool:
    if isinstance(layer, _Sign1EdDSA):
        return layer.verifies(cert, detached)
    pem = cert.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    layer.key = CoseKey.from_pem_public_key(pem.decode())
    try:
        return bool(layer.verify_signature(detached))
    except Exception:  # noqa: BLE001 - a key of another type is simply not this signer
        return False


def _positive(vectors):
    return sorted(c for c, (_, ind, _) in vectors.items() if c.startswith("P"))


def test_every_positive_signature_verifies_in_pycose(pki, vectors):
    checked = 0
    for case in _positive(vectors):
        data = vectors[case][0]
        for layer in _layers(data):
            hits = [c for c in _signing_certs(pki)
                    if _verifies(layer, c, DETACHED.get(case))]
            assert len(hits) == 1, case
            checked += 1
    assert checked == len(_positive(vectors)) + 1  # P5 has two signers


def test_pycose_rejects_the_signature_not_over_sig_structure(pki, vectors):
    data = vectors["N1-not-over-sig-structure"][0]
    (layer,) = _layers(data)
    assert not any(_verifies(layer, c, None) for c in _signing_certs(pki))
