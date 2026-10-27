# SPDX-License-Identifier: Apache-2.0
"""Own CB-AdES test vectors: a small PKI, positive cases, and negative cases,
one per defect class that a B-B verifier has to catch (format, signed time,
signature value, certificate validity and revocation, certificate reference,
signature policy, critical headers).

The vectors are built here from the public TS 119 152-1 V1.1.1 text, RFC 9052
and EN 319 102-1; they are not copies of any third-party test data. The eight
negative classes are those of the B-BN list in clause 7.2.1 of ETSI's public
JAdES Plugtests report (Nov-Dec 2021), carried over from JWS to COSE. ECDSA
signatures are randomised, so every run produces new bytes; the verdicts do
not change.

    python -m cbades_verify.vectors OUT_DIR

writes ``OUT_DIR/{signatures,pki,data}`` and ``OUT_DIR/expected.json``. Validate with
the fixed time :data:`VALIDATION_TIME` (``--validation-time``).
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import uuid
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .labels import (
    FORMAT_FAILURE,
    HDR_ALG,
    HDR_CRIT,
    HDR_CWT_CLAIMS,
    HDR_SIGD,
    HDR_SIGPID,
    HDR_UHEADERS,
    HDR_X5CHAIN,
    HDR_X5T,
    HDR_X5TS,
    INDETERMINATE,
    INVALID,
    NO_SIGNING_CERTIFICATE_FOUND,
    OUT_OF_BOUNDS_NO_POE,
    POLICY_PROCESSING_ERROR,
    REVOKED_NO_POE,
    SIG_CRYPTO_FAILURE,
    SIGD_MECH_BY_URI,
    SIGD_MECH_BY_URI_HASH,
    TAG_COSE_SIGN,
    TAG_COSE_SIGN1,
    VALID,
)
from .pki import _der_items

VALIDATION_TIME = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.timezone.utc)
SIGNING_TIME = dt.datetime(2026, 10, 26, 9, 0, tzinfo=dt.timezone.utc)

#: Self-assigned UUID-based OID (ITU-T X.667, arc 2.25) for the test policy.
POLICY_OID_URN = f"urn:oid:2.25.{uuid.UUID('6f0c1a3e-2b7d-4c55-9a1e-3d4b5c6d7e8f').int}"
PAYLOAD = b"cbades-verify own test payload\n"
DATA_NAME = "payload.txt"
#: The second data object of the two-object ObjectIdByURI vector.
DATA2_NAME = "payload-2.txt"
PAYLOAD2 = b"second data object\n"


def _t(y, m, d):
    return dt.datetime(y, m, d, tzinfo=dt.timezone.utc)


_SHA256 = hashes.SHA256()


CRL_THIS_UPDATE = _t(2026, 10, 1)
CRL_NEXT_UPDATE = _t(2027, 1, 1)
OCSP_THIS_UPDATE = _t(2026, 10, 20)


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cbades-verify test PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _cert(subject, issuer, key, issuer_key, not_before, not_after, *, ca=False,
          serial=None, eku=None, key_cert_sign=None, path_length=None, extra=(),
          hash_alg=_SHA256, aki=True, key_usage=None):
    """A test certificate. ``extra`` is a sequence of (extension, critical);
    ``key_usage`` replaces the default KeyUsage."""
    kcs = ca if key_cert_sign is None else key_cert_sign
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key())
         .serial_number(serial or x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
                        critical=True)
         .add_extension(key_usage or x509.KeyUsage(
             digital_signature=not ca, content_commitment=not ca, key_encipherment=False,
             data_encipherment=False, key_agreement=False, key_cert_sign=kcs, crl_sign=ca,
             encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                        critical=False))
    if aki and issuer_key is not key:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key()), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    for ext, critical in extra:
        b = b.add_extension(ext, critical=critical)
    edwards = isinstance(issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
    return b.sign(issuer_key, None if edwards else hash_alg)


def _crl(issuer_cert, issuer_key, revoked=(), this_update=CRL_THIS_UPDATE,
         next_update=CRL_NEXT_UPDATE):
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(issuer_cert.subject)
         .last_update(this_update).next_update(next_update))
    for serial, when in revoked:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when).build())
    return b.sign(issuer_key, hashes.SHA256())


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


class TestPKI:
    """Root CA -> issuing CA -> signer certificates, plus CRLs."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert(_name("CB-AdES Test Root CA"), _name("CB-AdES Test Root CA"),
                          self.root_key, self.root_key, _t(2026, 1, 1), _t(2036, 1, 1), ca=True)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = _cert(_name("CB-AdES Test Issuing CA"), self.root.subject, self.ca_key,
                        self.root_key, _t(2026, 1, 1), _t(2031, 1, 1), ca=True)

        def signer(cn, key, nb, na):
            return key, _cert(_name(cn), self.ca.subject, key, self.ca_key, nb, na)

        self.ok_key, self.ok = signer("Test Signer ES256", ec.generate_private_key(
            ec.SECP256R1()), _t(2026, 1, 1), _t(2028, 1, 1))
        self.rsa_key, self.rsa = signer("Test Signer RSA", rsa.generate_private_key(
            65537, 2048), _t(2026, 1, 1), _t(2028, 1, 1))
        self.expired_key, self.expired = signer("Test Signer expired", ec.generate_private_key(
            ec.SECP256R1()), _t(2024, 1, 1), _t(2025, 6, 30))
        self.revoked_key, self.revoked = signer("Test Signer revoked", ec.generate_private_key(
            ec.SECP256R1()), _t(2026, 1, 1), _t(2028, 1, 1))
        self.revoked_at = _t(2026, 6, 1)
        self.p384_key, self.p384 = signer("Test Signer ES384", ec.generate_private_key(
            ec.SECP384R1()), _t(2026, 1, 1), _t(2028, 1, 1))
        self.p521_key, self.p521 = signer("Test Signer ES512", ec.generate_private_key(
            ec.SECP521R1()), _t(2026, 1, 1), _t(2028, 1, 1))
        self.ed25519_key, self.ed25519 = signer("Test Signer Ed25519",
                                                ed25519.Ed25519PrivateKey.generate(),
                                                _t(2026, 1, 1), _t(2028, 1, 1))
        self.ed448_key, self.ed448 = signer("Test Signer Ed448", ed448.Ed448PrivateKey.generate(),
                                            _t(2026, 1, 1), _t(2028, 1, 1))
        self.ca_crl = _crl(self.ca, self.ca_key, [(self.revoked.serial_number, self.revoked_at)])
        self.root_crl = _crl(self.root, self.root_key)

    def ocsp_response(self, cert, *, revoked_at=None, this_update=OCSP_THIS_UPDATE):
        """An OCSP response signed by a delegated responder of the issuing CA."""
        rkey = ec.generate_private_key(ec.SECP256R1())
        rcert = _cert(_name("CB-AdES Test OCSP Responder"), self.ca.subject, rkey, self.ca_key,
                      _t(2026, 1, 1), _t(2028, 1, 1), eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
        status = ocsp.OCSPCertStatus.REVOKED if revoked_at else ocsp.OCSPCertStatus.GOOD
        b = (ocsp.OCSPResponseBuilder()
             .add_response(cert=cert, issuer=self.ca, algorithm=hashes.SHA256(),
                           cert_status=status, this_update=this_update,
                           next_update=this_update + dt.timedelta(days=7),
                           revocation_time=revoked_at,
                           revocation_reason=x509.ReasonFlags.key_compromise if revoked_at
                           else None)
             .responder_id(ocsp.OCSPResponderEncoding.HASH, rcert)
             .certificates([rcert]))
        return produced_at(b.sign(rkey, hashes.SHA256()), rkey, this_update)


def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def produced_at(resp, key, when: dt.datetime):
    """``resp`` with producedAt set to ``when`` and re-signed with ``key``.
    The library's builder stamps the wall clock, which would make the vectors
    depend on the day the tests run (RFC 6960 §4.2.1)."""
    ((_, data),) = _der_items(resp.tbs_response_bytes)
    stamp = when.astimezone(dt.timezone.utc).strftime("%Y%m%d%H%M%SZ").encode()
    tbs = _tlv(0x30, b"".join(_tlv(t, stamp if t == 0x18 else c) for t, c in _der_items(data)))
    h = resp.signature_hash_algorithm
    if isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(tbs, ec.ECDSA(h))
    elif isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(tbs, padding.PKCS1v15(), h)
    else:
        sig = key.sign(tbs)
    ((_, outer),) = _der_items(resp.public_bytes(serialization.Encoding.DER))
    (status, (_, explicit)) = _der_items(outer)
    ((_, rbytes),) = _der_items(explicit)
    (oid, (_, basic)) = _der_items(rbytes)
    ((_, fields),) = _der_items(basic)
    _, alg, _, *certs = _der_items(fields)
    basic = _tlv(0x30, tbs + _tlv(*alg) + _tlv(0x03, b"\0" + sig)
                 + b"".join(_tlv(*c) for c in certs))
    rbytes = _tlv(0x30, _tlv(*oid) + _tlv(0x04, basic))
    return ocsp.load_der_ocsp_response(_tlv(0x30, _tlv(*status) + _tlv(0xA0, rbytes)))


# --- signing ------------------------------------------------------------------------

_ES = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512}
_PS = {-37: hashes.SHA256, -38: hashes.SHA384, -39: hashes.SHA512}
_RS = {-257: hashes.SHA256, -258: hashes.SHA384, -259: hashes.SHA512}


def _raw_sign(key, alg: int, tbs: bytes) -> bytes:
    if alg in _ES:
        r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(_ES[alg]())))
        n = (key.curve.key_size + 7) // 8
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")
    if alg in _PS:
        h = _PS[alg]()
        return key.sign(tbs, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
    if alg in _RS:
        return key.sign(tbs, padding.PKCS1v15(), _RS[alg]())
    if alg in (-8, -19, -53):  # EdDSA, Ed25519, Ed448
        return key.sign(tbs)
    raise ValueError(f"alg {alg} not used by the vectors")


def _oid_der(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytearray()
    for n in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return b"\x06" + bytes([len(body)]) + bytes(body)


def policy_document() -> bytes:
    """A small DER document standing in for a signature policy: a SEQUENCE of
    the policy OID and a UTF8String, so that the document names its policy."""
    text = b"cbades-verify own test signature policy"
    inner = _oid_der(POLICY_OID_URN[len("urn:oid:"):]) + b"\x0c" + bytes([len(text)]) + text
    return b"\x30" + bytes([len(inner)]) + inner


def sig_pid(digest_value: bytes) -> dict:
    return {1: {1: cbor2.CBORTag(32, POLICY_OID_URN)}, 2: [-16, digest_value]}


def bb_protected(pki: TestPKI, cert, alg=-7, *, iat=True, x5t_value=None, policy=True) -> dict:
    """Protected header of a B-B signature: alg, CWT iat, x5chain, x5t, sigPId."""
    prot = {HDR_ALG: alg, HDR_X5CHAIN: der(cert),
            HDR_X5T: [-16, x5t_value if x5t_value is not None else sha256(der(cert))]}
    if iat:
        prot[HDR_CWT_CLAIMS] = {6: int(SIGNING_TIME.timestamp())}
    if policy:
        prot[HDR_SIGPID] = sig_pid(sha256(policy_document()))
    return prot


def bb_unprotected(pki: TestPKI, cert) -> dict:
    """uHeaders with an unsigned x5chain carrying the issuing CA (TS 119 152-1 clause 5.3.1)."""
    return {HDR_UHEADERS: [cbor2.dumps({HDR_X5CHAIN: [der(cert), der(pki.ca)]})]}


def sign1(prot: dict, unprot: dict, payload: bytes, key, alg: int, *, attached=True,
          tagged=True, signed_payload=None, raw_tbs=None) -> bytes:
    prot_bstr = cbor2.dumps(prot)
    sp = payload if signed_payload is None else signed_payload
    tbs = raw_tbs if raw_tbs is not None else cbor2.dumps(["Signature1", prot_bstr, b"", sp])
    body = [prot_bstr, unprot, payload if attached else None, _raw_sign(key, alg, tbs)]
    return cbor2.dumps(cbor2.CBORTag(TAG_COSE_SIGN1, body) if tagged else body)


def sign_multi(signers, payload: bytes) -> bytes:
    """COSE_Sign: ``signers`` is a list of (protected, unprotected, key, alg)."""
    body_prot = b""
    sigs = []
    for prot, unprot, key, alg in signers:
        pb = cbor2.dumps(prot)
        tbs = cbor2.dumps(["Signature", body_prot, pb, b"", payload])
        sigs.append([pb, unprot, _raw_sign(key, alg, tbs)])
    return cbor2.dumps(cbor2.CBORTag(TAG_COSE_SIGN, [body_prot, {}, payload, sigs]))


def build_vectors(pki: TestPKI) -> dict:
    """Return ``{case: (cbor_bytes, expected_indication, expected_subindication)}``."""
    P = PAYLOAD
    ok, k = pki.ok, pki.ok_key
    v = {}

    v["P1-es256-sign1"] = (sign1(bb_protected(pki, ok), bb_unprotected(pki, ok), P, k, -7),
                           VALID, None)
    v["P2-es256-sign1-untagged"] = (sign1(bb_protected(pki, ok), bb_unprotected(pki, ok), P,
                                          k, -7, tagged=False), VALID, None)
    v["P3-ps256"] = (sign1(bb_protected(pki, pki.rsa, -37), bb_unprotected(pki, pki.rsa), P,
                           pki.rsa_key, -37), VALID, None)
    v["P4-rs256"] = (sign1(bb_protected(pki, pki.rsa, -257), bb_unprotected(pki, pki.rsa), P,
                           pki.rsa_key, -257), VALID, None)
    v["P5-cose-sign-two-signers"] = (sign_multi([
        (bb_protected(pki, ok), bb_unprotected(pki, ok), k, -7),
        (bb_protected(pki, pki.rsa, -37), bb_unprotected(pki, pki.rsa), pki.rsa_key, -37),
    ], P), VALID, None)
    v["P6-detached-payload"] = (sign1(bb_protected(pki, ok), bb_unprotected(pki, ok), P, k, -7,
                                      attached=False), VALID, None)
    sigd = {1: cbor2.CBORTag(32, SIGD_MECH_BY_URI_HASH), 2: [DATA_NAME], 3: -16,
            4: [sha256(P)], 5: ["text/plain"]}
    prot = bb_protected(pki, ok)
    prot.update({HDR_SIGD: sigd, HDR_CRIT: [HDR_SIGD]})
    v["P7-sigd-uri-hash"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7, attached=False,
                                   signed_payload=b""), VALID, None)
    # The signed x5chain carries the whole path below the anchor; no uHeaders.
    prot = bb_protected(pki, ok)
    prot[HDR_X5CHAIN] = [der(ok), der(pki.ca)]
    v["P8-signed-chain-only"] = (sign1(prot, {}, P, k, -7), VALID, None)
    # x5ts references signer and CA; the certificates travel unsigned in uHeaders.
    prot = bb_protected(pki, ok)
    del prot[HDR_X5CHAIN], prot[HDR_X5T]
    prot[HDR_X5TS] = [[-16, sha256(der(ok))], [-16, sha256(der(pki.ca))]]
    v["P9-x5ts-unsigned-chain"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7), VALID, None)
    # ObjectIdByURI over two data objects: the signed payload is their concatenation.
    prot = bb_protected(pki, ok)
    prot.update({HDR_SIGD: {1: cbor2.CBORTag(32, SIGD_MECH_BY_URI), 2: [DATA_NAME, DATA2_NAME]},
                 HDR_CRIT: [HDR_SIGD]})
    v["P10-sigd-uri-two-objects"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7,
                                           attached=False, signed_payload=P + PAYLOAD2),
                                     VALID, None)
    v["P11-no-policy"] = (sign1(bb_protected(pki, ok, policy=False), bb_unprotected(pki, ok), P,
                                k, -7), VALID, None)
    for case, cert, key, alg in (("P12-es384", pki.p384, pki.p384_key, -35),
                                 ("P13-es512", pki.p521, pki.p521_key, -36),
                                 ("P14-ed25519", pki.ed25519, pki.ed25519_key, -19),
                                 ("P15-ed448", pki.ed448, pki.ed448_key, -53)):
        v[case] = (sign1(bb_protected(pki, cert, alg), bb_unprotected(pki, cert), P, key, alg),
                   VALID, None)

    # --- negatives: one per defect class --------------------------------------------
    # 1: the signature value is computed over the payload, not over Sig_structure.
    v["N1-not-over-sig-structure"] = (sign1(bb_protected(pki, ok), bb_unprotected(pki, ok), P, k,
                                            -7, raw_tbs=P), INVALID, SIG_CRYPTO_FAILURE)
    # 2: no claimed signing time (CWT Claims / iat missing).
    v["N2-no-iat"] = (sign1(bb_protected(pki, ok, iat=False), bb_unprotected(pki, ok), P, k, -7),
                      INVALID, FORMAT_FAILURE)
    # 3: the signing certificate expired before the validation time.
    v["N3-expired-signer"] = (sign1(bb_protected(pki, pki.expired), bb_unprotected(
        pki, pki.expired), P, pki.expired_key, -7), INDETERMINATE, OUT_OF_BOUNDS_NO_POE)
    # 4: the signing certificate is on the issuing CA's CRL.
    v["N4-revoked-signer"] = (sign1(bb_protected(pki, pki.revoked), bb_unprotected(
        pki, pki.revoked), P, pki.revoked_key, -7), INDETERMINATE, REVOKED_NO_POE)
    # 5: x5t does not match the signing certificate (or any available one).
    wrong = sha256(der(ok) + b"\x00")
    v["N5-x5t-mismatch"] = (sign1(bb_protected(pki, ok, x5t_value=wrong), bb_unprotected(pki, ok),
                                  P, k, -7), INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND)
    # 6: sigD is present but crit does not list it.
    prot = bb_protected(pki, ok)
    prot[HDR_SIGD] = sigd
    v["N6-sigd-not-in-crit"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7, attached=False,
                                      signed_payload=b""), INVALID, FORMAT_FAILURE)
    # 7: sigPId digest does not match the policy document.
    prot = bb_protected(pki, ok)
    prot[HDR_SIGPID] = sig_pid(sha256(policy_document() + b"tampered"))
    v["N7-policy-digest-mismatch"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7),
                                      INDETERMINATE, POLICY_PROCESSING_ERROR)
    # 8: crit lists a header parameter the verifier cannot understand.
    prot = bb_protected(pki, ok)
    prot.update({65000: "must be understood", HDR_CRIT: [65000]})
    v["N8-crit-unknown-label"] = (sign1(prot, bb_unprotected(pki, ok), P, k, -7),
                                  INVALID, FORMAT_FAILURE)
    return v


def write_set(out_dir, pki: TestPKI | None = None) -> dict:
    """Write the full vector set; return the expected-results manifest."""
    pki = pki or TestPKI()
    out = Path(out_dir)
    (out / "signatures").mkdir(parents=True, exist_ok=True)
    (out / "pki").mkdir(exist_ok=True)
    (out / "data").mkdir(exist_ok=True)
    pem = serialization.Encoding.PEM
    (out / "pki" / "root.pem").write_bytes(pki.root.public_bytes(pem))
    (out / "pki" / "issuing-ca.pem").write_bytes(pki.ca.public_bytes(pem))
    (out / "pki" / "issuing-ca.crl").write_bytes(pki.ca_crl.public_bytes(serialization.Encoding.DER))
    (out / "pki" / "root.crl").write_bytes(pki.root_crl.public_bytes(serialization.Encoding.DER))
    (out / "data" / "policy.der").write_bytes(policy_document())
    (out / "data" / DATA_NAME).write_bytes(PAYLOAD)
    (out / "data" / DATA2_NAME).write_bytes(PAYLOAD2)

    manifest = {"validation_time": VALIDATION_TIME.isoformat().replace("+00:00", "Z"),
                "cases": {}}
    for case, (data, ind, sub) in build_vectors(pki).items():
        (out / "signatures" / f"{case}.cbor").write_bytes(data)
        manifest["cases"][case] = {"indication": ind, "subindication": sub}
    (out / "expected.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m cbades_verify.vectors OUT_DIR", file=sys.stderr)
        sys.exit(2)
    m = write_set(sys.argv[1])
    print(f"wrote {len(m['cases'])} vectors to {sys.argv[1]}")
