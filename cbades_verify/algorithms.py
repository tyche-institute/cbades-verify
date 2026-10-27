# SPDX-License-Identifier: Apache-2.0
"""COSE signature and digest algorithms (RFC 9053, RFC 9054, RFC 8230, RFC 8812, RFC 9864).

Signature algorithms cover what CB-AdES signers are likely to use: ECDSA
(ES256/384/512, the fully specified ESP256/384/512 and the Brainpool
ESB256/384/512), EdDSA / Ed25519 / Ed448, RSASSA-PSS
(PS256/384/512) and RSASSA-PKCS1-v1_5 (RS256/384/512). Digest identifiers
cover ``COSE_CertHash`` (x5t, x5ts), ``sigPId`` and ``sigD``.

ESB320 (-266, brainpoolP320r1) is registered but not implemented: the
``cryptography`` package has no brainpoolP320r1 curve.

A small built-in set of cryptographic constraints (EN 319 102-1 clause
5.2.8.4.1) is applied by :mod:`cbades_verify.validate` after the signature
verifies: RSA and DSA keys of at least 2048 bits, elliptic curves of at
least 256 bits, and no SHA-1 or SHA-256/64 where a digest binds signed content (sigD,
sigPId). SHA-1 and SHA-256/64 remain accepted in x5t / x5ts, where RFC 9360
uses them only to select a certificate.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .cose import clip

# alg -> (family, hash class, ECDSA coordinate size in bytes or None, required curve or None)
# The polymorphic ES256/384/512 do not pin a curve (the coordinate size then
# follows the key, RFC 9053 §2.1); the fully specified ESP* and ESB*
# identifiers (RFC 9864) do.
_SIG_ALGS = {
    -7: ("ecdsa", hashes.SHA256, None, None),                  # ES256
    -35: ("ecdsa", hashes.SHA384, None, None),                 # ES384
    -36: ("ecdsa", hashes.SHA512, None, None),                 # ES512
    -9: ("ecdsa", hashes.SHA256, 32, ec.SECP256R1),            # ESP256
    -51: ("ecdsa", hashes.SHA384, 48, ec.SECP384R1),           # ESP384
    -52: ("ecdsa", hashes.SHA512, 66, ec.SECP521R1),           # ESP512
    -265: ("ecdsa", hashes.SHA256, 32, ec.BrainpoolP256R1),    # ESB256
    -267: ("ecdsa", hashes.SHA384, 48, ec.BrainpoolP384R1),    # ESB384
    -268: ("ecdsa", hashes.SHA512, 64, ec.BrainpoolP512R1),    # ESB512
    -8: ("eddsa", None, None, None),                           # EdDSA
    -19: ("ed25519", None, None, None),                        # Ed25519
    -53: ("ed448", None, None, None),                          # Ed448
    -37: ("pss", hashes.SHA256, None, None),                   # PS256
    -38: ("pss", hashes.SHA384, None, None),                   # PS384
    -39: ("pss", hashes.SHA512, None, None),                   # PS512
    -257: ("pkcs1", hashes.SHA256, None, None),                # RS256
    -258: ("pkcs1", hashes.SHA384, None, None),                # RS384
    -259: ("pkcs1", hashes.SHA512, None, None),                # RS512
}

SIG_ALG_NAMES = {
    -7: "ES256", -35: "ES384", -36: "ES512", -9: "ESP256", -51: "ESP384", -52: "ESP512",
    -265: "ESB256", -266: "ESB320", -267: "ESB384", -268: "ESB512",
    -8: "EdDSA", -19: "Ed25519", -53: "Ed448", -37: "PS256", -38: "PS384", -39: "PS512",
    -257: "RS256", -258: "RS384", -259: "RS512", -65535: "RS1",
}

#: Curves RFC 9053 defines the polymorphic ES256/384/512 for.
_ES_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
#: Accepted under ES* in lenient mode only, with a note: RFC 9053 §2.1 defines
#: ES256/384/512 for P-256, P-384 and P-521.
_ES_CURVES_LENIENT = _ES_CURVES + (ec.BrainpoolP256R1, ec.BrainpoolP384R1,
                                   ec.BrainpoolP512R1)

MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

# COSE digest identifiers (IANA "COSE Algorithms"): id -> (hash factory, truncate-to bytes)
_DIGESTS = {
    -14: (hashes.SHA1, None),                    # SHA-1 (filter only)
    -15: (hashes.SHA256, 8),                     # SHA-256/64
    -16: (hashes.SHA256, None),                  # SHA-256
    -17: (hashes.SHA512_256, None),              # SHA-512/256
    -18: (lambda: hashes.SHAKE128(32), None),    # SHAKE128, 256-bit output
    -43: (hashes.SHA384, None),                  # SHA-384
    -44: (hashes.SHA512, None),                  # SHA-512
    -45: (lambda: hashes.SHAKE256(64), None),    # SHAKE256, 512-bit output
}
_DIGEST_NAMES = {
    "SHA-1": -14, "SHA-256/64": -15, "SHA-256": -16, "SHA-512/256": -17, "SHAKE128": -18,
    "SHA-384": -43, "SHA-512": -44, "SHAKE256": -45,
}
#: Too weak to bind signed content (sigD hashM, sigPId digest).
WEAK_BINDING_DIGESTS = frozenset({-14, -15})


class AlgorithmError(Exception):
    """An algorithm identifier this verifier does not support."""


def digest_id(alg) -> int:
    """The integer COSE digest identifier for ``alg``: an int, or its IANA name
    (a name is a profile deviation that the caller accepts in lenient mode only)."""
    if isinstance(alg, bool) or not isinstance(alg, (int, str)):
        raise AlgorithmError(f"digest algorithm {alg!r} is not an int or tstr")
    if isinstance(alg, str):
        if alg not in _DIGEST_NAMES:
            raise AlgorithmError(f"unsupported digest algorithm {alg!r}")
        alg = _DIGEST_NAMES[alg]
    if alg not in _DIGESTS:
        raise AlgorithmError(f"unsupported digest algorithm {alg!r}")
    return alg


def digest(alg, data: bytes) -> bytes:
    """Digest ``data`` with a COSE digest identifier (int, or its IANA name; see
    :func:`digest_id`)."""
    cls, trunc = _DIGESTS[digest_id(alg)]
    h = hashes.Hash(cls())
    h.update(data)
    out = h.finalize()
    return out[:trunc] if trunc else out


def is_supported_signature_alg(alg) -> bool:
    return isinstance(alg, int) and not isinstance(alg, bool) and alg in _SIG_ALGS


def alg_name(alg) -> str:
    """The registered name of ``alg``, or its value (clipped) when unknown."""
    if isinstance(alg, bool) or not isinstance(alg, (int, str)) or alg not in SIG_ALG_NAMES:
        return clip(repr(alg))
    return SIG_ALG_NAMES[alg]


def key_constraint_failure(public_key) -> str | None:
    """Why ``public_key`` is too weak under the built-in constraints, or None."""
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < MIN_RSA_BITS:
        return f"RSA key of {public_key.key_size} bits (< {MIN_RSA_BITS})"
    if isinstance(public_key, dsa.DSAPublicKey) and public_key.key_size < MIN_RSA_BITS:
        return f"DSA key of {public_key.key_size} bits (< {MIN_RSA_BITS})"
    if isinstance(public_key, ec.EllipticCurvePublicKey) and \
            public_key.curve.key_size < MIN_EC_BITS:
        return f"EC key on {public_key.curve.name} (< {MIN_EC_BITS} bits)"
    return None


def es_curve_outside(alg, public_key) -> str | None:
    """For the polymorphic ES256/384/512: the name of a key curve of 256 bits
    or more outside P-256/384/521, else None."""
    if not is_supported_signature_alg(alg) or _SIG_ALGS[alg][0] != "ecdsa" or \
            _SIG_ALGS[alg][3] is not None or \
            not isinstance(public_key, ec.EllipticCurvePublicKey):
        return None
    if isinstance(public_key.curve, _ES_CURVES) or public_key.curve.key_size < MIN_EC_BITS:
        return None
    return public_key.curve.name


def es_curve_allowed(alg, public_key, *, lenient: bool) -> bool:
    """Whether the key curve is accepted under the polymorphic ES* ``alg``."""
    return es_curve_outside(alg, public_key) is None or (
        lenient and isinstance(public_key.curve, _ES_CURVES_LENIENT))


def verify_signature(alg: int, public_key, signature: bytes, tbs: bytes, *,
                     lenient: bool = False) -> bool:
    """True when ``signature`` over ``tbs`` verifies under ``public_key``.

    A key type or curve that does not match ``alg`` verifies as False: the
    signature cannot have been produced by that certificate's key with that
    algorithm (RFC 9053 §2.1 curve substitution). A curve below 256 bits is
    verified anyway, so that the constraint step can report it as weak.
    """
    if not is_supported_signature_alg(alg):
        raise AlgorithmError(f"unsupported signature algorithm {alg!r}")
    family, hcls, coord, curve = _SIG_ALGS[alg]
    try:
        if family == "ecdsa":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            if curve is not None:
                if not isinstance(public_key.curve, curve):
                    return False
            else:
                allowed = _ES_CURVES_LENIENT if lenient else _ES_CURVES
                if not isinstance(public_key.curve, allowed) and \
                        public_key.curve.key_size >= MIN_EC_BITS:
                    return False
                coord = (public_key.curve.key_size + 7) // 8
            if len(signature) != 2 * coord:
                return False
            r = int.from_bytes(signature[:coord], "big")
            s = int.from_bytes(signature[coord:], "big")
            public_key.verify(encode_dss_signature(r, s), tbs, ec.ECDSA(hcls()))
        elif family in ("eddsa", "ed25519", "ed448"):
            allowed = {
                "eddsa": (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
                "ed25519": (ed25519.Ed25519PublicKey,),
                "ed448": (ed448.Ed448PublicKey,),
            }[family]
            if not isinstance(public_key, allowed):
                return False
            public_key.verify(signature, tbs)
        elif family == "pss":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            # RFC 8230 §2: MGF1 with the same hash, salt length = hash length.
            public_key.verify(
                signature, tbs,
                padding.PSS(mgf=padding.MGF1(hcls()), salt_length=hcls.digest_size),
                hcls(),
            )
        else:  # pkcs1
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            public_key.verify(signature, tbs, padding.PKCS1v15(), hcls())
    except (InvalidSignature, ValueError):
        return False
    return True
