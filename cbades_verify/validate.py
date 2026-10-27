# SPDX-License-Identifier: Apache-2.0
"""CB-AdES B-B validation in the order of the EN 319 102-1 basic process.

Steps of EN 319 102-1 V1.4.1 clause 5.3.4, each mapped to the building block whose sub-indication
it returns:

1. Format checking: the COSE structure and the TS 119 152-1 rules a B-B
   signature must meet (FORMAT_FAILURE, a TOTAL-FAILED result).
2. Identification of the signing certificate: x5t / x5ts / x5chain must
   point at one certificate (NO_SIGNING_CERTIFICATE_FOUND).
3. Validation context initialisation: the signature policy named in sigPId
   must be available and match its digest (SIGNATURE_POLICY_NOT_AVAILABLE,
   POLICY_PROCESSING_ERROR).
4. X.509 certificate validation at the validation time (clause 5.2.6.4):
   prospective chains, RFC 5280 path validation with revocation (freshness
   with ``revocation_freshness="strict"``), chain crypto constraints, the
   signing certificate's validity range. B-B
   carries no proof of existence, so a past revocation or expiry gives
   INDETERMINATE ``*_NO_POE``. The result is stored, not returned.
5. Cryptographic verification: the signature over the RFC 9052
   Sig_structure (SIG_CRYPTO_FAILURE), the detached data objects of sigD
   (HASH_FAILURE, SIGNED_DATA_NOT_FOUND). A failure here wins over any
   stored X.509 result; otherwise a non-PASSED X.509 result is returned.
6. Signature acceptance validation, with a small built-in constraint set:
   key sizes and binding digests (CRYPTO_CONSTRAINTS_FAILURE_NO_POE), and the
   x5ts references against the validated chain (SIG_CONSTRAINTS_FAILURE).

``Context.strict`` (the default) applies the TS 119 152-1 profile rules as
format rules. With ``strict=False`` profile deviations that leave the
signature well defined (an extra unprotected member, a missing iat, no signed
certificate reference, a text alg, misplaced parameters, ...) are recorded in
the result detail instead; RFC 9052 and CBOR well-formedness stay hard rules.
"""
from __future__ import annotations

import datetime as dt
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509 import ocsp

from . import algorithms, pki
from .cose import (
    MAX_MESSAGE_BYTES,
    CoseMessage,
    FormatError,
    SignerLayer,
    clip,
    decode,
    is_label,
)
from .labels import (
    CERTIFICATE_CHAIN_GENERAL_FAILURE,
    CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
    CWT_IAT,
    DER_ENCODING_URI,
    FORMAT_FAILURE,
    HASH_FAILURE,
    HDR_ADOTST,
    HDR_ALG,
    HDR_CONTENT_TYPE,
    HDR_CRIT,
    HDR_CWT_CLAIMS,
    HDR_SIGD,
    HDR_SIGPID,
    HDR_UHEADERS,
    HDR_X5BAG,
    HDR_X5CHAIN,
    HDR_X5T,
    HDR_X5TS,
    INDETERMINATE,
    INVALID,
    NO_CERTIFICATE_CHAIN_FOUND,
    NO_SIGNING_CERTIFICATE_FOUND,
    OID_ID,
    OUT_OF_BOUNDS_NO_POE,
    OUT_OF_BOUNDS_NOT_REVOKED,
    PKIOB_ENCODING,
    PKIOB_VAL,
    POLICY_PROCESSING_ERROR,
    REVOCATION_OUT_OF_BOUNDS_NO_POE,
    REVOKED_CA_NO_POE,
    REVOKED_NO_POE,
    RVALS_CRL,
    RVALS_OCSP,
    SIG_CONSTRAINTS_FAILURE,
    SIG_CRYPTO_FAILURE,
    SIGD_CTYS,
    SIGD_HASHM,
    SIGD_HASHV,
    SIGD_MECH_BY_URI,
    SIGD_MECH_BY_URI_HASH,
    SIGD_MID,
    SIGD_PARS,
    SIGNATURE_POLICY_NOT_AVAILABLE,
    SIGNED_DATA_NOT_FOUND,
    SIGNED_ONLY_LABELS,
    SIGNER_LAYER_LABELS,
    SIGPID_DIGALGVAL,
    SIGPID_DIGPSP,
    SIGPID_ID,
    SIGPST_DOC,
    SIGPST_POLDOC,
    TRY_LATER,
    UH_SIGPST,
    UH_VALDATA,
    UNDERSTOOD_LABELS,
    VALDATA_RVALS,
    VALDATA_XVALS,
    VALID,
)


@dataclass
class Result:
    indication: str
    subindication: str | None = None
    detail: str = ""
    signers: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {"indication": self.indication, "subindication": self.subindication,
             "detail": self.detail}
        if self.signers:
            d["signers"] = [s.as_dict() for s in self.signers]
        return d


@dataclass
class Context:
    """Everything outside the signature file that validation may use."""

    trust_anchors: list
    certs: list = field(default_factory=list)
    crls: list = field(default_factory=list)
    ocsp_responses: list = field(default_factory=list)
    #: Signature policy documents, as bytes, not tied to a policy id. A
    #: document counts for a sigPId when its digest matches, or (for the
    #: mismatch verdict) when it names the policy id.
    policies: list = field(default_factory=list)
    #: Policy documents keyed by policy id (the sigPId URI, e.g. "urn:oid:..."),
    #: compared in the form :func:`policy_id_key` gives.
    policy_map: dict = field(default_factory=dict)
    #: "indeterminate": no document for a sigPId -> SIGNATURE_POLICY_NOT_AVAILABLE.
    #: "accept": a missing document only adds a note.
    unknown_policy: str = "indeterminate"
    #: The detached payload, when the signature has a nil payload and no sigD.
    detached_payload: bytes | None = None
    #: Where sigD URI-references are resolved, inside this directory only (as a
    #: relative path, then by file name).
    data_dir: Path | None = None
    validation_time: dt.datetime = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    #: "require": unknown revocation status -> TRY_LATER. "ignore": not checked.
    revocation: str = "require"
    #: "lenient": any applicable revocation data counts. "strict": EN 319 102-1
    #: clause 5.2.5 freshness with nextUpdate - thisUpdate as the maximum age.
    revocation_freshness: str = "lenient"
    #: Fetch revocation data from the certificates' CDP and AIA URLs when the
    #: supplied and embedded data has none that is fresh: for a certificate
    #: whose signatures up to the trust anchor verify, at most
    #: :data:`pki.MAX_FETCH_URLS` URLs of each kind.
    online: bool = False
    #: TS 119 152-1 profile rules as format rules (True) or as notes (False).
    strict: bool = True


#: Data objects the sigD headers of one input may name, and the bytes they may
#: hold together, an object named twice counted twice (resource bounds).
MAX_SIGD_OBJECTS = 1000
MAX_SIGD_BYTES = 256 * 1024 * 1024
#: The longest sigPId id read; a longer one is a format failure (input bound).
MAX_POLICY_ID_CHARS = 1024
#: A URI in RFC 3986 syntax: a scheme, then unreserved, reserved and
#: percent-encoded characters only.
_URI_SYNTAX = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]"
                         r"|%[0-9A-Fa-f]{2})*")
#: Notes kept in one result detail, repeats folded into one (output bound).
MAX_NOTES = 32


class _Stop(Exception):
    def __init__(self, indication, subindication, detail):
        super().__init__(detail)
        self.result = Result(indication, subindication, detail)


def _fail_format(detail):
    raise _Stop(INVALID, FORMAT_FAILURE, detail)


def _r(value) -> str:
    """A value from the input, for a result detail."""
    return clip(repr(value))


def _with_notes(detail: str, notes: list) -> str:
    """``detail`` and the notes, a repeated note once with its count, at most
    :data:`MAX_NOTES` of them: the first and the last ones (the notes of the
    later steps come last), with the number left out between them."""
    counts = {}
    for n in notes:
        counts[n] = counts.get(n, 0) + 1
    out = [n if c == 1 else f"{n} (repeated {c} times)" for n, c in counts.items()]
    if len(out) > MAX_NOTES:
        head = MAX_NOTES // 2
        out = (out[:head] + [f"{len(out) - MAX_NOTES + 1} more notes not shown"]
               + out[len(out) - (MAX_NOTES - head - 1):])
    return "; ".join([detail] + out)


def _profile(ctx: Context, notes: list, detail: str) -> None:
    """A TS 119 152-1 profile rule: FORMAT_FAILURE when strict, else a note."""
    if ctx.strict:
        _fail_format(detail)
    notes.append(f"lenient: {detail}")


def _uri(value) -> str | None:
    """A #6.32 URI as text (an untagged text string is tolerated)."""
    if isinstance(value, cbor2.CBORTag) and value.tag == 32 and isinstance(value.value, str):
        return value.value
    if isinstance(value, str):
        return value
    return None


def _is_alg_id(v) -> bool:
    return is_label(v)  # int (not bool) or tstr


def _is_cert_hash(v) -> bool:
    return (isinstance(v, list) and len(v) == 2 and _is_alg_id(v[0])
            and isinstance(v[1], (bytes, bytearray)))


def _check_keys(m, what: str) -> None:
    """Keys of a CB-AdES map are int or tstr (TS 119 152-1 clause 4.6, RFC
    8392 for CWT Claims); a bool or float would alias an int key."""
    if isinstance(m, dict):
        bad = [k for k in m if not is_label(k)]
        if bad:
            _fail_format(f"{what} has keys that are neither int nor tstr: {_r(bad)}")


def _text_digest(ctx: Context, notes: list, alg, where: str) -> None:
    if isinstance(alg, str):
        _profile(ctx, notes, f"{where} digest identifier {_r(alg)} is a text string; TS 119 "
                             "152-1 requires the IANA-registered (integer) identifier")


def _cose_x509(value, where) -> list:
    """COSE_X509 = bstr / [2*certs: bstr] (RFC 9360) -> list of DER items."""
    if isinstance(value, (bytes, bytearray)):
        return [value]
    if isinstance(value, list) and value and all(isinstance(x, (bytes, bytearray))
                                                 for x in value):
        return value
    _fail_format(f"{where} is not a COSE_X509 (bstr or array of bstr)")


def _load_certs(items, where, *, signed: bool, notes: list) -> list:
    out = []
    for b in items:
        try:
            out.append(pki.probe_cert(x509.load_der_x509_certificate(bytes(b))))
        except Exception as exc:  # noqa: BLE001 - ValueError, InvalidVersion, ...
            if signed:
                _fail_format(f"{where} contains a certificate that cannot be parsed "
                             f"({type(exc).__name__})")
            notes.append(f"{where}: unusable certificate dropped ({type(exc).__name__})")
    return out


# --- step 1: format ------------------------------------------------------------

def _check_crit(prot: dict, where: str) -> None:
    """RFC 9052 §3.1 for one protected header (TS 119 152-1 clause 5.1.10)."""
    if HDR_CRIT not in prot:
        return
    crit = prot[HDR_CRIT]
    if not isinstance(crit, list) or not crit:
        _fail_format(f"{where} crit (2) must be a non-empty array")
    for label in crit:
        if not is_label(label):
            _fail_format(f"{where} crit element {_r(label)} is not a label (int or tstr)")
        if label not in prot:
            _fail_format(f"{where} crit lists {_r(label)}, which is not in the protected header")
        if label not in UNDERSTOOD_LABELS:
            _fail_format(f"{where} crit marks {_r(label)} as critical and this verifier does not "
                         "understand it (RFC 9052 §3.1)")


def _check_content_types(headers, where: str) -> None:
    """RFC 9052 §3.1: a content type (3) is a tstr or a uint."""
    for hdr in headers:
        ct = hdr.get(HDR_CONTENT_TYPE, "")
        if not (isinstance(ct, str) or (type(ct) is int and ct >= 0)):
            _fail_format(f"{where} content type (3) is neither a tstr nor a uint: {_r(ct)}")


def check_message_format(msg: CoseMessage, ctx: Context | None = None,
                         notes: list | None = None) -> None:
    """Rules for the COSE_Sign body layer (TS 119 152-1 clause 4.4)."""
    ctx = ctx or Context(trust_anchors=[])
    notes = [] if notes is None else notes
    if msg.kind != "COSE_Sign":
        return
    body_u, body_p = msg.body_unprotected, msg.body_protected
    _check_content_types((body_p, body_u), "COSE_Sign body")
    if HDR_UHEADERS in body_u or HDR_UHEADERS in body_p:
        _fail_format("COSE_Sign body layer carries uHeaders (TS 119 152-1 clause 4.4)")
    if (HDR_CONTENT_TYPE in body_p or HDR_CONTENT_TYPE in body_u) and any(
            HDR_SIGD in s.protected for s in msg.signers):
        _fail_format("content type (3) together with sigD (TS 119 152-1 clause 5.1.3)")
    if body_u:
        _profile(ctx, notes, f"COSE_Sign body unprotected header is not empty: "
                             f"{_r(sorted(body_u, key=str))} (TS 119 152-1 clause 4.4)")
    _check_crit(body_p, "body")
    if HDR_SIGD in body_p:
        _fail_format("sigD (267) at the COSE_Sign body layer; TS 119 152-1 clause 4.4 places "
                     "it at the signer layer")
    misplaced = sorted(set(body_p) & (SIGNER_LAYER_LABELS | {HDR_CRIT}), key=str)
    if misplaced:
        _profile(ctx, notes, f"COSE_Sign body protected header carries {misplaced}; TS 119 152-1 "
                             "clause 4.4 places these parameters at the signer layer")


def _check_x509_shapes(signer: SignerLayer, ctx: Context, notes: list) -> None:
    places = [("protected", signer.protected)] + _unsigned_instances(signer, not ctx.strict)
    for where, hdr in places:
        for label, name in ((HDR_X5CHAIN, "x5chain"), (HDR_X5BAG, "x5bag")):
            if label in hdr:
                items = _cose_x509(hdr[label], f"{where} {name}")
                if isinstance(hdr[label], list) and len(items) == 1:
                    _profile(ctx, notes, f"{where} {name} is a 1-element array; COSE_X509 is "
                                         "bstr / [2*certs: bstr] (RFC 9360)")


def _check_sigd(msg: CoseMessage, signer: SignerLayer, ctx: Context, notes: list) -> None:
    prot = signer.protected
    if HDR_CRIT not in prot or HDR_SIGD not in prot[HDR_CRIT]:
        _fail_format("sigD (267) is present but not listed in crit (TS 119 152-1 clause 5.1.10)")
    if msg.payload is not None:
        _fail_format("sigD (267) with an attached payload (TS 119 152-1 clause 5.2.8.1)")
    # signed or not: a content type would describe a payload that sigD replaces
    if any(HDR_CONTENT_TYPE in h for h in (prot, signer.unprotected, *signer.u_headers)):
        _fail_format("content type (3) together with sigD (TS 119 152-1 clause 5.1.3)")
    sigd = prot[HDR_SIGD]
    _check_keys(sigd, "sigD")
    if not isinstance(sigd, dict) or _uri(sigd.get(SIGD_MID)) is None:
        _fail_format("sigD has no mId URI")
    pars = sigd.get(SIGD_PARS)
    if not isinstance(pars, list) or not pars or not all(isinstance(p, str) for p in pars):
        _fail_format("sigD pars must be a non-empty array of text strings")
    for ref in pars:
        try:
            urllib.parse.urlparse(ref)
        except ValueError:
            _fail_format(f"sigD pars element {_r(ref)} is not a URI-reference")
    has_m, has_v = SIGD_HASHM in sigd, SIGD_HASHV in sigd
    if has_m != has_v:
        _fail_format("sigD hashM and hashV must be present together")
    if has_m and not _is_alg_id(sigd[SIGD_HASHM]):
        _fail_format("sigD hashM must be an int or tstr algorithm identifier")
    if has_m:
        _text_digest(ctx, notes, sigd[SIGD_HASHM], "sigD hashM")
    if has_v:
        hv = sigd[SIGD_HASHV]
        if not isinstance(hv, list) or len(hv) != len(pars) or not all(
                isinstance(h, (bytes, bytearray)) for h in hv):
            _fail_format("sigD hashV must hold one bstr per pars element")
    mech = _uri(sigd[SIGD_MID])
    if mech == SIGD_MECH_BY_URI_HASH and not has_m:
        _fail_format("ObjectIdByURIHash without hashM / hashV (TS 119 152-1 clause 5.2.8.2.3)")
    if mech == SIGD_MECH_BY_URI and has_m:
        _profile(ctx, notes, "ObjectIdByURI with hashM / hashV (TS 119 152-1 clause 5.2.8.2.2: shall not "
                             "be present)")
    if SIGD_CTYS in sigd:
        ctys = sigd[SIGD_CTYS]
        if not isinstance(ctys, list) or len(ctys) != len(pars) or not all(
                c is None or isinstance(c, str) for c in ctys):
            _profile(ctx, notes, "sigD ctys must hold one tstr or null per pars element")


def check_signer_format(msg: CoseMessage, signer: SignerLayer, ctx: Context | None = None,
                        notes: list | None = None) -> None:
    ctx = ctx or Context(trust_anchors=[])
    notes = [] if notes is None else notes
    prot = signer.protected

    alg = prot.get(HDR_ALG)
    if alg is None:
        _fail_format("no alg (1) in the protected header")
    if not _is_alg_id(alg):
        _fail_format(f"alg (1) is not an int or tstr: {_r(alg)}")
    if isinstance(alg, str):
        _profile(ctx, notes, f"alg {_r(alg)} is a text string; TS 119 152-1 clause 5.1.2 requires "
                             "an IANA-registered identifier")
    _check_content_types((prot, signer.unprotected, *signer.u_headers), "signer")

    extra = set(signer.unprotected) - {HDR_UHEADERS}
    if extra:
        _profile(ctx, notes, f"unprotected header has members other than uHeaders: "
                             f"{_r(sorted(extra, key=str))} (TS 119 152-1 clause 4.4)")
    if HDR_UHEADERS in prot:
        _profile(ctx, notes, "uHeaders (268) in the protected header (TS 119 152-1 clause 5.3.1: "
                             "unprotected)")
    for i, inst in enumerate(signer.u_headers):
        signed_only = sorted(set(inst) & SIGNED_ONLY_LABELS, key=str)
        if signed_only:
            _profile(ctx, notes, f"uHeaders[{i}] carries signed parameters {signed_only} "
                                 "(clauses 5.1.9, 5.2.1: protected header only)")

    _check_crit(prot, "protected header")
    if HDR_SIGD in prot:
        _check_sigd(msg, signer, ctx, notes)

    # CWT Claims with iat: "shall be present" at every level (Table 14, req. a)
    if HDR_CWT_CLAIMS in prot and not isinstance(prot[HDR_CWT_CLAIMS], dict):
        _fail_format("CWT Claims (15) is not a map (RFC 9597)")
    _check_keys(prot.get(HDR_CWT_CLAIMS), "CWT Claims")
    claims = prot.get(HDR_CWT_CLAIMS) or {}
    if CWT_IAT not in claims:
        _profile(ctx, notes, "no CWT Claims (15) iat in the protected header; B-B requires "
                             "the claimed signing time (TS 119 152-1 clause 5.1.9, Table 14)")
    else:
        iat = claims[CWT_IAT]
        if isinstance(iat, bool) or not isinstance(iat, (int, float)):
            _fail_format("CWT Claims iat (6) is not a NumericDate (RFC 8392)")

    # Signing certificate protected by the signature (TS 119 152-1 clause 5.2.2)
    if not any(lbl in prot for lbl in (HDR_X5T, HDR_X5TS, HDR_X5CHAIN)):
        _profile(ctx, notes, "none of x5t, x5ts, x5chain in the protected header "
                             "(TS 119 152-1 clause 5.2.2)")
    if HDR_X5T in prot and not _is_cert_hash(prot[HDR_X5T]):
        _fail_format("x5t (34) is not a COSE_CertHash")
    if HDR_X5T in prot:
        _text_digest(ctx, notes, prot[HDR_X5T][0], "x5t")
    if HDR_X5TS in prot:
        x5ts = prot[HDR_X5TS]
        if not isinstance(x5ts, list) or len(x5ts) < 2 or not all(_is_cert_hash(x) for x in x5ts):
            _fail_format("x5ts (261) must be an array of 2+ COSE_CertHash")
        for i, ref in enumerate(x5ts):
            _text_digest(ctx, notes, ref[0], f"x5ts[{i}]")
    _check_x509_shapes(signer, ctx, notes)

    if HDR_SIGPID in prot:
        sp = prot[HDR_SIGPID]
        _check_keys(sp, "sigPId")
        oid = sp.get(SIGPID_ID) if isinstance(sp, dict) else None
        dav = sp.get(SIGPID_DIGALGVAL) if isinstance(sp, dict) else None
        _check_keys(oid, "sigPId id")
        if not isinstance(oid, dict) or _uri(oid.get(OID_ID)) is None:
            _fail_format("sigPId (266) has no id (obId with a URI)")
        if len(_uri(oid[OID_ID])) > MAX_POLICY_ID_CHARS:
            _fail_format(f"sigPId (266) id longer than {MAX_POLICY_ID_CHARS} characters")
        # Outside this syntax (spaces, other characters, no scheme) an id could
        # be read as a pinned one that policy_id_key does not fold it onto.
        if not _URI_SYNTAX.fullmatch(_uri(oid[OID_ID])):
            _fail_format(f"sigPId (266) id {_r(_uri(oid[OID_ID]))} is not a URI (RFC 3986)")
        if not _is_cert_hash(dav):
            _fail_format("sigPId (266) has no digAlgVal [hashAlg, hashValue]")
        _text_digest(ctx, notes, dav[0], "sigPId digAlgVal")
        if SIGPID_DIGPSP in sp and not isinstance(sp[SIGPID_DIGPSP], bool):
            _fail_format("sigPId digPSp (3) is not a bool")


# --- step 2: signing certificate ---------------------------------------------

@dataclass
class _Material:
    """Validation data carried by the signature itself (untrusted input)."""

    certs: list = field(default_factory=list)
    crls: list = field(default_factory=list)
    ocsp_responses: list = field(default_factory=list)


def _pki_values(items, where: str, notes: list) -> list:
    """DER values of an array of pkiOb (a bare bstr is tolerated)."""
    if not isinstance(items, list):
        notes.append(f"{where} is not an array; ignored")
        return []
    out = []
    for it in items:
        if isinstance(it, dict) and 1 in it and len(it) == 1 and isinstance(it[1], dict):
            it = it[1]  # xVals element {1: pkiOb}
        if isinstance(it, (bytes, bytearray)):
            out.append(bytes(it))
        elif isinstance(it, dict) and isinstance(it.get(PKIOB_VAL), (bytes, bytearray)):
            enc = it.get(PKIOB_ENCODING)
            if enc is None or _uri(enc) == DER_ENCODING_URI:
                out.append(bytes(it[PKIOB_VAL]))
            else:
                notes.append(f"{where}: pkiOb encoding {_r(_uri(enc))} not supported; ignored")
        else:
            notes.append(f"{where}: element is not a pkiOb; ignored")
    return out


def _parse_each(values, loader, where: str, notes: list) -> list:
    out = []
    for raw in values:
        try:
            out.append(loader(raw))
        except Exception as exc:  # noqa: BLE001 - unusable validation data is dropped
            notes.append(f"{where}: unusable item dropped ({type(exc).__name__})")
    return out


def _room(items: list, have: int, limit: int, where: str, notes: list) -> list:
    """The first items that fit under ``limit``; the rest dropped with a note."""
    keep = max(0, limit - have)
    if len(items) > keep:
        notes.append(f"{where}: {len(items) - keep} item(s) beyond the limit of {limit} "
                     "embedded items dropped")
    return list(items[:keep])


def _unsigned_instances(signer: SignerLayer, lenient: bool) -> list:
    """``(where, map)`` of the unsigned header instances: the uHeaders
    elements and, in lenient mode, x5chain / x5bag placed directly in the
    unprotected header (RFC 9360 allows that bucket)."""
    out = []
    if lenient:
        plain = {k: v for k, v in signer.unprotected.items() if k in (HDR_X5CHAIN, HDR_X5BAG)}
        if plain:
            out.append(("unprotected", plain))
    return out + [(f"uHeaders[{i}]", inst) for i, inst in enumerate(signer.u_headers)]


def signer_material(signer: SignerLayer, notes: list, *, lenient: bool = False) -> _Material:
    """Certificates (x5chain, x5bag, valData xVals) and revocation data
    (valData rVals) embedded in the signature, at most
    :data:`pki.MAX_EMBEDDED_CERTS` certificates (signed ones first) and
    :data:`pki.MAX_EMBEDDED_REVOCATION` CRLs and OCSP responses each."""
    m = _Material()
    prot = signer.protected
    cap_c, cap_r = pki.MAX_EMBEDDED_CERTS, pki.MAX_EMBEDDED_REVOCATION
    for label, name in ((HDR_X5CHAIN, "protected x5chain"), (HDR_X5BAG, "protected x5bag")):
        if label in prot:
            items = _room(_cose_x509(prot[label], name), len(m.certs), cap_c, name, notes)
            m.certs += _load_certs(items, name, signed=True, notes=notes)
    for where0, inst in _unsigned_instances(signer, lenient):
        for label, name in ((HDR_X5CHAIN, "x5chain"), (HDR_X5BAG, "x5bag")):
            if label in inst:
                where = f"{where0} {name}"
                items = _room(_cose_x509(inst[label], where), len(m.certs), cap_c, where, notes)
                m.certs += _load_certs(items, where, signed=False, notes=notes)
        vd = inst.get(UH_VALDATA)
        if vd is None:
            continue
        where = f"{where0} valData"
        if not isinstance(vd, dict):
            notes.append(f"{where} is not a map; ignored")
            continue
        if VALDATA_XVALS in vd:
            items = _room(_pki_values(vd[VALDATA_XVALS], f"{where} xVals", notes),
                          len(m.certs), cap_c, f"{where} xVals", notes)
            m.certs += _parse_each(
                items, lambda b: pki.probe_cert(x509.load_der_x509_certificate(b)),
                f"{where} xVals", notes)
        rv = vd.get(VALDATA_RVALS)
        if isinstance(rv, dict):
            if RVALS_CRL in rv:
                items = _room(_pki_values(rv[RVALS_CRL], f"{where} crlVals", notes),
                              len(m.crls), cap_r, f"{where} crlVals", notes)
                m.crls += _parse_each(items, x509.load_der_x509_crl, f"{where} crlVals", notes)
            if RVALS_OCSP in rv:
                items = _room(_pki_values(rv[RVALS_OCSP], f"{where} ocspVals", notes),
                              len(m.ocsp_responses), cap_r, f"{where} ocspVals", notes)
                m.ocsp_responses += _parse_each(items, ocsp.load_der_ocsp_response,
                                                f"{where} ocspVals", notes)
        elif rv is not None:
            notes.append(f"{where} rVals is not a map; ignored")
    return m


def _cert_hash_matches(ref, cert) -> bool:
    try:
        return algorithms.digest(ref[0], pki.der(cert)) == bytes(ref[1])
    except algorithms.AlgorithmError:
        return False


def identify_signing_certificate(signer: SignerLayer, ctx: Context, material: _Material):
    """The signing certificate, or stop with NO_SIGNING_CERTIFICATE_FOUND.

    A protected x5chain names it (its first element, RFC 9360); every signed
    reference (x5t, x5ts[0]) must then match that certificate. Only when the
    chain is unsigned or absent is the reference looked up elsewhere.
    """
    prot = signer.protected
    refs = []
    if HDR_X5T in prot:
        refs.append(prot[HDR_X5T])
    if HDR_X5TS in prot:
        refs.append(prot[HDR_X5TS][0])  # the first reference is the signing certificate
    for ref in refs:
        try:
            algorithms.digest_id(ref[0])
        except algorithms.AlgorithmError:
            raise _Stop(INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND,
                        f"certificate reference uses an unsupported digest {_r(ref[0])}") from None

    if HDR_X5CHAIN in prot:
        first = _load_certs(_cose_x509(prot[HDR_X5CHAIN], "protected x5chain")[:1],
                            "protected x5chain", signed=True, notes=[])[0]
        if all(_cert_hash_matches(r, first) for r in refs):
            return first
        raise _Stop(INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND,
                    "the signed x5chain[0] does not match the signed certificate reference "
                    "(x5t / x5ts[0])")

    unsigned_first = []
    for where, inst in _unsigned_instances(signer, not ctx.strict):
        if HDR_X5CHAIN in inst:
            unsigned_first = _load_certs(_cose_x509(inst[HDR_X5CHAIN], "")[:1],
                                         f"{where} x5chain", signed=False, notes=[])
            break
    if not refs:
        if not unsigned_first:
            raise _Stop(INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND, "no certificate in x5chain")
        return unsigned_first[0]
    for cand in unsigned_first + material.certs + list(ctx.certs) + list(ctx.trust_anchors):
        if all(_cert_hash_matches(r, cand) for r in refs):
            return cand
    raise _Stop(INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND,
                "no available certificate matches the signed certificate reference "
                "(x5t / x5ts[0])")


# --- step 3: signature policy --------------------------------------------------

#: Arcs and digits per arc of an OID this module encodes (bounds on input).
_MAX_OID_ARCS, _MAX_ARC_DIGITS = 64, 40


def _oid_content(dotted: str) -> bytes | None:
    """DER content octets of an OBJECT IDENTIFIER in dotted form, or None
    when ``dotted`` is not one (each arc ASCII digits, the first 0-2, the
    second below 40 under 0 and 1)."""
    parts = dotted.split(".")
    if not 2 <= len(parts) <= _MAX_OID_ARCS or not all(
            a.isascii() and a.isdigit() and len(a) <= _MAX_ARC_DIGITS for a in parts):
        return None
    arcs = [int(a) for a in parts]
    if arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        return None
    out = bytearray()
    for n in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_DEFAULT_PORT = {"http": "80", "https": "443"}


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 clause 5.2.4."""
    out = []
    while path:
        if path.startswith(("../", "./")):
            path = path[path.index("/") + 1:]
        elif path.startswith("/./") or path == "/.":
            path = "/" + path[3:]
        elif path.startswith("/../") or path == "/..":
            path = "/" + path[4:]
            if out:
                out.pop()
        elif path in (".", ".."):
            path = ""
        else:
            i = path.find("/", 1)
            out.append(path if i < 0 else path[:i])
            path = "" if i < 0 else path[i:]
    return "".join(out)


def is_policy_id(pid: str) -> bool:
    """Whether ``pid`` can be a sigPId id: a URI in RFC 3986 syntax of at most
    :data:`MAX_POLICY_ID_CHARS` characters."""
    return len(pid) <= MAX_POLICY_ID_CHARS and _URI_SYNTAX.fullmatch(pid) is not None


def policy_id_key(pid: str) -> str:
    """The form in which policy ids are compared, so that two spellings of one
    id are one key: scheme and host in lower case, percent-encoding normalised
    and dot segments removed (RFC 3986 clause 6.2.2), the default port and an
    empty path of an http(s) URI (clause 6.2.3), and for a URN the namespace
    in lower case, the components after the name dropped (RFC 8141) and the
    arcs of an OID URN without leading zeros. Unreserved characters are
    decoded in a URN too, which RFC 8141 does not do: two ids that share a
    key are pinned together, so a wider key only makes a pin hold for more
    spellings."""
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", pid, re.S)
    if m is None:
        return pid
    scheme = m.group(1).lower()
    rest = _PCT.sub(lambda h: chr(int(h.group(1), 16)) if chr(int(h.group(1), 16))
                    in _UNRESERVED else "%" + h.group(1).upper(), m.group(2))
    if scheme == "urn":
        nid, _, nss = re.split(r"\?[+=]|#", rest, maxsplit=1)[0].partition(":")
        arcs = nss.split(".")
        if nid.lower() == "oid" and all(a.isascii() and a.isdigit() for a in arcs):
            nss = ".".join(a.lstrip("0") or "0" for a in arcs)
        return f"urn:{nid.lower()}:{nss}"
    if not rest.startswith("//"):
        return f"{scheme}:{rest}"
    end = re.search(r"[/?#]|$", rest[2:]).start() + 2
    user, at, host = rest[2:end].rpartition("@")
    host = host.lower()
    if host.endswith(":" + _DEFAULT_PORT.get(scheme, "")) or host.endswith(":"):
        host = host[:host.rindex(":")]
    path_end = re.search(r"[?#]|$", rest[end:]).start() + end
    path = _remove_dot_segments(rest[end:path_end])
    if not path and scheme in _DEFAULT_PORT:
        path = "/"
    return f"{scheme}://{user}{at}{host}{path}{rest[path_end:]}"


#: Characters that may continue a URI (RFC 3986), so a match ending before one
#: is only a prefix of another identifier.
_URI_MORE = rb"[A-Za-z0-9_~/%?#&=+:@!$'()*,;-]|\.[A-Za-z0-9_~/%?#-]"


def _names_policy(doc: bytes, pid: str) -> bool:
    """Whether a policy document carries the policy identifier ``pid`` as a
    whole token: the DER OID, the dotted OID, or the URI, not a longer
    identifier that starts with it (1.2.3.4 is not 1.2.3.4.5)."""
    key = policy_id_key(pid)
    if key.startswith("urn:oid:"):
        dotted = key[8:]
        body = _oid_content(dotted)
        if body is not None and len(body) < 128 and \
                b"\x06" + bytes([len(body)]) + body in doc:
            return True
        pattern = rb"(?<![0-9])(?<![0-9]\.)" + re.escape(dotted.encode()) + rb"(?![0-9]|\.[0-9])"
        return re.search(pattern, doc) is not None
    pattern = rb"(?<![A-Za-z0-9+.-])" + re.escape(pid.encode()) + rb"(?!" + _URI_MORE + rb")"
    return re.search(pattern, doc) is not None


def check_signature_policy(signer: SignerLayer, ctx: Context, notes: list) -> None:
    """EN 319 102-1 clause 5.2.4.4: the document identified by sigPId is
    accessed and its digest compared (SIGNATURE_POLICY_NOT_AVAILABLE when it
    cannot be found, POLICY_PROCESSING_ERROR when it does not match)."""
    sp = signer.protected.get(HDR_SIGPID)
    if sp is None:
        return
    pid = _uri(sp[SIGPID_ID][OID_ID])
    shown = clip(pid)
    hash_alg, expected = sp[SIGPID_DIGALGVAL]
    if sp.get(SIGPID_DIGPSP) is True:
        raise _Stop(INDETERMINATE, POLICY_PROCESSING_ERROR,
                    f"policy {shown}: digest computed per a technical specification (digPSp), "
                    "which this verifier does not implement")
    try:
        algorithms.digest_id(hash_alg)
    except algorithms.AlgorithmError:
        raise _Stop(INDETERMINATE, POLICY_PROCESSING_ERROR,
                    f"policy digest algorithm {_r(hash_alg)} not supported") from None

    def matches(doc) -> bool:
        return algorithms.digest(hash_alg, doc) == bytes(expected)

    # sigPSt: copies of the document in the unsigned header. Anyone can add
    # one, so a copy can satisfy the digest but neither override the
    # document the operator names for the policy id nor veto a matching one.
    stored = []
    for i, inst in enumerate(signer.u_headers):
        st = inst.get(UH_SIGPST)
        doc = st.get(SIGPST_DOC) if isinstance(st, dict) and all(map(is_label, st)) else None
        doc = doc.get(SIGPST_POLDOC) if isinstance(doc, dict) and all(map(is_label, doc)) \
            else None
        if isinstance(doc, (bytes, bytearray)):
            stored.append((i, bytes(doc)))
    stray = [i for i, doc in stored if not matches(doc)]
    if stray:
        notes.append(f"policy document in uHeaders{clip(str(stray))} sigPSt does not match "
                     f"the sigPId digest of {shown}")
    key = policy_id_key(pid)
    pinned = [doc for k, doc in ctx.policy_map.items() if policy_id_key(k) == key]
    if pinned:
        if any(matches(doc) for doc in pinned):
            return
        raise _Stop(INDETERMINATE, POLICY_PROCESSING_ERROR,
                    f"the supplied policy document for {shown} does not match the sigPId digest")
    if any(matches(doc) for doc in ctx.policies):
        return
    if len(stray) < len(stored):
        notes.append(f"policy {shown}: the matching document is the signature's own sigPSt "
                     "copy; none was supplied")
        return
    if stored:
        raise _Stop(INDETERMINATE, POLICY_PROCESSING_ERROR,
                    f"the policy document in sigPSt does not match the sigPId digest of {shown}")
    if any(_names_policy(doc, pid) for doc in ctx.policies):
        raise _Stop(INDETERMINATE, POLICY_PROCESSING_ERROR,
                    f"the supplied policy document naming {shown} does not match the sigPId "
                    "digest")
    if ctx.unknown_policy == "accept":
        notes.append(f"signature policy {shown} not available; accepted "
                     "(--unknown-policy accept)")
        return
    raise _Stop(INDETERMINATE, SIGNATURE_POLICY_NOT_AVAILABLE,
                f"signature policy {shown} not supplied")


# --- step 4: X.509 validation (EN 319 102-1 clause 5.2.6.4) -------------------------

def _ts(t: dt.datetime) -> str:
    return f"{t:%Y-%m-%dT%H:%M:%SZ}"


def _evaluate_chain(chain, pool, ctx: Context, crls, resps, memo=None):
    """One prospective chain: ``(None, chain)`` when it passes, otherwise
    ``(result, final)`` where ``final`` stops the search for other chains.
    ``memo`` keeps revocation statuses across the chains of one signature."""
    at = ctx.validation_time
    memo = {} if memo is None else memo
    statuses = {}
    # Every link from the anchor down to chain[i] verifies: only then are the
    # URLs in chain[i] fetched (--online), since anyone can write them otherwise.
    verified = True
    # Step 4: RFC 5280 clause 6.1, from the anchor down, revocation included.
    for i in range(len(chain) - 2, -1, -1):
        cert = chain[i]
        reason = pki.basic_failure(chain, i, at)
        if reason:
            return Result(INDETERMINATE, CERTIFICATE_CHAIN_GENERAL_FAILURE, reason), False
        verified = verified and pki.signature_status(cert, chain[i + 1]) is True
        if ctx.revocation != "ignore":
            fetch = ctx.online and verified
            if (cert, chain[i + 1], fetch) not in memo:
                memo[cert, chain[i + 1], fetch] = pki.revocation_status(
                    cert, chain[i + 1], crls, resps, at, pool=pool, online=fetch)
            st = statuses[i] = memo[cert, chain[i + 1], fetch]
            when = f"{_ts(st.revoked_at)} ({st.source}" + (
                f", {st.reason})" if st.reason else ")") if st.revoked_at else ""
            if st.status == "revoked" and i == 0:  # 4b
                return Result(INDETERMINATE, REVOKED_NO_POE,
                              f"signing certificate revoked {when}; no POE in B-B"), True
            if st.status == "on_hold" and i == 0:  # 4c
                hint = f"; next update {_ts(st.next_update)}" if st.next_update else ""
                return Result(INDETERMINATE, TRY_LATER,
                              f"signing certificate on hold since {when}{hint}"), True
            if st.status in ("revoked", "on_hold"):  # 4d
                return Result(INDETERMINATE, REVOKED_CA_NO_POE,
                              f"CA certificate {pki.describe(cert)} {st.status.replace('_', ' ')}"
                              f" {when}; no POE in B-B"), False
        reason = pki.structure_failure(chain, i)
        if reason:
            return Result(INDETERMINATE, CERTIFICATE_CHAIN_GENERAL_FAILURE, reason), False

    # Step 4a: freshness of the revocation data used.
    if ctx.revocation == "require":
        for i, st in sorted(statuses.items()):
            who = "signing" if i == 0 else f"CA {pki.describe(chain[i])}"
            if i == 0 and not pki.within_validity(chain[0], at):
                continue  # step 7 decides for a signing certificate out of its range
            if st.status == "unknown":
                if pki.key_failure(chain[i + 1]) or \
                        pki.signature_status(chain[i], chain[i + 1]) is None:
                    break  # the issuer key or the link cannot be verified; step 6 says why
                return Result(INDETERMINATE, TRY_LATER,
                              f"no revocation information for the {who} certificate"), False
            if ctx.revocation_freshness == "strict" and not st.fresh(at):
                return Result(INDETERMINATE, TRY_LATER,
                              f"revocation data for the {who} certificate is not fresh at "
                              f"{_ts(at)} ({st.source} thisUpdate {_ts(st.this_update)})"), False

    # Step 6: cryptographic constraints on the chain.
    reason = pki.chain_crypto_failure(chain)
    if reason:
        return Result(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, reason), False

    # Step 7: the signing certificate's validity range.
    signer = chain[0]
    if not pki.within_validity(signer, at):
        st = statuses.get(0)
        known_good = st is not None and st.status == "good" and (
            at < signer.not_valid_before_utc or st.covers_expired)
        span = (f"valid {signer.not_valid_before_utc:%Y-%m-%d}.."
                f"{signer.not_valid_after_utc:%Y-%m-%d}")
        if known_good:
            return Result(INDETERMINATE, OUT_OF_BOUNDS_NOT_REVOKED,
                          f"signing certificate not valid at {_ts(at)} ({span}); known not "
                          f"revoked ({st.source})"), True
        return Result(INDETERMINATE, OUT_OF_BOUNDS_NO_POE,
                      f"signing certificate not valid at {_ts(at)} ({span}); no POE in B-B"), True

    # Step 8: the issuers of the revocation data, at the validation time.
    for _i, st in sorted(statuses.items()):
        if st.issuer_cert is not None and not pki.within_validity(st.issuer_cert, at):
            return Result(INDETERMINATE, REVOCATION_OUT_OF_BOUNDS_NO_POE,
                          f"issuer of the {st.source} data ({pki.describe(st.issuer_cert)}) "
                          f"is not valid at {_ts(at)}"), True
    return None, chain


def _anchor_as_signer(signing_cert, ctx: Context):
    """Step 1 with a signing certificate that is itself a trust anchor: there
    is no chain to build and no issuer to give revocation status, but the
    checks on the signing certificate still apply (keyUsage, critical
    extensions, key, step 7 validity range)."""
    chain = [signing_cert]
    reason = pki.structure_failure(chain, 0)
    if reason:
        return Result(INDETERMINATE, CERTIFICATE_CHAIN_GENERAL_FAILURE, reason), None
    reason = pki.key_failure(signing_cert)
    if reason:
        return Result(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                      f"signing certificate {pki.describe(signing_cert)}: {reason}"), None
    at = ctx.validation_time
    if not pki.within_validity(signing_cert, at):
        span = (f"valid {signing_cert.not_valid_before_utc:%Y-%m-%d}.."
                f"{signing_cert.not_valid_after_utc:%Y-%m-%d}")
        return Result(INDETERMINATE, OUT_OF_BOUNDS_NO_POE,
                      f"signing certificate not valid at {_ts(at)} ({span}); no POE in B-B"), None
    return None, chain


def validate_certificate(signing_cert, pool, ctx: Context, crls=None, resps=None):
    """EN 319 102-1 clause 5.2.6.4. Returns ``(None, chain)`` when PASSED,
    otherwise ``(result, None)`` with an INDETERMINATE result."""
    crls = list(ctx.crls) if crls is None else crls
    resps = list(ctx.ocsp_responses) if resps is None else resps
    if any(pki.der(a) == pki.der(signing_cert) for a in ctx.trust_anchors):
        return _anchor_as_signer(signing_cert, ctx)
    current, memo = None, {}
    for chain in pki.prospective_chains(signing_cert, pool, ctx.trust_anchors,
                                        ctx.validation_time):
        result, tail = _evaluate_chain(chain, pool, ctx, crls, resps, memo)
        if result is None:
            return None, tail
        current = result
        if tail is True:
            return current, None
    if current is None:
        return Result(INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND,
                      "no chain from the signing certificate to a trust anchor"), None
    return current, None


# --- step 5: cryptographic verification ---------------------------------------

def _resolve(ref: str, ctx: Context) -> Path | None:
    """The file a sigD reference names inside ``ctx.data_dir`` only: a
    relative reference as a path below the directory, otherwise (or when that
    is absent) by its file name. Nothing outside the directory is read,
    symbolic links included."""
    if ctx.data_dir is None:
        return None
    try:
        parsed = urllib.parse.urlparse(ref)
        path = urllib.parse.unquote(parsed.path or ref)
        base = Path(ctx.data_dir).resolve()
        tries = [path] if not (parsed.scheme or parsed.netloc) else []
        tries.append(Path(path).name)
        for rel in tries:
            if not rel:
                continue
            cand = (base / rel).resolve()
            if cand.is_relative_to(base) and cand != base and cand.is_file():
                return cand
        return None
    except (ValueError, OSError):
        return None


@dataclass
class _SigdReads:
    """The sigD reads of one input, all its signers together: each file is
    read once, and the objects and bytes count against the bounds."""

    files: dict = field(default_factory=dict)
    objects: int = 0
    total: int = 0


def _sigd_objects(pars, ctx: Context, reads: _SigdReads) -> list:
    """The data objects ``pars`` names, in order, within the bounds that
    ``reads`` keeps for the input (:data:`MAX_SIGD_OBJECTS` objects and
    :data:`MAX_SIGD_BYTES` bytes, repeats counted)."""
    reads.objects += len(pars)
    if reads.objects > MAX_SIGD_OBJECTS:
        raise _Stop(INDETERMINATE, SIGNED_DATA_NOT_FOUND,
                    f"sigD names {reads.objects} data objects in this input; at most "
                    f"{MAX_SIGD_OBJECTS} are read")
    objs, read = [], reads.files
    for ref in pars:
        path = _resolve(ref, ctx)
        if path is not None and path not in read:
            try:
                with open(path, "rb") as f:
                    read[path] = f.read(MAX_SIGD_BYTES - reads.total + 1)
            except OSError:
                path = None
        if path is None:
            raise _Stop(INDETERMINATE, SIGNED_DATA_NOT_FOUND, f"sigD object {_r(ref)} not found")
        reads.total += len(read[path])
        if reads.total > MAX_SIGD_BYTES:
            raise _Stop(INDETERMINATE, SIGNED_DATA_NOT_FOUND,
                        f"the sigD data objects of this input hold more than {MAX_SIGD_BYTES} "
                        "bytes together (a resource limit)")
        objs.append(read[path])
    return objs


def signed_payload(msg: CoseMessage, signer: SignerLayer, ctx: Context,
                   reads: _SigdReads | None = None):
    """Return ``(payload_for_signature, sigd_check)``; sigd_check is a list of
    ``(ref, data, expected_digest, hash_alg)`` to compare after the signature.
    ``reads`` carries the sigD bounds across the signers of one input."""
    sigd = signer.protected.get(HDR_SIGD)
    if sigd is None:
        if msg.payload is not None:
            return msg.payload, []
        if ctx.detached_payload is None:
            raise _Stop(INDETERMINATE, SIGNED_DATA_NOT_FOUND,
                        "detached payload not supplied")
        return ctx.detached_payload, []
    mech = _uri(sigd[SIGD_MID])
    if mech not in (SIGD_MECH_BY_URI, SIGD_MECH_BY_URI_HASH):
        raise _Stop(INDETERMINATE, SIGNED_DATA_NOT_FOUND,
                    f"sigD mechanism {_r(mech)} not supported, so the signed data cannot be "
                    "built")
    pars = sigd[SIGD_PARS]
    objs = _sigd_objects(pars, ctx, _SigdReads() if reads is None else reads)
    checks = []
    if SIGD_HASHM in sigd:  # always for ObjectIdByURIHash; lenient ObjectIdByURI too
        checks = [(ref, data, bytes(h), sigd[SIGD_HASHM])
                  for ref, data, h in zip(pars, objs, sigd[SIGD_HASHV], strict=True)]
    if mech == SIGD_MECH_BY_URI:
        return b"".join(objs), checks
    return b"", checks


def verify_crypto(msg: CoseMessage, signer: SignerLayer, signing_cert, ctx: Context,
                  notes: list, reads: _SigdReads | None = None) -> None:
    alg = signer.protected[HDR_ALG]
    if not algorithms.is_supported_signature_alg(alg):
        raise _Stop(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                    f"signature algorithm {algorithms.alg_name(alg)} is not supported by this "
                    "verifier")
    payload, checks = signed_payload(msg, signer, ctx, reads)
    try:
        key = signing_cert.public_key()
    except UnsupportedAlgorithm as exc:
        raise _Stop(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                    f"the signing certificate's key type is not supported ({exc})") from None
    except Exception as exc:  # noqa: BLE001 - e.g. an EC point not on the curve
        raise _Stop(INVALID, SIG_CRYPTO_FAILURE,
                    f"the signing certificate's public key cannot be used "
                    f"({type(exc).__name__})") from None
    lenient = not ctx.strict
    curve = algorithms.es_curve_outside(alg, key)
    if curve is not None:
        if not algorithms.es_curve_allowed(alg, key, lenient=lenient):
            raise _Stop(INVALID, SIG_CRYPTO_FAILURE,
                        f"{algorithms.alg_name(alg)} with a {curve} key: RFC 9053 §2.1 "
                        "defines it for P-256, P-384 and P-521 only")
        notes.append(f"lenient: {algorithms.alg_name(alg)} used with a {curve} key "
                     "(RFC 9053 §2.1: P-256, P-384, P-521)")
    ok = algorithms.verify_signature(alg, key, signer.signature,
                                     msg.sig_structure(signer, payload), lenient=lenient)
    if not ok and msg.has_nonzero_empty_header(signer):
        ok = algorithms.verify_signature(
            alg, key, signer.signature,
            msg.sig_structure(signer, payload, empty_as_zero_length=True), lenient=lenient)
        if ok:
            notes.append("the signature verifies with h'' in place of the received empty "
                         "protected header (RFC 9052 §3)")
    if not ok:
        raise _Stop(INVALID, SIG_CRYPTO_FAILURE,
                    f"{algorithms.alg_name(alg)} signature does not verify over the "
                    f"{msg.kind} Sig_structure with the signing certificate's key")
    for ref, data, expected, hash_alg in checks:
        try:
            ok = algorithms.digest(hash_alg, data) == expected
        except algorithms.AlgorithmError:
            raise _Stop(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                        f"sigD hashM {_r(hash_alg)} not supported") from None
        if not ok:
            raise _Stop(INVALID, HASH_FAILURE, f"digest of sigD object {_r(ref)} does not match")


# --- step 6: signature acceptance validation ---------------------------------------

def check_acceptance(signer: SignerLayer, signing_cert, chain, ctx: Context,
                     notes: list) -> None:
    """EN 319 102-1 clause 5.2.8 with the built-in constraint set."""
    prot = signer.protected
    reason = algorithms.key_constraint_failure(signing_cert.public_key())
    if reason:
        raise _Stop(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, f"signing key: {reason}")
    bindings = []
    if HDR_SIGD in prot and SIGD_HASHM in prot[HDR_SIGD]:
        bindings.append(("sigD hashM", prot[HDR_SIGD][SIGD_HASHM]))
    if HDR_SIGPID in prot:
        bindings.append(("sigPId digest", prot[HDR_SIGPID][SIGPID_DIGALGVAL][0]))
    for what, alg in bindings:
        if algorithms.digest_id(alg) in algorithms.WEAK_BINDING_DIGESTS:
            raise _Stop(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                        f"{what} uses {_r(alg)}, too weak to bind signed content")
    if HDR_X5TS in prot:  # EN 319 102-1 clause 5.2.8.4.2.1: every reference within the path
        stray = [i for i, ref in enumerate(prot[HDR_X5TS])
                 if not any(_cert_hash_matches(ref, c) for c in chain)]
        if stray:
            detail = (f"x5ts references {clip(str(stray))} match no certificate of the "
                      "validated chain")
            if ctx.strict:
                raise _Stop(INDETERMINATE, SIG_CONSTRAINTS_FAILURE, detail)
            notes.append(f"lenient: {detail}")


# --- driver ------------------------------------------------------------------------

def _validate_signer(msg: CoseMessage, signer: SignerLayer, ctx: Context, notes: list,
                     reads: _SigdReads) -> Result:
    check_signer_format(msg, signer, ctx, notes)
    material = signer_material(signer, notes, lenient=not ctx.strict)
    signing_cert = identify_signing_certificate(signer, ctx, material)
    check_signature_policy(signer, ctx, notes)
    pool = material.certs + list(ctx.certs)
    x509_result, chain = validate_certificate(
        signing_cert, pool, ctx, list(ctx.crls) + material.crls,
        list(ctx.ocsp_responses) + material.ocsp_responses)
    # Step 5: the cryptographic check runs whatever the X.509 result; its
    # failure wins (EN 319 102-1 clause 5.3.4 steps 4-5).
    verify_crypto(msg, signer, signing_cert, ctx, notes, reads)
    if x509_result is not None:
        return x509_result
    check_acceptance(signer, signing_cert, chain, ctx, notes)
    if len(chain) == 1:
        return Result(VALID, None, "signature verifies; the signing certificate is a trust "
                      "anchor (no chain or revocation to check); its validity checked at the "
                      "validation time")
    return Result(VALID, None, _valid_detail(ctx))


def _valid_detail(ctx: Context) -> str:
    """What a VALID result rests on, as the context set it."""
    if ctx.revocation == "ignore":
        return ("signature verifies; certificate chain and validity checked at the validation "
                "time; revocation not checked")
    data = ("fresh revocation data" if ctx.revocation_freshness == "strict" else
            "the latest revocation data, which need not be fresh")
    return ("signature verifies; certificate chain, validity and revocation checked at the "
            f"validation time, with {data}")


def validate_signer(msg: CoseMessage, signer: SignerLayer, ctx: Context,
                    reads: _SigdReads | None = None) -> Result:
    """One signer's result; ``reads`` carries the sigD bounds across the
    signers of one input."""
    notes = []
    try:
        result = _validate_signer(msg, signer, ctx, notes,
                                  _SigdReads() if reads is None else reads)
    except _Stop as stop:
        result = stop.result
    except Exception as exc:  # noqa: BLE001 - never abort a batch on one input
        result = Result(INDETERMINATE, None,
                        f"internal error {type(exc).__name__}: {clip(str(exc))}")
    if HDR_ADOTST in signer.protected:
        notes.append("content time-stamp (adoTst) present, not evaluated")
    if notes:
        result.detail = _with_notes(result.detail, notes)
    return result


_RANK = {VALID: 0, INDETERMINATE: 1, INVALID: 2}


def validate_bytes(data: bytes, ctx: Context) -> Result:
    """Validate one CB-AdES signature file."""
    notes = []
    try:
        msg = decode(data)
        check_message_format(msg, ctx, notes)
    except FormatError as exc:
        return Result(INVALID, FORMAT_FAILURE, str(exc))
    except _Stop as stop:
        return stop.result
    except Exception as exc:  # noqa: BLE001
        return Result(INDETERMINATE, None,
                      f"internal error {type(exc).__name__}: {clip(str(exc))}")
    reads = _SigdReads()
    results = [validate_signer(msg, s, ctx, reads) for s in msg.signers]
    if len(results) == 1:
        result = results[0]
    else:
        worst = max(results, key=lambda r: _RANK.get(r.indication, 1))
        detail = "; ".join(f"signer {i}: {r.indication}"
                           + (f"/{r.subindication}" if r.subindication else "")
                           + f" ({r.detail})"
                           for i, r in enumerate(results))
        result = Result(worst.indication, worst.subindication, detail, signers=results)
    if notes:
        result.detail = _with_notes(result.detail, notes)
    return result


def validate_file(path, ctx: Context) -> Result:
    """Validate one signature file; one larger than :data:`cose.MAX_MESSAGE_BYTES`
    is refused without being read in full."""
    with open(path, "rb") as f:
        data = f.read(MAX_MESSAGE_BYTES + 1)
    if len(data) > MAX_MESSAGE_BYTES:
        return Result(INVALID, FORMAT_FAILURE,
                      f"input too large (more than {MAX_MESSAGE_BYTES} bytes)")
    return validate_bytes(data, ctx)


__all__ = ["Context", "Result", "policy_id_key", "validate_bytes", "validate_file"]
