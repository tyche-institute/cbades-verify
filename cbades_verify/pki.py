# SPDX-License-Identifier: Apache-2.0
"""X.509 material: loading, prospective chains, path checks, CRL and OCSP status.

This is the part of EN 319 102-1 clause 5.2.6 (X.509 certificate validation)
that a B-B verifier needs. :mod:`cbades_verify.validate` runs the steps of
EN 319 102-1 clause 5.2.6.4; this module supplies the pieces:

* loading certificates, CRLs and OCSP responses, recognised by content;
* prospective certificate chains: RFC 5280 clause 6.1 conditions (a)-(c),
  that is, name chaining from the signing certificate to a trust anchor.
  Chains whose every link carries a verifying signature are tried first; only
  when there is none are name-only chains tried, for the diagnosis, and there
  a differing AKI/SKI pair rules a link out. Chain building has a work budget;
* the RFC 5280 clause 6.1 checks for one chain: issuer signatures, the shell
  validity model for CA certificates, basicConstraints cA, keyCertSign,
  pathLenConstraint, the signing certificate's keyUsage, and any critical
  extension these checks do not process (RFC 5280 6.1.4 (o), 6.1.5 (f));
* revocation status from the latest issued applicable CRL or OCSP response
  (EN 319 102-1 clause 5.2.6.4 step 4) and its freshness test (clause 5.2.5.4),
  which :mod:`cbades_verify.validate` applies when asked to. Data
  issued after the certificate expired applies only when the issuer keeps
  status for expired certificates (ExpiredCertsOnCRL, OCSP archiveCutoff);
  data signed with MD5 / SHA-1 or by a key below the constraints is not used,
  nor is a CRL or OCSP response with a critical extension (on any CRL entry
  or SingleResponse too) that these checks do not process. A delegated OCSP
  responder needs id-kp-OCSPSigning and a keyUsage, if present, that allows
  signing. ``removeFromCRL`` releases a certificate from hold on a CRL only
  (RFC 5280 clause 6.3.3); an OCSP "revoked" stays revoked.

Not processed: name constraints, certificate policies, policy mapping and
policy constraints (so a certificate that marks one of them critical is
rejected), OCSP responder revocation (id-pkix-ocsp-nocheck), and qualified
status (a trusted-list driven validation policy). Delta CRLs and indirect CRLs are not
merged; they are skipped, so they can never make a certificate look good. An
OCSP response signed by the certificate's issuer itself is accepted whatever
that CA's keyUsage, as common practice has it.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

from . import algorithms
from .cose import clip

#: Intermediate CA certificates allowed between the signing certificate and
#: the trust anchor in one chain (so a chain has at most 10 certificates).
MAX_PATH_LENGTH = 8
#: Prospective chains evaluated per signature (EN 319 102-1 clause 5.2.6.4 step 2).
MAX_PATHS = 16
#: Candidate certificates examined per search while building chains: bounds
#: the work a crafted certificate pool can cause.
MAX_STEPS = 10_000
#: Certificate signatures checked per signature while building chains.
MAX_SIGNATURE_CHECKS = 2_000
#: Validation data taken from one signature's own headers (x5chain, x5bag,
#: valData); the rest is dropped with a note.
MAX_EMBEDDED_CERTS = 256
MAX_EMBEDDED_REVOCATION = 64
FETCH_TIMEOUT_S = 15
#: CRL distribution point URLs, and OCSP responder URLs, fetched per certificate.
MAX_FETCH_URLS = 3
MAX_FETCH_BYTES = 20 * 1024 * 1024


# --- loading -----------------------------------------------------------------

_PEM_CERT = b"-----BEGIN CERTIFICATE-----"
_PEM_CRL_RE = re.compile(rb"-----BEGIN X509 CRL-----.+?-----END X509 CRL-----", re.S)


def _read(path) -> bytes:
    return Path(path).read_bytes()


def probe_cert(cert, with_key: bool = False):
    """Touch the lazily parsed fields, so that a broken certificate fails here
    rather than in the middle of validation. The public key is not loaded by
    default: a key this library cannot use is a validation result (step 6),
    not a reason to drop the certificate or its bundle."""
    _ = (cert.subject, cert.issuer, cert.not_valid_before_utc, cert.not_valid_after_utc,
         cert.serial_number)
    list(cert.extensions)
    if with_key:
        cert.public_key()
    return cert


def certs_from_bytes(raw: bytes) -> list:
    """All certificates in a PEM bundle, or the one certificate in DER."""
    if _PEM_CERT in raw:
        return [probe_cert(c) for c in x509.load_pem_x509_certificates(raw)]
    return [probe_cert(x509.load_der_x509_certificate(raw))]


def load_certs(paths) -> list:
    out = []
    for p in paths:
        out.extend(certs_from_bytes(_read(p)))
    return out


def crls_from_bytes(raw: bytes) -> list:
    blocks = _PEM_CRL_RE.findall(raw)
    if blocks:
        return [x509.load_pem_x509_crl(b) for b in blocks]
    return [x509.load_der_x509_crl(raw)]


def load_crls(paths) -> list:
    out = []
    for p in paths:
        out.extend(crls_from_bytes(_read(p)))
    return out


def load_ocsp_responses(paths) -> list:
    return [ocsp.load_der_ocsp_response(_read(p)) for p in paths]


def classify_bytes(raw: bytes) -> tuple:
    """``(certs, crls, ocsp_responses)`` found in one file, recognised by content:
    PEM certificates and CRLs first, then a DER certificate, CRL or OCSP response."""
    certs, crls = [], []
    if _PEM_CERT in raw:
        certs = certs_from_bytes(raw)
    if _PEM_CRL_RE.search(raw):
        crls = crls_from_bytes(raw)
    if certs or crls:
        return certs, crls, []
    for kind, loader in (("cert", lambda b: [probe_cert(x509.load_der_x509_certificate(b))]),
                         ("crl", lambda b: [x509.load_der_x509_crl(b)]),
                         ("ocsp", lambda b: [ocsp.load_der_ocsp_response(b)])):
        try:
            found = loader(raw)
        except Exception:  # noqa: BLE001 - try the next type
            continue
        return (found if kind == "cert" else [], found if kind == "crl" else [],
                found if kind == "ocsp" else [])
    raise ValueError("neither a certificate, a CRL nor an OCSP response")


def _raise(exc: OSError):
    raise exc


def load_material_dir(directory) -> tuple:
    """Load every certificate, CRL and OCSP response under ``directory``
    (subdirectories included; symbolic links to directories are not followed).

    The type of each file is recognised by its content, not its name. Returns
    ``(certs, crls, ocsp_responses, skipped)``; files that do not parse are
    listed in ``skipped`` rather than aborting the run. A directory or file
    that cannot be read raises :class:`OSError`: material that was meant to
    be used is never left out silently.
    """
    certs, crls, resps, skipped = [], [], [], []
    files = []
    for top, _dirs, names in os.walk(directory, onerror=_raise):
        files += [Path(top, n) for n in names]
    for p in sorted(files):
        if not p.is_file():
            continue
        raw = p.read_bytes()
        try:
            c, r, o = classify_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - report, do not abort
            skipped.append(f"{p}: {type(exc).__name__}")
            continue
        certs += c
        crls += r
        resps += o
    return certs, crls, resps, skipped


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _ext(cert_or_crl, cls):
    try:
        return cert_or_crl.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _is_ca(cert) -> bool:
    bc = _ext(cert, x509.BasicConstraints)
    return bool(bc and bc.ca)


_SIG_CACHE: dict = {}


def _signature_status(child, parent) -> bool | None:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 - an algorithm the X.509 API refuses (e.g. SHA-1)
        pass
    try:
        pub, h = parent.public_key(), child.signature_hash_algorithm
        tbs, sig = child.tbs_certificate_bytes, child.signature
    except Exception:  # noqa: BLE001 - UnsupportedAlgorithm: key or algorithm
        return None
    if h is None:
        return None
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            try:
                pad = child.signature_algorithm_parameters
            except Exception:  # noqa: BLE001
                pad = padding.PKCS1v15()
            pub.verify(sig, tbs, pad, h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, tbs, ec.ECDSA(h))
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(sig, tbs, h)
        else:
            return None
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001
        return None
    return True


def signature_status(child, parent) -> bool | None:
    """Whether ``parent``'s key verifies the signature on ``child``: True,
    False, or None when this library cannot tell (unsupported signature
    algorithm or key). SHA-1 signatures are verified too, and MD5 ones as far
    as the backend still can; the cryptographic constraints (step 6) reject
    them afterwards."""
    key = (child, parent)
    if key not in _SIG_CACHE:
        if len(_SIG_CACHE) >= 8192:
            _SIG_CACHE.clear()
        _SIG_CACHE[key] = _signature_status(child, parent)
    return _SIG_CACHE[key]


def _issued_by(child, parent) -> bool:
    return signature_status(child, parent) is True


def within_validity(cert, at: dt.datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc


def describe(cert) -> str:
    try:
        return clip(cert.subject.rfc4514_string())
    except Exception:  # noqa: BLE001
        return "<unreadable subject>"


# --- prospective chains (EN 319 102-1 clause 5.2.6.4 step 2) -------------------

def _link_info(cert):
    """(subject, issuer, authority key id, subject key id) of ``cert``."""
    aki = _ext(cert, x509.AuthorityKeyIdentifier)
    ski = _ext(cert, x509.SubjectKeyIdentifier)
    return (cert.subject, cert.issuer, aki.key_identifier if aki else None,
            ski.digest if ski else None)


def prospective_chains(signer, pool, anchors, at):
    """Yield chains ``[signer, ..., anchor]``, likeliest first.

    A chain links each certificate to one whose subject is its issuer (RFC
    5280 clause 6.1 conditions (a)-(c)). First come the chains in which every
    issuer's key verifies the signature below it: these are found from the
    anchors down, so certificates that merely carry a CA's name cannot crowd
    them out. Only when there is no such chain are name-only chains yielded,
    so that the failing link can be reported; there a differing AKI/SKI pair
    rules a link out (it names another key). Within a search, anchors, a
    matching AKI/SKI pair and certificates valid at ``at`` come first. At most
    :data:`MAX_PATHS` chains are yielded; :data:`MAX_STEPS` candidates and
    :data:`MAX_SIGNATURE_CHECKS` signature checks bound the work.
    """
    first = der(signer)
    nodes = {}
    for c in list(anchors) + list(pool):
        nodes.setdefault(der(c), c)
    nodes.pop(first, None)
    info = {}
    for d, c in list(nodes.items()) + [(first, signer)]:
        try:
            info[d] = _link_info(c)
        except Exception:  # noqa: BLE001 - an unreadable certificate links nowhere
            nodes.pop(d, None)
    if first not in info:
        return
    anchor_ders = {der(a) for a in anchors} & set(nodes)
    certs = {**nodes, first: signer}
    by_subject, by_issuer = defaultdict(list), defaultdict(list)
    for d in nodes:
        by_subject[info[d][0]].append(d)
        if d not in anchor_ders:
            by_issuer[info[d][1]].append(d)

    valid = {}

    def key_link(aki, p) -> int:
        """0: AKI matches SKI; 1: one of them absent; 2: they differ."""
        ski = info[p][3]
        return 1 if aki is None or ski is None else (0 if aki == ski else 2)

    def rank(aki, p):
        link = key_link(aki, p)
        if p not in valid:
            try:
                valid[p] = within_validity(nodes[p], at)
            except Exception:  # noqa: BLE001
                valid[p] = False
        return (p not in anchor_ders, link, not valid[p])

    checks = [MAX_SIGNATURE_CHECKS]

    def verifies(child, p) -> bool:
        if (certs[child], nodes[p]) not in _SIG_CACHE:
            if checks[0] <= 0:
                return False
            checks[0] -= 1
        return signature_status(certs[child], nodes[p]) is True

    # Names the signer's chains can pass through: the issuer names upwards.
    names, todo = set(), [info[first][1]]
    while todo:
        n = todo.pop()
        if n not in names:
            names.add(n)
            todo += [info[d][1] for d in by_subject.get(n, ())]

    # Pass 1: from the anchors down, the certificates with a verified path.
    verified = set(anchor_ders)
    level = set(anchor_ders)
    for _ in range(MAX_PATH_LENGTH + 1):
        grown = set()
        for p in level:
            for d in by_issuer.get(info[p][0], ()):
                if d not in verified and d not in grown and d != first and \
                        info[d][0] in names and verifies(d, p):
                    grown.add(d)
        if not grown:
            break
        verified |= grown
        level = grown

    def walk(path, seen, steps, allowed, link_ok, ordered):
        _, issuer, aki, _ = info[path[-1]]
        if (issuer, aki) not in ordered:
            bucket = [p for p in by_subject.get(issuer, ()) if allowed(p)]
            steps[0] -= len(bucket)
            ordered[issuer, aki] = sorted(bucket, key=lambda p: rank(aki, p))
        for p in ordered[issuer, aki]:
            steps[0] -= 1
            if steps[0] < 0:
                return
            if p in seen or not link_ok(path[-1], p):
                continue
            if p in anchor_ders:
                yield path[1:] + [p]
            elif len(path) <= MAX_PATH_LENGTH:
                yield from walk(path + [p], seen | {p}, steps, allowed, link_ok, ordered)

    yielded = 0
    for tail in walk([first], {first}, [MAX_STEPS], verified.__contains__, verifies, {}):
        yield [signer] + [nodes[q] for q in tail]
        yielded += 1
        if yielded >= MAX_PATHS:
            return
    if yielded:
        return

    # Pass 2 (no verified chain): name-only chains, to report what fails.
    reached = {info[d][0] for d in anchor_ders}
    for _ in range(MAX_PATH_LENGTH + 1):
        grown = {info[d][0] for d in nodes if info[d][1] in reached} - reached
        if not grown:
            break
        reached |= grown

    def useful(p):
        return p in anchor_ders or info[p][1] in reached

    def named_link(child, p) -> bool:
        return key_link(info[child][2], p) != 2

    for tail in walk([first], {first}, [MAX_STEPS], useful, named_link, {}):
        yield [signer] + [nodes[q] for q in tail]
        yielded += 1
        if yielded >= MAX_PATHS:
            return


# --- RFC 5280 clause 6.1 checks of one chain ----------------------------------------

def _who(i: int, cert, chain=None) -> str:
    if chain is not None and i == len(chain) - 1:
        return f"trust anchor {describe(cert)}"
    return "signing certificate" if i == 0 else f"CA certificate {describe(cert)}"


_WEAK_CERT_HASHES = (hashes.MD5, hashes.SHA1)


def unusable_signature(cert) -> str | None:
    """Why the signature on ``cert`` cannot count whatever its value: a weak
    (MD5, SHA-1) or an unsupported signature algorithm."""
    try:
        h = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - UnsupportedAlgorithm
        try:
            oid = cert.signature_algorithm_oid.dotted_string
        except Exception:  # noqa: BLE001
            oid = "?"
        return f"signature algorithm {oid} is not supported"
    if isinstance(h, _WEAK_CERT_HASHES):
        return f"signed with {h.name}"
    return None


def basic_failure(chain, i: int, at) -> str | None:
    """RFC 5280 6.1.3 (a)(1)-(2) for ``chain[i]``: the issuer's signature and,
    except for the signing certificate (EN 319 102-1 step 7), validity at ``at``
    (shell model). A signature this library cannot check (unsupported
    algorithm or key) is left to the cryptographic constraints (step 6,
    :func:`chain_crypto_failure`); an MD5 / SHA-1 signature is checked here,
    as far as the backend can, and rejected there."""
    cert, issuer = chain[i], chain[i + 1]
    if signature_status(cert, issuer) is False:
        return f"{_who(i, cert)}: the signature of {describe(issuer)} does not verify"
    try:
        if i > 0 and not within_validity(cert, at):
            return (f"{_who(i, cert)} not valid at {at:%Y-%m-%dT%H:%M:%SZ} "
                    f"(valid {cert.not_valid_before_utc:%Y-%m-%d}.."
                    f"{cert.not_valid_after_utc:%Y-%m-%d}; shell model)")
    except Exception as exc:  # noqa: BLE001
        return f"{_who(i, cert)} cannot be processed ({type(exc).__name__})"
    return None


#: The extensions these checks process. subjectAltName and issuerAltName carry
#: names only, and nothing here depends on them. Every other critical
#: extension rejects the certificate (RFC 5280 6.1.4 (o), 6.1.5 (f)): name
#: constraints, the policy extensions, extendedKeyUsage (no key purpose is
#: defined for CB-AdES), qcStatements and private extensions among them.
PROCESSED_EXTENSIONS = frozenset({
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.KEY_USAGE,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.CRL_DISTRIBUTION_POINTS,
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.ISSUER_ALTERNATIVE_NAME,
})


def unprocessed_critical(cert, also=()) -> list:
    """Dotted OIDs of the critical extensions of ``cert`` outside
    :data:`PROCESSED_EXTENSIONS` and ``also``."""
    known = PROCESSED_EXTENSIONS.union(also)
    return [e.oid.dotted_string for e in cert.extensions
            if e.critical and e.oid not in known]


def structure_failure(chain, i: int) -> str | None:
    """RFC 5280 6.1.4 (k), (l)/(m), (n), (o) for a CA ``chain[i]`` (i > 0), and
    6.1.5 (f) for the signing certificate: cA, pathLenConstraint, keyCertSign,
    for the signing certificate a keyUsage that allows signing, and no
    critical extension that is not processed."""
    cert = chain[i]
    try:
        if i == 0:
            ku = _ext(cert, x509.KeyUsage)
            if ku is not None and not (ku.digital_signature or ku.content_commitment):
                return (f"{_who(i, cert)}: keyUsage has neither digitalSignature nor "
                        "nonRepudiation")
        else:
            bc = _ext(cert, x509.BasicConstraints)
            if bc is None or not bc.ca:
                return f"{_who(i, cert)} is not a CA (basicConstraints cA)"
            below = sum(1 for c in chain[1:i] if c.subject != c.issuer)
            if bc.path_length is not None and below > bc.path_length:
                return f"{_who(i, cert)}: pathLenConstraint {bc.path_length} exceeded"
            ku = _ext(cert, x509.KeyUsage)
            if ku is not None and not ku.key_cert_sign:
                return f"{_who(i, cert)}: keyUsage without keyCertSign"
        crit = unprocessed_critical(cert)
        if crit:
            return f"{_who(i, cert)} has critical extensions that are not processed: {crit}"
    except Exception as exc:  # noqa: BLE001
        return f"{_who(i, cert)} cannot be processed ({type(exc).__name__})"
    return None


def key_failure(cert) -> str | None:
    """Why the public key of ``cert`` fails the built-in constraints or cannot be
    loaded, or None."""
    try:
        return algorithms.key_constraint_failure(cert.public_key())
    except Exception as exc:  # noqa: BLE001 - UnsupportedAlgorithm, an invalid point, ...
        return f"public key cannot be used ({type(exc).__name__})"


def chain_crypto_failure(chain) -> str | None:
    """EN 319 102-1 clause 5.2.6.4 step 6 with the built-in constraints: no
    MD5 / SHA-1 or unsupported certificate signature algorithms, and no weak
    or unusable keys, the anchor's included (it signs the certificate below
    it; its own self-signature does not count)."""
    for i, cert in enumerate(chain[:-1]):
        reason = unusable_signature(cert)
        if reason is None and signature_status(cert, chain[i + 1]) is None:
            above = key_failure(chain[i + 1])
            if above:
                return f"{_who(i + 1, chain[i + 1], chain)}: {above}"
            reason = f"the signature of {describe(chain[i + 1])} cannot be checked"
        reason = reason or key_failure(cert)
        if reason:
            return f"{_who(i, cert)}: {reason}"
    if len(chain) > 1:
        reason = key_failure(chain[-1])
        if reason:
            return f"{_who(len(chain) - 1, chain[-1], chain)}: {reason}"
    return None


# --- revocation ------------------------------------------------------------------

@dataclass
class RevocationStatus:
    status: str  # "good", "revoked", "on_hold" or "unknown"
    source: str = ""
    revoked_at: dt.datetime | None = None
    reason: str | None = None
    this_update: dt.datetime | None = None
    next_update: dt.datetime | None = None
    #: The certificate that signed the revocation data (CA or OCSP responder).
    issuer_cert: object = None
    #: The data keeps status for expired certificates (CRL ExpiredCertsOnCRL
    #: or OCSP archiveCutoff dated on or before the certificate's notAfter).
    covers_expired: bool = False

    def fresh(self, at: dt.datetime) -> bool:
        """EN 319 102-1 clause 5.2.5.4 with nextUpdate - thisUpdate as the
        maximum accepted freshness; no nextUpdate means not fresh."""
        if self.this_update is None or self.next_update is None:
            return False
        return self.this_update > at - (self.next_update - self.this_update)


def _entry_status(revoked_at, reason, at, *, crl: bool) -> str:
    """The status a revocation entry gives at ``at``. ``removeFromCRL``
    releases a held certificate on a CRL (RFC 5280 clause 6.3.3); OCSP has no
    such reason (RFC 6960 §2.2), so there it does not make a certificate good."""
    if revoked_at > at or (crl and reason == x509.ReasonFlags.remove_from_crl):
        return "good"
    if reason == x509.ReasonFlags.certificate_hold:
        return "on_hold"
    return "revoked"


_EXPIRED_CERTS_ON_CRL = x509.ObjectIdentifier("2.5.29.60")
_HANDLED_CRL_EXTENSIONS = {
    ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.ISSUER_ALTERNATIVE_NAME, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    ExtensionOID.ISSUING_DISTRIBUTION_POINT,
}  # not freshestCRL: delta CRLs are not merged, so a critical one is not processed
#: CRL entry extensions processed; a CRL with any other critical entry
#: extension, on any entry, is not used (RFC 5280 clause 5.3).
_HANDLED_ENTRY_EXTENSIONS = (x509.CRLReason, x509.InvalidityDate)
_ENTRY_CHECKS: dict = {}


def _entries_processable(crl) -> bool:
    """No entry of ``crl`` carries a critical extension this verifier does not
    process (CertificateIssuer included: indirect CRLs are not used). Cached
    per CRL object, since a large CRL is read once per certificate otherwise."""
    hit = _ENTRY_CHECKS.get(id(crl))
    if hit is not None and hit[0] is crl:
        return hit[1]
    ok = all(not e.critical or isinstance(e.value, _HANDLED_ENTRY_EXTENSIONS)
             for entry in crl for e in entry.extensions)
    if len(_ENTRY_CHECKS) >= 64:
        _ENTRY_CHECKS.clear()
    _ENTRY_CHECKS[id(crl)] = (crl, ok)  # the CRL is kept, so its id stays unique
    return ok


def _generalized_time(raw: bytes):
    if len(raw) < 2 or raw[0] != 0x18 or raw[1] != len(raw) - 2:
        return None
    try:
        return dt.datetime.strptime(raw[2:].decode("ascii"), "%Y%m%d%H%M%SZ").replace(
            tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _idp_covers(idp, cert) -> bool:
    """RFC 5280 clause 6.3.3 (b): the CRL's scope includes ``cert``."""
    if idp.only_contains_attribute_certs or idp.indirect_crl or idp.only_some_reasons:
        return False
    is_ca = _is_ca(cert)
    if (idp.only_contains_user_certs and is_ca) or (idp.only_contains_ca_certs and not is_ca):
        return False
    if idp.relative_name is not None:
        return False  # not matched by this verifier: the CRL is not used
    if idp.full_name:
        # The certificate's distribution point names; without a CDP, RFC 5280
        # clause 6.3.3 takes the certificate issuer as the point's name.
        cdp = _ext(cert, x509.CRLDistributionPoints)
        names = {n for dp in (cdp or []) for n in (dp.full_name or dp.crl_issuer or [])}
        if not names:
            names = {x509.DirectoryName(cert.issuer)}
        if not names.intersection(idp.full_name):
            return False
    return True


def _weak_revocation_signature(hash_alg, signer_cert, issuer) -> bool:
    """Revocation data signed with MD5 / SHA-1, or by a delegated responder
    whose key is below the constraints, is not used (EN 319 102-1 clause
    5.2.8.4.1 NOTE 2). The issuer's own key is in the chain, so step 6
    judges it."""
    if isinstance(hash_alg, _WEAK_CERT_HASHES):
        return True
    return signer_cert is not issuer and key_failure(signer_cert) is not None


def _crl_candidate(cert, issuer, crl, at) -> RevocationStatus | None:
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        return None
    if _weak_revocation_signature(crl.signature_hash_algorithm, issuer, issuer):
        return None
    ku = _ext(issuer, x509.KeyUsage)
    if ku is not None and not ku.crl_sign:
        return None
    this_update = crl.last_update_utc
    if not within_validity(issuer, this_update):
        return None  # issued outside its issuer's validity (EN 319 102-1 step 4)
    covers_expired = False
    for ext in crl.extensions:
        if isinstance(ext.value, x509.DeltaCRLIndicator):
            return None
        if isinstance(ext.value, x509.IssuingDistributionPoint):
            if not _idp_covers(ext.value, cert):
                return None
        elif ext.oid == _EXPIRED_CERTS_ON_CRL:
            since = _generalized_time(ext.value.value)
            covers_expired = since is not None and since <= cert.not_valid_after_utc
        elif ext.critical and ext.oid not in _HANDLED_CRL_EXTENSIONS:
            return None  # RFC 5280 clause 5.2: unprocessable critical extension
    if this_update > cert.not_valid_after_utc and not covers_expired:
        return None  # issued after expiry; may no longer list the certificate (step 4 NOTE 4)
    if not _entries_processable(crl):
        return None
    status, revoked_at, reason = "good", None, None
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is not None:
        for e in entry.extensions:
            if isinstance(e.value, x509.CRLReason):
                reason = e.value.reason
            elif isinstance(e.value, x509.CertificateIssuer):
                return None  # an indirect CRL entry
            elif e.critical and not isinstance(e.value, x509.InvalidityDate):
                return None
        revoked_at = entry.revocation_date_utc
        status = _entry_status(revoked_at, reason, at, crl=True)
    return RevocationStatus(status, "CRL", revoked_at if status != "good" else None,
                            reason.name if reason and status != "good" else None,
                            this_update, crl.next_update_utc, issuer, covers_expired)


def _verify_with_key(public_key, signature: bytes, data: bytes, hash_alg) -> bool:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_alg))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            return False
    except Exception:  # noqa: BLE001 - InvalidSignature, or a hash the key cannot use
        return False
    return True


@lru_cache(maxsize=4096)
def _key_hash(cert) -> bytes | None:
    try:
        return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
    except Exception:  # noqa: BLE001
        return None


def _ocsp_responders(resp, issuer, pool):
    """Certificates that may have signed ``resp``: the issuer itself, or a
    delegated responder issued by it with id-kp-OCSPSigning (RFC 6960
    §4.2.2.2), from the response's certs field or the supplied certificates.
    Issuer signature checks are cached, so many responses over one pool cost
    one check per candidate."""
    def matches(cert):
        try:
            if resp.responder_name is not None:
                return cert.subject == resp.responder_name
            return _key_hash(cert) == resp.responder_key_hash
        except Exception:  # noqa: BLE001
            return False

    if matches(issuer):
        yield issuer
    for cand in list(resp.certificates) + list(pool):
        try:
            if cand.issuer != issuer.subject or not matches(cand):
                continue
            eku = _ext(cand, x509.ExtendedKeyUsage)
            ku = _ext(cand, x509.KeyUsage)
            crit = unprocessed_critical(cand, also=[ExtensionOID.EXTENDED_KEY_USAGE])
        except Exception:  # noqa: BLE001
            continue
        if eku is None or ExtendedKeyUsageOID.OCSP_SIGNING not in eku or crit:
            continue
        if ku is not None and not (ku.digital_signature or ku.content_commitment):
            continue  # RFC 5280 4.2.1.12: keyUsage and extendedKeyUsage both apply
        if unusable_signature(cand) is None and _issued_by(cand, issuer):
            yield cand


def _utc(obj, attr: str):
    """``obj.<attr>_utc`` (OCSP: cryptography >= 43), else the naive UTC value made aware."""
    if hasattr(obj, attr + "_utc"):
        return getattr(obj, attr + "_utc")
    value = getattr(obj, attr)
    return value if value is None else value.replace(tzinfo=dt.timezone.utc)


_ARCHIVE_CUTOFF = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.6")
_OCSP_NONCE = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")
_OCSP_CRL_REFERENCES = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.3")


#: DER content octets of the OIDs above, as they appear in singleExtensions.
_ARCHIVE_CUTOFF_DER = bytes.fromhex("2b0601050507300106")
_OCSP_CRL_REFERENCES_DER = bytes.fromhex("2b0601050507300103")


def _der_items(raw: bytes) -> list:
    """``(tag, content)`` of each DER element in ``raw`` (low tag numbers only)."""
    out, pos = [], 0
    while pos < len(raw):
        if pos + 2 > len(raw) or raw[pos] & 0x1F == 0x1F:
            raise ValueError("DER element")
        tag, n = raw[pos], raw[pos + 1]
        pos += 2
        if n & 0x80:
            k = n & 0x7F
            if not 1 <= k <= 4 or pos + k > len(raw):
                raise ValueError("DER length")
            n = int.from_bytes(raw[pos:pos + k], "big")
            pos += k
        if pos + n > len(raw):
            raise ValueError("DER element truncated")
        out.append((tag, raw[pos:pos + n]))
        pos += n
    return out


def _single_extensions(resp) -> list:
    """The singleExtensions of every SingleResponse, in order, as lists of
    ``(OID content octets, critical, extnValue)``. The library exposes them
    only for a one-response OCSP response, so they are read from the DER of
    ResponseData (RFC 6960 §4.2.1). Raises :class:`ValueError`."""
    ((tag, data),) = _der_items(resp.tbs_response_bytes)
    fields = _der_items(data)
    at = [t for t, _ in fields].index(0x18)  # producedAt; responses follow it
    if tag != 0x30 or fields[at + 1][0] != 0x30:
        raise ValueError("ResponseData")
    out = []
    for stag, single in _der_items(fields[at + 1][1]):
        parts = _der_items(single)  # certID, certStatus, thisUpdate, [0] nextUpdate, [1] exts
        if stag != 0x30 or len(parts) < 3:
            raise ValueError("SingleResponse")
        exts = []
        for etag, explicit in parts[3:]:
            if etag != 0xA1:
                continue
            ((seq, body),) = _der_items(explicit)
            for xtag, ext in _der_items(body):
                items = _der_items(ext)
                critical = len(items) == 3 and items[1] == (0x01, b"\xff")
                if seq != 0x30 or xtag != 0x30 or items[0][0] != 0x06 or items[-1][0] != 0x04:
                    raise ValueError("Extension")
                exts.append((items[0][1], critical, items[-1][1]))
        if len({oid for oid, _, _ in exts}) != len(exts):
            raise ValueError("an extension given twice")
        out.append(exts)
    return out


def _ocsp_extensions_processable(resp, singles: list) -> bool:
    """No critical response extension but the nonce, and no critical single
    extension, in any SingleResponse, but archiveCutoff and CRL references
    (RFC 6960 §4.4 follows the RFC 5280 extension model)."""
    if any(e.critical and e.oid != _OCSP_NONCE for e in resp.extensions):
        return False
    handled = (_ARCHIVE_CUTOFF_DER, _OCSP_CRL_REFERENCES_DER)
    return not any(critical and oid not in handled
                   for exts in singles for oid, critical, _ in exts)


def _archive_cutoff(exts: list):
    """RFC 6960 §4.4.4 archiveCutoff among one SingleResponse's extensions, or None."""
    for oid, _critical, value in exts:
        if oid == _ARCHIVE_CUTOFF_DER:
            return _generalized_time(value)
    return None


def _ocsp_candidates(cert, issuer, resp, pool, at) -> list:
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return []
    extensions = _single_extensions(resp)
    if not _ocsp_extensions_processable(resp, extensions):
        return []
    singles = []
    # the certificate first: no responder search otherwise
    for single, exts in zip(resp.responses, extensions, strict=True):
        try:
            req = ocsp.OCSPRequestBuilder().add_certificate(
                cert, issuer, single.hash_algorithm).build()
        except Exception:  # noqa: BLE001 - a CertID hash this library cannot compute
            continue
        if (single.serial_number == cert.serial_number
                and single.issuer_key_hash == req.issuer_key_hash
                and single.issuer_name_hash == req.issuer_name_hash):
            singles.append((single, exts))
    if not singles:
        return []
    responder = next((r for r in _ocsp_responders(resp, issuer, pool)
                      if _verify_with_key(r.public_key(), resp.signature,
                                          resp.tbs_response_bytes,
                                          resp.signature_hash_algorithm)), None)
    if responder is None or not within_validity(responder, _utc(resp, "produced_at")):
        return []
    if _weak_revocation_signature(resp.signature_hash_algorithm, responder, issuer):
        return []
    out = []
    for single, exts in singles:
        cutoff = _archive_cutoff(exts)
        covers_expired = cutoff is not None and cutoff <= cert.not_valid_after_utc
        if _utc(single, "this_update") > cert.not_valid_after_utc and not covers_expired:
            continue  # issued after expiry, without archiveCutoff (step 4 NOTE 4)
        reason = revoked_at = None
        if single.certificate_status == ocsp.OCSPCertStatus.GOOD:
            status = "good"
        elif single.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            revoked_at, reason = _utc(single, "revocation_time"), single.revocation_reason
            status = _entry_status(revoked_at, reason, at, crl=False)
        else:
            continue  # "unknown" says nothing about the certificate
        out.append(RevocationStatus(status, "OCSP", revoked_at if status != "good" else None,
                                    reason.name if reason and status != "good" else None,
                                    _utc(single, "this_update"), _utc(single, "next_update"),
                                    responder, covers_expired))
    return out


def _candidates(cert, issuer, crls, responses, pool, at) -> list:
    out = []
    for crl in crls:
        try:
            st = _crl_candidate(cert, issuer, crl, at)
        except Exception:  # noqa: BLE001 - an unprocessable CRL is not used
            st = None
        if st is not None:
            out.append(st)
    for resp in responses:
        try:
            out += _ocsp_candidates(cert, issuer, resp, pool, at)
        except Exception:  # noqa: BLE001 - an unprocessable response is not used
            continue
    return out


_SEVERITY = {"good": 0, "on_hold": 1, "revoked": 2}


def _latest(cands):
    """The latest issued instance (EN 319 102-1 clause 5.2.6.4 step 4); on a tie
    the more severe status."""
    return max(cands, key=lambda s: (s.this_update, _SEVERITY[s.status])) if cands else None


def _fetch(url: str, data: bytes | None = None, content_type: str | None = None) -> bytes | None:
    if not url.lower().startswith(("http://", "https://")):
        return None
    req = urllib.request.Request(url, data=data)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as r:  # noqa: S310 - http(s) only
            return r.read(MAX_FETCH_BYTES)
    except Exception:  # noqa: BLE001 - an unreachable responder is "unknown"
        return None


def _http(urls) -> list:
    return [u for u in urls if u.lower().startswith(("http://", "https://"))][:MAX_FETCH_URLS]


def fetch_online(cert, issuer) -> tuple:
    """CRLs from the certificate's CRL distribution points and OCSP responses
    from its AIA responders, at most :data:`MAX_FETCH_URLS` http(s) URLs of each.
    Returns ``(crls, responses)``; failures are empty."""
    crls, responses = [], []
    try:
        cdp = _ext(cert, x509.CRLDistributionPoints) or []
        urls = [n.value for p in cdp for n in (p.full_name or [])
                if isinstance(n, x509.UniformResourceIdentifier)]
    except Exception:  # noqa: BLE001
        urls = []
    for url in _http(urls):
        raw = _fetch(url)
        if raw:
            try:
                crls += crls_from_bytes(raw)
            except Exception:  # noqa: BLE001
                pass
    try:
        aia = _ext(cert, x509.AuthorityInformationAccess) or []
        urls = [d.access_location.value for d in aia
                if d.access_method == AuthorityInformationAccessOID.OCSP
                and isinstance(d.access_location, x509.UniformResourceIdentifier)]
        body = ocsp.OCSPRequestBuilder().add_certificate(
            cert, issuer, hashes.SHA1()).build().public_bytes(serialization.Encoding.DER)
    except Exception:  # noqa: BLE001
        urls = []
    for url in _http(urls):
        raw = _fetch(url, body, "application/ocsp-request")
        if raw:
            try:
                responses.append(ocsp.load_der_ocsp_response(raw))
            except Exception:  # noqa: BLE001
                pass
    return crls, responses


def revocation_status(cert, issuer, crls, responses, at, *, pool=(),
                      online=False) -> RevocationStatus:
    """Status of ``cert`` from the latest applicable CRL or OCSP response.

    With ``online``, the certificate's own CDP and AIA OCSP URLs are asked
    whenever the latest supplied or embedded data is not fresh at ``at``
    (EN 319 102-1 clause 5.2.5.4), so that data the signer embedded cannot
    stand in for the fetch; never for a certificate whose signature
    ``issuer`` does not verify (the caller passes ``online`` only when the
    links above verify too). ``unknown`` when no source answers.
    """
    cands = _candidates(cert, issuer, crls, responses, pool, at)
    best = _latest(cands)
    if online and signature_status(cert, issuer) is True and (
            best is None or not best.fresh(at)):
        more_crls, more_resps = fetch_online(cert, issuer)
        best = _latest(cands + _candidates(cert, issuer, more_crls, more_resps, pool, at))
    return best or RevocationStatus("unknown")
