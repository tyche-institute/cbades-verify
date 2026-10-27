<!-- SPDX-License-Identifier: Apache-2.0 -->
# cbades-verify

A research verifier for CB-AdES (CBOR Advanced Electronic Signatures, ETSI
TS 119 152-1 V1.1.1) baseline **B-B** signatures. It reads COSE_Sign1 and
COSE_Sign messages (CBOR Object Signing and Encryption, RFC 9052), tagged or
untagged, and validates them in the order of the basic signature validation
process of ETSI EN 319 102-1 V1.4.1, with the built-in constraint set below.
Each signature gets an EN 319 102-1 indication (VALID, INVALID or
INDETERMINATE), a sub-indication and a one-line reason.

Status, 27 October 2026: version 0.1.0, not yet released.

**Scope.** This is research and interoperability-testing software. It is not
a signature validation service and is not offered or operated as one; it is
not a qualified validation service in the sense of Regulation (EU) No
910/2014. It does not check trusted-list or qualified status, and its
verdicts hold only for the constraints described here.

Requirements: Python 3.10 or later, `cbor2` 6.1.1 or later (below 7) and
`cryptography` 42 or later. An older `cbor2` is refused at import: 6.0.0 to
6.1.0 misread byte strings of 4 KiB or more.

## Usage

```bash
pip install .

# own test PKI and vectors (new random bytes each run, fixed verdicts)
python -m cbades_verify.vectors /tmp/cbades

cbades-verify /tmp/cbades/signatures \
    --trust-anchor /tmp/cbades/pki/root.pem --material /tmp/cbades/pki \
    --policy /tmp/cbades/data/policy.der --data-dir /tmp/cbades/data \
    --payload /tmp/cbades/data/payload.txt \
    --validation-time 2026-10-26T12:00:00Z
```

`python -m cbades_verify` runs the same command without installing the
package. It prints one line per file (case name, indication, sub-indication,
reason); `--json` prints all results as one JSON document.

Inputs:

- trust anchors (`--trust-anchor`, repeatable; required);
- certificates, certificate revocation lists (CRLs) and DER-encoded Online
  Certificate Status Protocol (OCSP) responses (`--cert`, `--crl`, `--ocsp`),
  or a whole `--material` directory (subdirectories included; symbolic links
  to directories inside it are not followed), whose files are recognised by content;
- signature-policy documents: `--policy FILE` is matched to `sigPId` by
  digest, and `--policy-map ID FILE` names the document for one policy id
  (for example `urn:oid:1.2.3`, a URI of at most 1024 characters, given once);
  for a known policy id, `--policy-map` is the safer choice;
- a detached payload (`--payload`), and a directory where `sigD` references
  are resolved (`--data-dir`): a relative reference is looked up under that
  directory (subdirectories included), then by its file name; nothing outside
  the directory is read.

Options:

- `--lenient` reports TS 119 152-1 profile deviations as notes instead of
  FORMAT_FAILURE (see below);
- `--unknown-policy accept` accepts a `sigPId` whose document is not
  available, with a note;
- `--validation-time` sets the validation time, in the form
  `YYYY-MM-DDTHH:MM:SS[.ffffff][Z|+HH:MM|-HH:MM]` (UTC when no offset is
  given; default: now);
- `--revocation ignore` skips revocation checking, and a VALID result says
  so;
- `--revocation-freshness strict` applies the EN 319 102-1 freshness check
  (clause 5.2.5.4: thisUpdate within nextUpdate − thisUpdate of the
  validation time); by default the latest data at hand is used, fresh or
  not, and a VALID result says which of the two applied;
- `--online` fetches CRLs and OCSP responses from the certificates' own CRL
  distribution points and authority information access URLs when the
  supplied and embedded data for a certificate is not fresh in that sense.
  These URLs come from certificates the signature may carry, so the verifier
  contacts hosts the signer chose: only for a certificate whose signatures
  up to the trust anchor verify, at most 3 http(s) URLs of each kind per
  certificate, 15 seconds each.

Exit status: 0 when every file was processed (whatever its verdict), 1 when a
file could not be read or processed (its result is INDETERMINATE with an
`internal error` reason) or when the results cannot be written (a closed
pipe), 2 on a usage error: a bad or empty option value (a `--policy-map` id
that is not a URI or is given twice included), an empty or missing input, an
input directory that cannot be listed, a `--material` or
`--data-dir` directory that cannot be read, or a file named by `--trust-anchor`,
`--cert`, `--crl`, `--ocsp`, `--policy`, `--policy-map` or `--payload`, or
found in a `--material` directory, that cannot be read or loaded. Files in a
`--material` directory that do not parse are skipped and listed on stderr,
and so are the
subdirectories of an input directory, which are not searched. A file name
that is not UTF-8 is printed with its undecodable bytes as `\xNN`; in text
output, control characters in names and reasons are printed as `\xNN` or
`\uNNNN` escapes, so an input cannot forge an output line.

As a library:

```python
from cbades_verify import Context, validate_file

result = validate_file("signature.cbor", Context(trust_anchors=[root]))
print(result.indication, result.subindication, result.detail)
```

`cbades_verify.cli` exposes `build_parser`, `prepare` and `verify_files` for
tools that do more with the results than print them.

## What is checked, and the result

| Step (EN 319 102-1) | Defect | Result |
|---|---|---|
| Format | not one well-formed COSE_Sign / COSE_Sign1: CBOR that is not well-formed (a stray break byte included), more than 100 000 data items in the whole input (header bstrs and indefinite-length chunks included), trailing bytes (also inside header bstrs), wrong tag, duplicate labels (compared as CBOR values: 1, 1.0 and true are three keys), labels that are not int or tstr (a tagged label too, the self-described tag 55799 included), a map key that is an unassigned simple value, a nil unprotected header, a COSE_Sign with more than 64 signatures | INVALID / FORMAT_FAILURE |
| Format | `crit` empty, holding a non-label, a label absent from its header, or one this verifier does not understand | INVALID / FORMAT_FAILURE |
| Format | `sigD` not in `crit`, with an attached payload, with a content type in any header (protected, unprotected or `uHeaders`, at either layer), at the COSE_Sign body layer; malformed `mId`, `pars`, `hashM`, `hashV`; `ObjectIdByURIHash` without digests | INVALID / FORMAT_FAILURE |
| Format | `uHeaders` at the COSE_Sign body layer (protected or not); malformed `x5t`, `x5ts`, `x5chain`, `x5bag`, CWT Claims, `iat`, `sigPId`, `alg`; a `sigPId` id that is not a URI in RFC 3986 syntax or is longer than 1024 characters; a content type that is neither tstr nor uint (RFC 9052 §3.1); keys that are not int or tstr inside `sigD`, CWT Claims or `sigPId`; an unparseable signed certificate | INVALID / FORMAT_FAILURE |
| Format (profile) | an unprotected member other than `uHeaders`; `uHeaders` in a signer's protected header; profiled parameters at the COSE_Sign body layer; signed-only parameters inside `uHeaders`; no CWT `iat`; no signed certificate reference; a text `alg`; a text digest identifier (`'SHA-256'`) in `x5t`, `x5ts`, `sigPId` or `hashM`; a 1-element `x5chain` array; `ctys` not matching `pars`; `hashM` with `ObjectIdByURI` | INVALID / FORMAT_FAILURE (a note with `--lenient`) |
| Signing certificate | the signed `x5chain[0]` differs from `x5t` / `x5ts[0]`; no certificate matches the reference; unsupported reference digest | INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND |
| Validation context | no policy document for the `sigPId` | INDETERMINATE / SIGNATURE_POLICY_NOT_AVAILABLE |
| Validation context | the document for the `sigPId` does not match the digest: the `--policy-map` document for the id, or, when no document matches, a `sigPSt` copy or a `--policy` file naming the policy id as a whole token; `digPSp`; unsupported policy digest | INDETERMINATE / POLICY_PROCESSING_ERROR |
| X.509 | no chain from the signing certificate to a trust anchor | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| X.509 | a certificate signature does not verify; a CA not valid at the validation time (shell model); not a CA, no keyCertSign, pathLenConstraint exceeded; a signing certificate whose keyUsage has neither digitalSignature nor nonRepudiation; a critical extension this verifier does not process (see Limits; the detail names its OID) | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| X.509 | signing certificate revoked; CA certificate revoked or on hold | INDETERMINATE / REVOKED_NO_POE, REVOKED_CA_NO_POE |
| X.509 | signing certificate on hold; no revocation status (with `--revocation require`); revocation data not fresh (with `--revocation-freshness strict`) | INDETERMINATE / TRY_LATER |
| X.509 | MD5 / SHA-1 or unsupported certificate signature algorithm; RSA or DSA key < 2048 bits or EC key < 256 bits, the trust anchor's key included; a key type this library cannot load | INDETERMINATE / CRYPTO_CONSTRAINTS_FAILURE_NO_POE |
| X.509 | signing certificate outside its validity range: known not revoked / otherwise | INDETERMINATE / OUT_OF_BOUNDS_NOT_REVOKED, OUT_OF_BOUNDS_NO_POE |
| X.509 | issuer of the revocation data not valid at the validation time | INDETERMINATE / REVOCATION_OUT_OF_BOUNDS_NO_POE |
| Crypto | signature does not verify over the RFC 9052 Sig_structure; an ES* key on a curve of 256 bits or more outside P-256/384/521 (the detail names the curve; Brainpool is a note with `--lenient`); a signing key of a type that does not fit `alg` (an X25519 or DSA key under ES256), which can never verify | INVALID / SIG_CRYPTO_FAILURE |
| Crypto | `sigD` object digest differs from `hashV` | INVALID / HASH_FAILURE |
| Crypto | unsupported signature algorithm; a signing key this library cannot load (an unknown curve); unsupported `sigD` digest | INDETERMINATE / CRYPTO_CONSTRAINTS_FAILURE_NO_POE |
| Crypto | detached payload or `sigD` object not available; unknown `sigD` mechanism; more than 1000 `sigD` objects, or more than 256 MiB of `sigD` data, in one input, all its signers and repeats counted (a resource limit) | INDETERMINATE / SIGNED_DATA_NOT_FOUND |
| Acceptance | `sigD` or `sigPId` digest SHA-1 or SHA-256/64 | INDETERMINATE / CRYPTO_CONSTRAINTS_FAILURE_NO_POE |
| Acceptance | an `x5ts` reference that matches no certificate of the validated chain | INDETERMINATE / SIG_CONSTRAINTS_FAILURE (a note with `--lenient`) |

Order (EN 319 102-1 V1.4.1 clause 5.3.4): format, signing certificate and policy
stop at their first failure. The X.509 result is kept, and the cryptographic
check runs whatever it is. A cryptographic failure wins, so a broken signature
gives INVALID / SIG_CRYPTO_FAILURE even when the chain is missing or the
certificate expired. Otherwise a failed X.509 result is returned, and the
acceptance checks run only after both passed. In a COSE_Sign, the result for
the file is the worst signer result (INVALID, then INDETERMINATE, then VALID),
and its detail gives each signer's indication and detail in turn.

X.509 validation follows EN 319 102-1 clause 5.2.6.4. Prospective chains are
built in two passes. The first uses only links whose certificate signature
verifies, found from the trust anchors down, so a same-named decoy or a wrong
AKI does not hide the real chain. Only when that pass finds nothing are
chains built by name (with AKI/SKI pruning), so that a broken link is reported
as CERTIFICATE_CHAIN_GENERAL_FAILURE. The work is bounded: at most 16 chains
of up to 10 certificates (8 intermediate CAs between the signing certificate
and the trust anchor), 10 000 candidate steps and 2 000 signature checks.
Chains are tried in turn: a chain that fails goes on to the next one, except
for the final results (signer revoked, signer on hold, signing certificate
out of bounds, revocation issuer out of bounds).

Revocation uses the latest issued applicable CRL or OCSP response, on a tie
the more severe one. Data issued after the validation time counts. Data issued
after the certificate expired counts only when it keeps status for expired
certificates (CRL `ExpiredCertsOnCRL`, OCSP `archiveCutoff`, dated on or
before notAfter); a CA may drop an expired certificate from later CRLs (RFC
5280 clause 3.3). A CRL counts for a certificate only when its issuing
distribution point covers it (for a certificate without a CDP, the
distribution point is the issuer name). `certificateHold` gives on hold.
`removeFromCRL` clears an entry on a CRL only; an OCSP response that says
revoked counts as revoked whatever its reason. OCSP responses are accepted from the CA or from a
delegated responder (id-kp-OCSPSigning, issued by the CA, valid at
producedAt), found in the response or among the supplied and embedded
certificates. A delegated responder certificate needs a keyUsage that allows
signing (digitalSignature or nonRepudiation) when it has one (RFC 5280 clause
4.2.1.12), and is not used with a critical extension other than those listed
under Limits. Revocation data signed with MD5 or SHA-1, or by a delegated
responder whose key is below the constraints, is not used. A CRL with a
critical extension this verifier does not process (`freshestCRL` included,
since delta CRLs are not merged) or with such a critical extension on any of
its entries is not used (RFC 5280 clauses 5.2 and 5.3). An OCSP response with
a critical response extension other than the nonce, or a critical single
extension other than `archiveCutoff` and CRL references (in any of its
SingleResponses), is not used. `archiveCutoff` is read from the
SingleResponse for the certificate.

Validation data in the signature is used: the signed `x5chain` and `x5bag`,
and in `uHeaders` the unsigned `x5chain`, `x5bag` and `valData` (`xVals`
certificates; `rVals` CRLs and OCSP responses, DER encoding only). Unsigned
items that do not parse are dropped with a note. A signature carries at most
256 certificates, 64 CRLs and 64 OCSP responses; items beyond that are dropped
with a note.

Signature policy: a `--policy-map` document for the policy id decides,
for every equivalent spelling of the id: ids are compared after RFC 3986
clause 6.2 normalisation (scheme and host in any case, percent-encoding, dot
segments, a default port), with the URN namespace in any case and the
components after the name ignored (RFC 8141), and OID arcs with leading zeros.
Percent-encoded unreserved characters are decoded in a URN too, which RFC 8141
does not do, so a `--policy-map` entry holds for more spellings, never fewer.
If there is no `--policy-map` document, any matching document is accepted: a
`--policy` file, or a `sigPSt` copy, which a VALID result then names. A
`sigPSt` copy that does not match gets a note, since anyone can add one to
the unsigned header. A policy document "names" the id only as
a whole token (`1.2.3.4` is not `1.2.3.4.5`).

Strict and lenient: by default the TS 119 152-1 profile rules are format
rules. `--lenient` (`Context.strict=False`) records them in the result detail
instead. It also accepts Brainpool keys under the polymorphic ES* algorithms
(with a note), and uses `x5chain` and `x5bag` placed directly in the
unprotected header. RFC 9052 and CBOR well-formedness stay hard rules in both
modes.

Algorithms: ES256/384/512 (polymorphic: the curve and coordinate size come
from the key; P-256, P-384, P-521), ESP256/384/512, ESB256/384/512, EdDSA,
Ed25519, Ed448, PS256/384/512 and RS256/384/512. Digests for `x5t`, `x5ts`,
`sigPId` and `sigD`: the COSE-registered SHA-1, SHA-256/64, SHA-256,
SHA-512/256, SHA-384, SHA-512, SHAKE128 and SHAKE256.

## Limits

- B-B only. Time-stamps and the other qualifying properties (`srCms`,
  `sigPl`, `srAts`, `adoTst`) are not validated. There is no proof of
  existence (POE), so a past revocation or expiry ends in `*_NO_POE`. When a
  content time-stamp (`adoTst`) is present, the result detail says that it
  was not evaluated.
- The validation constraints are the built-in ones above.
- A signing certificate that is itself a trust anchor has no chain and no
  issuer to give its revocation status. Its keyUsage, critical extensions,
  key and validity range are checked; its revocation is not, and a VALID
  result says so.
- Processed certificate extensions: basicConstraints, keyUsage, the key
  identifiers, CRL distribution points, authority information access and the
  alternative names; extendedKeyUsage only for delegated OCSP responders.
  Name constraints, certificate policies, policy mappings, policy constraints
  and every other extension are not processed: such an extension marked
  critical rejects the certificate (RFC 5280 clause 6.1.4 (o)), and a
  non-critical one is ignored.
- Trusted-list (qualified) status and OCSP responder revocation
  (`id-pkix-ocsp-nocheck`) are not checked. The keyUsage of a CA that signs
  OCSP responses itself is not checked, as is common practice.
- Delta CRLs, indirect CRLs and CRLs limited to some reasons are skipped, so
  they never make a certificate look good. RSASSA-PSS signed OCSP responses
  are not supported. ESB320 (brainpoolP320r1) is not supported. `x5u` is not
  fetched.
- `sigD` references are resolved inside `--data-dir` only (as a relative
  path, then by file name). `ObjectIdByURI` and `ObjectIdByURIHash` are
  supported.
- One input holds at most 20 MiB (a larger file is not read) and 100 000 CBOR
  data items in all, nested header byte strings and indefinite-length chunks
  included; a COSE_Sign holds at most 64 signatures. Beyond any of these
  limits, and for a `sigPId` id longer than 1024 characters, the result is
  INVALID / FORMAT_FAILURE. `sigD` reads at most 1000 data objects and
  256 MiB of data per input, all its signers and repeats counted; beyond that
  the result is INDETERMINATE / SIGNED_DATA_NOT_FOUND. A result detail keeps
  at most 32 notes, a repeated note once with its count: the first and the
  last ones, with the number left out between them.

## Tests and evidence

`cbades_verify/vectors.py` generates its own test PKI and vectors from the
public specifications; no third-party test data is included. There are 15
positive cases (ES256/384/512, PS256, RS256, Ed25519, Ed448, COSE_Sign with
two signers, detached payload, both `sigD` mechanisms, a signed chain,
`x5ts`, no policy) and 8 negative cases. The 8 negative cases follow the
eight B-BN defect classes listed in clause 7.2.1 of ETSI's public *Technical
Report of the JAdES Remote Plugtests™ Event (Nov-Dec 2021)*, carried over
from JWS to COSE: a signature not over the signed structure, no claimed
signing time, an expired signing certificate, a revoked signing certificate,
a wrong signing-certificate digest, a signed header parameter missing from
`crit`, a wrong signature-policy digest, and an unknown label in `crit`.

- `tests/test_cbades_negative.py` checks every vector's verdict, the
  revocation sources and the command line.
- `tests/test_cbades_hardening.py` has at least one test for each row of the
  table above, and tests the X.509 and revocation steps (two-pass chains,
  decoys, large pools, post-expiry revocation data and `archiveCutoff`, CRL
  scope, weak and unprocessable responders, critical extensions, a signing
  certificate that is a trust anchor), the embedded validation data and its
  limits, the policy step (the spellings of a policy id included), CBOR tags,
  map keys and input bounds, the bound on notes, `--online` against a local
  server (CRL and OCSP, the URL limit, no fetch through an unverified link),
  and the command line (usage errors, the time form, unreadable material, a
  closed output pipe).
- `tests/test_crosscheck_pycose.py` verifies 14 of the 16 signatures in the
  positive vectors with an independent COSE library (`pycose`). pycose 1.1
  cannot read the fully specified Ed25519 and Ed448 algorithms, so for those
  two the test builds the RFC 9052 Sig_structure itself and checks the
  signature with `cryptography`. It also checks that pycose rejects the N1
  vector.
- `tests/test_codepoints.py` pins every COSE label and algorithm number the
  verifier uses to a literal value with its source, and checks that every RFC
  the sources cite is on a reviewed list.

The X.509, policy and validation-process verdicts rest on these generated
vectors only. No interoperability-event results are cited here.

```bash
pip install -e '.[dev]'
pytest
ruff check .
```

## Citation and licence

Cite with `CITATION.cff`. Licensed under the Apache License 2.0
(`LICENSE`); see `NOTICE`.
