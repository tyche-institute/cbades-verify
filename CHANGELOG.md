<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

## 0.1.0 (unreleased)

First version.

- Decoding of COSE_Sign1 and COSE_Sign, tagged or untagged, with the RFC 9052
  well-formedness rules and the TS 119 152-1 V1.1.1 B-B profile rules (strict,
  or as notes with `--lenient`).
- Validation in the order of the EN 319 102-1 V1.4.1 basic signature
  validation process: signing-certificate identification, signature policy
  (a `--policy-map` document holds for the equivalent spellings of its
  policy id),
  X.509 validation with CRL and OCSP revocation, cryptographic verification
  (including `sigD` detached data objects) and signature acceptance.
- Bounded input: at most 20 MiB and 100 000 CBOR data items per input
  (nested header byte strings and indefinite-length chunks included) and 64
  COSE_Sign signers; `sigD` reads at most 1000 data objects and 256 MiB per
  input; a `sigPId` id is a URI in RFC 3986 syntax of at most 1024 characters.
  Tags on map labels, the self-described tag 55799 included, are format
  failures, and so are map keys that are unassigned simple values.
  A result detail keeps at most 32 notes, repeats folded.
- `--online` fetches only for certificates whose signatures up to the trust
  anchor verify, at most 3 URLs of each kind per certificate.
- Own test PKI and vectors: 15 positive and 8 negative cases.
- Command line `cbades-verify` with text or JSON output; control characters
  from the input are escaped in text output. A COSE_Sign line gives each
  signer's indication and detail.
- Needs `cbor2` 6.1.1 or later; older releases are refused at import.
