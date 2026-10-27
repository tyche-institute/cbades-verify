# SPDX-License-Identifier: Apache-2.0
"""Header labels, algorithm code points and EN 319 102-1 result names.

Labels 261-268 are the CB-AdES header parameters of ETSI TS 119 152-1 V1.1.1
(Table 1 and Table 8), as registered in the IANA "COSE Header Parameters"
registry. The rest come from RFC 9052, RFC 9338, RFC 9360 and RFC 9597. Result
names are those of EN 319 102-1 V1.4.1 clause 5.1.3.
"""
from __future__ import annotations

# --- COSE structures (RFC 9052 §2) ---------------------------------------
TAG_COSE_SIGN = 98
TAG_COSE_SIGN1 = 18

# --- IETF header parameters ------------------------------------------------
HDR_ALG = 1
HDR_CRIT = 2
HDR_CONTENT_TYPE = 3
HDR_KID = 4
HDR_COUNTER_SIGNATURE_V2 = 11
HDR_COUNTER_SIGNATURE0_V2 = 12
HDR_CWT_CLAIMS = 15  # RFC 9597
HDR_X5BAG = 32  # RFC 9360
HDR_X5CHAIN = 33
HDR_X5T = 34
HDR_X5U = 35

#: CWT claim key for "iat" (RFC 8392 §3.1.6).
CWT_IAT = 6

# --- CB-AdES header parameters (TS 119 152-1 Table 1 / Table 8) -----------
HDR_X5TS = 261
HDR_SRCMS = 262
HDR_SIGPL = 263
HDR_SRATS = 264
HDR_ADOTST = 265
HDR_SIGPID = 266
HDR_SIGD = 267
HDR_UHEADERS = 268

#: Labels this verifier understands, for RFC 9052 §3.1 ``crit`` processing.
#: "Understands" means it can process the parameter or knows that ignoring it
#: does not change the B-B verdict (x5u, srCms, sigPl, srAts are qualifying
#: attributes, not inputs to the signature check). adoTst (265) is left out:
#: a content time-stamp is proof of existence and can change the verdict
#: (EN 319 102-1 clause 5.3.4 step 4), and this verifier does not evaluate it.
UNDERSTOOD_LABELS = frozenset({
    HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS,
    HDR_X5BAG, HDR_X5CHAIN, HDR_X5T, HDR_X5U,
    HDR_X5TS, HDR_SRCMS, HDR_SIGPL, HDR_SRATS, HDR_SIGPID, HDR_SIGD,
})

#: Signed CB-AdES parameters and CWT Claims: they belong in a protected header
#: (TS 119 152-1 clauses 5.1.9 and 5.2.1), never inside uHeaders.
SIGNED_ONLY_LABELS = frozenset({
    HDR_CWT_CLAIMS, HDR_X5TS, HDR_SRCMS, HDR_SIGPL, HDR_SRATS, HDR_ADOTST, HDR_SIGPID,
    HDR_SIGD,
})

#: Parameters that TS 119 152-1 clause 4.4 places at the signer layer of a
#: COSE_Sign ("shall be placed at the signer layer").
SIGNER_LAYER_LABELS = frozenset({
    HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, HDR_COUNTER_SIGNATURE_V2, HDR_COUNTER_SIGNATURE0_V2,
    HDR_CWT_CLAIMS, HDR_X5CHAIN, HDR_X5T, HDR_X5U,
    HDR_X5TS, HDR_SRCMS, HDR_SIGPL, HDR_SRATS, HDR_ADOTST, HDR_SIGPID, HDR_SIGD,
})

# --- uHeaders instances (TS 119 152-1 Table 8) ------------------------------
UH_SIGTST = 1
UH_VALDATA = 2
UH_SIGPST = 7
VALDATA_XVALS = 1
VALDATA_RVALS = 2
RVALS_CRL = 1
RVALS_OCSP = 2
PKIOB_VAL = 1
PKIOB_ENCODING = 2
#: pkiOb encoding when the value is DER (also the default when absent).
DER_ENCODING_URI = "http://uri.etsi.org/01903/v1.2.2#DER"

# --- sigPId (TS 119 152-1 clause 5.2.7, Table 5) ---------------------------
SIGPID_ID = 1
SIGPID_DIGALGVAL = 2
SIGPID_DIGPSP = 3
SIGPID_QUALS = 4
OID_ID = 1  # obId.id (TS 119 152-1 clause 5.4.1)

# --- sigD (TS 119 152-1 clause 5.2.8, Table 7) ----------------------------
SIGD_MID = 1
SIGD_PARS = 2
SIGD_HASHM = 3
SIGD_HASHV = 4
SIGD_CTYS = 5
SIGD_MECH_BY_URI = "http://uri.etsi.org/19152/ObjectIdByURI"
SIGD_MECH_BY_URI_HASH = "http://uri.etsi.org/19152/ObjectIdByURIHash"
SIGPST_DOC = 1  # sigPSt: {1: DocOrLocalURI {1: sigPolDoc // 2: sigPolLocalURI}}
SIGPST_POLDOC = 1

# --- EN 319 102-1 indications and sub-indications -------------------------
VALID = "VALID"  # TOTAL-PASSED
INVALID = "INVALID"  # TOTAL-FAILED
INDETERMINATE = "INDETERMINATE"

# Sub-indications used by this verifier (EN 319 102-1, Table 5).
FORMAT_FAILURE = "FORMAT_FAILURE"
HASH_FAILURE = "HASH_FAILURE"
SIG_CRYPTO_FAILURE = "SIG_CRYPTO_FAILURE"
CRYPTO_CONSTRAINTS_FAILURE = "CRYPTO_CONSTRAINTS_FAILURE"
CRYPTO_CONSTRAINTS_FAILURE_NO_POE = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
SIG_CONSTRAINTS_FAILURE = "SIG_CONSTRAINTS_FAILURE"
NO_SIGNING_CERTIFICATE_FOUND = "NO_SIGNING_CERTIFICATE_FOUND"
NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND"
CERTIFICATE_CHAIN_GENERAL_FAILURE = "CERTIFICATE_CHAIN_GENERAL_FAILURE"
SIGNATURE_POLICY_NOT_AVAILABLE = "SIGNATURE_POLICY_NOT_AVAILABLE"
POLICY_PROCESSING_ERROR = "POLICY_PROCESSING_ERROR"
REVOKED_NO_POE = "REVOKED_NO_POE"
REVOKED_CA_NO_POE = "REVOKED_CA_NO_POE"
OUT_OF_BOUNDS_NO_POE = "OUT_OF_BOUNDS_NO_POE"
OUT_OF_BOUNDS_NOT_REVOKED = "OUT_OF_BOUNDS_NOT_REVOKED"
REVOCATION_OUT_OF_BOUNDS_NO_POE = "REVOCATION_OUT_OF_BOUNDS_NO_POE"
TRY_LATER = "TRY_LATER"
SIGNED_DATA_NOT_FOUND = "SIGNED_DATA_NOT_FOUND"
