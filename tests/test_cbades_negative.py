# SPDX-License-Identifier: Apache-2.0
"""CB-AdES B-B verifier (cbades_verify) against our own generated vectors.

Every vector, its PKI and the expected EN 319 102-1 result come from
cbades_verify.vectors; nothing here is third-party test data.
"""
from __future__ import annotations

import dataclasses
import json

import cbor2
import pytest

from cbades_verify import Context, validate_bytes, validate_file
from cbades_verify import vectors as V
from cbades_verify.cli import main
from cbades_verify.labels import (
    FORMAT_FAILURE,
    HASH_FAILURE,
    HDR_ADOTST,
    HDR_X5CHAIN,
    INDETERMINATE,
    INVALID,
    NO_CERTIFICATE_CHAIN_FOUND,
    REVOKED_CA_NO_POE,
    REVOKED_NO_POE,
    SIG_CRYPTO_FAILURE,
    SIGNATURE_POLICY_NOT_AVAILABLE,
    SIGNED_DATA_NOT_FOUND,
    TRY_LATER,
    VALID,
)


@pytest.fixture(scope="module")
def pki():
    return V.TestPKI()


@pytest.fixture(scope="module")
def vset(pki, tmp_path_factory):
    out = tmp_path_factory.mktemp("cbades")
    manifest = V.write_set(out, pki)
    return out, manifest


@pytest.fixture
def ctx(pki, vset):
    out, _ = vset
    return Context(
        trust_anchors=[pki.root],
        crls=[pki.ca_crl, pki.root_crl],
        policies=[V.policy_document()],
        detached_payload=V.PAYLOAD,
        data_dir=out / "data",
        validation_time=V.VALIDATION_TIME,
    )


def _with(ctx, **changes):
    return dataclasses.replace(ctx, **changes)


def _vector(vset, case) -> bytes:
    out, _ = vset
    return (out / "signatures" / f"{case}.cbor").read_bytes()


def _cases():
    # Case names only; the PKI behind them is built once per module.
    return sorted(V.build_vectors(V.TestPKI()))


CASES = _cases()


def test_set_has_eight_negatives_and_positives(vset):
    _, manifest = vset
    neg = [c for c in manifest["cases"] if c.startswith("N")]
    pos = [c for c in manifest["cases"] if c.startswith("P")]
    assert len(neg) == 8
    assert pos and all(manifest["cases"][c]["indication"] == VALID for c in pos)
    assert all(manifest["cases"][c]["indication"] != VALID for c in neg)


@pytest.mark.parametrize("case", CASES)
def test_vector_verdict(case, vset, ctx):
    out, manifest = vset
    want = manifest["cases"][case]
    got = validate_file(out / "signatures" / f"{case}.cbor", ctx)
    assert (got.indication, got.subindication) == (want["indication"], want["subindication"]), \
        got.detail


# --- revocation sources -------------------------------------------------------------

def test_ocsp_good_replaces_the_crl(pki, vset, ctx):
    c = _with(ctx, crls=[pki.root_crl], ocsp_responses=[pki.ocsp_response(pki.ok)])
    assert validate_bytes(_vector(vset, "P1-es256-sign1"), c).indication == VALID


def test_ocsp_revoked(pki, vset, ctx):
    resp = pki.ocsp_response(pki.ok, revoked_at=V._t(2026, 9, 1))
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, crls=[pki.root_crl],
                                                              ocsp_responses=[resp]))
    assert (r.indication, r.subindication) == (INDETERMINATE, REVOKED_NO_POE)


def test_revocation_after_validation_time_is_not_a_revocation(pki, vset, ctx):
    resp = pki.ocsp_response(pki.ok, revoked_at=V._t(2026, 10, 21))
    c = _with(ctx, crls=[pki.root_crl], ocsp_responses=[resp],
              validation_time=V._t(2026, 10, 20) + (V.VALIDATION_TIME - V._t(2026, 10, 26)))
    assert validate_bytes(_vector(vset, "P1-es256-sign1"), c).indication == VALID


def test_ocsp_from_an_unauthorised_responder_is_ignored(pki, vset, ctx):
    other = V.TestPKI()  # its responder is not issued by our issuing CA
    resp = other.ocsp_response(pki.ok)
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, crls=[pki.root_crl],
                                                              ocsp_responses=[resp]))
    assert (r.indication, r.subindication) == (INDETERMINATE, TRY_LATER)


def test_no_revocation_data(vset, ctx):
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, crls=[]))
    assert (r.indication, r.subindication) == (INDETERMINATE, TRY_LATER)
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, crls=[], revocation="ignore"))
    assert r.indication == VALID


def test_revoked_issuing_ca(pki, vset, ctx):
    root_crl = V._crl(pki.root, pki.root_key, [(pki.ca.serial_number, V._t(2026, 7, 1))])
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, crls=[pki.ca_crl, root_crl]))
    assert (r.indication, r.subindication) == (INDETERMINATE, REVOKED_CA_NO_POE)


def test_crl_signed_by_someone_else_is_ignored(pki, vset, ctx):
    other = V.TestPKI()
    forged = V._crl(pki.ca, other.ca_key)  # right issuer name, wrong key
    r = validate_bytes(_vector(vset, "N4-revoked-signer"), _with(ctx, crls=[forged,
                                                                           pki.root_crl]))
    assert (r.indication, r.subindication) == (INDETERMINATE, TRY_LATER)


# --- chain, policy, data ------------------------------------------------------------

def test_foreign_trust_anchor(vset, ctx):
    r = validate_bytes(_vector(vset, "P1-es256-sign1"),
                       _with(ctx, trust_anchors=[V.TestPKI().root]))
    assert (r.indication, r.subindication) == (INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND)


def test_policy_document_not_supplied(vset, ctx):
    r = validate_bytes(_vector(vset, "P1-es256-sign1"), _with(ctx, policies=[]))
    assert (r.indication, r.subindication) == (INDETERMINATE, SIGNATURE_POLICY_NOT_AVAILABLE)


def test_detached_payload(vset, ctx):
    data = _vector(vset, "P6-detached-payload")
    r = validate_bytes(data, _with(ctx, detached_payload=None))
    assert (r.indication, r.subindication) == (INDETERMINATE, SIGNED_DATA_NOT_FOUND)
    r = validate_bytes(data, _with(ctx, detached_payload=V.PAYLOAD + b"x"))
    assert (r.indication, r.subindication) == (INVALID, SIG_CRYPTO_FAILURE)


def test_sigd_object_missing_or_changed(vset, ctx, tmp_path):
    data = _vector(vset, "P7-sigd-uri-hash")
    r = validate_bytes(data, _with(ctx, data_dir=tmp_path))
    assert (r.indication, r.subindication) == (INDETERMINATE, SIGNED_DATA_NOT_FOUND)
    (tmp_path / V.DATA_NAME).write_bytes(V.PAYLOAD + b"changed")
    r = validate_bytes(data, _with(ctx, data_dir=tmp_path))
    assert (r.indication, r.subindication) == (INVALID, HASH_FAILURE)


# --- order of the checks ------------------------------------------------------------

def test_broken_signature_wins_over_expired_certificate(pki, ctx):
    data = V.sign1(V.bb_protected(pki, pki.expired), V.bb_unprotected(pki, pki.expired),
                   V.PAYLOAD, pki.expired_key, -7, raw_tbs=V.PAYLOAD)
    r = validate_bytes(data, ctx)
    assert (r.indication, r.subindication) == (INVALID, SIG_CRYPTO_FAILURE)


def test_cose_sign_reports_the_worst_signer(pki, ctx):
    bad = V.bb_protected(pki, pki.rsa, -37)
    bad[2] = [65000]
    bad[65000] = 1
    data = V.sign_multi([
        (V.bb_protected(pki, pki.ok), V.bb_unprotected(pki, pki.ok), pki.ok_key, -7),
        (bad, V.bb_unprotected(pki, pki.rsa), pki.rsa_key, -37),
    ], V.PAYLOAD)
    r = validate_bytes(data, ctx)
    assert (r.indication, r.subindication) == (INVALID, FORMAT_FAILURE)
    assert [s.indication for s in r.signers] == [VALID, INVALID]
    assert r.detail.startswith(f"signer 0: VALID ({r.signers[0].detail}); "
                               f"signer 1: INVALID/FORMAT_FAILURE ({r.signers[1].detail})")


def test_cose_sign_detail_keeps_each_signers_qualifications(pki, ctx):
    late = {**V.bb_protected(pki, pki.ok), HDR_ADOTST: b"\x30\x00"}
    data = V.sign_multi([
        (V.bb_protected(pki, pki.ok, iat=False), V.bb_unprotected(pki, pki.ok), pki.ok_key, -7),
        (late, V.bb_unprotected(pki, pki.ok), pki.ok_key, -7),
    ], V.PAYLOAD)
    loose = dataclasses.replace(ctx, strict=False, revocation="ignore", policies=[],
                                unknown_policy="accept")
    r = validate_bytes(data, loose)
    assert r.indication == VALID
    for part in ("revocation not checked", "lenient: no CWT Claims (15) iat",
                 "adoTst) present, not evaluated", "(--unknown-policy accept)"):
        assert part in r.detail, part


# --- format -------------------------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda b: b + b"\x00",  # trailing bytes after the COSE message
    lambda b: b[:-5],  # truncated
    lambda b: b"not cbor at all",
    lambda b: cbor2.dumps(cbor2.CBORTag(99, cbor2.loads(b).value)),  # wrong tag
])
def test_malformed_input(mutate, vset, ctx):
    r = validate_bytes(mutate(_vector(vset, "P1-es256-sign1")), ctx)
    assert (r.indication, r.subindication) == (INVALID, FORMAT_FAILURE)


def test_x5chain_outside_uheaders_is_a_format_failure(pki, ctx):
    data = V.sign1(V.bb_protected(pki, pki.ok), {HDR_X5CHAIN: [V.der(pki.ok), V.der(pki.ca)]},
                   V.PAYLOAD, pki.ok_key, -7)
    r = validate_bytes(data, ctx)
    assert (r.indication, r.subindication) == (INVALID, FORMAT_FAILURE)


# --- CLI ----------------------------------------------------------------------------

def test_cli_json_matches_the_manifest(vset, capsys):
    out, manifest = vset
    rc = main([str(out / "signatures"),
               "--trust-anchor", str(out / "pki" / "root.pem"),
               "--material", str(out / "pki"),
               "--policy", str(out / "data" / "policy.der"),
               "--payload", str(out / "data" / V.DATA_NAME),
               "--data-dir", str(out / "data"),
               "--validation-time", manifest["validation_time"], "--json"])
    assert rc == 0
    rows = {r["case"]: r for r in json.loads(capsys.readouterr().out)["results"]}
    assert set(rows) == set(manifest["cases"])
    for case, want in manifest["cases"].items():
        assert (rows[case]["indication"], rows[case]["subindication"]) == \
            (want["indication"], want["subindication"])


def test_cli_usage_errors(tmp_path, vset):
    out, _ = vset
    assert main([str(tmp_path), "--trust-anchor", str(out / "pki" / "root.pem")]) == 2
