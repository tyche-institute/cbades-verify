# SPDX-License-Identifier: Apache-2.0
"""Command line: verify CB-AdES signature files.

Example (the vector set that ``python -m cbades_verify.vectors OUT`` writes)::

    cbades-verify OUT/signatures \\
        --trust-anchor OUT/pki/root.pem --material OUT/pki \\
        --policy OUT/data/policy.der --data-dir OUT/data \\
        --payload OUT/data/payload.txt --validation-time 2026-10-26T12:00:00Z

Exit status: 0 when every file was processed (whatever its verdict), 1 when a
file could not be read or processed (its result is INDETERMINATE with an
``internal error`` detail) or the output could not be written (a closed
pipe), 2 on a usage error: a bad or empty option value, an input that is
empty or missing or a directory that cannot be listed, or validation material (a file,
or a ``--material`` or ``--data-dir`` directory) that cannot be read or
loaded. Unparseable files in a ``--material`` directory are skipped and
listed on stderr.

:func:`build_parser`, :func:`prepare` and :func:`verify_files` are also the
building blocks for a tool that does more with the results than print them.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

from . import pki
from .cose import clip
from .labels import INDETERMINATE
from .validate import Context, Result, is_policy_id, policy_id_key, validate_file

DESCRIPTION = ("Verify CB-AdES (ETSI TS 119 152-1) baseline B-B signatures with the "
               "EN 319 102-1 basic signature validation process.")


class UsageError(Exception):
    """A bad option value, a missing input or unreadable validation material:
    exit status 2."""


TIME_FORM = "YYYY-MM-DDTHH:MM:SS[.ffffff][Z|+HH:MM|-HH:MM]"
_TIME = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?"
                   r"(?:Z|([+-])(\d\d):(\d\d))?", re.ASCII)


def parse_time(text: str) -> dt.datetime:
    """A time of the form :data:`TIME_FORM`, the same on every Python
    version; UTC when no offset is given."""
    m = _TIME.fullmatch(text)
    try:
        if m is None:
            raise ValueError(text)
        *fields, frac, sign, hh, mm = m.groups()
        tz = dt.timezone.utc
        if sign:
            offset = dt.timedelta(hours=int(hh), minutes=int(mm))
            tz = dt.timezone(offset if sign == "+" else -offset)
        t = dt.datetime(*map(int, fields), int((frac or "0").ljust(6, "0")), tzinfo=tz)
        return t.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError):
        raise UsageError(f"--validation-time: not a time of the form {TIME_FORM}: "
                         f"{text!r}") from None


def safe_text(text: str) -> str:
    """A name from the file system as text that can be printed: bytes that
    are not UTF-8 become ``\\xNN``."""
    return os.fsencode(text).decode("utf-8", "backslashreplace")


#: C0 and C1 controls, DEL, line and paragraph separators, bidirectional overrides.
_CONTROLS = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def printable(text: str) -> str:
    """Text for one line of terminal output. Certificate names, policy ids
    and file names come from the input, so control characters are shown as
    ``\\xNN`` / ``\\uNNNN`` escapes: they cannot start a new line or move the
    cursor."""
    return _CONTROLS.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100
                         else f"\\u{ord(m.group()):04x}", text)


def collect_inputs(paths) -> tuple:
    """The .cbor files named or contained in ``paths``, and (path, reason) for
    the entries skipped. Subdirectories are not searched."""
    files, skipped = [], []
    for p in map(Path, paths):
        try:
            if p.is_dir():
                for q in sorted(p.iterdir()):
                    if q.is_file() and q.suffix.lower() == ".cbor":
                        files.append(q)
                    elif q.is_dir():
                        skipped.append((q, "directory, not searched"))
                    else:
                        skipped.append((q, "not .cbor"))
            elif p.is_file():
                files.append(p)
            else:
                raise UsageError(f"input not found: {safe_text(str(p))}")
        except OSError as exc:
            raise UsageError(f"input not readable: {safe_text(str(p))} "
                             f"({exc.strerror or type(exc).__name__})") from None
    return files, skipped


def _load(what: str, loader, arg):
    try:
        return loader(arg)
    except OSError as exc:  # its str() quotes the file name with repr()
        name = exc.filename
        if isinstance(name, (str, bytes)):
            raise UsageError(f"{what}: {exc.strerror or type(exc).__name__}: "
                             f"{safe_text(os.fsdecode(name))}") from None
        raise UsageError(f"{what}: {safe_text(str(exc))}") from None
    except ValueError as exc:
        raise UsageError(f"{what}: {safe_text(str(exc))}") from None
    except Exception as exc:  # noqa: BLE001 - e.g. an unsupported key or version
        raise UsageError(f"{what}: {type(exc).__name__}: {safe_text(str(exc))}") from None


def build_parser(prog: str = "cbades-verify",
                 description: str = DESCRIPTION) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=prog, description=description)
    ap.add_argument("inputs", nargs="+", help=".cbor files or directories of them")
    ap.add_argument("--trust-anchor", action="append", default=[], required=True,
                    help="trusted root certificate (PEM or DER); repeatable")
    ap.add_argument("--cert", action="append", default=[],
                    help="additional (intermediate) certificate; repeatable")
    ap.add_argument("--crl", action="append", default=[], help="CRL file; repeatable")
    ap.add_argument("--ocsp", action="append", default=[], help="DER OCSP response; repeatable")
    ap.add_argument("--material", action="append", default=[],
                    help="directory: load every certificate, CRL and OCSP response in it "
                         "(recognised by content, not by file name)")
    ap.add_argument("--policy", action="append", default=[],
                    help="signature policy document, matched to sigPId by digest; repeatable")
    ap.add_argument("--policy-map", nargs=2, action="append", default=[],
                    metavar=("ID", "FILE"),
                    help="the policy document for one sigPId id (e.g. urn:oid:1.2.3); "
                         "repeatable")
    ap.add_argument("--unknown-policy", choices=["indeterminate", "accept"],
                    default="indeterminate",
                    help="sigPId with no document: SIGNATURE_POLICY_NOT_AVAILABLE "
                         "(default) or accept with a note")
    ap.add_argument("--payload", help="detached payload for signatures with a nil payload")
    ap.add_argument("--data-dir", help="directory where sigD references are resolved by name")
    ap.add_argument("--validation-time",
                    help=f"{TIME_FORM}, UTC when no offset is given (default: now)")
    ap.add_argument("--revocation", choices=["require", "ignore"], default="require",
                    help="require: unknown status of a valid certificate gives TRY_LATER")
    ap.add_argument("--revocation-freshness", choices=["lenient", "strict"], default="lenient",
                    help="strict: EN 319 102-1 freshness (thisUpdate within "
                         "nextUpdate - thisUpdate of the validation time)")
    ap.add_argument("--online", action="store_true",
                    help="fetch CRLs / OCSP from the certificates' own CDP and AIA URLs "
                         "when the supplied and embedded data is not fresh")
    ap.add_argument("--lenient", action="store_true",
                    help="report TS 119 152-1 profile deviations as notes instead of "
                         "FORMAT_FAILURE")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    return ap


_PATH_OPTIONS = ("trust_anchor", "cert", "crl", "ocsp", "material", "policy", "payload",
                 "data_dir")


def _directory(option: str, d: str) -> Path:
    try:
        if Path(d).is_dir():
            with os.scandir(d):  # a directory that cannot be listed is refused here
                pass
            return Path(d)
    except OSError as exc:
        raise UsageError(f"{option}: cannot access {safe_text(d)} "
                         f"({exc.strerror or type(exc).__name__})") from None
    raise UsageError(f"{option}: not a directory: {safe_text(d)}")


def load_context(args) -> Context:
    """The validation context the parsed options describe."""
    for name in _PATH_OPTIONS:
        value = getattr(args, name)
        if value == "" or (isinstance(value, list) and "" in value):
            raise UsageError(f"--{name.replace('_', '-')}: empty value")
    if any("" in pair for pair in args.policy_map):
        raise UsageError("--policy-map: empty value")
    certs = _load("--cert", pki.load_certs, args.cert)
    crls = _load("--crl", pki.load_crls, args.crl)
    resps = _load("--ocsp", pki.load_ocsp_responses, args.ocsp)
    for d in args.material:
        c, r, o, skipped = _load("--material", pki.load_material_dir,
                                 _directory("--material", d))
        certs, crls, resps = certs + c, crls + r, resps + o
        for s in skipped:
            print(f"skipped (not parseable): {printable(safe_text(str(s)))}",
                  file=sys.stderr)
    anchors = _load("--trust-anchor", pki.load_certs, args.trust_anchor)
    if not anchors:
        raise UsageError("--trust-anchor: no certificate loaded")
    data_dir = None if args.data_dir is None else _directory("--data-dir", args.data_dir)
    policy_map, keys = {}, set()
    for pid, f in args.policy_map:
        if not is_policy_id(pid):
            raise UsageError(f"--policy-map: {safe_text(pid)} is not a URI (RFC 3986) of at "
                             "most 1024 characters, so no sigPId id can be it")
        if policy_id_key(pid) in keys:
            raise UsageError(f"--policy-map: {pid} given twice")
        keys.add(policy_id_key(pid))
        policy_map[pid] = _load("--policy-map", lambda p: Path(p).read_bytes(), f)
    ctx = Context(
        trust_anchors=anchors,
        certs=certs,
        crls=crls,
        ocsp_responses=resps,
        policies=[_load("--policy", lambda p: Path(p).read_bytes(), p) for p in args.policy],
        policy_map=policy_map,
        unknown_policy=args.unknown_policy,
        detached_payload=(_load("--payload", lambda p: Path(p).read_bytes(), args.payload)
                          if args.payload is not None else None),
        data_dir=data_dir,
        revocation=args.revocation,
        revocation_freshness=args.revocation_freshness,
        online=args.online,
        strict=not args.lenient,
    )
    if args.validation_time is not None:
        ctx.validation_time = parse_time(args.validation_time)
    return ctx


def case_name(f: Path) -> str:
    """The case name of an input file: its name without the extension."""
    return safe_text(f.stem)


def prepare(args) -> tuple:
    """The validation context and the input files; skipped entries are listed
    on stderr. Raises :class:`UsageError`."""
    if "" in args.inputs:
        raise UsageError("input: empty value")
    ctx = load_context(args)
    files, skipped = collect_inputs(args.inputs)
    for s, why in skipped:
        print(f"skipped ({why}): {printable(safe_text(str(s)))}", file=sys.stderr)
    if not files:
        raise UsageError("no .cbor inputs found")
    return ctx, files


def verify_files(files, ctx: Context) -> tuple:
    """``[(path, result), ...]`` in input order, and the number of files that
    could not be processed. A file that raises does not stop the batch: its
    result is INDETERMINATE with an ``internal error`` detail."""
    pairs, failed = [], 0
    for f in files:
        try:
            result = validate_file(f, ctx)
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the batch
            result = Result(INDETERMINATE, None,
                            f"internal error {type(exc).__name__}: {clip(str(exc))}")
        if any(r.detail.startswith("internal error") for r in [result, *result.signers]):
            failed += 1
        pairs.append((f, result))
    return pairs, failed


def print_results(pairs, ctx: Context, as_json: bool = False) -> None:
    rows = [{"file": safe_text(str(f)), "case": case_name(f), **r.as_dict()}
            for f, r in pairs]
    if as_json:
        print(json.dumps({"validation_time": ctx.validation_time.isoformat(),
                          "results": rows}, indent=2))
        return
    cases = [printable(r["case"]) for r in rows]
    width = max(len(c) for c in cases)
    for case, r in zip(cases, rows, strict=True):
        sub = f"/{r['subindication']}" if r["subindication"] else ""
        print(f"{case:<{width}}  {r['indication']}{sub}  — {printable(r['detail'])}")


def reconfigure_streams() -> None:
    """Print names that are not UTF-8 as escapes instead of failing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    reconfigure_streams()
    try:
        ctx, files = prepare(args)
    except UsageError as exc:
        print(f"cbades-verify: {printable(safe_text(str(exc)))}", file=sys.stderr)
        return 2
    pairs, failed = verify_files(files, ctx)
    try:
        print_results(pairs, ctx, args.json)
        sys.stdout.flush()
    except BrokenPipeError:  # the reader went away: stop without a traceback
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 1
    if failed:
        print(f"{failed} file(s) could not be processed; see their results", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
