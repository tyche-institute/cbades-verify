# SPDX-License-Identifier: Apache-2.0
"""Decode COSE_Sign / COSE_Sign1 into signer layers (RFC 9052 §4).

CB-AdES (TS 119 152-1 clauses 4.2-4.3) may use either structure, tagged or
untagged. This module only takes the message apart and rebuilds the
``Sig_structure`` for each signer; every judgement about the content lives in
:mod:`cbades_verify.validate`.

Decoding is deliberately *not* a strict deterministic-encoding decoder: a
CB-AdES verifier has to accept third-party signatures whose outer structure
is not canonically encoded. The protected-header bytes are kept
exactly as received, which is all the signature check depends on. What RFC 9052
does require is enforced: one data item per byte string (no trailing bytes), no
duplicate map labels (compared as CBOR values, so 1, 1.0 and true are three
keys), labels that are int or tstr, and map-typed header buckets. One input
holds at most :data:`MAX_MESSAGE_BYTES` bytes and :data:`MAX_ITEMS` data items,
the items inside bstr-wrapped headers included.
cbor2's semantic-tag decoders are switched off, so a tagged value stays a
:class:`cbor2.CBORTag` instead of being rewritten (or rejected) by cbor2.
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field

import cbor2

from .labels import HDR_UHEADERS, TAG_COSE_SIGN, TAG_COSE_SIGN1

#: Largest input this verifier decodes: a resource bound.
MAX_MESSAGE_BYTES = 20 * 1024 * 1024
#: Signatures one COSE_Sign may carry (a resource bound).
MAX_SIGNERS = 64


class FormatError(Exception):
    """The input is not a well-formed COSE_Sign / COSE_Sign1 structure."""


#: What cbor2 gives for a data item when no semantic decoder runs.
_SCALARS = (bytes, bytearray, str, int, float, type(None), cbor2.CBORSimpleValue,
            type(cbor2.undefined))


def plain(v):
    """Normalise cbor2 output: maps to ``dict``, arrays to ``list``.

    cbor2>=6 returns maps as ``frozendict`` and arrays as ``tuple``; structural
    checks below must not depend on the cbor2 version. Tagged items are kept as
    :class:`cbor2.CBORTag` with a normalised value. Any other Python object
    means that cbor2 decoded a tag this module does not keep raw, and is a
    format error rather than a value whose equality nobody checked.
    """
    if isinstance(v, (bytes, bytearray, str)):
        return v
    if type(v) is object:  # cbor2's break marker, read where a data item belongs
        raise FormatError("a break byte (0xff) where a data item belongs")
    if isinstance(v, cbor2.CBORTag):
        return cbor2.CBORTag(v.tag, plain(v.value))
    if hasattr(v, "items"):
        return {k: plain(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if not isinstance(v, _SCALARS):
        raise FormatError(f"a tagged item that cbor2 decoded into {type(v).__name__}")
    return v


#: cbor2 semantic tags that would otherwise be decoded into Python objects
#: (43000 into a complex number, which equals and hashes like an int).
#: Tag 55799 (self-described CBOR) stays a tag too: cbor2 would strip it at any
#: depth, so 55799(1) would pass as the label 1. :func:`decode` strips one at
#: the top of a signature file, where RFC 8949 §3.4.6 places it.
_RAW_TAGS = (0, 1, 2, 3, 4, 5, 25, 28, 29, 30, 35, 36, 37, 52, 54, 100, 256, 258, 260, 261,
             1004, 43000, 55799)
TAG_SELF_DESCRIBED = 55799
_SEMANTIC_DECODERS = {t: (lambda v, _imm, t=t: cbor2.CBORTag(t, v)) for t in _RAW_TAGS}

#: What a malformed input can raise from cbor2.
_DECODE_ERRORS = (cbor2.CBORDecodeError, ValueError, EOFError, OverflowError, RecursionError,
                  MemoryError)


def _check_cbor2() -> None:
    """Refuse a cbor2 that would make the verdicts wrong: one without the
    decoder options used here (before 6.1), which would make every signature
    look malformed, or one that misreads long byte strings from a stream
    (6.0.0 to 6.1.0 prepend stream bytes to a byte string of 4 KiB or more)."""
    long = b"a" * 5000
    probe = b"\x82\x59\x13\x88" + long + b"\x07"  # [h'61...61' (5000 bytes), 7]
    try:
        value = cbor2.CBORDecoder(io.BytesIO(probe), allow_duplicate_keys=False,
                                  semantic_decoders=_SEMANTIC_DECODERS).decode()
    except TypeError as exc:
        raise ImportError(f"cbades_verify needs cbor2 >= 6.1.1 ({exc})") from None
    if not isinstance(value, (list, tuple)) or list(value) != [long, 7]:
        raise ImportError("cbades_verify needs cbor2 >= 6.1.1 (this cbor2 misreads long "
                          "byte strings)")


_check_cbor2()

#: Data items one CBOR input may hold, those inside bstr-wrapped headers and
#: the chunks of indefinite-length strings included (a resource bound; a
#: CB-AdES signature holds a few hundred at most).
MAX_ITEMS = 100_000


def clip(text: str, limit: int = 200) -> str:
    """Input-derived text in a message, cut to ``limit`` characters."""
    return text if len(text) <= limit else f"{text[:limit]}... ({len(text)} characters)"


class _Budget:
    """The data items left for one input, shared by every byte string of it."""

    def __init__(self, items: int = MAX_ITEMS):
        self.left = items

    def take(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise _TooMany


class _TooMany(ValueError):
    pass


class _Refused(ValueError):
    """Well-formed CBOR that a COSE map may not hold; the text completes "has"."""


#: Simple values with a meaning (false, true, null, undefined); cbor2
#: releases compare the other simple values with ints differently.
_NAMED_SIMPLE = (20, 21, 22, 23)


class _Walker:
    """Reads raw CBOR before cbor2 does: well-formedness (RFC 8949 §3, a
    stray break byte included), the item budget, and map keys. It tells real
    duplicate map keys from keys that only Python thinks equal (1, 1.0 and
    true are three different CBOR keys, RFC 8949 §5.6.1), and refuses a key
    that is not an int or tstr in a map that ``label_maps(path)`` names.
    Each item gives (strict, loose): strict is the CBOR value, loose the
    value as cbor2 compares it."""

    def __init__(self, raw: bytes, budget: _Budget, label_maps):
        self.raw, self.pos, self.budget, self.label_maps = raw, 0, budget, label_maps
        self.duplicate = False
        self.collisions = []  # paths of maps with keys equal only as Python values

    def _byte(self) -> int:
        b = self.raw[self.pos]
        self.pos += 1
        return b

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.raw):
            raise ValueError("truncated")
        out = self.raw[self.pos:self.pos + n]
        self.pos += n
        return out

    def _arg(self, ai: int) -> int | None:
        if ai < 24:
            return ai
        if ai == 31:
            return None
        if ai > 27:
            raise ValueError("reserved additional information")
        return int.from_bytes(self._take(1 << (ai - 24)), "big")

    def _chunks(self, mt: int) -> bytes:
        out = bytearray()
        while self.raw[self.pos] != 0xFF:
            self.budget.take()  # each chunk is a definite-length string item
            ib = self._byte()
            if ib >> 5 != mt or ib & 31 == 31:
                raise ValueError("bad chunk")
            out += self._take(self._arg(ib & 31))
        self.pos += 1
        return bytes(out)

    def item(self, path: tuple):
        self.budget.take()
        ib = self._byte()
        mt, ai = ib >> 5, ib & 31
        if mt == 7:
            if ai in (25, 26, 27):
                v = struct.unpack((">e", ">f", ">d")[ai - 25], self._take(1 << (ai - 24)))[0]
                strict = ("f", struct.pack(">d", v))
                return strict, (("n", v) if v == v else strict)
            v = self._arg(ai)
            if v is None:
                raise ValueError("unexpected break")
            if v in (20, 21):
                return ("s", v), ("n", v - 20)
            # an unassigned simple value may equal an int in cbor2: assume it does
            return ("s", v), (("s", v) if v in _NAMED_SIMPLE else ("n", v))
        n = self._arg(ai)
        if mt in (0, 1):
            if n is None:
                raise ValueError("indefinite integer")
            v = n if mt == 0 else -1 - n
            return ("i", v), ("n", v)
        if mt in (2, 3):
            data = self._chunks(mt) if n is None else bytes(self._take(n))
            key = ("bt"[mt - 2], data)
            return key, key
        if mt == 6:
            if n is None:
                raise ValueError("indefinite tag")
            s, loose = self.item(path)
            return ("g", n, s), ("g", n, loose)
        if mt == 4:
            parts = []
            while (self.raw[self.pos] != 0xFF) if n is None else len(parts) < n:
                parts.append(self.item(path + (len(parts),)))
            if n is None:
                self.pos += 1
            return ("a", tuple(p[0] for p in parts)), ("a", tuple(p[1] for p in parts))
        pairs, seen, seen_loose, j = [], set(), set(), 0
        labels = self.label_maps(path)
        while (self.raw[self.pos] != 0xFF) if n is None else j < n:
            k, k_loose = self.item(path + ("k",))
            if labels and k[0] not in ("i", "t"):
                raise _Refused("a label that is neither int nor tstr")
            if k[0] == "s" and k[1] not in _NAMED_SIMPLE:
                raise _Refused("a map key that is an unassigned simple value")
            v = self.item(path + ("m", j))
            if k in seen:
                self.duplicate = True
            elif k_loose in seen_loose:
                self.collisions.append(path)
            seen.add(k)
            seen_loose.add(k_loose)
            pairs.append(((k, v[0]), (k_loose, v[1])))
            j += 1
        if n is None:
            self.pos += 1
        return ("m", frozenset(p[0] for p in pairs)), ("m", frozenset(p[1] for p in pairs))


def _top_map(path) -> bool:
    return path == ()


def strict_loads(raw: bytes, what: str, label_maps=_top_map, *, merge: bool = True,
                 budget: _Budget | None = None):
    """Exactly one well-formed CBOR data item, without duplicate map keys;
    tags kept raw.

    A map that ``label_maps(path)`` names holds header labels: a key that is
    not an int or tstr is a format error there. cbor2 compares map keys as
    Python values, so it also takes 1 and true (or 1 and 1.0) for one key.
    Such keys are distinct CBOR keys; in the other maps the item is decoded
    and the colliding keys merged, unless ``merge`` is false. ``budget``
    counts the data items of the whole input (a new one when not given).
    """
    walker = _Walker(raw, budget or _Budget(), label_maps)
    try:
        walker.item(())
    except _TooMany:
        raise FormatError(f"{what}: the input holds more than {MAX_ITEMS} data "
                          "items") from None
    except _Refused as exc:
        raise FormatError(f"{what} has {exc}") from None
    except (IndexError, ValueError, RecursionError, struct.error) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        raise FormatError(f"{what} is not well-formed CBOR ({clip(reason)})") from exc
    if walker.pos != len(raw):
        raise FormatError(f"{what}: {len(raw) - walker.pos} trailing bytes after the CBOR item")
    if walker.duplicate:
        raise FormatError(f"{what} has a duplicate map key")
    if walker.collisions and not merge:
        raise FormatError(f"{what} has map keys that are equal only as numbers "
                          "(such as 1, 1.0 and true)")
    stream = io.BytesIO(raw)
    dec = cbor2.CBORDecoder(stream, allow_duplicate_keys=bool(walker.collisions),
                            semantic_decoders=_SEMANTIC_DECODERS)
    try:
        value = dec.decode()
    except _DECODE_ERRORS as exc:
        raise FormatError(f"{what} is not well-formed CBOR "
                          f"({type(exc).__name__}: {clip(str(exc))})") from exc
    if stream.tell() != len(raw):
        raise FormatError(f"{what}: {len(raw) - stream.tell()} trailing bytes after the CBOR item")
    return plain(value)


def _cose_header_map(path) -> bool:
    """The header maps of a COSE_Sign1 / COSE_Sign array (RFC 9052 §2, §4.1)."""
    return path == (1,) or (len(path) == 3 and path[0] == 3 and path[2] == 1)


def is_label(key) -> bool:
    """RFC 9052 §1.5: a header label is an int or a tstr (a bool is neither)."""
    return isinstance(key, str) or (isinstance(key, int) and not isinstance(key, bool))


def _check_labels(m: dict, what: str) -> dict:
    bad = [k for k in m if not is_label(k)]
    if bad:
        raise FormatError(f"{what} has labels that are neither int nor tstr: "
                          f"{clip(repr(bad))}")
    return m


def _decode_header_bstr(raw, where: str, budget: _Budget) -> dict:
    if not isinstance(raw, (bytes, bytearray)):
        raise FormatError(f"{where} protected header is not a byte string")
    if len(raw) == 0:
        return {}
    # signed content: keys that cbor2 would merge are refused at any depth
    value = strict_loads(bytes(raw), f"{where} protected header", merge=False, budget=budget)
    if not isinstance(value, dict):
        raise FormatError(f"{where} protected header is not a map")
    return _check_labels(value, f"{where} protected header")


def _as_map(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise FormatError(f"{where} unprotected header is not a map")
    return _check_labels(value, f"{where} unprotected header")


@dataclass
class SignerLayer:
    """One signature: the body of a COSE_Sign1, or one COSE_Signature."""

    protected_bstr: bytes
    protected: dict
    unprotected: dict
    signature: bytes
    #: Decoded ``uHeaders`` elements (each a map), in order of appearance.
    u_headers: list = field(default_factory=list)


@dataclass
class CoseMessage:
    kind: str  # "COSE_Sign1" or "COSE_Sign"
    tagged: bool
    body_protected_bstr: bytes
    body_protected: dict
    body_unprotected: dict
    payload: bytes | None  # None when the payload is detached
    signers: list

    def sig_structure(self, signer: SignerLayer, payload: bytes, *,
                      empty_as_zero_length: bool = False) -> bytes:
        """RFC 9052 §4.4 ``Sig_structure`` with an empty external_aad.

        The protected headers go in as received. With ``empty_as_zero_length``
        a received protected header that encodes an empty map (such as
        ``h'a0'``) goes in as ``h''`` instead, the form RFC 9052 §3 uses for
        "no protected attributes".
        """
        def bstr(raw, decoded):
            return b"" if empty_as_zero_length and not decoded else raw

        body = bstr(self.body_protected_bstr, self.body_protected)
        if self.kind == "COSE_Sign1":
            return cbor2.dumps(["Signature1", body, b"", payload])
        return cbor2.dumps(
            ["Signature", body, bstr(signer.protected_bstr, signer.protected), b"", payload]
        )

    def has_nonzero_empty_header(self, signer: SignerLayer) -> bool:
        """True when a protected header is a non-empty bstr holding an empty map."""
        pairs = [(self.body_protected_bstr, self.body_protected)]
        if self.kind == "COSE_Sign":
            pairs.append((signer.protected_bstr, signer.protected))
        return any(raw and not decoded for raw, decoded in pairs)


def _decode_uheaders(unprotected: dict, where: str, budget: _Budget) -> list:
    if HDR_UHEADERS not in unprotected:
        return []
    arr = unprotected[HDR_UHEADERS]
    if not isinstance(arr, list) or not arr:
        raise FormatError(f"{where} uHeaders (268) must be a non-empty array")
    out = []
    for i, item in enumerate(arr):
        if not isinstance(item, (bytes, bytearray)):
            raise FormatError(f"{where} uHeaders[{i}] is not a bstr-wrapped item")
        inst = strict_loads(bytes(item), f"{where} uHeaders[{i}]", budget=budget)
        if not isinstance(inst, dict):
            raise FormatError(f"{where} uHeaders[{i}] is not a map")
        out.append(_check_labels(inst, f"{where} uHeaders[{i}]"))
    return out


def decode(data: bytes) -> CoseMessage:
    """Decode a CB-AdES signature file. Raises :class:`FormatError`."""
    if len(data) > MAX_MESSAGE_BYTES:
        raise FormatError(f"input too large ({len(data)} bytes)")
    budget = _Budget()
    top = strict_loads(bytes(data), "signature file", _cose_header_map, budget=budget)
    if isinstance(top, cbor2.CBORTag) and top.tag == TAG_SELF_DESCRIBED:
        top = top.value  # one self-described CBOR tag at the top (RFC 8949 §3.4.6)

    tagged = isinstance(top, cbor2.CBORTag)
    if tagged:
        if top.tag not in (TAG_COSE_SIGN1, TAG_COSE_SIGN):
            raise FormatError(f"unexpected CBOR tag {top.tag}; expected 18 or 98")
        value = top.value
    else:
        value = top
    if not isinstance(value, list) or len(value) != 4:
        raise FormatError("COSE structure must be a 4-element array")

    prot_bstr, unprot, payload, last = value
    if isinstance(last, (bytes, bytearray)):
        kind = "COSE_Sign1"
    elif isinstance(last, list):
        kind = "COSE_Sign"
    else:
        raise FormatError("fourth element is neither a signature nor a signatures array")
    if tagged and kind == "COSE_Sign1" and top.tag != TAG_COSE_SIGN1:
        raise FormatError("tag 98 (COSE_Sign) on a COSE_Sign1 body")
    if tagged and kind == "COSE_Sign" and top.tag != TAG_COSE_SIGN:
        raise FormatError("tag 18 (COSE_Sign1) on a COSE_Sign body")

    body_protected = _decode_header_bstr(prot_bstr, "body", budget)
    body_unprotected = _as_map(unprot, "body")
    if payload is not None and not isinstance(payload, (bytes, bytearray)):
        raise FormatError("payload must be a byte string or nil")

    signers = []
    if kind == "COSE_Sign1":
        signers.append(SignerLayer(
            protected_bstr=bytes(prot_bstr),
            protected=body_protected,
            unprotected=body_unprotected,
            signature=bytes(last),
            u_headers=_decode_uheaders(body_unprotected, "body", budget),
        ))
    else:
        if not last:
            raise FormatError("COSE_Sign has an empty signatures array")
        if len(last) > MAX_SIGNERS:
            raise FormatError(f"COSE_Sign has {len(last)} signatures; at most {MAX_SIGNERS} "
                              "are verified")
        for i, sig in enumerate(last):
            where = f"signer {i}"
            if not isinstance(sig, list) or len(sig) != 3:
                raise FormatError(f"{where}: COSE_Signature must be a 3-element array")
            s_prot, s_unprot, s_sig = sig
            if not isinstance(s_sig, (bytes, bytearray)):
                raise FormatError(f"{where}: signature is not a byte string")
            s_unprot = _as_map(s_unprot, where)
            signers.append(SignerLayer(
                protected_bstr=bytes(s_prot) if isinstance(s_prot, (bytes, bytearray)) else s_prot,
                protected=_decode_header_bstr(s_prot, where, budget),
                unprotected=s_unprot,
                signature=bytes(s_sig),
                u_headers=_decode_uheaders(s_unprot, where, budget),
            ))

    return CoseMessage(
        kind=kind,
        tagged=tagged,
        body_protected_bstr=bytes(prot_bstr),
        body_protected=body_protected,
        body_unprotected=body_unprotected,
        payload=None if payload is None else bytes(payload),
        signers=signers,
    )
