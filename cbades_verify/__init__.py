# SPDX-License-Identifier: Apache-2.0
"""CB-AdES (ETSI TS 119 152-1) B-B signature verifier.

A research verifier for interoperability testing: it decodes COSE_Sign /
COSE_Sign1 CB-AdES signatures and validates them in the order of the
EN 319 102-1 basic signature validation process, with a built-in constraint
set. It depends only on ``cbor2`` and ``cryptography``. It is not a
signature validation service and does not check qualified or trusted-list
status.
"""
from __future__ import annotations

from .validate import Context, Result, validate_bytes, validate_file

__all__ = ["Context", "Result", "validate_bytes", "validate_file"]
