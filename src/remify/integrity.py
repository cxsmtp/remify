"""Output integrity: sign each remediation so tampering is detectable.

A signed record binds the finding, the exact diff and the engine version.
CI verifies the signature before a fix is merged, so a patch altered after
Remify produced it, on the customer's side or in transit, is rejected.

HMAC-SHA256 with a shared key is enough when the signer and verifier are the
same organization. For signatures third parties can verify, swap in Ed25519
with the private key kept in a KMS or enclave.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from remify import __version__


def _payload(finding_id: str, diff: str, engine_version: str) -> bytes:
    record = {
        "finding": finding_id,
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "engine": engine_version,
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def sign(finding_id: str, diff: str, key: bytes) -> dict:
    payload = _payload(finding_id, diff, __version__)
    return {
        "finding": finding_id,
        "engine": __version__,
        "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "signature": hmac.new(key, payload, hashlib.sha256).hexdigest(),
    }


def verify(record: dict, diff: str, key: bytes) -> bool:
    payload = _payload(record["finding"], diff, record["engine"])
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, record.get("signature", ""))
