from __future__ import annotations

import hashlib
import re

from app.lifecycle import Rescan


def scan_synthetic_lock(
    text: str, *, asset: str, repository: str, revision: str, observed_at: str
) -> Rescan:
    """A real deterministic scanner for the explicitly fictional demo package contract."""
    match = re.fullmatch(r"synthetic-parser==(1\.0\.0|2\.0\.0)\n?", text)
    if not match:
        raise ValueError("Scanner scope is exactly one synthetic package pin")
    return Rescan(
        asset=asset,
        repository=repository,
        revision=revision,
        artifact_sha256=hashlib.sha256(text.encode()).hexdigest(),
        scanner="synthetic-package-rescan",
        complete=True,
        checked_cves=["CVE-2099-0001"],
        observed_cves=["CVE-2099-0001"] if match[1] == "1.0.0" else [],
        observed_at=observed_at,
    )
