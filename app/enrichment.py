from __future__ import annotations

from datetime import date
from typing import Any

from app.lifecycle import Enrichment


def import_feeds(cve: str, epss: dict[str, Any], kev: dict[str, Any]) -> Enrichment:
    """Consume saved official feed shapes without an arbitrary network destination."""
    if (
        epss.get("status") != "OK"
        or not isinstance(epss.get("data"), list)
        or not isinstance(kev.get("vulnerabilities"), list)
    ):
        raise ValueError("Incomplete enrichment feed")
    matches = [item for item in epss["data"] if item["cve"] == cve]
    if len(matches) != 1:
        raise ValueError("Exactly one EPSS record required")
    entry = matches[0]
    epss_date = date.fromisoformat(entry["date"])
    kev_date = date.fromisoformat(kev["dateReleased"][:10])
    if abs((epss_date - kev_date).days) > 7:
        raise ValueError("Feed dates are inconsistent")
    if len(kev["vulnerabilities"]) != kev.get("count"):
        raise ValueError("KEV feed count mismatch")
    return Enrichment(
        cve=cve,
        epss=float(entry["epss"]),
        kev=any(item["cveID"] == cve for item in kev["vulnerabilities"]),
        as_of=min(epss_date, kev_date).isoformat() + "T00:00:00Z",
        provenance="first-cisa-import",
    )
