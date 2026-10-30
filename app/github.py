from __future__ import annotations

from typing import Any

import httpx


def pr_request(record: dict[str, Any]) -> dict[str, str]:
    """Produce a reviewable PR payload. No remote branch or code execution occurs."""
    if record["state"] not in {"approved", "closed"}:
        raise ValueError("Approval required")
    return {
        "title": f"Remediate {record['cve']}",
        "head": f"remediation/{record['id']}",
        "base": "main",
        "body": f"Proposal SHA-256: {record['proposal_sha256']}\nTarget revision: {record['proposal']['target_revision']}\n\nReview the supplied patch artifact and rescan the exact resulting artifact before closure.",
        "patch": record["proposal"]["diff"],
    }


def verify_pr(record: dict[str, Any], number: int, token: str) -> dict[str, Any]:
    if number <= 0 or record["state"] != "approved":
        raise ValueError("Approved finding and positive PR number required")
    repository = record["repository"]
    with httpx.Client(timeout=10, follow_redirects=False) as client:
        response = client.get(
            f"https://api.github.com/repos/{repository}/pulls/{number}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response.raise_for_status()
        data = response.json()
    if (
        data["base"]["repo"]["full_name"] != repository
        or data["head"]["sha"] != record["proposal"]["target_revision"]
    ):
        raise ValueError("PR evidence binding mismatch")
    return {
        "repository": repository,
        "number": number,
        "head_sha": data["head"]["sha"],
        "merged": bool(data["merged"]),
        "closure_authorized": False,
    }
