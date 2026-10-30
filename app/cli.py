from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import uvicorn

from app.api import create_app
from app.common import DEMO_IDENTITIES, Identity, Store
from app.lifecycle import Intake, Lifecycle, Proposal
from app.rescan import scan_synthetic_lock


def demo() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / "demo.db")
        analyst, approver, verifier = (
            DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"]
        )
        data = json.loads(Path("samples/workflow.json").read_text())
        NOW = "2026-10-30T12:00:00Z"
        service = Lifecycle(store, {"alder": {"synthetic/service": "platform"}})
        service.ingest(analyst, Intake.model_validate(data), NOW)
        fixed = Path("samples/fixed.txt").read_text()
        proposal = Proposal(
            target_revision="b" * 40,
            artifact_sha256=hashlib.sha256(fixed.encode()).hexdigest(),
            fix="Upgrade synthetic-parser to 2.0.0",
            diff="--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-synthetic-parser==1.0.0\n+synthetic-parser==2.0.0\n",
        )
        record = service.propose(analyst, data["finding"]["id"], proposal, NOW)
        service.approve(approver, record["id"], record["proposal_sha256"], NOW)
        rescan = scan_synthetic_lock(
            fixed,
            asset=record["asset"],
            repository=record["repository"],
            revision=proposal.target_revision,
            observed_at=NOW,
        )
        result = service.close(verifier, record["id"], rescan, NOW)
        return {"mode": "synthetic-offline", "result": result, "evidence": store.evidence(analyst)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["demo", "serve"])
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.command == "demo":
        print(json.dumps(demo(), indent=2))
        return
    identities = None
    if not args.demo:
        path = Path(os.environ["IDENTITY_FILE"])
        if path.stat().st_mode & 0o077:
            raise ValueError("Identity file must be private to its owner")
        raw = json.loads(path.read_text())
        if not raw or any(len(token) < 32 for token in raw):
            raise ValueError("Credentials must contain at least 32 characters")
        identities = {token: Identity.model_validate(value) for token, value in raw.items()}
    app = create_app(
        Path(os.environ.get("STATE_PATH", "artifacts/state.db")),
        identities,
        demo=args.demo,
        owners=None if args.demo else json.loads(Path(os.environ["OWNER_FILE"]).read_text()),
    )
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=args.port, access_log=False)


if __name__ == "__main__":
    main()
