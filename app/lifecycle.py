from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from pydantic import Field, field_validator

from app.common import Contract, DomainError, Identity, Store, digest, require, timestamp


class Finding(Contract):
    id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    asset: str = Field(min_length=1, max_length=256)
    repository: str = Field(pattern=r"^[\w.-]+/[\w.-]+$")
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_vector: str = Field(max_length=128)
    observed_at: str
    source: Literal["synthetic-scanner", "authorized-import"]
    revision: str = Field(pattern=r"^[a-f0-9]{40}$")

    @field_validator("cvss_vector")
    @classmethod
    def valid_vector(cls, value: str) -> str:
        try:
            CVSS3(value)
        except CVSS3Error as error:
            raise ValueError("Invalid CVSS vector") from error
        return value

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value: str) -> str:
        timestamp(value)
        return value


class Enrichment(Contract):
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    epss: float = Field(ge=0, le=1, allow_inf_nan=False)
    kev: bool
    as_of: str
    provenance: Literal["synthetic", "first-cisa-import"]

    @field_validator("as_of")
    @classmethod
    def valid_time(cls, value: str) -> str:
        timestamp(value)
        return value


class Intake(Contract):
    finding: Finding
    enrichment: Enrichment


class Proposal(Contract):
    target_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    fix: str = Field(min_length=12, max_length=4000)
    diff: str = Field(min_length=12, max_length=20000)


class Rescan(Contract):
    asset: str
    repository: str
    revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scanner: Literal["synthetic-package-rescan", "trusted-ci-attestation"]
    complete: Literal[True]
    checked_cves: list[str] = Field(min_length=1, max_length=10000)
    observed_cves: list[str] = Field(max_length=10000)
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value: str) -> str:
        timestamp(value)
        return value


class Lifecycle:
    def __init__(self, store: Store, owners: dict[str, dict[str, str]]):
        self.store = store
        self.owners = owners

    def ingest(self, identity: Identity, intake: Intake, now: str) -> dict[str, Any]:
        require(identity, "analyst")
        finding, enrichment = intake.finding, intake.enrichment
        current = timestamp(now)
        if finding.cve != enrichment.cve or finding.repository not in self.owners.get(
            identity.tenant, {}
        ):
            raise DomainError("Enrichment or repository binding mismatch", 422)
        if (
            not current - timedelta(days=7) <= timestamp(enrichment.as_of) <= current
            or timestamp(finding.observed_at) > current
        ):
            raise DomainError("Stale or future evidence", 422)
        score = float(CVSS3(finding.cvss_vector).scores()[0])
        record = {
            **finding.model_dump(),
            "enrichment": enrichment.model_dump(),
            "cvss_base": score,
            "priority": "P0"
            if enrichment.kev
            else "P1"
            if enrichment.epss >= 0.5 or score >= 9
            else "P2",
            "owner": self.owners[identity.tenant][finding.repository],
            "state": "open",
            "created_by": identity.subject,
            "intake_sha256": digest(intake.model_dump()),
        }
        with self.store.tx() as db:
            row = db.execute(
                "SELECT payload FROM objects WHERE tenant=? AND id=? AND kind='finding'",
                (identity.tenant, finding.id),
            ).fetchone()
            if row:
                existing = self.store.get(db, identity.tenant, finding.id, "finding")
                if existing["intake_sha256"] != record["intake_sha256"]:
                    raise DomainError("Finding id is already bound to different evidence")
                return existing
            self.store.save(db, identity.tenant, finding.id, "finding", record)
            self.store.audit(
                db,
                identity,
                "ingested",
                {"id": finding.id, "intake_sha256": record["intake_sha256"]},
                now,
            )
        return record

    def propose(self, identity: Identity, key: str, proposal: Proposal, now: str) -> dict[str, Any]:
        require(identity, "analyst")
        with self.store.tx() as db:
            record = self.store.get(db, identity.tenant, key, "finding")
            if record["state"] != "open" or record["revision"] == proposal.target_revision:
                raise DomainError("A proposal requires an open finding and a changed revision")
            record.update(
                state="proposed",
                proposal=proposal.model_dump(),
                proposed_by=identity.subject,
                proposal_sha256=digest(proposal.model_dump()),
            )
            self.store.save(db, identity.tenant, key, "finding", record)
            self.store.audit(
                db,
                identity,
                "proposed",
                {"id": key, "proposal_sha256": record["proposal_sha256"]},
                now,
            )
            return record

    def approve(
        self, identity: Identity, key: str, proposal_sha256: str, now: str
    ) -> dict[str, Any]:
        require(identity, "approver")
        with self.store.tx() as db:
            record = self.store.get(db, identity.tenant, key, "finding")
            if record["state"] != "proposed" or record["proposal_sha256"] != proposal_sha256:
                raise DomainError("Approval must bind the current proposal digest")
            if identity.subject == record["proposed_by"]:
                raise DomainError("Independent approval required", 403)
            record.update(state="approved", approved_by=identity.subject, approved_at=now)
            self.store.save(db, identity.tenant, key, "finding", record)
            self.store.audit(
                db, identity, "approved", {"id": key, "proposal_sha256": proposal_sha256}, now
            )
            return record

    def close(self, identity: Identity, key: str, rescan: Rescan, now: str) -> dict[str, Any]:
        require(identity, "verifier")
        with self.store.tx() as db:
            record = self.store.get(db, identity.tenant, key, "finding")
            if record["state"] != "approved":
                raise DomainError("Closure requires an approved proposal")
            if identity.subject in {record["proposed_by"], record["approved_by"]}:
                raise DomainError("Independent verification required", 403)
            proposal = record["proposal"]
            if rescan.scanner == "synthetic-package-rescan" and (
                record["source"] != "synthetic-scanner" or record["cve"] != "CVE-2099-0001"
            ):
                raise DomainError("Synthetic scanner cannot close an imported real finding")
            if (
                rescan.asset != record["asset"]
                or rescan.repository != record["repository"]
                or rescan.revision != proposal["target_revision"]
                or rescan.artifact_sha256 != proposal["artifact_sha256"]
            ):
                raise DomainError("Rescan does not cover the approved artifact")
            if not timestamp(record["approved_at"]) <= timestamp(rescan.observed_at) <= timestamp(
                now
            ) or timestamp(now) - timestamp(rescan.observed_at) > timedelta(days=1):
                raise DomainError("Rescan is stale, future, or predates approval")
            if record["cve"] not in rescan.checked_cves or record["cve"] in rescan.observed_cves:
                raise DomainError("Rescan did not establish the target finding is absent")
            record.update(
                state="closed",
                closure={
                    "method": "trusted_rescan_evidence",
                    "verifier": identity.subject,
                    "evidence": rescan.model_dump(),
                    "evidence_sha256": digest(rescan.model_dump()),
                },
            )
            self.store.save(db, identity.tenant, key, "finding", record)
            self.store.audit(
                db,
                identity,
                "closed",
                {"id": key, "evidence_sha256": record["closure"]["evidence_sha256"]},
                now,
            )
            return record
