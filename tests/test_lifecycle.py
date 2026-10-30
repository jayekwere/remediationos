import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.cli import demo
from app.common import DEMO_IDENTITIES, DomainError, Identity, Store
from app.enrichment import import_feeds
from app.github import pr_request
from app.lifecycle import Enrichment, Intake, Lifecycle, Proposal, Rescan
from app.rescan import scan_synthetic_lock

NOW = "2026-10-30T12:00:00Z"
A, B, C = (DEMO_IDENTITIES[k] for k in ["demo-analyst", "demo-approver", "demo-verifier"])


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / "state.db")
    service = Lifecycle(store, {"alder": {"synthetic/service": "platform"}})
    intake = Intake.model_validate(json.loads(Path("samples/workflow.json").read_text()))
    fixed = Path("samples/fixed.txt").read_text()
    proposal = Proposal(
        target_revision="b" * 40,
        artifact_sha256=hashlib.sha256(fixed.encode()).hexdigest(),
        fix="Upgrade synthetic-parser to 2.0.0",
        diff="--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-synthetic-parser==1.0.0\n+synthetic-parser==2.0.0\n",
    )
    return store, service, intake, proposal


def approved(setup):
    store, service, intake, proposal = setup
    record = service.ingest(A, intake, NOW)
    record = service.propose(A, record["id"], proposal, NOW)
    return service.approve(B, record["id"], record["proposal_sha256"], NOW)


def rescan(record):
    return scan_synthetic_lock(
        Path("samples/fixed.txt").read_text(),
        asset=record["asset"],
        repository=record["repository"],
        revision="b" * 40,
        observed_at=NOW,
    )


def test_end_to_end_rescan_closure_is_reproducible():
    first, second = demo(), demo()
    assert first == second
    assert first["result"]["state"] == "closed"
    assert len(first["evidence"]["events"]) == 4
    assert first["result"]["cvss_base"] == 9.8


def test_idempotent_intake_and_conflict(setup):
    store, service, intake, _ = setup
    assert service.ingest(A, intake, NOW) == service.ingest(A, intake, NOW)
    assert len(store.evidence(A)["events"]) == 1
    intake.finding.asset = "synthetic:other"
    with pytest.raises(DomainError):
        service.ingest(A, intake, NOW)


@pytest.mark.parametrize("change", ["stale", "future", "foreign-cve", "foreign-repo"])
def test_intake_evidence_binding(setup, change):
    _, service, intake, _ = setup
    if change == "stale":
        intake.enrichment.as_of = "2026-01-01T00:00:00Z"
    elif change == "future":
        intake.finding.observed_at = "2027-01-01T00:00:00Z"
    elif change == "foreign-cve":
        intake.enrichment.cve = "CVE-2099-0002"
    else:
        intake.finding.repository = "foreign/repository"
    with pytest.raises(DomainError):
        service.ingest(A, intake, NOW)


def test_priority_is_transparent_and_owner_is_server_assigned(setup):
    _, service, intake, _ = setup
    intake.enrichment.kev = False
    assert service.ingest(A, intake, NOW)["priority"] == "P1"
    intake.finding.id = "low-score"
    intake.finding.cvss_vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    intake.enrichment.epss = 0.01
    result = service.ingest(A, intake, NOW)
    assert result["priority"] == "P2" and result["owner"] == "platform"


def test_approval_independence_digest_and_states(setup):
    _, service, intake, proposal = setup
    record = service.ingest(A, intake, NOW)
    with pytest.raises(DomainError):
        service.approve(B, record["id"], "0" * 64, NOW)
    record = service.propose(A, record["id"], proposal, NOW)
    same = Identity(tenant="alder", subject=A.subject, roles=["approver"])
    with pytest.raises(DomainError):
        service.approve(same, record["id"], record["proposal_sha256"], NOW)
    with pytest.raises(DomainError):
        service.approve(B, record["id"], "0" * 64, NOW)
    with pytest.raises(DomainError):
        service.propose(A, record["id"], proposal, NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("asset", "foreign"),
        ("repository", "foreign/repo"),
        ("revision", "c" * 40),
        ("artifact_sha256", "0" * 64),
        ("observed_at", "2026-10-29T00:00:00Z"),
        ("observed_at", "2026-10-31T00:00:00Z"),
        ("checked_cves", ["CVE-2099-9999"]),
        ("observed_cves", ["CVE-2099-0001"]),
    ],
)
def test_false_closure_rejected(setup, field, value):
    _, service, _, _ = setup
    record = approved(setup)
    evidence = rescan(record).model_dump()
    evidence[field] = value
    with pytest.raises(DomainError):
        service.close(C, record["id"], Rescan.model_validate(evidence), NOW)


def test_self_verification_foreign_tenant_and_role_rejected(setup):
    _, service, _, _ = setup
    record = approved(setup)
    same = Identity(tenant="alder", subject=A.subject, roles=["verifier"])
    for actor in [A, same, DEMO_IDENTITIES["demo-other-tenant"]]:
        with pytest.raises(DomainError):
            service.close(actor, record["id"], rescan(record), NOW)


def test_scanner_actually_distinguishes_fixed_and_vulnerable():
    args = dict(
        asset="synthetic:service/api",
        repository="synthetic/service",
        revision="b" * 40,
        observed_at=NOW,
    )
    assert scan_synthetic_lock(
        Path("samples/vulnerable.txt").read_text(), **args
    ).observed_cves == ["CVE-2099-0001"]
    assert scan_synthetic_lock(Path("samples/fixed.txt").read_text(), **args).observed_cves == []
    with pytest.raises(ValueError):
        scan_synthetic_lock("unrelated-package==1.0", **args)


def test_feed_import_checks_completeness_and_dates():
    epss = {"status": "OK", "data": [{"cve": "CVE-2099-0001", "epss": "0.7", "date": "2026-10-30"}]}
    kev = {"dateReleased": NOW, "count": 1, "vulnerabilities": [{"cveID": "CVE-2099-0001"}]}
    assert import_feeds("CVE-2099-0001", epss, kev).kev
    for bad in [{**kev, "count": 2}, {**kev, "dateReleased": "2026-01-01"}]:
        with pytest.raises(ValueError):
            import_feeds("CVE-2099-0001", epss, bad)
    with pytest.raises(ValueError):
        import_feeds("CVE-2099-9999", epss, kev)
    with pytest.raises(ValueError):
        import_feeds("CVE-2099-0001", {}, kev)


def test_strict_schema_rejects_unknown_fields_invalid_vectors_and_nan(setup):
    _, _, intake, _ = setup
    for patch in [{"tenant": "other"}, {"cvss_vector": "invalid"}, {"observed_at": "2026-10-30"}]:
        with pytest.raises(ValidationError):
            type(intake.finding).model_validate({**intake.finding.model_dump(), **patch})
    with pytest.raises(ValidationError):
        Enrichment.model_validate({**intake.enrichment.model_dump(), "epss": float("nan")})


def test_pr_proposal_does_not_authorize_closure(setup):
    record = approved(setup)
    payload = pr_request(record)
    assert payload["head"] == "remediation/demo-001"
    assert record["proposal_sha256"] in payload["body"]
    with pytest.raises(ValueError):
        pr_request({**record, "state": "open"})


def test_audit_corruption_detected_and_restart_preserves_state(setup):
    store, _, _, _ = setup
    approved(setup)
    restarted = Store(store.path)
    assert len(restarted.listing(A, "finding")) == 1
    assert restarted.listing(DEMO_IDENTITIES["demo-other-tenant"], "finding") == []
    with store.tx() as db:
        db.execute("UPDATE audit SET payload='{}' WHERE seq=1")
    with pytest.raises(DomainError):
        store.evidence(A)
