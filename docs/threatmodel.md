# RemediationOS threat model

## Overview

Intended use: the runnable repository implementation and its documented local demo. The user requested an open-source implementation with honest security scope. This model describes inspected source, not a security certification or a claim of complete audit coverage.

Data flow: Bearer identity --> tenant ownership --> intake/enrichment --> proposal --> independent approval --> exact artifact rescan evidence --> independent closure --> transactional audit.

| Component/source | Responsibility |
| --- | --- |
| `app/api.py:66` | Authenticated operation API and bounded request body middleware |
| `app/common.py:176` | Trusted token-to-tenant/subject/role mapping |
| `app/lifecycle.py:83` | State transitions, owner binding, approval and closure invariants |
| `app/rescan.py:9` | Actual deterministic fictional-package scanner |
| `app/github.py:21` | Optional read-only PR head/repository binding |

| Deployment or workflow | Resource/configuration and effective location | Readers, writers or recipients | Enforcing control or unknown |
| --- | --- | --- | --- |
| Configured service credentials | IDENTITY_FILE private JSON token map; OWNER_FILE tenant/repository owner map | Server memory and trusted operator | CLI rejects short credentials and group/other-readable identity files; direct factory callers own equivalent provisioning |
| Configured state | STATE_PATH or artifacts/state.db, relative to working directory | Tenant-scoped authenticated actors; server process | SQLite WAL, parameterized composite tenant keys, immediate transactions; database mode 0600; directory must be private |
| Offline demo | Temporary database; samples/vulnerable.txt and samples/fixed.txt | Synthetic demo actors | Actual bounded fictional scanner; fixed clock; temporary state removed |
| Browser demo rescan | Only explicit demo mode; fixed allowlisted samples/fixed.txt | Verifier role | Invokes actual scanner, then closure validates the approved artifact digest; no custom source path |
| PR evidence helper | Fixed https://api.github.com/repos/{repository}/pulls/{number} | GitHub receives operator token | No redirects; exact proposed head and repository match; never authorizes closure |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Tenant findings, ownership, proposal/artifact digests, independent approval identities, rescan evidence, bearer credentials and audit history.

The identity map supplies tenant and roles, independent of request JSON. Repository ownership is checked against the same tenant. Proposal approval binds its digest and requires a different subject; verification requires a third subject. Closure checks revision, artifact hash, scope, timestamp and absence of the target CVE in an explicitly covered completed scan. External CI evidence is a trusted verifier assertion, not an authenticated CI signature. The synthetic scanner is limited to fictional inputs and cannot close imported real findings.

Host administrators, private configuration owners and trusted repository maintainers can alter code, files and private state. They are trusted. An ordinary input author does not gain those capabilities by supplying JSON. Public demo credentials represent synthetic roles in one trusted local demonstration. The local stateless TypeScript evaluators do not establish authenticated service tenancy; the Python services derive tenancy from trusted identities. External assertions retain their stated trust prerequisites.

Live feed retrieval, real external scanner identity and real GitHub PR verification are unverified. There is no automatic patch application. No SSO, credential rotation service, distributed workers or production availability claim. Public demo identities are not separation between real people.

## Attack Surface, Mitigations, and Attacker Stories

These are threat scenarios and review obligations, not reported vulnerabilities. Priority describes plausible impact if the named control fails in its stated deployment. The source table above identifies the actual consumers and controls.

| Priority | Scenario and potential capability gain | Existing source-established controls | Additional mitigation or prerequisite |
| --- | --- | --- | --- |
| High | An authenticated user reads or changes another tenant record. | All database object keys and queries include the authenticated tenant; input contracts reject tenant selection. | Keep identity provisioning trusted; test new read and write paths. |
| High | A proposer approves or verifies their own patch using combined roles. | Subject separation is enforced independently of role possession. | Map distinct subjects to distinct people and protect credentials. |
| High | An unrelated, stale or fabricated clean report closes a finding. | Exact artifact/revision/asset/repository/CVE/freshness checks; independent verifier required. | Verifier truthfulness remains trusted; add authenticated CI artifact retrieval before claiming external attestation verification. |
| Medium | A state transition succeeds while its audit evidence is lost. | State and audit append commit in the same SQLite transaction. | Keep private durable storage and export external checkpoints; local chain cannot resist owner rewrite/truncation. |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require a credible unauthenticated path to broad privileged external execution or equivalent cross-tenant compromise. This model does not establish such a path. A fictional sandbox state change is not critical cloud compromise.

High includes a reachable authorization, approval or gate bypass that grants a materially new capability over another tenant or a deployment decision, with the required privileged consuming workflow present. An input author changing their own local file is a counterexample.

Medium includes bounded local denial of service, decision-fidelity loss or evidence misbinding under realistic deployment prerequisites. Merely changing trusted policy as its administrator is a counterexample.

Low includes limited presentation/integrity confusion without a new privileged operation. A string that is safely rendered as text is controlled behavior, not an injection finding. Confidence depends on source and executable evidence, independently of impact.

One fresh-context independent read-only architecture review informed this model. Source changed during construction; the parent rechecked the controls and source anchors after the reported discrepancies were fixed. Verified negatives are recorded in tests and verification artifacts. External account behavior remains unverified wherever stated.

Repository: https://github.com/jayekwere/remediationos
Version: cf0bb61277581b7ea021fca62b9c18bc383923d5
