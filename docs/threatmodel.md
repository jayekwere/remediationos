# RemediationOS threat model

## Overview

RemediationOS is a FastAPI and SQLite lifecycle service with a TypeScript browser operation workbench. Authenticated identities supply tenant, subject and roles. Repository ownership is server-configured. Findings pass through enrichment, proposed fixes, independent approval and exact-artifact rescan checks before closure. The offline CLI uses temporary state; served demos use persistent configured state. Optional feed-import and GitHub read helpers have separate, limited authority. One independent fresh-context read-only review confirmed the unchanged runtime boundaries and informed this revision. This model is not a security certification or completed audit.

| Component | Source and role |
| --- | --- |
| HTTP operations | `app/api.py:66`, authentication and request controls |
| Trusted identities and state | `app/common.py:56`, `app/common.py:176` |
| Ownership and lifecycle | `app/lifecycle.py:83` |
| Fictional-package scanner | `app/rescan.py:9` |
| Saved official-feed import | `app/enrichment.py:9` |
| Optional PR revision readback | `app/github.py:21` |
| Browser operation parser/display | `web/app.ts:17` |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Configured CLI service | Identity map | IDENTITY_FILE then JSON Identity validation | Operator-selected private file, relative to CWD when relative | Service memory and trusted operator | Owner-only file mode, tokens at least 32 characters, strict identities | `app/cli.py:60`; factory callers own equivalent provisioning |
| Configured CLI service | Ownership map | OWNER_FILE then Lifecycle owners | Operator-selected tenant/repository/owner map | Service and trusted operator | Explicit map required; authenticated-tenant repository membership | `app/cli.py:71`, `app/api.py:83`, `app/lifecycle.py:88`; file privacy is host-owned |
| Served configured/demo mode | Persistent state | STATE_PATH or artifacts/state.db | Selected database or cwd/artifacts/state.db and SQLite companions | Service and tenant-scoped callers | Database 0600, parameterized tenant keys, immediate WAL transactions | `app/cli.py:68`, `app/common.py:56`; directory and companion privacy remain host responsibilities |
| Offline CLI demo | Temporary state and fixture inputs | TemporaryDirectory, workflow.json, fixed.txt | Temporary demo.db; cwd/samples/workflow.json and fixed.txt | Synthetic actors and stdout consumer | Fixed clock, local scanner, temporary lifecycle | `app/cli.py:19`; vulnerable.txt is separately exercised by tests |
| Compose service | Persistent state/listener | WORKDIR /app, state volume, HOST=0.0.0.0 and loopback publication | /app/artifacts/state.db in engine-managed state volume; host 127.0.0.1:8080 | UID 10001 process, host and loopback clients | Read-only root, no capabilities, no-new-privileges and resource limits | `Dockerfile:9`, `compose.yaml:4`; engine host backing path is deployment-specific |
| Container smoke workflow | Ephemeral state | Explicit /app/artifacts tmpfs | Database in UID/GID 10001 mode-0700 tmpfs | Synthetic process | Private tmpfs and container removal | `scripts/container-smoke.mjs:17` |
| Browser demo rescan | Fixed fictional artifact | Verifier operation, explicit demo mode, no custom input | cwd/samples/fixed.txt or /app/samples/fixed.txt | Scanner and authenticated verifier | Approved synthetic finding required; closure independently checks digest | `app/api.py:147`, `app/rescan.py:9` |
| Feed library | Supplied provider-shaped data | Caller supplies EPSS and KEV objects | In-memory dated enrichment record | Caller and lifecycle intake | Exact CVE coverage, counts and date-consistency checks | `app/enrichment.py:9`; retrieval/authenticity remain caller-owned |
| Optional PR library | Repository/head readback | Caller supplies approved record, PR number and token | Fixed api.github.com/repos/bound-repository/pulls/number | GitHub receives caller token | No redirects, 10-second timeout, exact repository/head match, closure_authorized false | `app/github.py:21`; no patch, branch, merge or closure operation |
| Verification CI | Synthetic evidence export | Tests/demo and artifact upload | artifacts/, coverage and browser evidence; 14-day retention | GitHub artifact readers | Pinned actions, contents:read, disabled checkout credentials, synthetic inputs | `.github/workflows/verify.yml:7`, `.github/workflows/verify.yml:17`; real secrets must stay outside exported paths |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets are bearer credentials, ownership configuration, tenant findings, proposal and artifact digests, independent approval identities, rescan evidence and transactional audit history. An unauthenticated caller may reach UI/health routes but cannot invoke protected operations without credentials. An analyst can submit supported findings and patch text within its configured tenant; request JSON cannot select tenant or owner. Host administrators, configuration owners and trusted maintainers already control code and private state and are outside isolation (`SECURITY.md:6`, `app/api.py:96`, `app/common.py:84`).

Strict contracts reject extra fields. Identity-derived role checks and tenant-scoped database lookups are distinct from Host/Origin, 1 MiB body, CSP and data-only rendering controls. The TypeScript component is an operation workbench; it is not a separate stateless authorization service (`app/common.py:16`, `app/api.py:36`, `app/api.py:107`, `web/app.ts:17`).

Proposal approval binds its digest and excludes the proposing subject. Closure requires a third subject and exact asset, repository, approved revision, artifact SHA-256, covered CVE, complete scan and freshness. A PR link or an unrelated clean report cannot close a finding. The fictional scanner can close only the explicitly synthetic finding, never an imported real finding (`app/lifecycle.py:136`, `app/lifecycle.py:158`, `app/lifecycle.py:175`, `app/lifecycle.py:184`).

A trusted verifier may submit trusted-ci-attestation evidence. This remains that verifier's assertion, not a cryptographically authenticated CI artifact or verified external scanner identity. Truthfulness and credential provisioning are trusted. Public demo roles do not prove independent people. Configured identities must map distinct subjects to separately controlled credentials. No automatic external rescan, patch application or merge is implemented (`app/lifecycle.py:65`, `app/lifecycle.py:175`).

The feed importer validates supplied data, not its network origin. The PR helper reads one fixed API origin without redirects, trusts its supplied approved record and never authorizes closure. Provided runtime verification, separately recorded in `docs/live-read-verification.json:1`, exercised native FIRST/CISA import for CVE-2021-44228, an existing repository PR head read and rejection of a wrong head. Its approval input was synthetic. No finding or PR changed, and no real vulnerability rescan or deployment was verified.

State updates and audit append share one SQLite transaction. Local hash-chain verification checks consistency of retained rows but cannot prevent a trusted database owner rewriting or truncating the entire sequence (`app/common.py:68`, `app/common.py:102`, `app/common.py:123`). Existing directory privacy, ownership files and container volume access remain host obligations. Private paths, snapshot/key/environment files are excluded from accidental packaging, not authenticated by those exclusions (`.dockerignore:11`).

There is no SSO, credential-rotation service, general asset discovery, distributed worker, automatic feed poller or production availability claim. The reference implementation's closure checks do not prove deployment into a real service. Missing account/scanner verification must remain explicit.

## Attack Surface, Mitigations, and Attacker Stories

These are review hypotheses, not validated findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High | Authenticated user reads or changes another tenant record | Valid limited credential and reachable service | Cross-tenant disclosure or mutation | Identity-derived tenant, owner map, strict payloads, parameterized tenant keys | Test every new read/write path and protect provisioning | `app/common.py:84`, `app/lifecycle.py:88` |
| High | Proposer approves or verifies its own fix through combined roles | One subject holds multiple roles | Bypassed independent decision | Subject separation independently of roles | Use separately controlled credentials for real people | `app/lifecycle.py:158`, `app/lifecycle.py:175` |
| High | Fabricated or unrelated clean evidence closes a finding | Verifier authority or bypassed evidence boundary | Incorrect remediation closure | Exact artifact/revision/asset/repository/CVE/freshness checks | Authenticate external CI artifacts before claiming external scanner identity | `app/lifecycle.py:175` |
| Medium | Fresh feed labels hide missing CVE coverage or stale data | Caller supplies provider-shaped data | Misprioritization | Exact EPSS record, KEV count and date checks; lifecycle freshness | Preserve official source snapshots and retrieval provenance | `app/enrichment.py:9`, `app/lifecycle.py:88` |
| Medium | State commits while audit evidence is lost | Fault or faulty transition implementation | Incomplete lifecycle evidence | One SQLite transaction for state and audit | Durable private storage and external checkpoints | `app/common.py:68`, `app/common.py:102` |
| Low | PR existence or merge status is mistaken for closure authority | Misreading helper output | Overstated remediation evidence | closure_authorized false and separate closure API | Keep PR readback distinct from exact-artifact rescan | `app/github.py:21`, `app/lifecycle.py:175` |

## Severity Calibration (Critical, High, Medium, Low)

Critical requires a credible route to broad unauthorized authority, not a fictional package result. High applies to reachable tenant, independent-subject or evidence-binding bypasses that grant a new capability over another tenant or a real consuming decision. Medium covers bounded availability, confidentiality or decision-fidelity effects with actual prerequisites. Low covers limited presentation or workflow confusion without a new privileged operation. A trusted verifier's explicit authority and a host owner's file edits are existing trust, not newly gained attacker privilege. Native adapter reads improve confidence only in those reads and do not establish real finding closure.

Repository: https://github.com/jayekwere/remediationos
Version: 0ce7c92ad9c401e63e934b767d982b587595b49b
