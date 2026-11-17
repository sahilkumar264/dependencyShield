# Implementation checklist

## Phase 1 — Foundation

- [x] pnpm monorepo with Next.js web, Fastify API, and shared types.
- [x] PostgreSQL, Redis, and Docker Compose development stack.
- [x] Database migrations and startup environment validation.
- [x] GitHub sign-in foundation with PKCE, state, encrypted tokens, and session cookies.
- [x] Dashboard shell and real empty states.

## Phase 2 — Repository and SBOM workflow

- [x] GitHub App installation and per-user installation verification.
- [x] Repository selection and branch selection.
- [x] BullMQ scan jobs and persisted scan status.
- [x] Restricted scanner container with Syft 1.57.1 checksum verification.
- [x] Archive size limit, redirect host check, scan timeout, resource limits, and cleanup.
- [x] CycloneDX SBOM validation, persistence, and component/dependency indexing.
- [x] OSV exact package/version queries, advisory payload retention, and findings.
- [x] Unknown/unsupported coverage and OSV outage status are distinct from an unaffected result.
- [ ] Configure a real GitHub App and credentials, then run the complete authenticated workflow against a user-authorized repository.

## Phase 3 — Dependency intelligence

- [x] Create one application record for each connected repository and associate it with scan snapshots.
- [x] Preserve the CycloneDX metadata root and dependency edges alongside package components.
- [x] Classify direct and transitive package paths with explicit incomplete/unknown states.
- [x] Return application inventory, dependency graph, and affected finding paths from authenticated API endpoints.
- [x] Add an application dashboard and interactive React Flow dependency graph.
- [ ] Discover multiple independently deployable applications inside monorepositories.

## Phase 4 — OKF knowledge engine

- [x] Create per-workspace Markdown/YAML knowledge bundles with immutable revision history.
- [x] Synchronize application and repository concepts from authorized integration records with provenance and generated metadata.
- [x] Mark unavailable organizational attributes as unknown instead of inferring false values.
- [x] Parse and validate OKF v0.2 frontmatter and reserved bundle documents; surface soft metadata issues and unresolved links.
- [x] Extract Markdown concept links into versioned relationship indexes and expose concept lookup/search.
- [x] Add authenticated APIs for bundle export, revision history, validation, concept authoring, and application context.
- [x] Add a knowledge explorer for concepts, relationships, trust/provenance, freshness, and user-authored context.

## Phase 5 — Jev decisions and deterministic risk policy

- [x] Integrate the documented TypeSafe System One HTTP contract with typed Choice, Score, and Noul questions.
- [x] Validate response types, answer distributions, confidence, resolved model, and token usage.
- [x] Keep API credentials server-side and send only minimized structured impact/context; no repository source or paths are sent.
- [x] Add bounded timeout/network and 429/529 retry behavior with Retry-After support.
- [x] Persist request state, question definitions, full answers/probabilities, model, usage, fallback reason, deterministic policy evidence, and final action.
- [x] Add severity/CVSS policy floors, escalation/review thresholds, explicit deterministic fallback, and no-remediation execution boundary.
- [x] Add decision history/detail APIs, application-level evaluation controls, and a decision audit page.
- [ ] Configure a TypeSafe key and pinned model to exercise a live Jev request.

## Phase 6 — Static analysis and reachability evidence

- [x] Add safe, bounded archive extraction that rejects unsafe paths and links and never runs repository scripts.
- [x] Run pinned Semgrep Community Edition using local rules and JSON output.
- [x] Store code findings and commit-specific package import evidence separately from OSV findings.
- [x] Label import matches as possible usage; unsupported or unavailable analysis remains unknown.
- [x] Keep source snippets in DependencyShield and omit them from TypeSafe requests.
- [x] Capture Go grouped imports and Rust `use` references alongside JavaScript, TypeScript, Python, and Java import forms; all matches remain possible-usage evidence.
- [ ] Validate a full Semgrep scan on a connected repository and calibrate package-to-module mappings against real projects.

## Phase 7 — Human-controlled remediation

- [x] Create GitHub issues from authorized findings with idempotency markers and an audit record.
- [x] Generate draft pull requests for supported direct npm upgrades with a unique branch and explicit user confirmation.
- [x] Require an OSV fixed version; update a supported root npm package-lock safely with lifecycle scripts disabled and refuse unsupported lock formats.
- [x] Preserve a testing/review checklist in draft PRs; no dependency scripts are run and no PR is merged automatically.
- [x] Persist action status, GitHub URL/number, authorizing user, and failure reason.
- [x] Display current GitHub Checks API results for a draft PR's exact head commit, including pending, success, and failure states.
- [ ] Grant the GitHub App Issues, Contents, Pull requests write, and Checks read permissions; exercise remediation on a user-authorized repository.
- [ ] Add lockfile-aware remediation for pnpm, Yarn, npm shrinkwrap, workspaces, and private registries.

## Phase 9 — Advisory intelligence

- [x] Enrich exact-version package checks with GitHub Advisory Database results for npm, PyPI, Maven, Go, and Rust packages.
- [x] Retain GitHub advisory source payloads and connect CVE aliases to existing canonical vulnerabilities where available.
- [x] Refresh and persist the CISA Known Exploited Vulnerabilities catalog during daily monitoring.
- [x] Include confirmed KEV membership in Jev's structured evidence; absent catalog entries remain unknown.
- [x] Enrich CVE aliases with cached NVD records, including CVSS metrics and weakness data; NVD outages do not suppress findings.
- [x] Evaluate npm, Go, and Cargo OSV SEMVER ranges, PyPI OSV ECOSYSTEM/PEP 440 ranges, and GitHub npm vulnerable-version ranges locally; persist evidence and keep unsupported/conflicting formats explicitly unknown.
- [x] Follow OSV query pagination with a bounded page limit so large advisory result sets are not silently truncated.
- [ ] Add Maven ECOSYSTEM range evaluation; unsupported formats remain explicitly unknown locally.
- [ ] Exercise source enrichment and KEV synchronization against live advisory records in a configured deployment.

## Phase 8 — Continuous monitoring

- [x] Schedule daily scans through BullMQ Job Schedulers with an overridable UTC cron expression.
- [x] Add per-repository monitoring pause/resume and avoid overlapping active scans.
- [x] Verify GitHub webhook HMAC signatures against the raw request body and deduplicate deliveries.
- [x] Queue exact-commit scans for pushes to the configured branch and handle repository/install access changes.
- [x] Refresh OSV results during scheduled scans and persist deduplicated in-app alerts for newly observed vulnerable package versions.
- [x] Add alert list/read APIs and dashboard notifications.
- [x] Retry recent failed GitHub App webhook deliveries on a 15-minute schedule, with a three-attempt cap and delivery deduplication.
- [x] Add an optional HTTPS JSON webhook for new vulnerability alerts; delivery failures do not fail scans.
- [ ] Configure a public HTTPS GitHub App webhook URL and secret; validate push delivery and daily scheduler behavior on an authorized installation.
- [ ] Add dedicated provider integrations and full OSV feed synchronization beyond scan-based query refresh.

## Phase 10 — Deployment packaging

- [x] Add production-mode API and Next.js web containers to Docker Compose.
- [x] Add container health checks, dependency ordering, read-only root filesystems, and resource limits for API/web services.
- [x] Keep the scanner isolated as a worker container and persist PostgreSQL/Redis data in named volumes.
- [x] Build and start the local Compose stack; PostgreSQL, Redis, API, web, and scanner worker reached healthy/ready states.
- [ ] Validate the complete container stack with configured GitHub App credentials and public HTTPS endpoints.

## Integration references

- [GitHub App user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [GitHub installation access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)
- [Syft CLI](https://oss.anchore.com/docs/reference/syft/cli/)
- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [CycloneDX dependency graph guidance](https://www.cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf)
- [React Flow documentation](https://reactflow.dev/learn)
- [OKF v0.2 specification](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/main/SPEC.md)
- [TypeSafe System One API](https://docs.typesafe.ai/api/system-one)
- [TypeSafe Choice](https://docs.typesafe.ai/primitives/choice)
- [TypeSafe Score](https://docs.typesafe.ai/primitives/score)
- [TypeSafe Noul](https://docs.typesafe.ai/primitives/noul)
- [GitHub webhook validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- [BullMQ Job Schedulers](https://docs.bullmq.io/guide/job-schedulers/)
- [OSV querybatch API](https://google.github.io/osv.dev/post-v1-querybatch/)
- [GitHub global security advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [NVD vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities)
- [npm semver range API](https://github.com/npm/node-semver)
- [PEP 440](https://peps.python.org/pep-0440/)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [GitHub Issues REST API](https://docs.github.com/en/rest/issues/issues?apiVersion=2026-03-10)
- [GitHub Git References REST API](https://docs.github.com/en/rest/git/refs?apiVersion=2026-03-10)
- [GitHub Pull Requests REST API](https://docs.github.com/en/rest/pulls/pulls)
- [GitHub Checks REST API](https://docs.github.com/en/rest/checks/runs)
- [GitHub App webhook redelivery API](https://docs.github.com/en/rest/apps/webhooks)
