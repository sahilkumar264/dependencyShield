# DependencyShield architecture

## Runtime components

- `apps/web`: Next.js dashboard for sign-in, repository selection, scans, inventory, and findings.
- `apps/api`: Fastify API, GitHub OAuth callback, GitHub App integration, authorization, PostgreSQL access, and BullMQ producer.
- `apps/api/src/worker.ts`: separate queue worker process for repository scans.
- PostgreSQL: identities, GitHub installations, repositories, scans, SBOMs, components, dependency edges, OSV records, code evidence, remediation audits, webhook deliveries, and monitoring alerts.
- Redis: BullMQ transport.
- `scanner` Compose service: restricted Node worker image with a checksum-verified, version-pinned Syft binary.

## Repository and scan flow

1. GitHub App installation grants per-repository permission. The setup callback validates the installation using the signed-in user's GitHub App user access token before it stores the relationship.
2. The repository picker loads only repositories exposed by that installation. A selected branch is verified through GitHub before saving it.
3. A scan request stores the selected branch and adds a stable scan ID to BullMQ.
4. The worker requests a short-lived installation token scoped to the one repository, resolves the branch to a commit SHA, and fetches the archive from GitHub's API. Redirects are limited to HTTPS `codeload.github.com`.
5. Syft scans the archive without running repository scripts or installing packages. Its CycloneDX output is structurally validated, including component references and dependency endpoints.
6. PostgreSQL stores the SBOM document and indexed component/dependency records. OSV receives supported package ecosystem/name/version triples. Advisory records retain the original response, and findings point to the SBOM component that produced the query.
7. The worker safely extracts bounded source files and runs Semgrep with local rules. Findings and possible package import evidence are commit-scoped; this pass does not claim inter-file exploitability.
8. A UTC BullMQ scheduler queues daily scans for repositories with monitoring enabled. Signed GitHub push webhooks queue scans pinned to the pushed commit when the push targets the configured branch. Each scan re-queries current OSV package/version data and emits deduplicated in-app alerts for newly observed vulnerable package versions.

## Trust boundaries

Repository archives are untrusted. They are streamed to a size-limited temporary directory, scanned in a container with a read-only root filesystem, dropped Linux capabilities, no-exec temporary storage, memory/CPU/process limits, and a five-minute Syft timeout. The temporary directory is removed after processing.

Repository source content is not sent to OSV. Only package identity and version are queried. OSV outages mark the scan as completed with warnings and vulnerability coverage unavailable. Unmapped package identities produce partial coverage, not a safe result.

GitHub webhook payloads are authenticated with HMAC-SHA256 over the original raw body and deduplicated by delivery UUID. Webhook handling queues work and responds without waiting for a scan. Per-repository advisory refresh currently happens through scheduled exact-version OSV queries rather than a full OSV database mirror.

## Authentication and token handling

GitHub App web authorization uses state cookies, PKCE, and `offline_access` for expiring user tokens. Access and refresh tokens are encrypted using AES-GCM JWE before storage. App private keys remain in environment configuration. Scan work uses short-lived installation tokens restricted to the selected repository.

GitHub issue and draft PR actions are user-triggered and use repository-scoped installation tokens. Every draft PR requires a recorded user approval, remains a draft, and is never merged by DependencyShield. The current code-upgrade path is limited to a direct npm dependency with one unambiguous OSV fix and no root lockfile; other cases can create a remediation issue.

## Async processing and history

The API persists a scan record before enqueueing a job. Worker operations are designed to be idempotent by scan ID. BullMQ applies exponential retries; a final failure is reflected in PostgreSQL. Historical SBOMs and findings remain associated with their scans.
