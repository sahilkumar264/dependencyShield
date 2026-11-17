# Jev risk decisions

## Provider contract

When `TYPESAFE_API_KEY` is configured, the API sends one typed multi-question JSON request to `POST https://api.typesafe.ai/v1/systemone`. The request contains `model`, a minimized structured `state`, and six questions using Jev's `choice`, `score`, and `noul` primitives. The provider key is read server-side only. The returned `model`, full answer distributions, confidence values, and token usage are validated and retained for audit.

The request includes vulnerability ID and available severity/CVSS data, package identity/version/ecosystem, direct/transitive classification, and user-supplied OKF environment, criticality, exposure, data classification, SLA, and service dependencies. It excludes repository source, source paths, repository URLs, credentials, application names, owners, and teams. Vulnerability match facts remain deterministic OSV results; Jev only recommends response categories and priority.

The code retries provider timeouts/network failures and HTTP 429/529 with bounded exponential backoff and `Retry-After`. Other HTTP failures, malformed JSON, or response-schema mismatches produce an explicitly labelled deterministic fallback. Set `JEV_MODEL_VERSION` to a pinned model identifier in production; the default `jev-latest` is a moving alias, and the response's resolved model is stored separately.

## Deterministic policy

Policy `dependencyshield-risk-v1` applies a floor after Jev's recommendation:

- Known exploited: P1 or higher; this field remains unknown until KEV integration is available.
- CVSS 9.0 or higher / critical severity: P1 or higher.
- CVSS 7.0 or higher / high severity: P2 or higher.
- CVSS 4.0 or higher / medium severity: P3 or higher.
- Low severity: P4 floor.
- Missing/unsupported severity: conservative P3 baseline, marked in the persisted input and evidence.

Priority order is P0 (most urgent) through P4. The final priority is the more urgent of the deterministic floor and Jev's choice/score conversion. P0/P1 automatically require human review and escalation. Missing, conflicting, or invalid OKF risk context requires review. Fallback decisions always require review. No decision endpoint creates issues, pull requests, package upgrades, or other remediation actions.

Jev does not return a rationale field. DependencyShield stores its typed answers and probabilities, then records a separate deterministic explanation describing the floor, selected priority, context gaps, and review action. This avoids fabricating a model explanation.

## OKF context convention

User-authored context concepts linked to an application may supply this producer-defined extension in YAML frontmatter:

```yaml
risk_context:
  environment: production
  criticality: critical
  internet_exposed: true
  data_classification: confidential
  sla: "99.9% availability"
  service_dependencies: [payments-ledger, identity-provider]
```

Omit or set unavailable values to `unknown`; missing values are not converted to `false`. Conflicting linked concepts are passed as `conflicting` and force human review. The UI template shows the allowed values. Team/owner values remain available in OKF for future routing, but are not sent to Jev.

## API

- `POST /api/findings/:id/decisions` evaluates one finding and stores a decision audit record. Without a Jev key it returns a recorded deterministic fallback.
- `GET /api/decisions` lists the signed-in user's decision history. Supports `applicationId`, `findingId`, and `limit`.
- `GET /api/decisions/:id` returns the exact input state, question definitions, validated answers, policy evidence, usage, and final action for one decision.

## Official references

- [TypeSafe System One API](https://docs.typesafe.ai/api/system-one)
- [Choice](https://docs.typesafe.ai/primitives/choice)
- [Score](https://docs.typesafe.ai/primitives/score)
- [Noul](https://docs.typesafe.ai/primitives/noul)
- [TypeSafe request rules and errors](https://docs.typesafe.ai/api/errors)
- [TypeSafe introduction](https://docs.typesafe.ai/introduction)
