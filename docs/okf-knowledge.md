# OKF knowledge bundles

DependencyShield stores a separate OKF v0.2 bundle for each authenticated workspace. Bundle documents are canonical Markdown strings with YAML frontmatter in `okf_bundle_documents`; PostgreSQL indexes concepts and links for retrieval while complete snapshots remain versioned in `okf_bundle_revisions`.

## Generated concepts

The integration synchronizes `Application` concepts from connected application records and `Repository` concepts from repositories authorized through the GitHub App. Each generated concept includes a `generated` actor and timestamp plus a `sources` entry when a GitHub URL is available. Synchronization does not invent owners, teams, environments, criticality, internet exposure, data classification, SLAs, or remediation policies.

`context/organizational-context.md` explicitly records those missing values as unknown. Users can add Markdown concepts such as teams, owners, environments, service relationships, and policies. Link a context concept to an application with an ordinary Markdown link such as `[Payment API](/applications/<application-uuid>.md)`.

User concepts are stored as raw Markdown in versioned snapshots. Integration-owned `applications/`, `repositories/`, the generated context inventory, `index.md`, and `log.md` paths are protected from manual overwrite. A later revision preserves user-authored concepts.

## API

- `GET /api/okf/bundles` lists the workspace bundle and current revision.
- `GET /api/okf/bundles/export` returns the current bundle as a path-to-Markdown document list; `?revision=N` retrieves a previous snapshot.
- `GET /api/okf/bundles/:id/revisions` lists immutable revision metadata.
- `GET /api/okf/concepts` supports `q`, `type`, and `tag` filters.
- `GET /api/okf/concepts/:id` returns a concept and its incoming/outgoing links.
- `POST /api/okf/validate` validates a supplied map of relative Markdown paths to content. Broken links are reported as warnings and remain consumable, as OKF v0.2 requires.
- `POST /api/okf/concepts` creates or updates a user concept and writes a new bundle snapshot.
- `GET /api/applications/:id/context` returns the application concept and related organizational context concepts.

Validation enforces OKF's required YAML frontmatter and non-empty `type`, validates reserved `index.md` and `log.md` conventions, and reports soft metadata problems, unresolved links, trust tier, lifecycle status, and staleness. Unknown frontmatter keys and concept types are preserved.

## References

- [Canonical OKF repository](https://github.com/GoogleCloudPlatform/open-knowledge-format)
- [OKF v0.2 specification](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/main/SPEC.md)
