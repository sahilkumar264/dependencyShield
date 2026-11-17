import { createHash } from "node:crypto";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { pool } from "../db/pool.js";

export type OkfDocument = { path: string; markdown: string; sourceKind?: "integration" | "user" };
export type OkfIssue = { path: string; severity: "error" | "warning"; code: string; message: string };
export type ParsedOkfConcept = { path: string; conceptId: string; frontmatter: Record<string, unknown>; body: string; markdown: string };

const MARKDOWN_LINK = /(?<!!)\[([^\]]*)\]\(([^)]+)\)/g;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof Date);
}

export function normalizeDocumentPath(path: string) {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\//, "");
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized) || normalized.length > 255 || !normalized.endsWith(".md") || /[\u0000-\u001f\u007f]/.test(normalized) || normalized.split("/").some((part) => part === "" || part === "." || part === "..")) throw new Error("Document path must be a bundle-relative .md path without traversal segments");
  return normalized;
}

export function parseOkfDocument(path: string, markdown: string): ParsedOkfConcept | null {
  const normalized = normalizeDocumentPath(path);
  const lines = markdown.replace(/^\uFEFF/, "").split(/\r?\n/);
  const errors: string[] = [];
  if (lines[0] !== "---") throw new Error("Document must start with a YAML frontmatter block");
  const end = lines.indexOf("---", 1);
  if (end < 0) throw new Error("Document frontmatter is missing its closing --- delimiter");
  const parsed = parseYaml(lines.slice(1, end).join("\n"), { uniqueKeys: true, prettyErrors: false });
  if (!isRecord(parsed)) throw new Error("YAML frontmatter must be a mapping");
  if (typeof parsed.type !== "string" || !parsed.type.trim()) errors.push("OKF concept frontmatter requires a non-empty type field");
  if (errors.length) throw new Error(errors.join("; "));
  return { path: normalized, conceptId: normalized.slice(0, -3), frontmatter: parsed, body: lines.slice(end + 1).join("\n").replace(/^\n/, ""), markdown };
}

function parseReservedDocument(path: string, markdown: string): OkfIssue[] {
  const issues: OkfIssue[] = [];
  const lines = markdown.replace(/^\uFEFF/, "").split(/\r?\n/);
  if (path.endsWith("/index.md") || path === "index.md") {
    let body = markdown;
    if (lines[0] === "---") {
      const end = lines.indexOf("---", 1);
      if (end < 0) return [{ path, severity: "error", code: "INVALID_INDEX_FRONTMATTER", message: "Index frontmatter is not closed" }];
      try {
        const frontmatter = parseYaml(lines.slice(1, end).join("\n"), { uniqueKeys: true, prettyErrors: false });
        const allowed = path === "index.md" && isRecord(frontmatter) && Object.keys(frontmatter).every((key) => key === "okf_version");
        if (!allowed) issues.push({ path, severity: "error", code: "INVALID_INDEX_FRONTMATTER", message: "Only the bundle-root index may contain frontmatter, and it may contain only okf_version" });
        else if (frontmatter.okf_version !== undefined && typeof frontmatter.okf_version !== "string") issues.push({ path, severity: "error", code: "INVALID_OKF_VERSION", message: "okf_version must be a string" });
      } catch (error) {
        issues.push({ path, severity: "error", code: "INVALID_INDEX_FRONTMATTER", message: error instanceof Error ? error.message : "Could not parse index YAML" });
      }
      body = lines.slice(end + 1).join("\n");
    }
    if (!/^\s*#\s+\S/m.test(body)) issues.push({ path, severity: "warning", code: "INDEX_WITHOUT_HEADING", message: "Index files should group links under one or more headings" });
  } else {
    if (lines[0] === "---") issues.push({ path, severity: "error", code: "LOG_HAS_FRONTMATTER", message: "log.md is a reserved update log and must not have concept frontmatter" });
    for (const [index, line] of lines.entries()) if (/^##\s+/.test(line) && !/^##\s+\d{4}-\d{2}-\d{2}$/.test(line)) issues.push({ path, severity: "error", code: "INVALID_LOG_DATE", message: `Log heading on line ${index + 1} must use ## YYYY-MM-DD` });
    if (!/^#\s+\S/m.test(markdown)) issues.push({ path, severity: "warning", code: "LOG_WITHOUT_HEADING", message: "Log files should start with a heading" });
  }
  return issues;
}

function resolveLink(sourcePath: string, rawTarget: string) {
  const target = rawTarget.trim().replace(/^<|>$/g, "");
  if (!target || target.startsWith("#") || target.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(target)) return null;
  let clean: string;
  try { clean = decodeURIComponent(target.split(/[?#]/, 1)[0] ?? ""); }
  catch { return null; }
  if (!clean || clean.endsWith("/")) return null;
  const joined = clean.startsWith("/") ? clean.slice(1) : `${sourcePath.slice(0, sourcePath.lastIndexOf("/") + 1)}${clean}`;
  const parts: string[] = [];
  for (const part of joined.replaceAll("\\", "/").split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") { if (parts.length) parts.pop(); else return null; }
    else parts.push(part);
  }
  const normalized = parts.join("/");
  if (normalized === "index.md" || normalized.endsWith("/index.md") || normalized === "log.md" || normalized.endsWith("/log.md")) return null;
  return normalized.endsWith(".md") ? normalized : `${normalized}.md`;
}

export function validateOkfBundle(documents: OkfDocument[]) {
  const issues: OkfIssue[] = [];
  const paths = new Set<string>();
  const parsed: ParsedOkfConcept[] = [];
  const normalizedDocs: OkfDocument[] = [];
  for (const document of documents) {
    let path: string;
    try { path = normalizeDocumentPath(document.path); }
    catch (error) { issues.push({ path: document.path, severity: "error", code: "INVALID_PATH", message: error instanceof Error ? error.message : "Invalid document path" }); continue; }
    if (paths.has(path)) { issues.push({ path, severity: "error", code: "DUPLICATE_PATH", message: "Bundle contains more than one document at this path" }); continue; }
    paths.add(path);
    normalizedDocs.push({ ...document, path });
    if (path === "index.md" || path.endsWith("/index.md") || path === "log.md" || path.endsWith("/log.md")) {
      issues.push(...parseReservedDocument(path, document.markdown));
      continue;
    }
    try { parsed.push(parseOkfDocument(path, document.markdown)!); }
    catch (error) { issues.push({ path, severity: "error", code: "INVALID_CONCEPT", message: error instanceof Error ? error.message : "Invalid OKF concept" }); }
  }
  const pathsSet = new Set(parsed.map((concept) => concept.path));
  for (const concept of parsed) {
    const fm = concept.frontmatter;
    if (fm.generated !== undefined && (!isRecord(fm.generated) || typeof fm.generated.by !== "string" || !fm.generated.by || (fm.generated.at !== undefined && !validInstant(fm.generated.at)))) issues.push({ path: concept.path, severity: "warning", code: "INVALID_GENERATED_METADATA", message: "generated should include an actor in by and an ISO 8601 datetime in at" });
    if (fm.verified !== undefined) {
      const entries = Array.isArray(fm.verified) ? fm.verified : [fm.verified];
      if (entries.some((entry) => !isRecord(entry) || typeof entry.by !== "string" || !entry.by || !validInstant(entry.at))) issues.push({ path: concept.path, severity: "warning", code: "INVALID_VERIFIED_METADATA", message: "verified entries should contain by actors and ISO 8601 datetimes" });
    }
    if (fm.status !== undefined && !["draft", "stable", "deprecated"].includes(String(fm.status))) issues.push({ path: concept.path, severity: "warning", code: "INVALID_STATUS", message: "status should be draft, stable, or deprecated" });
    if (fm.stale_after !== undefined && !validInstant(fm.stale_after)) issues.push({ path: concept.path, severity: "warning", code: "INVALID_STALE_AFTER", message: "stale_after should be an ISO 8601 datetime with a UTC offset" });
    if (fm.sources !== undefined && (!Array.isArray(fm.sources) || fm.sources.some((source) => !isRecord(source) || typeof source.resource !== "string" || !source.resource))) issues.push({ path: concept.path, severity: "warning", code: "INVALID_SOURCES", message: "sources should be a list whose entries include resource" });
    for (const match of concept.body.matchAll(MARKDOWN_LINK)) {
      const [, linkText, linkUrl] = match;
      const target = resolveLink(concept.path, linkUrl!);
      if (target && !pathsSet.has(target)) issues.push({ path: concept.path, severity: "warning", code: "UNRESOLVED_LINK", message: `Link '${linkText}' targets ${target}, which is not present in this bundle` });
    }
  }
  return { ok: !issues.some((issue) => issue.severity === "error"), formatVersion: "0.2", documentCount: normalizedDocs.length, conceptCount: parsed.length, relationshipCount: parsed.reduce((n, concept) => n + [...concept.body.matchAll(MARKDOWN_LINK)].filter((match) => resolveLink(concept.path, match[2]!)).length, 0), issues, documents: normalizedDocs, concepts: parsed };
}

function validInstant(value: unknown) {
  if (value instanceof Date) return !Number.isNaN(value.getTime());
  return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && !Number.isNaN(Date.parse(value));
}

function conceptMarkdown(frontmatter: Record<string, unknown>, body: string) {
  return `---\n${stringifyYaml(frontmatter).trimEnd()}\n---\n\n${body.trim()}\n`;
}

type AppKnowledgeRow = { id: string; name: string; repository_id: string; owner: string; repository_name: string; html_url: string | null; branch: string | null; scan_status: string | null; vulnerability_status: string | null; scanned_at: Date | null; knowledge_updated_at: Date; dependency_count: number; finding_count: number };

function buildSystemDocuments(apps: AppKnowledgeRow[], createdAt: Date): OkfDocument[] {
  const timestamp = createdAt.toISOString();
  const actor = "process:dependencyshield-okf-sync";
  const appDocs = apps.flatMap((application) => {
    const appId = application.id;
    const appPath = `applications/${appId}.md`;
    const repoPath = `repositories/${application.repository_id}.md`;
    const source = application.html_url ? [{ id: "github-repository", resource: application.html_url, title: "Authorized GitHub repository" }] : [];
    const appFrontmatter: Record<string, unknown> = { type: "Application", title: application.name, description: "Application discovered from a user-authorized GitHub repository.", generated: { by: actor, at: application.knowledge_updated_at.toISOString() }, status: "stable", application_id: appId, repository_id: application.repository_id, sources: source };
    const appBody = `This application record is derived from the connected repository metadata.\n\n- Repository: [${application.owner}/${application.repository_name}](/${repoPath})\n- Branch: ${application.branch ?? "unknown"}\n- Latest scan status: ${application.scan_status ?? "unknown"}\n- Vulnerability lookup status: ${application.vulnerability_status ?? "unknown"}\n- Packages in latest completed SBOM: ${application.dependency_count}\n- Findings in latest scan: ${application.finding_count}\n- Last completed scan: ${application.scanned_at?.toISOString() ?? "unknown"}\n\nOrganizational owner, environment, criticality, internet exposure, data classification, SLA, and remediation policy are unknown until supplied in organizational context concepts.`;
    const repoFrontmatter: Record<string, unknown> = { type: "Repository", title: `${application.owner}/${application.repository_name}`, description: "Repository connected through GitHub App authorization.", ...(application.html_url ? { resource: application.html_url } : {}), generated: { by: actor, at: application.knowledge_updated_at.toISOString() }, status: "stable", repository_id: application.repository_id, application_id: appId, sources: source };
    const repoBody = `This repository is connected to DependencyShield for authorized scanning.\n\n- Application: [${application.name}](/${appPath})\n- Owner: ${application.owner}\n- Repository: ${application.repository_name}\n- Scan branch: ${application.branch ?? "unknown"}\n- GitHub URL: ${application.html_url ?? "unknown"}`;
    return [{ path: appPath, markdown: conceptMarkdown(appFrontmatter, appBody), sourceKind: "integration" as const }, { path: repoPath, markdown: conceptMarkdown(repoFrontmatter, repoBody), sourceKind: "integration" as const }];
  });
  const appLinks = apps.length ? apps.map((item) => `- [${item.name}](/applications/${item.id}.md)`).join("\n") : "- No applications are connected yet.";
  const context = conceptMarkdown({ type: "Organizational Context", title: "Organizational context: unknown values", description: "Values that must be supplied before DependencyShield can apply organizational risk context.", generated: { by: actor, at: timestamp }, status: "draft", tags: ["organizational-context", "unknown"] }, `No organization profile has been provided. DependencyShield does not infer organizational facts from repository names.\n\n## Unknown until supplied\n\n- Organization identity and membership\n- Application owners and teams\n- Deployment environments (including production or staging)\n- Business criticality and internet exposure\n- Data classification and service dependencies\n- Service-level agreements\n- Remediation policies\n\nThese values are unknown, not false. Add linked OKF concepts to provide reviewed organizational context.\n\n## Connected applications\n\n${appLinks}`);
  const docs: OkfDocument[] = [
    { path: "context/organizational-context.md", markdown: context, sourceKind: "integration" },
    ...appDocs,
  ];
  const entries = apps.map((application) => `- [${application.name}](/applications/${application.id}.md) - Application connected from ${application.owner}/${application.repository_name}.`).join("\n") || "- No applications are connected yet.";
  docs.push({ path: "index.md", markdown: `---\nokf_version: "0.2"\n---\n\n# DependencyShield knowledge bundle\n\n## Organizational context\n\n- [Organizational context](/context/organizational-context.md) - Known context and fields that remain unknown.\n\n## Application and repository concepts\n\n${entries}\n`, sourceKind: "integration" });
  docs.push({ path: "log.md", markdown: `# DependencyShield knowledge update log\n\n## ${timestamp.slice(0, 10)}\n* **Update**: Synchronized application and repository concepts from authorized workspace records.\n`, sourceKind: "integration" });
  return docs;
}

async function saveSnapshot(userId: string, inputDocs: OkfDocument[], actor: string) {
  const validation = validateOkfBundle(inputDocs);
  if (!validation.ok) throw Object.assign(new Error("OKF bundle contains conformance errors"), { issues: validation.issues });
  const documents = validation.documents;
  const hashInput = documents.slice().sort((a, b) => a.path.localeCompare(b.path)).map((doc) => `${doc.path}\0${doc.markdown}`).join("\0");
  const contentHash = createHash("sha256").update(hashInput).digest("hex");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const bundleResult = await client.query<{ id: string }>("INSERT INTO okf_bundles (user_id) VALUES ($1) ON CONFLICT (user_id) DO UPDATE SET updated_at = now() RETURNING id", [userId]);
    const bundleId = bundleResult.rows[0]!.id;
    const latest = await client.query<{ id: string; revision: number; content_hash: string }>("SELECT id, revision, content_hash FROM okf_bundle_revisions WHERE bundle_id = $1 ORDER BY revision DESC LIMIT 1", [bundleId]);
    if (latest.rows[0]?.content_hash === contentHash) { await client.query("COMMIT"); return { bundleId, revisionId: latest.rows[0].id, revision: latest.rows[0].revision, changed: false }; }
    const revision = (latest.rows[0]?.revision ?? 0) + 1;
    const revisionResult = await client.query<{ id: string }>("INSERT INTO okf_bundle_revisions (bundle_id, revision, content_hash, actor) VALUES ($1, $2, $3, $4) RETURNING id", [bundleId, revision, contentHash, actor]);
    const revisionId = revisionResult.rows[0]!.id;
    await client.query("UPDATE okf_bundles SET updated_at = now() WHERE id = $1", [bundleId]);
    const parsedByPath = new Map(validation.concepts.map((concept) => [concept.path, concept]));
    const conceptIds = new Map<string, string>();
    for (const document of documents) {
      const sourceKind = document.sourceKind ?? "user";
      await client.query("INSERT INTO okf_bundle_documents (bundle_id, revision_id, document_path, markdown, source_kind) VALUES ($1, $2, $3, $4, $5)", [bundleId, revisionId, document.path, document.markdown, sourceKind]);
      const concept = parsedByPath.get(document.path);
      if (!concept) continue;
      const fm = concept.frontmatter;
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO okf_concepts (bundle_id, revision_id, concept_path, concept_id, concept_type, title, description, frontmatter, body, markdown, source_kind)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
        [bundleId, revisionId, concept.path, concept.conceptId, fm.type, typeof fm.title === "string" ? fm.title : null, typeof fm.description === "string" ? fm.description : null, JSON.stringify(fm), concept.body, concept.markdown, sourceKind],
      );
      conceptIds.set(concept.path, inserted.rows[0]!.id);
    }
    for (const concept of validation.concepts) {
      const sourceId = conceptIds.get(concept.path)!;
      for (const match of concept.body.matchAll(MARKDOWN_LINK)) {
        const targetPath = resolveLink(concept.path, match[2]!);
        if (!targetPath) continue;
        await client.query(
          `INSERT INTO okf_relationships (bundle_id, revision_id, source_concept_id, target_concept_id, target_concept_path, link_text, link_url)
           VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
          [bundleId, revisionId, sourceId, conceptIds.get(targetPath) ?? null, targetPath, match[1]!, match[2]!],
        );
      }
    }
    await client.query("COMMIT");
    return { bundleId, revisionId, revision, changed: true };
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
}

async function currentSnapshot(userId: string) {
  const result = await pool.query<{ id: string; bundle_id: string; revision: number; content_hash: string; created_at: Date }>(
    `SELECT rev.id, rev.bundle_id, rev.revision, rev.content_hash, rev.created_at
     FROM okf_bundles b JOIN LATERAL (SELECT * FROM okf_bundle_revisions WHERE bundle_id = b.id ORDER BY revision DESC LIMIT 1) rev ON true
     WHERE b.user_id = $1`, [userId],
  );
  return result.rows[0] ?? null;
}

export async function syncOkfBundle(userId: string) {
  const apps = await pool.query<AppKnowledgeRow>(
    `SELECT a.id, a.name, a.repository_id, GREATEST(a.updated_at, r.updated_at, COALESCE(latest.completed_at, a.updated_at)) AS knowledge_updated_at, r.owner, r.name AS repository_name, r.html_url, r.scan_branch AS branch,
            latest.status AS scan_status, latest.vulnerability_status, latest.scanned_at,
            COALESCE(inv.dependency_count, 0)::int AS dependency_count, COALESCE(findings.finding_count, 0)::int AS finding_count
     FROM applications a JOIN repositories r ON r.id = a.repository_id
     LEFT JOIN LATERAL (SELECT s.status, s.vulnerability_status, s.completed_at, b.scanned_at FROM scans s LEFT JOIN sboms b ON b.scan_id = s.id WHERE s.repository_id = r.id ORDER BY s.created_at DESC LIMIT 1) latest ON true
     LEFT JOIN LATERAL (SELECT count(*) AS dependency_count FROM sbom_components c JOIN sboms b ON b.id = c.sbom_id JOIN scans s ON s.id = b.scan_id WHERE s.repository_id = r.id AND s.sbom_status = 'completed' AND c.package_id IS NOT NULL AND s.created_at = (SELECT max(s2.created_at) FROM scans s2 WHERE s2.repository_id = r.id AND s2.sbom_status = 'completed')) inv ON true
     LEFT JOIN LATERAL (SELECT count(*) AS finding_count FROM findings f JOIN scans s ON s.id = f.scan_id WHERE s.repository_id = r.id AND s.created_at = (SELECT max(s2.created_at) FROM scans s2 WHERE s2.repository_id = r.id AND s2.vulnerability_status IN ('completed','partial'))) findings ON true
     WHERE r.user_id = $1 ORDER BY a.name`, [userId],
  );
  const bundle = await pool.query<{ id: string; created_at: Date }>("INSERT INTO okf_bundles (user_id) VALUES ($1) ON CONFLICT (user_id) DO UPDATE SET updated_at = now() RETURNING id, created_at", [userId]);
  const generated = buildSystemDocuments(apps.rows, bundle.rows[0]!.created_at);
  const existingSnapshot = await currentSnapshot(userId);
  let documents = generated;
  if (existingSnapshot) {
    const existing = await pool.query<{ document_path: string; markdown: string; source_kind: "integration" | "user" }>("SELECT document_path, markdown, source_kind FROM okf_bundle_documents WHERE revision_id = $1", [existingSnapshot.id]);
    const userDocs = existing.rows.filter((doc) => doc.source_kind === "user");
    documents = [...generated, ...userDocs.filter((doc) => !generated.some((item) => item.path === doc.document_path)).map((doc) => ({ path: doc.document_path, markdown: doc.markdown, sourceKind: "user" as const }))];
  }
  return saveSnapshot(userId, documents, "process:dependencyshield-okf-sync");
}

export async function getOkfBundle(userId: string) {
  const saved = await syncOkfBundle(userId);
  const result = await pool.query(
    `SELECT b.id, b.name, b.format_version, rev.revision, rev.content_hash, rev.actor, rev.created_at,
            count(DISTINCT c.id)::int AS concept_count, count(DISTINCT rel.id)::int AS relationship_count
     FROM okf_bundles b JOIN okf_bundle_revisions rev ON rev.id = $2
     LEFT JOIN okf_concepts c ON c.revision_id = rev.id LEFT JOIN okf_relationships rel ON rel.revision_id = rev.id
     WHERE b.id = $1 GROUP BY b.id, rev.id`, [saved.bundleId, saved.revisionId],
  );
  return result.rows[0] ?? null;
}

function conceptSignals(frontmatter: Record<string, unknown>, now = new Date()) {
  const verified = frontmatter.verified === undefined ? [] : Array.isArray(frontmatter.verified) ? frontmatter.verified : [frontmatter.verified];
  const trust = verified.some((entry) => isRecord(entry) && typeof entry.by === "string" && entry.by.startsWith("human:")) ? "human-reviewed" : verified.length ? "machine-confirmed" : "unverified";
  const staleAfter = validInstant(frontmatter.stale_after) ? new Date(frontmatter.stale_after as string | Date).toISOString() : null;
  return { trust, stale: staleAfter !== null && now >= new Date(staleAfter), staleAfter, status: typeof frontmatter.status === "string" ? frontmatter.status : "stable" };
}

export async function listOkfConcepts(userId: string, filters: { query?: string; type?: string; tag?: string }) {
  const snapshot = await syncOkfBundle(userId);
  const result = await pool.query<{ id: string; concept_id: string; concept_path: string; concept_type: string; title: string | null; description: string | null; frontmatter: Record<string, unknown>; body: string; markdown: string; source_kind: string; created_at: Date }>(
    `SELECT c.id, c.concept_id, c.concept_path, c.concept_type, c.title, c.description, c.frontmatter, c.body, c.markdown, c.source_kind, c.created_at,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('path', r.target_concept_path, 'text', r.link_text, 'url', r.link_url, 'resolved', r.target_concept_id IS NOT NULL)) FROM okf_relationships r WHERE r.source_concept_id = c.id), '[]'::jsonb) AS outgoing,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('path', src.concept_path, 'title', src.title, 'text', r.link_text)) FROM okf_relationships r JOIN okf_concepts src ON src.id = r.source_concept_id WHERE r.target_concept_id = c.id), '[]'::jsonb) AS incoming
     FROM okf_concepts c WHERE c.revision_id = $1 AND ($2::text IS NULL OR c.concept_type ILIKE '%' || $2 || '%')
       AND ($3::text IS NULL OR (jsonb_typeof(c.frontmatter->'tags') = 'array' AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(c.frontmatter->'tags') t WHERE t = $3)))
       AND ($4::text IS NULL OR concat_ws(' ', c.concept_id, c.title, c.description, c.body) ILIKE '%' || $4 || '%')
     ORDER BY c.concept_type, COALESCE(c.title, c.concept_id)`, [snapshot.revisionId, filters.type ?? null, filters.tag ?? null, filters.query ?? null],
  );
  return result.rows.map((row) => ({ ...row, ...conceptSignals(row.frontmatter) }));
}

export async function getOkfConcept(userId: string, conceptUuid: string) {
  const snapshot = await syncOkfBundle(userId);
  const result = await pool.query(
    `SELECT c.id, c.concept_id, c.concept_path, c.concept_type, c.title, c.description, c.frontmatter, c.body, c.markdown, c.source_kind, c.created_at,
            COALESCE(jsonb_agg(DISTINCT jsonb_build_object('path', out.target_concept_path, 'text', out.link_text, 'url', out.link_url, 'resolved', out.target_concept_id IS NOT NULL)) FILTER (WHERE out.id IS NOT NULL), '[]'::jsonb) AS outgoing,
            COALESCE(jsonb_agg(DISTINCT jsonb_build_object('path', inc.concept_path, 'title', inc.title, 'text', inc_rel.link_text)) FILTER (WHERE inc_rel.id IS NOT NULL), '[]'::jsonb) AS incoming
     FROM okf_concepts c LEFT JOIN okf_relationships out ON out.source_concept_id = c.id LEFT JOIN okf_relationships inc_rel ON inc_rel.target_concept_id = c.id LEFT JOIN okf_concepts inc ON inc.id = inc_rel.source_concept_id
     WHERE c.revision_id = $1 AND c.id = $2 GROUP BY c.id`, [snapshot.revisionId, conceptUuid],
  );
  const row = result.rows[0] as (Record<string, unknown> & { frontmatter: Record<string, unknown> }) | undefined;
  return row ? { ...row, ...conceptSignals(row.frontmatter) } : null;
}

export async function saveUserOkfConcept(userId: string, path: string, markdown: string) {
  const normalized = normalizeDocumentPath(path);
  if (["index.md", "log.md"].includes(normalized) || normalized.endsWith("/index.md") || normalized.endsWith("/log.md")) throw new Error("index.md and log.md are reserved bundle documents");
  if (normalized.startsWith("applications/") || normalized.startsWith("repositories/")) throw new Error("Application and repository concepts are synchronized from authorized integration data; add a linked context concept instead");
  if (normalized === "context/organizational-context.md") throw new Error("The workspace context inventory is integration-managed; add a separate linked context concept instead");
  const concept = parseOkfDocument(normalized, markdown)!;
  const snapshot = await syncOkfBundle(userId);
  const existing = await pool.query<{ document_path: string; markdown: string; source_kind: "integration" | "user" }>("SELECT document_path, markdown, source_kind FROM okf_bundle_documents WHERE revision_id = $1", [snapshot.revisionId]);
  const docs = existing.rows.filter((doc) => doc.document_path !== normalized).map((doc) => ({ path: doc.document_path, markdown: doc.markdown, sourceKind: doc.source_kind }));
  docs.push({ path: normalized, markdown: concept.markdown, sourceKind: "user" });
  const result = await saveSnapshot(userId, docs, `human:${userId}`);
  return { ...result, path: normalized, conceptId: concept.conceptId };
}

export async function validateAndSaveOkfBundle(userId: string, documents: OkfDocument[]) {
  const validation = validateOkfBundle(documents);
  if (!validation.ok) return { validation, saved: null };
  const saved = await saveSnapshot(userId, documents.map((doc) => ({ ...doc, sourceKind: "user" })), `human:${userId}`);
  return { validation: { ...validation, documents: undefined, concepts: undefined }, saved };
}

export async function getApplicationOkfContext(userId: string, applicationId: string) {
  const snapshot = await syncOkfBundle(userId);
  const owned = await pool.query("SELECT 1 FROM applications a JOIN repositories r ON r.id = a.repository_id WHERE a.id = $1 AND r.user_id = $2", [applicationId, userId]);
  if (!owned.rowCount) return null;
  const appPath = `applications/${applicationId}.md`;
  const result = await pool.query(
    `SELECT c.id, c.concept_id, c.concept_path, c.concept_type, c.title, c.description, c.frontmatter, c.body, c.source_kind
     FROM okf_concepts c
     WHERE c.revision_id = $1 AND (c.concept_path = $2 OR c.concept_path = 'context/organizational-context.md'
       OR EXISTS (SELECT 1 FROM okf_relationships rel WHERE rel.revision_id = $1 AND rel.source_concept_id = c.id AND rel.target_concept_path = $2))
     ORDER BY CASE WHEN c.concept_path = $2 THEN 0 WHEN c.concept_path = 'context/organizational-context.md' THEN 1 ELSE 2 END, c.concept_path`, [snapshot.revisionId, appPath],
  );
  return result.rows.map((row) => ({ ...row, ...conceptSignals(row.frontmatter as Record<string, unknown>) }));
}

export async function getApplicationRiskContext(userId: string, applicationId: string) {
  const concepts = await getApplicationOkfContext(userId, applicationId);
  if (!concepts) return null;
  const keys = ["environment", "criticality", "internet_exposed", "data_classification", "sla", "service_dependencies"] as const;
  const values: Record<(typeof keys)[number], unknown> = {
    environment: "unknown", criticality: "unknown", internet_exposed: "unknown",
    data_classification: "unknown", sla: "unknown", service_dependencies: "unknown",
  };
  const sources: Record<string, string[]> = {};
  const conflicts: string[] = [];
  const invalidConcepts: string[] = [];
  for (const key of keys) {
    const candidates: Array<{ value: unknown; path: string }> = [];
    for (const concept of concepts) {
      const item = concept as { concept_path: string; frontmatter: Record<string, unknown>; source_kind: string };
      if (item.source_kind !== "user") continue;
      const context = item.frontmatter.risk_context;
      if (context === undefined) continue;
      if (!isRecord(context)) { invalidConcepts.push(item.concept_path); continue; }
      const value = context[key];
      if (value === undefined || value === null || value === "" || value === "unknown") continue;
      const valid = key === "internet_exposed" ? typeof value === "boolean"
        : key === "service_dependencies" ? Array.isArray(value) && value.every((entry) => typeof entry === "string")
        : typeof value === "string" && value.trim().length > 0;
      if (!valid) { invalidConcepts.push(item.concept_path); continue; }
      candidates.push({ value, path: item.concept_path });
    }
    if (candidates.length) {
      const distinct = new Map(candidates.map((candidate) => [JSON.stringify(candidate.value), candidate.value]));
      sources[key] = [...new Set(candidates.map((candidate) => candidate.path))];
      if (distinct.size > 1) { values[key] = "conflicting"; conflicts.push(key); }
      else values[key] = [...distinct.values()][0];
    }
  }
  return { values, sources, conflicts, invalidConcepts: [...new Set(invalidConcepts)] };
}

export async function listOkfRevisions(userId: string, bundleId: string) {
  await syncOkfBundle(userId);
  const result = await pool.query(
    `SELECT rev.revision, rev.content_hash, rev.actor, rev.created_at,
            count(DISTINCT doc.id)::int AS document_count, count(DISTINCT c.id)::int AS concept_count,
            count(DISTINCT rel.id)::int AS relationship_count
     FROM okf_bundles b JOIN okf_bundle_revisions rev ON rev.bundle_id = b.id
     LEFT JOIN okf_bundle_documents doc ON doc.revision_id = rev.id
     LEFT JOIN okf_concepts c ON c.revision_id = rev.id
     LEFT JOIN okf_relationships rel ON rel.revision_id = rev.id
     WHERE b.user_id = $1 AND b.id = $2
     GROUP BY rev.id ORDER BY rev.revision DESC`, [userId, bundleId],
  );
  return result.rows;
}

export async function exportOkfBundle(userId: string, requestedRevision?: number) {
  const snapshot = await syncOkfBundle(userId);
  let revisionId = snapshot.revisionId;
  let revision = snapshot.revision;
  if (requestedRevision !== undefined && requestedRevision !== revision) {
    const previous = await pool.query<{ id: string }>("SELECT id FROM okf_bundle_revisions WHERE bundle_id = $1 AND revision = $2", [snapshot.bundleId, requestedRevision]);
    if (!previous.rowCount) return null;
    revisionId = previous.rows[0]!.id;
    revision = requestedRevision;
  }
  const result = await pool.query("SELECT document_path, markdown FROM okf_bundle_documents WHERE revision_id = $1 ORDER BY document_path", [revisionId]);
  return { revision, formatVersion: "0.2", documents: result.rows as Array<{ document_path: string; markdown: string }> };
}
