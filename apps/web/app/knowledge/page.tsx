"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
type Concept = { id: string; concept_id: string; concept_path: string; concept_type: string; title: string | null; description: string | null; frontmatter: Record<string, unknown>; body: string; markdown: string; source_kind: string; trust: string; stale: boolean; staleAfter: string | null; status: string; incoming: Array<{ path: string; title: string | null; text: string }>; outgoing: Array<{ path: string; text: string; url: string; resolved: boolean }> };
type Bundle = { id: string; name: string; format_version: string; revision: number; content_hash: string; actor: string; created_at: string; concept_count: number; relationship_count: number };
type Revision = { revision: number; content_hash: string; actor: string; created_at: string; document_count: number; concept_count: number; relationship_count: number };
type Validation = { ok: boolean; formatVersion: string; documentCount: number; conceptCount: number; relationshipCount: number; issues: Array<{ path: string; severity: string; code: string; message: string }> };

async function getData<T>(path: string): Promise<T> {
  const response = await fetch(`${api}${path}`, { credentials: "include", cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(body?.error?.message ?? "Request failed");
  return body.data as T;
}

export default function KnowledgePage() {
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [concepts, setConcepts] = useState<Concept[]>([]);
  const [selected, setSelected] = useState<Concept | null>(null);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("");
  const [path, setPath] = useState("context/application-context.md");
  const [markdown, setMarkdown] = useState(`---\ntype: Organizational Context\ntitle: Application context\ndescription: Reviewed organizational context for an application.\nstatus: draft\nrisk_context:\n  environment: unknown\n  criticality: unknown\n  internet_exposed: unknown\n  data_classification: unknown\n  sla: unknown\n  service_dependencies: unknown\n---\n\n# Context\n\n- Application owner or team: unknown\n- Remediation policy: unknown\n\nLink to an application using a bundle-relative Markdown link, for example [Application](/applications/<application-uuid>.md).`);
  const [showEditor, setShowEditor] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [validation, setValidation] = useState<Validation | null>(null);
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [showRevisions, setShowRevisions] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const [bundles, rows] = await Promise.all([getData<Bundle[]>("/api/okf/bundles"), getData<Concept[]>("/api/okf/concepts")]);
    setBundle(bundles[0] ?? null);
    setConcepts(rows);
    setSelected((current) => current ? rows.find((row) => row.id === current.id) ?? null : null);
  }, []);
  useEffect(() => { refresh().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load OKF knowledge")); }, [refresh]);

  const filtered = useMemo(() => concepts.filter((concept) => (!type || concept.concept_type === type) && (!query || `${concept.concept_id} ${concept.title ?? ""} ${concept.description ?? ""} ${concept.body}`.toLowerCase().includes(query.toLowerCase()))), [concepts, query, type]);
  const types = useMemo(() => [...new Set(concepts.map((concept) => concept.concept_type))].sort(), [concepts]);
  const edit = (concept: Concept) => { setPath(concept.concept_path); setMarkdown(concept.markdown); setShowEditor(true); setValidation(null); setMessage(""); };

  const validate = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(`${api}/api/okf/validate`, { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify({ documents: { [path]: markdown } }) });
      const body = await response.json();
      if (!response.ok && response.status !== 422) throw new Error(body?.error?.message ?? "Validation failed");
      setValidation(body.data as Validation);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Validation failed"); }
    finally { setBusy(false); }
  };
  const save = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await fetch(`${api}/api/okf/concepts`, { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify({ path, markdown }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message ?? "Could not save concept");
      setMessage(`Saved ${path} as a new bundle revision.`); setShowEditor(false); setValidation(null); await refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not save concept"); }
    finally { setBusy(false); }
  };

  return <main className="application-page knowledge-page">
    <a href="/">← Overview</a>
    <div className="topline application-heading"><div><div className="eyebrow">Open Knowledge Format v0.2</div><h1>Knowledge explorer</h1><p className="subtitle">Workspace facts remain as Markdown with YAML frontmatter. PostgreSQL provides revision history and lookup indexes.</p></div><button className="button" onClick={() => { setPath("context/application-context.md"); setShowEditor(true); setValidation(null); setMessage(""); }}>Add context</button></div>
    {error && <div className="notice error-notice">{error}</div>}{message && <div className="notice">{message}</div>}
    {bundle && <div className="card knowledge-bundle"><div><strong>{bundle.name}</strong><div className="metric-note">OKF {bundle.format_version} · revision {bundle.revision} · {bundle.concept_count} concepts · {bundle.relationship_count} links</div></div><div className="knowledge-actions"><button className="button secondary" onClick={async () => { try { setRevisions(await getData<Revision[]>(`/api/okf/bundles/${bundle.id}/revisions`)); setShowRevisions((value) => !value); } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load revision history"); } }}>Revision history</button><a className="button secondary" href={`${api}/api/okf/bundles/export`} target="_blank" rel="noreferrer">View bundle export</a></div></div>}
    {showRevisions && <article className="card section"><div className="section-title"><span>Immutable bundle revisions</span><button className="text-button" onClick={() => setShowRevisions(false)}>Close</button></div><div className="repo-list">{revisions.map((revision) => <div className="repo-row" key={revision.revision}><div><strong>Revision {revision.revision}</strong><div className="metric-note">{revision.created_at} · {revision.actor} · {revision.concept_count} concepts · {revision.relationship_count} links</div><div className="metric-note">SHA-256 {revision.content_hash}</div></div><a className="button secondary" href={`${api}/api/okf/bundles/export?revision=${revision.revision}`} target="_blank" rel="noreferrer">View snapshot</a></div>)}</div></article>}
    {showEditor && <article className="card section"><div className="section-title"><span>Author a Markdown concept</span><button className="text-button" onClick={() => setShowEditor(false)}>Close</button></div><label className="knowledge-label">Bundle path<input className="knowledge-input" value={path} onChange={(event) => setPath(event.target.value)} placeholder="organizations/teams/platform.md" /></label><label className="knowledge-label">Markdown document<textarea className="knowledge-editor" spellCheck={false} value={markdown} onChange={(event) => setMarkdown(event.target.value)} /></label><div className="knowledge-actions"><button className="button secondary" disabled={busy} onClick={validate}>{busy ? "Validating…" : "Validate concept"}</button><button className="button" disabled={busy || (validation !== null && !validation.ok)} onClick={save}>{busy ? "Saving…" : "Save new revision"}</button></div>{validation && <div className={validation.ok ? "notice" : "notice error-notice"}>{validation.ok ? "Conformant OKF v0.2 concept" : "Conformance errors"} · {validation.conceptCount} concept · {validation.relationshipCount} relationship{validation.issues.map((issue, index) => <div className="validation-issue" key={`${issue.path}:${index}`}><strong>{issue.severity}: {issue.code}</strong> — {issue.path} · {issue.message}</div>)}</div>}<p className="metric-note">Broken links are retained as unresolved relationships. Missing organizational values should be written as unknown, not assumed false.</p></article>}
    <div className="knowledge-grid section">
      <section className="card"><div className="section-title"><span>Concepts</span><span className="status">{filtered.length}</span></div><input className="knowledge-input" aria-label="Search knowledge concepts" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search concepts, tags, or text" /><select className="knowledge-input knowledge-type" value={type} onChange={(event) => setType(event.target.value)}><option value="">All types</option>{types.map((item) => <option key={item} value={item}>{item}</option>)}</select><div className="concept-list">{filtered.map((concept) => <button className={`concept-item ${selected?.id === concept.id ? "selected" : ""}`} key={concept.id} onClick={() => setSelected(concept)}><strong>{concept.title ?? concept.concept_id}</strong><span>{concept.concept_type} · {concept.concept_id}</span><small>{concept.trust} · {concept.status}{concept.stale ? " · stale" : ""}</small></button>)}</div></section>
      <section className="card concept-detail">{selected ? <><div className="section-title"><span>{selected.title ?? selected.concept_id}</span>{selected.source_kind === "user" && <button className="text-button" onClick={() => edit(selected)}>Edit</button>}</div><p className="metric-note">{selected.concept_type} · {selected.concept_path}</p><div className="concept-signals"><span className="status">{selected.trust}</span><span className="status">{selected.status}</span>{selected.stale && <span className="status stale-status">Stale after {selected.staleAfter}</span>}</div>{selected.description && <p>{selected.description}</p>}<h3>Relationships</h3><div className="knowledge-relationships">{selected.outgoing.map((link, index) => <div key={`out:${link.path}:${index}`}>→ {link.text} <code>{link.path}</code> {link.resolved ? "· resolved" : "· unresolved"}</div>)}{selected.incoming.map((link, index) => <div key={`in:${link.path}:${index}`}>← {link.title ?? link.path} <code>{link.path}</code></div>)}{!selected.outgoing.length && !selected.incoming.length && <span className="metric-note">No concept links.</span>}</div><h3>Frontmatter</h3><pre className="knowledge-code">{JSON.stringify(selected.frontmatter, null, 2)}</pre><h3>Markdown body</h3><pre className="knowledge-code body-code">{selected.body}</pre>{Array.isArray(selected.frontmatter.sources) && <><h3>Provenance sources</h3><pre className="knowledge-code">{JSON.stringify(selected.frontmatter.sources, null, 2)}</pre></>}</> : <div className="empty"><strong>Select a concept</strong><p>Application records are synced from authorized GitHub repositories. Add reviewed concepts to describe the ownership and operating context that is not available from repository metadata.</p></div>}</section>
    </div>
  </main>;
}
