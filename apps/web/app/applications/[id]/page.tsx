"use client";

import { use, useEffect, useState } from "react";
import { DependencyGraph } from "../../../components/dependency-graph";

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
type Impact = {
  application: { application_name: string; owner: string; repository_name: string; html_url: string | null; branch: string | null; commit_sha: string | null; scanned_at: string | null; dependency_graph_status: "complete" | "incomplete" | "unknown" | null; vulnerability_status: string | null; vulnerability_error: string | null };
  impact: null | {
    graphStatus: "complete" | "incomplete" | "unknown";
    counts: { packages: number; direct: number; transitive: number; notInGraph: number; unknownPath: number; findings: number };
    nodes: Array<{ id: string; label: string; componentType: string; packageId: string | null; purl: string | null; relationship: string; depth: number; hasFinding: boolean }>;
    edges: Array<{ id: string; source: string; target: string }>;
    dependencies: Array<{ bomRef: string; name: string | null; version: string | null; relationship: string; path: string[] | null }>;
    findings: Array<{ id: string; vulnerabilityId: string; summary: string | null; severity: string | null; package: string; version: string | null; relationship: string; dependencyPath: string[] | null }>;
  };
};
type ContextConcept = { concept_id: string; concept_path: string; concept_type: string; title: string | null; body: string; trust: string; stale: boolean; status: string; source_kind: string };
type DecisionSummary = { id: string; finding_id: string; application_id: string; source: "jev" | "deterministic_fallback"; requested_model: string; resolved_model: string | null; suggested_priority: string | null; final_priority: string; risk_score: number | null; immediate_escalation: boolean; human_review_required: boolean; remediation_category: string; operational_response: string; policy_action: string; decision_reason: string; fallback_reason: string | null; created_at: string; vulnerability_id: string; package_name: string; package_version: string | null };

export default function ApplicationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [result, setResult] = useState<Impact | null>(null);
  const [context, setContext] = useState<ContextConcept[]>([]);
  const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
  const [evaluating, setEvaluating] = useState<string | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([
      fetch(`${api}/api/applications/${id}/impact`, { credentials: "include", cache: "no-store" }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(body?.error?.message ?? "Could not load application impact"); return body.data as Impact; }),
      fetch(`${api}/api/applications/${id}/context`, { credentials: "include", cache: "no-store" }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(body?.error?.message ?? "Could not load application context"); return body.data as ContextConcept[]; }),
      fetch(`${api}/api/decisions?applicationId=${id}`, { credentials: "include", cache: "no-store" }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(body?.error?.message ?? "Could not load decision history"); return body.data as DecisionSummary[]; }),
    ]).then(([impact, concepts, decisionRows]) => { setResult(impact); setContext(concepts); setDecisions(decisionRows); }).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load application details"));
  }, [id]);

  const evaluateFinding = async (findingId: string) => {
    setEvaluating(findingId); setError("");
    try {
      const response = await fetch(`${api}/api/findings/${findingId}/decisions`, { method: "POST", credentials: "include" });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message ?? "Risk decision failed");
      setDecisions((current) => [body.data as DecisionSummary, ...current]);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Risk decision failed"); }
    finally { setEvaluating(null); }
  };

  if (error) return <main className="application-page"><a href="/">← Overview</a><div className="notice">{error}</div></main>;
  if (!result) return <main className="application-page"><a href="/">← Overview</a><p className="subtitle">Loading application impact…</p></main>;
  const app = result.application;
  const impact = result.impact;
  return <main className="application-page">
    <a href="/">← Overview</a>
    <div className="topline application-heading"><div><div className="eyebrow">Dependency intelligence</div><h1>{app.application_name}</h1><p className="subtitle">{app.owner}/{app.repository_name} · {app.branch ?? "branch unknown"}{app.commit_sha ? ` · ${app.commit_sha.slice(0, 12)}` : ""}</p></div>{app.html_url && <a className="button" href={app.html_url} target="_blank" rel="noreferrer">Open GitHub</a>}</div>
    {!impact ? <article className="card empty"><strong>No completed SBOM is available yet</strong><p>Run a repository scan to inventory dependencies and resolve their graph paths.</p></article> : <>
      <div className="notice">Graph status: <strong>{impact.graphStatus}</strong>. Direct and transitive labels follow the root paths represented in the CycloneDX dependency graph. Missing or incomplete paths remain unknown.</div>
      <div className="grid application-metrics">{[["Packages", impact.counts.packages], ["Direct", impact.counts.direct], ["Transitive", impact.counts.transitive], ["Vulnerability findings", impact.counts.findings]].map(([label, value]) => <article className="card" key={String(label)}><div className="metric-label">{label}</div><div className="metric-value">{value}</div></article>)}</div>
      {app.vulnerability_error && <div className="notice">Advisory coverage: {app.vulnerability_error}</div>}
      <article className="card section"><div className="section-title"><span>Organizational context (OKF)</span><a className="text-button" href="/knowledge">Manage knowledge</a></div>{!context.length ? <div className="empty">No organizational context concepts are linked yet. Missing values remain unknown.</div> : <div className="okf-context-list">{context.map((concept) => <div className="okf-context" key={concept.concept_id}><div className="section-title"><div><strong>{concept.title ?? concept.concept_id}</strong><div className="metric-note">{concept.concept_type} · {concept.trust} · {concept.status}{concept.stale ? " · stale" : ""}</div></div></div><pre className="knowledge-code body-code">{concept.body}</pre></div>)}</div>}</article>
      <article className="card section"><div className="section-title"><span>Dependency graph</span><span className="status">{impact.edges.length} relationships</span></div>{impact.nodes.length ? <DependencyGraph graph={impact} /> : <div className="empty">No components were present in this SBOM.</div>}</article>
      <article className="card section"><div className="section-title"><span>Vulnerable dependencies</span><span className="status">{impact.findings.length} findings</span></div>{!impact.findings.length ? <div className="empty">No matched advisory findings in the latest scan.</div> : <div className="repo-list">{impact.findings.map((finding) => { const decision = decisions.find((item) => item.finding_id === finding.id); return <div className="repo-row finding-row" key={finding.id}><div><strong>{finding.vulnerabilityId}</strong><div className="metric-note">{finding.package}@{finding.version ?? "unknown"} · {finding.relationship}</div><div className="metric-note">Path: {finding.dependencyPath?.join(" → ") ?? "Path unknown"}</div>{finding.summary && <div className="metric-note">{finding.summary}</div>}{decision && <div className="finding-decision"><strong>{decision.final_priority} · {decision.source === "jev" ? `Jev ${decision.resolved_model ?? decision.requested_model}` : "Deterministic fallback"}</strong><div className="metric-note">{decision.decision_reason}</div>{decision.fallback_reason && <div className="metric-note">Fallback reason: {decision.fallback_reason}</div>}</div>}</div><div className="finding-controls"><span className="status">{finding.severity ?? "Advisory"}</span><button className="button secondary" disabled={evaluating !== null} onClick={() => evaluateFinding(finding.id)}>{evaluating === finding.id ? "Evaluating…" : decision ? "Re-evaluate" : "Get risk decision"}</button></div></div>; })}</div>}<a className="text-button" href="/decisions">Open decision audit →</a></article>
      <article className="card section"><div className="section-title"><span>Dependency inventory</span><span className="status">{impact.counts.notInGraph + impact.counts.unknownPath} unresolved paths</span></div><div className="repo-list">{impact.dependencies.map((dependency) => <div className="repo-row" key={dependency.bomRef}><div><strong>{dependency.name ?? "Unknown package"}@{dependency.version ?? "unknown"}</strong><div className="metric-note">{dependency.path?.join(" → ") ?? "No root path available"}</div></div><span className="status">{dependency.relationship}</span></div>)}</div></article>
    </>}
  </main>;
}
