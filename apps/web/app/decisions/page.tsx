"use client";

import { useCallback, useEffect, useState } from "react";

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
type Decision = { id: string; finding_id: string; application_id: string; scan_id: string; source: string; requested_model: string; resolved_model: string | null; policy_version: string; suggested_priority: string | null; final_priority: string; risk_score: number | null; immediate_escalation: boolean; human_review_required: boolean; remediation_category: string; operational_response: string; policy_action: string; decision_reason: string; fallback_reason: string | null; created_at: string; vulnerability_id: string; package_name: string; package_version: string | null; application_name: string; owner: string; repository_name: string };
type DecisionDetail = Decision & { input_state: unknown; questions: unknown; answers: Record<string, unknown>; usage: unknown; policy_evidence: unknown; provider_request_id: string | null };

async function getData<T>(path: string): Promise<T> {
  const response = await fetch(`${api}${path}`, { credentials: "include", cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(body?.error?.message ?? "Request failed");
  return body.data as T;
}

export default function DecisionsPage() {
  const [rows, setRows] = useState<Decision[]>([]);
  const [selected, setSelected] = useState<DecisionDetail | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(() => getData<Decision[]>("/api/decisions?limit=200").then(setRows).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load decision history")).finally(() => setLoading(false)), []);
  useEffect(() => { refresh(); }, [refresh]);
  const openDecision = async (id: string) => {
    setError("");
    try { setSelected(await getData<DecisionDetail>(`/api/decisions/${id}`)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load decision details"); }
  };
  const closeDetails = () => setSelected(null);

  return <main className="application-page decisions-page">
    <a href="/">← Overview</a>
    <div className="application-heading"><div className="eyebrow">Structured risk decisions</div><h1>Decision audit</h1><p className="subtitle">Jev supplies typed judgments; DependencyShield policy enforces evidence floors and review requirements. This page never treats Jev as a vulnerability fact source.</p></div>
    {error && <div className="notice error-notice">{error}</div>}
    {selected && <article className="card section"><div className="section-title"><span>Decision {selected.final_priority}</span><button className="text-button" onClick={closeDetails}>Close details</button></div><div className="metric-note">{selected.source === "jev" ? `Requested ${selected.requested_model}; resolved ${selected.resolved_model ?? "unknown"}` : `Deterministic fallback · ${selected.fallback_reason ?? "provider unavailable"}`} · policy {selected.policy_version} · {selected.created_at}</div><p>{selected.decision_reason}</p><div className="decision-flags"><span className={selected.immediate_escalation ? "status decision-alert" : "status"}>{selected.immediate_escalation ? "Escalate now" : "No immediate escalation"}</span><span className={selected.human_review_required ? "status decision-alert" : "status"}>{selected.human_review_required ? "Human review required" : "Normal policy workflow"}</span><span className="status">Action: {selected.policy_action}</span></div><div className="decision-columns"><div><h3>Exact input state</h3><pre className="knowledge-code">{JSON.stringify(selected.input_state, null, 2)}</pre><h3>Question definitions</h3><pre className="knowledge-code">{JSON.stringify(selected.questions, null, 2)}</pre></div><div><h3>Validated answers and probabilities</h3><pre className="knowledge-code">{JSON.stringify(selected.answers, null, 2)}</pre><h3>Deterministic policy evidence</h3><pre className="knowledge-code">{JSON.stringify(selected.policy_evidence, null, 2)}</pre>{selected.usage !== null && selected.usage !== undefined && <><h3>Provider usage</h3><pre className="knowledge-code">{JSON.stringify(selected.usage, null, 2)}</pre></>}</div></div></article>}
    <article className="card section"><div className="section-title"><span>Decision history</span><span className="status">{loading ? "Loading" : `${rows.length} records`}</span></div>{!loading && rows.length === 0 ? <div className="empty"><strong>No risk decisions yet</strong><p>Open an application impact page and select “Get risk decision” on a finding. If the API key is not configured, the system records an explicitly labelled deterministic fallback.</p><a className="button secondary" href="/">Return to overview</a></div> : <div className="repo-list">{rows.map((decision) => <button className="decision-row" key={decision.id} onClick={() => openDecision(decision.id)}><div><strong>{decision.final_priority} · {decision.vulnerability_id}</strong><div className="metric-note">{decision.application_name} · {decision.package_name}@{decision.package_version ?? "unknown"} · {decision.owner}/{decision.repository_name}</div><div className="metric-note">{decision.source === "jev" ? `Jev ${decision.resolved_model ?? decision.requested_model}` : `Fallback: ${decision.fallback_reason ?? "provider unavailable"}`} · {decision.created_at}</div></div><div className="decision-flags"><span className="status">{decision.policy_action}</span>{decision.human_review_required && <span className="status decision-alert">Review</span>}</div></button>)}</div>}</article>
  </main>;
}
