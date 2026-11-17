"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { CiChecks } from "../components/ci-checks";

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
type User = { id: string; githubLogin: string; name: string | null; avatarUrl: string | null };
type Repo = { id: string; owner: string; name: string; branch: string; private: boolean; archived: boolean; monitoring_enabled: boolean; dependency_count: number; finding_count: number; latest_scan_id: string | null; latest_scan_status: string | null; sbom_status: string | null; vulnerability_status: string | null; url: string };
type AvailableRepo = { id: number; installationId: number; fullName: string; owner: string; name: string; defaultBranch: string | null; private: boolean; archived: boolean; htmlUrl: string };
type Finding = { id: string; repository: string; package: string; version: string | null; vulnerability_id: string; payload: { summary?: string; severity?: Array<{ score?: string }> }; local_range_status?: string; local_range_source?: string | null; local_range_evidence?: Record<string, unknown>; source_records?: Array<{ source: string; external_id: string }>; reachability_status: string | null; reachability_evidence: Array<{ file: string; line: number; snippet: string }> | null; code_analysis_status: string | null };
type Remediation = { id: string; finding_id: string; action_type: "issue" | "draft_pr"; status: string; github_number: number | null; github_url: string | null; branch_name: string | null; target_version: string | null; error_message: string | null };
type Alert = { id: string; finding_id: string; category: string; read_at: string | null; created_at: string; vulnerability_id: string; summary: string | null; package_name: string; package_version: string | null; owner: string; repository_name: string; trigger_source: string };
type Application = { id: string; name: string; repository_id: string; owner: string; repository_name: string; scan_id: string | null; branch: string | null; dependency_graph_status: string | null; dependency_count: number; finding_count: number; vulnerability_status: string | null };

async function getData<T>(path: string): Promise<T> {
  const response = await fetch(`${api}${path}`, { credentials: "include", cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(body?.error?.message ?? "Request failed");
  return body.data as T;
}

async function postData<T>(path: string, value: unknown): Promise<T> {
  const response = await fetch(`${api}${path}`, { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify(value) });
  const body = await response.json();
  if (!response.ok) throw new Error(body?.error?.message ?? "Request failed");
  return body.data as T;
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [available, setAvailable] = useState<AvailableRepo[]>([]);
  const [branchLists, setBranchLists] = useState<Record<number, string[]>>({});
  const [selectedBranches, setSelectedBranches] = useState<Record<number, string>>({});
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const session = await getData<User>("/api/auth/session");
    setUser(session);
    const [repositoryRows, availableRows, findingRows, applicationRows, remediationRows, alertRows] = await Promise.all([
      getData<Repo[]>("/api/repositories"), getData<AvailableRepo[]>("/api/github/repositories/available"), getData<Finding[]>("/api/findings"), getData<Application[]>("/api/applications"), getData<Remediation[]>("/api/remediations"), getData<Alert[]>("/api/alerts"),
    ]);
    setRepos(repositoryRows);
    setAvailable(availableRows);
    setFindings(findingRows);
    setApplications(applicationRows);
    setRemediations(remediationRows);
    setAlerts(alertRows);
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("github") === "connected") setMessage("GitHub App installation connected. Choose repositories below.");
    else if (params.get("github") === "install_failed") setMessage("GitHub App installation could not be verified. Confirm the app settings and try again.");
    else if (params.get("github") === "approval_pending") setMessage("Your organization must approve the GitHub App installation before repositories are available.");
    if (params.get("auth") === "failed") setMessage("GitHub sign-in failed. Please try again.");
    getData<User>("/api/auth/session").then((session) => {
      setUser(session);
      return Promise.all([getData<Repo[]>("/api/repositories"), getData<AvailableRepo[]>("/api/github/repositories/available"), getData<Finding[]>("/api/findings"), getData<Application[]>("/api/applications"), getData<Remediation[]>("/api/remediations"), getData<Alert[]>("/api/alerts")]);
    }).then(([repositoryRows, availableRows, findingRows, applicationRows, remediationRows, alertRows]) => {
      setRepos(repositoryRows); setAvailable(availableRows); setFindings(findingRows); setApplications(applicationRows);
      setRemediations(remediationRows);
      setAlerts(alertRows);
    }).catch((error: unknown) => {
      if (error instanceof Error && error.message !== "Sign in to continue") setMessage(error.message);
    }).finally(() => setLoading(false));
  }, []);

  const connectedNames = useMemo(() => new Set(repos.map((repo) => repo.url)), [repos]);
  const loadBranches = async (repo: AvailableRepo) => {
    setBusy(`branches:${repo.id}`); setMessage("");
    try {
      const rows = await getData<Array<{ name: string }>>(`/api/github/repositories/${repo.id}/branches?installationId=${repo.installationId}`);
      setBranchLists((current) => ({ ...current, [repo.id]: rows.map((row) => row.name) }));
      setSelectedBranches((current) => ({ ...current, [repo.id]: current[repo.id] ?? repo.defaultBranch ?? rows[0]?.name ?? "" }));
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not load branches"); }
    finally { setBusy(null); }
  };
  const connectRepository = async (repo: AvailableRepo) => {
    setBusy(`connect:${repo.id}`); setMessage("");
    try { await postData("/api/repositories/connect", { installationId: repo.installationId, githubRepoId: repo.id, branch: selectedBranches[repo.id] ?? repo.defaultBranch }); await refresh(); setMessage(`${repo.fullName} connected.`); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Could not connect repository"); }
    finally { setBusy(null); }
  };
  const scanRepository = async (repo: Repo) => {
    setBusy(`scan:${repo.id}`); setMessage("");
    try {
      const scan = await postData<{ scanId: string }>("/api/scans", { repositoryId: repo.id });
      setMessage(`Scan queued for ${repo.owner}/${repo.name}.`);
      for (let i = 0; i < 90; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        const state = await getData<{ status: string; vulnerability_error?: string | null }>(`/api/scans/${scan.scanId}`);
        if (["completed", "completed_with_warnings", "failed"].includes(state.status)) {
          setMessage(state.status === "failed" ? "Scan failed. Check the scanner service and repository access." : state.vulnerability_error ? `Scan finished with a coverage warning: ${state.vulnerability_error}` : `Scan complete for ${repo.owner}/${repo.name}.`);
          await refresh(); break;
        }
      }
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not start scan"); }
    finally { setBusy(null); }
  };
  const toggleMonitoring = async (repo: Repo) => {
    setBusy(`monitor:${repo.id}`); setMessage("");
    try {
      const response = await fetch(`${api}/api/repositories/${repo.id}/monitoring`, { method: "PATCH", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: !repo.monitoring_enabled }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message ?? "Could not update monitoring");
      setRepos((current) => current.map((item) => item.id === repo.id ? { ...item, monitoring_enabled: body.data.monitoring_enabled } : item));
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not update monitoring"); }
    finally { setBusy(null); }
  };
  const markAlertRead = async (alert: Alert) => {
    try {
      await postData(`/api/alerts/${alert.id}/read`, {});
      setAlerts((current) => current.map((item) => item.id === alert.id ? { ...item, read_at: new Date().toISOString() } : item));
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not mark alert read"); }
  };
  const createRemediation = async (finding: Finding, kind: "issue" | "draft_pr") => {
    if (kind === "draft_pr" && !window.confirm(`Create a draft pull request to update ${finding.package}? DependencyShield will not merge it. Review the diff, run the repository tests, and obtain maintainer approval.`)) return;
    setBusy(`remediation:${finding.id}`); setMessage("");
    try {
      const action = await postData<Remediation>(`/api/findings/${finding.id}/remediation/${kind === "issue" ? "issue" : "draft-pr"}`, kind === "draft_pr" ? { humanApproval: true } : {});
      setRemediations((current) => [action, ...current.filter((item) => !(item.finding_id === finding.id && item.action_type === kind))]);
      setMessage(action.github_url ? `Created ${kind === "issue" ? "GitHub issue" : "draft pull request"}. Review and test it before merging.` : "Remediation action submitted.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Remediation request failed"); }
    finally { setBusy(null); }
  };

  return <main className="layout">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">◈</span> DependencyShield</div>
      <div className="nav-label">Workspace</div>
      <a className="nav-item active" href="#overview">Overview</a>
      <a className="nav-item" href="#repositories">Repositories</a>
      <a className="nav-item" href="#findings">Vulnerability explorer</a>
      <div className="nav-label">Intelligence</div>
      <a className="nav-item" href="#applications">Applications</a>
      <a className="nav-item" href="#alerts">Alerts{alerts.some((alert) => !alert.read_at) ? ` · ${alerts.filter((alert) => !alert.read_at).length}` : ""}</a>
      <a className="nav-item" href="/knowledge">Knowledge</a>
      <a className="nav-item" href="/decisions">Decision audit</a>
      <a className="nav-item" href="#remediation">Remediation</a>
    </aside>
    <section className="main" id="overview">
      <div className="topline"><div><div className="eyebrow">Supply chain security</div><h1>Risk overview</h1></div>{user ? <div className="topline"><span className="metric-label">Signed in as {user.githubLogin}</span><a className="button" href={`${api}/api/github/app-install`}>Install GitHub App</a></div> : <a className="button" href={`${api}/api/auth/github`}>Sign in with GitHub</a>}</div>
      <p className="subtitle">Find affected dependencies across authorized repositories.</p>
      {message && <div className="notice">{message}</div>}
      <div className="grid">
        {[["Connected repositories", repos.length, "Authorized GitHub repositories"], ["Dependencies inventoried", repos.reduce((n, r) => n + r.dependency_count, 0), "Components in latest SBOMs"], ["Known vulnerable instances", findings.length, "Matched against OSV advisory data"], ["Scans", repos.filter((r) => r.latest_scan_id).length, "Repositories with a scan"]].map(([label, value, note]) => <article className="card" key={String(label)}><div className="metric-label">{label}</div><div className="metric-value">{loading ? "…" : value}</div><div className="metric-note">{note}</div></article>)}
      </div>
      {user && <article className="card section" id="repositories">
        <div className="section-title"><span>Repositories</span><span className="status">GitHub App access</span></div>
        {!repos.length && !available.length ? <div className="empty"><strong>Install the GitHub App to select repositories</strong><p>Access is limited to repositories selected for the app installation. Private repository source is fetched only by the scanner.</p><a className="button secondary" href={`${api}/api/github/app-install`}>Choose GitHub account</a></div> : <div className="repo-list">{repos.map((repo) => <div className="repo-row" key={repo.id}><div><a href={repo.url} target="_blank" rel="noreferrer"><strong>{repo.owner}/{repo.name}</strong></a><div className="metric-note">{repo.branch} · {repo.dependency_count} components · {repo.finding_count} findings · {repo.latest_scan_status ?? "not scanned"}{repo.vulnerability_status === "unavailable" ? " · OSV unavailable" : repo.vulnerability_status === "partial" ? " · partial OSV coverage" : ""}</div></div><div className="repo-actions"><button className="button secondary" disabled={busy !== null || repo.archived} onClick={() => scanRepository(repo)}>{busy === `scan:${repo.id}` ? "Scanning…" : "Scan now"}</button><button className="text-button" disabled={busy !== null || repo.archived} onClick={() => toggleMonitoring(repo)}>{repo.monitoring_enabled ? "Pause monitoring" : "Resume monitoring"}</button></div></div>)}</div>}
        {!!available.length && <><div className="subheading">Available in your GitHub App installation</div><div className="repo-list">{available.filter((repo) => !connectedNames.has(repo.htmlUrl)).map((repo) => <div className="repo-row" key={`${repo.installationId}:${repo.id}`}><div className="repo-info"><strong>{repo.fullName}</strong><div className="metric-note">Default: {repo.defaultBranch || "No default branch"} · {repo.private ? "Private" : "Public"}{repo.archived ? " · Archived" : ""}</div>{branchLists[repo.id] ? <select className="branch-select" aria-label={`Branch for ${repo.fullName}`} value={selectedBranches[repo.id] ?? repo.defaultBranch ?? ""} onChange={(event) => setSelectedBranches((current) => ({ ...current, [repo.id]: event.target.value }))}>{branchLists[repo.id]!.map((branch) => <option key={branch} value={branch}>{branch}</option>)}</select> : <button className="text-button" disabled={busy !== null} onClick={() => loadBranches(repo)}>{busy === `branches:${repo.id}` ? "Loading branches…" : "Choose a branch"}</button>}</div><button className="button secondary" disabled={busy !== null || repo.archived || (!repo.defaultBranch && !branchLists[repo.id]?.length)} onClick={() => connectRepository(repo)}>{busy === `connect:${repo.id}` ? "Connecting…" : "Connect"}</button></div>)}</div></>}
      </article>}
      {user && <article className="card section" id="applications"><div className="section-title"><span>Applications &amp; dependency impact</span><span className="status">{applications.length} connected</span></div>{!applications.length ? <div className="empty"><strong>Connect and scan a repository to build its dependency graph</strong><p>Each connected repository is currently represented as one application.</p></div> : <div className="repo-list">{applications.map((application) => <a className="repo-row" href={`/applications/${application.id}`} key={application.id}><div><strong>{application.name}</strong><div className="metric-note">{application.dependency_count} packages · {application.finding_count} findings · {application.branch ?? "Awaiting scan"}</div></div><span className="status">{application.dependency_graph_status ?? "no SBOM"}</span></a>)}</div>}</article>}
      <article className="card section" id="alerts"><div className="section-title"><span>Monitoring alerts</span><span className="status">{alerts.filter((alert) => !alert.read_at).length} unread</span></div>{!alerts.length ? <div className="empty"><strong>No new vulnerability alerts</strong><p>Monitoring alerts appear when a scan first detects a vulnerable package in a repository.</p></div> : <div className="repo-list">{alerts.map((alert) => <div className="repo-row" key={alert.id}><div><strong>{alert.vulnerability_id} · {alert.owner}/{alert.repository_name}</strong><div className="metric-note">{alert.package_name}@{alert.package_version ?? "unknown"} · {alert.summary ?? "New vulnerable dependency detected"} · {alert.trigger_source} scan</div></div><div className="repo-actions">{!alert.read_at && <button className="text-button" onClick={() => markAlertRead(alert)}>Mark read</button>}<a className="text-button" href="#findings">View finding</a></div></div>)}</div>}</article>      <article className="card section" id="findings"><div className="section-title"><span>Vulnerability findings</span><span className="status">OSV + GitHub + Semgrep</span></div>{!findings.length ? <div className="empty"><strong>{user ? "No matched advisory findings yet" : "Sign in to view your findings"}</strong><p>Findings appear after a repository scan completes. Unsupported source or range formats remain unknown, not unaffected.</p></div> : <div className="repo-list">{findings.map((finding) => { const issue = remediations.find((item) => item.finding_id === finding.id && item.action_type === "issue"); const draft = remediations.find((item) => item.finding_id === finding.id && item.action_type === "draft_pr"); return <div className="repo-row finding-row" key={finding.id}><div><strong>{finding.vulnerability_id}</strong><div className="metric-note">{finding.repository} · {finding.package}@{finding.version ?? "unknown"} · {finding.payload.summary ?? "No advisory summary supplied"}</div><div className="metric-note">Version range: {finding.local_range_status ?? "unknown"}{finding.local_range_source ? ` (${finding.local_range_source})` : ""} · Advisory sources: {finding.source_records?.map((item) => item.source).join(", ") || "OSV"}</div><div className="metric-note">Code usage: {finding.reachability_status ?? (finding.code_analysis_status === "unavailable" ? "unknown (Semgrep unavailable)" : "unknown (analysis pending)")}{finding.reachability_evidence?.slice(0, 2).map((item) => <div key={`${item.file}:${item.line}`}>{item.file}:{item.line} · <code>{item.snippet.trim()}</code></div>)}</div>{user && <div className="remediation-actions"><button className="button secondary" disabled={busy !== null || issue?.status === "created"} onClick={() => createRemediation(finding, "issue")}>{issue?.status === "created" ? "Issue created" : "Create GitHub issue"}</button><button className="button secondary" disabled={busy !== null || draft?.status === "created"} onClick={() => createRemediation(finding, "draft_pr")}>{draft?.status === "created" ? `Draft PR · ${draft.target_version ?? "created"}` : "Create draft PR"}</button>{issue?.github_url && <a href={issue.github_url} target="_blank" rel="noreferrer">Issue #{issue.github_number}</a>}{draft?.github_url && <a href={draft.github_url} target="_blank" rel="noreferrer">PR #{draft.github_number}</a>}{draft?.status === "created" && <CiChecks actionId={draft.id} />}{(issue?.error_message || draft?.error_message) && <div className="metric-note">{issue?.error_message ?? draft?.error_message}</div>}</div>}</div><span className="status">{finding.payload.severity?.[0]?.score ?? "Advisory"}</span></div>; })}</div>}</article>
      <p className="metric-note section">{loading ? "Loading workspace…" : user ? "Live repository and scan data. Vulnerability facts come from OSV responses." : "No synthetic findings are displayed."}</p>
    </section>
  </main>;
}
