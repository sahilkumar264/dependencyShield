"use client";

import { useState } from "react";

const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
type Checks = { status: string; total: number; headSha: string; checks: Array<{ id: number; name: string; status: string; conclusion: string | null; url: string | null }> };

export function CiChecks({ actionId }: { actionId: string }) {
  const [checks, setChecks] = useState<Checks | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const load = async () => {
    setLoading(true); setError("");
    try {
      const response = await fetch(`${api}/api/remediations/${actionId}/checks`, { credentials: "include", cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message ?? "Could not load GitHub CI checks");
      setChecks(body.data as Checks);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load GitHub CI checks"); }
    finally { setLoading(false); }
  };
  return <div className="ci-checks"><button className="text-button" disabled={loading} onClick={load}>{loading ? "Loading CI…" : "Refresh CI checks"}</button>{error && <div className="metric-note">CI status unavailable: {error}</div>}{checks && <div className="metric-note">CI status: {checks.status} · {checks.total} checks · {checks.checks.map((check) => `${check.name}: ${check.conclusion ?? check.status}`).join("; ") || "No check runs reported"}</div>}</div>;
}
