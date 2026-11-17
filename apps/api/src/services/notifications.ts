import { env } from "../config/env.js";

export async function sendVulnerabilityAlert(input: { repository: string; packageName: string; version: string | null; vulnerabilityId: string; summary: string | null }) {
  if (!env.ALERT_WEBHOOK_URL) return false;
  const url = new URL(env.ALERT_WEBHOOK_URL);
  if (url.protocol !== "https:" || url.username || url.password || url.hostname === "localhost" || url.hostname.endsWith(".local")) {
    throw new Error("ALERT_WEBHOOK_URL must be a public HTTPS webhook URL");
  }
  const text = `DependencyShield detected ${input.vulnerabilityId} in ${input.repository}: ${input.packageName}@${input.version ?? "unknown"}. ${input.summary ?? "Review the finding in DependencyShield."}`;
  const response = await fetch(url, { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error(`Notification webhook returned ${response.status}`);
  return true;
}
