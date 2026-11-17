import { importPKCS8, SignJWT } from "jose";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";
import { githubUserAccessToken } from "./github-oauth.js";

const apiBase = "https://api.github.com";
const apiVersion = "2026-03-10";

export type GitHubRepo = {
  id: number; name: string; full_name: string; owner: { login: string; type: string };
  default_branch: string | null; private: boolean; archived: boolean; html_url: string;
};

function requireAppConfig() {
  if (!env.GITHUB_APP_ID || !env.GITHUB_APP_PRIVATE_KEY_B64) throw new Error("GitHub App is not configured");
}

async function appJwt() {
  requireAppConfig();
  const pem = Buffer.from(env.GITHUB_APP_PRIVATE_KEY_B64, "base64").toString("utf8").replace(/\\n/g, "\n");
  const key = await importPKCS8(pem, "RS256");
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({}).setProtectedHeader({ alg: "RS256" }).setIssuedAt(now - 30).setIssuer(env.GITHUB_APP_ID).setExpirationTime(now + 8 * 60).sign(key);
}

async function githubFetch<T>(url: string, token: string, method = "GET", body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${token}`, "x-github-api-version": apiVersion, ...(body ? { "content-type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    const message = response.status === 404 ? "GitHub resource was not found or is not available to this installation" : `GitHub API returned ${response.status}`;
    throw Object.assign(new Error(message), { status: response.status });
  }
  const responseBody = await response.text();
  return responseBody ? JSON.parse(responseBody) as T : undefined as T;
}

export async function installationAccessToken(installationId: number, repositoryId?: number) {
  const jwt = await appJwt();
  const body = repositoryId ? { repository_ids: [repositoryId] } : undefined;
  const result = await githubFetch<{ token: string; expires_at: string }>(`${apiBase}/app/installations/${installationId}/access_tokens`, jwt, "POST", body);
  return result.token;
}

export async function listInstallationRepositories(installationId: number, token?: string): Promise<GitHubRepo[]> {
  const accessToken = token ?? await installationAccessToken(installationId);
  const repos: GitHubRepo[] = [];
  for (let page = 1; page <= 100; page += 1) {
    const result = await githubFetch<{ total_count: number; repositories: GitHubRepo[] }>(`${apiBase}/installation/repositories?per_page=100&page=${page}`, accessToken);
    repos.push(...result.repositories);
    if (repos.length >= result.total_count || result.repositories.length === 0) break;
  }
  return repos;
}

export async function listUserInstallations(userId: string) {
  const rows = await pool.query<{ id: string; account_login: string; account_type: string }>(
    "SELECT id, account_login, account_type FROM github_installations WHERE user_id = $1 ORDER BY account_login", [userId],
  );
  const results = [];
  for (const installation of rows.rows) {
    const repositories = await listInstallationRepositories(Number(installation.id));
    results.push({ id: Number(installation.id), accountLogin: installation.account_login, accountType: installation.account_type, repositories });
  }
  return results;
}

export async function verifyInstallationForUser(userId: string, installationId: number) {
  const token = await githubUserAccessToken(userId);
  const result = await githubFetch<{ total_count: number; repositories: GitHubRepo[] }>(`${apiBase}/user/installations/${installationId}/repositories?per_page=1`, token);
  return result;
}

export async function getInstallationAccount(installationId: number) {
  const jwt = await appJwt();
  return githubFetch<{ id: number; account: { login: string; type: string } }>(`${apiBase}/app/installations/${installationId}`, jwt);
}

export async function redeliverFailedAppWebhookGuids(guids: string[]) {
  const requested = new Set(guids);
  const jwt = await appJwt();
  const matched = new Set<string>();
  let redelivered = 0;
  for (let page = 1; page <= 5 && requested.size > matched.size; page += 1) {
    const deliveries = await githubFetch<Array<{ id: number; guid: string; status: string }>>(`${apiBase}/app/hook/deliveries?status=failure&per_page=100&page=${page}`, jwt);
    for (const delivery of deliveries) {
      if (!requested.has(delivery.guid) || matched.has(delivery.guid)) continue;
      matched.add(delivery.guid);
      await githubFetch<unknown>(`${apiBase}/app/hook/deliveries/${delivery.id}/attempts`, jwt, "POST");
      redelivered += 1;
    }
    if (deliveries.length < 100) break;
  }
  return { redelivered, unmatched: guids.filter((guid) => !matched.has(guid)) };
}

export async function listRepositoryBranches(installationId: number, repo: GitHubRepo) {
  const token = await installationAccessToken(installationId, repo.id);
  const branches: Array<{ name: string; protected: boolean }> = [];
  for (let page = 1; page <= 10; page += 1) {
    const batch = await githubFetch<Array<{ name: string; protected: boolean }>>(
      `${apiBase}/repos/${encodeURIComponent(repo.owner.login)}/${encodeURIComponent(repo.name)}/branches?per_page=100&page=${page}`, token,
    );
    branches.push(...batch);
    if (batch.length < 100) break;
  }
  return branches;
}

export async function verifyRepositoryBranch(installationId: number, repo: GitHubRepo, branch: string) {
  const token = await installationAccessToken(installationId, repo.id);
  return githubFetch<{ name: string }>(
    `${apiBase}/repos/${encodeURIComponent(repo.owner.login)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(branch)}`, token,
  );
}

export async function getRepositoryArchive(owner: string, repo: string, ref: string, token: string, destination: string, maxBytes: number) {
  const archiveUrl = `${apiBase}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tarball/${encodeURIComponent(ref)}`;
  const first = await fetch(archiveUrl, { redirect: "manual", headers: { accept: "application/vnd.github+json", authorization: `Bearer ${token}`, "x-github-api-version": apiVersion }, signal: AbortSignal.timeout(30_000) });
  if (first.status !== 302 && first.status !== 301) throw new Error(`GitHub archive request returned ${first.status}`);
  const location = first.headers.get("location");
  if (!location) throw new Error("GitHub archive response did not include a download location");
  const downloadUrl = new URL(location);
  if (downloadUrl.protocol !== "https:" || downloadUrl.hostname !== "codeload.github.com") throw new Error("GitHub returned an untrusted archive host");
  const response = await fetch(downloadUrl, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok || !response.body) throw new Error(`Repository archive download returned ${response.status}`);
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (contentLength > maxBytes) throw new Error("Repository archive exceeds configured size limit");
  const { createWriteStream } = await import("node:fs");
  const { pipeline } = await import("node:stream/promises");
  let written = 0;
  const limiter = new TransformStream({ transform(chunk, controller) { written += chunk.byteLength; if (written > maxBytes) throw new Error("Repository archive exceeds configured size limit"); controller.enqueue(chunk); } });
  await pipeline(response.body.pipeThrough(limiter), createWriteStream(destination));
}

export { githubFetch };
