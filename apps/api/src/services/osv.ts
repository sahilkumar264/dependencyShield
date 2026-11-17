import { env } from "../config/env.js";

export type OsvVulnerability = { id: string; modified?: string; aliases?: string[]; affected?: Array<{ package?: { name?: string; ecosystem?: string }; versions?: string[]; ranges?: Array<{ type?: string; events?: Array<{ fixed?: string; introduced?: string; last_affected?: string; limit?: string }> }> }>; severity?: Array<{ type?: string; score?: string }>; summary?: string; details?: string };
export type OsvPackage = { name: string; version: string; ecosystem: string; purl: string };

const ecosystems: Record<string, string> = { npm: "npm", pypi: "PyPI", maven: "Maven", golang: "Go", cargo: "crates.io" };

export function parsePurl(purl: string, fallbackVersion?: string): OsvPackage | null {
  if (!purl.startsWith("pkg:")) return null;
  const clean = purl.slice(4).split(/[?#]/, 1)[0]!;
  const slash = clean.indexOf("/");
  if (slash < 1) return null;
  const type = clean.slice(0, slash).toLowerCase();
  const ecosystem = ecosystems[type];
  if (!ecosystem) return null;
  const path = clean.slice(slash + 1);
  const at = path.lastIndexOf("@");
  if (at < 1 && !fallbackVersion) return null;
  let rawName = at < 0 ? path : path.slice(0, at);
  const version = at < 0 ? fallbackVersion! : safeDecode(path.slice(at + 1));
  if (type === "maven") {
    const parts = rawName.split("/");
    if (parts.length < 2) return null;
    rawName = `${parts.slice(0, -1).join(".")}:${parts.at(-1)}`;
  } else rawName = safeDecode(rawName);
  if (!rawName || !version) return null;
  return { name: rawName, version, ecosystem, purl };
}

function safeDecode(value: string) {
  try { return decodeURIComponent(value); } catch { return value; }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000), headers: { "content-type": "application/json", ...init?.headers } });
      if (response.ok) return await response.json() as T;
      if (response.status !== 429 && response.status < 500) throw new Error(`OSV API returned ${response.status}`);
      lastError = new Error(`OSV API returned ${response.status}`);
    } catch (error) { lastError = error; }
    if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 300 * 2 ** attempt));
  }
  throw lastError instanceof Error ? lastError : new Error("OSV request failed");
}

export async function queryOsv(packages: OsvPackage[]) {
  const results: Array<OsvVulnerability[]> = [];
  for (let offset = 0; offset < packages.length; offset += 500) {
    const slice = packages.slice(offset, offset + 500);
    const body = { queries: slice.map(({ name, version, ecosystem }) => ({ package: { name, ecosystem }, version })) };
    const response = await request<{ results: Array<{ vulns?: Array<{ id: string; modified?: string }>; next_page_token?: string }> }>(`${env.OSV_API_BASE_URL}/v1/querybatch`, { method: "POST", body: JSON.stringify(body) });
    if (!Array.isArray(response.results) || response.results.length !== slice.length) throw new Error("OSV batch response did not match the query count");
    for (let index = 0; index < response.results.length; index += 1) {
      const initial = response.results[index]!;
      const found = [...(initial.vulns ?? [])];
      let pageToken = initial.next_page_token;
      let pageCount = 0;
      while (pageToken && pageCount < 20) {
        const pkg = slice[index]!;
        const page = await request<{ vulns?: Array<{ id: string; modified?: string }>; next_page_token?: string }>(`${env.OSV_API_BASE_URL}/v1/query`, { method: "POST", body: JSON.stringify({ package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version, page_token: pageToken }) });
        found.push(...(page.vulns ?? []));
        pageToken = page.next_page_token;
        pageCount += 1;
      }
      if (pageToken) throw new Error(`OSV advisory pagination exceeded its safety limit for ${slice[index]!.name}`);
      results.push([...new Map(found.map((vulnerability) => [vulnerability.id, vulnerability])).values()]);
    }
  }
  const ids = [...new Set(results.flat().map((vulnerability) => vulnerability.id))];
  const details = new Map<string, OsvVulnerability>();
  let cursor = 0;
  const workers = Array.from({ length: Math.min(8, ids.length) }, async () => {
    while (cursor < ids.length) {
      const id = ids[cursor++]!;
      const vulnerability = await request<OsvVulnerability>(`${env.OSV_API_BASE_URL}/v1/vulns/${encodeURIComponent(id)}`);
      details.set(id, vulnerability);
    }
  });
  await Promise.all(workers);
  return { results, vulnerabilities: details };
}
