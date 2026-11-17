import { pool } from "../db/pool.js";
import type { OsvPackage } from "./osv.js";
import { env } from "../config/env.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const ghEcosystem: Record<string, string> = { npm: "npm", PyPI: "pip", Maven: "maven", Go: "go", "crates.io": "rust" };

async function jsonRequest<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000), headers: { "User-Agent": "DependencyShield/0.1", Accept: "application/json", ...init?.headers } });
  if (!response.ok) throw new Error(`Advisory source returned ${response.status}`);
  return await response.json() as T;
}

export async function enrichFromGithubAdvisories(packages: OsvPackage[]) {
  const hits = new Map<string, Array<{ id: string; payload: unknown }>>();
  const unique = new Map(packages.map((pkg) => [`${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`, pkg]));
  for (const pkg of unique.values()) {
    const ecosystem = ghEcosystem[pkg.ecosystem];
    if (!ecosystem) continue;
    const query = new URLSearchParams({ "affects[]": `${pkg.name}@${pkg.version}`, ecosystem, per_page: "100" });
    try {
      const advisories = await jsonRequest<Array<{ ghsa_id: string; cve_id?: string | null; updated_at?: string; vulnerabilities?: Array<{ package?: { ecosystem?: string; name?: string }; vulnerable_version_range?: string; first_patched_version?: { identifier?: string } | null }> }>>(`https://api.github.com/advisories?${query}`, { headers: { "X-GitHub-Api-Version": "2026-03-10", Accept: "application/vnd.github+json" } });
      for (const advisory of advisories) {
        if (!advisory.ghsa_id) continue;
        const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
        hits.set(key, [...(hits.get(key) ?? []), { id: advisory.ghsa_id, payload: advisory }]);
      }
    } catch (error) { console.warn(`GitHub advisory lookup unavailable for ${pkg.name}: ${error instanceof Error ? error.message : "request failed"}`); }
  }
  return hits;
}

export async function syncCisaKev() {
  const feed = await jsonRequest<{ vulnerabilities?: Array<{ cveID?: string; dateAdded?: string; [key: string]: unknown }> }>(KEV_URL);
  if (!Array.isArray(feed.vulnerabilities)) throw new Error("CISA KEV feed had no vulnerabilities list");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of feed.vulnerabilities) {
      if (!item.cveID || !/^CVE-\d{4}-\d{4,}$/i.test(item.cveID) || !item.dateAdded || Number.isNaN(Date.parse(item.dateAdded))) continue;
      await client.query(`INSERT INTO kev_entries (cve_id, date_added, payload, synchronized_at) VALUES ($1,$2,$3,now()) ON CONFLICT (cve_id) DO UPDATE SET date_added=EXCLUDED.date_added, payload=EXCLUDED.payload, synchronized_at=now()`, [item.cveID.toUpperCase(), item.dateAdded, JSON.stringify(item)]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
  return feed.vulnerabilities.length;
}

export async function persistGithubAdvisories(client: { query: (sql: string, params?: unknown[]) => Promise<unknown> }, records: Array<{ id: string; payload: unknown }>) {
  for (const record of records) {
    const payload = record.payload as { cve_id?: string | null; updated_at?: string };
    const canonical = payload.cve_id ? await client.query("SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = $1 ORDER BY vulnerability_id LIMIT 1", [payload.cve_id]) as { rows?: Array<{ vulnerability_id: string }> } : null;
    const canonicalId = canonical?.rows?.[0]?.vulnerability_id ?? null;
    await client.query(`INSERT INTO vulnerability_source_records (source, external_id, canonical_vulnerability_id, payload, modified_at, synchronized_at) VALUES ('GitHub Advisory Database',$1,$2,$3,$4,now()) ON CONFLICT (source, external_id) DO UPDATE SET canonical_vulnerability_id=COALESCE(EXCLUDED.canonical_vulnerability_id,vulnerability_source_records.canonical_vulnerability_id), payload=EXCLUDED.payload, modified_at=EXCLUDED.modified_at, synchronized_at=now()`, [record.id, canonicalId, JSON.stringify(record.payload), payload.updated_at && !Number.isNaN(Date.parse(payload.updated_at)) ? new Date(payload.updated_at) : null]);
  }
}

type NvdCve = { id: string; lastModified?: string; descriptions?: Array<{ lang: string; value: string }>; metrics?: unknown; weaknesses?: unknown; references?: unknown; [key: string]: unknown };
export async function enrichFromNvd(cveIds: string[]) {
  const uniqueIds = [...new Set(cveIds.map((id) => id.toUpperCase()).filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)))];
  if (!uniqueIds.length) return { requested: 0, enriched: 0, truncated: false };
  const truncated = uniqueIds.length > 100;
  const ids = uniqueIds.slice(0, 100);
  const cached = await pool.query<{ external_id: string }>("SELECT external_id FROM vulnerability_source_records WHERE source='NVD' AND external_id = ANY($1::text[]) AND synchronized_at > now() - interval '14 days'", [ids]);
  const fresh = new Set(cached.rows?.map((row) => row.external_id) ?? []);
  const missing = ids.filter((id) => !fresh.has(id));
  let enriched = 0;
  for (let offset = 0; offset < missing.length; offset += 25) {
    if (!env.NVD_API_KEY && offset > 0) await new Promise((resolve) => setTimeout(resolve, 6500));
    const batch = missing.slice(offset, offset + 25);
    const query = new URLSearchParams({ cveIds: batch.join(","), resultsPerPage: String(batch.length) });
    const payload = await jsonRequest<{ vulnerabilities?: Array<{ cve: NvdCve }> }>(`https://services.nvd.nist.gov/rest/json/cves/2.0?${query}`, env.NVD_API_KEY ? { headers: { apiKey: env.NVD_API_KEY } } : undefined);
    for (const item of payload.vulnerabilities ?? []) {
      const cve = item.cve;
      if (!/^CVE-\d{4}-\d{4,}$/i.test(cve?.id ?? "")) continue;
      const canonical = await pool.query<{ vulnerability_id: string }>("SELECT vulnerability_id FROM vulnerability_aliases WHERE alias=$1 ORDER BY vulnerability_id LIMIT 1", [cve.id]);
      const modified = cve.lastModified && !Number.isNaN(Date.parse(cve.lastModified)) ? new Date(cve.lastModified) : null;
      await pool.query(`INSERT INTO vulnerability_source_records (source,external_id,canonical_vulnerability_id,payload,modified_at,synchronized_at) VALUES ('NVD',$1,$2,$3,$4,now()) ON CONFLICT (source,external_id) DO UPDATE SET canonical_vulnerability_id=COALESCE(EXCLUDED.canonical_vulnerability_id,vulnerability_source_records.canonical_vulnerability_id),payload=EXCLUDED.payload,modified_at=EXCLUDED.modified_at,synchronized_at=now()`, [cve.id.toUpperCase(), canonical.rows?.[0]?.vulnerability_id ?? null, JSON.stringify(cve), modified]);
      enriched += 1;
    }
  }
  return { requested: ids.length, enriched, truncated };
}

export function githubPackageKey(pkg: OsvPackage) { return `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`; }
