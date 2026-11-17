import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile as readLocalFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import semver from "semver";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";
import { githubFetch, installationAccessToken } from "./github-app.js";

const API = "https://api.github.com";
const API_VERSION = "2026-03-10";
const execFileAsync = promisify(execFile);
type Context = { id: string; finding_id: string; owner: string; name: string; repository_id: string; github_repo_id: string; installation_id: string; branch: string; archived: boolean; package_name: string; package_version: string; ecosystem: string; vulnerability_id: string; payload: unknown };
type GitHubFile = { content: string; encoding: string; sha: string };
type ActionResult = { id: string; status: string; action_type: string; github_number: number | null; github_url: string | null; branch_name: string | null; target_version: string | null; error_message: string | null; authorized_at: Date };

function record(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function apiRepo(owner: string, name: string) { return `${API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`; }
function statusOf(error: unknown) { return typeof error === "object" && error !== null && "status" in error ? Number((error as { status: unknown }).status) : 0; }

async function contextForFinding(userId: string, findingId: string) {
  const result = await pool.query<Context>(
    `SELECT f.id AS finding_id, r.owner, r.name, r.id AS repository_id, r.github_repo_id::text, r.installation_id::text, r.archived,
            s.branch, p.name AS package_name, p.version AS package_version, p.ecosystem, v.id AS vulnerability_id, v.payload
     FROM findings f JOIN scans s ON s.id = f.scan_id JOIN repositories r ON r.id = s.repository_id
     JOIN packages p ON p.id = f.package_id JOIN vulnerabilities v ON v.id = f.vulnerability_id
     WHERE f.id = $1 AND r.user_id = $2`, [findingId, userId],
  );
  return result.rows[0] ?? null;
}

async function reserveAction(userId: string, findingId: string, action: "issue" | "draft_pr") {
  const result = await pool.query<ActionResult>(
    `INSERT INTO remediation_actions (user_id, finding_id, action_type, status, authorized_by)
     VALUES ($1,$2,$3,'in_progress',$1)
     ON CONFLICT (finding_id, action_type) DO UPDATE SET status='in_progress', error_message=NULL, authorized_by=EXCLUDED.authorized_by, authorized_at=now(), updated_at=now()
     WHERE remediation_actions.status='failed' OR (remediation_actions.status='in_progress' AND remediation_actions.updated_at < now() - interval '10 minutes')
     RETURNING id, status, action_type, github_number, github_url, branch_name, target_version, error_message, authorized_at`, [userId, findingId, action],
  );
  if (result.rows[0]) return { action: result.rows[0], claimed: true };
  const existing = await pool.query<ActionResult>("SELECT id, status, action_type, github_number, github_url, branch_name, target_version, error_message, authorized_at FROM remediation_actions WHERE finding_id=$1 AND action_type=$2 AND user_id=$3", [findingId, action, userId]);
  return { action: existing.rows[0] ?? null, claimed: false };
}

async function saveAction(id: string, status: "created" | "failed", values: { number?: number; url?: string; branch?: string; version?: string; error?: string }) {
  const result = await pool.query<ActionResult>(
    `UPDATE remediation_actions SET status=$2, github_number=$3, github_url=$4, branch_name=$5, target_version=$6, error_message=$7, updated_at=now()
     WHERE id=$1 RETURNING id, status, action_type, github_number, github_url, branch_name, target_version, error_message, authorized_at`,
    [id, status, values.number ?? null, values.url ?? null, values.branch ?? null, values.version ?? null, values.error?.slice(0, 500) ?? null],
  );
  return result.rows[0]!;
}

async function readFile(owner: string, repo: string, path: string, ref: string, token: string) {
  try {
    return await githubFetch<GitHubFile>(`${apiRepo(owner, repo)}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(ref)}`, token);
  } catch (error) { if (statusOf(error) === 404) return null; throw error; }
}

function marker(findingId: string, kind: "issue" | "draft-pr") { return `<!-- dependencyshield:${findingId}:${kind} -->`; }

function validateRegistryLock(lock: Record<string, unknown>) {
  if (typeof lock.lockfileVersion !== "number" || lock.lockfileVersion < 2) throw new Error("Automatic lockfile updates require npm package-lock version 2 or newer; create an issue for maintainer remediation");
  const visit = (value: unknown) => {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) { for (const item of value) visit(item); return; }
    const item = value as Record<string, unknown>;
    if (typeof item.resolved === "string") {
      let resolved: URL;
      try { resolved = new URL(item.resolved); } catch { throw new Error("The lockfile contains an unsupported package source; create an issue instead"); }
      if (resolved.protocol !== "https:" || resolved.hostname !== "registry.npmjs.org" || resolved.username || resolved.password) throw new Error("Automatic lockfile updates support only packages resolved from registry.npmjs.org");
    }
    for (const child of Object.values(item)) visit(child);
  };
  visit(lock.packages);
  visit(lock.dependencies);
}

async function updateNpmLockfile(packageJson: Record<string, unknown>, lockContent: string, packageName: string, version: string) {
  if (packageJson.workspaces) throw new Error("Workspace package manifests require a workspace-aware lockfile update; create an issue for maintainer remediation");
  const lock = JSON.parse(lockContent) as Record<string, unknown>;
  validateRegistryLock(lock);
  for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const [name, spec] of Object.entries(record(packageJson[group]))) {
      if (typeof spec !== "string" || !semver.validRange(spec)) throw new Error(`Automatic lockfile updates cannot safely resolve ${name}'s non-registry version specifier`);
    }
  }
  const scratch = await mkdtemp(join(tmpdir(), "dependencyshield-npm-lock-"));
  try {
    await writeFile(join(scratch, "package.json"), JSON.stringify(packageJson, null, 2));
    await writeFile(join(scratch, "package-lock.json"), lockContent);
    await execFileAsync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org", `--lockfile-version=${lock.lockfileVersion}`, "--prefix", scratch], {
      cwd: scratch, timeout: 120_000, maxBuffer: 2_000_000,
      env: { PATH: process.env.PATH ?? "", HOME: scratch, USERPROFILE: scratch, NPM_CONFIG_CACHE: join(scratch, "cache"), NPM_CONFIG_UPDATE_NOTIFIER: "false", NPM_CONFIG_FUND: "false", NPM_CONFIG_AUDIT: "false", NPM_CONFIG_IGNORE_SCRIPTS: "true" },
    });
    const updated = await readLocalFile(join(scratch, "package-lock.json"), "utf8");
    const parsed = JSON.parse(updated) as { packages?: Record<string, { version?: string }> };
    if (parsed.packages?.[`node_modules/${packageName}`]?.version !== version) throw new Error("The generated npm lockfile did not resolve the requested fixed version");
    validateRegistryLock(parsed as Record<string, unknown>);
    return updated.endsWith("\n") ? updated : `${updated}\n`;
  } catch (error) {
    if (error instanceof Error && error.message.includes("Automatic lockfile")) throw error;
    throw new Error(`Could not safely update the npm lockfile: ${error instanceof Error ? error.message.slice(0, 300) : "npm lock update failed"}`);
  } finally { await rm(scratch, { recursive: true, force: true }); }
}

async function findExisting(owner: string, repo: string, markerText: string, token: string, type: "issue" | "draft-pr") {
  for (let page = 1; page <= 10; page += 1) {
    const rows = await githubFetch<Array<{ number: number; html_url: string; body?: string | null; pull_request?: unknown }>>(`${apiRepo(owner, repo)}/issues?state=all&per_page=100&page=${page}`, token);
    const match = rows.find((row) => (type === "draft-pr" ? Boolean(row.pull_request) : !row.pull_request) && row.body?.includes(markerText));
    if (match) return match;
    if (rows.length < 100) break;
  }
  return null;
}

export async function createRemediationIssue(userId: string, findingId: string) {
  const finding = await contextForFinding(userId, findingId);
  if (!finding) return null;
  if (finding.archived) throw new Error("Archived repositories cannot receive remediation issues");
  const claim = await reserveAction(userId, findingId, "issue");
  if (!claim.action) throw new Error("Could not reserve the issue action");
  if (!claim.claimed) {
    if (claim.action.status === "created") return claim.action;
    throw new Error("Issue creation is already in progress; refresh shortly");
  }
  const tag = marker(findingId, "issue");
  let token = "";
  try {
    token = await installationAccessToken(Number(finding.installation_id), Number(finding.github_repo_id));
    const existing = await findExisting(finding.owner, finding.name, tag, token, "issue");
    if (existing) return await saveAction(claim.action.id, "created", { number: existing.number, url: existing.html_url });
    const body = [
      `## Dependency vulnerability remediation`,
      `- **Advisory:** ${finding.vulnerability_id}`,
      `- **Package:** \`${finding.package_name}\``,
      `- **Detected version:** \`${finding.package_version}\``,
      `- **Ecosystem:** ${finding.ecosystem}`,
      `- **Scan branch:** \`${finding.branch}\``,
      "",
      "OSV reports this installed package version as affected. Review the advisory's affected ranges and fixed versions before selecting an update.",
      "",
      "Review the advisory's affected ranges and fixed versions, update the dependency and lockfile, then run the repository's relevant tests. Do not merge until a maintainer reviews the change and required checks pass.",
      "",
      tag,
    ].join("\n");
    const created = await githubFetch<{ number: number; html_url: string }>(`${apiRepo(finding.owner, finding.name)}/issues`, token, "POST", { title: `Security: remediate ${finding.vulnerability_id} in ${finding.package_name}`.slice(0, 240), body });
    return await saveAction(claim.action.id, "created", { number: created.number, url: created.html_url });
  } catch (error) {
    const existing = await findExisting(finding.owner, finding.name, tag, token, "issue").catch(() => null);
    if (existing) return await saveAction(claim.action.id, "created", { number: existing.number, url: existing.html_url });
    await saveAction(claim.action.id, "failed", { error: error instanceof Error ? error.message : "GitHub issue creation failed" });
    throw error;
  }
}

function parseRelease(value: string) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  return match ? match.slice(1).map(Number) : value === "0" ? [0, 0, 0] : null;
}
function compareRelease(left: number[], right: number[]) {
  for (let i = 0; i < 3; i += 1) if (left[i] !== right[i]) return left[i]! - right[i]!;
  return 0;
}
function fixedVersion(payload: unknown, packageName: string, ecosystem: string, installed: string) {
  const advisory = record(payload);
  if (!Array.isArray(advisory.affected)) return null;
  const affected = advisory.affected.find((entry) => {
    const item = record(entry); const pkg = record(item.package);
    return typeof pkg.name === "string" && pkg.name.toLocaleLowerCase() === packageName.toLocaleLowerCase() && typeof pkg.ecosystem === "string" && pkg.ecosystem.toLocaleLowerCase() === ecosystem.toLocaleLowerCase();
  });
  if (!affected) return null;
  const installedParts = parseRelease(installed);
  if (!installedParts) return null;
  const ranges = record(affected).ranges;
  if (!Array.isArray(ranges)) return null;
  const candidates = new Set<string>();
  for (const range of ranges) {
    const rangeType = record(range).type;
    if (rangeType !== "SEMVER" && rangeType !== "ECOSYSTEM") continue;
    const events = record(range).events;
    if (!Array.isArray(events)) continue;
    let introduced: number[] | null = [0, 0, 0];
    for (const event of events) {
      const change = record(event);
      if (typeof change.introduced === "string") introduced = parseRelease(change.introduced);
      if (typeof change.fixed === "string") {
        const fix = parseRelease(change.fixed);
        if (fix && introduced && compareRelease(installedParts, introduced) >= 0 && compareRelease(installedParts, fix) < 0) candidates.add(change.fixed);
        introduced = null;
      }
    }
  }
  if (candidates.size !== 1) return null;
  return [...candidates][0] ?? null;
}

export async function createDraftRemediationPr(userId: string, findingId: string) {
  const finding = await contextForFinding(userId, findingId);
  if (!finding) return null;
  if (finding.archived) throw new Error("Archived repositories cannot receive remediation pull requests");
  if (finding.ecosystem !== "npm") throw new Error("Draft upgrades currently support direct npm dependencies only; create a remediation issue instead");
  const version = fixedVersion(finding.payload, finding.package_name, "npm", finding.package_version);
  if (!version) throw new Error("OSV did not supply a supported fixed version for this package");
  const claim = await reserveAction(userId, findingId, "draft_pr");
  if (!claim.action) throw new Error("Could not reserve the pull request action");
  if (!claim.claimed) {
    if (claim.action.status === "created") return claim.action;
    throw new Error("Draft pull request creation is already in progress; refresh shortly");
  }
  const tag = marker(findingId, "draft-pr");
  let branch: string | undefined;
  let token = "";
  try {
    token = await installationAccessToken(Number(finding.installation_id), Number(finding.github_repo_id));
    const existing = await findExisting(finding.owner, finding.name, tag, token, "draft-pr");
    if (existing) return await saveAction(claim.action.id, "created", { number: existing.number, url: existing.html_url, version });
    const file = await readFile(finding.owner, finding.name, "package.json", finding.branch, token);
    if (!file || file.encoding !== "base64") throw new Error("Could not read the root package.json from the scanned branch");
    const unsupportedLock = await Promise.all(["npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"].map(async (lock) => ({ lock, file: await readFile(finding.owner, finding.name, lock, finding.branch, token) })));
    const presentUnsupportedLock = unsupportedLock.find((item) => item.file);
    if (presentUnsupportedLock) throw new Error(`Automatic draft PR currently cannot update ${presentUnsupportedLock.lock}; create an issue for maintainer remediation`);
    const packageJson = JSON.parse(Buffer.from(file.content.replace(/\s/g, ""), "base64").toString("utf8")) as Record<string, unknown>;
    const dependencyGroups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
    const group = dependencyGroups.find((key) => Object.hasOwn(record(packageJson[key]), finding.package_name));
    if (!group) throw new Error("This vulnerable package is not a direct dependency in the root package.json; create an issue for maintainer remediation");
    const dependencies = { ...record(packageJson[group]) };
    dependencies[finding.package_name] = version;
    packageJson[group] = dependencies;
    const updatedFile = `${JSON.stringify(packageJson, null, 2)}\n`;
    const packageLockFile = await readFile(finding.owner, finding.name, "package-lock.json", finding.branch, token);
    const updatedLock = packageLockFile
      ? await updateNpmLockfile(packageJson, Buffer.from(packageLockFile.content.replace(/\s/g, ""), "base64").toString("utf8"), finding.package_name, version)
      : null;

    const baseRef = await githubFetch<{ object: { sha: string } }>(`${apiRepo(finding.owner, finding.name)}/git/ref/heads/${encodeURIComponent(finding.branch)}`, token);
    const baseCommit = await githubFetch<{ tree: { sha: string } }>(`${apiRepo(finding.owner, finding.name)}/git/commits/${baseRef.object.sha}`, token);
    const manifestBlob = await githubFetch<{ sha: string }>(`${apiRepo(finding.owner, finding.name)}/git/blobs`, token, "POST", { content: Buffer.from(updatedFile).toString("base64"), encoding: "base64" });
    const treeEntries: Array<{ path: string; mode: "100644"; type: "blob"; sha: string }> = [{ path: "package.json", mode: "100644", type: "blob", sha: manifestBlob.sha }];
    if (updatedLock) {
      const lockBlob = await githubFetch<{ sha: string }>(`${apiRepo(finding.owner, finding.name)}/git/blobs`, token, "POST", { content: Buffer.from(updatedLock).toString("base64"), encoding: "base64" });
      treeEntries.push({ path: "package-lock.json", mode: "100644", type: "blob", sha: lockBlob.sha });
    }
    const tree = await githubFetch<{ sha: string }>(`${apiRepo(finding.owner, finding.name)}/git/trees`, token, "POST", { base_tree: baseCommit.tree.sha, tree: treeEntries });
    const commit = await githubFetch<{ sha: string }>(`${apiRepo(finding.owner, finding.name)}/git/commits`, token, "POST", { message: `fix: upgrade ${finding.package_name} to ${version}`, tree: tree.sha, parents: [baseRef.object.sha] });
    branch = claim.action.branch_name ?? `dependencyshield-fix-${findingId.slice(0, 8)}-${claim.action.id.slice(0, 8)}`;
    const existingBranch = await githubFetch<{ object: { sha: string } }>(`${apiRepo(finding.owner, finding.name)}/git/ref/heads/${encodeURIComponent(branch)}`, token).catch((error) => statusOf(error) === 404 ? null : Promise.reject(error));
    if (existingBranch) {
      const branchFile = await readFile(finding.owner, finding.name, "package.json", branch, token);
      if (!branchFile || branchFile.encoding !== "base64") throw new Error("The existing remediation branch could not be verified");
      const branchJson = JSON.parse(Buffer.from(branchFile.content.replace(/\s/g, ""), "base64").toString("utf8")) as Record<string, unknown>;
      if (record(branchJson[group])[finding.package_name] !== version) throw new Error("The existing remediation branch does not contain the expected package version");
      if (updatedLock) {
        const branchLock = await readFile(finding.owner, finding.name, "package-lock.json", branch, token);
        if (!branchLock || Buffer.from(branchLock.content.replace(/\s/g, ""), "base64").toString("utf8").trimEnd() !== updatedLock.trimEnd()) throw new Error("The existing remediation branch does not contain the expected package-lock.json update");
      }
    } else {
      await githubFetch<{ ref: string }>(`${apiRepo(finding.owner, finding.name)}/git/refs`, token, "POST", { ref: `refs/heads/${branch}`, sha: commit.sha });
    }
    const body = [
      "## DependencyShield draft remediation", "",
      `- Advisory: ${finding.vulnerability_id}`, `- Package: \`${finding.package_name}\``, `- Detected version: \`${finding.package_version}\``, `- Proposed fixed version: \`${version}\``, `- Base commit: \`${baseRef.object.sha}\``, "",
      "### Review and validation required", "",
      `${updatedLock ? "This draft updates the root package manifest and package-lock.json using npm's package-lock-only mode with lifecycle scripts disabled. No packages were installed and no repository script was run by DependencyShield." : "This draft changes the root package manifest only because no root package-lock.json exists. No dependency installation or repository script was run by DependencyShield."} Review the diff, run the repository's relevant tests, and obtain maintainer approval before marking ready or merging. DependencyShield never merges this pull request.`, "",
      tag,
    ].join("\n");
    const pull = await githubFetch<{ number: number; html_url: string }>(`${apiRepo(finding.owner, finding.name)}/pulls`, token, "POST", { title: `Draft security fix: ${finding.package_name} ${version}`, body, head: branch, base: finding.branch, draft: true });
    return await saveAction(claim.action.id, "created", { number: pull.number, url: pull.html_url, branch, version });
  } catch (error) {
    const existing = await findExisting(finding.owner, finding.name, tag, token, "draft-pr").catch(() => null);
    if (existing) return await saveAction(claim.action.id, "created", { number: existing.number, url: existing.html_url, branch, version });
    await saveAction(claim.action.id, "failed", { branch, version, error: error instanceof Error ? error.message : "Draft pull request creation failed" });
    throw error;
  }
}

export async function listRemediationActions(userId: string, findingId?: string) {
  const result = await pool.query(
    `SELECT ra.id, ra.finding_id, ra.action_type, ra.status, ra.github_number, ra.github_url, ra.branch_name, ra.target_version, ra.error_message, ra.authorized_at,
            v.id AS vulnerability_id, p.name AS package_name, p.version AS package_version, r.owner, r.name AS repository_name
     FROM remediation_actions ra JOIN findings f ON f.id=ra.finding_id JOIN packages p ON p.id=f.package_id
     JOIN vulnerabilities v ON v.id=f.vulnerability_id JOIN scans s ON s.id=f.scan_id JOIN repositories r ON r.id=s.repository_id
     WHERE ra.user_id=$1 AND ($2::uuid IS NULL OR ra.finding_id=$2) ORDER BY ra.created_at DESC LIMIT 200`, [userId, findingId ?? null],
  );
  return result.rows;
}

export async function getDraftPullRequestChecks(userId: string, actionId: string) {
  const result = await pool.query<{ owner: string; name: string; github_repo_id: string; installation_id: string; github_number: number; html_url: string | null; status: string; action_type: string }>(
    `SELECT r.owner,r.name,r.github_repo_id::text,r.installation_id::text,ra.github_number,ra.github_url AS html_url,ra.status,ra.action_type
     FROM remediation_actions ra JOIN findings f ON f.id=ra.finding_id JOIN scans s ON s.id=f.scan_id JOIN repositories r ON r.id=s.repository_id
     WHERE ra.id=$1 AND ra.user_id=$2 AND r.user_id=$2`, [actionId, userId],
  );
  const action = result.rows[0];
  if (!action) return null;
  if (action.action_type !== "draft_pr" || action.status !== "created" || !action.github_number) throw new Error("CI status is available only for a created draft pull request");
  const token = await installationAccessToken(Number(action.installation_id), Number(action.github_repo_id));
  const pull = await githubFetch<{ head: { sha: string } }>(`${apiRepo(action.owner, action.name)}/pulls/${action.github_number}`, token);
  const response = await githubFetch<{ total_count: number; check_runs: Array<{ id: number; name: string; status: string; conclusion: string | null; html_url: string | null; completed_at: string | null }> }>(`${apiRepo(action.owner, action.name)}/commits/${encodeURIComponent(pull.head.sha)}/check-runs?per_page=100`, token);
  const runs = response.check_runs ?? [];
  const failed = runs.some((run) => ["failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"].includes(run.conclusion ?? ""));
  const pending = runs.length === 0 || runs.some((run) => run.status !== "completed");
  const status = failed ? "failure" : pending ? "pending" : runs.every((run) => ["success", "skipped", "neutral"].includes(run.conclusion ?? "")) ? "success" : "unknown";
  return { status, total: response.total_count, headSha: pull.head.sha, checks: runs.map(({ id, name, status, conclusion, html_url, completed_at }) => ({ id, name, status, conclusion, url: html_url, completedAt: completed_at })) };
}

export function remediationConfigAvailable() { return Boolean(env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY_B64); }
