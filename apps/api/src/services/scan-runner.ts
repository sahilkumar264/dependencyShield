import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { pool } from "../db/pool.js";
import { env } from "../config/env.js";
import { getRepositoryArchive, githubFetch, installationAccessToken } from "./github-app.js";
import { validateCycloneDx } from "./cyclonedx.js";
import { OsvPackage, OsvVulnerability, parsePurl, queryOsv } from "./osv.js";
import { enrichFromGithubAdvisories, enrichFromNvd, githubPackageKey, persistGithubAdvisories } from "./advisory-intelligence.js";
import { evaluateGithubSemverRange, evaluateOsvLocalRange } from "./range-evidence.js";
import { sendVulnerabilityAlert } from "./notifications.js";

type ScanRow = { id: string; repository_id: string; owner: string; name: string; github_repo_id: string; installation_id: string; scan_branch: string; requested_commit_sha: string | null };
type SemgrepMatch = { check_id: string; path: string; start: { line: number }; end: { line: number }; extra: { message?: string; severity?: string; lines?: string } };

function runProcess(binary: string, args: string[], cwd: string, timeoutMs: number) {
  return new Promise<{ stdout: string; stderr: string }>((resolvePromise, reject) => {
    const child = spawn(binary, args, { cwd, shell: false, windowsHide: true, env: { PATH: process.env.PATH ?? "", HOME: cwd, USERPROFILE: cwd, PYTHONNOUSERSITE: "1", SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => { if (stdout.length < 20_000_000) stdout += chunk.toString("utf8").slice(0, 20_000_000 - stdout.length); });
    child.stderr?.on("data", (chunk: Buffer) => { if (stderr.length < 20_000) stderr += chunk.toString("utf8").slice(0, 20_000 - stderr.length); });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("error", (error) => { clearTimeout(timer); reject(new Error(`Could not start ${binary}: ${error.message}`)); });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolvePromise({ stdout, stderr });
      else reject(new Error(code === null ? `${binary} exceeded its time limit` : `${binary} exited with code ${code}: ${stderr.slice(0, 1000)}`));
    });
  });
}

async function runSemgrep(archive: string, scratch: string) {
  const source = join(scratch, "source");
  await mkdir(source);
  await runProcess(env.PYTHON_BINARY, ["apps/api/scripts/extract_archive.py", archive, source], process.cwd(), 2 * 60_000);
  const output = join(scratch, "semgrep.json");
  const rules = resolve("apps/api/semgrep-rules.yml");
  const result = await runProcess(env.SEMGREP_BINARY, ["scan", "--config", rules, "--json", "--metrics=off", "--disable-version-check", "--quiet", "--output", output, source], source, 3 * 60_000);
  const payload = JSON.parse(await readFile(output, "utf8")) as { results?: SemgrepMatch[]; version?: string; errors?: Array<{ message?: string }> };
  const matches = Array.isArray(payload.results) ? payload.results : [];
  const findings = matches.flatMap((match) => {
    if (!match || typeof match.check_id !== "string" || typeof match.path !== "string" || !Number.isInteger(match.start?.line) || !Number.isInteger(match.end?.line)) return [];
    const absolute = isAbsolute(match.path) ? resolve(match.path) : resolve(source, match.path);
    const file = relative(source, absolute);
    if (!file || file === ".." || file.startsWith(`..${sep}`) || isAbsolute(file)) return [];
    return [{ ruleId: match.check_id.slice(0, 200), severity: (match.extra?.severity ?? "INFO").toUpperCase().slice(0, 20), message: (match.extra?.message ?? "Semgrep match").slice(0, 2000), filePath: file.split(sep).join("/"), startLine: match.start.line, endLine: Math.max(match.start.line, match.end.line), snippet: (match.extra?.lines ?? "").slice(0, 4000) }];
  });
  return { version: typeof payload.version === "string" ? payload.version : "unknown", findings, warning: payload.errors?.map((item) => item.message).filter(Boolean).join("; ") || result.stderr.slice(0, 1000) || null };
}

function runSyft(archivePath: string, outputPath: string, source: string, version: string, home: string) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(env.SYFT_BINARY, ["scan", archivePath, "--scope", "squashed", "-o", `cyclonedx-json=${outputPath}`, `--source-name=${source}`, `--source-version=${version}`], {
      cwd: home,
      shell: false,
      windowsHide: true,
      env: { PATH: process.env.PATH ?? "", HOME: home, USERPROFILE: home, SYFT_CHECK_FOR_APP_UPDATE: "false", SYFT_FORMAT_CYCLONEDX_JSON_PRETTY: "false" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => { if (stderr.length < 20_000) stderr += chunk.toString("utf8").slice(0, 20_000 - stderr.length); });
    const timer = setTimeout(() => child.kill("SIGKILL"), 5 * 60_000);
    child.once("error", (error) => { clearTimeout(timer); reject(new Error(`Could not start Syft: ${error.message}`)); });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(code === null ? "Syft exceeded the five-minute scan limit" : `Syft exited with code ${code}: ${stderr.slice(0, 1000)}`));
    });
  });
}

function advisoryModified(value: OsvVulnerability) {
  if (!value.modified) return null;
  const timestamp = new Date(value.modified);
  return Number.isNaN(timestamp.getTime()) ? null : timestamp;
}

export async function runRepositoryScan(scanId: string) {
  const selected = await pool.query<ScanRow>(
    `SELECT s.id, s.repository_id, r.owner, r.name, r.github_repo_id::text, r.installation_id::text, s.branch AS scan_branch, s.requested_commit_sha
     FROM scans s JOIN repositories r ON r.id = s.repository_id
     JOIN github_installations i ON i.id = r.installation_id AND i.user_id = r.user_id
     WHERE s.id = $1 AND s.status IN ('queued', 'processing')`, [scanId],
  );
  if (!selected.rowCount) return;
  const scan = selected.rows[0]!;
  const scratch = await mkdtemp(join(tmpdir(), "dependencyshield-scan-"));
  const archive = join(scratch, "source.tar.gz");
  const output = join(scratch, "bom.cdx.json");
  try {
    await pool.query("UPDATE scans SET status = 'processing', started_at = now(), error_message = NULL, vulnerability_error = NULL WHERE id = $1", [scanId]);
    const accessToken = await installationAccessToken(Number(scan.installation_id), Number(scan.github_repo_id));
    const encodedOwner = encodeURIComponent(scan.owner);
    const encodedName = encodeURIComponent(scan.name);
    const encodedBranch = encodeURIComponent(scan.scan_branch);
    const commit = scan.requested_commit_sha ? { sha: scan.requested_commit_sha } : await githubFetch<{ sha: string }>(`https://api.github.com/repos/${encodedOwner}/${encodedName}/commits/${encodedBranch}`, accessToken);
    if (!/^[a-f0-9]{40,64}$/i.test(commit.sha)) throw new Error("GitHub returned an invalid commit identifier");
    await getRepositoryArchive(scan.owner, scan.name, commit.sha, accessToken, archive, env.MAX_ARCHIVE_BYTES);
    await runSyft(archive, output, `${scan.owner}/${scan.name}`, commit.sha, scratch);
    let codeAnalysis: Awaited<ReturnType<typeof runSemgrep>> | null = null;
    let codeAnalysisError: string | null = null;
    try { codeAnalysis = await runSemgrep(archive, scratch); }
    catch (error) { codeAnalysisError = error instanceof Error ? error.message.slice(0, 1000) : "Semgrep analysis failed"; console.warn(`Code analysis unavailable for scan ${scanId}: ${codeAnalysisError}`); }
    const rawBom = JSON.parse(await readFile(output, "utf8")) as unknown;
    const bom = validateCycloneDx(rawBom);
    const rootRef = bom.metadata?.component?.["bom-ref"] ?? null;
    let bomId: string = randomUUID();
    const db = await pool.connect();
    const refs = new Map<string, string>();
    const parsedComponents = bom.components.map((component, index) => {
      const bomRef = component["bom-ref"] ?? `urn:uuid:${randomUUID()}`;
      const purl = component.purl ?? null;
      const purlPackage = purl ? parsePurl(purl, component.version) : null;
      const parsed = purlPackage && component.version && purlPackage.version !== component.version ? null : purlPackage;
      const version = component.version ?? parsed?.version ?? null;
      const identity = purl ? `${purl}@${version ?? "unknown"}` : JSON.stringify([component.type, component.name, version ?? "unknown"]);
      refs.set(bomRef, bomRef);
      return { component, bomRef, purl, parsed, version, identity };
    });
    if (rootRef) refs.set(rootRef, rootRef);
    try {
      await db.query("BEGIN");
      const applicationResult = await db.query<{ id: string }>(
        `INSERT INTO applications (repository_id, name) VALUES ($1, $2)
         ON CONFLICT (repository_id) DO UPDATE SET name = EXCLUDED.name, updated_at = now() RETURNING id`,
        [scan.repository_id, `${scan.owner}/${scan.name}`],
      );
      const applicationId = applicationResult.rows[0]!.id;
      await db.query(
        `INSERT INTO sboms (id, scan_id, repository_id, commit_sha, branch, spec_version, serial_number, component_count, bom)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (scan_id) DO UPDATE SET commit_sha = EXCLUDED.commit_sha, branch = EXCLUDED.branch, spec_version = EXCLUDED.spec_version, serial_number = EXCLUDED.serial_number, component_count = EXCLUDED.component_count, bom = EXCLUDED.bom
         RETURNING id`,
        [bomId, scanId, scan.repository_id, commit.sha, scan.scan_branch, bom.specVersion, bom.serialNumber ?? null, parsedComponents.length, JSON.stringify(bom)],
      );
      const sbomResult = await db.query<{ id: string }>("SELECT id FROM sboms WHERE scan_id = $1", [scanId]);
      bomId = sbomResult.rows[0]!.id;
      await db.query("DELETE FROM sbom_components WHERE sbom_id = $1", [bomId]);
      for (const entry of parsedComponents) {
        const packageResult = await db.query<{ id: string }>(
          `INSERT INTO packages (identity, purl, name, version, ecosystem) VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (identity) DO UPDATE SET purl = EXCLUDED.purl, name = EXCLUDED.name, version = EXCLUDED.version, ecosystem = EXCLUDED.ecosystem RETURNING id`,
          [entry.identity, entry.purl, entry.component.name, entry.version, entry.parsed?.ecosystem ?? null],
        );
        await db.query("INSERT INTO sbom_components (sbom_id, package_id, bom_ref, component_type) VALUES ($1, $2, $3, $4) ON CONFLICT (sbom_id, bom_ref) DO UPDATE SET package_id = EXCLUDED.package_id, component_type = EXCLUDED.component_type", [bomId, packageResult.rows[0]!.id, entry.bomRef, entry.component.type]);
        (entry as typeof entry & { packageId?: string }).packageId = packageResult.rows[0]!.id;
      }
      if (rootRef && !parsedComponents.some((entry) => entry.bomRef === rootRef)) {
        await db.query("INSERT INTO sbom_components (sbom_id, package_id, bom_ref, component_type) VALUES ($1, NULL, $2, 'application') ON CONFLICT DO NOTHING", [bomId, rootRef]);
      }
      const rootDependency = rootRef ? bom.dependencies.find((dependency) => dependency.ref === rootRef) : undefined;
      const graphStatus = !rootRef ? "unknown" : rootDependency || parsedComponents.length === 0 ? "complete" : "incomplete";
      await db.query(
        `INSERT INTO scan_applications (scan_id, application_id, root_bom_ref, dependency_graph_status) VALUES ($1, $2, $3, $4)
         ON CONFLICT (scan_id, application_id) DO UPDATE SET root_bom_ref = EXCLUDED.root_bom_ref, dependency_graph_status = EXCLUDED.dependency_graph_status`,
        [scanId, applicationId, rootRef, graphStatus],
      );
      for (const dependency of bom.dependencies) {
        for (const child of dependency.dependsOn) {
          if (refs.has(dependency.ref) && refs.has(child)) await db.query("INSERT INTO dependency_edges (sbom_id, source_ref, target_ref) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [bomId, dependency.ref, child]);
        }
      }
      await db.query("DELETE FROM finding_reachability WHERE scan_id = $1", [scanId]);
      await db.query("DELETE FROM code_analysis_findings WHERE scan_id = $1", [scanId]);
      const analysisStatus = codeAnalysis ? (codeAnalysis.warning ? "partial" : "completed") : "unavailable";
      await db.query(
        `INSERT INTO code_analysis_runs (scan_id, status, engine, engine_version, commit_sha, error_message, completed_at)
         VALUES ($1, $2, 'Semgrep CE', $3, $4, $5, now())
         ON CONFLICT (scan_id) DO UPDATE SET status = EXCLUDED.status, engine = EXCLUDED.engine, engine_version = EXCLUDED.engine_version, commit_sha = EXCLUDED.commit_sha, error_message = EXCLUDED.error_message, started_at = now(), completed_at = now()`,
        [scanId, analysisStatus, codeAnalysis?.version ?? null, commit.sha, codeAnalysisError ?? codeAnalysis?.warning ?? null],
      );
      for (const item of codeAnalysis?.findings ?? []) {
        await db.query(
          `INSERT INTO code_analysis_findings (scan_id, rule_id, severity, message, file_path, start_line, end_line, code_snippet)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (scan_id, rule_id, file_path, start_line) DO UPDATE SET severity=EXCLUDED.severity, message=EXCLUDED.message, end_line=EXCLUDED.end_line, code_snippet=EXCLUDED.code_snippet`,
          [scanId, item.ruleId, item.severity, item.message, item.filePath, item.startLine, item.endLine, item.snippet],
        );
      }
      await db.query("UPDATE scans SET sbom_status = 'completed' WHERE id = $1", [scanId]);
      await db.query("COMMIT");
    } catch (error) {
      await db.query("ROLLBACK");
      throw error;
    } finally { db.release(); }

    try {
      const queryPackages = new Map<string, OsvPackage>();
      for (const entry of parsedComponents) if (entry.purl && entry.parsed) queryPackages.set(entry.bomRef, entry.parsed);
      const queryList = [...queryPackages.entries()];
      const { results, vulnerabilities } = await queryOsv(queryList.map(([, pkg]) => pkg));
      const githubHits = await enrichFromGithubAdvisories(queryList.map(([, pkg]) => pkg));
      const nvdCveIds = [...vulnerabilities.values()].flatMap((advisory) => advisory.aliases ?? [])
        .concat([...githubHits.values()].flat().flatMap((hit) => { const cve = (hit.payload as { cve_id?: unknown }).cve_id; return typeof cve === "string" ? [cve] : []; }));
      const db = await pool.connect();
      try {
        await db.query("BEGIN");
        for (const [id, advisory] of vulnerabilities) {
          await db.query(
            `INSERT INTO vulnerabilities (id, source, modified_at, payload, synchronized_at) VALUES ($1, 'OSV', $2, $3, now())
             ON CONFLICT (id) DO UPDATE SET modified_at = EXCLUDED.modified_at, payload = EXCLUDED.payload, synchronized_at = now()`,
            [id, advisoryModified(advisory), JSON.stringify(advisory)],
          );
          for (const alias of new Set([id, ...(advisory.aliases ?? [])])) await db.query("INSERT INTO vulnerability_aliases (vulnerability_id, alias) VALUES ($1, $2) ON CONFLICT DO NOTHING", [id, alias]);
        }
        await persistGithubAdvisories(db, [...new Map([...githubHits.values()].flat().map((item) => [item.id, item])).values()]);
        for (let i = 0; i < queryList.length; i += 1) {
          const [bomRef] = queryList[i]!;
          const entry = parsedComponents.find((item) => item.bomRef === bomRef)! as typeof parsedComponents[number] & { packageId: string };
          const packageKey = githubPackageKey(queryList[i]![1]);
          const hits = [
            ...(results[i] ?? []).flatMap((hit) => { const payload = vulnerabilities.get(hit.id); return payload ? [{ id: hit.id, payload, source: "OSV" as const }] : []; }),
            ...(githubHits.get(packageKey) ?? []).map((hit) => ({ ...hit, source: "GitHub Advisory Database" as const })),
          ];
          for (const hit of hits) {
            let advisoryId = hit.id;
            if (hit.source !== "OSV") {
              const advisory = hit.payload as { cve_id?: string | null };
              const canonical = advisory.cve_id ? await db.query<{ vulnerability_id: string }>("SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = $1 ORDER BY vulnerability_id LIMIT 1", [advisory.cve_id]) : null;
              advisoryId = canonical?.rows[0]?.vulnerability_id ?? hit.id;
              if (advisoryId === hit.id) {
                await db.query(`INSERT INTO vulnerabilities (id, source, modified_at, payload, synchronized_at) VALUES ($1,'GitHub Advisory Database',now(),$2,now()) ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload, synchronized_at=now()`, [hit.id, JSON.stringify(hit.payload)]);
                await db.query("INSERT INTO vulnerability_aliases (vulnerability_id, alias) VALUES ($1,$2) ON CONFLICT DO NOTHING", [hit.id, hit.id]);
                if (advisory.cve_id) await db.query("INSERT INTO vulnerability_aliases (vulnerability_id, alias) VALUES ($1,$2) ON CONFLICT DO NOTHING", [hit.id, advisory.cve_id]);
              }
              await db.query("UPDATE vulnerability_source_records SET canonical_vulnerability_id=$2 WHERE source='GitHub Advisory Database' AND external_id=$1 AND canonical_vulnerability_id IS NULL", [hit.id, advisoryId]);
            }
            const pkg = queryList[i]![1];
            let rangeEvaluation;
            if (hit.source === "OSV") rangeEvaluation = evaluateOsvLocalRange(pkg, hit.payload as OsvVulnerability);
            else {
              const advisory = hit.payload as { vulnerabilities?: Array<{ package?: { ecosystem?: string; name?: string }; vulnerable_version_range?: string }> };
              const affectedPackage = advisory.vulnerabilities?.find((item) => item.package?.name?.toLocaleLowerCase() === pkg.name.toLocaleLowerCase() && item.package.ecosystem?.toLocaleLowerCase() === pkg.ecosystem.toLocaleLowerCase());
              rangeEvaluation = evaluateGithubSemverRange(pkg, affectedPackage?.vulnerable_version_range);
            }
            if (rangeEvaluation.status === "not_affected") rangeEvaluation = {
              status: "unknown" as const,
              source: rangeEvaluation.source,
              evidence: { ...rangeEvaluation.evidence, reason: "local_range_disagrees_with_exact_version_advisory_match", exact_version_match: "affected" },
            };
            const insertedFinding = await db.query<{ id: string; inserted: boolean }>(
              `INSERT INTO findings (scan_id, sbom_id, bom_ref, package_id, vulnerability_id, local_range_status, local_range_source, local_range_evidence)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
               ON CONFLICT (scan_id,bom_ref,vulnerability_id) DO UPDATE SET local_range_status=EXCLUDED.local_range_status, local_range_source=EXCLUDED.local_range_source, local_range_evidence=EXCLUDED.local_range_evidence
               RETURNING id,(xmax=0) AS inserted`,
              [scanId, bomId, bomRef, entry.packageId, advisoryId, rangeEvaluation.status, rangeEvaluation.source, JSON.stringify({ ...rangeEvaluation.evidence, advisory_source: hit.source })],
            );
            if (insertedFinding.rows[0]?.inserted) {
              const alert = await db.query<{ owner: string; repository: string; package_name: string; package_version: string | null; vulnerability_id: string; summary: string | null }>(
                `INSERT INTO monitoring_alerts (user_id, repository_id, scan_id, finding_id, vulnerability_id, package_id, category)
                 SELECT r.user_id, s.repository_id, s.id, f.id, f.vulnerability_id, f.package_id, 'new_vulnerability'
                 FROM scans s JOIN repositories r ON r.id=s.repository_id JOIN findings f ON f.id=$1 WHERE s.id=$2
                 ON CONFLICT (repository_id, vulnerability_id, package_id, category) DO NOTHING`,
                [insertedFinding.rows[0]!.id, scanId],
              );
              if (alert.rowCount) {
                const details = await db.query<{ owner: string; name: string; package_name: string; package_version: string | null; vulnerability_id: string; summary: string | null }>(
                  `SELECT r.owner,r.name,p.name AS package_name,p.version AS package_version,v.id AS vulnerability_id,v.payload->>'summary' AS summary
                   FROM findings f JOIN scans s ON s.id=f.scan_id JOIN repositories r ON r.id=s.repository_id JOIN packages p ON p.id=f.package_id JOIN vulnerabilities v ON v.id=f.vulnerability_id WHERE f.id=$1`,
                  [insertedFinding.rows[0]!.id],
                );
                const item = details.rows[0];
                if (item) try { await sendVulnerabilityAlert({ repository: `${item.owner}/${item.name}`, packageName: item.package_name, version: item.package_version, vulnerabilityId: item.vulnerability_id, summary: item.summary }); }
                catch (error) { console.warn(`External alert webhook failed for ${item.vulnerability_id}: ${error instanceof Error ? error.message : "request failed"}`); }
              }
            }
          }
        }
        const scanFindings = await db.query<{ id: string; package_name: string; ecosystem: string | null }>(
          `SELECT f.id, p.name AS package_name, p.ecosystem FROM findings f JOIN packages p ON p.id = f.package_id WHERE f.scan_id = $1`, [scanId],
        );
        const imports = (codeAnalysis?.findings ?? []).filter((item) => item.ruleId.endsWith("dependencyshield.import-reference"));
        const supportedEcosystems = new Set(["npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist"]);
        for (const finding of scanFindings.rows) {
          const name = finding.package_name.toLocaleLowerCase();
          const aliases = [name, name.replaceAll("-", "_"), name.replaceAll("_", "-")].filter((alias) => alias.length >= 3);
          const evidence = imports.filter((item) => aliases.some((alias) => item.snippet.toLocaleLowerCase().includes(alias)))
            .slice(0, 20).map((item) => ({ file: item.filePath, line: item.startLine, snippet: item.snippet }));
          const status = !codeAnalysis || !finding.ecosystem || !supportedEcosystems.has(finding.ecosystem) || aliases.length === 0 ? "unknown" : evidence.length ? "possible_usage" : "not_observed";
          await db.query(
            `INSERT INTO finding_reachability (finding_id, scan_id, status, evidence, analyzed_commit_sha) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (finding_id) DO UPDATE SET scan_id=EXCLUDED.scan_id, status=EXCLUDED.status, evidence=EXCLUDED.evidence, analyzed_commit_sha=EXCLUDED.analyzed_commit_sha, updated_at=now()`,
            [finding.id, scanId, status, JSON.stringify(evidence), commit.sha],
          );
        }
        const uncoveredCount = parsedComponents.length - queryList.length;
        const coverageMessage = uncoveredCount > 0 ? `${uncoveredCount} components did not have a supported ecosystem and version identity for OSV lookup` : null;
        await db.query("UPDATE scans SET vulnerability_status = $2, status = $3, vulnerability_error = $4, completed_at = now() WHERE id = $1", [scanId, uncoveredCount > 0 ? "partial" : "completed", uncoveredCount > 0 ? "completed_with_warnings" : "completed", coverageMessage]);
        await db.query("COMMIT");
        try {
          const result = await enrichFromNvd(nvdCveIds);
          if (result.requested) console.info(`NVD enrichment for scan ${scanId}: ${result.enriched}/${result.requested} CVEs refreshed${result.truncated ? " (100-CVE per-scan safety cap reached)" : ""}`);
        } catch (error) { console.warn(`NVD enrichment unavailable for scan ${scanId}: ${error instanceof Error ? error.message : "request failed"}`); }
      } catch (error) {
        await db.query("ROLLBACK");
        throw error;
      } finally { db.release(); }
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 1000) : "OSV lookup failed";
      await pool.query("UPDATE scans SET status = 'completed_with_warnings', vulnerability_status = 'unavailable', vulnerability_error = $2, completed_at = now() WHERE id = $1", [scanId, message]);
      console.warn(`OSV lookup failed for scan ${scanId}: ${message}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 1000) : "Scan failed";
    await pool.query("UPDATE scans SET status = 'queued', sbom_status = CASE WHEN sbom_status = 'completed' THEN sbom_status ELSE 'failed' END, error_message = $2, completed_at = NULL WHERE id = $1", [scanId, message]);
    console.error(`Repository scan ${scanId} failed: ${message}`);
    throw error;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
