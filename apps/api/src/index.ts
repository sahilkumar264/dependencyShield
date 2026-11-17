import Fastify from "fastify";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import { Redis } from "ioredis";
import { Queue } from "bullmq";
import { z } from "zod";
import { env } from "./config/env.js";
import { pool } from "./db/pool.js";
import { cookieOptions, finishGithubOAuth, readSession, startGithubOAuth } from "./services/github-oauth.js";
import { getInstallationAccount, listInstallationRepositories, listRepositoryBranches, verifyInstallationForUser, verifyRepositoryBranch } from "./services/github-app.js";
import { analyzeDependencyGraph, ImpactFinding, ImpactNode } from "./services/dependency-impact.js";
import { exportOkfBundle, getApplicationOkfContext, getOkfBundle, getOkfConcept, listOkfConcepts, listOkfRevisions, saveUserOkfConcept, validateOkfBundle } from "./services/okf.js";
import { createFindingDecision, getDecision, listDecisions } from "./services/jev-risk.js";
import { createDraftRemediationPr, createRemediationIssue, getDraftPullRequestChecks, listRemediationActions } from "./services/remediation.js";
import { enqueueRepositoryScan, processGithubWebhook } from "./services/monitoring.js";

const redis = new Redis(env.REDIS_URL, { maxRetriesPerRequest: null });
const scanQueue = new Queue("repository_scan", { connection: redis });
declare module "fastify" { interface FastifyRequest { rawBody?: Buffer } }
const trustedProxies = env.TRUST_PROXY.split(",").map((value) => value.trim()).filter(Boolean);
const app = Fastify({ logger: true, trustProxy: trustedProxies.length ? trustedProxies : false, bodyLimit: 10 * 1_048_576 });
app.removeContentTypeParser("application/json");
app.addContentTypeParser("application/json", { parseAs: "buffer" }, (request, body, done) => {
  request.rawBody = body as Buffer;
  try { done(null, JSON.parse(request.rawBody.toString("utf8"))); }
  catch (error) { done(error as Error, undefined); }
});

type ApplicationSnapshot = {
  id: string; repository_id: string; application_name: string; description: string | null; owner: string; repository_name: string; html_url: string | null;
  scan_id: string | null; scan_status: string | null; branch: string | null; vulnerability_status: string | null; vulnerability_error: string | null;
  completed_at: Date | null; root_bom_ref: string | null; dependency_graph_status: "complete" | "incomplete" | "unknown" | null;
  sbom_id: string | null; commit_sha: string | null; component_count: number | null; scanned_at: Date | null;
};

async function getApplicationSnapshot(applicationId: string, userId: string) {
  const result = await pool.query<ApplicationSnapshot>(
    `SELECT a.id, a.repository_id, a.name AS application_name, a.description, r.owner, r.name AS repository_name, r.html_url,
            s.id AS scan_id, s.status AS scan_status, s.branch, s.vulnerability_status, s.vulnerability_error, s.completed_at,
            sa.root_bom_ref, sa.dependency_graph_status, b.id AS sbom_id, b.commit_sha, b.component_count, b.scanned_at
     FROM applications a JOIN repositories r ON r.id = a.repository_id
     LEFT JOIN LATERAL (
       SELECT s.id, s.status, s.branch, s.vulnerability_status, s.vulnerability_error, s.completed_at, sa.root_bom_ref, sa.dependency_graph_status
       FROM scan_applications sa JOIN scans s ON s.id = sa.scan_id
       WHERE sa.application_id = a.id AND s.sbom_status = 'completed'
       ORDER BY s.created_at DESC LIMIT 1
     ) s ON true
     LEFT JOIN sboms b ON b.scan_id = s.id
     WHERE a.id = $1 AND r.user_id = $2`, [applicationId, userId],
  );
  return result.rows[0] ?? null;
}

async function loadApplicationImpact(applicationId: string, userId: string) {
  const snapshot = await getApplicationSnapshot(applicationId, userId);
  if (!snapshot) return null;
  if (!snapshot.sbom_id || !snapshot.scan_id) return { snapshot, analysis: null };
  const [componentRows, edgeRows, findingRows] = await Promise.all([
    pool.query<ImpactNode>(
      `SELECT c.bom_ref AS "bomRef", c.package_id AS "packageId", c.component_type AS "componentType", p.name, p.version, p.purl
       FROM sbom_components c LEFT JOIN packages p ON p.id = c.package_id WHERE c.sbom_id = $1`, [snapshot.sbom_id],
    ),
    pool.query<{ source_ref: string; target_ref: string }>("SELECT source_ref, target_ref FROM dependency_edges WHERE sbom_id = $1", [snapshot.sbom_id]),
    pool.query<ImpactFinding>(
      `SELECT f.id, f.bom_ref AS "bomRef", v.id AS "vulnerabilityId", v.payload->>'summary' AS summary,
              v.payload->'severity'->0->>'score' AS severity, p.name AS package, p.version
       FROM findings f JOIN vulnerabilities v ON v.id = f.vulnerability_id JOIN packages p ON p.id = f.package_id
       WHERE f.scan_id = $1`, [snapshot.scan_id],
    ),
  ]);
  const analysis = analyzeDependencyGraph({
    rootRef: snapshot.root_bom_ref,
    graphStatus: snapshot.dependency_graph_status ?? "unknown",
    nodes: componentRows.rows,
    edges: edgeRows.rows.map((edge) => ({ sourceRef: edge.source_ref, targetRef: edge.target_ref })),
    findings: findingRows.rows,
  });
  return { snapshot, analysis };
}

await app.register(cors, { origin: env.WEB_URL, credentials: true });
await app.register(cookie);
await app.register(rateLimit, { max: 100, timeWindow: "1 minute" });
app.addHook("onSend", async (_request, reply, payload) => {
  reply.header("X-Content-Type-Options", "nosniff");
  reply.header("X-Frame-Options", "DENY");
  reply.header("Referrer-Policy", "no-referrer");
  reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return payload;
});
app.addHook("onSend", async (request, reply, payload) => {
  if (request.url.startsWith("/api/okf/") || request.url.startsWith("/api/decisions") || request.url.startsWith("/api/remediations") || request.url.startsWith("/api/alerts") || request.url.includes("/context")) reply.header("cache-control", "private, no-store");
  return payload;
});

app.get("/health", async (_request, reply) => {
  const [db, cache] = await Promise.allSettled([pool.query("SELECT 1"), redis.ping()]);
  const dependencies = { postgres: db.status === "fulfilled" ? "ok" as const : "error" as const, redis: cache.status === "fulfilled" ? "ok" as const : "error" as const };
  const status = dependencies.postgres === "ok" && dependencies.redis === "ok" ? "ok" : "degraded";
  return reply.code(status === "ok" ? 200 : 503).send({ data: { status, dependencies }, error: null });
});

app.post("/api/github/webhook", async (request, reply) => {
  if (!env.GITHUB_WEBHOOK_SECRET || !request.rawBody) return reply.code(503).send({ data: null, error: { code: "WEBHOOK_NOT_CONFIGURED", message: "GitHub webhook secret is not configured" } });
  const signature = request.headers["x-hub-signature-256"];
  const deliveryId = request.headers["x-github-delivery"];
  const eventName = request.headers["x-github-event"];
  if (typeof signature !== "string" || !/^sha256=[a-f0-9]{64}$/i.test(signature) || typeof deliveryId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(deliveryId) || typeof eventName !== "string" || !/^[a-z_]{1,100}$/.test(eventName)) {
    return reply.code(400).send({ data: null, error: { code: "INVALID_WEBHOOK_HEADERS", message: "GitHub webhook headers are incomplete or invalid" } });
  }
  const expected = createHmac("sha256", env.GITHUB_WEBHOOK_SECRET).update(request.rawBody).digest();
  const received = Buffer.from(signature.slice(7), "hex");
  if (received.length !== expected.length || !timingSafeEqual(expected, received)) return reply.code(401).send({ data: null, error: { code: "INVALID_WEBHOOK_SIGNATURE", message: "GitHub webhook signature did not validate" } });
  try {
    const result = await processGithubWebhook(scanQueue, deliveryId, eventName, request.body);
    return reply.code(202).send({ data: result, error: null });
  } catch (error) {
    request.log.error({ err: error, deliveryId, eventName }, "GitHub webhook processing failed");
    return reply.code(503).send({ data: null, error: { code: "WEBHOOK_PROCESSING_FAILED", message: "Webhook event could not be queued; GitHub may retry the delivery" } });
  }
});

app.get("/api/auth/github", async (_request, reply) => {
  try { return reply.redirect(await startGithubOAuth(reply)); }
  catch (error) { return reply.code(503).send({ data: null, error: { code: "AUTH_NOT_CONFIGURED", message: error instanceof Error ? error.message : "GitHub login is unavailable" } }); }
});

app.get("/api/auth/github/callback", async (request, reply) => {
  const query = z.object({ code: z.string().min(1), state: z.string().min(1), error: z.string().optional() }).safeParse(request.query);
  const stateCookie = request.cookies.github_oauth_state;
  const verifierCookie = request.cookies.github_oauth_verifier;
  reply.clearCookie("github_oauth_state", { path: "/" });
  reply.clearCookie("github_oauth_verifier", { path: "/" });
  if (!query.success || query.data.error) return reply.redirect(`${env.WEB_URL}/?auth=failed`);
  try {
    const result = await finishGithubOAuth({ code: query.data.code, state: query.data.state, cookieState: stateCookie, codeVerifier: verifierCookie });
    reply.setCookie("ds_session", result.jwt, { ...cookieOptions, maxAge: 60 * 60 * 24 * 7 });
    return reply.redirect(`${env.WEB_URL}/?auth=success`);
  } catch (error) {
    request.log.warn({ err: error }, "GitHub OAuth callback failed");
    return reply.redirect(`${env.WEB_URL}/?auth=failed`);
  }
});

app.get("/api/auth/session", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const user = await pool.query("SELECT id, github_login AS \"githubLogin\", name, avatar_url AS \"avatarUrl\" FROM users WHERE id = $1", [session.id]);
  if (!user.rowCount) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Session user no longer exists" } });
  return reply.send({ data: user.rows[0], error: null });
});

app.post("/api/auth/logout", async (_request, reply) => reply.clearCookie("ds_session", { path: "/" }).send({ data: { signedOut: true }, error: null }));

app.get("/api/github/app-install", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in before installing the GitHub App" } });
  if (!env.GITHUB_APP_SLUG) return reply.code(503).send({ data: null, error: { code: "GITHUB_APP_NOT_CONFIGURED", message: "Set GITHUB_APP_SLUG to enable repository access" } });
  const state = randomBytes(32).toString("hex");
  reply.setCookie("github_install_state", state, { ...cookieOptions, maxAge: 600 });
  const installUrl = new URL(`https://github.com/apps/${encodeURIComponent(env.GITHUB_APP_SLUG)}/installations/new`);
  installUrl.searchParams.set("state", state);
  return reply.redirect(installUrl.toString());
});

app.get("/api/github/app-install/callback", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  const parsed = z.object({ installation_id: z.coerce.number().int().positive(), state: z.string().min(1), setup_action: z.enum(["install", "update", "request"]).optional() }).safeParse(request.query);
  const cookieState = request.cookies.github_install_state;
  reply.clearCookie("github_install_state", { path: "/" });
  if (!session || !parsed.success || !cookieState || parsed.data.state.length !== cookieState.length || !timingSafeEqual(Buffer.from(parsed.data.state), Buffer.from(cookieState))) {
    return reply.redirect(`${env.WEB_URL}/?github=install_failed`);
  }
  if (parsed.data.setup_action === "request") return reply.redirect(`${env.WEB_URL}/?github=approval_pending`);
  try {
    await verifyInstallationForUser(session.id, parsed.data.installation_id);
    const installation = await getInstallationAccount(parsed.data.installation_id);
    await pool.query(
      `INSERT INTO github_installations (id, user_id, account_login, account_type) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, id) DO UPDATE SET account_login = EXCLUDED.account_login, account_type = EXCLUDED.account_type, updated_at = now()`,
      [installation.id, session.id, installation.account.login, installation.account.type],
    );
    return reply.redirect(`${env.WEB_URL}/?github=connected`);
  } catch (error) {
    request.log.warn({ err: error }, "GitHub App installation could not be verified");
    return reply.redirect(`${env.WEB_URL}/?github=install_failed`);
  }
});

app.get("/api/github/repositories/available", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const installations = await pool.query<{ id: string; account_login: string; account_type: string }>("SELECT id, account_login, account_type FROM github_installations WHERE user_id = $1 ORDER BY account_login", [session.id]);
  try {
    const data = [];
    for (const installation of installations.rows) {
      const repositories = await listInstallationRepositories(Number(installation.id));
      data.push(...repositories.map((repo) => ({ id: repo.id, installationId: Number(installation.id), fullName: repo.full_name, owner: repo.owner.login, ownerType: repo.owner.type, name: repo.name, defaultBranch: repo.default_branch, private: repo.private, archived: repo.archived, htmlUrl: repo.html_url })));
    }
    return reply.send({ data, error: null });
  } catch (error) {
    request.log.warn({ err: error }, "Could not list authorized GitHub repositories");
    return reply.code(502).send({ data: null, error: { code: "GITHUB_UNAVAILABLE", message: "Could not load repositories from GitHub" } });
  }
});

app.get("/api/github/repositories/:repoId/branches", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ repoId: z.coerce.number().int().positive() }).safeParse(request.params);
  const query = z.object({ installationId: z.coerce.number().int().positive() }).safeParse(request.query);
  if (!params.success || !query.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Repository and installation ids must be positive integers" } });
  const owned = await pool.query("SELECT id FROM github_installations WHERE id = $1 AND user_id = $2", [query.data.installationId, session.id]);
  if (!owned.rowCount) return reply.code(404).send({ data: null, error: { code: "INSTALLATION_NOT_FOUND", message: "GitHub App installation not found" } });
  try {
    const repositories = await listInstallationRepositories(query.data.installationId);
    const repository = repositories.find((item) => item.id === params.data.repoId);
    if (!repository) return reply.code(404).send({ data: null, error: { code: "REPOSITORY_NOT_AUTHORIZED", message: "Repository is not available to this installation" } });
    return reply.send({ data: await listRepositoryBranches(query.data.installationId, repository), error: null });
  } catch (error) {
    request.log.warn({ err: error }, "Could not list repository branches");
    return reply.code(502).send({ data: null, error: { code: "GITHUB_UNAVAILABLE", message: "Could not load repository branches" } });
  }
});

app.post("/api/repositories/connect", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const body = z.object({ installationId: z.number().int().positive(), githubRepoId: z.number().int().positive(), branch: z.string().min(1).max(255).optional() }).safeParse(request.body);
  if (!body.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "installationId and githubRepoId must be positive integers" } });
  const installation = await pool.query("SELECT id FROM github_installations WHERE id = $1 AND user_id = $2", [body.data.installationId, session.id]);
  if (!installation.rowCount) return reply.code(404).send({ data: null, error: { code: "INSTALLATION_NOT_FOUND", message: "GitHub App installation not found" } });
  try {
    const repositories = await listInstallationRepositories(body.data.installationId);
    const repo = repositories.find((item) => item.id === body.data.githubRepoId);
    if (!repo) return reply.code(404).send({ data: null, error: { code: "REPOSITORY_NOT_AUTHORIZED", message: "Repository is not available to this GitHub App installation" } });
    const selectedBranch = body.data.branch ?? repo.default_branch;
    if (!selectedBranch) return reply.code(400).send({ data: null, error: { code: "BRANCH_REQUIRED", message: "This repository has no branch to scan" } });
    await verifyRepositoryBranch(body.data.installationId, repo, selectedBranch);
    const result = await pool.query(
      `INSERT INTO repositories (user_id, installation_id, github_repo_id, owner, name, default_branch, scan_branch, private, archived, html_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (user_id, github_repo_id) DO UPDATE SET installation_id = EXCLUDED.installation_id, default_branch = EXCLUDED.default_branch, scan_branch = EXCLUDED.scan_branch, private = EXCLUDED.private, archived = EXCLUDED.archived, html_url = EXCLUDED.html_url, updated_at = now()
       RETURNING id, owner, name, scan_branch AS branch, private, archived, html_url AS url`,
      [session.id, body.data.installationId, repo.id, repo.owner.login, repo.name, repo.default_branch, selectedBranch, repo.private, repo.archived, repo.html_url],
    );
    return reply.code(201).send({ data: result.rows[0], error: null });
  } catch (error) {
    request.log.warn({ err: error }, "Could not connect authorized GitHub repository");
    return reply.code(502).send({ data: null, error: { code: "GITHUB_UNAVAILABLE", message: "Could not verify repository access with GitHub" } });
  }
});

app.get("/api/repositories", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const result = await pool.query(
    `SELECT r.id, r.owner, r.name, r.scan_branch AS branch, r.private, r.archived, r.monitoring_enabled, r.html_url AS url,
            a.id AS application_id, a.name AS application_name,
            s.id AS latest_scan_id, s.status AS latest_scan_status, s.created_at AS last_scanned_at,
            s.sbom_status, s.vulnerability_status, COALESCE(b.component_count, 0)::int AS dependency_count, COALESCE(f.finding_count, 0)::int AS finding_count
     FROM repositories r
     LEFT JOIN applications a ON a.repository_id = r.id
     LEFT JOIN LATERAL (SELECT id, status, created_at, sbom_status, vulnerability_status FROM scans WHERE repository_id = r.id ORDER BY created_at DESC LIMIT 1) s ON true
     LEFT JOIN LATERAL (SELECT id FROM scans WHERE repository_id = r.id AND sbom_status = 'completed' ORDER BY created_at DESC LIMIT 1) inventory_scan ON true
     LEFT JOIN LATERAL (SELECT component_count FROM sboms WHERE scan_id = inventory_scan.id LIMIT 1) b ON true
     LEFT JOIN LATERAL (SELECT id FROM scans WHERE repository_id = r.id AND vulnerability_status IN ('completed', 'partial') ORDER BY created_at DESC LIMIT 1) findings_scan ON true
     LEFT JOIN LATERAL (SELECT count(*) AS finding_count FROM findings WHERE scan_id = findings_scan.id) f ON true
     WHERE r.user_id = $1 ORDER BY r.owner, r.name`, [session.id],
  );
  return reply.send({ data: result.rows, error: null });
});

app.patch("/api/repositories/:id/monitoring", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  const body = z.object({ enabled: z.boolean() }).safeParse(request.body);
  if (!params.success || !body.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Provide a repository id and monitoring enabled flag" } });
  const result = await pool.query("UPDATE repositories SET monitoring_enabled=$3, updated_at=now() WHERE id=$1 AND user_id=$2 RETURNING id, monitoring_enabled", [params.data.id, session.id, body.data.enabled]);
  if (!result.rowCount) return reply.code(404).send({ data: null, error: { code: "REPOSITORY_NOT_FOUND", message: "Repository not found" } });
  return reply.send({ data: result.rows[0], error: null });
});

app.get("/api/applications", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const result = await pool.query(
    `SELECT a.id, a.name, a.description, r.id AS repository_id, r.owner, r.name AS repository_name, r.html_url,
            s.id AS scan_id, s.status AS scan_status, s.branch, s.vulnerability_status, s.vulnerability_error,
            sa.dependency_graph_status, COALESCE(d.package_count, 0)::int AS dependency_count,
            COALESCE(f.finding_count, 0)::int AS finding_count
     FROM applications a JOIN repositories r ON r.id = a.repository_id
     LEFT JOIN LATERAL (
       SELECT s.id, s.status, s.branch, s.vulnerability_status, s.vulnerability_error, sa.dependency_graph_status
       FROM scan_applications sa JOIN scans s ON s.id = sa.scan_id
       WHERE sa.application_id = a.id AND s.sbom_status = 'completed'
       ORDER BY s.created_at DESC LIMIT 1
     ) s ON true
     LEFT JOIN LATERAL (SELECT id FROM sboms WHERE scan_id = s.id LIMIT 1) b ON true
     LEFT JOIN LATERAL (SELECT count(*) AS package_count FROM sbom_components WHERE sbom_id = b.id AND package_id IS NOT NULL) d ON true
     LEFT JOIN LATERAL (SELECT count(*) AS finding_count FROM findings WHERE scan_id = s.id) f ON true
     WHERE r.user_id = $1 ORDER BY a.name`, [session.id],
  );
  return reply.send({ data: result.rows, error: null });
});

app.get("/api/applications/:id", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Application id must be a UUID" } });
  const snapshot = await getApplicationSnapshot(params.data.id, session.id);
  if (!snapshot) return reply.code(404).send({ data: null, error: { code: "APPLICATION_NOT_FOUND", message: "Application not found" } });
  return reply.send({ data: { application: snapshot, error: snapshot.scan_id ? null : "No completed SBOM is available yet" }, error: null });
});

app.get("/api/applications/:id/impact", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Application id must be a UUID" } });
  const result = await loadApplicationImpact(params.data.id, session.id);
  if (!result) return reply.code(404).send({ data: null, error: { code: "APPLICATION_NOT_FOUND", message: "Application not found" } });
  return reply.send({ data: { application: result.snapshot, impact: result.analysis }, error: null });
});

app.get("/api/applications/:id/context", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Application id must be a UUID" } });
  const context = await getApplicationOkfContext(session.id, params.data.id);
  if (!context) return reply.code(404).send({ data: null, error: { code: "APPLICATION_NOT_FOUND", message: "Application not found" } });
  return reply.send({ data: context, error: null });
});

app.get("/api/applications/:id/graph", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Application id must be a UUID" } });
  const result = await loadApplicationImpact(params.data.id, session.id);
  if (!result) return reply.code(404).send({ data: null, error: { code: "APPLICATION_NOT_FOUND", message: "Application not found" } });
  return reply.send({ data: { application: result.snapshot, graph: result.analysis }, error: null });
});

app.post("/api/scans", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const body = z.object({ repositoryId: z.string().uuid() }).safeParse(request.body);
  if (!body.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "repositoryId must be a UUID" } });
  const repository = await pool.query<{ id: string; branch: string; archived: boolean }>("SELECT id, scan_branch AS branch, archived FROM repositories WHERE id = $1 AND user_id = $2", [body.data.repositoryId, session.id]);
  if (!repository.rowCount) return reply.code(404).send({ data: null, error: { code: "REPOSITORY_NOT_FOUND", message: "Repository not found" } });
  if (repository.rows[0]!.archived) return reply.code(409).send({ data: null, error: { code: "REPOSITORY_ARCHIVED", message: "Archived repositories cannot be scanned" } });
  try {
    const scan = await enqueueRepositoryScan(scanQueue, { repositoryId: repository.rows[0]!.id, userId: session.id, branch: repository.rows[0]!.branch, source: "manual" });
    return reply.code(202).send({ data: { scanId: scan.scanId, jobId: scan.scanId, status: scan.status, created: scan.created }, error: null });
  } catch (error) {
    request.log.error({ err: error }, "Could not add scan to Redis queue");
    return reply.code(503).send({ data: null, error: { code: "QUEUE_UNAVAILABLE", message: "Scanning is temporarily unavailable" } });
  }
});

app.get("/api/scans", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const result = await pool.query(
    `SELECT s.id, s.repository_id, r.owner, r.name, s.status, s.sbom_status, s.vulnerability_status, s.vulnerability_error, s.created_at, s.completed_at
     FROM scans s JOIN repositories r ON r.id = s.repository_id WHERE r.user_id = $1 ORDER BY s.created_at DESC LIMIT 100`, [session.id],
  );
  return reply.send({ data: result.rows, error: null });
});

app.get("/api/scans/:id", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Scan id must be a UUID" } });
  const result = await pool.query(
    `SELECT s.*, r.owner, r.name, ca.status AS code_analysis_status, ca.engine_version AS semgrep_version, ca.error_message AS code_analysis_error,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('ruleId', f.rule_id, 'severity', f.severity, 'message', f.message, 'file', f.file_path, 'line', f.start_line, 'snippet', f.code_snippet) ORDER BY f.severity, f.file_path, f.start_line)
                      FROM code_analysis_findings f WHERE f.scan_id = s.id), '[]'::jsonb) AS code_analysis_findings
     FROM scans s JOIN repositories r ON r.id = s.repository_id LEFT JOIN code_analysis_runs ca ON ca.scan_id = s.id
     WHERE s.id = $1 AND r.user_id = $2`, [params.data.id, session.id],
  );
  if (!result.rowCount) return reply.code(404).send({ data: null, error: { code: "SCAN_NOT_FOUND", message: "Scan not found" } });
  return reply.send({ data: result.rows[0], error: null });
});

app.get("/api/findings/:id/reachability", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Finding id must be a UUID" } });
  const result = await pool.query(
    `SELECT fr.status, fr.evidence, fr.analyzed_commit_sha, fr.updated_at
     FROM finding_reachability fr JOIN findings f ON f.id = fr.finding_id JOIN scans s ON s.id = f.scan_id JOIN repositories r ON r.id = s.repository_id
     WHERE fr.finding_id = $1 AND r.user_id = $2`, [params.data.id, session.id],
  );
  return reply.send({ data: result.rows[0] ?? null, error: null });
});

app.get("/api/remediations", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const query = z.object({ findingId: z.string().uuid().optional() }).safeParse(request.query);
  if (!query.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Invalid remediation filter" } });
  return reply.send({ data: await listRemediationActions(session.id, query.data.findingId), error: null });
});

app.get("/api/remediations/:id/checks", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Invalid remediation action id" } });
  try {
    const checks = await getDraftPullRequestChecks(session.id, params.data.id);
    if (!checks) return reply.code(404).send({ data: null, error: { code: "REMEDIATION_NOT_FOUND", message: "Remediation action not found" } });
    return reply.send({ data: checks, error: null });
  } catch (error) {
    request.log.warn({ err: error }, "Could not load GitHub CI status");
    return reply.code(422).send({ data: null, error: { code: "CI_STATUS_UNAVAILABLE", message: error instanceof Error ? error.message : "Could not load GitHub checks" } });
  }
});

app.post("/api/findings/:id/remediation/issue", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Finding id must be a UUID" } });
  try {
    const action = await createRemediationIssue(session.id, params.data.id);
    if (!action) return reply.code(404).send({ data: null, error: { code: "FINDING_NOT_FOUND", message: "Finding not found" } });
    return reply.code(201).send({ data: action, error: null });
  } catch (error) {
    request.log.warn({ err: error }, "GitHub issue remediation failed");
    return reply.code(422).send({ data: null, error: { code: "REMEDIATION_UNAVAILABLE", message: error instanceof Error ? error.message : "Could not create the GitHub issue" } });
  }
});

app.post("/api/findings/:id/remediation/draft-pr", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  const body = z.object({ humanApproval: z.literal(true) }).safeParse(request.body);
  if (!params.success || !body.success) return reply.code(400).send({ data: null, error: { code: "HUMAN_APPROVAL_REQUIRED", message: "Review and explicitly approve creation of a draft pull request" } });
  try {
    const action = await createDraftRemediationPr(session.id, params.data.id);
    if (!action) return reply.code(404).send({ data: null, error: { code: "FINDING_NOT_FOUND", message: "Finding not found" } });
    return reply.code(201).send({ data: action, error: null });
  } catch (error) {
    request.log.warn({ err: error }, "Draft pull request remediation failed");
    return reply.code(422).send({ data: null, error: { code: "REMEDIATION_UNAVAILABLE", message: error instanceof Error ? error.message : "Could not create the draft pull request" } });
  }
});

app.get("/api/findings", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const result = await pool.query(
    `SELECT f.id, f.scan_id, f.bom_ref, a.id AS application_id, a.name AS application, r.owner, r.name AS repository, p.name AS package, p.version, p.purl,
            v.id AS vulnerability_id, v.payload, f.created_at, f.local_range_status, f.local_range_source, f.local_range_evidence,
            COALESCE((SELECT jsonb_agg(jsonb_build_object('source',vs.source,'external_id',vs.external_id,'payload',vs.payload) ORDER BY vs.source)
                      FROM vulnerability_source_records vs WHERE vs.canonical_vulnerability_id=v.id),'[]'::jsonb) AS source_records,
            fr.status AS reachability_status, fr.evidence AS reachability_evidence,
            ca.status AS code_analysis_status
     FROM findings f JOIN scans s ON s.id = f.scan_id JOIN repositories r ON r.id = s.repository_id
     JOIN applications a ON a.repository_id = r.id
     JOIN packages p ON p.id = f.package_id JOIN vulnerabilities v ON v.id = f.vulnerability_id
     LEFT JOIN finding_reachability fr ON fr.finding_id = f.id LEFT JOIN code_analysis_runs ca ON ca.scan_id = f.scan_id
     JOIN LATERAL (SELECT id FROM scans latest WHERE latest.repository_id = r.id AND latest.vulnerability_status IN ('completed', 'partial') ORDER BY latest.created_at DESC LIMIT 1) latest_scan ON latest_scan.id = s.id
     WHERE r.user_id = $1 ORDER BY f.created_at DESC LIMIT 500`, [session.id],
  );
  return reply.send({ data: result.rows, error: null });
});

app.get("/api/alerts", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const result = await pool.query(
    `SELECT a.id, a.repository_id, a.scan_id, a.finding_id, a.category, a.read_at, a.created_at,
            v.id AS vulnerability_id, v.payload->>'summary' AS summary, p.name AS package_name, p.version AS package_version,
            r.owner, r.name AS repository_name, s.trigger_source
     FROM monitoring_alerts a JOIN repositories r ON r.id=a.repository_id JOIN scans s ON s.id=a.scan_id
     JOIN findings f ON f.id=a.finding_id JOIN vulnerabilities v ON v.id=a.vulnerability_id JOIN packages p ON p.id=a.package_id
     WHERE a.user_id=$1 ORDER BY a.created_at DESC LIMIT 200`, [session.id],
  );
  return reply.send({ data: result.rows, error: null });
});

app.post("/api/alerts/:id/read", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Alert id must be a UUID" } });
  const result = await pool.query("UPDATE monitoring_alerts SET read_at=COALESCE(read_at,now()) WHERE id=$1 AND user_id=$2 RETURNING id,read_at", [params.data.id, session.id]);
  if (!result.rowCount) return reply.code(404).send({ data: null, error: { code: "ALERT_NOT_FOUND", message: "Alert not found" } });
  return reply.send({ data: result.rows[0], error: null });
});

app.get("/api/okf/bundles", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const bundle = await getOkfBundle(session.id);
  return reply.send({ data: bundle ? [bundle] : [], error: null });
});

app.get("/api/okf/bundles/export", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const query = z.object({ revision: z.coerce.number().int().positive().optional() }).safeParse(request.query);
  if (!query.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Revision must be a positive integer" } });
  const bundle = await exportOkfBundle(session.id, query.data.revision);
  if (!bundle) return reply.code(404).send({ data: null, error: { code: "REVISION_NOT_FOUND", message: "OKF bundle revision not found" } });
  return reply.send({ data: bundle, error: null });
});

app.get("/api/okf/bundles/:id/revisions", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Bundle id must be a UUID" } });
  const revisions = await listOkfRevisions(session.id, params.data.id);
  if (!revisions.length) return reply.code(404).send({ data: null, error: { code: "BUNDLE_NOT_FOUND", message: "OKF bundle not found" } });
  return reply.send({ data: revisions, error: null });
});

app.get("/api/okf/concepts", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const query = z.object({ q: z.string().max(200).optional(), type: z.string().max(100).optional(), tag: z.string().max(100).optional() }).safeParse(request.query);
  if (!query.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Invalid OKF concept filters" } });
  return reply.send({ data: await listOkfConcepts(session.id, { query: query.data.q, type: query.data.type, tag: query.data.tag }), error: null });
});

app.get("/api/okf/concepts/:id", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Concept id must be a UUID" } });
  const concept = await getOkfConcept(session.id, params.data.id);
  if (!concept) return reply.code(404).send({ data: null, error: { code: "CONCEPT_NOT_FOUND", message: "OKF concept not found" } });
  return reply.send({ data: concept, error: null });
});

app.post("/api/okf/validate", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const body = z.object({ documents: z.record(z.string(), z.string()).refine((docs) => Object.keys(docs).length <= 1000, "Bundle may contain at most 1000 documents") }).safeParse(request.body);
  if (!body.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "documents must map bundle-relative Markdown paths to document contents" } });
  const validation = validateOkfBundle(Object.entries(body.data.documents).map(([path, markdown]) => ({ path, markdown })));
  return reply.code(validation.ok ? 200 : 422).send({ data: { ok: validation.ok, formatVersion: validation.formatVersion, documentCount: validation.documentCount, conceptCount: validation.conceptCount, relationshipCount: validation.relationshipCount, issues: validation.issues }, error: null });
});

app.post("/api/okf/concepts", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const body = z.object({ path: z.string().min(1).max(300), markdown: z.string().min(1).max(200_000) }).safeParse(request.body);
  if (!body.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Provide a bundle-relative .md path and Markdown concept document" } });
  try {
    const saved = await saveUserOkfConcept(session.id, body.data.path, body.data.markdown);
    return reply.code(201).send({ data: saved, error: null });
  } catch (error) {
    return reply.code(422).send({ data: null, error: { code: "INVALID_OKF_CONCEPT", message: error instanceof Error ? error.message : "Could not save OKF concept" } });
  }
});

app.get("/api/decisions", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const query = z.object({ applicationId: z.string().uuid().optional(), findingId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(200).default(100) }).safeParse(request.query);
  if (!query.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Invalid decision history filters" } });
  return reply.send({ data: await listDecisions(session.id, query.data), error: null });
});

app.get("/api/decisions/:id", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Decision id must be a UUID" } });
  const decision = await getDecision(session.id, params.data.id);
  if (!decision) return reply.code(404).send({ data: null, error: { code: "DECISION_NOT_FOUND", message: "Decision not found" } });
  return reply.send({ data: decision, error: null });
});

app.post("/api/findings/:id/decisions", async (request, reply) => {
  const session = await readSession(request.cookies.ds_session);
  if (!session) return reply.code(401).send({ data: null, error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
  const params = z.object({ id: z.string().uuid() }).safeParse(request.params);
  if (!params.success) return reply.code(400).send({ data: null, error: { code: "INVALID_REQUEST", message: "Finding id must be a UUID" } });
  const decision = await createFindingDecision(session.id, params.data.id);
  if (!decision) return reply.code(404).send({ data: null, error: { code: "FINDING_NOT_FOUND", message: "Finding not found" } });
  return reply.code(201).send({ data: decision, error: null });
});

app.setErrorHandler((error, request, reply) => {
  request.log.error({ err: error }, "Request failed");
  return reply.code(500).send({ data: null, error: { code: "INTERNAL_ERROR", message: "An unexpected error occurred" } });
});

await app.listen({ port: env.PORT, host: "0.0.0.0" });
app.log.info("DependencyShield API ready");
