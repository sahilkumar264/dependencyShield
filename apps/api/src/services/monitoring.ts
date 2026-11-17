import type { Queue } from "bullmq";
import { pool } from "../db/pool.js";
import { redeliverFailedAppWebhookGuids } from "./github-app.js";

type ScanRequest = { repositoryId: string; userId: string; branch: string; source: "manual" | "scheduled" | "webhook"; commitSha?: string; deliveryId?: string };
type QueuedScan = { scanId: string; created: boolean; status: string };
const shaPattern = /^[a-f0-9]{40,64}$/i;

export async function enqueueRepositoryScan(queue: Queue, request: ScanRequest): Promise<QueuedScan> {
  const db = await pool.connect();
  let scanId: string | null = null;
  let status = "queued";
  try {
    await db.query("BEGIN");
    await db.query("SELECT pg_advisory_xact_lock(hashtext($1))", [request.repositoryId]);
    const active = await db.query<{ id: string; status: string; requested_commit_sha: string | null }>(
      `SELECT id, status, requested_commit_sha FROM scans WHERE repository_id=$1 AND (status='queued' OR (status='processing' AND started_at > now() - interval '30 minutes')) ORDER BY created_at DESC LIMIT 1`, [request.repositoryId],
    );
    const shouldQueueNewCommit = request.source === "webhook" && active.rows[0] && active.rows[0].requested_commit_sha !== request.commitSha;
    if (active.rows[0] && !shouldQueueNewCommit) {
      scanId = active.rows[0].id;
      status = active.rows[0].status;
      await db.query("COMMIT");
      return { scanId, created: false, status };
    }
    const inserted = await db.query<{ id: string }>(
      `INSERT INTO scans (repository_id, status, requested_by, branch, trigger_source, requested_commit_sha, trigger_delivery_id)
       VALUES ($1,'queued',$2,$3,$4,$5,$6) RETURNING id`,
      [request.repositoryId, request.userId, request.branch, request.source, request.commitSha ?? null, request.deliveryId ?? null],
    );
    scanId = inserted.rows[0]!.id;
    await db.query("COMMIT");
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  } finally { db.release(); }

  try {
    await queue.add("repository_scan", { scanId }, { jobId: scanId, attempts: 3, backoff: { type: "exponential", delay: 5000 }, removeOnComplete: 1000, removeOnFail: 5000 });
    return { scanId, created: true, status };
  } catch (error) {
    await pool.query("UPDATE scans SET status='failed', error_message='Could not queue scan', completed_at=now() WHERE id=$1", [scanId]);
    throw error;
  }
}

export async function enqueueScheduledScans(queue: Queue) {
  const staleJobs = await pool.query<{ id: string }>("SELECT id FROM scans WHERE status='queued' AND created_at < now() - interval '2 minutes' ORDER BY created_at LIMIT 500");
  for (const scan of staleJobs.rows) {
    try { await queue.add("repository_scan", { scanId: scan.id }, { jobId: scan.id, attempts: 3, backoff: { type: "exponential", delay: 5000 }, removeOnComplete: 1000, removeOnFail: 5000 }); }
    catch (error) { console.warn(`Could not restore queued scan ${scan.id}: ${error instanceof Error ? error.message : "unknown error"}`); }
  }
  const repositories = await pool.query<{ id: string; user_id: string; scan_branch: string }>(
    `SELECT r.id, r.user_id, r.scan_branch FROM repositories r
     JOIN github_installations i ON i.id=r.installation_id AND i.user_id=r.user_id
     WHERE r.monitoring_enabled=true AND r.archived=false ORDER BY r.owner, r.name`,
  );
  let queued = 0; let skipped = 0; let failed = 0;
  for (const repository of repositories.rows) {
    try {
      const result = await enqueueRepositoryScan(queue, { repositoryId: repository.id, userId: repository.user_id, branch: repository.scan_branch, source: "scheduled" });
      if (result.created) queued += 1; else skipped += 1;
    } catch (error) {
      failed += 1;
      console.warn(`Scheduled scan enqueue failed for repository ${repository.id}: ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }
  return { total: repositories.rowCount ?? 0, queued, skipped, failed };
}

export async function reconcileFailedWebhookDeliveries() {
  const rows = await pool.query<{ delivery_id: string }>(
    `UPDATE github_webhook_deliveries SET redelivery_attempts=redelivery_attempts+1,last_redelivery_at=now()
     WHERE delivery_id IN (
       SELECT delivery_id FROM github_webhook_deliveries
       WHERE status='failed' AND redelivery_attempts < 3 AND received_at > now() - interval '7 days'
         AND (last_redelivery_at IS NULL OR last_redelivery_at < now() - interval '15 minutes')
       ORDER BY received_at LIMIT 50
       FOR UPDATE SKIP LOCKED
     ) RETURNING delivery_id`,
  );
  if (!rows.rowCount) return { attempted: 0, redelivered: 0, unmatched: 0 };
  const result = await redeliverFailedAppWebhookGuids(rows.rows.map((row) => row.delivery_id));
  if (result.unmatched.length) console.warn(`GitHub webhook reconciliation could not locate ${result.unmatched.length} recorded failed deliveries in recent app-delivery history`);
  return { attempted: rows.rowCount, redelivered: result.redelivered, unmatched: result.unmatched.length };
}

function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function positiveId(value: unknown) { return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null; }

export async function processGithubWebhook(queue: Queue, deliveryId: string, eventName: string, payload: unknown) {
  const claimed = await pool.query<{ delivery_id: string }>(
    `INSERT INTO github_webhook_deliveries (delivery_id,event_name,status) VALUES ($1,$2,'processing')
     ON CONFLICT (delivery_id) DO UPDATE SET status='processing', event_name=EXCLUDED.event_name, error_message=NULL, completed_at=NULL, received_at=now()
     WHERE github_webhook_deliveries.status='failed' OR (github_webhook_deliveries.status='processing' AND github_webhook_deliveries.received_at < now() - interval '10 minutes')
     RETURNING delivery_id`, [deliveryId, eventName],
  );
  if (!claimed.rowCount) return { duplicate: true, queued: false };
  let repositoryId: string | null = null;
  try {
    if (object(payload) && eventName === "push") {
      const repo = object(payload.repository) ? payload.repository : {};
      const installation = object(payload.installation) ? payload.installation : {};
      const githubRepoId = positiveId(repo.id); const installationId = positiveId(installation.id);
      const ref = typeof payload.ref === "string" ? payload.ref : "";
      const after = typeof payload.after === "string" ? payload.after : "";
      const deleted = payload.deleted === true;
      if (githubRepoId && installationId && !deleted && shaPattern.test(after) && ref.startsWith("refs/heads/")) {
        const branch = ref.slice("refs/heads/".length);
        const row = await pool.query<{ id: string; user_id: string; scan_branch: string }>(
          `SELECT id,user_id,scan_branch FROM repositories WHERE github_repo_id=$1 AND installation_id=$2 AND monitoring_enabled=true AND archived=false`, [githubRepoId, installationId],
        );
        const repository = row.rows[0];
        if (repository && branch === repository.scan_branch) {
          repositoryId = repository.id;
          await enqueueRepositoryScan(queue, { repositoryId: repository.id, userId: repository.user_id, branch, source: "webhook", commitSha: after, deliveryId });
        }
      }
    } else if (object(payload) && eventName === "repository") {
      const repo = object(payload.repository) ? payload.repository : {};
      const installation = object(payload.installation) ? payload.installation : {};
      const githubRepoId = positiveId(repo.id); const installationId = positiveId(installation.id);
      if (githubRepoId && installationId && typeof repo.archived === "boolean") {
        const changed = await pool.query<{ id: string }>("UPDATE repositories SET archived=$3, updated_at=now() WHERE github_repo_id=$1 AND installation_id=$2 RETURNING id", [githubRepoId, installationId, repo.archived]);
        repositoryId = changed.rows[0]?.id ?? null;
      }
    } else if (object(payload) && eventName === "installation") {
      const installation = object(payload.installation) ? payload.installation : {};
      const installationId = positiveId(installation.id);
      if (installationId && (payload.action === "deleted" || payload.action === "suspend")) {
        await pool.query("UPDATE repositories SET monitoring_enabled=false, updated_at=now() WHERE installation_id=$1", [installationId]);
      }
    } else if (object(payload) && eventName === "installation_repositories" && payload.action === "removed") {
      const installation = object(payload.installation) ? payload.installation : {};
      const installationId = positiveId(installation.id);
      const removed = Array.isArray(payload.repositories_removed) ? payload.repositories_removed : [];
      if (installationId) for (const item of removed) {
        const repoId = object(item) ? positiveId(item.id) : null;
        if (repoId) await pool.query("UPDATE repositories SET monitoring_enabled=false, updated_at=now() WHERE installation_id=$1 AND github_repo_id=$2", [installationId, repoId]);
      }
    }
    await pool.query("UPDATE github_webhook_deliveries SET status='completed', repository_id=$2, completed_at=now() WHERE delivery_id=$1", [deliveryId, repositoryId]);
    return { duplicate: false, queued: Boolean(repositoryId), repositoryId };
  } catch (error) {
    await pool.query("UPDATE github_webhook_deliveries SET status='failed', repository_id=$2, error_message=$3 WHERE delivery_id=$1", [deliveryId, repositoryId, error instanceof Error ? error.message.slice(0, 500) : "Webhook handling failed"]);
    throw error;
  }
}
