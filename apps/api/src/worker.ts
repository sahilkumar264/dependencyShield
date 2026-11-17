import { Redis } from "ioredis";
import { Queue, Worker } from "bullmq";
import { env } from "./config/env.js";
import { pool } from "./db/pool.js";
import { runRepositoryScan } from "./services/scan-runner.js";
import { enqueueScheduledScans, reconcileFailedWebhookDeliveries } from "./services/monitoring.js";
import { syncCisaKev } from "./services/advisory-intelligence.js";

const connection = new Redis(env.REDIS_URL, { maxRetriesPerRequest: null, enableReadyCheck: true });
const scanQueue = new Queue("repository_scan", { connection });
if (env.ENABLE_SCHEDULED_SCANS) {
  await scanQueue.upsertJobScheduler("dependencyshield-daily-monitoring", { pattern: env.MONITORING_CRON, tz: "UTC" }, {
    name: "scheduled_monitoring", data: {}, opts: { attempts: 3, backoff: { type: "exponential", delay: 30_000 }, removeOnComplete: 100, removeOnFail: 100 },
  });
  console.info(`Daily repository monitoring enabled with cron '${env.MONITORING_CRON}' UTC`);
} else {
  await scanQueue.removeJobScheduler("dependencyshield-daily-monitoring");
  console.info("Scheduled repository monitoring is disabled");
}
await scanQueue.upsertJobScheduler("dependencyshield-webhook-reconciliation", { pattern: "0 */15 * * * *", tz: "UTC" }, {
  name: "webhook_reconciliation", data: {}, opts: { attempts: 2, backoff: { type: "exponential", delay: 30_000 }, removeOnComplete: 100, removeOnFail: 100 },
});

const worker = new Worker("repository_scan", async (job) => {
  if (job.name === "scheduled_monitoring") {
    if (!env.ENABLE_SCHEDULED_SCANS) return { disabled: true };
    try { console.info(`CISA KEV refreshed with ${await syncCisaKev()} entries`); }
    catch (error) { console.warn(`CISA KEV refresh unavailable: ${error instanceof Error ? error.message : "feed request failed"}`); }
    const result = await enqueueScheduledScans(scanQueue);
    console.info(`Scheduled monitoring: ${result.queued} queued, ${result.skipped} already active, ${result.failed} failed`);
    return result;
  }
  if (job.name === "webhook_reconciliation") {
    if (!env.GITHUB_APP_ID || !env.GITHUB_APP_PRIVATE_KEY_B64) return { skipped: "GitHub App is not configured" };
    const result = await reconcileFailedWebhookDeliveries();
    if (result.attempted) console.info(`Webhook reconciliation: ${result.redelivered} redeliveries accepted, ${result.unmatched} not found`);
    return result;
  }
  const scanId = String(job.data.scanId ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(scanId)) throw new Error("Invalid scan job payload");
  await runRepositoryScan(scanId);
}, { connection, concurrency: 2, lockDuration: 6 * 60_000 });

worker.on("ready", () => console.info("DependencyShield scanner worker is ready"));
worker.on("failed", async (job, error) => {
  console.error(`Scan job ${job?.id ?? "unknown"} failed: ${error.message}`);
  if (job && job.attemptsMade >= Number(job.opts.attempts ?? 1)) {
    await pool.query("UPDATE scans SET status = 'failed', completed_at = now() WHERE id = $1 AND status = 'queued'", [job.data.scanId]);
  }
});
worker.on("error", (error) => console.error(`Scanner worker error: ${error.message}`));

const shutdown = async () => {
  await worker.close();
  await scanQueue.close();
  await connection.quit();
  await pool.end();
  process.exit(0);
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
