import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { pool } from "./pool.js";

try {
  await pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  for (const name of ["001_foundation.sql", "002_repository_scanning.sql", "003_dependency_impact.sql", "004_okf_knowledge.sql", "005_repository_updated_at.sql", "006_jev_decisions.sql", "007_jev_audit_evidence.sql", "008_advanced_analysis.sql", "009_remediation_actions.sql", "010_continuous_monitoring.sql", "011_advisory_intelligence.sql", "012_local_range_evidence.sql", "013_webhook_reconciliation.sql"]) {
    const migration = await readFile(fileURLToPath(new URL(`../../../../database/migrations/${name}`, import.meta.url)), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query("SELECT 1 FROM schema_migrations WHERE name = $1", [name]);
      if (existing.rowCount) {
        await client.query("COMMIT");
        console.info(`Skipped ${name} (already applied).`);
      } else {
        await client.query(migration);
        await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [name]);
        await client.query("COMMIT");
        console.info(`Applied ${name}.`);
      }
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }
  }
} finally {
  await pool.end();
}
