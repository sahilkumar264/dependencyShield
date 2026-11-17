import { config } from "dotenv";
import { fileURLToPath } from "node:url";
import { z } from "zod";

config({ path: fileURLToPath(new URL("../../../../.env", import.meta.url)), override: true });

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  TRUST_PROXY: z.string().default(""),
  WEB_URL: z.string().url().default("http://localhost:3000"),
  API_URL: z.string().url().default("http://localhost:4000"),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  GITHUB_CLIENT_ID: z.string().optional().default(""),
  GITHUB_CLIENT_SECRET: z.string().optional().default(""),
  GITHUB_APP_ID: z.string().optional().default(""),
  GITHUB_APP_SLUG: z.string().optional().default(""),
  GITHUB_APP_PRIVATE_KEY_B64: z.string().optional().default(""),
  SYFT_BINARY: z.string().default("syft"),
  SEMGREP_BINARY: z.string().default("semgrep"),
  PYTHON_BINARY: z.string().default("python3"),
  OSV_API_BASE_URL: z.string().url().default("https://api.osv.dev"),
  NVD_API_KEY: z.string().optional().default(""),
  ALERT_WEBHOOK_URL: z.union([z.literal(""), z.string().url().refine((value) => new URL(value).protocol === "https:", "must use HTTPS")]).default(""),
  GITHUB_WEBHOOK_SECRET: z.string().optional().default(""),
  MONITORING_CRON: z.string().default("0 0 3 * * *"),
  ENABLE_SCHEDULED_SCANS: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  TYPESAFE_API_KEY: z.string().optional().default(""),
  JEV_MODEL_VERSION: z.string().min(1).default("jev-latest"),
  MAX_ARCHIVE_BYTES: z.coerce.number().int().positive().default(100 * 1024 * 1024),
  SESSION_SECRET: z.string().min(32),
  ENCRYPTION_KEY: z.string().min(1),
  PORT: z.coerce.number().int().positive().default(4000),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:", parsed.error.flatten().fieldErrors);
  throw new Error("API environment validation failed");
}
export const env = parsed.data;
