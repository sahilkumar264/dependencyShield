ALTER TABLE github_webhook_deliveries
  ADD COLUMN IF NOT EXISTS redelivery_attempts SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_redelivery_at TIMESTAMPTZ;
