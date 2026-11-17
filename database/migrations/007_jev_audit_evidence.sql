ALTER TABLE jev_decisions ADD COLUMN IF NOT EXISTS provider_request_id TEXT;
ALTER TABLE jev_decisions ADD COLUMN IF NOT EXISTS policy_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE jev_decisions ALTER COLUMN policy_evidence DROP DEFAULT;
