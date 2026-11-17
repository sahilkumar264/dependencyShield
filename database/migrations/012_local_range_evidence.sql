ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS local_range_status TEXT NOT NULL DEFAULT 'unknown'
    CHECK (local_range_status IN ('affected', 'not_affected', 'unknown')),
  ADD COLUMN IF NOT EXISTS local_range_source TEXT,
  ADD COLUMN IF NOT EXISTS local_range_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
