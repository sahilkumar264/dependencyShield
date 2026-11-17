CREATE TABLE IF NOT EXISTS code_analysis_runs (
  scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'unavailable')),
  engine TEXT NOT NULL,
  engine_version TEXT,
  commit_sha TEXT NOT NULL,
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS code_analysis_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL CHECK (start_line > 0),
  end_line INTEGER NOT NULL CHECK (end_line >= start_line),
  code_snippet TEXT NOT NULL,
  UNIQUE (scan_id, rule_id, file_path, start_line)
);

CREATE TABLE IF NOT EXISTS finding_reachability (
  finding_id UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('possible_usage', 'not_observed', 'unknown')),
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  analyzed_commit_sha TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS code_analysis_findings_scan_idx ON code_analysis_findings(scan_id);
