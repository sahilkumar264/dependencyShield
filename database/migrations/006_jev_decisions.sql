CREATE TABLE IF NOT EXISTS jev_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (source IN ('jev', 'deterministic_fallback')),
  requested_model TEXT NOT NULL,
  resolved_model TEXT,
  provider_request_id TEXT,
  policy_version TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  input_state JSONB NOT NULL,
  questions JSONB NOT NULL,
  answers JSONB NOT NULL,
  usage JSONB,
  policy_evidence JSONB NOT NULL,
  fallback_reason TEXT,
  suggested_priority TEXT CHECK (suggested_priority IS NULL OR suggested_priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
  final_priority TEXT NOT NULL CHECK (final_priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
  risk_score DOUBLE PRECISION CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 4)),
  immediate_escalation BOOLEAN NOT NULL,
  human_review_required BOOLEAN NOT NULL,
  remediation_category TEXT NOT NULL,
  operational_response TEXT NOT NULL,
  policy_action TEXT NOT NULL,
  decision_reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS jev_decisions_user_created_idx ON jev_decisions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS jev_decisions_finding_created_idx ON jev_decisions (finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS jev_decisions_application_created_idx ON jev_decisions (application_id, created_at DESC);
