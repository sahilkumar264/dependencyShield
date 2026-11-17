ALTER TABLE repositories ADD COLUMN IF NOT EXISTS monitoring_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS trigger_source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS requested_commit_sha TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS trigger_delivery_id TEXT;
ALTER TABLE scans ADD CONSTRAINT scans_trigger_source_check CHECK (trigger_source IN ('manual', 'scheduled', 'webhook'));

CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
  delivery_id UUID PRIMARY KEY,
  event_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'completed', 'failed')),
  repository_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
  error_message TEXT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS monitoring_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  package_id UUID NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
  category TEXT NOT NULL CHECK (category IN ('new_vulnerability')),
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (repository_id, vulnerability_id, package_id, category)
);
CREATE INDEX IF NOT EXISTS monitoring_alerts_user_unread_idx ON monitoring_alerts(user_id, created_at DESC) WHERE read_at IS NULL;
