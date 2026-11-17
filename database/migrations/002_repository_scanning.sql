CREATE TABLE IF NOT EXISTS github_installations (
  id BIGINT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_login TEXT NOT NULL,
  account_type TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, id)
);

ALTER TABLE github_accounts ADD COLUMN IF NOT EXISTS encrypted_refresh_token TEXT;
ALTER TABLE github_accounts ADD COLUMN IF NOT EXISTS access_token_expires_at TIMESTAMPTZ;
ALTER TABLE github_accounts ADD COLUMN IF NOT EXISTS refresh_token_expires_at TIMESTAMPTZ;

ALTER TABLE repositories ADD COLUMN IF NOT EXISTS installation_id BIGINT REFERENCES github_installations(id) ON DELETE CASCADE;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS html_url TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS scan_branch TEXT;
UPDATE repositories SET scan_branch = default_branch WHERE scan_branch IS NULL;
ALTER TABLE repositories ALTER COLUMN scan_branch SET NOT NULL;
CREATE INDEX IF NOT EXISTS repositories_installation_idx ON repositories (installation_id);

ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_status_check;
ALTER TABLE scans ADD CONSTRAINT scans_status_check CHECK (status IN ('queued', 'processing', 'completed', 'completed_with_warnings', 'failed', 'cancelled'));
ALTER TABLE scans ADD COLUMN IF NOT EXISTS sbom_status TEXT NOT NULL DEFAULT 'pending' CHECK (sbom_status IN ('pending', 'completed', 'failed'));
ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerability_status TEXT NOT NULL DEFAULT 'pending' CHECK (vulnerability_status IN ('pending', 'completed', 'partial', 'unavailable'));
ALTER TABLE scans ADD COLUMN IF NOT EXISTS vulnerability_error TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS branch TEXT;
UPDATE scans s SET branch = r.scan_branch FROM repositories r WHERE s.repository_id = r.id AND s.branch IS NULL;
ALTER TABLE scans ALTER COLUMN branch SET NOT NULL;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_vulnerability_status_check;
ALTER TABLE scans ADD CONSTRAINT scans_vulnerability_status_check CHECK (vulnerability_status IN ('pending', 'completed', 'partial', 'unavailable'));

CREATE TABLE IF NOT EXISTS sboms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
  repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  branch TEXT NOT NULL,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  spec_version TEXT NOT NULL,
  serial_number TEXT,
  component_count INTEGER NOT NULL,
  bom JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity TEXT NOT NULL UNIQUE,
  purl TEXT,
  name TEXT NOT NULL,
  version TEXT,
  ecosystem TEXT
);

CREATE TABLE IF NOT EXISTS sbom_components (
  sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  package_id UUID NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
  bom_ref TEXT NOT NULL,
  component_type TEXT NOT NULL,
  PRIMARY KEY (sbom_id, bom_ref)
);

CREATE TABLE IF NOT EXISTS dependency_edges (
  sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  source_ref TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  PRIMARY KEY (sbom_id, source_ref, target_ref),
  FOREIGN KEY (sbom_id, source_ref) REFERENCES sbom_components(sbom_id, bom_ref) ON DELETE CASCADE,
  FOREIGN KEY (sbom_id, target_ref) REFERENCES sbom_components(sbom_id, bom_ref) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL DEFAULT 'OSV',
  modified_at TIMESTAMPTZ,
  payload JSONB NOT NULL,
  synchronized_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vulnerability_aliases (
  vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  PRIMARY KEY (vulnerability_id, alias)
);

CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
  bom_ref TEXT NOT NULL,
  package_id UUID NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (scan_id, bom_ref, vulnerability_id),
  FOREIGN KEY (sbom_id, bom_ref) REFERENCES sbom_components(sbom_id, bom_ref) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_vulnerability_idx ON findings (vulnerability_id);
