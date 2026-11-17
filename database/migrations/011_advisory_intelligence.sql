CREATE TABLE IF NOT EXISTS kev_entries (
  cve_id TEXT PRIMARY KEY,
  date_added DATE NOT NULL,
  payload JSONB NOT NULL,
  synchronized_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vulnerability_source_records (
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  canonical_vulnerability_id TEXT REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  payload JSONB NOT NULL,
  modified_at TIMESTAMPTZ,
  synchronized_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (source, external_id)
);
CREATE INDEX IF NOT EXISTS vulnerability_source_records_canonical_idx ON vulnerability_source_records(canonical_vulnerability_id);
