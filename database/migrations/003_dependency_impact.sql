ALTER TABLE sbom_components ALTER COLUMN package_id DROP NOT NULL;

CREATE TABLE IF NOT EXISTS applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id UUID NOT NULL UNIQUE REFERENCES repositories(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_applications (
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  root_bom_ref TEXT,
  dependency_graph_status TEXT NOT NULL CHECK (dependency_graph_status IN ('complete', 'incomplete', 'unknown')),
  PRIMARY KEY (scan_id, application_id)
);

CREATE INDEX IF NOT EXISTS scan_applications_application_idx ON scan_applications (application_id, scan_id);

INSERT INTO applications (repository_id, name)
SELECT id, owner || '/' || name FROM repositories
ON CONFLICT (repository_id) DO NOTHING;

INSERT INTO sbom_components (sbom_id, package_id, bom_ref, component_type)
SELECT s.id, NULL, s.bom->'metadata'->'component'->>'bom-ref', 'application'
FROM sboms s
WHERE NULLIF(s.bom->'metadata'->'component'->>'bom-ref', '') IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM sbom_components c
    WHERE c.sbom_id = s.id AND c.bom_ref = s.bom->'metadata'->'component'->>'bom-ref'
  )
ON CONFLICT (sbom_id, bom_ref) DO NOTHING;

INSERT INTO dependency_edges (sbom_id, source_ref, target_ref)
SELECT s.id, relation->>'ref', child.value
FROM sboms s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.bom->'dependencies', '[]'::jsonb)) AS relation
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(relation->'dependsOn', '[]'::jsonb)) AS child(value)
JOIN sbom_components source_node ON source_node.sbom_id = s.id AND source_node.bom_ref = relation->>'ref'
JOIN sbom_components target_node ON target_node.sbom_id = s.id AND target_node.bom_ref = child.value
ON CONFLICT DO NOTHING;

INSERT INTO scan_applications (scan_id, application_id, root_bom_ref, dependency_graph_status)
SELECT s.scan_id,
       a.id,
       NULLIF(s.bom->'metadata'->'component'->>'bom-ref', ''),
       CASE
         WHEN NULLIF(s.bom->'metadata'->'component'->>'bom-ref', '') IS NULL THEN 'unknown'
         WHEN jsonb_typeof(s.bom->'dependencies') = 'array'
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(s.bom->'dependencies') AS relation
            WHERE relation->>'ref' = s.bom->'metadata'->'component'->>'bom-ref'
          ) THEN 'complete'
         WHEN COALESCE(s.component_count, 0) = 0 THEN 'complete'
         ELSE 'incomplete'
       END
FROM sboms s JOIN applications a ON a.repository_id = s.repository_id
ON CONFLICT (scan_id, application_id) DO NOTHING;
