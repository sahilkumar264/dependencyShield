CREATE TABLE IF NOT EXISTS okf_bundles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'DependencyShield workspace knowledge',
  format_version TEXT NOT NULL DEFAULT '0.2',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS okf_bundle_revisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id UUID NOT NULL REFERENCES okf_bundles(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL CHECK (revision > 0),
  content_hash TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (bundle_id, revision)
);

CREATE TABLE IF NOT EXISTS okf_bundle_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id UUID NOT NULL REFERENCES okf_bundles(id) ON DELETE CASCADE,
  revision_id UUID NOT NULL REFERENCES okf_bundle_revisions(id) ON DELETE CASCADE,
  document_path TEXT NOT NULL,
  markdown TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('integration', 'user')),
  UNIQUE (revision_id, document_path)
);

CREATE INDEX IF NOT EXISTS okf_bundle_documents_revision_idx ON okf_bundle_documents (revision_id, document_path);

CREATE TABLE IF NOT EXISTS okf_concepts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id UUID NOT NULL REFERENCES okf_bundles(id) ON DELETE CASCADE,
  revision_id UUID NOT NULL REFERENCES okf_bundle_revisions(id) ON DELETE CASCADE,
  concept_path TEXT NOT NULL,
  concept_id TEXT NOT NULL,
  concept_type TEXT NOT NULL,
  title TEXT,
  description TEXT,
  frontmatter JSONB NOT NULL,
  body TEXT NOT NULL,
  markdown TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('integration', 'user')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (revision_id, concept_path),
  UNIQUE (revision_id, concept_id)
);

CREATE INDEX IF NOT EXISTS okf_concepts_revision_type_idx ON okf_concepts (revision_id, concept_type);
CREATE INDEX IF NOT EXISTS okf_concepts_revision_path_idx ON okf_concepts (revision_id, concept_path);

CREATE TABLE IF NOT EXISTS okf_relationships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bundle_id UUID NOT NULL REFERENCES okf_bundles(id) ON DELETE CASCADE,
  revision_id UUID NOT NULL REFERENCES okf_bundle_revisions(id) ON DELETE CASCADE,
  source_concept_id UUID NOT NULL REFERENCES okf_concepts(id) ON DELETE CASCADE,
  target_concept_id UUID REFERENCES okf_concepts(id) ON DELETE CASCADE,
  target_concept_path TEXT NOT NULL,
  link_text TEXT NOT NULL,
  link_url TEXT NOT NULL,
  UNIQUE (source_concept_id, target_concept_path, link_url)
);

CREATE INDEX IF NOT EXISTS okf_relationships_revision_target_idx ON okf_relationships (revision_id, target_concept_path);
CREATE INDEX IF NOT EXISTS okf_relationships_source_idx ON okf_relationships (source_concept_id);
