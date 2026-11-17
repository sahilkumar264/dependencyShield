CREATE TABLE IF NOT EXISTS remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action_type TEXT NOT NULL CHECK (action_type IN ('issue', 'draft_pr')),
  status TEXT NOT NULL CHECK (status IN ('in_progress', 'created', 'failed')),
  github_number INTEGER,
  github_url TEXT,
  branch_name TEXT,
  target_version TEXT,
  base_commit_sha TEXT,
  authorized_by UUID NOT NULL REFERENCES users(id),
  authorized_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (finding_id, action_type)
);
CREATE INDEX IF NOT EXISTS remediation_actions_user_idx ON remediation_actions(user_id, created_at DESC);
