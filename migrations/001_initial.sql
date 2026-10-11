-- Reference migration for PostgreSQL deployments.
-- The application creates the same schema on startup for the zero-friction demo path.
-- Production deployments should apply this SQL through a migration runner before startup.
CREATE TABLE IF NOT EXISTS schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO schema_version(version) VALUES (1) ON CONFLICT DO NOTHING;
