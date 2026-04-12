-- RansomEye PRD-03 deterministic bootstrap prelude (idempotent, non-destructive).
-- Full relational schema is applied by core/migrations/*.sql via the migrator.
-- FORBIDDEN: graph_nodes, graph_edges (and any graph_* tables) — never add here.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS timescaledb;
