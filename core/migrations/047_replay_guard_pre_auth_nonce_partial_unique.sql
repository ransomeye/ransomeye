-- replay_guard had UNIQUE NULLS NOT DISTINCT (partition_id, logical_shard_id, pre_auth_nonce).
-- With NULLS NOT DISTINCT, all rows with pre_auth_nonce NULL collide: only one ADMITTED row per
-- (partition_id, logical_shard_id) was possible, breaking multi-tick SIGNAL replay progression.
-- Enforce uniqueness for pre-auth nonces only when pre_auth_nonce IS NOT NULL.

ALTER TABLE replay_guard
  DROP CONSTRAINT IF EXISTS replay_guard_partition_id_logical_shard_id_pre_auth_nonce_key;

CREATE UNIQUE INDEX IF NOT EXISTS replay_guard_partition_shard_pre_auth_nonce_unique
  ON replay_guard (partition_id, logical_shard_id, pre_auth_nonce)
  WHERE pre_auth_nonce IS NOT NULL;

SELECT register_migration(47, 'replay_guard_pre_auth_nonce_partial_unique');
