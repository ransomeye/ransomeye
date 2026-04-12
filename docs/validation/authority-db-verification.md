# Authority DB Verification

This is the repo-supported DB-backed verification path for Mishka authority-cutover work.

## Scope

The harness covers:

- gateway DB-backed replay and authority tests
- authority package proof tests
- pipeline hot-path authority integration test
- deterministic migration preflight using repo-local `core/migrations`

It does not weaken tests or auto-skip failures.

## Defaults

If `POSTGRES_DSN` is already exported, the harness uses it verbatim.

Otherwise it constructs a deterministic DSN from:

- host: `127.0.0.1`
- port: `5432`
- user: `ransomeye`
- password: `dev_password`
- database: `ransomeye_core`
- TLS root cert: `configs/db-certs/ca.crt`
- TLS client cert: `configs/db-certs/client.crt`
- TLS client key: `configs/db-certs/client.key`
- sslmode: `verify-full`

Override any of those with:

- `MISHKA_TEST_DB_HOST`
- `MISHKA_TEST_DB_PORT`
- `MISHKA_TEST_DB_USER`
- `MISHKA_TEST_DB_PASSWORD`
- `MISHKA_TEST_DB_NAME`
- `MISHKA_TEST_DB_SSLROOTCERT`
- `MISHKA_TEST_DB_SSLCERT`
- `MISHKA_TEST_DB_SSLKEY`
- `MISHKA_TEST_DB_SSLMODE`

## Exact Commands

Print the exact exported environment:

```bash
make authority-db-env
```

Validate listener, TLS, and auth:

```bash
make authority-db-check
```

Apply pending `core/migrations` using the repo psql helper:

```bash
make authority-db-prepare
```

Run the three proof targets independently:

```bash
make authority-db-test-gateway
make authority-db-test-authority
make authority-db-test-pipeline
```

Run the full proof sequence:

```bash
make authority-db-test
```

## Local Postgres Without Docker

Docker access is not required.

If the host already has PostgreSQL bound to `127.0.0.1:5432`, set the correct credentials explicitly and rerun the harness:

```bash
export MISHKA_TEST_DB_USER='...'
export MISHKA_TEST_DB_PASSWORD='...'
export MISHKA_TEST_DB_NAME='...'
make authority-db-check
```

If the host requires a fully explicit DSN instead of discrete overrides:

```bash
export POSTGRES_DSN='host=127.0.0.1 port=5432 user=... password=... dbname=... sslmode=verify-full sslrootcert=/abs/path/ca.crt sslcert=/abs/path/client.crt sslkey=/abs/path/client.key'
make authority-db-test
```

## What Success Means

- `authority-db-test-gateway` proves DB-backed replay/commit behavior for gateway authority tests.
- `authority-db-test-authority` proves the authority package tests and integrity checks actually run against a real DB where applicable.
- `authority-db-test-pipeline` proves the pipeline hot-path authority integration test runs against a real DB.

Any compile error, auth failure, TLS failure, migration failure, or test failure is a real blocker and must be treated as such.
