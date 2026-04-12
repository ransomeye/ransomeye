SHELL := /bin/bash

GO_DIR := core

BUILD_DIR := build
CORE_OUT := $(BUILD_DIR)/ransomeye-core
DB_BOOTSTRAP_OUT := $(BUILD_DIR)/db-bootstrap
INTEGRITY_MANIFEST_OUT := $(BUILD_DIR)/integrity.manifest
INTEGRITY_SIG_OUT := $(BUILD_DIR)/integrity.sig
SIGN_INTEGRITY_MANIFEST := scripts/sign-integrity-manifest
REPRO_ENV_SCRIPT := "$(CURDIR)/scripts/reproducible-build-env.sh"
REPRO_ENV := source $(REPRO_ENV_SCRIPT) "$(CURDIR)"
GO_REPRO_FLAGS := -trimpath -buildvcs=false -ldflags "-buildid="
# Monotonic signed manifest header (Phase 6.7); bump on every deploy that must reject older manifests.
INTEGRITY_MANIFEST_VERSION ?= 3
INTEGRITY_SIGNING_KEY ?=
SOURCE_DATE_EPOCH ?= 1700000000

INSTALL_ETC_DIR := /etc/ransomeye
INSTALL_CORE_DIR := /opt/ransomeye/core

.PHONY: all build-core generate-manifest sign-manifest generate-integrity install up-db validate-hardcoded-addrs verify-reproducible-build verify-prd install-prd-pre-receive-hook authority-db-env authority-db-check authority-db-prepare authority-db-test-gateway authority-db-test-authority authority-db-test-pipeline authority-db-test replay-db-test purge-in-repo-cargo-targets

all: build-core

# Remove any legacy in-repo target/ trees (Mishka hygiene: CARGO_TARGET_DIR is set by reproducible-build-env.sh).
purge-in-repo-cargo-targets:
	@rm -rf \
		"$(CURDIR)/installer/target" \
		"$(CURDIR)/scripts/sign-integrity-manifest/target" \
		"$(CURDIR)/signed-config/target" \
		"$(CURDIR)/sine-engine/target" \
		2>/dev/null || true

validate-hardcoded-addrs:
	@echo "[VALIDATE] hardcoded network addresses"
	@cd "$(CURDIR)" && go test ./core/internal/netcfg -run TestNoHardcodedNetworkAddresses -count=1

# Project Mishka: verify locked PRD manifest (all *.md under prd_project_mishka/ vs prd.sha256)
verify-prd:
	@echo "[VERIFY] Mishka PRD checksum manifest (prd_project_mishka/prd.sha256)"
	@cd "$(CURDIR)/prd_project_mishka" && sha256sum -c prd.sha256

# Install server-side gate into this clone (remote bare repos should use the same script path).
install-prd-pre-receive-hook:
	@test -d "$(CURDIR)/.git" || (echo "FATAL: not a git checkout (.git missing)" && false)
	@install -m 0755 "$(CURDIR)/git-hooks/pre-receive" "$(CURDIR)/.git/hooks/pre-receive"
	@echo "[OK] installed .git/hooks/pre-receive — authoritative remote gate: only prd_project_mishka/prd.sha256 may change under prd_project_mishka/"

build-core:
	@mkdir -p "$(BUILD_DIR)"
	@$(MAKE) validate-hardcoded-addrs
	@echo "[BUILD] Core Engine (Go)"
	@$(REPRO_ENV) && cd "$(CURDIR)" && go build $(GO_REPRO_FLAGS) -o "$(CORE_OUT)" ./core/cmd/ransomeye-core
	@$(REPRO_ENV) && cd "$(CURDIR)" && go build $(GO_REPRO_FLAGS) -o "$(DB_BOOTSTRAP_OUT)" ./core/cmd/db-bootstrap
	@echo "[OK] core -> $(CORE_OUT)"
	@echo "[OK] db-bootstrap -> $(DB_BOOTSTRAP_OUT)"

# Mishka Phase-1 slice: signed manifest covers the running core ELF only.
generate-manifest: build-core
	@mkdir -p "$(BUILD_DIR)"
	@echo "[MANIFEST] integrity.manifest (version $(INTEGRITY_MANIFEST_VERSION))"
	@{ \
		core_h=$$(sha256sum "$(CORE_OUT)" | awk '{print $$1}'); \
		{ \
			printf 'version: %s\n' "$(INTEGRITY_MANIFEST_VERSION)"; \
			echo "sha256:$$core_h  $(INSTALL_CORE_DIR)/ransomeye-core"; \
		} > "$(INTEGRITY_MANIFEST_OUT)"; \
	}
	@echo "[OK] manifest -> $(INTEGRITY_MANIFEST_OUT)"

sign-manifest: purge-in-repo-cargo-targets
	@test -f "$(CURDIR)/$(INTEGRITY_MANIFEST_OUT)" || (echo "FATAL: run make generate-manifest first" && false)
	@echo "[SIGN] integrity.sig (WORM Ed25519 over manifest bytes)"
	@$(REPRO_ENV) && cd "$(SIGN_INTEGRITY_MANIFEST)" && \
		args=("$(CURDIR)/$(INTEGRITY_MANIFEST_OUT)" "$(CURDIR)/$(INTEGRITY_SIG_OUT)"); \
		if [[ -n "$(INTEGRITY_SIGNING_KEY)" ]]; then \
			args+=("$(INTEGRITY_SIGNING_KEY)"); \
		fi; \
		cargo run --quiet --release -- "$${args[@]}"
	@$(MAKE) purge-in-repo-cargo-targets

# Run manifest then sign sequentially (both are phony; parallel prereqs would race).
generate-integrity:
	@$(MAKE) generate-manifest
	@$(MAKE) sign-manifest
	@$(MAKE) purge-in-repo-cargo-targets
	@echo "[OK] generate-integrity complete (manifest + sig)"

verify-reproducible-build:
	@bash "$(CURDIR)/scripts/verify-reproducible-build.sh"

install: all
	@$(MAKE) generate-integrity
	@echo "[INSTALL] Deploying Mishka Phase-1 core artifacts + integrity"
	@install -d "$(INSTALL_ETC_DIR)" "$(INSTALL_CORE_DIR)"
	@install -m 0500 "$(CORE_OUT)" "$(INSTALL_CORE_DIR)/ransomeye-core"
	@install -m 0444 "$(INTEGRITY_MANIFEST_OUT)" "$(INSTALL_ETC_DIR)/integrity.manifest"
	@install -m 0444 "$(INTEGRITY_SIG_OUT)" "$(INSTALL_ETC_DIR)/integrity.sig"
	@chown root:root "$(INSTALL_ETC_DIR)/integrity.manifest" "$(INSTALL_ETC_DIR)/integrity.sig"
	@install -d /var/lib/ransomeye/state
	@python3 scripts/compute-integrity-anchor.py "$(BUILD_DIR)/.integrity-anchor" "$(BUILD_DIR)/.integrity-anchor.history"
	@install -m 0400 "$(BUILD_DIR)/.integrity-anchor" /var/lib/ransomeye/state/anchor
	@install -m 0600 "$(BUILD_DIR)/.integrity-anchor.history" /var/lib/ransomeye/state/anchor.history
	@ver=$$(head -n1 "$(INTEGRITY_MANIFEST_OUT)" | sed -n 's/^[Vv]ersion: *//p'); \
		printf '%s\n' "$$ver" > "$(BUILD_DIR)/.integrity-version-seed"
	@install -m 0600 "$(BUILD_DIR)/.integrity-version-seed" /var/lib/ransomeye/state/version
	@-chown root:root /var/lib/ransomeye/state /var/lib/ransomeye/state/version /var/lib/ransomeye/state/anchor /var/lib/ransomeye/state/anchor.history
	@-chmod 0700 /var/lib/ransomeye/state
	@echo "[OK] install complete"

up-db:
	@echo "[UP] postgres (dev)"
	@docker-compose -f docker-compose.dev.yml up -d

# Mishka PRD-13: apply numbered migrations from core/migrations (requires DB trust + POSTGRES_DSN per core config).
.PHONY: migrate-core
migrate-core: build-core
	@"$(CURDIR)/build/db-bootstrap" bootstrap -migrations "$(CURDIR)/core/migrations/"

authority-db-env:
	@"$(CURDIR)/scripts/authority_db_env.sh" --export

# Live DB/TLS parity: load /etc/ransomeye/core.env as root (secrets + cert paths under /opt), keep caller PATH for Go.
authority-db-check:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; "$(CURDIR)/scripts/authority_db_env.sh" --check'

authority-db-prepare:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; cd "$(CURDIR)" && "$(CURDIR)/scripts/run_authority_db_tests.sh" prepare'

authority-db-test-gateway:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; cd "$(CURDIR)" && "$(CURDIR)/scripts/run_authority_db_tests.sh" gateway'

authority-db-test-authority:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; cd "$(CURDIR)" && "$(CURDIR)/scripts/run_authority_db_tests.sh" authority'

authority-db-test-pipeline:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; cd "$(CURDIR)" && "$(CURDIR)/scripts/run_authority_db_tests.sh" pipeline'

authority-db-test:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; cd "$(CURDIR)" && "$(CURDIR)/scripts/run_authority_db_tests.sh" all'

# PRD-15 replay lane: requires POSTGRES_DSN + PGSSL* identical to authority-db-test (do not rely on dev defaults; live DB name/password differ).
replay-db-test:
	@sudo -E env "PATH=$${PATH}" bash -lc 'set -euo pipefail; \
	  set -a; [[ -r /etc/ransomeye/core.env ]] && . /etc/ransomeye/core.env; set +a; \
	  unset RANSOMEYE_EXECUTION_CONTEXT_HASH || true; \
	  if [[ -z "$${POSTGRES_DSN:-}" ]]; then \
	    echo "FATAL: POSTGRES_DSN missing after sourcing /etc/ransomeye/core.env" >&2; \
	    exit 2; \
	  fi; \
	  export PGSSLROOTCERT PGSSLCERT PGSSLKEY PGSSLMODE PGSSLSERVERNAME; \
	  cd "$(CURDIR)" && go test ./core/internal/replay -count=1 -timeout 180s'
