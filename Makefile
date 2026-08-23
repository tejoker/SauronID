# SauronID Makefile — minimal, opinionated.
.PHONY: help build clean test verify empirical redteam redteam-suites demo demo-strict demo-real demo-real-attacks docs python-setup python-test dashboard-test sdk-test

help:  ## Show this help
	@echo "SauronID — agent-binding stack"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build:  ## Build Rust core (release) + TS clients
	cd core && cargo build --release
	cd redteam && npm ci --ignore-scripts --silent && npm run build --silent
	cd sdk/typescript && npm ci --ignore-scripts --silent && npm run build --silent

python-setup:  ## Create .venv at repo root + install Python SDK + script deps
	python3 -m venv .venv
	. .venv/bin/activate && pip install -q --upgrade pip && pip install -q -e sdk/python && pip install -q httpx requests solana solders
	@echo
	@echo "  Activate: source .venv/bin/activate"
	@echo "  Test:     python -c 'from sauronid_client import SauronIDClient; print(\"OK\")'"

clean:  ## Remove build artefacts and DB files
	cd core && cargo clean && rm -f sauron.db sauron.db-shm sauron.db-wal
	rm -rf redteam/dist sdk/typescript/dist
	rm -f /tmp/sauron-*.log

test:  ## Run cargo test for the workspace
	cd core && cargo test --release --workspace

python-test:  ## Run the Python SDK and adapter tests
	python3 -m pytest sdk/python/tests -q

dashboard-test:  ## Run dashboard unit tests
	cd dashboard && npm ci --ignore-scripts --silent && npm test -- --run

sdk-test:  ## Run the TypeScript SDK test suites
	cd sdk/typescript && npm ci --ignore-scripts --silent && npm test --silent && npm run test:enforcement --silent && npm run test:stats --silent

demo:  ## Quickstart: build + start + invariants (advisory mode)
	./scripts/dev/quickstart.sh

demo-strict:  ## Quickstart in fail-closed mode + 16-attack empirical
	SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh

demo-real:  ## End-to-end real-agent demo: register Groq+Gemini+Anthropic, chat, attacks, anchor, forensics
	@test -n "$$SAURON_ADMIN_KEY" || (echo "SAURON_ADMIN_KEY env required (see .dev-secrets)" && exit 2)
	python3 scripts/demo_real_agent.py

demo-real-attacks:  ## Real-agent demo, ONLY the four live attacks (fast, no LLM keys needed)
	@test -n "$$SAURON_ADMIN_KEY" || (echo "SAURON_ADMIN_KEY env required (see .dev-secrets)" && exit 2)
	python3 scripts/demo_real_agent.py --only-attacks

empirical:  ## Run 16-attack empirical suite against an already-running server
	SAURON_REQUIRE_CALL_SIG=1 \
	  SAURON_CORE_URL=http://127.0.0.1:3001 \
	  SAURON_ADMIN_KEY=$${SAURON_ADMIN_KEY:-super_secret_hackathon_key} \
	  node redteam/dist/scenarios/empirical-suite.js

redteam-suites:  ## Run the six run-all-* scenario aggregators (needs a running server)
	@# These 54 scenarios existed and NOTHING ran them, so they rotted quietly:
	@# three carried a policy YAML the parser had stopped accepting, and one hid a
	@# real cross-tenant spend_ledger collision for as long as it went unrun.
	@# Wiring them is the fix that keeps them honest.
	@for f in redteam/dist/scenarios/run-all-*.js; do \
	  echo "── $$f"; \
	  SAURON_CORE_URL=$${SAURON_CORE_URL:-http://127.0.0.1:3001} \
	  SAURON_ADMIN_KEY=$${SAURON_ADMIN_KEY:-super_secret_hackathon_key} \
	  node $$f || echo "  ^ FAILURES above"; \
	done

redteam:  ## Run Tavily-driven autonomous red-team agent (15 attacks; needs running server)
	SAURON_CORE_URL=http://127.0.0.1:3001 \
	  SAURON_ADMIN_KEY=$${SAURON_ADMIN_KEY:-super_secret_hackathon_key} \
	  node redteam/dist/scenarios/tavily-redteam.js

verify: build  ## cargo test + invariants + empirical (full release gate)
	cd core && cargo fmt --check
	cd core && cargo clippy --release -- -D warnings
	cd core && cargo test --release --workspace
	$(MAKE) python-test
	./scripts/dev/quickstart.sh
	SAURON_REQUIRE_CALL_SIG=1 ./scripts/dev/quickstart.sh

docs:  ## Open the empirical comparison doc
	@cat docs/planning/empirical-comparison.md | less

.DEFAULT_GOAL := help
