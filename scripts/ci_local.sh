#!/usr/bin/env bash
# Mirrors every job of .github/workflows/ci.yml, plus the local-only gates CI never
# reaches (the ops catalogue and the agent setup). One command, one verdict per gate.
#
#   scripts/ci_local.sh               full output, as CI prints it
#   scripts/ci_local.sh --quiet       one line per gate; a red gate prints its tail
#   scripts/ci_local.sh --fast        leave out the slow jobs CI still runs on every push
#                                     (clean install, SBOM, images) — reported as NOT RUN
#   scripts/ci_local.sh --skip-audit  leave out `uv audit` (it needs the network)
#
# --quiet keeps every gate's full output in cache/ci/<gate>.log, so a reader pays
# for the log only when a gate is red. A gate that did not run is reported as
# NOT RUN and the script exits 1: "not measured" is never "passed" here.
set -uo pipefail
cd "$(dirname "$0")/.."

quiet=0
fast=0
skip_audit=0
for arg in "$@"; do
  case "$arg" in
    --quiet) quiet=1 ;;
    --fast) fast=1 ;;
    --skip-audit) skip_audit=1 ;;
    *) printf 'unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

# Caches that have answered for changed files before: a stale .ruff_cache once let
# a red tag through, and __pycache__ keeps old bytecode when a same-size edit lands
# within the same second.
rm -rf .ruff_cache
find packages examples scripts -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null

log_dir=cache/ci
[ "$quiet" -eq 1 ] && mkdir -p "$log_dir"

fail=0
notrun=0
verdict_re='(passed|failed|error)[^=]* in [0-9.]+s|^Found [0-9]+ error|^Success: no issues|^All checks passed|files? (already formatted|would be reformatted)|^Contracts: |in sync|out of sync|has drifted|is current|is stale|stale|No findings|[0-9]+ finding'

step() {
  local name="$1"; shift
  if [ "$quiet" -eq 0 ]; then
    printf '\n\033[1m▶ %s\033[0m\n' "$name"
    if "$@"; then printf '  ✓\n'; else printf '  ✗ FAILED\n'; fail=1; fi
    return
  fi
  local log started status verdict
  log="$log_dir/$(printf '%s' "$name" | tr 'A-Z ()/' 'a-z____' | tr -s '_' | sed 's/_$//').log"
  started=$SECONDS
  if "$@" >"$log" 2>&1; then status='✓'; else status='✗'; fail=1; fi
  # The gate's own verdict line is printed beside the status, and a verdict that
  # contradicts a zero exit code turns the gate red.
  verdict=$(grep -E "$verdict_re" "$log" | tail -1)
  [ -z "$verdict" ] && verdict=$(grep -v '^\s*$' "$log" | tail -1 | cut -c1-110)
  if [ "$status" = '✓' ] && verdict_contradicts "$verdict"; then
    status='✗'; fail=1; verdict="$verdict  (exit 0, but the verdict line says otherwise)"
  fi
  printf '%s %-22s %4ss  %s\n' "$status" "$name" "$((SECONDS - started))" "$verdict"
  if [ "$status" = '✗' ]; then
    printf '  --- last 40 lines of %s\n' "$log"
    tail -40 "$log" | sed 's/^/  /'
  fi
}

skip() {
  printf -- '– %-22s       NOT RUN: %s\n' "$1" "$2"
  notrun=1
}

verdict_contradicts() {
  case "$1" in
    *" failed"*|*"has drifted"*|*"out of sync"*|*"is stale"*|*"would be reformatted"*|"Found "*" error"*) return 0 ;;
    Contracts:*) case "$1" in *" 0 broken"*) return 1 ;; *) return 0 ;; esac ;;
  esac
  return 1
}

step "Locked sync"         uv sync --locked
step "Ruff check"          uv run ruff check .
step "Ruff format"         uv run ruff format --check .
step "Mypy"                uv run mypy --strict .
step "Import contract"     uv run lint-imports

# CI runs the collector's tests against a real PostgreSQL and refuses the skip.
if docker compose -f deploy/docker-compose.dev.yml up -d --wait >/dev/null 2>&1; then
  export GUARDANA_TEST_DATABASE_URL="postgresql://guardana:guardana@127.0.0.1:55439/guardana_test"
  export GUARDANA_REQUIRE_POSTGRES=1
else
  skip "PostgreSQL" "docker compose could not start deploy/docker-compose.dev.yml; the collector tests will skip"
fi
if command -v pg_dump >/dev/null 2>&1; then
  export GUARDANA_REQUIRE_PG_TOOLS=1
else
  skip "PostgreSQL client" "pg_dump is not installed; the backup/restore test will skip"
fi

step "Pytest and coverage" uv run pytest --cov --cov-report=json:.coverage.json
step "Coverage floors"     uv run python scripts/critical_coverage.py .coverage.json
if [ "$skip_audit" -eq 0 ]; then
  step "Dependency audit"  uv audit --preview-features audit
else
  skip "Dependency audit" "--skip-audit"
fi
step "Dogfood"             uv run guardana scan packages

step "Generated docs"      uv run python scripts/generate_docs.py --check
step "Landing counts"      uv run python scripts/sync_site.py --check
step "Site build"          uv run python scripts/build_site.py --check
step "llms.txt"            uv run python scripts/generate_llms_txt.py --check
step "Sitemap"             uv run python scripts/generate_sitemap.py --check

# The third-party story, isolated on purpose; --no-cache is load-bearing (a cached
# wheel hides exactly the data files an extension change touches). No -q here: the
# root addopts already carry one, and a second silences the "N passed" summary.
step "Example custom_rule" uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./packages/guardana-cli --with ./packages/guardana-report \
  --with ./examples/custom_rule --with pytest pytest examples/custom_rule/tests
step "Example hermes"      uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/hermes_integrator --with pytest pytest examples/hermes_integrator/tests
step "Example shell_hook"  uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/shell_hook_integrator --with pytest pytest examples/shell_hook_integrator/tests

# The fourth: the three above prove a hand-written pack still works, this one proves
# the command that writes one from nothing does.
step "New pack"           uv run python scripts/new_pack_check.py

# Local-only: CI has no job for the agent setup or the ops catalogue.
step "Ops catalogue"       uv run python scripts/check_ops_catalogue.py
step "Agent setup"         uv run python scripts/check_claude_setup.py

# CI runs these three on every push too; they are only slow, not optional.
if [ "$fast" -eq 1 ]; then
  skip "Clean install" "--fast"
  skip "SBOM" "--fast"
  skip "Images" "--fast"
else
  step "Clean install"     uv run --no-project python scripts/clean_install_check.py
  step "SBOM"              uv run --no-project python scripts/generate_sbom.py --check
  if docker info >/dev/null 2>&1; then
    step "Images"          uv run --no-project python scripts/image_smoke.py
  else
    skip "Images" "docker is not running"
  fi
fi

if [ "$fail" -ne 0 ]; then
  printf '\n\033[31mCI WOULD FAIL — do not push.\033[0m\n'; exit 1
fi
if [ "$notrun" -ne 0 ]; then
  printf '\n\033[33mSome gates did NOT RUN — this is not green until they do.\033[0m\n'; exit 1
fi
printf '\n\033[32mAll CI gates green.\033[0m\n'
