# dev/lib/harness.sh — shared plumbing for the dev harnesses (`dev/test-deb`, `dev/e2e`).
#
# Four things, and nothing clever: the ✓/✗ report, the durable evidence record that report leaves
# behind, the container-engine invocation, and a teardown registry. Sourced, never executed.
#
# The report's only rule: a claim that was not actually checked must never print a ✓. `skip` exists
# for that — it prints, it says why, and it counts separately from both passes and failures, so a
# harness that could not run a leg cannot be mistaken for one that ran it.

HARNESS_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# --------------------------------------------------------------------------------- ✓ / ✗ report --
HARNESS_PASS=0
HARNESS_FAIL=0
HARNESS_SKIP=0
HARNESS_START_EPOCH="$(date +%s)"
if [ -t 1 ]; then
  H_G=$'\033[32m'; H_R=$'\033[31m'; H_Y=$'\033[33m'; H_D=$'\033[2m'; H_Z=$'\033[0m'
else
  H_G=""; H_R=""; H_Y=""; H_D=""; H_Z=""
fi

ok() {
  printf '  %s✓%s %-44s %s%s%s\n' "$H_G" "$H_Z" "$1" "$H_D" "${2:-}" "$H_Z"
  HARNESS_PASS=$((HARNESS_PASS + 1))
  harness_evidence_claim "$1" passed "${2:-held}"
}

bad() { # name expected observed
  printf '  %s✗%s %-44s\n      expected: %s\n      observed: %s\n' "$H_R" "$H_Z" "$1" "$2" "$3"
  HARNESS_FAIL=$((HARNESS_FAIL + 1))
  harness_evidence_claim "$1" failed "expected: $2 — observed: $3"
}

skip() { # name reason
  printf '  %s·%s %-44s %sSKIPPED BY DESIGN — %s%s\n' "$H_Y" "$H_Z" "$1" "$H_D" "$2" "$H_Z"
  HARNESS_SKIP=$((HARNESS_SKIP + 1))
  harness_evidence_claim "$1" skipped-by-design "$2"
}

assert_eq() { # name expected observed
  if [ "$2" = "$3" ]; then ok "$1" "$3"; else bad "$1" "$2" "$3"; fi
}

assert_contains() { # name needle haystack-description haystack
  case "$4" in
    *"$2"*) ok "$1" "found: $2" ;;
    *) bad "$1" "$3 contains: $2" "it does not — got: $(printf '%s' "$4" | tr '\n' ' ' | cut -c1-200)" ;;
  esac
}

assert_absent() { # name needle haystack-description haystack
  case "$4" in
    *"$2"*) bad "$1" "$3 does NOT contain: $2" "it does" ;;
    *) ok "$1" "absent: $2" ;;
  esac
}

leg_header() {
  printf '\n----------------------------------------------------------------------\n== %s\n----------------------------------------------------------------------\n' "$1"
  HARNESS_EVIDENCE_LEG="$1"
}

# Prints the summary and returns the process exit status: 0 all held, 1 something failed.
# It is also where the evidence record is finalized, because this line IS the verdict.
harness_report() { # tool-name trailing-detail
  local elapsed=$(( $(date +%s) - HARNESS_START_EPOCH ))
  local total=$((HARNESS_PASS + HARNESS_FAIL))
  local summary status
  if [ "$HARNESS_FAIL" -eq 0 ]; then
    summary="$(printf '%s: %d/%d contract claims held' "$1" "$HARNESS_PASS" "$total")"
  else
    summary="$(printf '%s: %d/%d contract claims held, %d FAILED' "$1" "$HARNESS_PASS" "$total" "$HARNESS_FAIL")"
  fi
  [ "$HARNESS_SKIP" -eq 0 ] || summary="$summary$(printf ', %d skipped by design' "$HARNESS_SKIP")"
  summary="$summary$(printf ' (%ds%s)' "$elapsed" "${2:+, $2}")"

  printf '\n----------------------------------------------------------------------\n'
  if [ "$HARNESS_FAIL" -eq 0 ]; then
    printf '%s%s%s\n' "$H_G" "$summary" "$H_Z"
  else
    printf '%s%s%s\n' "$H_R" "$summary" "$H_Z"
  fi

  # A run that proved nothing is not a complete run: with no pass and at least one skip, the whole
  # thing was skipped by design, and the record says so rather than "complete".
  if [ "$HARNESS_FAIL" -ne 0 ]; then
    status=failed
  elif [ "$HARNESS_PASS" -eq 0 ] && [ "$HARNESS_SKIP" -gt 0 ]; then
    status=skipped-by-design
  else
    status=complete
  fi
  harness_evidence_finalize "$([ "$HARNESS_FAIL" -eq 0 ] && printf 0 || printf 1)" "$status" "$summary" \
    "$HARNESS_PASS held, $HARNESS_FAIL failed, $HARNESS_SKIP skipped by design"
  [ "$HARNESS_FAIL" -eq 0 ]
}

# --------------------------------------------------------------------------------------- evidence -
# EVERY dev/e2e and dev/test-deb run leaves a durable evidence record. Before it, "34/34 last
# Tuesday" was a claim in a transcript: a run wrote stdout and worktree-local temp, and nothing a
# later reader could open.
#
# The shape mirrors this project's other operational tooling, deliberately, rather than inventing a
# third vocabulary: rows are `{name, status, reason}`, and the final block carries `schema` /
# `run_id` / `status` / `reason` / `claims_summary` / `counts` / `started_at` / `ended_at` /
# `generated_at` / `source_commit` / `platform`. Fields with no meaning for a dev run are simply
# absent, and the four a dev run needs — harness, source_dirty, context, wall_clock_seconds,
# exit_code — are added rather than spelled some other way.
#
# Crash safety is structural, not machinery: rows are appended as each claim resolves, and the final
# block is written once, at the end. A harness that dies mid-run leaves the rows it had resolved and
# no `run.json` — the ABSENCE of the final block IS the incompleteness marker.
#
#   CERMET_DEV_EVIDENCE=0        — write nothing at all.
#   CERMET_DEV_EVIDENCE_DIR=<d>  — the root the per-run directory is created under.
#                                  Default: /var/tmp/cermet-dev-runs (disk-backed, 30-day aging;
#                                  /tmp is tmpfs and forbidden for this).
#
# Per-run directory: <root>/<UTC timestamp>-<harness>, with the pid appended when a run of the same
# harness already claimed that second — two records rather than one overwriting the other, found by
# running two harness invocations back to back inside the same second.
HARNESS_EVIDENCE_DIR=""
HARNESS_EVIDENCE_LEG="(before the first leg)"
HARNESS_EVIDENCE_HARNESS=""
HARNESS_EVIDENCE_RUN_ID=""
HARNESS_EVIDENCE_STARTED_AT=""
declare -A HARNESS_EVIDENCE_LEG_COUNTS=()
HARNESS_EVIDENCE_LEG_ORDER=()

# A JSON string literal, with the two things a shell harness must not get wrong: escaping, and
# credential-shaped fragments. The scrub sits at the ONE chokepoint every row and every final field
# crosses — a claim's observed value is often raw provider or container output, and provider error
# prose quotes the key it rejected ("Invalid API Key provided: sk_test_…"). Named adversary: T2,
# harness accident. Truncated at 500 characters.
harness_json_string() {
  local s
  s="$(printf '%s' "${1-}" | LC_ALL=C sed -E \
    -e 's/\x1b\[[0-9;]*[A-Za-z]//g' \
    -e 's/(sk|rk)_(live|test)_[A-Za-z0-9_]+/<redacted>/gI' \
    -e 's/github_pat_[A-Za-z0-9_]+/<redacted>/gI' \
    -e 's/gh[pousr]_[A-Za-z0-9_]+/<redacted>/gI' \
    -e 's/bearer[[:space:]]+[^[:space:]"]+/<redacted>/gI' \
    -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/<redacted>/g' \
    | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177')"
  s="${s:0:500}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '"%s"' "$s"
}

harness_evidence_open() { # harness-name (e.g. dev/e2e)
  [ "${CERMET_DEV_EVIDENCE:-1}" != 0 ] || return 0
  local root stamp
  root="${CERMET_DEV_EVIDENCE_DIR:-/var/tmp/cermet-dev-runs}"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  HARNESS_EVIDENCE_HARNESS="$1"
  HARNESS_EVIDENCE_RUN_ID="$stamp-$$"
  HARNESS_EVIDENCE_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  HARNESS_EVIDENCE_DIR="$root/$stamp-${1##*/}"
  mkdir -p -- "$root"
  mkdir -- "$HARNESS_EVIDENCE_DIR" 2>/dev/null || {
    HARNESS_EVIDENCE_DIR="$HARNESS_EVIDENCE_DIR-$$"
    mkdir -p -- "$HARNESS_EVIDENCE_DIR"
  }
  chmod 0700 "$HARNESS_EVIDENCE_DIR"
  : >"$HARNESS_EVIDENCE_DIR/claims.jsonl"
  chmod 0600 "$HARNESS_EVIDENCE_DIR/claims.jsonl"
  printf 'evidence: %s\n' "$HARNESS_EVIDENCE_DIR"
}

harness_evidence_claim() { # name status reason
  [ -n "$HARNESS_EVIDENCE_DIR" ] || return 0
  printf '{"name": %s, "leg": %s, "status": "%s", "reason": %s}\n' \
    "$(harness_json_string "$1")" "$(harness_json_string "$HARNESS_EVIDENCE_LEG")" "$2" \
    "$(harness_json_string "$3")" >>"$HARNESS_EVIDENCE_DIR/claims.jsonl"
  local key="$HARNESS_EVIDENCE_LEG"
  case " ${HARNESS_EVIDENCE_LEG_ORDER[*]-} " in
    *" $key "*) ;;
    *) HARNESS_EVIDENCE_LEG_ORDER+=("$key")
       HARNESS_EVIDENCE_LEG_COUNTS["$key|passed"]=0
       HARNESS_EVIDENCE_LEG_COUNTS["$key|failed"]=0
       HARNESS_EVIDENCE_LEG_COUNTS["$key|skipped-by-design"]=0 ;;
  esac
  HARNESS_EVIDENCE_LEG_COUNTS["$key|$2"]=$(( ${HARNESS_EVIDENCE_LEG_COUNTS["$key|$2"]} + 1 ))
}

# The one writer of the final block. Called by `harness_report` on the normal path, and directly by
# a harness that refuses before it can claim anything.
harness_evidence_finalize() { # exit-code status claims-summary reason
  [ -n "$HARNESS_EVIDENCE_DIR" ] || return 0
  local commit dirty context leg first=1
  commit="$(git -C "$HARNESS_REPO_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
  if [ -n "$(git -C "$HARNESS_REPO_ROOT" status --porcelain 2>/dev/null)" ]; then dirty=true; else dirty=false; fi
  # Which box these claims were made ON. Both harnesses drive containers; what matters to a later
  # reader is whether the harness ITSELF ran on the metal or inside one.
  if [ -e /run/.containerenv ] || [ -e /.dockerenv ]; then
    context=container
  elif command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet; then
    context=container
  else
    context=host
  fi

  {
    printf '{\n'
    printf '  "schema": "cermet.dev-run.v1",\n'
    printf '  "run_id": %s,\n' "$(harness_json_string "$HARNESS_EVIDENCE_RUN_ID")"
    printf '  "harness": %s,\n' "$(harness_json_string "$HARNESS_EVIDENCE_HARNESS")"
    printf '  "status": "%s",\n' "$2"
    printf '  "reason": %s,\n' "$(harness_json_string "$4")"
    printf '  "claims_summary": %s,\n' "$(harness_json_string "$3")"
    printf '  "exit_code": %s,\n' "$1"
    printf '  "source_commit": %s,\n' "$(harness_json_string "$commit")"
    printf '  "source_dirty": %s,\n' "$dirty"
    printf '  "context": "%s",\n' "$context"
    printf '  "platform": %s,\n' "$(harness_json_string "$(uname -s | tr '[:upper:]' '[:lower:]')")"
    printf '  "started_at": %s,\n' "$(harness_json_string "$HARNESS_EVIDENCE_STARTED_AT")"
    printf '  "ended_at": %s,\n' "$(harness_json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    printf '  "generated_at": %s,\n' "$(harness_json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    printf '  "wall_clock_seconds": %d,\n' "$(( $(date +%s) - HARNESS_START_EPOCH ))"
    printf '  "counts": {\n'
    printf '    "claims": %d,\n' "$((HARNESS_PASS + HARNESS_FAIL + HARNESS_SKIP))"
    printf '    "passed": %d,\n' "$HARNESS_PASS"
    printf '    "failed": %d,\n' "$HARNESS_FAIL"
    printf '    "skipped_by_design": %d\n' "$HARNESS_SKIP"
    printf '  },\n'
    if [ "${#HARNESS_EVIDENCE_LEG_ORDER[@]}" -eq 0 ]; then
      printf '  "legs": []\n'
    else
      printf '  "legs": [\n'
      for leg in "${HARNESS_EVIDENCE_LEG_ORDER[@]}"; do
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"leg": %s, "passed": %d, "failed": %d, "skipped_by_design": %d}' \
          "$(harness_json_string "$leg")" \
          "${HARNESS_EVIDENCE_LEG_COUNTS["$leg|passed"]}" \
          "${HARNESS_EVIDENCE_LEG_COUNTS["$leg|failed"]}" \
          "${HARNESS_EVIDENCE_LEG_COUNTS["$leg|skipped-by-design"]}"
      done
      printf '\n  ]\n'
    fi
    printf '}\n'
  } >"$HARNESS_EVIDENCE_DIR/run.json"
  chmod 0600 "$HARNESS_EVIDENCE_DIR/run.json"
  printf 'evidence: %s\n' "$HARNESS_EVIDENCE_DIR"
}

# -------------------------------------------------------------------- evidence: the self-test ----
# Offline proof of the emitter above — no engine, no container, no daemon. Both harnesses expose it
# as `--self-test`, and each then proves ITS OWN emission end to end by running itself on a leg that
# needs no engine (see the harnesses).
#
# It lives here, beside the code it tests, because the emitter is shared: a copy in each harness
# would be two things to keep true instead of one.
harness_evidence_self_test() {
  local probe root dir rows
  probe="$(mktemp -d "${TMPDIR:-/tmp}/cermet-dev-evidence-selftest.XXXXXX")"
  root="$probe/runs"

  # ---- 1. a run that dies mid-flight leaves its rows and NO final verdict ----------------------
  # The crash-safety contract in one claim: rows are appended as each claim resolves, the final
  # block is written once at the end, and its ABSENCE is the incompleteness marker. No separate
  # state machinery, so a SIGKILL cannot leave a lie behind.
  # The `( … ) 2>/dev/null` wrapper is the subshell absorbing its own "Killed" job-control notice.
  ( CERMET_DEV_EVIDENCE_DIR="$root" bash -c '
      . "$1/dev/lib/harness.sh"
      harness_evidence_open dev/self-test >/dev/null
      leg_header "crash leg" >/dev/null
      ok "first claim" "observed one" >/dev/null
      bad "second claim" "an expectation" "what actually happened" >/dev/null
      kill -9 $$
    ' _ "$HARNESS_REPO_ROOT" || true ) >/dev/null 2>&1

  dir="$(find "$root" -mindepth 1 -maxdepth 1 -type d -name '*-self-test' | head -1)"
  [ -n "$dir" ] || { printf 'SELF-TEST FAIL: a killed run left no evidence directory under %s\n' "$root" >&2; return 1; }
  [ -f "$dir/claims.jsonl" ] || { printf 'SELF-TEST FAIL: the killed run wrote no claims.jsonl\n' >&2; return 1; }
  rows="$(wc -l <"$dir/claims.jsonl")"
  [ "$rows" -eq 2 ] || { printf 'SELF-TEST FAIL: the killed run left %s claim rows, not the 2 it resolved\n' "$rows" >&2; return 1; }
  grep -Fq '"status": "passed"' "$dir/claims.jsonl" && grep -Fq '"status": "failed"' "$dir/claims.jsonl" \
    || { printf 'SELF-TEST FAIL: the killed run did not record both a passed and a failed claim\n' >&2; return 1; }
  grep -Fq 'what actually happened' "$dir/claims.jsonl" \
    || { printf "SELF-TEST FAIL: a failed claim's observed value is missing from the row\n" >&2; return 1; }
  [ ! -e "$dir/run.json" ] || { printf 'SELF-TEST FAIL: a killed run wrote a final verdict anyway\n' >&2; return 1; }
  printf 'SELF-TEST PROOF: a run killed mid-flight leaves its resolved rows and NO final verdict\n'

  # ---- 2. a complete run finalizes, and the final block carries the whole record ---------------
  rm -rf -- "$root"
  CERMET_DEV_EVIDENCE_DIR="$root" bash -c '
    . "$1/dev/lib/harness.sh"
    harness_evidence_open dev/self-test >/dev/null
    leg_header "alpha" >/dev/null
    ok "alpha claim" "observed alpha" >/dev/null
    leg_header "beta" >/dev/null
    skip "beta claim" "nothing to run here" >/dev/null
    # Credential-shaped text, straight down the same path a container command output takes.
    ok "leak probe" "ghp_selftestcredential sk_live_selftestcredential Bearer selftestcredential eyJhbGci.eyJzdWIi.c2ln" >/dev/null
    harness_report "dev/self-test" "leg=selftest" >/dev/null
  ' _ "$HARNESS_REPO_ROOT" >/dev/null 2>&1 || true

  dir="$(find "$root" -mindepth 1 -maxdepth 1 -type d -name '*-self-test' | head -1)"
  [ -f "$dir/run.json" ] || { printf 'SELF-TEST FAIL: a complete run wrote no final verdict block\n' >&2; return 1; }
  local field
  for field in '"schema": "cermet.dev-run.v1"' '"harness": "dev/self-test"' '"run_id"' '"source_commit"' \
    '"source_dirty"' '"context"' '"wall_clock_seconds"' '"claims_summary"' '"exit_code": 0' \
    '"status": "complete"' '"legs"' '"counts"'; do
    grep -Fq "$field" "$dir/run.json" \
      || { printf 'SELF-TEST FAIL: the final block is missing %s\n' "$field" >&2; return 1; }
  done
  grep -Fq 'dev/self-test: 2/2 contract claims held' "$dir/run.json" \
    || { printf 'SELF-TEST FAIL: the final block does not carry the verdict line\n' >&2; return 1; }
  grep -Fq '"leg": "alpha"' "$dir/run.json" && grep -Fq '"leg": "beta"' "$dir/run.json" \
    || { printf 'SELF-TEST FAIL: the final block carries no per-leg summary\n' >&2; return 1; }
  grep -Fq '"leg": "beta"' "$dir/claims.jsonl" \
    || { printf 'SELF-TEST FAIL: claim rows do not name the leg they resolved under\n' >&2; return 1; }
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$dir" <<'PY' || { printf 'SELF-TEST FAIL: the evidence is not valid JSON\n' >&2; return 1; }
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
run = json.loads((d / "run.json").read_text(encoding="utf-8"))
rows = [json.loads(line) for line in (d / "claims.jsonl").read_text(encoding="utf-8").splitlines()]
assert run["counts"] == {"claims": 3, "passed": 2, "failed": 0, "skipped_by_design": 1}, run["counts"]
assert len(rows) == 3, rows
assert {row["status"] for row in rows} == {"passed", "skipped-by-design"}, rows
PY
  fi
  printf 'SELF-TEST PROOF: a complete run finalizes with run id, commit, context, per-leg summaries and its verdict line\n'

  # ---- 3. no credential-shaped text survives into the evidence ---------------------------------
  # Named adversary: T2 — a harness claim whose observed value is provider output quoting the key it
  # rejected. The scrub is at the ONE chokepoint every row crosses, not per call site.
  local leaked
  leaked="$(grep -rniE '(sk|rk)_(live|test)_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|bearer[[:space:]]+[^[:space:]"]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$dir" || true)"
  [ -z "$leaked" ] || { printf 'SELF-TEST FAIL: credential-shaped text reached the evidence: %s\n' "$leaked" >&2; return 1; }
  grep -Fq '<redacted>' "$dir/claims.jsonl" \
    || { printf 'SELF-TEST FAIL: the leak probe was not redacted (it was not even recorded)\n' >&2; return 1; }
  printf 'SELF-TEST PROOF: no credential-shaped fragment survives into the evidence directory\n'

  # ---- 4. two runs inside one second keep two records --------------------------------------------
  # Found by running it: the sitting's container-install self-test drives dev/test-deb twice in a
  # row, both landed in the same second, and the second run's `: >claims.jsonl` erased the first
  # run's evidence. A record that a later run can silently destroy is not a durable record.
  rm -rf -- "$root"
  local run
  for run in 1 2; do
    CERMET_DEV_EVIDENCE_DIR="$root" bash -c '
      . "$1/dev/lib/harness.sh"
      harness_evidence_open dev/self-test >/dev/null
      ok "claim" "run $2" >/dev/null
      harness_report "dev/self-test" >/dev/null
    ' _ "$HARNESS_REPO_ROOT" "$run" >/dev/null 2>&1 || true
  done
  rows="$(find "$root" -mindepth 1 -maxdepth 1 -type d | wc -l)"
  [ "$rows" -eq 2 ] || { printf 'SELF-TEST FAIL: two runs left %s evidence directories, not 2\n' "$rows" >&2; return 1; }
  printf 'SELF-TEST PROOF: two runs of one harness inside the same second keep two records\n'

  # ---- 5. the off switch is real ----------------------------------------------------------------
  rm -rf -- "$root"
  CERMET_DEV_EVIDENCE=0 CERMET_DEV_EVIDENCE_DIR="$root" bash -c '
    . "$1/dev/lib/harness.sh"
    harness_evidence_open dev/self-test >/dev/null
    ok "a claim nobody records" >/dev/null
    harness_report "dev/self-test" >/dev/null
  ' _ "$HARNESS_REPO_ROOT" >/dev/null 2>&1 || true
  [ ! -e "$root" ] || { printf 'SELF-TEST FAIL: CERMET_DEV_EVIDENCE=0 wrote evidence anyway\n' >&2; return 1; }
  printf 'SELF-TEST PROOF: CERMET_DEV_EVIDENCE=0 writes nothing; CERMET_DEV_EVIDENCE_DIR redirects the root\n'

  rm -rf -- "$probe"
}

# ------------------------------------------------------------------------------ container engine --
# `$CONTAINER_ENGINE` (default podman), driven through the docker-compatible CLI only. Rootful,
# because a rootless userns changes exactly the things these harnesses assert — the credential
# ramfs, the setgid runtime dirs, the service uid — and would prove a different box than the one a
# user installs on. `$CERMET_HARNESS_ENGINE_CMD` overrides the whole invocation.
harness_engine_init() {
  ENGINE="${CONTAINER_ENGINE:-podman}"
  if [ -n "${CERMET_HARNESS_ENGINE_CMD:-}" ]; then
    read -r -a ENGINE_CMD <<<"$CERMET_HARNESS_ENGINE_CMD"
  elif [ "$ENGINE" = podman ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
    ENGINE_CMD=(sudo "$ENGINE")
  else
    ENGINE_CMD=("$ENGINE")
  fi
}

engine() { "${ENGINE_CMD[@]}" "$@"; }

harness_engine_available() { command -v "$ENGINE" >/dev/null 2>&1; }

# --------------------------------------------------------------------------------------- cleanup --
HARNESS_CONTAINERS=()
HARNESS_KEEP=0

harness_cleanup() {
  local status=$?
  if [ "$HARNESS_KEEP" -eq 1 ]; then
    [ "${#HARNESS_CONTAINERS[@]}" -eq 0 ] || printf '\n--keep: containers left up: %s\n' "${HARNESS_CONTAINERS[*]}"
    return "$status"
  fi
  local name
  for name in ${HARNESS_CONTAINERS[@]+"${HARNESS_CONTAINERS[@]}"}; do
    engine rm -f "$name" >/dev/null 2>&1 || true
  done
  return "$status"
}

# The base image both harnesses boot: the stock systemd image plus `sudo`, which is not part of
# anything Cermet ships but IS how a human installs a package and what `visudo` lives in. Built once
# and cached under a local tag, because paying an `apt-get` on every run is minutes a day.
# Rebuild it by hand with `<engine> rmi localhost/cermet-harness-base:24.04`.
HARNESS_BASE_IMAGE=localhost/cermet-harness-base:24.04

harness_ensure_base_image() { # upstream-image
  engine image exists "$HARNESS_BASE_IMAGE" >/dev/null 2>&1 && return 0
  printf 'building the cached harness base image (%s + sudo)…\n' "$1"
  # `run` + `commit` rather than `build`: the build path sets up its own network namespace, which
  # this box's nested-container networking refuses, while `run` (the same path both harnesses
  # already depend on) works. One image layer either way.
  local builder="cermet-harness-base-build-$$"
  engine rm -f "$builder" >/dev/null 2>&1 || true
  engine run --name "$builder" "$1" bash -c \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo && rm -rf /var/lib/apt/lists/*' >/dev/null
  # `commit` records the command the builder container ran, so the systemd entrypoint has to be put
  # back explicitly — otherwise the cached image boots `apt-get` as PID 1.
  local original_cmd
  original_cmd="$(engine image inspect "$1" --format '{{json .Config.Cmd}}')"
  engine commit -q --change "CMD $original_cmd" "$builder" "$HARNESS_BASE_IMAGE" >/dev/null
  engine rm -f "$builder" >/dev/null 2>&1 || true
}

# Boot a privileged systemd container and wait for PID 1 to settle.
#
# NOTE WHAT IS *NOT* HERE. This used to run `mount --make-rshared /` before installing,
# because podman/docker start containers with private mount propagation and systemd's credential
# handoff — a mount MOVE onto /run/credentials/<unit> — is invisible to PID 1 without shared
# propagation. That line was the harness papering over a real product defect: every user installing
# into a container hit the same crash loop and had no such line. The prerequisite is now converged
# by the SHIPPED `cermet-credential-env.service`, and these containers are left exactly as the
# engine hands them over, so the container legs prove the product rather than the harness.
harness_boot_systemd_container() { # name image [extra engine run args…]
  local name="$1" image="$2"
  shift 2
  HARNESS_CONTAINERS+=("$name")
  engine rm -f "$name" >/dev/null 2>&1 || true
  engine run -d --name "$name" --systemd=always --privileged "$@" "$image" >/dev/null

  local waited=0 state
  while :; do
    state="$(engine exec "$name" systemctl is-system-running 2>/dev/null || true)"
    [ "$state" = running ] || [ "$state" = degraded ] || [ "$state" = maintenance ] || {
      waited=$((waited + 1))
      [ "$waited" -lt 60 ] || { printf 'REFUSED: systemd never came up in %s (last state: %s)\n' "$name" "${state:-unreachable}" >&2; return 1; }
      sleep 1
      continue
    }
    break
  done
}
