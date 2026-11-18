#!/usr/bin/env bash
#
# mayhem/test.sh - runs the known-answer self-test built by mayhem/build.sh (/mayhem/moonlight_selftest,
# normal flags, dynamically linked) and reports its counts as CTRF. exit 0 = pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER=/mayhem/moonlight_selftest
MIN_TESTS=41
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER (mayhem/build.sh should have built it)" >&2
  emit_ctrf "moonlight-selftest" 0 1 0
  exit 1
fi

out=$("$RUNNER" 2>&1); rc=$?
printf '%s\n' "$out"
line=$(printf '%s\n' "$out" | grep -E '^SELFTEST passed=[0-9]+ failed=[0-9]+$' | tail -n1)
if [ -z "$line" ]; then
  echo "no SELFTEST summary line from $RUNNER (rc=$rc)" >&2
  emit_ctrf "moonlight-selftest" 0 1 0
  exit 1
fi
passed=${line#SELFTEST passed=}; passed=${passed%% *}
failed=${line##*failed=}
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ "$passed" -lt "$MIN_TESTS" ]; then failed=$(( failed + MIN_TESTS - passed )); fi
emit_ctrf "moonlight-selftest" "$passed" "$failed" 0
