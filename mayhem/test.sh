#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
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

# Runs upstream's googletest suite (test/unittests/, coreUnitTests) that mayhem/build.sh built with
# normal flags from upstream's full Linux/OpenSSL source list: known-answer and rapidcheck property
# tests of the buffer, string, crypto, SSL, option/push-lexer, address, HTTP-proxy, compression,
# tls-crypt(-v2)/psid-cookie/OOB-probe, app-custom-control/certcheck, protocol and server code.
# The sitnl/sockbuf/tunreal/netpolicy tests that need CAP_NET_ADMIN skip themselves (counted as skipped).
RUNNER="$SRC/mayhem/build/tests/coreUnitTests"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing -- run mayhem/build.sh first" >&2
  emit_ctrf "googletest" 0 1 0
  exit 1
fi

# The DynamicTlsCryptRekeys* proto tests count key renegotiations, which only happen within upstream's
# default 1,000,000 handshake iterations; build.sh builds test_proto with 1,000 to keep the suite fast.
FILTER='-ProtoUnitTest.DynamicTlsCryptRekeys*'

log="$(mktemp)"
xml="$(mktemp --suffix=.xml)"
( cd "$SRC/test/unittests" && "$RUNNER" --gtest_filter="$FILTER" --gtest_output="xml:$xml" ) >"$log" 2>&1
rc=$?
tail -n 30 "$log"

# Counts come from googletest's XML report; a runner that produced no report counts as one failure.
read -r total failures errors skipped < <(python3 - "$xml" <<'PY' 2>/dev/null || echo "0 1 0 0"
import sys, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot()
# googletest's root element has no "skipped" count: a GTEST_SKIP()ed case is a <testcase result="skipped">.
skipped = sum(1 for t in r.iter("testcase") if t.get("result") == "skipped")
print(r.get("tests", "0"), r.get("failures", "0"), r.get("errors", "0"), skipped)
PY
)
rm -f "$log" "$xml"
failed=$(( failures + errors ))
if [ "$total" -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
  failed=$(( failed + 1 ))   # runner crashed / exited non-zero / ran nothing
fi
passed=$(( total - failures - errors - skipped ))
[ "$passed" -ge 0 ] || passed=0
emit_ctrf "googletest" "$passed" "$failed" "$skipped"
