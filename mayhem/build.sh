#!/usr/bin/env bash
#
# mayhem/build.sh — build the openvpn3 fuzz harnesses and upstream's coreUnitTests.
#
# openvpn3 is a header-only C++20 library: there is no library to build first. Each harness in
# mayhem/harnesses/ includes the headers it fuzzes, so compiling the harness with $SANITIZER_FLAGS
# instruments the project code too. The only out-of-header source, openvpn/crypto/data_epoch.cpp,
# is compiled with the same flags and linked into every binary.
#
# Outputs (all under mayhem/build/, gitignored by mayhem/.gitignore):
#   mayhem/build/bin/<harness>             libFuzzer target (Mayhemfile cmd)
#   mayhem/build/bin/<harness>-standalone  run-once reproducer ($STANDALONE_FUZZ_MAIN)
#   mayhem/build/tests/coreUnitTests       upstream unit tests (normal flags), run by mayhem/test.sh
#
# Dependencies are Debian packages installed by mayhem/Dockerfile (OpenSSL, lz4, asio, fmt, jsoncpp,
# xxHash, LZO, libcap, libnl-genl-3, googletest) plus rapidcheck, prebuilt at upstream's pinned commit
# under /opt/toolchains/deps/rapidcheck-ff6af6fc; nothing is fetched here, so the build re-runs offline.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

OUT="$SRC/mayhem/build"
GEN="$OUT/gen"
OBJ="$OUT/obj"
BIN="$OUT/bin"
TST="$OUT/tests"
mkdir -p "$GEN" "$OBJ/fuzz" "$OBJ/plain" "$OBJ/tests" "$BIN" "$TST"

HARNESSES=(
  fuzz_addrpair
  fuzz_eval_config
  fuzz_pktstream
  fuzz_decompress
  fuzz_push_options
  fuzz_http
  fuzz_proxy_auth
  fuzz_challenge
  fuzz_keys
  fuzz_proto
  fuzz_psid_cookie
  fuzz_oob_probe
  fuzz_ip_packet
  fuzz_control_msg
)

# The core defines upstream's cmake/findcoredeps.cmake sets for a Linux OpenSSL build.
CORE_DEFS=(-DASIO_STANDALONE -DUSE_ASIO -DHAVE_LZ4 -DUSE_OPENSSL -DHAVE_JSONCPP -DOPENVPN_FORCE_TUN_NULL)
INCS=(-I"$SRC" -I"$SRC/mayhem/harnesses" -I"$GEN" -I/usr/include/jsoncpp)
LIBS=(-lssl -lcrypto -llz4 -lfmt -ljsoncpp -lpthread)

# Upstream's test PKI (test/ssl/) as string constants for the protocol harnesses.
bash "$SRC/mayhem/gen_test_keys.sh" "$GEN"

# ---- 1) fuzz harnesses (sanitized, DWARF 3) ---------------------------------------------------
read -r -a SAN <<<"$SANITIZER_FLAGS"
read -r -a DBG <<<"$DEBUG_FLAGS"
FUZZ_CXXFLAGS=(-std=c++20 -O1 "${SAN[@]}" "${DBG[@]}" -fsanitize=fuzzer-no-link "${CORE_DEFS[@]}" "${INCS[@]}")

$CC "${SAN[@]}" "${DBG[@]}" -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
# The standalone driver is C: compiled as C so its LLVMFuzzerTestOneInput reference is not mangled.
$CC "${SAN[@]}" "${DBG[@]}" -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

compile_fuzz() { # <name>
  if [ "$1" = data_epoch ]; then src="$SRC/openvpn/crypto/data_epoch.cpp"; else src="$SRC/mayhem/harnesses/$1.cpp"; fi
  $CXX "${FUZZ_CXXFLAGS[@]}" -c "$src" -o "$OBJ/fuzz/$1.o"
}
# Without sanitizers nothing provides the SanCov callbacks for the standalone reproducers, so they
# get their own uninstrumented objects; otherwise both link the same objects.
compile_plain() {
  if [ "$1" = data_epoch ]; then src="$SRC/openvpn/crypto/data_epoch.cpp"; else src="$SRC/mayhem/harnesses/$1.cpp"; fi
  $CXX -std=c++20 -O1 "${DBG[@]}" "${CORE_DEFS[@]}" "${INCS[@]}" -c "$src" -o "$OBJ/plain/$1.o"
}
# Runs <fn> on each name, MAYHEM_JOBS at a time; fails if any job failed.
run_parallel() { # <fn> <names...>
  local fn="$1"; shift
  local running=0 failed=0
  for n in "$@"; do
    "$fn" "$n" &
    running=$((running + 1))
    if [ "$running" -ge "$MAYHEM_JOBS" ]; then
      wait -n || failed=1
      running=$((running - 1))
    fi
  done
  while [ "$running" -gt 0 ]; do wait -n || failed=1; running=$((running - 1)); done
  return "$failed"
}

run_parallel compile_fuzz data_epoch "${HARNESSES[@]}"
SA_OBJ="$OBJ/fuzz"
if [ -z "$SANITIZER_FLAGS" ]; then
  run_parallel compile_plain data_epoch "${HARNESSES[@]}"
  SA_OBJ="$OBJ/plain"
fi

for h in "${HARNESSES[@]}"; do
  $CXX "${SAN[@]}" "${DBG[@]}" $LIB_FUZZING_ENGINE "$OBJ/fuzz/$h.o" "$OBJ/fuzz/data_epoch.o" "$OBJ/lsan_off.o" \
    "${LIBS[@]}" -o "$BIN/$h"
  $CXX "${SAN[@]}" "${DBG[@]}" "$SA_OBJ/$h.o" "$SA_OBJ/data_epoch.o" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" \
    "${LIBS[@]}" -o "$BIN/$h-standalone"
done

# ---- 2) upstream unit tests (normal flags) -----------------------------------------------------
# test/unittests/CMakeLists.txt's coreUnitTests as upstream builds it on Linux with OpenSSL: every
# source in its core list, the OpenSSL list, the Linux (sitnl/sockbuf), UNIX and Linux-server lists,
# plus openvpn/crypto/data_epoch.cpp. Same defines (CORE_TEST_DEFINES, -DHAVE_XXHASH, -DHAVE_LZO,
# -DENABLE_OVPNDCO), the PROTO_* defines on test_proto.cpp only, and the same libraries (xxHash, LZO,
# libcap, libnl-genl-3, googletest, rapidcheck + rapidcheck_gtest). Upstream's CMake is not driven
# directly because it FetchContent-downloads googletest and rapidcheck; googletest comes from Debian
# and rapidcheck from the pinned prefix the Dockerfile builds.
UNIT_TESTS=(
  # core list
  core_tests test_acc test_alignment test_acc_certcheck test_addrlist test_addrpair
  test_route_emulation test_log test_comp test_b64 test_verify_x509_name test_ssl test_sslctx
  test_continuation test_pushlex test_crypto test_optfilt test_clamp_typerange test_pktstream
  test_remotelist test_optional_ref test_relack test_oob_probe test_oob_probe_wrap
  test_serverprober test_http_proxy test_peer_fingerprint test_safestr test_numeric_cast test_dns
  test_header_deps test_capture test_cleanup test_crypto_hashstr test_csum test_format
  test_headredact test_hostport test_ip test_ostream_containers test_parseargv test_path
  test_pktid_control test_pktid_data test_prefixlen test_randapi test_randbytestore
  test_intrinsic_type test_rc test_route test_reliable test_splitlines test_loggingmixin
  test_statickey test_streq test_time test_make_rc test_typeindex test_tun_builder test_userpass
  test_validatecreds test_weak test_cliopt test_string test_buffer test_proto test_peerid
  # OpenSSL
  test_openssl_x509certinfo test_openssl_authcert test_opensslpki test_openssl_misc test_session_id
  # Linux
  test_sitnl test_sockbuf
  # UNIX
  test_buffer_ip test_cpu_time test_misc_unix test_pipe test_psid_cookie
  # Linux server engine
  test_tunsink test_simpleman test_udptransserv test_peerroutes test_tunreal test_netpolicy
  test_handler_man test_openvpn_server test_dcoserv test_servconf
)
RC_DIR=/opt/toolchains/deps/rapidcheck-ff6af6fc
TEST_DEFS=(-DUNIT_TEST -DOPENVPN_RC_NOTIFY -DOPENVPN_ENABLE_ASSERT
           "-DUNITTEST_SOURCE_DIR=\"$SRC/test/unittests/\"" -DHAVE_XXHASH -DHAVE_LZO -DENABLE_OVPNDCO)
TEST_INCS=(-I"$RC_DIR/include" $(pkg-config --cflags libnl-genl-3.0))
# PROTO_ITER is 1000 instead of upstream's 1000000 to keep the suite fast; test.sh filters the two
# tests whose counts depend on the full iteration count. -DQUIET keeps test_proto from switching on its
# VERBOSE mode (ITER <= 10000 does), which no longer compiles.
PROTO_DEFS=(-DPROTO_N_THREADS=-1 -DPROTO_RENEG=900 -DPROTO_ITER=1000 -DQUIET "-DTEST_KEYCERT_DIR=\"$SRC/test/ssl/\"")
read -r -a COV <<<"$COVERAGE_FLAGS"
compile_test() {
  local extra=()
  [ "$1" = test_proto ] && extra=("${PROTO_DEFS[@]}")
  $CXX -std=c++20 -O1 "${COV[@]}" "${CORE_DEFS[@]}" "${TEST_DEFS[@]}" "${extra[@]}" "${INCS[@]}" "${TEST_INCS[@]}" \
    -c "$SRC/test/unittests/$1.cpp" -o "$OBJ/tests/$1.o"
}
compile_test_epoch() {
  $CXX -std=c++20 -O1 "${COV[@]}" "${CORE_DEFS[@]}" "${TEST_DEFS[@]}" "${INCS[@]}" "${TEST_INCS[@]}" \
    -c "$SRC/openvpn/crypto/data_epoch.cpp" -o "$OBJ/tests/data_epoch.o"
}
run_parallel compile_test "${UNIT_TESTS[@]}"
compile_test_epoch
objs=()
for t in "${UNIT_TESTS[@]}"; do objs+=("$OBJ/tests/$t.o"); done
$CXX "${COV[@]}" "${objs[@]}" "$OBJ/tests/data_epoch.o" -L"$RC_DIR/lib" -lrapidcheck -lgmock -lgtest \
  "${LIBS[@]}" -lxxhash -llzo2 -lcap $(pkg-config --libs libnl-genl-3.0) -o "$TST/coreUnitTests"

echo "build.sh: built ${#HARNESSES[@]} harnesses into $BIN and $TST/coreUnitTests"
