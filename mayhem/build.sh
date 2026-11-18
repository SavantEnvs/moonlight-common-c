#!/usr/bin/env bash
#
# mayhem/build.sh — builds moonlight-common-c with the sanitizers, one libFuzzer binary + one
# standalone reproducer per harness, and the known-answer self-test that mayhem/test.sh runs.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Dependencies upstream vendors as (empty) git submodules, fetched by mayhem/Dockerfile at the commits
# .gitmodules pins: enet (static, uninstrumented) and nanors (sources, compiled below).
ENET=$(echo /opt/toolchains/deps/enet-*)
NANORS=$(echo /opt/toolchains/deps/nanors-*)/src
[ -f "$ENET/lib/libenet.a" ] && [ -f "$NANORS/rs.c" ]

B="$SRC/mayhem/build"
mkdir -p "$B/fuzz" "$B/test"

# Upstream's CMake build: C11, the library defines HAS_SOCKLEN_T, sources are src/*.c plus three nanors files.
# LC_DEBUG enables upstream's LC_ASSERTs; LC_FUZZING is upstream's own switch that turns off the ones that
# check data coming from the host (Platform.h) and the frame-order / first-frame timeout rejections.
INC=(-I"$SRC/src" -I"$ENET/include" -I"$NANORS" -I"$NANORS/deps" -I"$NANORS/deps/obl")
COMMON=(-std=gnu11 -DHAS_SOCKLEN_T -fPIC "${INC[@]}")
SRCS=("$SRC"/src/*.c "$NANORS/rs.c" "$NANORS/deps/obl/oblas_common.c" "$NANORS/deps/obl/oblas_lite.c")

obj_name() { echo "$(basename "$(dirname "$1")")_$(basename "${1%.c}").o"; }

# 1) Fuzz/standalone library: sanitized, DWARF 3, coverage via -fsanitize=fuzzer-no-link.
#    Every file is built with the same flags so ccache can reuse it between runs.
build_lib() { # <dir> <flags...>
    local dir=$1; shift
    local pids=() f
    for f in "${SRCS[@]}"; do
        "$CC" "${COMMON[@]}" "$@" -c "$f" -o "$dir/$(obj_name "$f")" &
        pids+=($!)
        if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
    done
    local p; for p in "${pids[@]}"; do wait "$p"; done
    rm -f "$dir/libmoonlight.a"
    ar rcs "$dir/libmoonlight.a" "$dir"/*.o
}
build_lib "$B/fuzz" -O1 -DLC_DEBUG -DLC_FUZZING $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link

# 2) Harnesses: fuzzer binary and standalone reproducer, LSan switched off at build time (lsan_off.cc).
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

LIBS=("$B/fuzz/libmoonlight.a" "$ENET/lib/libenet.a" -lssl -lcrypto -lpthread -lm)
for h in fuzz_rtsp_message fuzz_rtp_video fuzz_rtp_audio fuzz_rtsp_handshake fuzz_control_stream fuzz_stun_response; do
    "$CC" "${COMMON[@]}" -O1 -DLC_DEBUG -DLC_FUZZING $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
        -c "$SRC/mayhem/$h.c" -o "$B/$h.o"
    "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "$B/lsan_off.o" "${LIBS[@]}" -o "/mayhem/$h"
    "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$h.o" "$B/standalone_main.o" "$B/lsan_off.o" "${LIBS[@]}" -o "/mayhem/$h-standalone"
done

# 3) Known-answer self-test for mayhem/test.sh: the same sources, NORMAL flags (no sanitizers, no LC_DEBUG),
#    dynamically linked so the oracle can't be satisfied by a program that just exits.
mkdir -p "$B/test/lib"
build_lib "$B/test/lib" -O2 -DNDEBUG $COVERAGE_FLAGS
"$CC" "${COMMON[@]}" -O2 -DNDEBUG $COVERAGE_FLAGS "$SRC/mayhem/selftest.c" "$B/test/lib/libmoonlight.a" "$ENET/lib/libenet.a" \
    -lssl -lcrypto -lpthread -lm -o /mayhem/moonlight_selftest
