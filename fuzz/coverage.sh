#!/bin/bash
#
# Builds a coverage-instrumented copy of the fuzz target, exercises it, and
# renders a report showing each source line with its execution count.
# Run it inside the container: ./build.sh ./coverage.sh

set -e

# LeakSanitizer needs ptrace, which isn't available in this container.
export ASAN_OPTIONS=detect_leaks=0

BUILD_DIR=${BUILD_DIR:-build-coverage}
FUZZ_FOR=${FUZZ_FOR:-10s}
PROFRAW_DIR=${BUILD_DIR}/profraw
REPORT_DIR=${BUILD_DIR}/report

cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 -DFUZZTEST_FUZZING_MODE=on -DFUZZ_COVERAGE=on -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}"

rm -rf "${PROFRAW_DIR}" "${REPORT_DIR}"
mkdir -p "${PROFRAW_DIR}"

run() {
    LLVM_PROFILE_FILE="${PROFRAW_DIR}/%m-%p.profraw" "${BUILD_DIR}/fuzz_test" "$@"
}

# SanitizerSuite aborts on purpose, which would discard its profile.
run '--gtest_filter=-SanitizerSuite.*'
run --fuzz_for="${FUZZ_FOR}" --fuzz=McuBootSuite.InvokeBootGo
run --fuzz_for="${FUZZ_FOR}" --fuzz=McuBootSuite.InvokeBootUpgradeLifecycle
run --fuzz_for="${FUZZ_FOR}" --fuzz=McuBootSuite.BootSurvivesPowerCutsDuringSwap
run --fuzz_for="${FUZZ_FOR}" --fuzz=McuBootSuite.BootNeverRunsUnauthenticatedImage

llvm-profdata-19 merge -sparse "${PROFRAW_DIR}"/*.profraw -o "${BUILD_DIR}/fuzz.profdata"

cov_args=(
    "${BUILD_DIR}/fuzz_test"
    "-instr-profile=${BUILD_DIR}/fuzz.profdata"
    '-ignore-filename-regex=(_deps|ext/mbedtls[^/]*)/'
)

llvm-cov-19 report "${cov_args[@]}"
llvm-cov-19 show "${cov_args[@]}" -show-line-counts-or-regions > "${BUILD_DIR}/coverage.txt"
llvm-cov-19 show "${cov_args[@]}" -show-line-counts-or-regions -format=html -output-dir="${REPORT_DIR}"

echo
echo "Per-line execution counts: ${BUILD_DIR}/coverage.txt"
echo "HTML report:               ${REPORT_DIR}/index.html"
