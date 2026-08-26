#!/bin/bash

set -e

# LeakSanitizer needs ptrace, which isn't available in this container.
export ASAN_OPTIONS=detect_leaks=0

cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 -DFUZZTEST_FUZZING_MODE=on -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build
cmake --build build

# The unit tests double as a smoke test for the harness itself.
build/fuzz_test --gtest_filter='McuBootSuite.Upgrade*:McuBootSuite.Permanent*:McuBootSuite.Swap*'

# --fuzz= alone runs indefinitely; bound it so this script terminates.
FUZZ_FOR=${FUZZ_FOR:-120s}
for target in \
    McuBootSuite.InvokeBootGo \
    McuBootSuite.InvokeBootUpgradeLifecycle \
    McuBootSuite.BootSurvivesPowerCutsDuringSwap \
    McuBootSuite.BootNeverRunsUnauthenticatedImage
do
    build/fuzz_test --fuzz_for="${FUZZ_FOR}" --fuzz="${target}"
done
