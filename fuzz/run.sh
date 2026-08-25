#!/bin/bash

set -e

# LeakSanitizer needs ptrace, which isn't available in this container.
export ASAN_OPTIONS=detect_leaks=0

cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 -DFUZZTEST_FUZZING_MODE=on -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build
cmake --build build
# --fuzz= alone runs indefinitely; bound it so this script terminates.
# build/fuzz_test --fuzz_for=30s --fuzz=McuBootSuite.InvokeBootGo
build/fuzz_test --fuzz_for=300s --fuzz=McuBootSuite.InvokeBootUpgradeLifecycle
#build/fuzz_test
