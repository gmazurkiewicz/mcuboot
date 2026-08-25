#!/bin/bash

set -e

cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 -DFUZZTEST_FUZZING_MODE=off -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build
cmake --build build
# build/fuzz_test --fuzz=McuBootSuite.InvokeBootGo
build/fuzz_test
