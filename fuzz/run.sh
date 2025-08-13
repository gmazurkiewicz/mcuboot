
#!/bin/bash

set -e

cmake -G Ninja -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 -DFUZZTEST_FUZZING_MODE=on -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -S . -B build
cmake --build build
build/fuzz_test --fuzz=MyTestSuite.IntegerAdditionCommutes
