cmake_minimum_required(VERSION 3.25)
project(bootutil_fuzz)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build type" FORCE)

# Continuous fuzzing mode (FUZZTEST_FUZZING_MODE=on) needs FuzzTest's own
# SanitizerCoverage instrumentation (added later by
# fuzztest_setup_fuzzing_flags()); applying ASan+UBSan globally here too
# would instrument fuzztest's own comparison-tracing runtime, which then
# recurses into itself via __sanitizer_cov_trace_const_cmp8 and
# stack-overflows -- an upstream FuzzTest/SanitizerCoverage interaction, not
# a bug in mcuboot. Confirmed by direct test: applying these flags
# unconditionally (alongside fuzztest_setup_fuzzing_flags(), matching a
# working setup from another project that doesn't run continuous
# coverage-guided fuzzing) reproduces the exact same recursion once
# FUZZTEST_FUZZING_MODE=on is actually used. So this global block only
# applies in unit-test mode (FUZZTEST_FUZZING_MODE unset/off), which needs
# no coverage instrumentation at all, and is what actually runs the
# deterministic regression tests (UpgradeConfirmedSwapPersists etc.) and a
# single default execution of each FUZZ_TEST's seeds.
#
# Applied via add_compile_options()/add_link_options() before any
# add_subdirectory(), so bootutil/mbedtls/fuzztest/its transitive deps
# (abseil, antlr) are ALL instrumented identically -- mixing instrumented
# and uninstrumented compiles of the same header-only template code (e.g.
# absl::flat_hash_map's SwissTable internals) across translation units
# previously caused an ODR-related SEGV in
# absl::container_internal::GroupSse2Impl when only fuzz_test.cpp itself
# was sanitized.
# -fno-sanitize=null,alignment: excludes UBSan checks that false-positive
# inside clang's own SSE2 intrinsic headers (e.g. _mm_loadu_si128 in
# emmintrin.h), unrelated to bugs in mcuboot itself.
# -fno-sanitize-recover so a detected bug aborts the process instead of
# just printing a warning and continuing.
if (NOT FUZZTEST_FUZZING_MODE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize=null,alignment -fno-sanitize-recover=address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif ()

add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../boot/bootutil
  ${CMAKE_CURRENT_BINARY_DIR}/bootutil
  EXCLUDE_FROM_ALL
)

target_include_directories(bootutil PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bootutil PRIVATE mbedtls)

add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/fuzztest
  ${CMAKE_CURRENT_BINARY_DIR}/fuzztest
  EXCLUDE_FROM_ALL
)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable MbedTLS programs")
set(ENABLE_TESTING OFF CACHE BOOL "Disable MbedTLS tests")

add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/mbedtls
  ${CMAKE_CURRENT_BINARY_DIR}/mbedtls
  EXCLUDE_FROM_ALL
)

enable_testing()
include(GoogleTest)
fuzztest_setup_fuzzing_flags()

add_executable(
  fuzz_test
  fuzz_test.cpp
  storage/flash_map.c
  keys.c
)

target_include_directories(fuzz_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(fuzz_test PRIVATE bootutil)
target_link_libraries(fuzz_test PRIVATE mbedtls)

link_fuzztest(fuzz_test)
gtest_discover_tests(fuzz_test)
