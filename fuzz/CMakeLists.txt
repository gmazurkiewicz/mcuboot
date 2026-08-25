cmake_minimum_required(VERSION 3.25)
project(bootutil_fuzz)

set(CMAKE_CXX_STANDARD 17)

# Must be an optimized build: at -O0 the inline functions of FuzzTest's own
# headers are emitted as weak symbols in this coverage-instrumented target and
# preempt FuzzTest's uninstrumented copies, so its sancov cmp hooks recurse into
# themselves until the stack overflows.
if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-fsanitize=address,undefined -fno-sanitize=null,alignment -fno-sanitize-recover=address,undefined)
add_link_options(-fsanitize=address,undefined)

include(FetchContent)
set(FUZZTEST_VERSION "20fad20ee3f393c836e0015523aae0bff8ce9693")
FetchContent_Declare(fuzztest
  GIT_REPOSITORY    https://github.com/google/fuzztest.git
  GIT_TAG           ${FUZZTEST_VERSION}
)
set(FUZZTEST_FUZZING_MODE ON CACHE BOOL "Enable FuzzTest fuzzing mode")
FetchContent_MakeAvailable(fuzztest)

# Must come before the code under test is added, otherwise bootutil/mbedtls are
# built without coverage instrumentation and the fuzzer runs blind.
fuzztest_setup_fuzzing_flags()

# Source-based coverage for the code under test only; FuzzTest and its
# dependencies are added above and stay uninstrumented. See coverage.sh.
option(FUZZ_COVERAGE "Emit clang source-based coverage data" OFF)
if(FUZZ_COVERAGE)
  add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
  add_link_options(-fprofile-instr-generate)
endif()

add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../boot/bootutil
  ${CMAKE_CURRENT_BINARY_DIR}/bootutil
  EXCLUDE_FROM_ALL
)

target_include_directories(bootutil PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bootutil PRIVATE mbedtls)

set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable MbedTLS programs")
set(ENABLE_TESTING OFF CACHE BOOL "Disable MbedTLS tests")

add_subdirectory(
  ${CMAKE_CURRENT_SOURCE_DIR}/../ext/mbedtls
  ${CMAKE_CURRENT_BINARY_DIR}/mbedtls
  EXCLUDE_FROM_ALL
)

enable_testing()
include(GoogleTest)

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
