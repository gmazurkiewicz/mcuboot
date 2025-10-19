cmake_minimum_required(VERSION 3.25)
project(first_fuzz_project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build type" FORCE)

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
