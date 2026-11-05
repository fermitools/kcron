# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
# test/CMakeLists.txt - Unit test executables for kcron
#
# Design rationale
# ----------------
# Every test executable compiles the production headers directly rather than
# linking a shared OBJECT library. This ensures coverage instrumentation is
# applied to every translation unit under test; objects compiled without
# --coverage produce no .gcno data and silently drop out of reports.
#
# The production path/keytab logic lives in headers (kcron_filename.h,
# kcron_empty_keytab_file.h), so the tests include those headers directly.
# Each binary is also kept self-contained so coverage data is always emitted.
include(CTest)

# ============================================================================
# Shared include paths
# ============================================================================
set(TEST_INCLUDES "${CMAKE_SOURCE_DIR}/src/C"
                  "${CMAKE_BINARY_DIR}/src/C" "${CMAKE_CURRENT_SOURCE_DIR}")

# ============================================================================
# Coverage detection
# ============================================================================
set(HAVE_COVERAGE_TOOLS OFF)

# genhtml ships with lcov and is required by both toolchains, so search it
# once here (not only inside the GCC branch) so the Clang branch can use it.
find_program(LCOV_EXEC lcov)
find_program(GENHTML_EXEC genhtml)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

  if(LCOV_EXEC AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS -g --coverage -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
                               -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS --coverage)

    message(STATUS "Coverage enabled: GCC + lcov")
  endif()

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

  find_program(LLVM_PROFDATA_EXEC llvm-profdata)
  find_program(LLVM_COV_EXEC llvm-cov)

  if(LLVM_PROFDATA_EXEC AND LLVM_COV_EXEC AND GENHTML_EXEC)
    set(HAVE_COVERAGE_TOOLS ON)

    set(COVERAGE_COMPILE_FLAGS -g -fprofile-instr-generate -fcoverage-mapping
                               -fdebug-prefix-map=${CMAKE_BINARY_DIR}=.
                               -fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.)

    set(COVERAGE_LINK_FLAGS -fprofile-instr-generate)

    message(STATUS "Coverage enabled: Clang + llvm-cov")
  endif()

endif()

# Internal helper: apply coverage flags (and disable LTO, which would otherwise
# strip the instrumentation) to a target when tools are present.
macro(add_coverage_flags target)
  if(HAVE_COVERAGE_TOOLS)
    target_compile_options(${target} PRIVATE ${COVERAGE_COMPILE_FLAGS} -fno-lto)
    target_link_options(${target} PRIVATE ${COVERAGE_LINK_FLAGS} -fno-lto)
  endif()
endmacro()

# ============================================================================
# test_kcron_filename
# ============================================================================
# Tests get_client_dirname() and get_filenames() from kcron_filename.h.

add_executable(test_kcron_filename test_kcron_filename.c)

target_include_directories(test_kcron_filename PRIVATE ${TEST_INCLUDES})
add_coverage_flags(test_kcron_filename)

add_test(NAME test_kcron_filename COMMAND test_kcron_filename)

# ============================================================================
# test_kcron_keytab
# ============================================================================
# Tests write_empty_keytab() from kcron_empty_keytab_file.h.

add_executable(test_kcron_keytab test_kcron_keytab.c)

target_include_directories(test_kcron_keytab PRIVATE ${TEST_INCLUDES})
add_coverage_flags(test_kcron_keytab)

add_test(NAME test_kcron_keytab COMMAND test_kcron_keytab)

# ============================================================================
# test_client_keytab_name
# ============================================================================
# Integration test: run the built client-keytab-name binary and verify its
# stdout matches the path derived from the calling UID.

add_executable(test_client_keytab_name test_client_keytab_name.c)

target_include_directories(test_client_keytab_name PRIVATE ${TEST_INCLUDES})
target_compile_definitions(test_client_keytab_name PRIVATE
                           "CLIENT_KEYTAB_NAME_BIN=\"$<TARGET_FILE:client-keytab-name>\"")
add_coverage_flags(test_client_keytab_name)

add_test(NAME test_client_keytab_name COMMAND test_client_keytab_name)

# Instrument the client-keytab-name binary itself so its main() and the path
# helpers it calls are captured by the coverage report when the integration
# test executes it. Gated on the coverage toolchain just like the test binaries.
if(HAVE_COVERAGE_TOOLS)
  add_coverage_flags(client-keytab-name)
endif(HAVE_COVERAGE_TOOLS)


# ============================================================================
# test_kcron_caps
# ============================================================================
# Tests the libcap(3) helpers from kcron_caps.h: disable_capabilities(),
# print_cap_error() and enable_capabilities(). The privilege-free helpers are
# called directly; enable_capabilities() is checked via a grandchild so its
# documented exit-on-failure contract is verified without failing the test.

add_executable(test_kcron_caps test_kcron_caps.c)

target_include_directories(test_kcron_caps PRIVATE ${TEST_INCLUDES})
add_coverage_flags(test_kcron_caps)
target_link_libraries(test_kcron_caps PRIVATE cap)

add_test(NAME test_kcron_caps COMMAND test_kcron_caps)

# ============================================================================
# test_kcron_keytab_file
# ============================================================================
# Tests the on-disk validation and creation helpers from kcron_keytab_file.h:
# validate_client_dirname(), validate_keytab_directory() and create_keytab_file().
# These are pure, privilege-free, and return a status code, so the tests run
# them directly in a private temporary directory. create_keytab_file() writes
# the real empty-keytab header, so the success path is verified by reading the
# bytes back and checking the resulting file mode.

add_executable(test_kcron_keytab_file test_kcron_keytab_file.c)

target_include_directories(test_kcron_keytab_file PRIVATE ${TEST_INCLUDES})
add_coverage_flags(test_kcron_keytab_file)

add_test(NAME test_kcron_keytab_file COMMAND test_kcron_keytab_file)

# ============================================================================
# Shell tests (bats)
# ============================================================================
# bats is the shell test framework for the kcron utilities. It is optional at
# configure time so a minimal toolchain without bats still configures and runs
# the C tests; when present it is added like any other test so it runs under
# "make test"/"ctest".
find_program(BATS_EXEC bats)
if(BATS_EXEC)

  add_test(
    NAME Shell:bats
    COMMAND ${BATS_EXEC} ${CMAKE_CURRENT_SOURCE_DIR}/kcron.bats)

endif()

# ============================================================================
# Shell source tests
# ============================================================================
# The kcron shell utilities live under src/shell; their tests are registered
# here so that every CTest test (C, bats, shell) is registered from the test
# tree. Source scripts referenced by name stay where the source owns them.

add_test(NAME Syntax:Config COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig)
add_test(NAME Syntax:Init COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcroninit)
add_test(NAME Syntax:Destroy COMMAND bash -n ${PROJECT_SOURCE_DIR}/src/shell/kcrondestroy)

add_test(
  NAME Sysconfig:Sourcing
  COMMAND bash ${PROJECT_SOURCE_DIR}/test/test_sysconfig.sh
          ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig)

# Hardening check (ported from the RPM spec %check section)
# Determine which hardening auditor is available; prefer checksec, fall back to
# hardening-check. When neither is installed the check is a no-op so that
# minimal toolchains do not fail the build.
find_program(CHECKSEC_EXEC checksec)
find_program(HARDENING_CHECK_EXEC hardening-check)

if(CHECKSEC_EXEC OR HARDENING_CHECK_EXEC)
  add_test(
    NAME Hardening:Checksec
    COMMAND bash ${PROJECT_SOURCE_DIR}/test/hardening.sh
            $<TARGET_FILE:init-kerberos-client-dir>
            $<TARGET_FILE:create-empty-client-keytab>
            $<TARGET_FILE:client-keytab-name>)
endif()

# Static analysis of shell scripts (ported from issue #9)
find_program(SHELLCHECK_EXEC shellcheck)
if(SHELLCHECK_EXEC)
  add_test(
    NAME Shell:Shellcheck
    COMMAND ${SHELLCHECK_EXEC} -x
            ${PROJECT_SOURCE_DIR}/src/shell/kcroninit
            ${PROJECT_SOURCE_DIR}/src/shell/kcrondestroy
            ${PROJECT_SOURCE_DIR}/src/shell/kcron.sysconfig)
endif()

# ============================================================================
# Coverage report target
# ============================================================================
set(UNIT_TEST_BINARIES $<TARGET_FILE:test_kcron_filename>
                       $<TARGET_FILE:test_kcron_keytab>
                       $<TARGET_FILE:test_kcron_caps>
                       $<TARGET_FILE:test_kcron_keytab_file>
                       $<TARGET_FILE:test_client_keytab_name>)

add_custom_target(test_binaries DEPENDS test_kcron_filename test_kcron_keytab
                                            test_kcron_caps
                                            test_kcron_keytab_file
                                            test_client_keytab_name
  COMMENT "Building every unit test binary")

if(BUILD_TESTING AND HAVE_COVERAGE_TOOLS)

  set(COVERAGE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/coverage)
  set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_OUTPUT_DIR})

  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(COVERAGE_INFO ${CMAKE_BINARY_DIR}/coverage.info)
    set(COVERAGE_INFO_CLEAN ${CMAKE_BINARY_DIR}/coverage.info.cleaned)
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${COVERAGE_INFO}
                                               ${COVERAGE_INFO_CLEAN})

    add_custom_target(
      coverage
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --zerocounters
      COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LCOV_EXEC} --directory ${CMAKE_BINARY_DIR} --capture --rc
              branch_coverage=1 --output-file ${COVERAGE_INFO}
      COMMAND
        ${LCOV_EXEC} --remove ${COVERAGE_INFO} '${CMAKE_SOURCE_DIR}/test/*' --rc
        branch_coverage=1 --output-file ${COVERAGE_INFO_CLEAN}
      COMMAND ${GENHTML_EXEC} --rc branch_coverage=1 -o ${COVERAGE_OUTPUT_DIR}
              ${COVERAGE_INFO_CLEAN}
      COMMAND ${LCOV_EXEC} --summary ${COVERAGE_INFO_CLEAN} --rc
              branch_coverage=1
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating GCC coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")

    set(PROFILE_DATA ${CMAKE_BINARY_DIR}/coverage/default.profdata)
    # Instrumented processes write their sparse .profraw here. CTest changes
    # into the subdirectory that holds its CTestTestfile.cmake, so a relative
    # LLVM_PROFILE_FILE would land in build/test (not build) and the merge step
    # below could not find it; use an absolute pattern instead.
    set(COVERAGE_PROF_RAW ${CMAKE_BINARY_DIR}/coverage-prof)
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${PROFILE_DATA}
                                               ${COVERAGE_PROF_RAW})

    add_custom_target(
      coverage
      COMMAND ${CMAKE_COMMAND} -E rm -rf ${COVERAGE_PROF_RAW}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${COVERAGE_PROF_RAW}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${COVERAGE_OUTPUT_DIR}
      # %p-%m gives each process (and each child spawned under it, e.g. the
      # instrumented client-keytab-name) a unique file so runs never clobber
      # one another, and the absolute path makes the cwd irrelevant.
      COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${COVERAGE_PROF_RAW}/default-%p-%m.profraw
              ${CMAKE_CTEST_COMMAND} --output-on-failure
      COMMAND ${LLVM_PROFDATA_EXEC} merge -sparse ${COVERAGE_PROF_RAW}/*.profraw -o ${PROFILE_DATA}
      COMMAND ${LLVM_COV_EXEC} show ${UNIT_TEST_BINARIES} -instr-profile=${PROFILE_DATA}
              -format=html -output-dir=${COVERAGE_OUTPUT_DIR}
      COMMAND ${LLVM_COV_EXEC} report ${UNIT_TEST_BINARIES}
              -instr-profile=${PROFILE_DATA} -show-region-summary=false
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS test_binaries
      COMMENT
        "Running tests and generating Clang coverage report in ${COVERAGE_OUTPUT_DIR}/index.html"
    )

  endif()

endif()
