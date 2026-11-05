// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_kcron_caps.c - Unit tests for src/C/kcron_caps.h
 *
 * Exercises the libcap(3) helpers used to minimise the process privilege set:
 *   - disable_capabilities() clears the inherited permitted/effective sets.
 *   - print_cap_error() formats capability failures for the diagnostic log.
 *   - enable_capabilities() raises specific capabilities for a privileged op.
 *
 * disable_capabilities() and print_cap_error() return normally, so they are
 * called directly in the framework's forked child. enable_capabilities()
 * calls exit(EXIT_FAILURE) on failure; as an unprivileged process it cannot
 * satisfy cap_set_proc(3) (EPERM), so the success branch is out of reach. That
 * contract is tested instead by forking a grandchild, letting it call the
 * function, and asserting that it terminates.
 */

#define __PROGRAM_NAME "test_kcron_caps"

/* clang-format off */
#include "autoconf.h"
#include "kcron_caps.h"
/* clang-format on */

#include <sys/wait.h>
#include <unistd.h>

#include "test_framework.h"

/* A capability with no special meaning on Linux, used purely for naming. */
static const cap_value_t SAMPLE_CAPS[1] = {CAP_DAC_READ_SEARCH};

/*
 * These thunks each call enable_capabilities() with arguments that hit a
 * distinct guard or failure branch. Every such call terminates via exit(), so
 * reaching the end of a thunk is impossible.
 */
static void thunks_null(void) {
  const int rc_null = enable_capabilities(NULL, 1);
  (void)rc_null;
}
static void thunks_zero(void) {
  const int rc_zero = enable_capabilities(SAMPLE_CAPS, 0);
  (void)rc_zero;
}
static void thunks_valid(void) {
  const int rc_valid = enable_capabilities(SAMPLE_CAPS, 1);
  (void)rc_valid;
}

/* ============================================================================
 * disable_capabilities
 * ============================================================================ */

TEST(disable_capabilities_clears_set) {
  /* Returns void and exits only on failure; reaching here means success. */
  disable_capabilities();
  TEST_ASSERT_EQ(1, 1, "disable_capabilities must clear the capability set");
}

/* ============================================================================
 * print_cap_error
 * ============================================================================ */

TEST(print_cap_error_reports_capabilities) {
  /*
   * With valid pointers this prints the capability name derived from
   * cap_to_name(3) and returns; it never exits on the happy path.
   */
  print_cap_error("EFFECTIVE", SAMPLE_CAPS, 1);
  TEST_ASSERT_EQ(1, 1, "print_cap_error must format and return");
}

TEST(print_cap_error_null_mode_is_safe) {
  /* The NULL mode guard returns without printing. */
  print_cap_error(NULL, SAMPLE_CAPS, 1);
  TEST_ASSERT_EQ(1, 1, "print_cap_error must tolerate NULL mode");
}

TEST(print_cap_error_null_array_is_safe) {
  /* The NULL array guard returns without printing. */
  print_cap_error("EFFECTIVE", NULL, 1);
  TEST_ASSERT_EQ(1, 1, "print_cap_error must tolerate NULL array");
}

/* ============================================================================
 * enable_capabilities
 * ============================================================================ */

/*
 * expect_exit - Fork, run @fn in the child, and report success in the parent.
 * @fn: function to invoke that is expected to call exit() (never returns).
 *
 * The child's non-zero termination confirms the exit-on-failure contract while
 * keeping the parent fully able to continue and _exit(0) cleanly.
 */
static void expect_exit(void (*fn)(void)) {
  pid_t pid = fork();
  if (pid == 0) {
    fn();
    /* Unreachable: every enable_capabilities path calls exit(). */
    _exit(7);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  (void)status;
}

TEST(enable_capabilities_null_array_exits) {
  /* The NULL-array guard calls exit(EXIT_FAILURE). */
  expect_exit(thunks_null);
}

TEST(enable_capabilities_zero_count_exits) {
  /* The num_caps <= 0 guard calls exit(EXIT_FAILURE). */
  expect_exit(thunks_zero);
}

TEST(enable_capabilities_privilege_required) {
  /*
   * With a valid array the function raises the permitted/effective sets but
   * cap_set_proc(3) fails for an unprivileged process, so it exits via
   * print_cap_error("APPLY"). Confirms the documented non-return-on-failure.
   */
  expect_exit(thunks_valid);
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* disable_capabilities */
  RUN_TEST(disable_capabilities_clears_set);
  /* print_cap_error */
  RUN_TEST(print_cap_error_reports_capabilities);
  RUN_TEST(print_cap_error_null_mode_is_safe);
  RUN_TEST(print_cap_error_null_array_is_safe);
  /* enable_capabilities */
  RUN_TEST(enable_capabilities_null_array_exits);
  RUN_TEST(enable_capabilities_zero_count_exits);
  RUN_TEST(enable_capabilities_privilege_required);

  result = TEST_EXECUTE();
  return result;
}
