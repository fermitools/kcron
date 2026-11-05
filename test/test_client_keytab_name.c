// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_client_keytab_name.c - Integration test for the client-keytab-name(8)
 * binary.
 *
 * The unit tests above exercise the path-building functions in-process. This
 * test validates the *built artifact* end to end: it runs the compiled binary,
 * captures its stdout, and confirms it prints exactly the path derived from the
 * calling UID. client-keytab-name performs no privilege handling or
 * hardening, so invoking it is safe inside the test process.
 *
 * The binary path is injected at build time via CLIENT_KEYTAB_NAME_BIN.
 */

/* clang-format off */
#include "autoconf.h"
/* clang-format on */

#include <stdio.h>
#include <string.h>

#include "test_framework.h"

#ifndef CLIENT_KEYTAB_NAME_BIN
#define CLIENT_KEYTAB_NAME_BIN "client-keytab-name"
#endif

/*
 * run_binary - Capture the binary's stdout into @out.
 * @out:    Destination buffer.
 * @n:      Size of @out.
 *
 * Returns 0 if the binary exited successfully and produced output, else -1.
 */
static int run_binary(char *out, size_t n) {
  FILE *pipe;
  char line[FILE_PATH_MAX_LENGTH + 3];
  size_t total = 0;

  pipe = popen(CLIENT_KEYTAB_NAME_BIN, "r");
  if (pipe == NULL) {
    return -1;
  }

  while (fgets(line, sizeof(line), pipe) != NULL) {
    size_t linelen = strlen(line);
    if (total + linelen >= n) {
      break;
    }
    memcpy(out + total, line, linelen);
    total += linelen;
  }
  out[total] = '\0';

  return (pclose(pipe) == 0) ? 0 : -1;
}

/*
 * compute_expected - Derive the path the binary is expected to print.
 */
static int compute_expected(char *buf, size_t n) {
  char uid_str[32]; /* 64-bit unsigned IDs fit in 21 characters */
  char dirname[FILE_PATH_MAX_LENGTH];
  char path[FILE_PATH_MAX_LENGTH];

  if (snprintf(uid_str, sizeof(uid_str), "%u", (unsigned)getuid()) < 0) {
    return -1;
  }
  if (snprintf(dirname, sizeof(dirname), "%s/%s", __CLIENT_KEYTAB_DIR, uid_str) < 0) {
    return -1;
  }
  if (snprintf(path, sizeof(path), "%s/client.keytab", dirname) < 0) {
    return -1;
  }
  if (snprintf(buf, n, "%s", path) < 0) {
    return -1;
  }
  return 0;
}

TEST(binary_prints_expected_path) {
  char out[FILE_PATH_MAX_LENGTH + 3];
  char expected[FILE_PATH_MAX_LENGTH + 3];

  (void)memset(out, 0, sizeof(out));
  (void)memset(expected, 0, sizeof(expected));

  TEST_ASSERT_EQ(run_binary(out, sizeof(out)), 0, "binary must exit successfully and print the path");

  TEST_ASSERT_EQ(compute_expected(expected, sizeof(expected)), 0, "expected-path computation must succeed");

  /* strip the trailing newline captured from stdout */
  size_t len = strlen(out);
  if (len > 0 && out[len - 1] == '\n') {
    out[len - 1] = '\0';
  }

  TEST_ASSERT_STR_EQ(out, expected, "binary stdout must equal the derived keytab path");
}

TEST(binary_output_has_no_extra_lines) {
  char out[FILE_PATH_MAX_LENGTH + 3];
  int newlines = 0;
  size_t i;

  (void)memset(out, 0, sizeof(out));
  if (run_binary(out, sizeof(out)) != 0) {
    return;
  }

  for (i = 0; out[i] != '\0'; i++) {
    if (out[i] == '\n') {
      newlines++;
    }
  }
  TEST_ASSERT_EQ(newlines, 1, "exactly one line of output is expected");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  RUN_TEST(binary_prints_expected_path);
  RUN_TEST(binary_output_has_no_extra_lines);

  result = TEST_EXECUTE();
  return result;
}
