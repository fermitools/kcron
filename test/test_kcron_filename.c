// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_kcron_filename.c - Unit tests for src/C/kcron_filename.h
 *
 * get_client_dirname() and get_filenames() build the deterministic paths used
 * throughout kcron. They are pure string functions (the only syscall is
 * getuid()), so they can be exercised directly in-process without touching the
 * filesystem or requiring privileges.
 *
 * Tests cover:
 *   - the configured client keytab directory is copied verbatim
 *   - the per-UID directory, fixed filename, and full path all agree
 *   - the full path is reproducible from an independent computation
 *   - the filename is the constant "client.keytab" for every caller
 *   - buffer sizing is sufficient (no truncation at the configured length)
 */

#define __PROGRAM_NAME "test_kcron_filename"

/* clang-format off */
#include "autoconf.h"
#include "kcron_filename.h"
/* clang-format on */

#include <stdio.h>
#include <string.h>

#include "test_framework.h"

/*
 * compute_expected - Independently derive the expected keytab path.
 *
 * Recomputes what get_filenames() should produce using getuid() plus the same
 * string pieces, so the test does not hardcode the UID or the base directory.
 */
static int compute_expected(char *keytab_dir, char *keytab_filename,
                            char *keytab) {
  char uid_str[32]; /* 64-bit unsigned IDs fit in 21 characters */

  if (snprintf(uid_str, sizeof(uid_str), "%u", (unsigned)getuid()) < 0) {
    return -1;
  }

  if (snprintf(keytab_filename, FILE_PATH_MAX_LENGTH, "client.keytab") < 0) {
    return -1;
  }
  if (snprintf(keytab_dir, FILE_PATH_MAX_LENGTH, "%s/%s", __CLIENT_KEYTAB_DIR,
               uid_str) < 0) {
    return -1;
  }
  if (snprintf(keytab, FILE_PATH_MAX_LENGTH, "%s/%s", keytab_dir,
               keytab_filename) < 0) {
    return -1;
  }
  return 0;
}

/* ============================================================================
 * get_client_dirname
 * ============================================================================
 */

TEST(client_dirname_matches_config) {
  char buf[FILE_PATH_MAX_LENGTH + 3];

  (void)memset(buf, 0, sizeof(buf));
  TEST_ASSERT_EQ(get_client_dirname(buf), 0, "expected success");
  TEST_ASSERT_STR_EQ(buf, __CLIENT_KEYTAB_DIR,
                     "must equal the compiled-in client keytab directory");
}

TEST(client_dirname_buffer_has_null_terminator) {
  /* A caller passing exactly FILE_PATH_MAX_LENGTH must still get a valid
   * NUL-terminated string because the implementation bounds the copy. */
  char *buf = malloc(FILE_PATH_MAX_LENGTH);

  TEST_ASSERT_NOT_EQ(buf, NULL, "malloc must succeed");
  (void)memset(buf, 0, FILE_PATH_MAX_LENGTH);
  TEST_ASSERT_EQ(get_client_dirname(buf), 0, "expected success");
  TEST_ASSERT_STR_EQ(buf, __CLIENT_KEYTAB_DIR, "must be NUL-terminated");
  free(buf);
}

/* ============================================================================
 * get_filenames
 * ============================================================================
 */

TEST(get_filenames_succeeds) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0,
                 "expected success");
}

TEST(get_filenames_filename_is_constant) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0,
                 "expected success");
  TEST_ASSERT_STR_EQ(keytab_filename, "client.keytab",
                     "filename must always be client.keytab");
}

TEST(get_filenames_directory_under_config) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];
  size_t dir_len;

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0,
                 "expected success");

  dir_len = strlen(keytab_dir);
  TEST_ASSERT_EQ(dir_len > strlen(__CLIENT_KEYTAB_DIR), 1,
                 "directory must be nested below the configured base");
  TEST_ASSERT_EQ(strncmp(keytab_dir, __CLIENT_KEYTAB_DIR,
                         strlen(__CLIENT_KEYTAB_DIR)), 0,
                 "directory must start with the configured base");
  TEST_ASSERT_EQ((int)keytab_dir[strlen(__CLIENT_KEYTAB_DIR)], (int)'/',
                 "base must be followed by a path separator");
}

TEST(get_filenames_reproducible) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];
  char exp_dir[FILE_PATH_MAX_LENGTH + 3];
  char exp_name[FILE_PATH_MAX_LENGTH + 3];
  char exp_path[FILE_PATH_MAX_LENGTH + 3];

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  (void)memset(exp_dir, 0, sizeof(exp_dir));
  (void)memset(exp_name, 0, sizeof(exp_name));
  (void)memset(exp_path, 0, sizeof(exp_path));

  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0,
                 "get_filenames must succeed");
  TEST_ASSERT_EQ(compute_expected(exp_dir, exp_name, exp_path), 0,
                 "compute_expected must succeed");

  TEST_ASSERT_STR_EQ(keytab_dir, exp_dir,
                     "computed directory must match independent computation");
  TEST_ASSERT_STR_EQ(keytab_filename, exp_name,
                     "computed filename must match independent computation");
  TEST_ASSERT_STR_EQ(keytab, exp_path,
                     "computed path must match independent computation");
}

TEST(get_filenames_path_ends_with_filename) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];
  size_t path_len;
  size_t name_len;

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0,
                 "expected success");

  path_len = strlen(keytab);
  name_len = strlen(keytab_filename);
  TEST_ASSERT_EQ((int)(path_len >= name_len), 1,
                 "path must be at least as long as filename");
  TEST_ASSERT_EQ(strncmp(keytab + (path_len - name_len), keytab_filename,
                         name_len), 0,
                 "path must end with the keytab filename");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* get_client_dirname */
  RUN_TEST(client_dirname_matches_config);
  RUN_TEST(client_dirname_buffer_has_null_terminator);

  /* get_filenames */
  RUN_TEST(get_filenames_succeeds);
  RUN_TEST(get_filenames_filename_is_constant);
  RUN_TEST(get_filenames_directory_under_config);
  RUN_TEST(get_filenames_reproducible);
  RUN_TEST(get_filenames_path_ends_with_filename);

  result = TEST_EXECUTE();
  return result;
}
