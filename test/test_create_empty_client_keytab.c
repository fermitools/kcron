// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_create_empty_client_keytab.c - Integration test for the
 * create-empty-client-keytab(8) binary.
 *
 * create-empty-client-keytab derives <base>/<uid>/client.keytab from the
 * calling UID, validates that the per-UID directory exists, and creates an
 * empty but valid keytab there. It performs no hardening of its own, so the
 * built binary can be exercised end to end exactly like client-keytab-name.
 *
 * The test is environment-adaptive: it works whether or not the per-UID
 * directory already exists.
 *
 *   * When the directory exists (or can be created), the first run creates the
 *     keytab (exit 0, mode 0600) and the second run is refused (exit 1,
 *     "already exists") - covering the creation path and the O_EXCL refusal.
 *   * When the directory is absent and cannot be created here (typical for an
 *     unprivileged user under a root-owned base), the run is refused (exit 1) -
 *     covering the validate_keytab_directory() rejection path.
 *
 * The binary path is injected at build time via CLIENT_EMPTY_CLIENT_KEYTAB_BIN.
 */

#define __PROGRAM_NAME "test_create_empty_client_keytab"

/* clang-format off */
#include "autoconf.h"
#include "kcron_filename.h"
/* clang-format on */

#include <sys/stat.h>
#include <unistd.h>

#include "test_framework.h"

#ifndef CLIENT_EMPTY_CLIENT_KEYTAB_BIN
#define CLIENT_EMPTY_CLIENT_KEYTAB_BIN "create-empty-client-keytab"
#endif

/*
 * run_binary - Capture the binary's stdout into @out.
 * @out:    Destination buffer.
 * @n:      Size of @out.
 *
 * Returns 0 if the binary exited successfully, EXIT_FAILURE on refusal, or -1
 * if the binary could not be launched.
 */
static int run_binary(char *out, size_t n) {
  FILE *pipe;
  char line[FILE_PATH_MAX_LENGTH + 3];
  size_t total = 0;

  pipe = popen(CLIENT_EMPTY_CLIENT_KEYTAB_BIN, "r");
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

  return (pclose(pipe) == 0) ? 0 : EXIT_FAILURE;
}

/*
 * create_empty_client_keytab_runs - Drive create-empty-client-keytab end to end.
 *
 * Covers main(): allocation success, get_filenames(), and either the creation
 * success path (validate_keytab_directory + create_keytab_file both return 0)
 * with the subsequent "already exists" refusal, or the validate_keytab_directory
 * rejection path when the per-UID directory is not available.
 */
TEST(create_empty_client_keytab_runs) {
  char keytab_dir[FILE_PATH_MAX_LENGTH + 3];
  char keytab_filename[FILE_PATH_MAX_LENGTH + 3];
  char keytab[FILE_PATH_MAX_LENGTH + 3];
  char out[FILE_PATH_MAX_LENGTH + 3];
  struct stat st;
  int rc;

  (void)memset(keytab_dir, 0, sizeof(keytab_dir));
  (void)memset(keytab_filename, 0, sizeof(keytab_filename));
  (void)memset(keytab, 0, sizeof(keytab));
  (void)memset(out, 0, sizeof(out));

  /* Derive the same path the binary will use. */
  TEST_ASSERT_EQ(get_filenames(keytab_dir, keytab_filename, keytab), 0, "path derivation must succeed");

  /* Start from a known state so the first run exercises the creation path. */
  (void)unlink(keytab);

  /*
   * Ensure the per-UID directory is present. If it already exists we proceed to
   * the creation path; if it is missing we try to create it, and if that is not
   * permitted we fall back to the rejection assertion below.
   */
  if (stat(keytab_dir, &st) != 0) {
    if (mkdir(keytab_dir, 0700) != 0) {
      /* The per-UID directory does not exist and cannot be created here (the
       * base directory is typically not writable by an unprivileged user). The
       * binary must reject the missing directory. */
      rc = run_binary(out, sizeof(out));
      TEST_ASSERT_EQ(rc, EXIT_FAILURE, "a missing per-UID directory must be rejected");
      return;
    }
  }

  /* Per-UID directory present: the first run creates the keytab. */
  rc = run_binary(out, sizeof(out));
  TEST_ASSERT_EQ(rc, 0, "creation must succeed when the per-UID directory exists");

  /* The keytab must now exist at the derived path, be a regular file, and be
   * created mode 0600. */
  TEST_ASSERT_EQ(stat(keytab, &st), 0, "the keytab must be created");
  if (stat(keytab, &st) == 0) {
    TEST_ASSERT_EQ((int)(S_ISREG(st.st_mode)), 1, "created entry must be a regular file");
    TEST_ASSERT_EQ((int)(st.st_mode & 07777), 0600, "the keytab must be mode 0600");
  }

  /* A second run must refuse to clobber the now-existing keytab (O_EXCL). */
  rc = run_binary(out, sizeof(out));
  TEST_ASSERT_EQ(rc, EXIT_FAILURE, "recreating an existing keytab must be rejected");

  /* Clean up so later runs start from the same known state. */
  (void)unlink(keytab);
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  RUN_TEST(create_empty_client_keytab_runs);

  result = TEST_EXECUTE();
  return result;
}
