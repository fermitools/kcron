// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_kcron_keytab.c - Unit tests for src/C/kcron_empty_keytab_file.h
 *
 * write_empty_keytab() emits the two magic bytes that make a file a valid,
 * empty MIT Kerberos keytab (version 5, format 2). The function writes to an
 * arbitrary file descriptor, so tests open a real temporary file, invoke the
 * function, then read the bytes back to confirm the exact contents.
 *
 * Error paths in the implementation call exit(2)/exit(1), which is
 * incompatible with the framework's fork-isolation model (a child exit is
 * reported as a test failure), so only the success path is exercised here.
 */

#define __PROGRAM_NAME "test_kcron_keytab"

/* clang-format off */
#include "autoconf.h"
#include "kcron_empty_keytab_file.h"
/* clang-format on */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_framework.h"

/*
 * These are the exact magic bytes the implementation is required to write.
 * Kept as constants here so a regression in either value is caught.
 */
static const unsigned char EXPECTED_MAGIC[2] = {0x05, 0x02};

/*
 * make_temp_file - Create an empty temporary file and return its descriptor.
 * @dir_template: mkdtemp-style template (trailing XXXXXX).
 *
 * The directory is created with mode 0700 and removed at test cleanup via
 * atexit(); the file inside is unlinked immediately on success.
 */
static int make_temp_file(char *dir_template) {
  char *dir;
  char path[FILE_PATH_MAX_LENGTH];
  int filedescriptor;

  dir = mkdtemp(dir_template);
  if (dir == NULL) {
    return -1;
  }

  (void)snprintf(path, sizeof(path), "%s/.keytab_probe", dir);
  filedescriptor = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
  (void)unlink(path);
  return filedescriptor;
}

TEST(write_empty_keytab_writes_exact_magic) {
  char template[FILE_PATH_MAX_LENGTH];
  int filedescriptor;
  unsigned char readback[2];
  ssize_t nread;

  (void)memset(template, 0, sizeof(template));
  (void)memset(readback, 0, sizeof(readback));
  snprintf(template, sizeof(template), "/tmp/kcron_keytab_XXXXXX");

  filedescriptor = make_temp_file(template);
  TEST_ASSERT_NOT_EQ(filedescriptor, -1, "temp file must be creatable");
  if (filedescriptor < 0) {
    return;
  }

  TEST_ASSERT_EQ(write_empty_keytab(filedescriptor), 0, "expected successful write of magic bytes");

  (void)lseek(filedescriptor, 0, SEEK_SET);
  nread = read(filedescriptor, readback, sizeof(readback));
  (void)close(filedescriptor);

  TEST_ASSERT_EQ(nread, 2, "must read exactly the two magic bytes");
  if (nread == 2) {
    TEST_ASSERT_EQ((int)readback[0], (int)EXPECTED_MAGIC[0], "first magic byte must be the version (0x05)");
    TEST_ASSERT_EQ((int)readback[1], (int)EXPECTED_MAGIC[1], "second magic byte must be the format (0x02)");
  }
}

TEST(write_empty_keytab_writes_only_two_bytes) {
  char template[FILE_PATH_MAX_LENGTH];
  int filedescriptor;
  unsigned char readback[8];
  ssize_t nread;

  (void)memset(template, 0, sizeof(template));
  (void)memset(readback, 0, sizeof(readback));
  snprintf(template, sizeof(template), "/tmp/kcron_keytab_XXXXXX");

  filedescriptor = make_temp_file(template);
  TEST_ASSERT_NOT_EQ(filedescriptor, -1, "temp file must be creatable");
  if (filedescriptor < 0) {
    return;
  }

  TEST_ASSERT_EQ(write_empty_keytab(filedescriptor), 0, "expected success");

  (void)lseek(filedescriptor, 0, SEEK_SET);
  nread = read(filedescriptor, readback, sizeof(readback));
  (void)close(filedescriptor);

  TEST_ASSERT_EQ(nread, 2, "file must contain exactly two bytes");
}

/*
 * write_empty_keytab() rejects a non-positive or stdio file descriptor before
 * writing anything. Those guards call exit(), so each is exercised in a
 * grandchild whose non-zero termination is captured here rather than allowed to
 * fail the enclosing test.
 *
 * Note: the descriptor is validated before any write, so passing fd 0/1/2 never
 * touches the inherited /dev/null-backed stdout/stderr.
 */
static void expect_exit_write(void (*fn)(void)) {
  pid_t pid = fork();
  if (pid == 0) {
    fn();
    _exit(7);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  TEST_ASSERT_NOT_EQ(status, 0, "write_empty_keytab must reject the descriptor");
}

static void guard_neg(void) {
  const int rc = write_empty_keytab(-1);
  (void)rc;
}
static void guard_stdin(void) {
  const int rc = write_empty_keytab(0);
  (void)rc;
}
static void guard_stdout(void) {
  const int rc = write_empty_keytab(1);
  (void)rc;
}
static void guard_stderr(void) {
  const int rc = write_empty_keytab(2);
  (void)rc;
}

TEST(write_empty_keytab_neg_descriptor_rejected) { expect_exit_write(guard_neg); }

TEST(write_empty_keytab_stdin_descriptor_rejected) { expect_exit_write(guard_stdin); }

TEST(write_empty_keytab_stdout_descriptor_rejected) { expect_exit_write(guard_stdout); }

TEST(write_empty_keytab_stderr_descriptor_rejected) { expect_exit_write(guard_stderr); }

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* write_empty_keytab */
  RUN_TEST(write_empty_keytab_writes_exact_magic);
  RUN_TEST(write_empty_keytab_writes_only_two_bytes);

  /* write_empty_keytab descriptor guards (each exits on failure) */
  RUN_TEST(write_empty_keytab_neg_descriptor_rejected);
  RUN_TEST(write_empty_keytab_stdin_descriptor_rejected);
  RUN_TEST(write_empty_keytab_stdout_descriptor_rejected);
  RUN_TEST(write_empty_keytab_stderr_descriptor_rejected);

  result = TEST_EXECUTE();
  return result;
}
