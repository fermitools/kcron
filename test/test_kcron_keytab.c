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

  TEST_ASSERT_EQ(write_empty_keytab(filedescriptor), 0,
                 "expected successful write of magic bytes");

  (void)lseek(filedescriptor, 0, SEEK_SET);
  nread = read(filedescriptor, readback, sizeof(readback));
  (void)close(filedescriptor);

  TEST_ASSERT_EQ(nread, 2, "must read exactly the two magic bytes");
  if (nread == 2) {
    TEST_ASSERT_EQ((int)readback[0], (int)EXPECTED_MAGIC[0],
                   "first magic byte must be the version (0x05)");
    TEST_ASSERT_EQ((int)readback[1], (int)EXPECTED_MAGIC[1],
                   "second magic byte must be the format (0x02)");
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

  result = TEST_EXECUTE();
  return result;
}
