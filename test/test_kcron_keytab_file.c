// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group

/**
 * test_kcron_keytab_file.c - Unit tests for src/C/kcron_keytab_file.h
 *
 * Exercises the on-disk validation and creation helpers that form the real
 * logic of create-empty-client-keytab and init-kerberos-client-dir. These are
 * pure, privilege-free, and return a status code, so unlike the hardening
 * primitives they can be exercised directly and deterministically in a
 * throwaway temp directory without special privileges.
 *
 * Each test that creates files uses its own mkdtemp() directory so tests never
 * interfere with one another (important for the already-exists path).
 */

#define __PROGRAM_NAME "test_kcron_keytab_file"

/* clang-format off */
#include "autoconf.h"
#include "kcron_keytab_file.h"
/* clang-format on */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_framework.h"

/* Number of magic bytes write_empty_keytab() is expected to have produced. */
static const unsigned char EXPECTED_MAGIC[2] = {0x05, 0x02};

/*
 * make_temp_dir - Create a private 0700 directory and return its path.
 *
 * The returned buffer is FILE_PATH_MAX_LENGTH bytes so it can be handed
 * straight to the path-handling helpers.
 */
static char *make_temp_dir(void) {
  char template[FILE_PATH_MAX_LENGTH];
  char *dir;

  /* mkdtemp() fills its argument in place and returns a pointer into it, so
   * hand the caller a fresh heap copy they are responsible for freeing. */
  (void)memset(template, 0, sizeof(template));
  snprintf(template, sizeof(template), "/tmp/kcron_ktf_XXXXXX");
  dir = mkdtemp(template);
  if (dir == NULL) {
    return NULL;
  }
  return strdup(dir);
}

/* make_symlink - Create a dangling symlink at link_path -> "nope". */
static void make_symlink(const char *link_path) {
  (void)unlink(link_path);
  if (symlink("cron_keytab_target_does_not_exist", link_path) != 0) {
    perror("symlink");
  }
}

/* make_regular_file - Create an empty regular file at file_path. */
static void make_regular_file(const char *file_path) {
  int fd;

  (void)unlink(file_path);
  fd = open(file_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    perror("open regular file");
  } else {
    (void)close(fd);
  }
}

/* ============================================================================
 * validate_client_dirname
 * ============================================================================ */

TEST(validate_client_dirname_null_is_rejected) {
  TEST_ASSERT_EQ(validate_client_dirname(NULL), 1, "NULL directory must be rejected");
}

TEST(validate_client_dirname_missing_is_rejected) {
  TEST_ASSERT_EQ(validate_client_dirname("/this/does/not/exist/kron"), 1,
                 "non-existent directory must be rejected");
}

TEST(validate_client_dirname_symlink_is_rejected) {
  char *dir = make_temp_dir();
  char link[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)snprintf(link, sizeof(link), "%s/link", dir);
  make_symlink(link);

  rc = validate_client_dirname(link);
  TEST_ASSERT_EQ(rc, 1, "symlinked directory must be rejected");
  free(dir);
}

TEST(validate_client_dirname_real_directory_is_accepted) {
  char *dir = make_temp_dir();
  int rc;

  rc = validate_client_dirname(dir);
  TEST_ASSERT_EQ(rc, 0, "real directory must be accepted");
  free(dir);
}

/* ============================================================================
 * validate_keytab_directory
 * ============================================================================ */

TEST(validate_keytab_directory_null_is_rejected) {
  TEST_ASSERT_EQ(validate_keytab_directory(NULL), 1, "NULL directory must be rejected");
}

TEST(validate_keytab_directory_missing_is_rejected) {
  TEST_ASSERT_EQ(validate_keytab_directory("/no/such/path/kron_keytab"), 1,
                 "non-existent directory must be rejected");
}

TEST(validate_keytab_directory_symlink_is_rejected) {
  char *dir = make_temp_dir();
  char link[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)snprintf(link, sizeof(link), "%s/link", dir);
  make_symlink(link);

  rc = validate_keytab_directory(link);
  TEST_ASSERT_EQ(rc, 1, "symlinked directory must be rejected");
  free(dir);
}

TEST(validate_keytab_directory_not_a_directory_is_rejected) {
  char *dir = make_temp_dir();
  char file[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)snprintf(file, sizeof(file), "%s/blocker", dir);
  make_regular_file(file);

  rc = validate_keytab_directory(file);
  TEST_ASSERT_EQ(rc, 1, "a regular file is not a directory");
  free(dir);
}

TEST(validate_keytab_directory_real_directory_is_accepted) {
  char *dir = make_temp_dir();
  int rc;

  rc = validate_keytab_directory(dir);
  TEST_ASSERT_EQ(rc, 0, "real directory must be accepted");
  free(dir);
}

/* ============================================================================
 * create_keytab_file
 * ============================================================================ */

TEST(create_keytab_file_null_dirname_rejected) {
  TEST_ASSERT_EQ(create_keytab_file(NULL, "client.keytab", "/x"), 1,
                 "NULL dirname must be rejected");
}

TEST(create_keytab_file_null_filename_rejected) {
  char *dir = make_temp_dir();

  TEST_ASSERT_EQ(create_keytab_file(dir, NULL, "/x"), 1, "NULL filename must be rejected");
  free(dir);
}

TEST(create_keytab_file_null_keytab_rejected) {
  char *dir = make_temp_dir();

  TEST_ASSERT_EQ(create_keytab_file(dir, "client.keytab", NULL), 1,
                 "NULL keytab path must be rejected");
  free(dir);
}

TEST(create_keytab_file_missing_dir_rejected) {
  TEST_ASSERT_EQ(create_keytab_file("/no/such/dir/kron", "client.keytab",
                                    "/no/such/dir/kron/1/client.keytab"),
                 1, "non-existent directory must be rejected");
}

TEST(create_keytab_file_symlink_dir_rejected) {
  char *dir = make_temp_dir();
  char link[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)snprintf(link, sizeof(link), "%s/link", dir);
  make_symlink(link);

  rc = create_keytab_file(link, "client.keytab", "/tmp/keytab");
  TEST_ASSERT_EQ(rc, 1, "symlinked directory must be rejected");
  free(dir);
}

TEST(create_keytab_file_writes_valid_empty_keytab) {
  char *dir = make_temp_dir();
  char name[FILE_PATH_MAX_LENGTH];
  char path[FILE_PATH_MAX_LENGTH];
  int rc;
  int fd;
  ssize_t nread;
  unsigned char readback[2];
  struct stat st;
  int mode;

  (void)memset(name, 0, sizeof(name));
  (void)memset(path, 0, sizeof(path));
  (void)memset(readback, 0, sizeof(readback));
  (void)snprintf(name, sizeof(name), "client.keytab");
  (void)snprintf(path, sizeof(path), "%s/client.keytab", dir);

  rc = create_keytab_file(dir, name, path);
  TEST_ASSERT_EQ(rc, 0, "creating the keytab must succeed");

  /* The file must exist and contain exactly the two magic bytes. */
  fd = open(path, O_RDONLY);
  TEST_ASSERT_NOT_EQ(fd, -1, "created keytab must be openable");
  if (fd >= 0) {
    nread = read(fd, readback, sizeof(readback));
    (void)close(fd);
    TEST_ASSERT_EQ(nread, 2, "keytab must contain exactly two bytes");
    if (nread == 2) {
      TEST_ASSERT_EQ((int)readback[0], (int)EXPECTED_MAGIC[0], "magic byte 0");
      TEST_ASSERT_EQ((int)readback[1], (int)EXPECTED_MAGIC[1], "magic byte 1");
    }
  }

  /* Permissions must be exactly 0600. */
  (void)stat(path, &st);
  mode = (int)(st.st_mode & 07777);
  TEST_ASSERT_EQ(mode, 0600, "keytab must be created mode 0600");

  (void)unlink(path);
  free(dir);
}

TEST(create_keytab_file_existing_file_is_rejected) {
  char *dir = make_temp_dir();
  char name[FILE_PATH_MAX_LENGTH];
  char path[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)memset(name, 0, sizeof(name));
  (void)memset(path, 0, sizeof(path));
  (void)snprintf(name, sizeof(name), "client.keytab");
  (void)snprintf(path, sizeof(path), "%s/client.keytab", dir);

  /* First call creates the file successfully... */
  rc = create_keytab_file(dir, name, path);
  TEST_ASSERT_EQ(rc, 0, "first creation must succeed");

  /* ...second call must refuse to clobber the existing file. */
  rc = create_keytab_file(dir, name, path);
  TEST_ASSERT_EQ(rc, 1, "recreating an existing keytab must be rejected");

  (void)unlink(path);
  free(dir);
}

TEST(create_keytab_file_unreadable_directory_rejected) {
  /* Permission-denial paths only apply to a non-root caller: root bypasses
   * directory access checks, so a 000 mode cannot make opendir() fail. Running
   * this suite as root (as CI does) would yield a false failure, so skip here
   * and rely on the non-root run to exercise the branch. */
  if (geteuid() == 0) {
    return;
  }

  char *dir = make_temp_dir();
  int rc;

  /* Remove all access so opendir() fails with EACCES, exercising the
   * "cannot open directory" branch rather than only the success paths. */
  if (chmod(dir, 000) != 0) {
    /* If the mode cannot be changed, skip cleanly rather than fail. */
    free(dir);
    return;
  }

  rc = create_keytab_file(dir, "client.keytab", "/tmp/keytab");
  TEST_ASSERT_EQ(rc, 1, "a directory that cannot be opened must be rejected");

  (void)chmod(dir, 0700); /* restore so the temp directory stays removable */
  free(dir);
}

TEST(create_keytab_file_existing_directory_rejected) {
  char *dir = make_temp_dir();
  char name[FILE_PATH_MAX_LENGTH];
  char sub[FILE_PATH_MAX_LENGTH];
  char path[FILE_PATH_MAX_LENGTH];
  int rc;

  (void)memset(name, 0, sizeof(name));
  (void)memset(sub, 0, sizeof(sub));
  (void)memset(path, 0, sizeof(path));
  (void)snprintf(name, sizeof(name), "client.keytab");

  /* Put a *directory* where the file is expected: openat(O_CREAT | O_EXCL)
   * against a directory fails with EISDIR, exercising the non-EEXIST error
   * branch instead of only the already-exists path. */
  (void)snprintf(sub, sizeof(sub), "%s/client.keytab", dir);
  if (mkdir(sub, 0700) != 0) {
    free(dir);
    return;
  }
  (void)snprintf(path, sizeof(path), "%s/client.keytab", sub);

  rc = create_keytab_file(dir, name, path);
  TEST_ASSERT_EQ(rc, 1, "an existing directory in the target path must be rejected");

  (void)rmdir(sub);
  free(dir);
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int main(int argc, char **argv) {
  int result;

  TEST_INIT(10, false, false); /* timeout, verbose, duration */

  /* validate_client_dirname */
  RUN_TEST(validate_client_dirname_null_is_rejected);
  RUN_TEST(validate_client_dirname_missing_is_rejected);
  RUN_TEST(validate_client_dirname_symlink_is_rejected);
  RUN_TEST(validate_client_dirname_real_directory_is_accepted);

  /* validate_keytab_directory */
  RUN_TEST(validate_keytab_directory_null_is_rejected);
  RUN_TEST(validate_keytab_directory_missing_is_rejected);
  RUN_TEST(validate_keytab_directory_symlink_is_rejected);
  RUN_TEST(validate_keytab_directory_not_a_directory_is_rejected);
  RUN_TEST(validate_keytab_directory_real_directory_is_accepted);

  /* create_keytab_file */
  RUN_TEST(create_keytab_file_null_dirname_rejected);
  RUN_TEST(create_keytab_file_null_filename_rejected);
  RUN_TEST(create_keytab_file_null_keytab_rejected);
  RUN_TEST(create_keytab_file_missing_dir_rejected);
  RUN_TEST(create_keytab_file_symlink_dir_rejected);
  RUN_TEST(create_keytab_file_writes_valid_empty_keytab);
  RUN_TEST(create_keytab_file_existing_file_is_rejected);
  RUN_TEST(create_keytab_file_unreadable_directory_rejected);
  RUN_TEST(create_keytab_file_existing_directory_rejected);

  result = TEST_EXECUTE();
  return result;
}
