/* SPDX-License-Identifier: MIT */
/*
 *
 * On-disk validation and creation helpers for per-user client keytab files.
 *
 * These are the testable core of the create-empty-client-keytab and
 * init-kerberos-client-dir programs: they operate on caller-supplied paths,
 * return an integer status, and require no special privileges, so they can be
 * exercised directly in unit tests the same way kcron_filename.h and
 * kcron_empty_keytab_file.h logic is. The programs' main() functions stay thin
 * wrappers that call these helpers and translate the result into an exit code.
 *
 */
#include "autoconf.h" /* for our automatic config bits        */

#ifndef KCRON_KEYTAB_FILE_H
#define KCRON_KEYTAB_FILE_H 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kcron_empty_keytab_file.h"

#ifndef _0600
#define _0600 (S_IRUSR | S_IWUSR)
#endif

/*
 * Validate the client keytab base directory.
 *
 * The directory must exist, be reachable, and not be a symlink (symlink
 * indirection would let a caller substitute an unrelated path). This is the
 * check the init-kerberos-client-dir program runs before creating anything.
 *
 * Parameters:
 *   client_keytab_dirname: Path of the base directory to validate.
 *
 * Returns: 0 if the path is an existing, non-symlink directory; 1 otherwise.
 *
 * Security Note: lstat() is used first (not stat()) so the check cannot be
 * defeated by a TOCTOU symlink race.
 */
int validate_client_dirname(const char *client_keytab_dirname) __attribute__((warn_unused_result));
int validate_client_dirname(const char *client_keytab_dirname) {
  struct stat lst = {0};
  struct stat st = {0};

  if (client_keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: Client keytab directory pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }

  /* Check symlink on client_keytab_dirname before stat */
  if (lstat(client_keytab_dirname, &lst) != 0) {
    (void)fprintf(stderr, "%s: Client keytab directory does not exist: %s.\n", __PROGRAM_NAME, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Contact your admin to have it created correctly.\n", __PROGRAM_NAME);
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    (void)fprintf(stderr, "%s: Client keytab directory %s is a symlink, not allowed.\n", __PROGRAM_NAME, client_keytab_dirname);
    return 1;
  }

  if (stat(client_keytab_dirname, &st) == -1) {
    (void)fprintf(stderr, "%s: Client keytab directory does not exist: %s.\n", __PROGRAM_NAME, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Contact your admin to have it created.\n", __PROGRAM_NAME);
    return 1;
  }
  return 0;
}

/*
 * Validate the per-user keytab directory.
 *
 * The create-empty-client-keytab program writes into <base>/<uid>, so the
 * per-UID directory must already exist (created by init-kerberos-client-dir)
 * and must not be a symlink.
 *
 * Parameters:
 *   keytab_dirname: Path of the per-user directory to validate.
 *
 * Returns: 0 if the path is an existing, non-symlink directory; 1 otherwise.
 *
 * Security Note: lstat() is used first (not stat()) to avoid a TOCTOU symlink
 * race that could substitute an attacker-controlled path.
 */
int validate_keytab_directory(const char *keytab_dirname)
#if !defined(__clang__)
    __attribute__((access(read_only, 1)))
#endif
    __attribute__((warn_unused_result));
int validate_keytab_directory(const char *keytab_dirname) {
  struct stat lst = {0};
  struct stat st = {0};

  if (keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: Keytab directory pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }

  /* Check symlink on keytab_dirname before stat to prevent symlink attacks */
  if (lstat(keytab_dirname, &lst) != 0) {
    (void)fprintf(stderr, "%s: Keytab directory does not exist: %s.\n", __PROGRAM_NAME, keytab_dirname);
    (void)fprintf(stderr, "%s: Run init-kerberos-client-dir first.\n", __PROGRAM_NAME);
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    (void)fprintf(stderr, "%s: Keytab directory %s is a symlink, not allowed.\n", __PROGRAM_NAME, keytab_dirname);
    return 1;
  }

  if (stat(keytab_dirname, &st) == -1) {
    (void)fprintf(stderr, "%s: Keytab directory does not exist: %s.\n", __PROGRAM_NAME, keytab_dirname);
    (void)fprintf(stderr, "%s: Run init-kerberos-client-dir first.\n", __PROGRAM_NAME);
    return 1;
  }

  if (!S_ISDIR(st.st_mode)) {
    (void)fprintf(stderr, "%s: Keytab directory %s is not a directory.\n", __PROGRAM_NAME, keytab_dirname);
    return 1;
  }

  return 0;
}

/*
 * Create an empty client keytab file.
 *
 * The file is created atomically with O_CREAT|O_EXCL so a pre-existing entry
 * is reported rather than clobbered, is opened with O_NOFOLLOW to reject
 * symlink races, is pinned to mode 0600, and is given the valid empty keytab
 * header by write_empty_keytab(). All operations are performed relative to the
 * already-open directory inode to avoid a TOCTOU window between the directory
 * check and the create.
 *
 * Parameters:
 *   keytab_dirname: Existing, non-symlink directory to create the file in.
 *   keytab_filename: Base name of the keytab file to create.
 *   keytab: Full path, used only for error messages.
 *
 * Returns: 0 on success; 1 on any failure.
 *
 * Security Note: Every failure path closes the directory handle and returns
 * non-zero so the caller knows the keytab was not (re)created.
 */
int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) __attribute__((warn_unused_result));
int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) {
  struct stat st = {0};
  struct stat lst = {0};
  DIR *keytab_dir = NULL;
  int filedescriptor = -1;

  /* Validate non-null input pointers */
  if (keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: keytab_dirname pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }
  if (keytab_filename == NULL) {
    (void)fprintf(stderr, "%s: keytab_filename pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }
  if (keytab == NULL) {
    (void)fprintf(stderr, "%s: keytab pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }

  /* Check if keytab_dirname exists and is not a symlink (to avoid TOCTOU symlink attacks) */
  if (lstat(keytab_dirname, &lst) != 0) {
    (void)fprintf(stderr, "%s: %s does not exist.\n", __PROGRAM_NAME, keytab_dirname);
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    (void)fprintf(stderr, "%s: %s is a symlink, not allowed.\n", __PROGRAM_NAME, keytab_dirname);
    return 1;
  }

  /* Open the directory handle to perform file operations safely on the directory inode */
  keytab_dir = opendir(keytab_dirname);
  if (keytab_dir == NULL) {
    (void)fprintf(stderr, "%s: Unable to open %s.\n", __PROGRAM_NAME, keytab_dirname);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  /* Verify the opened directory is indeed a directory */
  if (fstat(dirfd(keytab_dir), &st) != 0) {
    (void)fprintf(stderr, "%s: %s could not be read.\n", __PROGRAM_NAME, keytab_dirname);
    (void)closedir(keytab_dir);
    return 1;
  }

  if (!S_ISDIR(st.st_mode)) {
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, keytab_dirname);
    (void)closedir(keytab_dir);
    return 1;
  }

  /* Open the keytab file with O_NOFOLLOW to prevent symlink attacks,
   * O_CREAT | O_EXCL to create only if missing and atomically detect existence,
   * and O_CLOEXEC for descriptor safety. Permissions set to 0600 for security.
   */
  filedescriptor = openat(dirfd(keytab_dir), keytab_filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, _0600);
  if (filedescriptor < 0) {
    if (errno == EEXIST) {
      (void)fprintf(stderr, "%s: %s already exists.\n", __PROGRAM_NAME, keytab);
    } else {
      (void)fprintf(stderr, "%s: %s cannot be created: %s\n", __PROGRAM_NAME, keytab, strerror(errno));
    }
    (void)closedir(keytab_dir);
    return 1;
  }
  (void)closedir(keytab_dir);

  /* Verify that the created file is a regular file */
  if (fstat(filedescriptor, &st) != 0) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, keytab);
    return 1;
  }
  if (!S_ISREG(st.st_mode)) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: %s is not a regular file.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* Write empty keytab content to the file */
  if (write_empty_keytab(filedescriptor) != 0) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* Ensure permissions are exactly 0600 */
  if (fchmod(filedescriptor, _0600) != 0) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: Unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
    return 1;
  }

  (void)close(filedescriptor);
  return 0;
}

#endif /* KCRON_KEYTAB_FILE_H */
