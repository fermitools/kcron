/*
 *
 * A simple program that creates an empty client keytab file.
 *
 * It runs with NO special privileges. The per-user keytab directory must
 * already exist and be owned by the calling user.
 *
 */
#include "autoconf.h" /* for our automatic config bits        */
/*

   Copyright 2023 Fermi Research Alliance, LLC

   This software was produced under U.S. Government contract DE-AC02-07CH11359
   for Fermi National Accelerator Laboratory (Fermilab), which is operated by
   Fermi Research Alliance, LLC for the U.S. Department of Energy. The U.S.
   Government has rights to use, reproduce, and distribute this software.
   NEITHER THE GOVERNMENT NOR FERMI RESEARCH ALLIANCE, LLC MAKES ANY WARRANTY,
   EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.
   If software is modified to produce derivative works, such modified software
   should be clearly marked, so as not to confuse it with the version available
   from Fermilab.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR FERMI RESEARCH ALLIANCE, LLC BE LIABLE FOR ANY CLAIM, DAMAGES OR
   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.

*/

#ifndef __PROGRAM_NAME
#define __PROGRAM_NAME "create-empty-client-keytab"
#endif

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
#include "kcron_filename.h"

#ifndef _0600
#define _0600 (S_IRUSR | S_IWUSR)
#endif

/*
 * Cleanup helper to free all allocated buffers.
 * Ensures consistent cleanup on all exit paths.
 */
static void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename) __attribute__((flatten)) __attribute__((cold));
static void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename) {
  /* NULL checks required for explicitness even though free() accepts NULL */
  if (keytab != NULL) {
    (void)free(keytab);
  }
  if (keytab_dirname != NULL) {
    (void)free(keytab_dirname);
  }
  if (keytab_filename != NULL) {
    (void)free(keytab_filename);
  }
}


static int validate_keytab_directory(const char *keytab_dirname) __attribute__((access(read_only, 1))) __attribute__((warn_unused_result));
static int validate_keytab_directory(const char *keytab_dirname) {
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

static int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) __attribute__((warn_unused_result));
static int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) {
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

int main(void) {
  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));

  if ((keytab == NULL) || (keytab_dirname == NULL) || (keytab_filename == NULL)) {
    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    exit(EXIT_FAILURE);
  }

  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    exit(EXIT_FAILURE);
  }

  if (validate_keytab_directory(keytab_dirname) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    exit(EXIT_FAILURE);
  }

  if (create_keytab_file(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    exit(EXIT_FAILURE);
  }

  (void)free_buffers(keytab, keytab_dirname, keytab_filename);

  exit(EXIT_SUCCESS);
}
