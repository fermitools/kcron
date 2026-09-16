/*
 *
 * A simple program that generates a blank keytab in a deterministic location.
 *
 * It should be SETUID(3p) root or have the right CAPABILITIES(7).
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
#define __PROGRAM_NAME "init-kcron-keytab"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kcron_caps.h"
#include "kcron_filename.h"
#include "kcron_setup.h"

#ifndef _0600
#define _0600 (S_IRUSR | S_IWUSR)
#endif
#ifndef _0700
#define _0700 (S_IRWXU)
#endif

/*
 * Cleanup helper to free all allocated buffers.
 * Ensures consistent cleanup on all exit paths.
 */
static void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename, char *client_keytab_dirname) __attribute__((flatten)) __attribute__((cold));
static void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename, char *client_keytab_dirname) {
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
  if (client_keytab_dirname != NULL) {
    (void)free(client_keytab_dirname);
  }
}

static int mkdir_if_missing(const char *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((access(read_only, 1))) __attribute__((warn_unused_result));
static int mkdir_if_missing(const char *dir, uid_t owner, gid_t group, mode_t mode) {
  const cap_value_t caps_dac_override[] = {CAP_DAC_OVERRIDE};
  const int num_caps_dac_override = sizeof(caps_dac_override) / sizeof(cap_value_t);
  const cap_value_t caps_chown[] = {CAP_CHOWN};
  const int num_caps_chown = sizeof(caps_chown) / sizeof(cap_value_t);

  struct stat st = {0};
  struct stat lst = {0};

  if (dir == NULL) {
    /* nothing to do - no dir passed */
    return 0;
  }

  /* Check for symlink to prevent TOCTOU symlink attacks */
  if (lstat(dir, &lst) == 0) {
    if (S_ISLNK(lst.st_mode)) {
      (void)fprintf(stderr, "%s: %s is a symlink, not allowed.\n", __PROGRAM_NAME, dir);
      return 1;
    }
  }

  if (stat(dir, &st) == 0) {
    /* exists */
    if (S_ISDIR(st.st_mode)) {
      /* and is a directory */
      return 0;
    } else {
      /* whatever this is, it is not a directory */
      (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
      return 1;
    }
  }

  if (enable_capabilities(caps_dac_override, num_caps_dac_override) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE to bypass discretionary access controls for mkdir */
  if (mkdir(dir, mode) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE as we might not be able to write to dir */
  DIR *my_dir = opendir(dir);
  if (my_dir == NULL) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to locate %s ?\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE as we might not be able to list dir */
  if (fstat(dirfd(my_dir), &st) != 0) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  disable_capabilities();

  if (!S_ISDIR(st.st_mode)) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (enable_capabilities(caps_chown, num_caps_chown) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_CHOWN to change ownership of the directory */
  if (fchown(dirfd(my_dir), owner, group) != 0) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  disable_capabilities();

  (void)closedir(my_dir);
  return 0;
}

static int validate_client_dirname(char *client_keytab_dirname) __attribute__((warn_unused_result));
static int validate_client_dirname(char *client_keytab_dirname) {
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

void constructor(void) __attribute__((constructor));
void constructor(void) {
  /* Setup runtime hardening /before/ main() is even called */
  (void)harden_runtime();
}

int main(void) {
  const uid_t uid = getuid();
  const gid_t gid = getgid();

  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *client_keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));

  if ((keytab == NULL) || (keytab_dirname == NULL) || (keytab_filename == NULL) || (client_keytab_dirname == NULL)) {
    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  if (get_client_dirname(client_keytab_dirname) != 0) {
    (void)fprintf(stderr, "%s: Client keytab directory not set.\n", __PROGRAM_NAME);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  if (validate_client_dirname(client_keytab_dirname) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  if (mkdir_if_missing(keytab_dirname, uid, gid, _0700) != 0) {
    (void)fprintf(stderr, "%s: Cannot make dir %s.\n", __PROGRAM_NAME, keytab_dirname);
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);

  exit(EXIT_SUCCESS);
}
