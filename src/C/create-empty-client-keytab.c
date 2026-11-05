/* SPDX-License-Identifier: MIT */
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
#include "kcron_keytab_file.h"

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
