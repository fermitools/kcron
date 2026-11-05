/* SPDX-License-Identifier: MIT */
/*
 *
 * A simple program that prints the path to the user's client keytab file.
 *
 * This program determines the keytab path based on the calling user's UID
 * and prints it to stdout. It does NOT require special privileges.
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
#define __PROGRAM_NAME "client-keytab-name"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "kcron_filename.h"

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

/*
 * Main program entry point.
 *
 * This program simply computes and prints the keytab path for the current user.
 * It requires no special privileges and performs no file operations.
 *
 * Returns: EXIT_SUCCESS on success, EXIT_FAILURE on error
 */
int main(void) {
  /*
   * Allocate buffers with extra space for safety.
   * calloc() zero-initializes, providing NULL terminators throughout.
   */
  char *keytab = calloc(FILE_PATH_MAX_LENGTH, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH, sizeof(char));

  /* Check all allocations - fail fast if any allocation failed */
  if ((keytab == NULL) || (keytab_dirname == NULL) || (keytab_filename == NULL)) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Build the keytab path based on current user's UID */
  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Print the keytab path to stdout */
  (void)printf("%s\n", keytab);

  /* Clean up allocated memory */
  (void)free_buffers(keytab, keytab_dirname, keytab_filename);

  exit(EXIT_SUCCESS);
}
