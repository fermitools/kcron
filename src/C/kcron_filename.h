/* SPDX-License-Identifier: MIT */
/*
 *
 * Filename and path handling functions for kcron keytabs
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

#ifndef KCRON_FILENAME_H
#define KCRON_FILENAME_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Get the base client keytab directory path.
 *
 * This function copies the compile-time configured client keytab directory
 * path into the provided buffer.
 *
 * Parameters:
 *   keytab_dir: Output buffer for the directory path
 *               Must be at least FILE_PATH_MAX_LENGTH +3 bytes
 *
 * Returns: 0 on success, exits on failure
 *
 * Security Note: Buffer must be properly allocated before calling.
 */
int get_client_dirname(char *keytab_dir) __attribute__((warn_unused_result)) __attribute__((flatten));
int get_client_dirname(char *keytab_dir) {
  /* Runtime NULL check - required, do not rely on nonnull attribute */
  if (keytab_dir == NULL) {
    (void)fprintf(stderr, "%s: keytab_dir parameter is NULL.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /*
   * Copy the configured client keytab directory path.
   * snprintf ensures NULL termination and prevents buffer overflow.
   */
  int written = snprintf(keytab_dir, FILE_PATH_MAX_LENGTH, "%s", __CLIENT_KEYTAB_DIR);

  /* Verify the write was successful and complete */
  if (written < 0) {
    (void)fprintf(stderr, "%s: snprintf failed for keytab_dir.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (written >= FILE_PATH_MAX_LENGTH) {
    (void)fprintf(stderr, "%s: keytab_dir path truncated (too long).\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  return 0;
}

/*
 * Build user-specific keytab filenames and paths.
 *
 * This function constructs the directory path and full file path for a
 * user's keytab file based on their UID.
 *
 * Parameters:
 *   keytab_dir: Output buffer for the user-specific directory path
 *               Format: __CLIENT_KEYTAB_DIR/<uid>
 *   keytab_filename: Output buffer for the keytab filename
 *                    Always set to "client.keytab"
 *   keytab: Output buffer for the full keytab file path
 *           Format: __CLIENT_KEYTAB_DIR/<uid>/client.keytab
 *
 * All buffers must be at least FILE_PATH_MAX_LENGTH +3 bytes.
 *
 * Returns: 0 on success, exits on failure
 *
 * Security Note: Uses UID instead of username to avoid TOCTOU issues
 * and username lookup failures. UIDs are immutable during process lifetime.
 */
int get_filenames(char *keytab_dir, char *keytab_filename, char *keytab) __attribute__((warn_unused_result)) __attribute__((flatten));
int get_filenames(char *keytab_dir, char *keytab_filename, char *keytab) {
  const uid_t uid = getuid();
  char *uid_str = NULL;
  int written = 0;

  /* Runtime NULL checks - required, do not rely on nonnull attribute */
  if (keytab_dir == NULL) {
    (void)fprintf(stderr, "%s: keytab_dir parameter is NULL.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (keytab_filename == NULL) {
    (void)fprintf(stderr, "%s: keytab_filename parameter is NULL.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (keytab == NULL) {
    (void)fprintf(stderr, "%s: keytab parameter is NULL.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /*
   * Allocate buffer for UID string representation.
   * USERNAME_MAX_LENGTH provides sufficient space for any reasonable UID.
   * Extra 3 bytes provide margin for NULL termination and formatting.
   */
  uid_str = calloc(USERNAME_MAX_LENGTH, sizeof(char));
  if (uid_str == NULL) {
    (void)fprintf(stderr, "%s: Unable to allocate memory for uid_str.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Convert UID to string safely */
  written = snprintf(uid_str, USERNAME_MAX_LENGTH, "%u", uid);
  if (written < 0) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: snprintf failed for UID conversion.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (written >= (int)(USERNAME_MAX_LENGTH)) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: UID string too long (this should never happen).\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Build the keytab filename (constant across all users) */
  written = snprintf(keytab_filename, FILE_PATH_MAX_LENGTH, "client.keytab");
  if (written < 0 || written >= FILE_PATH_MAX_LENGTH) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: Failed to set keytab_filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Build the user-specific directory path */
  written = snprintf(keytab_dir, FILE_PATH_MAX_LENGTH, "%s/%s", __CLIENT_KEYTAB_DIR, uid_str);
  if (written < 0) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: snprintf failed for keytab_dir.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (written >= FILE_PATH_MAX_LENGTH) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: keytab_dir path too long.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Build the complete keytab file path */
  written = snprintf(keytab, FILE_PATH_MAX_LENGTH, "%s/%s", keytab_dir, keytab_filename);
  if (written < 0) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: snprintf failed for keytab path.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (written >= FILE_PATH_MAX_LENGTH) {
    (void)free(uid_str);
    (void)fprintf(stderr, "%s: keytab path too long.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Clean up allocated memory */
  (void)free(uid_str);

  return 0;
}

#endif /* KCRON_FILENAME_H */
