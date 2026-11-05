/* SPDX-License-Identifier: MIT */
/*
 *
 * Functions for writing empty keytab file headers
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

#ifndef KCRON_EMPTY_KEYTAB_FILE_H
#define KCRON_EMPTY_KEYTAB_FILE_H 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Write an empty keytab file header.
 *
 * A valid keytab file must start with two magic bytes that identify it
 * as a keytab file (version 5, format 2). This function writes those
 * magic bytes to create an empty but valid keytab file.
 *
 * The magic bytes are:
 * - 0x05: Keytab version 5
 * - 0x02: Format 2
 *
 * This format is compatible with MIT Kerberos tools like ktutil and kadmin.
 *
 * Parameters:
 *   filedescriptor: Open file descriptor to write to (must be writable)
 *
 * Returns: 0 on success, exits on failure
 *
 * Security Note: The file descriptor should already have proper permissions
 * set (0600) and ownership before calling this function.
 */
int write_empty_keytab(int filedescriptor) __attribute__((warn_unused_result)) __attribute__((flatten));
int write_empty_keytab(int filedescriptor) {
  ssize_t bytes_written = 0;

  /* Validate file descriptor */
  if (filedescriptor < 0) {
    (void)fprintf(stderr, "%s: Invalid file descriptor (%d) for keytab.\n", __PROGRAM_NAME, filedescriptor);
    exit(EXIT_FAILURE);
  }
  /* Validate file descriptor is not stdin */
  if (filedescriptor == 0) {
    (void)fprintf(stderr, "%s: Invalid file descriptor (STDIN) for keytab.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Validate file descriptor is not stdout */
  if (filedescriptor == 1) {
    (void)fprintf(stderr, "%s: Invalid file descriptor (STDOUT) for keytab.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Validate file descriptor is not stderr */
  if (filedescriptor == 2) {
    (void)fprintf(stderr, "%s: Invalid file descriptor (STDERR) for keytab.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /*
   * Magic bytes for empty keytab file (Kerberos keytab v5.2 format).
   * These bytes make ktutil and kadmin recognize this as a valid empty keytab.
   */
  const unsigned char emptykeytab_a = 0x05; /* Version byte */
  const unsigned char emptykeytab_b = 0x02; /* Format byte */

  /* Write first magic byte (version) */
  bytes_written = write(filedescriptor, &emptykeytab_a, sizeof(emptykeytab_a));
  if (bytes_written != sizeof(emptykeytab_a)) {
    if (bytes_written < 0) {
      (void)fprintf(stderr, "%s: Failed to write version byte to keytab: %s\n", __PROGRAM_NAME, strerror(errno));
    } else {
      (void)fprintf(stderr, "%s: Partial write of version byte to keytab (%zd/%zu bytes).\n", __PROGRAM_NAME, bytes_written, sizeof(emptykeytab_a));
    }
    exit(EXIT_FAILURE);
  }

  /* Write second magic byte (format) */
  bytes_written = write(filedescriptor, &emptykeytab_b, sizeof(emptykeytab_b));
  if (bytes_written != sizeof(emptykeytab_b)) {
    if (bytes_written < 0) {
      (void)fprintf(stderr, "%s: Failed to write format byte to keytab: %s\n", __PROGRAM_NAME, strerror(errno));
    } else {
      (void)fprintf(stderr, "%s: Partial write of format byte to keytab (%zd/%zu bytes).\n", __PROGRAM_NAME, bytes_written, sizeof(emptykeytab_b));
    }
    exit(EXIT_FAILURE);
  }

  /*
   * Synchronize file data to disk.
   * This ensures the keytab is actually written before we return success.
   * Important for crash resilience.
   */
  if (fsync(filedescriptor) != 0) {
    (void)fprintf(stderr, "%s: Failed to sync keytab to disk: %s\n", __PROGRAM_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return 0;
}

#endif /* KCRON_EMPTY_KEYTAB_FILE_H */
