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
#define __PROGRAM_NAME "client-keytab-name"
#endif

#include <stdio.h>                      /* for fprintf, stderr, NULL, etc   */
#include <stdlib.h>                     /* for free, EXIT_FAILURE, etc      */

#include "kcron_filename.h"             /* for get_filename                 */

int main(void) {

  char *nullstring = NULL;

  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  if ((keytab == nullstring) || (keytab_dirname == nullstring) || (keytab_filename == nullstring)) {
    if (keytab != nullstring) {
      free(keytab);
    }
    if (keytab_dirname != nullstring) {
      free(keytab_dirname);
    }
    if (keytab_filename != nullstring) {
      free(keytab_filename);
    }

    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)free(keytab);
    (void)free(keytab_dirname);
    (void)free(keytab_filename);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  (void)printf("%s\n", keytab);

  (void)free(keytab);
  (void)free(keytab_dirname);
  (void)free(keytab_filename);

  exit(EXIT_SUCCESS);
}
