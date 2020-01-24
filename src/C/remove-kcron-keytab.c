/*
 *
 * A simple program that removes a file in a deterministic location.
 *
 * It should be SETUID root or have the right CAPABILITIES(7).
 *
 */
#include "autoconf.h" /* for our automatic config bits        */
/*

   Copyright 2017 Fermi Research Alliance, LLC

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
#define __PROGRAM_NAME "remove-kcron-keytab"
#endif

#include <stdio.h>                      /* for fprintf, stderr, remove       */
#include <stdlib.h>                     /* for EXIT_FAILURE, EXIT_SUCCESS    */
#include <sys/stat.h>                   /* for stat                          */

#include "kcron_caps.h"                 /* for disable_capabilities, etc     */
#include "kcron_filename.h"             /* for get_filename                  */
#include "kcron_setup.h"                /* for harden_runtime                */

#if USE_CAPABILITIES == 1
const cap_value_t caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
#else
const cap_value_t caps[] = {};
#endif

void constructor(void) __attribute__((constructor));
void constructor(void)
{ 
  /* Setup runtime hardening /before/ main() is even called */
  (void)harden_runtime();
}

int main(void) {

  struct stat st = {0};
  char *nullpointer = NULL;
  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  if (keytab == nullpointer) {
    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* already done keytab dir if missing */
  if (stat(__KCRON_KEYTAB_DIR, &st) == -1) {
    return EXIT_SUCCESS;
  }

  if (get_filename(keytab) != 0) {
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* If keytab is missing we are done */
  if (stat(keytab, &st) == -1) {
    return EXIT_SUCCESS;
  } else {

    if (enable_capabilities(caps) != 0) {
      (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
      return EXIT_FAILURE;
    }

    if (remove(keytab) != 0) {
      (void)fprintf(stderr, "%s: Failed: rm %s\n", __PROGRAM_NAME, keytab);
      return EXIT_FAILURE;
    }

    if (disable_capabilities() != 0) {
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
