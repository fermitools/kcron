/*
 *
 * A simple place where we keep our SETRLIMIT(2) calls
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

#ifndef KCRON_EMPTY_KEYTAB_FILE_H
#define KCRON_EMPTY_KEYTAB_FILE_H 1

#include <stdio.h>                      /* for fprintf, stderr, NULL, etc   */

#include "kcron_caps.h"                 /* for disable_capabilities, etc    */

int write_empty_keytab(char *keytab) __attribute__((nonnull (1))) __attribute__((warn_unused_result));
int write_empty_keytab(char *keytab) {

  #if USE_CAPABILITIES == 1
  const cap_value_t caps[] = {CAP_DAC_OVERRIDE};
  #else
  const cap_value_t caps[] = {};
  #endif

  char *nullpointer = NULL;

  if (keytab == nullpointer) {
    (void)fprintf(stderr, "%s: no keytab file specified.\n", __PROGRAM_NAME);
    return 1;
  }

  /* This magic string makes ktutil and kadmin happy with an empty file */
  char emptykeytab_a = 0x05;
  char emptykeytab_b = 0x02;

  FILE *fp;
  if (enable_capabilities(caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if ((fp = fopen(keytab, "w+b")) == NULL) {
    (void)fprintf(stderr, "%s: %s is missing, cannot create.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  if (disable_capabilities() != 0) {
    fclose(fp);
    return 1;
  }

  (void)fwrite(&emptykeytab_a, sizeof(emptykeytab_a), 1, fp);
  (void)fwrite(&emptykeytab_b, sizeof(emptykeytab_b), 1, fp);
  return fclose(fp);
}

#endif
