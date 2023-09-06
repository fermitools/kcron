/*
 *
 * A simple place where we keep our SETRLIMIT(2) calls
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

#include <stdio.h>          /* for fprintf, stderr, NULL, etc   */
#include <stdlib.h>         /* for EXIT_FAILURE                 */

int write_empty_keytab(int filedescriptor) __attribute__((warn_unused_result));
int write_empty_keytab(int filedescriptor) {

  if (filedescriptor == 0) {
    (void)fprintf(stderr, "%s: no keytab file specified.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* This magic string makes ktutil and kadmin happy with an empty file */
  char emptykeytab_a = 0x05;
  char emptykeytab_b = 0x02;

  if (write(filedescriptor, &emptykeytab_a, sizeof(emptykeytab_a)) != sizeof(emptykeytab_a)) {
    (void)fprintf(stderr, "%s: could not write initial block to keytab.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
  if (write(filedescriptor, &emptykeytab_b, sizeof(emptykeytab_b)) != sizeof(emptykeytab_b)) {
    (void)fprintf(stderr, "%s: could not write initial blocks to keytab.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  (void)fsync(filedescriptor);

  return 0;
}

#endif
