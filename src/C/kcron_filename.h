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

#include <stdio.h>        /* for calloc, fprintf, snprintf        */
#include <stdlib.h>       /* for EXIT_FAILURE                     */
#include <unistd.h>       /* for getuid                           */


int get_filenames(char *keytab_dir, char *keytab_filename, char *keytab) __attribute__((nonnull (1, 2, 3))) __attribute__((warn_unused_result)) __attribute__((flatten));
int get_filenames(char *keytab_dir, char *keytab_filename, char *keytab) {

  uid_t uid = getuid();

  char *nullpointer = NULL;

  /* we are just using an int rather than the name, so this is enough space */
  char *uid_str = calloc(USERNAME_MAX_LENGTH + 1, sizeof(char));

  if (uid_str == nullpointer) {
    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if ((keytab == nullpointer) || (keytab_dir == nullpointer) || (keytab_filename == nullpointer)) {
    (void)fprintf(stderr, "%s: invalid memory passed in.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* safely copy the uid from the system into a string */
  (void)snprintf(uid_str, USERNAME_MAX_LENGTH, "%d", uid);

  /* build our filename variables */
  (void)snprintf(keytab_filename, FILE_PATH_MAX_LENGTH, "client.keytab");
  (void)snprintf(keytab_dir, FILE_PATH_MAX_LENGTH, "%s/%s", __CLIENT_KEYTAB_DIR, uid_str);
  (void)snprintf(keytab, FILE_PATH_MAX_LENGTH, "%s/%s", keytab_dir, keytab_filename);

  (void)free(uid_str);

  return 0;
}

