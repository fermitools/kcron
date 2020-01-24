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

#include <libgen.h>       /* for basename, dirname                */
#include <pwd.h>          /* for getpwuid, passwd                 */
#include <stdio.h>        /* for calloc, fprintf, snprintf        */
#include <unistd.h>       /* for gethostname, getuid              */


int get_filename(char *keytab) __attribute__((nonnull (1))) __attribute__((warn_unused_result)) __attribute__((flatten));
int get_filename(char *keytab) {

  uid_t uid;
  struct passwd *pd;

  char *nullpointer = NULL;

  char *username = calloc(USERNAME_MAX_LENGTH + 1, sizeof(char));
  char *hostname = calloc(HOSTNAME_MAX_LENGTH + 1, sizeof(char));

  if ((username == nullpointer) || (hostname == nullpointer)) {
    if (username != nullpointer) {
      free(username);
    }
    if (hostname != nullpointer) {
      free(hostname);
    }
    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    return 1;
  }

  /* What is this system called? */
  if (gethostname(hostname, HOSTNAME_MAX_LENGTH) != 0) {
    free(username);
    free(hostname);
    (void)fprintf(stderr, "%s: gethostname() error.\n", __PROGRAM_NAME);
    return 1;
  }

  /* What is my UID (not effective UID), ie whoami when I'm not root */
  uid = getuid();
  if ((pd = getpwuid(uid)) == NULL) {
    free(username);
    free(hostname);
    (void)fprintf(stderr, "%s: getpwuid() error for %d.\n", __PROGRAM_NAME, uid);
    return 1;
  }
  (void)snprintf(username, USERNAME_MAX_LENGTH, "%s", basename(pd->pw_name));

  /* Where do the keytabs go?  Here of course */
  (void)snprintf(keytab, FILE_PATH_MAX_LENGTH, "%s/%s.cron.%s.keytab", __KCRON_KEYTAB_DIR, username, basename(hostname));

  free(username);
  free(hostname);

  return 0;
}

