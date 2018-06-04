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

#include <pwd.h>          /* for getpwuid, passwd              */
#include <stdio.h>        /* for fprintf, fwrite, stderr, etc  */
#include <stdlib.h>       /* for EXIT_SUCCESS, EXIT_FAILURE    */
#include <string.h>       /* for basename, memset              */
#include <sys/stat.h>     /* for stat, chmod, S_IRUSR, etc     */
#include <sys/prctl.h>    /* for prctl, PR_SET_DUMPABLE        */
#include <sys/resource.h> /* for rlimit, RLIMIT_               */
#include <sys/types.h>    /* for uid_t, cap_t, etc             */
#include <unistd.h>       /* for gethostname, getuid, etc      */

#include "kcron_ulimit.h" /* for set_ulimits                      */

#if USE_CAPABILITIES == 1
inline int disable_capabilities(void) __attribute__((warn_unused_result));
inline int disable_capabilities(void) {
  cap_t capabilities;

  uid_t euid;
  euid = geteuid();
  if (unlikely(euid == 0)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 2);
    /* pointless for euid 0 */
    return 0;
  }

  capabilities = cap_get_proc();

  if (unlikely(cap_clear(capabilities))) {
    /* error */
    DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 1);
    (void)cap_free(capabilities);
    (void)fprintf(stderr, "%s: Unable to clear CAPABILITIES\n", __PROGRAM_NAME);
    return 1;
  }

  DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 0);
  (void)cap_free(capabilities);
  return 0;
}

inline int enable_capabilities(void) __attribute__((warn_unused_result));
inline int enable_capabilities(void) {
  cap_t capabilities;
  int clear_cap = 0;

  cap_value_t expected_cap[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
  int num_caps = sizeof(expected_cap) / sizeof(expected_cap[0]);

  uid_t euid = geteuid();
  if (unlikely(euid == 0)) {
    /* pointless for euid 0 */
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 2);
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 2);
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 2);
    return 0;
  }

  capabilities = cap_get_proc();

  /* clear any active capabilities */
  clear_cap = disable_capabilities();
  if (unlikely(clear_cap != 0)) {
    (void)cap_free(capabilities);
    return clear_cap;
  }

  if (unlikely(cap_set_flag(capabilities, CAP_PERMITTED, num_caps, expected_cap, CAP_SET) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, "%s: Unable to set CAPABILITIES PERMITTED\n", __PROGRAM_NAME);
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 0);

  if (unlikely(cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, expected_cap, CAP_SET) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, "%s: Unable to set CAPABILITIES EFFECTIVE\n", __PROGRAM_NAME);
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 0);

  if (unlikely(cap_set_proc(capabilities) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, "%s: Unable to activate CAPABILITIES\n", __PROGRAM_NAME);
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 0);

  (void)cap_free(capabilities);
  return 0;
}
#else
/* If not caps, just return 0 */
inline int disable_capabilities(void) {
  DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 2);
  return 0;
}
inline int enable_capabilities(void) {
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 2);
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 2);
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 2);
  return 0;
}
#endif

int get_filename(char *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int get_filename(char *keytab) {

  uid_t uid;
  struct passwd *pd;
  char username[USERNAME_MAX_LENGTH + 1];
  char hostname[HOSTNAME_MAX_LENGTH + 1];

  memset(username, '\0', sizeof(username));
  memset(hostname, '\0', sizeof(hostname));

  /* What is this system called? */
  if (unlikely(gethostname(hostname, HOSTNAME_MAX_LENGTH) != 0)) {
    (void)fprintf(stderr, "%s: gethostname() error.\n", __PROGRAM_NAME);
    return 1;
  }

  /* What is my UID (not effective UID), ie whoami when I'm not root */
  uid = getuid();
  if ((pd = getpwuid(uid)) == NULL) {
    (void)fprintf(stderr, "%s: getpwuid() error for %d.\n", __PROGRAM_NAME, uid);
    return 1;
  }
  (void)snprintf(username, sizeof(username), "%s", basename(pd->pw_name));

  /* Where do the keytabs go?  Here of course */
  (void)snprintf(keytab, FILE_PATH_MAX_LENGTH, "%s/%s.cron.%s.keytab", __KCRON_KEYTAB_DIR, username, basename(hostname));

  return 0;
}

int main(void) {

  struct stat st = {0};
  char keytab[FILE_PATH_MAX_LENGTH + 1];
  memset(keytab, '\0', sizeof(keytab));

  if (unlikely(prctl(PR_SET_DUMPABLE, 0) != 0)) {
    (void)fprintf(stderr, "%s: Cannot disable core dumps.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  if (unlikely(set_ulimits()) != 0) {
    (void)fprintf(stderr, "%s: Cannot set ulimits.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

#if USE_SECCOMP == 1
  if (unlikely(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)) {
    (void)fprintf(stderr, "%s: Cannot drop useless syscalls.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }
#endif

  if (unlikely(disable_capabilities() != 0)) {
    (void)fprintf(stderr, "%s: Cannot drop extra permissions.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* already done keytab dir if missing */
  if (unlikely(stat(__KCRON_KEYTAB_DIR, &st) == -1)) {
    return EXIT_SUCCESS;
  }

  if (unlikely(get_filename(keytab) != 0)) {
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* If keytab is missing we are done */
  if (unlikely(stat(keytab, &st) == -1)) {
    return EXIT_SUCCESS;
  } else {

    if (unlikely(enable_capabilities() != 0)) {
      return EXIT_FAILURE;
    }

    if (unlikely(remove(keytab) != 0)) {
      (void)fprintf(stderr, "%s: Failed: rm %s\n", __PROGRAM_NAME, keytab);
      return EXIT_FAILURE;
    }

    if (unlikely(disable_capabilities() != 0)) {
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
