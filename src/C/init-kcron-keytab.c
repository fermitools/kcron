/*
 *
 * A simple program that generates a blank keytab in a deterministic location.
 *
 * It should be SETUID(3p) root or have the right CAPABILITIES(7).
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
#define __PROGRAM_NAME "init-kcron-keytab"
#endif

#include <libgen.h>       /* for dirname                          */
#include <pwd.h>          /* for getpwuid, passwd                 */
#include <stdio.h>        /* for fprintf, fwrite, stderr, etc     */
#include <stdlib.h>       /* for EXIT_SUCCESS, EXIT_FAILURE       */
#include <string.h>       /* for basename, memset                 */
#include <sys/stat.h>     /* for stat, chmod, S_IRUSR, etc        */
#include <sys/prctl.h>    /* for prctl, PR_SET_DUMPABLE           */
#include <sys/ptrace.h>   /* for ptrace                           */
#include <sys/types.h>    /* for uid_t, cap_t, etc                */
#include <unistd.h>       /* for chown, gethostname, getuid, etc  */

#include "kcron_ulimit.h" /* for set_ulimits                               */
#include "kcron_caps.h"   /* for disable_capabilities, enable_capabilities */

#ifndef _0600
#define _0600 S_IRUSR | S_IWUSR
#endif
#ifndef _0700
#define _0700 S_IRWXU
#endif
#ifndef _1711
#define _1711 S_ISVTX | S_IRWXU | S_IXGRP | S_IXOTH
#endif
#ifndef _0711
#define _0711 S_IRWXU | S_IXGRP | S_IXOTH
#endif

#if USE_CAPABILITIES == 1
const cap_value_t caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER};
#else
const cap_value_t caps[] = {};
#endif

int mkdir_p(char restrict *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((nonnull)) __attribute__((warn_unused_result));
int mkdir_p(char restrict *dir, uid_t owner, gid_t group, mode_t mode) {

  struct stat st = {0};

  uid_t safe_owner = 0;
  gid_t safe_group = 0;
  mode_t safe_mode = _0711;

  char path_str[FILE_PATH_MAX_LENGTH + 1];
  memset(path_str, '\0', sizeof(path_str));

  if (unlikely(dir == NULL)) {
    /* nothing to do no dir passed */
    return 0;
  } else if (unlikely(stat(dir, &st) == 0)) {
    /* nothing to do */
    return 0;
  }

  (void)snprintf(path_str, sizeof(path_str), "%s", dir);

  /* recursive, safer user/group/modes */
  if (unlikely(mkdir_p(dirname(path_str), safe_owner, safe_group, safe_mode) != 0)) {
    /* If it breaks abort recursion */
    return 1;
  }

  if (unlikely(enable_capabilities(caps) != 0)) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (unlikely(mkdir(dir, mode) != 0)) {
    (void)fprintf(stderr, "%s: unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }
  if (unlikely(chown(dir, owner, group) != 0)) {
    (void)fprintf(stderr, "%s: unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    return 1;
  }
  if (unlikely(chmod(dir, mode) != 0)) {
    (void)fprintf(stderr, "%s: unable to chmod %o %s\n", __PROGRAM_NAME, mode, dir);
    return 1;
  }

  if (unlikely(disable_capabilities() != 0)) {
    return 1;
  }

  return 0;
}

int make_client_keytab_dir(void) __attribute__((warn_unused_result));
int make_client_keytab_dir(void) {
  /* Make UID keytab dir if missing */
  uid_t uid;
  char user_keytab_dir[FILE_PATH_MAX_LENGTH + 1];
  char uid_str[USERNAME_MAX_LENGTH + 1];

  memset(uid_str, '\0', sizeof(uid_str));
  memset(user_keytab_dir, '\0', sizeof(user_keytab_dir));

  uid = getuid();

  (void)snprintf(uid_str, sizeof(uid_str), "%d", uid);

  (void)snprintf(user_keytab_dir, sizeof(user_keytab_dir), "%s/%s", __CLIENT_KEYTAB, uid_str);

  if (unlikely(mkdir_p(user_keytab_dir, uid, _USER_GID, _0700) != 0)) {
    return 1;
  }

  return 0;
}

int get_filename(char restrict *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int get_filename(char restrict *keytab) {
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

int write_empty_keytab(char restrict *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int write_empty_keytab(char restrict *keytab) {

  /* This magic string makes ktutil and kadmin happy with an empty file */
  char emptykeytab_a = 0x05;
  char emptykeytab_b = 0x02;

  FILE *fp;
  if (unlikely(enable_capabilities(caps) != 0)) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if ((fp = fopen(keytab, "w+b")) == NULL) {
    (void)fprintf(stderr, "%s: %s is missing, cannot create.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  if (unlikely(disable_capabilities() != 0)) {
    fclose(fp);
    return 1;
  }

  (void)fwrite(&emptykeytab_a, sizeof(emptykeytab_a), 1, fp);
  (void)fwrite(&emptykeytab_b, sizeof(emptykeytab_b), 1, fp);
  return fclose(fp);
}

int chmod_keytab(char restrict *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int chmod_keytab(char restrict *keytab) {

  uid_t uid;
  uid = getuid();

  /* ensure permissions are as expected on keytab file */

  if (unlikely(enable_capabilities(caps) != 0)) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (unlikely(chown(keytab, uid, _USER_GID) != 0)) {
    (void)fprintf(stderr, "%s: unable to chown %d:%d %s\n", __PROGRAM_NAME, uid, _USER_GID, keytab);
    return 1;
  }

  if (unlikely(chmod(keytab, _0600) != 0)) {
    (void)fprintf(stderr, "%s: unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
    return 1;
  }

  if (unlikely(disable_capabilities() != 0)) {
    return 1;
  }

  return 0;
}

int main(void) {

  struct stat st = {0};
  char keytab[FILE_PATH_MAX_LENGTH + 1];
  memset(keytab, '\0', sizeof(keytab));

  if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
    (void)fprintf(stderr, "%s: Do not trace me.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

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

  if (unlikely(make_client_keytab_dir() != 0)) {
    (void)fprintf(stderr, "%s: Cannot setup containing KRB5 EUID directory.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }
  if (unlikely(mkdir_p(__KCRON_KEYTAB_DIR, 0, _USER_GID, _1711) != 0)) {
    (void)fprintf(stderr, "%s: Cannot setup containing directory.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  if (unlikely(get_filename(keytab) != 0)) {
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* If keytab is missing make it */
  if (likely(stat(keytab, &st) == -1)) {
    if (unlikely(write_empty_keytab(keytab) != 0)) {
      (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
      return EXIT_FAILURE;
    }
  }

  if (unlikely(chmod_keytab(keytab) != 0)) {
    (void)fprintf(stderr, "%s: Cannot set permissions on keytab : %s.\n", __PROGRAM_NAME, keytab);
    return EXIT_FAILURE;
  }

  (void)printf("%s\n", keytab);

  return EXIT_SUCCESS;
}
