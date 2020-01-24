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

#include <libgen.h>       /* for basename, dirname                */
#include <pwd.h>          /* for getpwuid, passwd                 */
#include <stdio.h>        /* for fprintf, fwrite, stderr, etc     */
#include <stdlib.h>       /* for EXIT_SUCCESS, EXIT_FAILURE       */
#include <sys/stat.h>     /* for stat, chmod, S_IRUSR, etc        */
#include <sys/prctl.h>    /* for prctl, PR_SET_DUMPABLE           */
#include <sys/ptrace.h>   /* for ptrace                           */
#include <sys/types.h>    /* for uid_t, cap_t, etc                */
#include <unistd.h>       /* for chown, gethostname, getuid, etc  */

#include "kcron_caps.h"       /* for disable_capabilities, enable_capabilities */
#include "kcron_filename.h"   /* for get_filename                              */
#include "kcron_setup.h"      /* for the hardening constructor                 */

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

int mkdir_p(char *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((nonnull)) __attribute__((warn_unused_result));
int mkdir_p(char *dir, uid_t owner, gid_t group, mode_t mode) {

  struct stat st = {0};

  uid_t safe_owner = 0;
  gid_t safe_group = 0;
  mode_t safe_mode = _0711;

  char *nullpointer = NULL;

  char *path_str = NULL;

  if (dir == nullpointer) {
    /* nothing to do - no dir passed */
    return 0;
  }

  if (stat(dir, &st) == 0) {
    /* nothing to do - dir exists*/
    return 0;
  }

  path_str = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  if (path_str == nullpointer) {
    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    return 1;
  }

  /* safely copy over or new dir */
  (void)snprintf(path_str, FILE_PATH_MAX_LENGTH, "%s", dir);

  /* recursive, safer user/group/modes */
  if (mkdir_p(dirname(path_str), safe_owner, safe_group, safe_mode) != 0) {
    /* If it breaks abort recursion */
    free(path_str);
    return 1;
  }

  if (enable_capabilities(caps) != 0) {
    free(path_str);
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (mkdir(dir, mode) != 0) {
    free(path_str);
    (void)fprintf(stderr, "%s: unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }
  if (chown(dir, owner, group) != 0) {
    free(path_str);
    (void)fprintf(stderr, "%s: unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    return 1;
  }
  if (chmod(dir, mode) != 0) {
    free(path_str);
    (void)fprintf(stderr, "%s: unable to chmod %o %s\n", __PROGRAM_NAME, mode, dir);
    return 1;
  }

  if (disable_capabilities() != 0) {
    free(path_str);
    return 1;
  }

  free(path_str);
  return 0;
}

int make_client_keytab_dir(void) __attribute__((warn_unused_result));
int make_client_keytab_dir(void) {

  /* Make UID keytab dir if missing */

  uid_t uid;

  char *user_keytab_dir = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *uid_str = calloc(USERNAME_MAX_LENGTH + 1, sizeof(char));

  uid = getuid();

  /* safely copy the uid from the system in */
  (void)snprintf(uid_str, USERNAME_MAX_LENGTH, "%d", uid);

  (void)snprintf(user_keytab_dir, FILE_PATH_MAX_LENGTH, "%s/%s", __CLIENT_KEYTAB, uid_str);

  if (mkdir_p(user_keytab_dir, 0, 0, _0711) != 0) {
    return 1;
  }

  return 0;
}

int write_empty_keytab(char *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int write_empty_keytab(char *keytab) {

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

int chmod_keytab(char *keytab) __attribute__((nonnull)) __attribute__((warn_unused_result));
int chmod_keytab(char *keytab) {

  uid_t uid;
  uid = getuid();

  /* ensure permissions are as expected on keytab file */

  if (enable_capabilities(caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (chown(keytab, uid, _USER_GID) != 0) {
    (void)fprintf(stderr, "%s: unable to chown %d:%d %s\n", __PROGRAM_NAME, uid, _USER_GID, keytab);
    return 1;
  }

  if (chmod(keytab, _0600) != 0) {
    (void)fprintf(stderr, "%s: unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
    return 1;
  }

  if (disable_capabilities() != 0) {
    return 1;
  }

  return 0;
}

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

  if (make_client_keytab_dir() != 0) {
    free(keytab);
    (void)fprintf(stderr, "%s: Cannot setup containing KRB5 EUID directory.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }
  if (mkdir_p(__KCRON_KEYTAB_DIR, 0, _USER_GID, _1711) != 0) {
    free(keytab);
    (void)fprintf(stderr, "%s: Cannot setup containing directory.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  if (get_filename(keytab) != 0) {
    free(keytab);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    return EXIT_FAILURE;
  }

  /* If keytab is missing make it */
  if (stat(keytab, &st) == -1) {
    if (write_empty_keytab(keytab) != 0) {
      free(keytab);
      (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
      return EXIT_FAILURE;
    }
  }

  if (chmod_keytab(keytab) != 0) {
    free(keytab);
    (void)fprintf(stderr, "%s: Cannot set permissions on keytab : %s.\n", __PROGRAM_NAME, keytab);
    return EXIT_FAILURE;
  }

  (void)printf("%s\n", keytab);

  free(keytab);
  return EXIT_SUCCESS;
}
