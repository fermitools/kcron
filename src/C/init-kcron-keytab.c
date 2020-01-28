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

#include <dirent.h>                     /* for dirfd                        */
#include <libgen.h>                     /* for dirname                      */
#include <stdio.h>                      /* for fprintf, stderr, NULL, etc   */
#include <stdlib.h>                     /* for free, EXIT_FAILURE, etc      */
#include <sys/stat.h>                   /* for S_IRWXU, stat, S_IXGRP, etc  */
#include <sys/types.h>                  /* for uid_t, gid_t, etc            */
#include <unistd.h>                     /* for getuid, fchown, fchmod       */

#include "kcron_caps.h"                 /* for disable_capabilities, etc    */
#include "kcron_filename.h"             /* for get_filename                 */
#include "kcron_empty_keytab_file.h"    /* for write_empty_keytab           */
#include "kcron_setup.h"                /* for harden_runtime               */

#if USE_CAPABILITIES == 1
#include <sys/capability.h>            /* for CAP_CHOWN, CAP_FOWNER,etc     */
#endif

#ifndef _0600
#define _0600 S_IRUSR | S_IWUSR
#endif
#ifndef _0700
#define _0700 S_IRWXU
#endif
#ifndef _0711
#define _0711 S_IRWXU | S_IXGRP | S_IXOTH
#endif

int mkdir_p(char *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((nonnull (1))) __attribute__((warn_unused_result));
int mkdir_p(char *dir, uid_t owner, gid_t group, mode_t mode) {

  #if USE_CAPABILITIES == 1
  const cap_value_t caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
  #else
  const cap_value_t caps[] = {-1};
  #endif

  struct stat st = {0};

  uid_t safe_owner = 0;
  gid_t safe_group = 0;
  mode_t safe_mode = _0711;

  char *nullstring = NULL;

  char *path_str = NULL;

  DIR *my_dir = NULL;
  DIR *null_dir = NULL;

  if (dir == nullstring) {
    /* nothing to do - no dir passed */
    return 0;
  }

  if (stat(dir, &st) == 0) {
    /* exists*/
    if (S_ISDIR(st.st_mode)) {
      /* and is a directory */
      return 0;
    } else { if (S_ISLNK(st.st_mode)) {
      /* we will accept links here */
      return 0;
    } else {
      /* whatever this is, it is not acceptable here */
      (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
      return 1;
    } }
  }

  path_str = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  if (path_str == nullstring) {
    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    return 1;
  }

  /* safely copy over or new dir */
  (void)snprintf(path_str, FILE_PATH_MAX_LENGTH, "%s", dir);

  /* recursive, safer user/group/modes */
  if (mkdir_p(dirname(path_str), safe_owner, safe_group, safe_mode) != 0) {
    /* If it breaks abort recursion */
    (void)free(path_str);
    return 1;
  }

  if (enable_capabilities(caps) != 0) {
    (void)free(path_str);
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE */
  if (mkdir(dir, mode) != 0) {
    (void)free(path_str);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)free(path_str);
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use the inode of the dir we made earlier so folks can't move it      */
  /* there is still a small race condition, but we are somewhat protected */
  /* since opendir should make sure this is a directory                   */
  my_dir = opendir(dir);

  if (my_dir == null_dir) {
    (void)free(path_str);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: unable to locate %s ?\n", __PROGRAM_NAME, dir);
  }

  if (fstat(dirfd(my_dir), &st) != 0) {
    (void)free(path_str);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (!S_ISDIR(st.st_mode)) {
    (void)free(path_str);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (enable_capabilities(caps) != 0) {
    (void)free(path_str);
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_CHOWN */
  if (fchown(dirfd(my_dir), owner, group) != 0) {
    (void)closedir(my_dir);
    (void)free(path_str);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)free(path_str);
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  (void)closedir(my_dir);

  (void)free(path_str);
  return 0;
}

int chown_chmod_keytab(FILE *filehandle, char *keytab) __attribute__((nonnull (1, 2))) __attribute__((warn_unused_result));
int chown_chmod_keytab(FILE *filehandle, char *keytab) {

  #if USE_CAPABILITIES == 1
  const cap_value_t keytab_caps[] = {CAP_CHOWN};
  #else
  const cap_value_t keytab_caps[] = {-1};
  #endif

  uid_t uid = getuid();
  gid_t gid = getgid();

  /* ensure permissions are as expected on keytab file */

  if (enable_capabilities(keytab_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_CHOWN, needed for SUID mode */
  if (fchown(fileno(filehandle), uid, gid) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: unable to chown %d:%d %s\n", __PROGRAM_NAME, uid, gid, keytab);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* I own it now, so no need for CAP_FOWNER here */
  if (fchmod(fileno(filehandle), _0600) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
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
  FILE *filehandle = NULL;

  uid_t uid = getuid();
  gid_t gid = getgid();

  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *keytab_dir = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  if ((keytab == nullpointer) || (keytab_dir == nullpointer)) {
    if (keytab != nullpointer) {
      free(keytab);
    }
    if (keytab_dir != nullpointer) {
      free(keytab_dir);
    }

    (void)fprintf(stderr, "%s: unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (get_filenames(keytab, keytab_dir) != 0) {
    (void)free(keytab);
    (void)free(keytab_dir);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (mkdir_p(keytab_dir, uid, gid, _0700) != 0) {
    (void)fprintf(stderr, "%s: Cannot make dir %s.\n", __PROGRAM_NAME, keytab_dir);
    (void)free(keytab);
    (void)free(keytab_dir);
    exit(EXIT_FAILURE);
  }

  /* If keytab is missing make it */
  if (stat(keytab, &st) == -1) {

    if ((filehandle = fopen(keytab, "w+b")) == NULL) {
      (void)fprintf(stderr, "%s: %s is missing, cannot create.\n", __PROGRAM_NAME, keytab);
      (void)free(keytab);
      (void)free(keytab_dir);
      exit(EXIT_FAILURE);
    }

    if (write_empty_keytab(filehandle) != 0) {
      (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
      (void)fclose(filehandle);
      (void)free(keytab);
      (void)free(keytab_dir);
      exit(EXIT_FAILURE);
    }

    if (chown_chmod_keytab(filehandle, keytab) != 0) {
      (void)fprintf(stderr, "%s: Cannot set permissions on keytab : %s.\n", __PROGRAM_NAME, keytab);
      (void)free(keytab);
      (void)free(keytab_dir);
      exit(EXIT_FAILURE);
    }

    (void)fclose(filehandle);
  }

  (void)printf("%s\n", keytab);

  (void)free(keytab);
  (void)free(keytab_dir);

  exit(EXIT_SUCCESS);
}
