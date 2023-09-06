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
#define __PROGRAM_NAME "init-kcron-keytab"
#endif

#include <dirent.h>                     /* for dirfd                          */
#include <fcntl.h>                      /* for openat, O_WRONLY               */
#include <libgen.h>                     /* for dirname                        */
#include <stdio.h>                      /* for fprintf, stderr, NULL, etc     */
#include <stdlib.h>                     /* for free, EXIT_FAILURE, etc        */
#include <sys/stat.h>                   /* for S_IRWXU, stat, S_IXGRP, etc    */
#include <sys/types.h>                  /* for uid_t, gid_t, etc              */
#include <unistd.h>                     /* for getuid, fchown, fchmod         */

#include "kcron_caps.h"                 /* for disable_capabilities, etc      */
#include "kcron_filename.h"             /* for get_filename                   */
#include "kcron_empty_keytab_file.h"    /* for write_empty_keytab             */
#include "kcron_setup.h"                /* for harden_runtime                 */

#if USE_CAPABILITIES == 1
#include <sys/capability.h>             /* for CAP_CHOWN, CAP_FOWNER,etc      */
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

static int mkdir_if_missing(char *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((nonnull (1))) __attribute__((warn_unused_result));
static int mkdir_if_missing(char *dir, uid_t owner, gid_t group, mode_t mode) {

  #if USE_CAPABILITIES == 1
  const cap_value_t caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
  #else
  const cap_value_t caps[] = {-1};
  #endif
  int num_caps = sizeof(caps) / sizeof(cap_value_t);

  struct stat st = {0};

  char *nullstring = NULL;

  DIR *my_dir = NULL;
  DIR *null_dir = NULL;

  uid_t uid = getuid();
  uid_t euid = geteuid();

  if (dir == nullstring) {
    /* nothing to do - no dir passed */
    return 0;
  }

  if (stat(dir, &st) == 0) {
    /* exists*/
    if (S_ISDIR(st.st_mode)) {
      /* and is a directory */
      return 0;
    } else {
      /* whatever this is, it is not acceptable here */
      (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
      return 1;
    } }
  }

  if (enable_capabilities(caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE */
  if (mkdir(dir, mode) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (euid != uid) {
    /* use of CAP_DAC_OVERRIDE as we may not be able to chdir/make files otherwise   */
    /* as the dir may be chmod 700 for not our euid */
    if (enable_capabilities(caps, num_caps) != 0) {
      (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
      return 1;
    }
  }

  /* use the inode of the dir we made earlier so folks can't move it      */
  /* there is still a small race condition, but we are somewhat protected */
  /* since opendir should make sure this is a directory.                  */
  /* use of CAP_DAC_OVERRIDE */
  my_dir = opendir(dir);

  if (my_dir == null_dir) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to locate %s ?\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  /* did the directory really create on disk */
  if (fstat(dirfd(my_dir), &st) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  if (disable_capabilities() != 0) {
    /* technically we might not have active caps now, but eh              */
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  if (!S_ISDIR(st.st_mode)) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (enable_capabilities(caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_CHOWN */
  if (fchown(dirfd(my_dir), owner, group) != 0) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  (void)closedir(my_dir);
  return 0;
}

static int chown_chmod_keytab(int filedescriptor, char *keytab) __attribute__((nonnull (2))) __attribute__((warn_unused_result));
static int chown_chmod_keytab(int filedescriptor, char *keytab) {

  #if USE_CAPABILITIES == 1
  const cap_value_t keytab_caps[] = {CAP_CHOWN};
  #else
  const cap_value_t keytab_caps[] = {-1};
  #endif
  int num_caps = sizeof(keytab_caps) / sizeof(cap_value_t);

  uid_t uid = getuid();
  gid_t gid = getgid();

  struct stat st = {0};

  if (filedescriptor == 0) {
    (void)fprintf(stderr, "%s: Invalid file %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* did the file really create on disk */
  if (fstat(filedescriptor, &st) != 0) {
    (void)fprintf(stderr, "%s: Cannot stat file %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  if (!S_ISREG(st.st_mode)) {
    (void)fprintf(stderr, "%s: %s is not a regular file.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* Set the right owner of our keytab */
  if (st.st_uid != uid || st.st_gid != gid) {

    if (enable_capabilities(keytab_caps, num_caps) != 0) {
      (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
      return 1;
    }

    /* use of CAP_CHOWN, needed for SUID mode */
    if (fchown(filedescriptor, uid, gid) != 0) {
      (void)disable_capabilities();
      (void)fprintf(stderr, "%s: Unable to chown %d:%d %s\n", __PROGRAM_NAME, uid, gid, keytab);
      return 1;
    }

    if (disable_capabilities() != 0) {
      (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
      return 1;
    }
  }

  if (enable_capabilities(keytab_caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* ensure permissions are as expected on keytab file */
  /* use of CAP_CHMOD, needed for SUID mode */
  if (fchmod(filedescriptor, _0600) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
    return 1;
  }

  if (disable_capabilities() != 0) {
    (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
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

  char *nullstring = NULL;
  int filedescriptor = 0;
  int stat_code = -1;

  DIR *keytab_dir = NULL;
  DIR *null_dir = NULL;

  #if USE_CAPABILITIES == 1
  const cap_value_t caps[] = {CAP_DAC_OVERRIDE};
  #else
  const cap_value_t caps[] = {-1};
  #endif
  int num_caps = sizeof(caps) / sizeof(cap_value_t);

  uid_t euid = geteuid();
  uid_t uid = getuid();
  gid_t gid = getgid();

  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  char *client_keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 1, sizeof(char));

  /* verify memory can be allocated */
  if ((keytab == nullstring) || (keytab_dirname == nullstring) || (keytab_filename == nullstring) || (client_keytab_dirname == nullstring)) {
    if (keytab != nullstring) {
      (void)free(keytab);
    }
    if (keytab_dirname != nullstring) {
      (void)free(keytab_dirname);
    }
    if (keytab_filename != nullstring) {
      (void)free(keytab_filename);
    }
    if (client_keytab_dirname != nullstring) {
      (void)free(client_keytab_dirname);
    }

    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* is our client keytab directory set*/
  if (get_client_dirname(client_keytab_dirname) != 0) {
    (void)free(keytab);
    (void)free(keytab_dirname);
    (void)free(keytab_filename);
    (void)free(client_keytab_dirname);
    (void)fprintf(stderr, "%s: Client keytab directory not set.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* look for our client keytab directory */
  stat_code = stat(client_keytab_dirname, &st);
  if (stat_code == -1) {
    (void)free(keytab);
    (void)free(keytab_dirname);
    (void)free(keytab_filename);
    (void)free(client_keytab_dirname);
    (void)fprintf(stderr, "%s: Client keytab directory does not exist: %s.\n", __PROGRAM_NAME, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Contact your admin to have it created.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* find our filenames */
  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)free(keytab);
    (void)free(keytab_dirname);
    (void)free(keytab_filename);
    (void)free(client_keytab_dirname);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* make sure our storage directory exists */
  if (mkdir_if_missing(keytab_dirname, uid, gid, _0700) != 0) {
    (void)fprintf(stderr, "%s: Cannot make dir %s.\n", __PROGRAM_NAME, keytab_dirname);
    (void)free(keytab);
    (void)free(keytab_dirname);
    (void)free(keytab_filename);
    (void)free(client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  /* look for our keytab */
  stat_code = stat(keytab, &st);

  /* If keytab is missing make it */
  /* If it exists but has the wrong permissions/owner do nothing, it is safer */
  if (stat_code == -1) {

    /* use the inode of the dir we made earlier so folks can't move it      */
    /* there is still a small race condition, but we are somewhat protected */
    /* since opendir should make sure this is a directory                   */
    keytab_dir = opendir(keytab_dirname);

    /* did the dir really open */
    if (keytab_dir == null_dir) {
      (void)fprintf(stderr, "%s: Unable to locate %s ?\n", __PROGRAM_NAME, keytab_dirname);
      (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    if (fstat(dirfd(keytab_dir), &st) != 0) {
      (void)fprintf(stderr, "%s: %s could not be read.\n", __PROGRAM_NAME, keytab_dirname);
      (void)closedir(keytab_dir);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    if (!S_ISDIR(st.st_mode)) {
      (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, keytab_dirname);
      (void)closedir(keytab_dir);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    if (euid != uid) {
      /* use of CAP_DAC_OVERRIDE as we may not be able to edit the file otherwise   */
      if (enable_capabilities(caps, num_caps) != 0) {
        (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
        (void)free(keytab);
        (void)free(keytab_dirname);
        (void)free(keytab_filename);
        (void)free(client_keytab_dirname);
        exit(EXIT_FAILURE);
      }
    }

    filedescriptor = openat(dirfd(keytab_dir), keytab_filename, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, _0600);

    if (disable_capabilities() != 0) {
      /* technically we might not have active caps now, but eh              */
      (void)fprintf(stderr, "%s: Cannot drop capabilities.\n", __PROGRAM_NAME);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    /* did the file really create at the target location */
    if (filedescriptor == 0) {
      (void)fprintf(stderr, "%s: %s is missing, cannot create.\n", __PROGRAM_NAME, keytab);
      (void)closedir(keytab_dir);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    /* we have the fd, don't need this one any more */
    (void)closedir(keytab_dir);

    /* did the file really create on disk */
    if (fstat(filedescriptor, &st) != 0) {
      (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, keytab);
      (void)close(filedescriptor);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    /* is the file a normal file */
    if (!S_ISREG(st.st_mode)) {
      (void)fprintf(stderr, "%s: %s is not a file.\n", __PROGRAM_NAME, keytab);
      (void)close(filedescriptor);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    if (write_empty_keytab(filedescriptor) != 0) {
      (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
      (void)close(filedescriptor);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    filedescriptor = openat(dirfd(keytab_dir), keytab_filename, O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC, _0600);
    if (chown_chmod_keytab(filedescriptor, keytab) != 0) {
      (void)fprintf(stderr, "%s: Cannot set permissions on keytab : %s.\n", __PROGRAM_NAME, keytab);
      (void)close(filedescriptor);
      (void)free(keytab);
      (void)free(keytab_dirname);
      (void)free(keytab_filename);
      (void)free(client_keytab_dirname);
      exit(EXIT_FAILURE);
    }

    (void)close(filedescriptor);
  } /* no else required, this exists to make it */

  (void)printf("%s\n", keytab);

  (void)free(keytab);
  (void)free(keytab_dirname);
  (void)free(keytab_filename);
  (void)free(client_keytab_dirname);

  exit(EXIT_SUCCESS);
}
