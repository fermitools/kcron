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

#ifndef KCRON_LANDLOCK_H
#define KCRON_LANDLOCK_H 1

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/landlock.h>
#include <sys/syscall.h>

void set_kcron_landlock(void) __attribute__((flatten));
void set_kcron_landlock(void) {

  int landlock_ruleset_fd = 0;
  long int landlock_error = 0;

  long int landlock_abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);

  char *client_keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  const char *nullstring = NULL;

  struct landlock_ruleset_attr ruleset_attr = {
      .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                           LANDLOCK_ACCESS_FS_MAKE_SYM,
  };

  struct landlock_path_beneath_attr path_beneath = {
      .allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_FILE,
  };

  /* verify memory can be allocated */
  if (client_keytab_dirname == nullstring) {
    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* landlock unsupported, this is not an error exactly */
  if (landlock_abi > 0) {

    if (get_client_dirname(client_keytab_dirname) != 0) {
      (void)fprintf(stderr, "%s: Client keytab directory not set.\n", __PROGRAM_NAME);
      (void)free(client_keytab_dirname);
      (void)close(landlock_ruleset_fd);
      exit(EXIT_FAILURE);
    }

    landlock_ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (landlock_ruleset_fd < 0) {
      (void)fprintf(stderr, "%s: landlock is enabled but non-functional?\n", __PROGRAM_NAME);
      (void)free(client_keytab_dirname);
      (void)close(landlock_ruleset_fd);
      exit(EXIT_FAILURE);
    }

    path_beneath.parent_fd = open(dirname(client_keytab_dirname), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (path_beneath.parent_fd < 0) {
      (void)fprintf(stderr, "%s: landlock could not find %s?\n", __PROGRAM_NAME, client_keytab_dirname);
      (void)free(client_keytab_dirname);
      (void)close(landlock_ruleset_fd);
      exit(EXIT_FAILURE);
    }

    landlock_error = syscall(__NR_landlock_add_rule, landlock_ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    (void)close(path_beneath.parent_fd);

    if (landlock_error) {
      (void)fprintf(stderr, "%s: landlock could not apply ruleset to %s?\n", __PROGRAM_NAME, client_keytab_dirname);
      (void)free(client_keytab_dirname);
      (void)close(landlock_ruleset_fd);
      exit(EXIT_FAILURE);
    }

    if (syscall(__NR_landlock_restrict_self, landlock_ruleset_fd, 0)) {
      (void)fprintf(stderr, "%s: landlock could not apply ruleset to self?\n", __PROGRAM_NAME);
      (void)free(client_keytab_dirname);
      (void)close(landlock_ruleset_fd);
      exit(EXIT_FAILURE);
    }

    (void)close(landlock_ruleset_fd);
  }
}
#endif
