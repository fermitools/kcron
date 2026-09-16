/*
 *
 * Landlock filesystem access control for kcron
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

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Set up landlock filesystem access control.
 *
 * Landlock restricts filesystem access to only the client keytab directory tree.
 * This prevents the process from accessing any other part of the filesystem,
 * even if it's somehow compromised.
 *
 * The function detects the available landlock ABI version and enables all
 * supported features for that version. If landlock is not supported by the
 * kernel, the function returns gracefully (landlock is optional hardening).
 *
 * Security Note: This should be called BEFORE seccomp is enabled, as landlock
 * setup requires syscalls that may not be in the seccomp allowlist.
 */
void set_kcron_landlock(void) __attribute__((flatten));
void set_kcron_landlock(void) {
  int landlock_ruleset_fd = -1;
  int parent_fd = -1;
  long int landlock_error = 0;
  char *client_keytab_dirname = NULL;
  char *client_keytab_parent = NULL;

  struct landlock_ruleset_attr ruleset_attr = {0};
  struct landlock_path_beneath_attr path_beneath = {0};

  /* Query landlock ABI version supported by the kernel */
  long int landlock_abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);

  /* If landlock is not supported, return gracefully (not an error) */
  if (landlock_abi <= 0) {
    return;
  }

  /* Allocate buffer for client keytab directory path */
  client_keytab_dirname = calloc(FILE_PATH_MAX_LENGTH, sizeof(char));
  if (client_keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: Unable to allocate memory for landlock setup.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Get the client keytab base directory path */
  if (get_client_dirname(client_keytab_dirname) != 0) {
    (void)fprintf(stderr, "%s: Client keytab directory not configured for landlock.\n", __PROGRAM_NAME);
    (void)free(client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  /*
   * Configure landlock ruleset based on ABI version.
   * Start with ABI v1 (baseline) and add features from newer versions.
   */

  /* ABI v1 - Basic filesystem access control */
  ruleset_attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                                   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                                   LANDLOCK_ACCESS_FS_MAKE_SYM;

  /* Set allowed operations for the keytab directory */
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG;

  /* ABI v2 - Add file renaming/linking control */
  if (landlock_abi >= 2) {
    ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
    path_beneath.allowed_access |= LANDLOCK_ACCESS_FS_REFER;
  }

  /* ABI v3 - Add file truncation control */
  if (landlock_abi >= 3) {
    ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    path_beneath.allowed_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }

  /* ABI v4 - Add network access control */
  if (landlock_abi >= 4) {
    ruleset_attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
  }

  /* ABI v5 - Add ioctl restrictions */
  if (landlock_abi >= 5) {
    ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }

  /* ABI v6 - Add IPC scoping */
  if (landlock_abi >= 6) {
    ruleset_attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
  }

  /* Create the landlock ruleset */
  landlock_ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
  if (landlock_ruleset_fd < 0) {
    (void)fprintf(stderr, "%s: Landlock is supported but ruleset creation failed: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)free(client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  /*
   * Open the parent directory of the client keytab directory.
   * We need to allow access to the parent so we can access subdirectories.
   * dirname() modifies its argument, so we need to work on a copy.
   */
  client_keytab_parent = strdup(client_keytab_dirname);
  if (client_keytab_parent == NULL) {
    (void)fprintf(stderr, "%s: Unable to duplicate path for landlock.\n", __PROGRAM_NAME);
    (void)close(landlock_ruleset_fd);
    (void)free(client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  /*
   * Open the parent directory with:
   * - O_RDONLY: Read-only access
   * - O_NOFOLLOW: Don't follow symlinks (security)
   * - O_DIRECTORY: Must be a directory
   * - O_CLOEXEC: Close on exec (defense in depth)
   */
  parent_fd = open(dirname(client_keytab_parent), O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
  if (parent_fd < 0) {
    (void)fprintf(stderr, "%s: Landlock cannot open/read parent directory %s: %s\n", __PROGRAM_NAME, client_keytab_parent, strerror(errno));
    (void)free(client_keytab_parent);
    (void)free(client_keytab_dirname);
    (void)close(landlock_ruleset_fd);
    exit(EXIT_FAILURE);
  }

  /* Clean up the duplicated path */
  (void)free(client_keytab_parent);
  client_keytab_parent = NULL;

  /* Associate the parent directory with the landlock ruleset */
  path_beneath.parent_fd = parent_fd;

  landlock_error = syscall(__NR_landlock_add_rule, landlock_ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);

  /* Close parent fd - it's been consumed by landlock */
  (void)close(parent_fd);
  parent_fd = -1;

  if (landlock_error != 0) {
    (void)fprintf(stderr, "%s: Landlock cannot apply ruleset to %s: %s\n", __PROGRAM_NAME, client_keytab_dirname, strerror(errno));
    (void)free(client_keytab_dirname);
    (void)close(landlock_ruleset_fd);
    exit(EXIT_FAILURE);
  }

  /* Apply the landlock ruleset to the current process */
  if (syscall(__NR_landlock_restrict_self, landlock_ruleset_fd, 0) != 0) {
    (void)fprintf(stderr, "%s: Landlock cannot restrict process: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)free(client_keytab_dirname);
    (void)close(landlock_ruleset_fd);
    exit(EXIT_FAILURE);
  }

  /* Clean up resources */
  (void)free(client_keytab_dirname);
  (void)close(landlock_ruleset_fd);
}

#endif /* KCRON_LANDLOCK_H */
