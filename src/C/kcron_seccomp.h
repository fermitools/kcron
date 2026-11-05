/* SPDX-License-Identifier: MIT */
/*
 *
 * Seccomp syscall filtering for kcron
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

#ifndef KCRON_SECCOMP_H
#define KCRON_SECCOMP_H 1

#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef _0600
#define _0600 (S_IRUSR | S_IWUSR)
#endif

/*
 * Set up seccomp syscall filtering.
 *
 * This function creates a strict allowlist of syscalls that the program
 * is permitted to use. Any syscall not explicitly allowed will result in
 * the process being killed (SCMP_ACT_KILL).
 *
 * Allowed syscalls are grouped by purpose:
 * - Basic runtime: rt_sigreturn, brk, exit, exit_group
 * - Identity queries: geteuid, getuid, getgid
 * - I/O operations: write (restricted to specific fds), openat, close, fstat, fsync
 * - File operations: stat, newfstatat, mkdir, fchown, fchmod (restricted)
 * - Capability management: capget, capset (if capabilities enabled)
 *
 * Returns: 0 on success, exits on failure
 *
 * Security Principle: Default deny with explicit allow. If it's not in the list,
 * it can't be used. This is defense-in-depth against exploitation.
 *
 * Note on argument-restricted rules: SCMP_A0()/SCMP_A1() build a
 * "struct scmp_arg_cmp" from only three fields (arg, op, datum_a). datum_b is
 * now supplied explicitly as 0 so the call compiles identically under GCC and
 * Clang; Clang otherwise reports -Wmissing-field-initializers on the omitted
 * trailing field (GCC tolerates it, which is exactly why the omission is not
 * obvious on the host build). datum_b is unused for SCMP_CMP_EQ.
 */
int set_kcron_seccomp(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int set_kcron_seccomp(void) {
  scmp_filter_ctx ctx = NULL;

  /* Create seccomp context with default action: KILL */
  ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    (void)fprintf(stderr, "%s: Cannot initialize seccomp context\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /*
   * BASIC RUNTIME SYSCALLS
   * These are essential for program execution and cannot be avoided.
   */

  /* Signal handling - required for proper signal delivery */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'rt_sigreturn': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Memory allocation - required by libc malloc/free */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'brk': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Process termination - required for clean exit */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'exit': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Thread group termination - required for multi-threaded libc */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'exit_group': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * IDENTITY QUERY SYSCALLS
   * These are needed to determine the calling user's identity.
   */

  /* Get effective user ID - used for keytab path construction */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'geteuid': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get real user ID - used for keytab ownership */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'getuid': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get group ID - used for keytab ownership */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'getgid': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * RESTRICTED OUTPUT SYSCALLS
   * Write is only permitted to stdout (fd 1) and stderr (fd 2).
   * This prevents writing to arbitrary file descriptors.
   */

  /* Write to stdout - for printing keytab path */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'write' to stdout: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Write to stderr - for error messages */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'write' to stderr: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * FILE DESCRIPTOR OPERATIONS
   * These are needed for directory and file handle management.
   */

  /*
   * Open files relative to directory fd - used for safe file creation.
   * Note: Cannot easily restrict arguments, so this is a broader permission.
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'openat': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Close directory handle (fd 3) */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, 3, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'close' for fd 3: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * FILE HANDLE OPERATIONS
   * These operate on the keytab file (fd 4).
   */

  /* Write to keytab file (fd 4) */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 4, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'write' to fd 4: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Close keytab file (fd 4) */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, 4, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'close' for fd 4: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Sync keytab file to disk (fd 4) */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 1, SCMP_A0(SCMP_CMP_EQ, 4, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'fsync' for fd 4: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * Set permissions on keytab file (fd 4) to 0600.
   * Restricts to exactly mode 0600 (user read/write only).
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 2, SCMP_A0(SCMP_CMP_EQ, 4, 0), SCMP_A1(SCMP_CMP_EQ, _0600, 0)) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'fchmod' for mode 0600: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * FILE METADATA OPERATIONS
   * These are needed for checking file/directory properties.
   * Note: Cannot easily restrict arguments for these syscalls.
   */

  /* Get file status by fd - used extensively for verification */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'fstat': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get file status by path - used for existence checks */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'stat': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get file status (newer variant) - used by modern libc */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'newfstatat': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get file status without following symlinks - for symlink detection */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'lstat': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * DIRECTORY OPERATIONS
   * Needed for creating user-specific keytab directories.
   */

  /* Create directory - for user keytab directory */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'mkdir': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Change file ownership - for setting keytab ownership to user */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'fchown': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Get directory entries - used by opendir/readdir */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'getdents64': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * CAPABILITY MANAGEMENT SYSCALLS
   * Only included if capabilities are enabled at compile time.
   */

  /* Get capability state - used by cap_get_proc */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'capget': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Set capability state - used by cap_set_proc */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot allowlist 'capset': %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * Load the seccomp filter into the kernel.
   * After this point, any syscall not in the allowlist will kill the process.
   */
  if (seccomp_load(ctx) != 0) {
    (void)fprintf(stderr, "%s: Cannot load seccomp filters: %s\n", __PROGRAM_NAME, strerror(errno));
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Release the seccomp context memory */
  (void)seccomp_release(ctx);

  return 0;
}

#endif /* KCRON_SECCOMP_H */
