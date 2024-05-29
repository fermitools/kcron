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

#ifndef KCRON_SECCOMP_H
#define KCRON_SECCOMP_H 1

#include <seccomp.h> /* libseccomp                  */
#include <stdio.h>   /* for fprintf, stderr, NULL   */
#include <stdlib.h>  /* for EXIT_FAILURE            */

#include <sys/stat.h> /* for S_IRUSR, S_IWUSR, stat, etc  */

#ifndef _0600
#define _0600 S_IRUSR | S_IWUSR
#endif

int set_kcron_seccomp(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int set_kcron_seccomp(void) {

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */

  if (ctx == NULL) {
    exit(EXIT_FAILURE);
  }

  /* Basic features */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'rt_sigreturn'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'brk'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'exit'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'exit_group'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Permitted actions */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'geteuid'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'getuid'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'getgid'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * STDOUT
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'write' to stdout.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   * STDERR
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'write' to stderr.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   *   Our directory handle
   */

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) != 0) {
    /* not sure how to restrict this to the args I want */
    (void)fprintf(stderr, "%s: Cannot set allowlist 'openat'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, 3)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'close'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   *   Our file handle
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 4)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'write' to our file handle.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 1, SCMP_A0(SCMP_CMP_EQ, 4)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'close'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 1, SCMP_A0(SCMP_CMP_EQ, 4)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'fsync' on file handle.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 2, SCMP_A0(SCMP_CMP_EQ, 4), SCMP_A1(SCMP_CMP_EQ, _0600)) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'fchmod' for mode 0600 only.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /*
   *   General usage, not sure how to restrict these to the args I want....
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'fstat'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'stat'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'newfstatat'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'mkdir'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'fchown'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

#if USE_CAPABILITIES == 1
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'capget'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set allowlist 'capset'.\n", __PROGRAM_NAME);
    (void)seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
#endif

  /* Load rules */
  (void)seccomp_load(ctx);

  /* Release memory */
  (void)seccomp_release(ctx);

  return 0;
}

#endif
