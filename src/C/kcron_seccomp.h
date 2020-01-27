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

#ifndef KCRON_SECCOMP_H
#define KCRON_SECCOMP_H 1

#include <seccomp.h>      /* libseccomp */

int set_kcron_seccomp(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int set_kcron_seccomp(void) {

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); /* default action: kill */

  if (ctx == NULL) {
    return 1;
  }

  /* Permitted actions */
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'rt_sigreturn'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'exit'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'exit_group'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'prctl'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'geteuid'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'getuid'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'getgid'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1)) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'write' to stdout.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 2)) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'write' to stderr.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 3)) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'write' to our file handle.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'close'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'fsync'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'fstat'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'stat'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'mkdir'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'chown'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'chmod'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }

  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'openat'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }

#if USE_CAPABILITIES == 1
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'capget'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset), 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot whitelist 'capset'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
#endif




/*
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) != 0 {
    (void)fprintf(stderr, "%s: Cannot whitelist 'read'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) != 0 {
    (void)fprintf(stderr, "%s: Cannot whitelist 'write'.\n", __PROGRAM_NAME);
    seccomp_release(ctx);
    return 1;
  }
*/

  /* Load rules */
  seccomp_load(ctx);

  /* Release memory */
  seccomp_release(ctx);

  return 0;
}

#endif
