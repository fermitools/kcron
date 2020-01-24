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

#ifndef KCRON_SETUP_H
#define KCRON_SETUP_H 1

#include <stdio.h>        /* for fprintf, fwrite, stderr, etc  */
#include <stdlib.h>       /* for EXIT_SUCCESS, EXIT_FAILURE    */
#include <sys/prctl.h>    /* for prctl, PR_SET_DUMPABLE        */
#include <sys/ptrace.h>   /* for ptrace                        */
#include <sys/resource.h> /* for rlimit, RLIMIT_               */

int set_kcron_ulimits(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int set_kcron_ulimits(void) {

  const struct rlimit proc = {0, 0};
  const struct rlimit filesize = {1024, 2048};
  const struct rlimit memlock = {0, 0};
  const struct rlimit data = {16384, 32768};
  const struct rlimit memq = {0, 0};
  const struct rlimit stack = {1024, 2048};
  const struct rlimit fileopen = {8, 10};
  const struct rlimit cpusecs = {8, 16};

  if (setrlimit(RLIMIT_NPROC, &proc) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable forking.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_FSIZE, &filesize) != 0) {
    (void)fprintf(stderr, "%s: Cannot lower max file size.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_MEMLOCK, &memlock) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable memory locking.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_DATA, &data) != 0) {
    (void)fprintf(stderr, "%s: Cannot set max data segment.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_MSGQUEUE, &memq) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable memory queue.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_STACK, &stack) != 0) {
    (void)fprintf(stderr, "%s: Cannot lower stack size.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_NOFILE, &fileopen) != 0) {
    (void)fprintf(stderr, "%s: Cannot lower max open files.\n", __PROGRAM_NAME);
    return 1;
  }

  if (setrlimit(RLIMIT_CPU, &cpusecs) != 0) {
    (void)fprintf(stderr, "%s: Cannot set CPU max runtime.\n", __PROGRAM_NAME);
    return 1;
  }

  return 0;
}

void harden_runtime(void) __attribute__((flatten));
void harden_runtime(void) {
  if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
    (void)fprintf(stderr, "%s: Do not trace me.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (prctl(PR_SET_DUMPABLE, 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable core dumps.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (clearenv() != 0) {
    (void)fprintf(stderr, "%s: Cannot clear environment variables.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (set_kcron_ulimits() != 0) {
    (void)fprintf(stderr, "%s: Cannot set ulimits.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

#if USE_SECCOMP == 1
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0) {
    (void)fprintf(stderr, "%s: Cannot drop useless syscalls.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
#endif

  if (disable_capabilities() != 0) {
    (void)fprintf(stderr, "%s: Cannot drop extra permissions.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

}

#endif
