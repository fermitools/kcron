/* SPDX-License-Identifier: MIT */
/*
 *
 * Runtime hardening setup functions including ulimits, seccomp, and landlock
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

#ifndef KCRON_SETUP_H
#define KCRON_SETUP_H 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#if USE_SECCOMP == 1
#include "kcron_seccomp.h"
#endif

#if USE_LANDLOCK == 1
#include "kcron_landlock.h"
#endif

#include "kcron_caps.h"

/*
 * Set restrictive ulimits to minimize attack surface.
 *
 * This function restricts various resource limits to prevent:
 * - Fork bombs (RLIMIT_NPROC = 0)
 * - Large file creation (RLIMIT_FSIZE = 64 bytes, enough for keytab header)
 * - Memory locking attacks (RLIMIT_MEMLOCK = 0)
 * - Message queue attacks (RLIMIT_MSGQUEUE = 0)
 * - Stack overflow attacks (RLIMIT_STACK = 1024 bytes, minimal)
 * - File descriptor exhaustion (RLIMIT_NOFILE = 5: stdin, stdout, stderr, dir fd, file fd)
 * - CPU time bombs (RLIMIT_CPU = 4 seconds, plenty for keytab operations)
 * - Data segment attacks (RLIMIT_DATA = 1MB for mmap page sharing)
 *
 * Returns: 0 on success, 1 on failure
 *
 * Security Principle: Start with most restrictive limits, only relax what's needed.
 */
int set_kcron_ulimits(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int set_kcron_ulimits(void) {
  /* Prevent forking - this process should never spawn children */
  const struct rlimit proc = {0, 0};
  if (setrlimit(RLIMIT_NPROC, &proc) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable forking: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /* Limit file size to 64 bytes (keytab header is 2 bytes, margin for safety) */
  const struct rlimit filesize = {64, 64};
  if (setrlimit(RLIMIT_FSIZE, &filesize) != 0) {
    (void)fprintf(stderr, "%s: Cannot set max file size: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /* Prevent memory locking (mlock/mlockall) */
  const struct rlimit memlock = {0, 0};
  if (setrlimit(RLIMIT_MEMLOCK, &memlock) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable memory locking: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /* Prevent message queue creation */
  const struct rlimit memq = {0, 0};
  if (setrlimit(RLIMIT_MSGQUEUE, &memq) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable message queue: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /* Minimal stack size should be sufficient for this simple program */
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size < 1024) {
    page_size = 4096; /* fallback to workable size */
  }
  rlim_t min_stack = (rlim_t)page_size * 2u;
  const struct rlimit stack = {min_stack, min_stack};
  if (setrlimit(RLIMIT_STACK, &stack) != 0) {
    (void)fprintf(stderr, "%s: Cannot set stack size limit: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /*
   * Limit open file descriptors to exactly what we need:
   * 0: stdin (redirected to /dev/null)
   * 1: stdout (for printing keytab path)
   * 2: stderr (for error messages)
   * 3: directory fd (from opendir)
   * 4: file fd (for keytab file)
   */
  const struct rlimit fileopen = {5, 5};
  if (setrlimit(RLIMIT_NOFILE, &fileopen) != 0) {
    (void)fprintf(stderr, "%s: Cannot set max open files: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /* CPU time limit (4 seconds is generous for this operation) */
  const struct rlimit cpusecs = {4, 4};
  if (setrlimit(RLIMIT_CPU, &cpusecs) != 0) {
    (void)fprintf(stderr, "%s: Cannot set CPU time limit: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  /*
   * Data segment limit: 1MB for mmap page sharing.
   * This is needed because mmap creates a 1MB page for shared memory.
   */
  const struct rlimit data = {1048576, 1048576};
  if (setrlimit(RLIMIT_DATA, &data) != 0) {
    (void)fprintf(stderr, "%s: Cannot set data segment limit: %s\n", __PROGRAM_NAME, strerror(errno));
    return 1;
  }

  return 0;
}

/*
 * Apply comprehensive runtime hardening measures.
 *
 * This function sets up multiple layers of defense:
 * - Redirects stdin to /dev/null (prevents input-based attacks)
 * - Disables core dumps (prevents memory disclosure)
 * - Sets no_new_privs (prevents privilege escalation via execve)
 * - Clears environment variables (prevents LD_PRELOAD and similar attacks)
 * - Sets restrictive ulimits (resource exhaustion prevention)
 * - Enables landlock (filesystem access control)
 * - Enables seccomp (syscall filtering)
 * - Drops capabilities (privilege minimization)
 *
 * Exits on any failure - hardening is mandatory, not optional.
 *
 * Security Note: Order matters - landlock before seccomp so seccomp can't
 * interfere with landlock setup syscalls.
 */
void harden_runtime(void) __attribute__((flatten));
void harden_runtime(void) {
  /* Redirect stdin to /dev/null to prevent any input operations */
  if (freopen("/dev/null", "r", stdin) == NULL) {
    (void)fprintf(stderr, "%s: Cannot redirect stdin to /dev/null: %s\n", __PROGRAM_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Disable core dumps to prevent memory disclosure on crash */
  if (prctl(PR_SET_DUMPABLE, 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot disable core dumps: %s\n", __PROGRAM_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }

  /*
   * Set no_new_privs flag to prevent gaining privileges through execve.
   * This ensures that even if we somehow execve, we can't gain more privileges.
   */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    (void)fprintf(stderr, "%s: Cannot set no_new_privs: %s\n", __PROGRAM_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Clear all environment variables to prevent environment-dependent behavior */
  if (clearenv() != 0) {
    (void)fprintf(stderr, "%s: Cannot clear environment variables: %s\n", __PROGRAM_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }

  /* Apply resource limits */
  if (set_kcron_ulimits() != 0) {
    (void)fprintf(stderr, "%s: Cannot set ulimits.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

#if USE_LANDLOCK == 1
  /*
   * Enable landlock filesystem access control.
   * This restricts filesystem access to only the keytab directory.
   * Must be done BEFORE seccomp so landlock syscalls are available.
   */
  (void)set_kcron_landlock();
#endif

#if USE_SECCOMP == 1
  /*
   * Enable seccomp syscall filtering.
   * This creates an allowlist of permitted syscalls.
   * Any syscall not explicitly allowed will kill the process.
   */
  if (set_kcron_seccomp() != 0) {
    (void)fprintf(stderr, "%s: Cannot enable seccomp filters.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }
#endif

  /*
   * Drop all capabilities as the final hardening step.
   * At this point, all setup is complete and we should have no special privileges.
   */
  disable_capabilities();
}

#endif /* KCRON_SETUP_H */
