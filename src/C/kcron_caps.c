/*
 *
 * A simple place where we keep our CAPABILITIES(7) calls
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

#include <stdio.h>        /* for fprintf, stderr, etc  */
#include <sys/types.h>    /* for uid_t, cap_t, etc     */
#include <unistd.h>       /* for geteuid, etc          */

#if USE_CAPABILITIES == 1
#include <sys/capability.h> /* for cap_t, cap_get_proc, cap_clear, etc */

inline int disable_capabilities(void) {
  cap_t capabilities;

  uid_t euid;
  euid = geteuid();
  if (unlikely(euid == 0)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 2);
    /* pointless for euid 0 */
    return 0;
  }

  capabilities = cap_get_proc();

  if (unlikely(cap_clear(capabilities))) {
    /* error */
    DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 1);
    (void)cap_free(capabilities);
    (void)fprintf(stderr, " Unable to clear CAPABILITIES\n");
    return 1;
  }

  DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 0);
  (void)cap_free(capabilities);
  return 0;
}

inline int enable_capabilities(const cap_value_t expected_cap[]) {
  cap_t capabilities;

  int num_caps = sizeof(*expected_cap) / sizeof((expected_cap)[0]);

  uid_t euid = geteuid();
  if (unlikely(euid == 0)) {
    /* pointless for euid 0 */
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 2);
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 2);
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 2);
    return 0;
  }

  capabilities = cap_get_proc();

  /* clear any active capabilities */
  if (unlikely(disable_capabilities() != 0)) {
    (void)cap_free(capabilities);
    return 1;
  }

  if (unlikely(cap_set_flag(capabilities, CAP_PERMITTED, num_caps, expected_cap, CAP_SET) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, " Unable to set CAPABILITIES PERMITTED\n");
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 0);

  if (unlikely(cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, expected_cap, CAP_SET) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, " Unable to set CAPABILITIES EFFECTIVE\n");
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 0);

  if (unlikely(cap_set_proc(capabilities) == -1)) {
    DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 1);
    (void)cap_free(capabilities);
    /* error */
    (void)fprintf(stderr, " Unable to activate CAPABILITIES\n");
    return 1;
  }
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 0);

  (void)cap_free(capabilities);
  return 0;
}
#else
typedef int cap_value_t; /* so prototypes stay identical */

/* If not caps, just return 0 */
inline int disable_capabilities(void) {
  DTRACE_PROBE1(__PROGRAM_NAME, "clear_cap", 2);
  return 0;
}
inline int enable_capabilities(const cap_value_t expected_cap[]) {
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-permitted", 2);
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-flag-effective", 2);
  DTRACE_PROBE1(__PROGRAM_NAME, "cap-set-active", 2);
  return 0;
}
#endif
