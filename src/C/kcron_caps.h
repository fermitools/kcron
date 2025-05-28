/*
 *
 * A simple place where we keep our CAPABILITIES(7) calls
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

#ifndef KCRON_CAPS_H
#define KCRON_CAPS_H 1

#if USE_CAPABILITIES == 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/types.h>

int disable_capabilities(void) __attribute__((flatten)) __attribute__((hot));
int disable_capabilities(void) {
  cap_t capabilities = cap_get_proc();

  if (cap_clear(capabilities)) {
    /* error */
    (void)cap_free(capabilities);
    (void)fprintf(stderr, "%s: Unable to clear CAPABILITIES\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  (void)cap_free(capabilities);
  return 0;
}

static void print_cap_error(const char *mode, const cap_value_t expected_cap[], const int num_caps) __attribute__((nonnull(1))) __attribute__((access(read_only, 1))) __attribute__((flatten));
static void print_cap_error(const char *mode, const cap_value_t expected_cap[], const int num_caps) {
  (void)fprintf(stderr, "%s: Unable to set CAPABILITIES %s\n", __PROGRAM_NAME, mode);
  (void)fprintf(stderr, "%s: Requested CAPABILITIES %s %i:\n", __PROGRAM_NAME, mode, num_caps);
  for (int i = 0; i < num_caps; i++) {
    (void)fprintf(stderr, "%s:    capability:%s\n", __PROGRAM_NAME, cap_to_name(expected_cap[i]));
  }
}

int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) __attribute__((nonnull(1))) __attribute__((warn_unused_result)) __attribute__((flatten)) __attribute__((hot)) __attribute__((access(read_only, 1)));
int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) {
  cap_t capabilities = cap_get_proc();

  /* clear any active capabilities */
  if (disable_capabilities() != 0) {
    (void)cap_free(capabilities);
    exit(EXIT_FAILURE);
  }

  if (cap_set_flag(capabilities, CAP_PERMITTED, num_caps, expected_cap, CAP_SET) == -1) {
    (void)cap_free(capabilities);
    /* error */
    (void)print_cap_error("PERMITTED", expected_cap, num_caps);
    exit(EXIT_FAILURE);
  }

  if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, expected_cap, CAP_SET) == -1) {
    (void)cap_free(capabilities);
    /* error */
    (void)print_cap_error("ACTIVE", expected_cap, num_caps);
    exit(EXIT_FAILURE);
  }

  if (cap_set_proc(capabilities) == -1) {
    (void)cap_free(capabilities);
    /* error */
    (void)print_cap_error("ACTIVE", expected_cap, num_caps);
    exit(EXIT_FAILURE);
  }

  (void)cap_free(capabilities);
  return 0;
}
#else
typedef int cap_value_t; /* so prototypes stay identical */

/* If not caps, just return 0 */
int disable_capabilities(void) __attribute__((warn_unused_result)) __attribute__((flatten));
int disable_capabilities(void) {
  return 0;
}

int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) __attribute__((nonnull(1))) __attribute__((warn_unused_result)) __attribute__((flatten)) __attribute__((access(read_only, 1))) __attribute__((access(read_only, 2)));
int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) {
  return 0;
}
#endif
#endif
