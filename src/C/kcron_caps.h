/* SPDX-License-Identifier: MIT */
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/types.h>

/*
 * Disable all capabilities.
 * This function clears all capabilities from the current process.
 *
 * Note: This function exits on failure rather than returning an error code
 * because failing to drop capabilities is a critical security failure.
 */
void disable_capabilities(void) __attribute__((flatten)) __attribute__((hot));
void disable_capabilities(void) {
  cap_t capabilities = cap_get_proc();

  /* Verify capability structure was allocated */
  if (capabilities == NULL) {
    (void)fprintf(stderr, "%s: Unable to get process CAPABILITIES\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Clear all capabilities from the capability set */
  if (cap_clear(capabilities) != 0) {
    (void)cap_free(capabilities);
    (void)fprintf(stderr, "%s: Unable to clear CAPABILITIES\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  (void)cap_free(capabilities);
}

/*
 * Print error message about capability operation failure.
 * Helper function to provide consistent error reporting.
 *
 * Parameters:
 *   mode: Description of the capability mode (e.g., "PERMITTED", "EFFECTIVE")
 *   expected_cap: Array of capability values that were requested
 *   num_caps: Number of capabilities in the array
 */
static void print_cap_error(const char *mode, const cap_value_t expected_cap[], const int num_caps) __attribute__((flatten));
static void print_cap_error(const char *mode, const cap_value_t expected_cap[], const int num_caps) {
  /* Runtime NULL check - required even though this is static/internal */
  if (mode == NULL) {
    (void)fprintf(stderr, "%s: print_cap_error called with NULL mode\n", __PROGRAM_NAME);
    return;
  }
  if (expected_cap == NULL) {
    (void)fprintf(stderr, "%s: print_cap_error called with NULL expected_cap\n", __PROGRAM_NAME);
    return;
  }

  (void)fprintf(stderr, "%s: Unable to set CAPABILITIES %s\n", __PROGRAM_NAME, mode);
  (void)fprintf(stderr, "%s: Requested CAPABILITIES %s count=%d:\n", __PROGRAM_NAME, mode, num_caps);

  /* Print each requested capability name */
  for (int i = 0; i < num_caps; i++) {
    char *cap_name = cap_to_name(expected_cap[i]);
    if (cap_name != NULL) {
      (void)fprintf(stderr, "%s:    capability: %s\n", __PROGRAM_NAME, cap_name);
      (void)cap_free(cap_name);
    } else {
      (void)fprintf(stderr, "%s:    capability: UNKNOWN (value=%d)\n", __PROGRAM_NAME, expected_cap[i]);
    }
  }
}

/*
 * Enable specific capabilities for the current process.
 * This sets both PERMITTED and EFFECTIVE capability sets.
 *
 * Parameters:
 *   expected_cap: Array of capability values to enable
 *   num_caps: Number of capabilities in the array
 *
 * Returns: 0 on success, never returns on failure (calls exit).
 *
 * Security Note: This function should only be called immediately before
 * a privileged operation, and disable_capabilities() should be called
 * immediately after. Holding capabilities longer than necessary increases
 * attack surface.
 */
int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) __attribute__((warn_unused_result)) __attribute__((flatten)) __attribute__((hot));
int enable_capabilities(const cap_value_t expected_cap[], const int num_caps) {
  cap_t capabilities = NULL;

  /* Runtime NULL check - required, do not rely on nonnull attribute */
  if (expected_cap == NULL) {
    (void)fprintf(stderr, "%s: enable_capabilities called with NULL expected_cap array\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Validate capability count is reasonable */
  if (num_caps <= 0) {
    (void)fprintf(stderr, "%s: enable_capabilities called with invalid num_caps=%d\n", __PROGRAM_NAME, num_caps);
    exit(EXIT_FAILURE);
  }

  /* Get current process capabilities */
  capabilities = cap_get_proc();
  if (capabilities == NULL) {
    (void)fprintf(stderr, "%s: Unable to get process CAPABILITIES\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Clear any currently active capabilities before setting new ones */
  (void)disable_capabilities();

  /* Re-get capabilities after clearing (disable_capabilities modifies process caps) */
  (void)cap_free(capabilities);
  capabilities = cap_get_proc();
  if (capabilities == NULL) {
    (void)fprintf(stderr, "%s: Unable to re-get process CAPABILITIES\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  /* Set the PERMITTED capability set */
  if (cap_set_flag(capabilities, CAP_PERMITTED, num_caps, expected_cap, CAP_SET) == -1) {
    (void)print_cap_error("PERMITTED", expected_cap, num_caps);
    (void)cap_free(capabilities);
    exit(EXIT_FAILURE);
  }

  /* Set the EFFECTIVE capability set */
  if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, expected_cap, CAP_SET) == -1) {
    (void)print_cap_error("EFFECTIVE", expected_cap, num_caps);
    (void)cap_free(capabilities);
    exit(EXIT_FAILURE);
  }

  /* Apply the capability changes to the current process */
  if (cap_set_proc(capabilities) == -1) {
    (void)print_cap_error("APPLY", expected_cap, num_caps);
    (void)cap_free(capabilities);
    exit(EXIT_FAILURE);
  }

  (void)cap_free(capabilities);
  return 0;
}

#endif /* KCRON_CAPS_H */
