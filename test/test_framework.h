/*
 * test_framework.h
 *
 * SPDX-License-Identifier: CC-PDDC
 * SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
 *
 * This file is dedicated to the public domain under the
 * Creative Commons Public Domain Dedication and Certification (CC-PDDC).
 * This license applies only to the framework, not uses of the framework.
 *
 * Minimal TAP 14–compliant unit test framework (fork-isolated).
 *
 * Features:
 *   - TAP version 14 output
 *   - Fork isolation per test
 *   - Per-test timeout
 *   - Output suppression (use -s flag to show)
 *   - Multi-test filtering (space-separated)
 *   - lcov/gcov compatible
 *
 * NOTE: The macros hide a lot, you should not use different syntax!
 *
 * Example usage:
 *
 *   #include "test_framework.h"
 *
 *   TEST(addition) {
 *       TEST_ASSERT_EQ(2 + 2, 4, "basic arithmetic");
 *       TEST_ASSERT_NOT_EQ(2 + 2, 5, "should not equal 5");
 *   }
 *
 *   TEST(strings) {
 *       TEST_ASSERT_STR_EQ("abc", "abc", "strings match");
 *       TEST_ASSERT_STR_NOT_EQ("abc", "xyz", "strings differ");
 *   }
 *
 *   TEST(pointers) {
 *       char *ptr = malloc(10);
 *       TEST_ASSERT_NOT_EQ(ptr, NULL, "allocation succeeded");
 *       free(ptr);
 *   }
 *
 *   int main(int argc, char **argv) {
 *       TEST_INIT(10, false, false); // timeout, verbose, duration
 *
 *       RUN_TEST(addition);
 *       RUN_TEST(strings);
 *       RUN_TEST(pointers);
 *
 *       int result = TEST_EXECUTE();
 *       return result;
 *   }
 *
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================
 * Internal State
 * ============================================================================
 */

struct _test_state_struct {
  int current;
  int failed;
};

static struct _test_state_struct _test_state = {0, 0};

struct _test_entry {
  const char *name;
  void (*func)(void);
};

#define MAX_TESTS 1024

static struct _test_entry _test_registry[MAX_TESTS];
static int _test_registry_count = 0;

/* ============================================================================
 * Assertion Macros
 * ============================================================================
 */

#define TEST_ASSERT_EQ(actual, expected, msg)                                  \
  do {                                                                         \
    long _a = (long)(actual);                                                  \
    long _e = (long)(expected);                                                \
    if (_a != _e) {                                                            \
      fprintf(stderr, "# FAIL: %s:%d\n", __FILE__, __LINE__);                  \
      fprintf(stderr, "#   Expected: %ld\n", _e);                              \
      fprintf(stderr, "#   Got:      %ld\n", _a);                              \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_NOT_EQ(actual, expected, msg)                              \
  do {                                                                         \
    long _a = (long)(actual);                                                  \
    long _e = (long)(expected);                                                \
    if (_a == _e) {                                                            \
      fprintf(stderr, "# FAIL: %s:%d\n", __FILE__, __LINE__);                  \
      fprintf(stderr, "#   Should not equal: %ld\n", _e);                      \
      fprintf(stderr, "#   Got:              %ld\n", _a);                      \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_STR_EQ(actual, expected, msg)                              \
  do {                                                                         \
    const char *_a = (actual);                                                 \
    const char *_e = (expected);                                               \
    if (_a == NULL || _e == NULL) {                                            \
      fprintf(stderr, "# FAIL: %s:%d\n", __FILE__, __LINE__);                  \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
    if (strcmp(_a, _e) != 0) {                                                 \
      fprintf(stderr, "# FAIL: %s:%d: strings differ\n", __FILE__, __LINE__);  \
      fprintf(stderr, "#   Expected: \"%s\"\n", _e);                           \
      fprintf(stderr, "#   Got:      \"%s\"\n", _a);                           \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_STR_NOT_EQ(actual, expected, msg)                          \
  do {                                                                         \
    const char *_a = (actual);                                                 \
    const char *_e = (expected);                                               \
    if (_a == NULL || _e == NULL) {                                            \
      fprintf(stderr, "# FAIL: %s:%d\n", __FILE__, __LINE__);                  \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
    if (strcmp(_a, _e) == 0) {                                                 \
      fprintf(stderr, "# FAIL: %s:%d: strings should differ\n", __FILE__,      \
              __LINE__);                                                       \
      fprintf(stderr, "#   Should not equal: \"%s\"\n", _e);                   \
      fprintf(stderr, "#   Got:              \"%s\"\n", _a);                   \
      fprintf(stderr, "#   %s\n", msg);                                        \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

/* ============================================================================
 * Test Definition and Registration
 * ============================================================================
 */

#define TEST(name) static void test_##name(void)

/* Register a test - must be called inside main() */
#define RUN_TEST(test_name)                                                    \
  do {                                                                         \
    if (_test_registry_count >= MAX_TESTS) {                                   \
      fprintf(stderr, "Too many tests registered\n");                          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
    _test_registry[_test_registry_count].name = #test_name;                    \
    _test_registry[_test_registry_count].func = test_##test_name;              \
    _test_registry_count++;                                                    \
  } while (0)

/* ============================================================================
 * Test Configuration
 * ============================================================================
 */

struct _test_config {
  int timeout_seconds; /* Per-test timeout (0 = disabled) */
  bool verbose;        /* Show diagnostic messages */
  bool show_duration;  /* Show test execution time */
};

static struct _test_config _test_config = {10, 0, 0};

/* ============================================================================
 * Output Suppression
 * ============================================================================
 */

static int _show_test_outputs = 0;

static inline void _suppress_outputs(void) {
  if (_show_test_outputs)
    return;

  int devnull = open("/dev/null", O_WRONLY);
  if (devnull < 0) {
    perror("open /dev/null");
    return;
  }

  dup2(devnull, STDOUT_FILENO);
  dup2(devnull, STDERR_FILENO);
  close(devnull);
}

/* ============================================================================
 * Test Filtering
 * ============================================================================
 */

#define MAX_FILTERS 256

struct _test_filter {
  char *patterns[MAX_FILTERS];
  int count;
};

static inline void _filter_init(struct _test_filter *f) { f->count = 0; }

static inline void _filter_add(struct _test_filter *f, const char *pattern) {
  if (f->count >= MAX_FILTERS) {
    fprintf(stderr, "Too many filter patterns (max %d)\n", MAX_FILTERS);
    exit(EXIT_FAILURE);
  }
  f->patterns[f->count++] = strdup(pattern);
}

static inline int _filter_matches(const struct _test_filter *f,
                                  const char *name) {
  if (f->count == 0)
    return 1; /* No filter = match all */

  for (int i = 0; i < f->count; i++) {
    if (strcmp(f->patterns[i], name) == 0)
      return 1;
  }
  return 0;
}

static inline void _filter_free(struct _test_filter *f) {
  for (int i = 0; i < f->count; i++) {
    free(f->patterns[i]);
  }
}

/* ============================================================================
 * Test Execution
 * ============================================================================
 */

static inline int _run_test_isolated(const char *name, void (*func)(void)) {
  /* Flush parent output before fork */
  fflush(stdout);
  fflush(stderr);

  struct timespec start, end;
  if (_test_config.show_duration) {
    clock_gettime(CLOCK_MONOTONIC, &start);
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if (pid == 0) {
    /* Child process: set timeout alarm if enabled */
    if (_test_config.timeout_seconds > 0) {
      /* Cast to unsigned int to satisfy alarm() prototype */
      alarm((unsigned int)_test_config.timeout_seconds);
    }

    /* Suppress outputs (unless -s) and run test */
    _suppress_outputs();
    func();
    exit(0);
  }

  /* Parent process: wait and report result */
  int status = 0;
  waitpid(pid, &status, 0);

  double duration = 0.0;
  if (_test_config.show_duration) {
    clock_gettime(CLOCK_MONOTONIC, &end);

    /* Cast to double to avoid -Wconversion warnings */
    duration = (double)(end.tv_sec - start.tv_sec) +
               (double)(end.tv_nsec - start.tv_nsec) / 1e9;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    if (_test_config.show_duration) {
      printf("ok %d - %s # %.3fs\n", _test_state.current, name, duration);
    } else {
      printf("ok %d - %s\n", _test_state.current, name);
    }
    fflush(stdout);
    return 0;
  } else {
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
      if (_test_config.show_duration) {
        printf("not ok %d - %s # TIMEOUT (>%ds)\n", _test_state.current, name,
               _test_config.timeout_seconds);
      } else {
        printf("not ok %d - %s # TIMEOUT\n", _test_state.current, name);
      }
    } else {
      if (_test_config.show_duration) {
        printf("not ok %d - %s # %.3fs\n", _test_state.current, name, duration);
      } else {
        printf("not ok %d - %s\n", _test_state.current, name);
      }
    }
    fflush(stdout);
    return 1;
  }
}

static inline int _test_execute_all(struct _test_filter *filter) {
  int total_tests = 0;

  /* Count matching tests */
  for (int i = 0; i < _test_registry_count; i++) {
    if (_filter_matches(filter, _test_registry[i].name))
      total_tests++;
  }

  if (total_tests == 0) {
    fprintf(stderr, "# No tests matched filter\n");
    return EXIT_FAILURE;
  }

  /* Emit TAP header ONCE before any tests run */
  printf("TAP version 14\n");
  printf("1..%d\n", total_tests);
  fflush(stdout);

  /* Run tests */
  for (int i = 0; i < _test_registry_count; i++) {
    if (!_filter_matches(filter, _test_registry[i].name))
      continue;

    _test_state.current++;

    if (_run_test_isolated(_test_registry[i].name, _test_registry[i].func) !=
        0) {
      _test_state.failed++;
    }
  }

  _filter_free(filter);
  return (_test_state.failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ============================================================================
 * Main Entry Helpers
 * ============================================================================
 */

/* Initialize test framework - call at start of main() */
static inline void _test_init(int argc, char **argv,
                              struct _test_filter *filter, int default_timeout,
                              bool default_verbose,
                              bool default_show_duration) {
  _filter_init(filter);

  /* Set defaults */
  _test_config.timeout_seconds = default_timeout;
  _test_config.verbose = default_verbose;
  _test_config.show_duration = default_show_duration;

  int opt;
  while ((opt = getopt(argc, argv, "st:vdh")) != -1) {
    switch (opt) {
    case 's':
      _show_test_outputs = 1;
      break;
    case 't':
      _test_config.timeout_seconds = atoi(optarg);
      break;
    case 'v':
      _test_config.verbose = true;
      break;
    case 'd':
      _test_config.show_duration = true;
      break;
    case 'h':
      fprintf(stderr, "Usage: %s [-svd] [-t timeout] [test1 test2 ...]\n",
              argv[0]);
      fprintf(stderr, "  -s          Show test stdout/stderr\n");
      fprintf(stderr,
              "  -t SECONDS  Set per-test timeout (0=disabled, default=%d)\n",
              default_timeout);
      fprintf(stderr, "  -v          Verbose output\n");
      fprintf(stderr, "  -d          Show test duration\n");
      fprintf(stderr, "  -h          Show this help\n");
      exit(EXIT_SUCCESS);
    default:
      fprintf(stderr, "Usage: %s [-svd] [-t timeout] [test1 test2 ...]\n",
              argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* Parse space-separated test names from remaining arguments */
  while (optind < argc) {
    _filter_add(filter, argv[optind]);
    optind++;
  }

  if (_test_config.verbose) {
    fprintf(stderr, "# Test configuration:\n");
    fprintf(stderr, "#   Timeout: %d seconds\n", _test_config.timeout_seconds);
    fprintf(stderr, "#   Verbose: %s\n",
            _test_config.verbose ? "enabled" : "disabled");
    fprintf(stderr, "#   Show duration: %s\n",
            _test_config.show_duration ? "enabled" : "disabled");
    fprintf(stderr, "#   Show outputs: %s\n",
            _show_test_outputs ? "enabled" : "disabled");
  }

  _test_state.current = 0;
  _test_state.failed = 0;
  _test_registry_count = 0;
}

#define TEST_INIT(timeout, verbose, show_duration)                             \
  struct _test_filter filter;                                                  \
  _test_init(argc, argv, &filter, timeout, verbose, show_duration)

/* Execute all registered tests */
#define TEST_EXECUTE() _test_execute_all(&filter)

#endif /* TEST_FRAMEWORK_H */
