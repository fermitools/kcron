#!/bin/bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
#
# test_sysconfig.sh - Validate kcron.sysconfig variable derivation.
#
# Sourcing the sysconfig performs no privileged operations; it only derives
# REALM / WHOAMI / NODENAME / FULLPRINCIPAL from the environment and the krb5
# configuration. Tests therefore run fully offline: KRB5_CONFIG points at a
# throwaway file and the default krb5.conf.d glob is neutralized so the real
# system configuration is never read.

set -u

TESTS_RUN=0
TESTS_FAILED=0

# assert_eq <description> <expected> <actual>
assert_eq() {
    if [[ "$2" == "$3" ]]; then
        printf 'ok %d - %s\n' "$TESTS_RUN" "$1"
        TESTS_RUN=$((TESTS_RUN + 1))
    else
        printf 'not ok %d - %s\n' "$TESTS_RUN" "$1"
        printf '#   expected: %s\n' "$2"
        printf '#   actual:   %s\n' "$3"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        TESTS_RUN=$((TESTS_RUN + 1))
    fi
}

# run_sysconfig <sysconfig> <VAR=VALUE...> - Source the sysconfig under a
# pristine environment and print the four derived variables (one per line):
# REALM, WHOAMI, NODENAME, FULLPRINCIPAL.
#
# The inner script is single-quoted so the outer shell performs no expansion;
# the sysconfig path is passed as a positional parameter and expanded inside.
run_sysconfig() {
    local sysconfig="$1"
    shift
    # KRB5_CONF_D is forced to a harmless glob so the real system configuration
    # is never consulted, keeping tests deterministic across machines.
    # shellcheck disable=SC2016
    # The bash -c script is single-quoted on purpose: its ${VAR} references
    # must expand in the inner shell, not the outer one.
    env -i PATH="$PATH" HOME="$HOME" \
        KRB5_CONF_D="/nonexistent/krb5.conf.d/nonexistent/*" "${@}" \
        bash -c '
            source "$1"
            printf "%s\n" "${REALM}"
            printf "%s\n" "${WHOAMI}"
            printf "%s\n" "${NODENAME}"
            printf "%s\n" "${FULLPRINCIPAL}"
        ' bash "$sysconfig"
}

SYS="$1"
[[ $# -ge 1 ]] || { echo "usage: $0 <kcron.sysconfig>"; exit 2; }

# Build a throwaway krb5 config containing a single default_realm line.
KRB5CONF="$(mktemp /tmp/kcron_sysconfig_krb5.XXXXXX)"
printf 'default_realm = REALM.TEST\n' > "${KRB5CONF}"
printf 'krb4_realm = OLDREALM\n' >> "${KRB5CONF}"
trap 'rm -f "${KRB5CONF}"' EXIT

# 1. Explicit KCRON_* values win over everything.
mapfile -t OUT < <(run_sysconfig "${SYS}" \
    KCRON_REALM=EXAMPLE.ORG KCRON_WHOAMI=alice KCRON_NODENAME=node01)
assert_eq "explicit overrides win" "alice/cron/node01@EXAMPLE.ORG" "${OUT[3]}"

# 2. REALM/WHOAMI/NODENAME derived, with default_realm from the krb5 config.
mapfile -t OUT < <(run_sysconfig "${SYS}" \
    KRB5_CONFIG="${KRB5CONF}" \
    KCRON_WHOAMI=bob KCRON_NODENAME=node99)
assert_eq "REALM derived from default_realm" "REALM.TEST" "${OUT[0]}"
assert_eq "WHOAMI kept from environment" "bob" "${OUT[1]}"
assert_eq "NODENAME kept from environment" "node99" "${OUT[2]}"
assert_eq "FULLPRINCIPAL derived" "bob/cron/node99@REALM.TEST" "${OUT[3]}"

# 3. KCRON_REALM takes precedence over the derived DEFAULT_REALM.
mapfile -t OUT < <(run_sysconfig "${SYS}" \
    KRB5_CONFIG="${KRB5CONF}" \
    KCRON_REALM=OVERRIDE.ORG KCRON_WHOAMI=carol KCRON_NODENAME=node02)
assert_eq "KCRON_REALM beats derived default" "OVERRIDE.ORG" "${OUT[0]}"
assert_eq "FULLPRINCIPAL uses override realm" "carol/cron/node02@OVERRIDE.ORG" "${OUT[3]}"

# 4. Malformed default_realm lines are ignored (comment + non-matching key).
mapfile -t OUT < <(run_sysconfig "${SYS}" \
    KRB5_CONFIG="${KRB5CONF}" \
    KCRON_WHOAMI=dave KCRON_NODENAME=node03)
assert_eq "only default_realm is honored" "REALM.TEST" "${OUT[0]}"

if [[ "${TESTS_FAILED}" -ne 0 ]]; then
    echo "${TESTS_FAILED} of ${TESTS_RUN} sysconfig checks failed"
    exit 1
fi
echo "${TESTS_RUN} sysconfig checks passed"
exit 0
