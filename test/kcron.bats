#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
#
# cron.bats - shell tests for the kcron utilities.
#
# These tests exercise everything that can be tested hermetically:
#   * kcron.sysconfig variable derivation (offline, deterministic)
#   * the control flow of kcroninit / kcrondestroy when all external commands
#     (kadmin, kinit, ...) are stubbed, so no Kerberos tooling or KDC is needed.
#
# End-to-end keytab creation requires a live KDC and is intentionally out of
# scope for automated tests.
#
# This suite deliberately ships its own tiny assertion helpers rather than
# pulling in bats-assert. The distro bats-core installed here does not provide
# the `batslib_*` / `fail` helpers that bats-assert depends on, so the upstream
# library cannot load. A handful of self-contained helpers keeps the suite
# dependency-free, deterministic, and easy to audit.

# shellcheck shell=bats

# Resolve paths relative to this file so the suite works from any CWD.
: "${BATS_TEST_DIRNAME:=$PWD}"
KCRON_SRC_DIR="$BATS_TEST_DIRNAME/../src/shell"
SYSKCONFIG="$KCRON_SRC_DIR/kcron.sysconfig"
KCRONINIT="$KCRON_SRC_DIR/kcroninit"
KCRONDESTROY="$KCRON_SRC_DIR/kcrondestroy"

# A fixed identity keeps derivations deterministic regardless of the caller.
readonly REALM=EXAMPLE.ORG
readonly WHOAMI=alice
readonly NODENAME=node01

# ---------------------------------------------------------------------------
# Minimal assertion helpers (assert_success, assert_failure, assert_output,
# refute_output, assert_equal). Each returns non-zero on failure, which is how
# bats marks a test "not ok"; assert functions also print a diagnostic.
# ---------------------------------------------------------------------------

__assert_fail() {
    # $1 = human-readable reason
    printf -- '-- assertion failed: %s --\n' "$1" >&2
    printf '%s\n' "$output" >&2
    return 1
}

assert_success() {
    if [[ $status -ne 0 ]]; then
        __assert_fail "expected status 0, got $status"
    fi
}

assert_failure() {
    if [[ $status -eq 0 ]]; then
        __assert_fail "expected non-zero status, got 0"
    fi
}

# assert_output [--partial] <expected>
assert_output() {
    local partial=0 expected=""
    while [[ ${1:-} == --* ]]; do
        case "$1" in
            --partial) partial=1 ;;
            --) shift; break ;;
            *) shift ;;
        esac
        shift
    done
    expected="${1:-}"
    if [[ $partial -eq 1 ]]; then
        [[ "$output" == *"$expected"* ]] \
            || __assert_fail "output did not contain: $expected"
    else
        [[ "$output" == "$expected" ]] \
            || __assert_fail "output did not equal: $expected"
    fi
}

# refute_output [--partial] <unexpected>
refute_output() {
    local partial=0 unexpected=""
    while [[ ${1:-} == --* ]]; do
        case "$1" in
            --partial) partial=1 ;;
            --) shift; break ;;
            *) shift ;;
        esac
        shift
    done
    unexpected="${1:-}"
    if [[ $partial -eq 1 ]]; then
        [[ "$output" != *"$unexpected"* ]] \
            || __assert_fail "output unexpectedly contained: $unexpected"
    else
        [[ "$output" != "$unexpected" ]] \
            || __assert_fail "output unexpectedly equal: $unexpected"
    fi
}

# assert_equal [actual] [expected]
assert_equal() {
    if [[ "$2" != "$1" ]]; then
        __assert_fail "expected '$2' but got '$1'"
    fi
}

setup() {
    # Build a hermetic stub for every external the scripts may call, then run
    # them with that stub directory first on PATH. This makes the control flow
    # deterministic and removes the Kerberos dependency from the test.
    STUBDIR="$(mktemp -d)"
    local tool
    for tool in kadmin kinit klist kdestroy logger md5sum id date \
                basename hostname cut whoami grep tr tail cat printf; do
        printf '#!/bin/bash\nexit 0\n' >"$STUBDIR/$tool"
        chmod +x "$STUBDIR/$tool"
    done

    # The kcron shell utilities invoke the kcron-internal helpers through
    # env-overridable absolute-path variables. Point those at tiny stubs so the
    # real (seccomp/landlock-restricted) /usr/libexec binaries never run.
    printf '#!/bin/bash\nexit 0\n' >"$STUBDIR/kdir"
    printf '#!/bin/bash\nexit 0\n' >"$STUBDIR/kcreate"
    # shellcheck disable=SC2016
    printf '#!/bin/bash\necho "${STUBDIR}/client.keytab"\nexit 0\n' >"$STUBDIR/kname"
    for tool in kdir kcreate kname; do
        chmod +x "$STUBDIR/$tool"
    done
    touch "$STUBDIR/client.keytab"

    export STUBDIR
    STUBPATH="$STUBDIR:/usr/bin:/bin"
    export STUBPATH
    export KEYTAB_DIR_INIT="$STUBDIR/kdir"
    export KEYTAB_NAME="$STUBDIR/kname"
    export KEYTAB_CREATE="$STUBDIR/kcreate"
    export KEYTAB_NAME_UTIL="$STUBDIR/kname"
}

teardown() {
    rm -rf "$STUBDIR"
}

# sysconfig_get <VAR> [ENV=value ...]
# Source the sysconfig under the given environment and print one variable.
sysconfig_get() {
    local var="$1"
    shift
    env "$@" bash -c "source '$SYSKCONFIG'; printf '%s' \"\${$var}\""
}

# run_cli <script> <input> [ENV=value ...]
# Execute a cron shell script with the stub PATH and the supplied stdin.
run_cli() {
    local script="$1" input="$2"
    shift 2
    run env PATH="$STUBPATH" "$@" bash "$script" <<<"$input"
}

# ---------------------------------------------------------------------------
# kcron.sysconfig derivation
# ---------------------------------------------------------------------------

@test "sysconfig: explicit KCRON_* values are used verbatim" {
    run sysconfig_get FULLPRINCIPAL \
        KCRON_REALM="$REALM" KCRON_WHOAMI="$WHOAMI" KCRON_NODENAME="$NODENAME"
    assert_equal "$output" "alice/cron/node01@EXAMPLE.ORG"
}

@test "sysconfig: WHOAMI and NODENAME derive from KCRON_* overrides" {
    run sysconfig_get WHOAMI KCRON_WHOAMI="$WHOAMI"
    assert_equal "$output" "alice"

    run sysconfig_get NODENAME KCRON_NODENAME="$NODENAME"
    assert_equal "$output" "node01"
}

@test "sysconfig: REALM derives from krb5 default_realm" {
    local conf
    conf="$(mktemp "$BATS_TEST_DIRNAME/.krb5.XXXXXX")"
    printf 'default_realm = REALM.TEST\n' >"$conf"

    # Pin KRB5_CONF_D to an unmatched glob so the system /etc/krb5.conf.d/*
    # drop-ins cannot leak into the derived realm (keeps the test hermetic).
    run sysconfig_get REALM \
        KRB5_CONFIG="$conf" KRB5_CONF_D="$BATS_TEST_DIRNAME/.nobind/*"
    assert_equal "$output" "REALM.TEST"

    rm -f "$conf"
}

@test "sysconfig: explicit KCRON_REALM wins over derived default_realm" {
    local conf
    conf="$(mktemp "$BATS_TEST_DIRNAME/.krb5.XXXXXX")"
    printf 'default_realm = REALM.TEST\n' >"$conf"

    run sysconfig_get REALM \
        KRB5_CONFIG="$conf" KRB5_CONF_D="$BATS_TEST_DIRNAME/.nobind/*" \
        KCRON_REALM="OVERRIDE.ORG"
    assert_equal "$output" "OVERRIDE.ORG"

    rm -f "$conf"
}

# ---------------------------------------------------------------------------
# kcroninit control flow (externals stubbed)
# ---------------------------------------------------------------------------

@test "kcroninit: declining the prompt exits cleanly" {
    run_cli "$KCRONINIT" "n" \
        KCRON_REALM="$REALM" KCRON_WHOAMI="$WHOAMI" KCRON_NODENAME="$NODENAME"
    assert_success
    assert_output --partial "need to know the password"
    refute_output --partial "Cannot create principal"
}

@test "kcroninit: accepting the prompt proceeds to principal creation" {
    run_cli "$KCRONINIT" "y" \
        KCRON_REALM="$REALM" KCRON_WHOAMI="$WHOAMI" KCRON_NODENAME="$NODENAME"
    # Stubs return no data, so the principal check fails and the tool exits
    # non-zero after logging the credential step and cleanup.
    assert_failure
    assert_output --partial "Trying to obtain initial credentials"
    assert_output --partial "Cannot create principal"
    assert_output --partial "DESTROYED administration credentials"
}

# ---------------------------------------------------------------------------
# kcrondestroy control flow (externals stubbed)
# ---------------------------------------------------------------------------

@test "kcrondestroy: declining the prompt exits cleanly" {
    run_cli "$KCRONDESTROY" "n" \
        KCRON_REALM="$REALM" KCRON_WHOAMI="$WHOAMI" KCRON_NODENAME="$NODENAME"
    assert_success
    refute_output --partial "NOTHING TO DO"
}

@test "kcrondestroy: a missing principal is reported as nothing to do" {
    run_cli "$KCRONDESTROY" "y" \
        KCRON_REALM="$REALM" KCRON_WHOAMI="$WHOAMI" KCRON_NODENAME="$NODENAME"
    assert_success
    assert_output --partial "does not exist"
    assert_output --partial "NOTHING TO DO"
}
