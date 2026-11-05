#!/bin/bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Fermi Forward Discovery Group
#
# hardening.sh - Verify build hardening of kcron binaries.
#
# It is driven by CTest instead of rpmbuild. It prefers checksec and falls back
# to hardening-check when checksec is unavailable. When neither tool is
# installed the test is a no-op so minimal toolchains do not break.

set -u

if [[ $# -eq 0 ]]; then
    echo "no binaries provided"
    exit 1
fi

if command -v checksec >/dev/null 2>&1; then
    TOOL=checksec
elif command -v hardening-check >/dev/null 2>&1; then
    TOOL=hardening-check
else
    echo "SKIP: neither checksec nor hardening-check is installed"
    exit 0
fi

FAILED=0
for binary in "$@"; do
    if [[ ! -f "$binary" ]]; then
        echo "SKIP: binary not found: $binary"
        continue
    fi

    echo "==> $TOOL on $(basename "$binary")"
    if [[ "$TOOL" == "checksec" ]]; then
        if ! checksec --file="$binary"; then
            echo "checksec --file reported issues for $binary"
            FAILED=1
        fi
        if ! checksec --fortify-file="$binary"; then
            echo "checksec --fortify-file reported issues for $binary"
            FAILED=1
        fi
    else
        if ! hardening-check "$binary"; then
            echo "hardening-check reported issues for $binary"
            FAILED=1
        fi
    fi
done

if [[ "$FAILED" -ne 0 ]]; then
    echo "hardening checks failed"
    exit 1
fi
echo "hardening checks passed"
exit 0
