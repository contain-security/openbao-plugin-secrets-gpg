#!/usr/bin/env bash
# Run all regression tests for the GPG plugin against a live OpenBao instance.
#
# Usage:
#   ./tests/run-all.sh                  # run all tests
#   ./tests/run-all.sh 01 04            # run specific test numbers
#   ./tests/run-all.sh --list           # list available tests
#
# Prerequisites:
#   - OpenBao dev server running (with UI or without)
#   - GPG plugin built, registered, and mounted at gpg/
#   - jq installed
#   - GnuPG installed (for interop tests)
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

# List mode
if [ "${1:-}" = "--list" ]; then
    echo "Available tests:"
    for f in "$TESTS_DIR"/[0-9]*.sh; do
        name=$(basename "$f")
        desc=$(head -2 "$f" | grep "^# Test:" | sed 's/^# Test: //' || echo "")
        printf "  %-25s %s\n" "$name" "$desc"
    done
    exit 0
fi

# Check prerequisites
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required but not installed"
    exit 1
fi

echo ""
echo "============================================="
echo "  GPG Plugin Regression Test Suite"
echo "============================================="
echo ""

SUITE_PASS=0
SUITE_FAIL=0
FAILED_SUITES=()

# Determine which tests to run
if [ $# -gt 0 ]; then
    # Run specific tests by number
    TEST_FILES=()
    for num in "$@"; do
        pattern="$TESTS_DIR/${num}-*.sh"
        files=($pattern)
        if [ -f "${files[0]}" ]; then
            TEST_FILES+=("${files[0]}")
        else
            echo "WARNING: No test found matching pattern '$num'"
        fi
    done
else
    # Run all tests
    TEST_FILES=("$TESTS_DIR"/[0-9]*.sh)
fi

for test_file in "${TEST_FILES[@]}"; do
    test_name=$(basename "$test_file")
    echo "--- Running: $test_name ---"
    echo ""

    if bash "$test_file"; then
        SUITE_PASS=$((SUITE_PASS + 1))
    else
        SUITE_FAIL=$((SUITE_FAIL + 1))
        FAILED_SUITES+=("$test_name")
    fi

    echo ""
done

echo "============================================="
echo "  OVERALL RESULTS"
echo "============================================="
echo "  Test suites passed: $SUITE_PASS"
echo "  Test suites failed: $SUITE_FAIL"
if [ ${#FAILED_SUITES[@]} -gt 0 ]; then
    echo ""
    echo "  Failed suites:"
    for s in "${FAILED_SUITES[@]}"; do
        echo "    - $s"
    done
fi
echo "============================================="

[ $SUITE_FAIL -eq 0 ] && exit 0 || exit 1
