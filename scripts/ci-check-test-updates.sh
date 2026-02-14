#!/usr/bin/env bash
set -euo pipefail

BASE_SHA="${1:-}"
HEAD_SHA="${2:-}"

if [[ -z "${BASE_SHA}" || -z "${HEAD_SHA}" ]]; then
  if git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    BASE_SHA="$(git rev-parse HEAD~1)"
    HEAD_SHA="$(git rev-parse HEAD)"
  else
    echo "ci-check-tests: skipping; repository has fewer than 2 commits"
    exit 0
  fi
fi

mapfile -t changed < <(git diff --name-only "${BASE_SHA}" "${HEAD_SHA}")
if [[ ${#changed[@]} -eq 0 ]]; then
  echo "ci-check-tests: no changed files"
  exit 0
fi

has_prod_go=0
has_tests=0
for path in "${changed[@]}"; do
  if [[ "${path}" =~ ^(cmd|internal|pkg)/.*\.go$ ]] && [[ "${path}" != *_test.go ]]; then
    has_prod_go=1
  fi
  if [[ "${path}" =~ _test\.go$ ]] || [[ "${path}" =~ ^test/.*\.go$ ]]; then
    has_tests=1
  fi
done

if [[ ${has_prod_go} -eq 1 && ${has_tests} -eq 0 ]]; then
  echo "ci-check-tests: production Go changes detected without test updates"
  echo "Add or update relevant tests, or split truly trivial refactors into isolated changes."
  exit 1
fi

echo "ci-check-tests: PASS"
