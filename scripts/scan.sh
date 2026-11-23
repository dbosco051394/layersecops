#!/usr/bin/env bash
# Thin wrapper around the Python CLI. Keeps the repo-local tool directory and
# source tree on PATH/PYTHONPATH without requiring an install.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${ROOT}/.tools/bin:${PATH}"

if command -v cygpath >/dev/null 2>&1; then
  PY_ROOT="$(cygpath -w "${ROOT}")"
else
  PY_ROOT="${ROOT}"
fi
export PYTHONPATH="${PY_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

exec "${PYTHON}" -m layersecops "$@"
