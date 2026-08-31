#!/usr/bin/env bash
# Fetch a PR into an isolated git worktree with its own venv, and flag
# changes that would execute code as soon as tests run.
#
# Usage: bash scripts/pr_setup.sh <pr-number>
#
# Creates ../driftsentry-pr-<N>/ next to the repo. Nothing in the main
# working tree is modified.

set -euo pipefail

PR="${1:-}"
if [[ -z "$PR" ]]; then
    echo "usage: $0 <pr-number>" >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKTREE="${REPO_ROOT}/../driftsentry-pr-${PR}"
BRANCH="pr-${PR}"
DIFF="/tmp/pr-${PR}.diff"

cd "$REPO_ROOT"

echo "==> Fetching PR #${PR}"
git fetch origin "pull/${PR}/head:${BRANCH}" --force

echo
echo "==> Diff summary"
git diff --stat "origin/main...${BRANCH}" | tee "/tmp/pr-${PR}.stat"
git diff "origin/main...${BRANCH}" > "$DIFF"
echo "full diff: ${DIFF}"

echo
echo "==> Risk triage (hits are prompts to look, not verdicts)"

flag() {
    local label="$1" pattern="$2"
    local hits
    hits="$(grep -nE "^\+.*${pattern}" "$DIFF" || true)"
    if [[ -n "$hits" ]]; then
        echo
        echo "  [${label}]"
        echo "$hits" | sed 's/^/    /'
    fi
}

CHANGED="$(git diff --name-only "origin/main...${BRANCH}")"
SENSITIVE_FILES="$(echo "$CHANGED" | grep -E '(^\.github/|pyproject\.toml|requirements.*\.txt|conftest\.py|setup\.py|__init__\.py|Dockerfile|\.gitignore)' || true)"
if [[ -n "$SENSITIVE_FILES" ]]; then
    echo
    echo "  [files that run or gate execution]"
    echo "$SENSITIVE_FILES" | sed 's/^/    /'
fi

flag "process execution"  'subprocess|os\.system|os\.popen|\beval\(|\bexec\('
flag "deserialization"    'pickle|marshal\.loads|yaml\.load\('
flag "network"            'requests\.|urllib|httpx|socket\.|aiohttp'
flag "encoded payloads"   'b64decode|base64\.|fromhex|codecs\.decode'
flag "credentials"        'AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|api_key|password\s*='
flag "filesystem writes"  'open\(|write_text|mkdir|rmtree|unlink'

echo
echo "==> Creating isolated worktree at ${WORKTREE}"
if [[ -d "$WORKTREE" ]]; then
    echo "  already exists — reusing"
else
    git worktree add "$WORKTREE" "$BRANCH"
fi

cd "$WORKTREE"

echo
echo "==> Building venv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"

echo
echo "Ready. Next:"
echo "  cd ${WORKTREE} && source .venv/bin/activate"
echo "  make lint && make test"
echo
echo "Do NOT export real AWS credentials in this shell."
echo
echo "Teardown when done:"
echo "  cd ${REPO_ROOT} && git worktree remove ${WORKTREE} --force && git branch -D ${BRANCH}"
