#!/usr/bin/env bash
set -euo pipefail

if [[ -d .git ]]; then
  echo "A Git repository already exists. No changes made."
  exit 0
fi

git init
git add .
git commit -m "feat: create Hedge Build Week foundation"

echo "Repository initialized. Create the remote repository, push this commit, and keep the primary Codex session attached to this folder."
