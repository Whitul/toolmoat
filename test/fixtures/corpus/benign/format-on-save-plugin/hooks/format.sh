#!/usr/bin/env bash
# PostToolUse hook: formats the file Claude just wrote or edited.
# Reads the hook payload from stdin and only touches files Prettier supports.
set -euo pipefail

file_path=$(jq -r '.tool_input.file_path // empty')
[ -z "$file_path" ] && exit 0
[ -f "$file_path" ] || exit 0

case "$file_path" in
  *.js|*.jsx|*.ts|*.tsx|*.mjs|*.cjs|*.json|*.css|*.scss|*.md|*.yaml|*.yml|*.html)
    ;;
  *)
    exit 0
    ;;
esac

# Use the project's own Prettier when it has one; never install anything.
if [ -x "./node_modules/.bin/prettier" ]; then
  ./node_modules/.bin/prettier --write --log-level warn "$file_path"
elif command -v prettier >/dev/null 2>&1; then
  prettier --write --log-level warn "$file_path"
fi
