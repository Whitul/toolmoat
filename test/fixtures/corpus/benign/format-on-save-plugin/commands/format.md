---
description: Format the files changed on this branch with Prettier
allowed-tools: Bash(git diff:*), Bash(npx prettier:*)
---

Format every file changed on the current branch:

1. List the changed files with `git diff --name-only main...HEAD`.
2. Run `npx prettier --write` on the files Prettier supports.
3. Report which files changed.
