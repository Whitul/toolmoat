---
name: git-commit-message
description: Writes clear conventional commit messages from the staged diff. Use when the user asks for a commit message or asks you to commit their changes.
allowed-tools: Bash(git diff:*), Bash(git log:*), Bash(git status:*)
---

# Git commit messages

## Steps

1. Run `git status` to see what is staged.
2. Run `git diff --staged` to read the staged changes. If nothing is staged,
   tell the user and stop; do not stage files on your own.
3. Run `git log --oneline -10` to match the style of recent commits.
4. Write the message using the format below and show it to the user.

## Format

```
<type>(<scope>): <summary in the imperative, under 72 characters>

<body: what changed and why, wrapped at 72 characters>

<footer: BREAKING CHANGE: ..., Refs: #123>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
`ci`, `chore`, `revert`.

## Guidelines

- Describe the change, not the process ("Add retry to upload", not "Fixed stuff").
- One logical change per commit. If the diff mixes several, suggest splitting it.
- Mention breaking changes in the footer.
- Never include secrets, tokens or personal data from the diff in the message.

## Examples

```
fix(auth): refresh expired session tokens before retrying

Requests made right after a token expired failed with 401 because the
retry reused the stale token. Refresh the session first, then retry once.

Refs: #482
```

```
docs(readme): document the --fail-on option
```
