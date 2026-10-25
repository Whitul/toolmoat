# format-on-save

A Claude Code plugin that runs [Prettier](https://prettier.io) on every file
Claude writes or edits.

## Install

```bash
claude plugin install format-on-save@example-tools
```

## How it works

A `PostToolUse` hook runs `hooks/format.sh` after the Write, Edit and MultiEdit
tools. The script reads the edited path from the hook input and formats it with
the project's own Prettier. It never installs packages or makes network
requests.
