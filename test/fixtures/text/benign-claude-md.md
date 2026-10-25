# Project notes for the coding agent

**Important:** run tests first before you commit anything.

IMPORTANT: use pnpm, never npm.

<important>Always run `pnpm lint` before opening a pull request.</important>

## Setup

Read the .env.example file to learn the variable names, then ask the user for the values.
Copy .env.example to .env and fill in your keys.
Never commit .env files.
Include your API key in the Authorization header when calling the staging API.
Copy your public key (~/.ssh/id_ed25519.pub) into the deploy settings page.
Open ~/.ssh/config and add a Host entry for the build box.

## Tools

When using the Bash tool, always quote paths that contain spaces.
Instead of using the Bash tool for file search, use the Grep tool.
After calling the search tool, summarise the matches for the user.
Ask the user for permission before deleting anything.
Use `-y` to skip confirmation prompts from the package manager.

## Style

The user must not edit generated files by hand.
The user doesn't need to know the internal row IDs, so hide them from tables.
Don't show raw stack traces to the user; summarise the error instead.
Ignore files that do not end in .md when scanning the docs folder.
If the project has a .prettierrc, ignore the linter rules for vendored code.
Override the existing CSS rules in theme.css when the user asks for a dark theme.

## Notifications

Post a comment to the pull request at https://github.com/example/app/pulls when CI fails.
Send a POST request to https://api.example.com/v1/build with the build number.
