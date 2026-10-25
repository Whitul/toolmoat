# Security policy

toolmoat is a security tool, so bugs in it can matter more than usual. Two kinds of reports are especially welcome:

- **Bypasses**: a malicious skill, plugin, hook, MCP config or tool definition that toolmoat should catch but does not.
- **Weaknesses in toolmoat itself**: anything that lets scanned content crash or hang the scanner (for example a regex with catastrophic backtracking), escape the proxy's checks, corrupt the lockfile, or run code on the machine doing the scanning.

## Reporting

Please report vulnerabilities privately through GitHub's **Report a vulnerability** button on the repository's Security tab, not in a public issue. Include a minimal sample that reproduces the problem. Keep samples inert: use `attacker.example` hosts and fake keys.

Detection gaps that do not put toolmoat users at extra risk (a missed pattern, a false positive) can go in a normal issue.

## Design principles

- toolmoat never executes the code it scans. `scan` only reads files.
- It makes no network requests and sends no telemetry.
- It has no runtime dependencies, so installing it does not pull in third-party code.
- Suppressions come only from the user's own `.toolmoatignore` or command-line flags. Content inside a scanned artifact cannot switch the scanner off.
- Every rule runs on attacker-controlled input and is tested to stay fast on adversarial strings.
