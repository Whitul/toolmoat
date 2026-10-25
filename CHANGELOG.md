# Changelog

## 0.1.0

First release.

- `toolmoat scan`: 50 rules for prompt injection and hidden Unicode, download-and-execute installers, credential and wallet theft, exfiltration endpoints, persistence, agent config tampering, hardcoded secrets, unpinned MCP servers, plaintext secrets in MCP configs and over-broad Claude Code permissions. Finds skills, plugins, hooks and MCP configs for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI. Reports as text, JSON, SARIF or Markdown.
- `toolmoat proxy`: runtime firewall for stdio MCP servers with tool pinning, rug-pull blocking, injection scanning of tool descriptions and output, an egress guard for credentials and an audit log. `pins`, `diff` and `approve` manage the lockfile.
- `toolmoat wrap` / `unwrap`: route the stdio servers in MCP client configs through the proxy and restore them.
- GitHub Action with SARIF upload to code scanning.
