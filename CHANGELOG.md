# Changelog

## 0.2.0

- `toolmoat mcp`: run toolmoat as a stdio MCP server so an agent can scan things itself. Five read-only, offline tools: `scan_path` (a skill, plugin, hook or MCP server before you install it), `scan_installed` (the same locations as `toolmoat scan` with no arguments), `scan_text` (inline content such as a SKILL.md or tool description), `list_rules` and `list_pins`. There is no tool to approve pins, change configs or write files, so an agent cannot approve its own tool changes. No ignore file is read in this mode.
- In MCP mode, `scan_path` refuses network shares and device paths (UNC paths and named pipes on Windows) before touching them. `ping` is answered while a scan runs, `notifications/cancelled` is honoured, and JSON-RPC batches are accepted for clients on protocol version 2025-03-26.
- The MCP server is also exported from the package API: `runMcpServer`, `McpServer`, `MCP_TOOLS` and `callTool`.
- Dockerfile for MCP hosts that run servers in a container. See the README for what to mount.
- Scanning is safer on odd files: reads are capped at the size limit even when a file grows or reports a wrong size, FIFOs and devices are never opened as plugin manifests, and file links that lead to a network share are not followed.
- Reports escape Unicode line and paragraph separators and C1 control characters, and mask passwords embedded in URLs (`https://user:****@host`).
- `TM-SEC-001` reports the API key Claude Code itself keeps in `~/.claude.json` (top-level `primaryApiKey`) as low instead of high, since every Claude Code user signed in with an API key has it. The same key anywhere else, in any other file or in content passed to `scan_text`, is still high.

## 0.1.0

First release.

- `toolmoat scan`: 50 rules for prompt injection and hidden Unicode, download-and-execute installers, credential and wallet theft, exfiltration endpoints, persistence, agent config tampering, hardcoded secrets, unpinned MCP servers, plaintext secrets in MCP configs and over-broad Claude Code permissions. Finds skills, plugins, hooks and MCP configs for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI. Reports as text, JSON, SARIF or Markdown.
- `toolmoat proxy`: runtime firewall for stdio MCP servers with tool pinning, rug-pull blocking, injection scanning of tool descriptions and output, an egress guard for credentials and an audit log. `pins`, `diff` and `approve` manage the lockfile.
- `toolmoat wrap` / `unwrap`: route the stdio servers in MCP client configs through the proxy and restore them.
- GitHub Action with SARIF upload to code scanning.
