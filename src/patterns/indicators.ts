/**
 * Shared indicator lists for the dangerous-code rules. Other modules (the
 * config scanner, the proxy) may import these so detection stays consistent.
 *
 * Every regex must be linear-time: no nested quantifiers and bounded
 * repetition only. Path patterns accept either "/" or "\\" as the separator
 * so they fire on POSIX and Windows spellings alike, and they match the
 * distinctive tail of a path so a leading "~", "$HOME" or "C:\\Users\\x" is
 * not required.
 */
import type { Severity } from '../types.js';

export interface Indicator {
  id: string;
  /** Human-readable name used in finding messages. */
  name: string;
  /** Linear-time matcher. */
  regex: RegExp;
  /** Optional default severity contribution for callers that want one. */
  severity?: Severity;
}

/**
 * Credential and secret files whose contents are valuable to an attacker:
 * SSH keys, cloud credentials, package registry tokens and so on.
 */
export const SENSITIVE_CRED_PATHS: readonly Indicator[] = [
  { id: 'ssh-private-key', name: 'SSH private key', regex: /\.ssh[/\\]id_[a-z0-9]+\b/i },
  { id: 'ssh-identity', name: 'SSH identity key', regex: /\.ssh[/\\][a-z0-9_.-]{0,40}(?:_rsa|_ed25519|_ecdsa|_dsa|\.pem)\b/i },
  { id: 'aws-credentials', name: 'AWS credentials file', regex: /\.aws[/\\]credentials\b/i },
  { id: 'gcloud-adc', name: 'gcloud application default credentials', regex: /application_default_credentials\.json/i },
  { id: 'gcloud-credentials-db', name: 'gcloud credentials database', regex: /gcloud[/\\][a-z0-9_.-]{0,30}credentials\.db/i },
  { id: 'azure-dir', name: 'Azure credential directory', regex: /\.azure[/\\]/i },
  { id: 'kube-config', name: 'Kubernetes config', regex: /\.kube[/\\]config\b/i },
  { id: 'docker-config', name: 'Docker config (registry auth)', regex: /\.docker[/\\]config\.json\b/i },
  { id: 'netrc', name: '.netrc credentials', regex: /\.netrc\b/i },
  { id: 'git-credentials', name: 'git stored credentials', regex: /\.git-credentials\b/i },
  { id: 'npmrc', name: 'npm credentials (.npmrc)', regex: /\.npmrc\b/i },
  { id: 'pypirc', name: 'PyPI credentials (.pypirc)', regex: /\.pypirc\b/i },
  { id: 'gnupg', name: 'GnuPG keyring directory', regex: /\.gnupg[/\\]/i },
  { id: 'etc-shadow', name: '/etc/shadow password hashes', regex: /\/etc\/shadow\b/ },
];

/**
 * AI-agent and developer-tool config files that store API keys, OAuth tokens
 * or that, once rewritten, make an injection persistent. The config scanner
 * reuses this list for its own path matching.
 */
export const AGENT_CONFIG_PATHS: readonly Indicator[] = [
  { id: 'claude-json', name: '~/.claude.json', regex: /\.claude\.json\b/i },
  { id: 'claude-credentials', name: 'Claude credentials', regex: /\.claude[/\\]\.credentials\.json\b/i },
  { id: 'claude-settings', name: 'Claude settings', regex: /\.claude[/\\]settings(?:\.local)?\.json\b/i },
  { id: 'claude-desktop-config', name: 'Claude Desktop config', regex: /claude_desktop_config\.json\b/i },
  { id: 'codex-auth', name: 'Codex auth', regex: /\.codex[/\\]auth\.json\b/i },
  { id: 'codex-config', name: 'Codex config', regex: /\.codex[/\\]config\.toml\b/i },
  { id: 'gh-hosts', name: 'GitHub CLI hosts', regex: /gh[/\\]hosts\.yml\b/i },
  { id: 'openai-config', name: 'OpenAI config directory', regex: /\.config[/\\]openai\b/i },
  { id: 'cursor-mcp', name: 'Cursor MCP config', regex: /\.cursor[/\\]mcp\.json\b/i },
  { id: 'gemini-settings', name: 'Gemini settings', regex: /\.gemini[/\\]settings\.json\b/i },
  { id: 'mcp-json', name: '.mcp.json', regex: /(?:^|[/\\])\.mcp\.json\b/i },
  { id: 'claude-md', name: 'CLAUDE.md agent instructions', regex: /\bCLAUDE\.md\b/ },
  { id: 'agents-md', name: 'AGENTS.md agent instructions', regex: /\bAGENTS\.md\b/ },
  { id: 'claude-skills-dir', name: '~/.claude/skills', regex: /\.claude[/\\]skills\b/i },
  { id: 'claude-plugins-dir', name: '~/.claude/plugins', regex: /\.claude[/\\]plugins\b/i },
  { id: 'git-hooks-dir', name: '.git/hooks', regex: /\.git[/\\]hooks\b/i },
];

/**
 * Hosts and URL shapes used to exfiltrate stolen data: webhook sinks, request
 * bins, tunnels, out-of-band interaction services and anonymous file drops.
 */
export const EXFIL_HOSTS: readonly Indicator[] = [
  { id: 'discord-webhook', name: 'Discord webhook', regex: /discord(?:app)?\.com\/api\/webhooks\//i, severity: 'high' },
  { id: 'telegram-bot', name: 'Telegram bot API', regex: /api\.telegram\.org\/bot[^\s/"']{0,80}\/send(?:Message|Document|Photo)/i, severity: 'high' },
  { id: 'webhook-site', name: 'webhook.site sink', regex: /\bwebhook\.site\//i, severity: 'high' },
  { id: 'requestbin', name: 'RequestBin', regex: /\brequestbin\.[a-z]{2,10}\b/i, severity: 'high' },
  { id: 'pipedream', name: 'Pipedream endpoint', regex: /\b[a-z0-9-]{1,40}\.m\.pipedream\.net\b/i, severity: 'high' },
  { id: 'ngrok', name: 'ngrok tunnel', regex: /\b[a-z0-9-]{1,40}\.ngrok(?:-free)?\.(?:app|io)\b/i, severity: 'high' },
  { id: 'cloudflare-tunnel', name: 'Cloudflare quick tunnel', regex: /\b[a-z0-9-]{1,60}\.trycloudflare\.com\b/i, severity: 'high' },
  { id: 'interactsh', name: 'interact.sh OOB', regex: /\binteract\.sh\b/i, severity: 'high' },
  { id: 'oast', name: 'OAST OOB domain', regex: /\b[a-z0-9.-]{1,60}\.oast\.(?:pro|live|site|fun|me|online)\b/i, severity: 'high' },
  { id: 'burp-collaborator', name: 'Burp Collaborator', regex: /\b[a-z0-9.-]{0,60}burpcollaborator\.net\b/i, severity: 'high' },
  { id: 'pastebin-api', name: 'Pastebin API', regex: /pastebin\.com\/(?:api|raw)\//i, severity: 'high' },
  { id: 'transfer-sh', name: 'transfer.sh drop', regex: /(?:https?:\/\/)?transfer\.sh\/[A-Za-z0-9]/i, severity: 'high' },
  { id: 'file-io', name: 'file.io drop', regex: /(?:https?:\/\/)?file\.io\/[A-Za-z0-9]/i, severity: 'high' },
  { id: '0x0', name: '0x0.st drop', regex: /\b0x0\.st\b/i, severity: 'high' },
  { id: 'temp-sh', name: 'temp.sh drop', regex: /(?:https?:\/\/)?temp\.sh\/[A-Za-z0-9]/i, severity: 'high' },
  { id: 'termbin', name: 'termbin.com drop', regex: /\btermbin\.com\b/i, severity: 'high' },
  { id: 'gofile', name: 'gofile.io drop', regex: /\bgofile\.io\b/i, severity: 'high' },
  { id: 'bashupload', name: 'bashupload.com drop', regex: /\bbashupload\.com\b/i, severity: 'high' },
];

/**
 * Living-off-the-land binaries abused to download and run payloads on Windows.
 * Exported as plain names for other modules that want to match them.
 */
export const LOLBINS: readonly string[] = [
  'certutil',
  'bitsadmin',
  'mshta',
  'regsvr32',
  'rundll32',
  'wmic',
  'installutil',
  'msbuild',
  'cscript',
  'wscript',
  'curl',
  'certreq',
];
