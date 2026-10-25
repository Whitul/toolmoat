/**
 * Dangerous-code rules: things a skill, hook, command file or MCP server
 * script does that an attacker wants but a benign tool almost never needs.
 *
 * These rules also run over one-line command strings (the config scanner wraps
 * a hook command, an MCP server command line or a package.json script in a
 * synthetic ScanFile of kind 'script'), so every pattern must work on a single
 * line as well as inside a multi-line script.
 *
 * All regexes are linear-time: bounded repetition, no nested quantifiers,
 * anchored on a distinctive keyword so attacker-controlled filler cannot make
 * the engine backtrack.
 */
import type { FileKind, Rule, RuleMatch, Severity } from '../types.js';
import { findAll, lineAt, lineColAt } from '../util/text.js';
import { AGENT_CONFIG_PATHS, EXFIL_HOSTS, SENSITIVE_CRED_PATHS } from '../patterns/indicators.js';

/** Kinds that carry runnable commands. Docs are intentionally excluded. */
const CODE_KINDS: readonly FileKind[] = ['script', 'skill', 'instructions', 'tool-definition'];

const MATCH_LIMIT = 40;

/** A download command, in shell or PowerShell form. */
const DOWNLOADER = String.raw`curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod`;
/** An interpreter that will run whatever it is handed. */
const INTERP = String.raw`sh|bash|zsh|dash|ksh|fish|python[23]?|node|nodejs|perl|ruby|php|pwsh|powershell|iex|Invoke-Expression`;

/** Extracts the first http(s) URL from a slice, for use in messages. */
function firstUrl(text: string): string | undefined {
  const m = /https?:\/\/[^\s"'`)|<>]{1,200}/i.exec(text);
  return m ? m[0] : undefined;
}

/** True when `re` matches anywhere in a window around an offset. `re` must not be global. */
function near(content: string, index: number, matchLen: number, re: RegExp, before = 0, after = 320): boolean {
  const start = Math.max(0, index - before);
  const end = Math.min(content.length, index + matchLen + after);
  return re.test(content.slice(start, end));
}

/** Runs one regex and maps each hit to a match with a message built from the hit text. */
function collect(content: string, re: RegExp, toMessage: (text: string) => string, limit = MATCH_LIMIT): RuleMatch[] {
  return findAll(re, content, limit).map((h) => ({ index: h.index, message: toMessage(h.text) }));
}

/** De-duplicates matches that land on the same line, keeping the first. */
function oncePerLine(content: string, matches: RuleMatch[]): RuleMatch[] {
  const seen = new Set<number>();
  const out: RuleMatch[] = [];
  for (const m of matches) {
    const line = m.index === undefined ? (m.line ?? 0) : lineColAt(content, m.index).line;
    if (seen.has(line)) continue;
    seen.add(line);
    out.push(m);
  }
  return out;
}

// --- TM-EXEC-001 ---------------------------------------------------------

const PIPE_TO_INTERP = new RegExp(
  String.raw`(?:\b(?:${DOWNLOADER})\b)[^\n]{0,400}\|\s*(?:sudo\s+)?(?:${INTERP})\b`,
  'i',
);
const PROC_SUBST = /\b(?:sh|bash|zsh|dash|ksh|fish)\s+<\(\s*(?:curl|wget|fetch|irm|iwr)\b/i;
const SH_C_SUBST = /\b(?:sh|bash|zsh|dash|ksh|eval)\b[^\n]{0,24}\$\(\s*(?:curl|wget|fetch|irm|iwr)\b/i;
const IEX_DOWNLOAD = /\b(?:iex|Invoke-Expression)\b[^\n]{0,200}(?:DownloadString|DownloadData|DownloadFile)\s*\(/i;
const DOWNLOAD_PIPE_IEX = /(?:DownloadString|DownloadData)\s*\([^\n]{0,250}\|\s*(?:iex|Invoke-Expression)\b/i;
const IEX_IRM = /\b(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:irm|iwr|curl|wget|Invoke-RestMethod|Invoke-WebRequest)\b/i;

const execDownloadPipe: Rule = {
  id: 'TM-EXEC-001',
  title: 'Download piped into an interpreter',
  description:
    'Fetches a remote script and executes it in place (curl | bash, iex (irm ...), bash <(curl ...)). The code that runs is whatever the server returns, so the author can change it at any time.',
  category: 'dangerous-execution',
  severity: 'critical',
  kinds: CODE_KINDS,
  remediation: 'Download to a file, review it, pin a checksum, then run the reviewed copy.',
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const re of [PIPE_TO_INTERP, PROC_SUBST, SH_C_SUBST, IEX_DOWNLOAD, DOWNLOAD_PIPE_IEX, IEX_IRM]) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        const url = firstUrl(h.text) ?? firstUrl(c.slice(h.index, h.index + 300));
        const official = url ? OFFICIAL_INSTALLERS.find((i) => url.startsWith(i.prefix)) : undefined;
        if (official) {
          matches.push({
            index: h.index,
            severity: 'medium',
            message: `Pipes the official ${official.name} installer (${url}) into an interpreter; well known, but it still runs unreviewed remote code`,
          });
          continue;
        }
        matches.push({
          index: h.index,
          message: url ? `Pipes a download from ${url} into an interpreter` : 'Pipes a remote download straight into an interpreter',
        });
      }
    }
    return oncePerLine(c, matches);
  },
};

/**
 * Vendor-documented curl | sh installers. They are still remote code, so they
 * stay reported, but at medium so they do not drown out real droppers. Only
 * exact https prefixes count: an attacker's repo on the same host does not match.
 */
const OFFICIAL_INSTALLERS: readonly { prefix: string; name: string }[] = [
  { prefix: 'https://raw.githubusercontent.com/Homebrew/install/', name: 'Homebrew' },
  { prefix: 'https://sh.rustup.rs', name: 'rustup' },
  { prefix: 'https://raw.githubusercontent.com/nvm-sh/nvm/', name: 'nvm' },
  { prefix: 'https://bun.sh/install', name: 'Bun' },
  { prefix: 'https://deno.land/install.sh', name: 'Deno' },
  { prefix: 'https://astral.sh/uv/', name: 'uv' },
  { prefix: 'https://get.docker.com', name: 'Docker' },
  { prefix: 'https://ollama.com/install.sh', name: 'Ollama' },
  { prefix: 'https://claude.ai/install.sh', name: 'Claude Code' },
  { prefix: 'https://get.pnpm.io/install.sh', name: 'pnpm' },
  { prefix: 'https://install.python-poetry.org', name: 'Poetry' },
  { prefix: 'https://pyenv.run', name: 'pyenv' },
];

// --- TM-EXEC-002 ---------------------------------------------------------

const DOWNLOAD_OUT = new RegExp(
  String.raw`\b(?:${DOWNLOADER})\b[^\n]{0,200}(?:\s-o\b|\s-O\b|--output\b|-OutFile\b)`,
  'i',
);
const EXEC_AFTER_DOWNLOAD = /chmod\s+[0-7]*[+]?x|chmod\s+\+x|Start-Process|(?:^|[\s;&(])\.\/[a-z0-9._-]+/im;
const LOLBIN_PATTERNS: readonly { re: RegExp; label: string }[] = [
  { re: /\bcertutil(?:\.exe)?\s+[^\n]{0,80}-urlcache/i, label: 'certutil -urlcache download' },
  { re: /\bbitsadmin(?:\.exe)?\s+[^\n]{0,80}\/transfer\b/i, label: 'bitsadmin /transfer download' },
  { re: /\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)/i, label: 'mshta remote/script execution' },
  { re: /\bregsvr32(?:\.exe)?\s+[^\n]{0,60}\/i:\s*https?:/i, label: 'regsvr32 scriptlet from URL' },
  { re: /\brundll32(?:\.exe)?\s+[^\n]{0,40}javascript:/i, label: 'rundll32 javascript: execution' },
];

const execDownloadRun: Rule = {
  id: 'TM-EXEC-002',
  title: 'Download then execute',
  description:
    'Downloads a file and runs it (download, chmod +x, execute) or uses a living-off-the-land binary such as certutil or bitsadmin to fetch and launch a payload.',
  category: 'dangerous-execution',
  severity: 'high',
  kinds: CODE_KINDS,
  remediation: 'Avoid fetch-and-run; ship the executable with the skill or verify it before running.',
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const h of findAll(DOWNLOAD_OUT, c, MATCH_LIMIT)) {
      if (near(c, h.index, h.text.length, EXEC_AFTER_DOWNLOAD, 0, 320)) {
        const url = firstUrl(h.text) ?? firstUrl(c.slice(h.index, h.index + 300));
        matches.push({
          index: h.index,
          message: url ? `Downloads ${url} to a file and then executes it` : 'Downloads a file and then executes it',
        });
      }
    }
    for (const { re, label } of LOLBIN_PATTERNS) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        matches.push({ index: h.index, message: `Uses a living-off-the-land binary to fetch and run code (${label})` });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-EXEC-003 ---------------------------------------------------------

const PW_ARCHIVE = [
  /\bunzip\b[^\n]{0,80}\s-P\s*\S/i,
  /\b7za?\b[^\n]{0,40}\sx\b[^\n]{0,20}-p\S/i,
  /\b7za?\b[^\n]{0,40}-p\S[^\n]{0,20}\sx\b/i,
];
const DOWNLOAD_ANY = new RegExp(String.raw`\b(?:${DOWNLOADER})\b`, 'i');

const execPasswordArchive: Rule = {
  id: 'TM-EXEC-003',
  title: 'Password-protected archive extraction',
  description:
    'Extracts a password-protected archive. Malware ships payloads inside encrypted zips so antivirus and static scanners cannot read them (seen in the ClawHavoc campaign).',
  category: 'dangerous-execution',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    const downloadNearby = DOWNLOAD_ANY.test(c);
    for (const re of PW_ARCHIVE) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        matches.push({
          index: h.index,
          severity: downloadNearby ? 'high' : 'medium',
          message: downloadNearby
            ? 'Extracts a password-protected archive near a download (payload hidden from scanners)'
            : 'Extracts a password-protected archive',
        });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-EXEC-004 ---------------------------------------------------------

const PROTECTION_OFF: readonly { re: RegExp; label: string }[] = [
  { re: /xattr\s+(?:-d\s+com\.apple\.quarantine|-cr?\b|-c\b)/i, label: 'strips the macOS quarantine attribute (xattr)' },
  { re: /spctl\s+--master-disable/i, label: 'disables Gatekeeper (spctl --master-disable)' },
  { re: /Set-MpPreference\s+[^\n]{0,120}-DisableRealtimeMonitoring/i, label: 'disables Defender real-time monitoring' },
  { re: /Add-MpPreference\s+[^\n]{0,120}-ExclusionPath/i, label: 'adds a Defender exclusion path' },
  { re: /netsh\s+advfirewall\s+set\s+[^\n]{0,60}\bstate\s+off/i, label: 'turns off the Windows firewall' },
  { re: /\bsetenforce\s+0\b/i, label: 'puts SELinux into permissive mode (setenforce 0)' },
  { re: /\bcsrutil\s+disable/i, label: 'disables System Integrity Protection (csrutil disable)' },
];

const execDisableProtection: Rule = {
  id: 'TM-EXEC-004',
  title: 'Disables OS malware protection or quarantine',
  description:
    'Turns off a security control: macOS quarantine/Gatekeeper/SIP, Windows Defender or firewall, or SELinux. Legitimate skills do not need to disable the machine defences.',
  category: 'dangerous-execution',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of PROTECTION_OFF) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Code ${label}` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-EXEC-005 ---------------------------------------------------------

const REVERSE_SHELL: readonly { re: RegExp; label: string }[] = [
  { re: /\/dev\/tcp\/[0-9a-z.\-]{1,60}\/\d{1,5}/i, label: '/dev/tcp redirection' },
  { re: /\bn(?:c|cat)\b[^\n]{0,60}\s-e\b/i, label: 'netcat -e' },
  { re: /\bbash\s+-i\b[^\n]{0,40}>&/i, label: 'interactive bash redirected to a socket' },
  { re: /\bsocat\b[^\n]{0,100}\bexec:/i, label: 'socat exec:' },
  { re: /\bmkfifo\b[^\n]{0,120}\bn(?:c|cat)\b/i, label: 'mkfifo + netcat shell' },
  { re: /os\.dup2\s*\(\s*s\.fileno\s*\(/i, label: 'Python socket dup2 shell' },
  { re: /System\.Net\.Sockets\.TCPClient[^\n]{0,200}GetStream/i, label: 'PowerShell TCPClient shell' },
];

const execReverseShell: Rule = {
  id: 'TM-EXEC-005',
  title: 'Reverse shell',
  description:
    'Opens an interactive shell back to a remote host, giving an attacker a foothold on the machine. No benign skill needs a reverse shell.',
  category: 'dangerous-execution',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of REVERSE_SHELL) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Reverse shell (${label})` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-OBF-001 ----------------------------------------------------------

const DECODE_EXEC: readonly { re: RegExp; label: string }[] = [
  { re: /\bbase64\s+(?:-d|-D|--decode)\b[^\n]{0,120}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[23]?|node|perl|ruby)\b/i, label: 'base64 -d | shell' },
  { re: /\|\s*base64\s+(?:-d|-D|--decode)\b[^\n]{0,60}\|\s*(?:sh|bash|zsh|python[23]?)\b/i, label: 'piped base64 -d | shell' },
  { re: /\beval\s*\(\s*atob\s*\(/i, label: 'eval(atob(...))' },
  { re: /\beval\s*\(\s*Buffer\.from\s*\([^\n]{0,80}(?:base64|hex)/i, label: "eval(Buffer.from(..., 'base64'))" },
  { re: /\bnew\s+Function\s*\(\s*atob\s*\(/i, label: 'new Function(atob(...))' },
  { re: /\bexec\s*\(\s*base64\.b64decode\s*\(/i, label: 'exec(base64.b64decode(...))' },
  { re: /\b(?:exec|eval)\s*\(\s*(?:zlib|gzip|lzma|bz2)\.decompress\s*\(/i, label: 'exec(zlib.decompress(...))' },
  { re: /\b(?:exec|eval)\s*\(\s*codecs\.decode\s*\([^\n]{0,80}rot[_-]?13/i, label: 'exec(codecs.decode(..., rot13))' },
  { re: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,60}\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}/i, label: 'powershell -EncodedCommand' },
  { re: /\[(?:System\.)?Convert\]::FromBase64String\s*\([^\n]{0,200}(?:iex|Invoke-Expression)/i, label: '[Convert]::FromBase64String + IEX' },
  { re: /\b(?:iex|Invoke-Expression)\b[^\n]{0,120}\[(?:System\.)?Convert\]::FromBase64String/i, label: 'IEX + [Convert]::FromBase64String' },
];

const obfDecodeExec: Rule = {
  id: 'TM-OBF-001',
  title: 'Decode-and-execute',
  description:
    'Decodes a base64, hex or compressed blob and immediately executes it. Encoding is used to hide the real command from a reader and from scanners.',
  category: 'obfuscation',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of DECODE_EXEC) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Decodes and executes hidden code (${label})` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-OBF-002 ----------------------------------------------------------

const HEX_ESCAPE_RUN = /(?:\\x[0-9a-fA-F]{2}){64,}/;
const FROMCHARCODE = /String\.fromCharCode\s*\(\s*(?:\d{1,6}\s*,\s*){29,}\d{1,6}/;
const CHR_CHAIN = /(?:chr\s*\(\s*\d{1,6}\s*\)\s*\+?\s*){20,}/i;

/** Linear scan for a long run of base64-alphabet characters with real character diversity. */
function findBase64Blobs(content: string, limit = 8): RuleMatch[] {
  const out: RuleMatch[] = [];
  let i = 0;
  const n = content.length;
  while (i < n && out.length < limit) {
    const ch = content.charCodeAt(i);
    const isB64 =
      (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57) || ch === 43 || ch === 47 || ch === 61 || ch === 95 || ch === 45;
    if (!isB64) {
      i++;
      continue;
    }
    const start = i;
    let hasUpper = false;
    let hasLower = false;
    let hasDigit = false;
    while (i < n) {
      const c = content.charCodeAt(i);
      if (c >= 65 && c <= 90) hasUpper = true;
      else if (c >= 97 && c <= 122) hasLower = true;
      else if (c >= 48 && c <= 57) hasDigit = true;
      else if (c === 43 || c === 47 || c === 61 || c === 95 || c === 45) {
        /* symbol, keep going */
      } else break;
      i++;
    }
    const len = i - start;
    if (len >= 400 && hasUpper && hasLower && hasDigit) {
      // Skip data: URIs (the run follows "base64,") and Subresource-Integrity /
      // lockfile hashes (the run itself starts with "sha256-/sha384-/sha512-").
      const before = content.slice(Math.max(0, start - 16), start);
      const run = content.slice(start, Math.min(start + 10, i));
      if (!/base64,?$/i.test(before) && !/^sha(?:256|384|512)-/i.test(run)) {
        out.push({ index: start, message: `Large encoded blob (${len} base64 characters) hidden in the file` });
      }
    }
  }
  return out;
}

const obfLargeBlob: Rule = {
  id: 'TM-OBF-002',
  title: 'Large encoded blob',
  description:
    'Contains a long base64 run, dense hex escapes or a long fromCharCode/chr chain. These hide a payload or string inside otherwise readable code.',
  category: 'obfuscation',
  severity: 'medium',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [...findBase64Blobs(c)];
    for (const h of findAll(HEX_ESCAPE_RUN, c, 8)) matches.push({ index: h.index, message: 'Dense hex escape sequence (obfuscated string)' });
    for (const h of findAll(FROMCHARCODE, c, 8)) matches.push({ index: h.index, message: 'String.fromCharCode chain building a hidden string' });
    for (const h of findAll(CHR_CHAIN, c, 8)) matches.push({ index: h.index, message: 'chr() chain building a hidden string' });
    return oncePerLine(c, matches);
  },
};

// --- TM-OBF-003 ----------------------------------------------------------

const EXEC_FETCHED = [
  /\b(?:eval|exec)\s*\(\s*[^\n]{0,30}(?:fetch|axios|requests\.(?:get|post)|urllib|urlopen|http\.get|Invoke-WebRequest|Invoke-RestMethod)\s*\(/i,
  /\bnew\s+Function\s*\(\s*[^\n]{0,30}(?:fetch|axios|requests\.(?:get|post)|urlopen|http\.get)\s*\(/i,
  /\bvm\.runInNewContext\s*\(\s*[^\n]{0,30}(?:fetch|axios|requests\.get|urlopen|http\.get)\s*\(/i,
  /\bfetch\s*\([^\n]{0,200}\)\s*\.then\s*\(\s*eval\b/i,
  /\brequests\.(?:get|post)\s*\([^\n]{0,120}\)\s*\.(?:text|content)[^\n]{0,30}\)?\s*\)?\s*(?:#[^\n]{0,40})?\s*$/i,
];

const obfExecFetched: Rule = {
  id: 'TM-OBF-003',
  title: 'Executes fetched content',
  description:
    'Passes the body of an HTTP response straight to eval, exec or new Function. The executed code is controlled by whoever answers the request.',
  category: 'obfuscation',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    // The classic inline forms: eval(fetch(...)), new Function(await (await fetch()).text()), fetch().then(eval).
    for (const re of EXEC_FETCHED.slice(0, 4)) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        const url = firstUrl(h.text);
        matches.push({ index: h.index, message: url ? `Executes the response from ${url}` : 'Executes the body of an HTTP response' });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- shared verb lists for credential/config access ----------------------

const READ_COPY_VERB =
  /\b(?:cat|less|more|head|tail|cp|scp|rsync|mv|tar|zip|gzip|gpg|curl|wget|base64|openssl|xxd|strings|type|Get-Content|gc|Copy-Item|Move-Item|Compress-Archive|readFile|readFileSync|read_text|open|fopen|load)\b|[<>]/i;
/**
 * Text right before a path that makes the path the destination of a write:
 * a shell redirect or tee into it, a cp/mv whose last argument it is, or a
 * write API called with it. Checked against the same line only, so a "2>/dev/null"
 * or an HTML tag elsewhere on the line does not count.
 */
const WRITE_INTO = [
  /(?:(?<!<[^<>\n]{0,80})>>?|\btee(?:\s+-a)?)\s*["']?[^\s"'|;&<>]{0,60}$/,
  /\b(?:cp|mv|install|rsync|ln|Copy-Item|Move-Item)\b[^\n|;&]{1,160}\s["']?[^\s"'|;&<>]{0,60}$/,
  /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile|copyFileSync|copyFile|write_text|write_bytes|Set-Content|Add-Content|Out-File)\b[^\n]{0,60}$/,
];
/** open(path, 'w'|'a') where the path starts the call. */
const OPEN_BEFORE = /\bopen\s*\(\s*[^\n),]{0,60}$/;
const OPEN_WRITE_MODE = /^[^\n)]{0,80},\s*["'][wa]\+?b?["']/;

/** True when the path at [index, index+length) is written to on its line. */
function writtenTo(content: string, index: number, length: number): boolean {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const before = content.slice(Math.max(lineStart, index - 200), index);
  if (WRITE_INTO.some((re) => re.test(before))) return true;
  return OPEN_BEFORE.test(before) && OPEN_WRITE_MODE.test(content.slice(index + length, index + length + 120));
}

// --- TM-CRED-001 ---------------------------------------------------------

const credReadFiles: Rule = {
  id: 'TM-CRED-001',
  title: 'Reads SSH, cloud or developer credentials',
  description:
    'Reads, copies or archives credential files such as SSH keys, ~/.aws/credentials, ~/.kube/config or ~/.npmrc. Stealing these gives an attacker access to other systems.',
  category: 'credential-access',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const ind of SENSITIVE_CRED_PATHS) {
      for (const h of findAll(ind.regex, c, MATCH_LIMIT)) {
        const withVerb = near(c, h.index, h.text.length, READ_COPY_VERB, 120, 60);
        matches.push({
          index: h.index,
          severity: withVerb ? 'high' : 'low',
          message: withVerb ? `Reads or copies ${ind.name}` : `References ${ind.name}`,
        });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-CRED-002 ---------------------------------------------------------

const BROWSER_SECRETS: readonly { re: RegExp; label: string }[] = [
  { re: /\b(?:key4\.db|logins\.json|cookies\.sqlite|login\.keychain-db)\b/i, label: 'browser/keychain credential store' },
  { re: /(?:Chrome|Chromium|Edge|Brave|Opera)[^\n]{0,120}(?:Login Data|Web Data|Local State|Cookies)/i, label: 'Chromium credential store' },
  { re: /(?:Login Data|Local State|Web Data)[^\n]{0,120}(?:Chrome|Chromium|Edge|Brave|Opera)/i, label: 'Chromium credential store' },
  { re: /security\s+(?:find-generic-password|find-internet-password|dump-keychain)/i, label: 'macOS keychain dump' },
  { re: /\bcmdkey\s+\/list\b/i, label: 'Windows stored credentials (cmdkey)' },
  { re: /\bvaultcmd\b/i, label: 'Windows Credential Vault (vaultcmd)' },
  { re: /\bCryptUnprotectData\b/i, label: 'Windows DPAPI decryption' },
  { re: /\b(?:mimikatz|sekurlsa)\b/i, label: 'mimikatz credential dumping' },
  { re: /(?:procdump|comsvcs|MiniDumpWriteDump|rundll32)[^\n]{0,80}lsass/i, label: 'LSASS memory dump' },
  { re: /lsass[^\n]{0,60}(?:\.dmp|dump)/i, label: 'LSASS memory dump' },
];

const credBrowserKeychain: Rule = {
  id: 'TM-CRED-002',
  title: 'Browser password stores and OS keychains',
  description:
    'Accesses saved browser passwords/cookies, an OS keychain or LSASS memory. This is the behaviour of an infostealer harvesting logged-in sessions.',
  category: 'credential-access',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of BROWSER_SECRETS) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Harvests credentials from a ${label}` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-CRED-003 ---------------------------------------------------------

const WALLET_INDICATORS: readonly { re: RegExp; label: string }[] = [
  { re: /\bwallet\.dat\b/i, label: 'wallet.dat' },
  { re: /\bnkbihfbeogaeaoehlefnkodbefgpgknn\b/i, label: 'MetaMask extension data' },
  { re: /\bbfnaelmomeimhlpmgjnjophhpkkoljpa\b/i, label: 'Phantom extension data' },
  { re: /\bhnfanknocfeofbddgcijnmhnfnkdnaad\b/i, label: 'Coinbase Wallet extension data' },
  { re: /\.solana[/\\]id\.json\b/i, label: 'Solana keypair' },
  { re: /keystore[/\\]UTC--/i, label: 'Ethereum keystore' },
  { re: /\b(?:Exodus|Electrum|Coinomi|Guarda)\b[/\\]/i, label: 'crypto wallet data directory' },
  { re: /Atomic Wallet[/\\]/i, label: 'Atomic Wallet data directory' },
  { re: /\b(?:mnemonicToSeed|walletFromMnemonic|importMnemonic|fromMnemonic|recoverWallet)\b/i, label: 'wallet mnemonic recovery' },
];

const credWallet: Rule = {
  id: 'TM-CRED-003',
  title: 'Crypto wallet theft',
  description:
    'Targets cryptocurrency wallet files, browser wallet extensions or seed phrases. These lead directly to theft of funds and are a hallmark of stealer malware.',
  category: 'credential-access',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of WALLET_INDICATORS) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Accesses a cryptocurrency ${label}` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-CRED-004 ---------------------------------------------------------

const AGENT_TOKEN_PATHS = AGENT_CONFIG_PATHS.filter((p) =>
  ['claude-json', 'claude-credentials', 'codex-auth', 'gh-hosts', 'openai-config', 'cursor-mcp', 'claude-desktop-config', 'gemini-settings'].includes(p.id),
);

const credAgentTokens: Rule = {
  id: 'TM-CRED-004',
  title: 'Reads AI agent or developer tool tokens',
  description:
    'Reads config files where AI agents and developer tools store API keys and OAuth tokens (~/.claude.json, ~/.codex/auth.json, gh hosts.yml). Stolen agent keys were sold after the OpenCode breach.',
  category: 'credential-access',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const ind of AGENT_TOKEN_PATHS) {
      for (const h of findAll(ind.regex, c, MATCH_LIMIT)) {
        const withVerb = near(c, h.index, h.text.length, READ_COPY_VERB, 120, 60);
        matches.push({
          index: h.index,
          severity: withVerb ? 'high' : 'low',
          message: withVerb ? `Reads agent/tool token store ${ind.name}` : `References agent/tool token store ${ind.name}`,
        });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-EXFIL-001 --------------------------------------------------------

const PRIVATE_IP =
  /^(?:10\.|127\.|0\.0\.0\.0|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.255\.255\.255)/;
const URL_WITH_IP = /\bhttps?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?/i;

const exfilEndpoint: Rule = {
  id: 'TM-EXFIL-001',
  title: 'Known exfiltration endpoint',
  description:
    'Sends data to a webhook sink, request bin, tunnel, out-of-band service, anonymous file drop or a raw IP address. These are the drop points stealers use to collect what they take.',
  category: 'exfiltration',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const host of EXFIL_HOSTS) {
      for (const h of findAll(host.regex, c, MATCH_LIMIT)) {
        matches.push({ index: h.index, severity: host.severity ?? 'high', message: `Contacts exfiltration endpoint: ${host.name}` });
      }
    }
    for (const h of findAll(URL_WITH_IP, c, MATCH_LIMIT)) {
      const ip = h.groups[0];
      if (ip && !PRIVATE_IP.test(ip)) {
        matches.push({ index: h.index, severity: 'medium', message: `Sends a request to a raw IP address (${ip})` });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-EXFIL-002 --------------------------------------------------------

const ENV_DUMP: readonly { re: RegExp; label: string }[] = [
  { re: /JSON\.stringify\s*\(\s*process\.env\b/i, label: 'JSON.stringify(process.env)' },
  { re: /\bObject\.(?:entries|keys|values|assign)\s*\(\s*process\.env\b/i, label: 'Object.*(process.env)' },
  { re: /\b(?:json\.dumps|str|repr)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b/i, label: 'serialises os.environ' },
  { re: /\b(?:env|printenv)\b[^\n|]{0,40}\|\s*(?:curl|wget|nc|ncat)\b/i, label: 'env | network tool' },
  { re: /Get-ChildItem\s+env:[^\n]{0,80}\|/i, label: 'Get-ChildItem env: piped out' },
];
const NET_REQUEST =
  /\b(?:curl|wget|fetch|axios|requests\.(?:get|post|put)|urlopen|http\.(?:get|post|request)|Invoke-WebRequest|Invoke-RestMethod|XMLHttpRequest|\.send\s*\()/i;

const exfilEnvDump: Rule = {
  id: 'TM-EXFIL-002',
  title: 'Bulk environment or secret dump',
  description:
    'Serialises the whole environment (process.env / os.environ) or pipes env output to a network tool. Environments hold API keys and tokens, so a bulk dump is a credential grab.',
  category: 'exfiltration',
  severity: 'medium',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const hasNet = NET_REQUEST.test(c);
    const matches: RuleMatch[] = [];
    for (const { re, label } of ENV_DUMP) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        const piped = /\|/.test(h.text);
        const escalate = hasNet || piped;
        // Iterating the environment is routine; it only matters when the data can leave.
        if (!escalate && /^Object\./.test(h.text)) continue;
        matches.push({
          index: h.index,
          severity: escalate ? 'high' : 'medium',
          message: escalate ? `Dumps the environment and sends it over the network (${label})` : `Dumps the whole environment (${label})`,
        });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-PERSIST-001 ------------------------------------------------------

const SHELL_RC = /\.(?:bashrc|zshrc|bash_profile|profile|zprofile|zshenv)\b|config\.fish\b/i;
const PERSIST_DIRECT: readonly { re: RegExp; label: string }[] = [
  { re: /\|\s*crontab\s+-\s*$/im, label: 'installs a crontab entry' },
  { re: /\bcrontab\s+-(?=\s|$)/im, label: 'installs a crontab entry' },
  { re: /\/etc\/cron(?:\.d|tab|\.daily|\.hourly|\.weekly)?\b/i, label: 'writes a system cron job' },
  { re: /(?:LaunchAgents|LaunchDaemons)[/\\][^\n]{0,60}\.plist/i, label: 'installs a macOS launch agent/daemon' },
  { re: /\blaunchctl\s+(?:load|bootstrap|enable)\b/i, label: 'loads a launchd job' },
  { re: /\bsystemctl\s+(?:--user\s+)?enable\b/i, label: 'enables a systemd unit' },
  { re: /\breg(?:\.exe)?\s+add\b[^\n]{0,200}\\Run(?:Once)?\b/i, label: 'adds a Windows Run registry entry' },
  { re: /New-ItemProperty\b[^\n]{0,200}\\(?:CurrentVersion\\)?Run(?:Once)?\b/i, label: 'adds a Windows Run registry entry' },
  { re: /\bschtasks\b[^\n]{0,80}\/create\b/i, label: 'creates a scheduled task' },
  { re: /\bRegister-ScheduledTask\b/i, label: 'registers a scheduled task' },
  { re: /Start Menu\\Programs\\Startup/i, label: 'drops into the Startup folder' },
  { re: /\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|Register-WmiEvent)\b/i, label: 'installs a WMI event subscription' },
];

const persistStartup: Rule = {
  id: 'TM-PERSIST-001',
  title: 'Startup persistence',
  description:
    'Installs itself to run automatically later: shell rc files, cron, launchd, systemd, a Windows Run key, a scheduled task, the Startup folder or a WMI subscription.',
  category: 'persistence',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const h of findAll(SHELL_RC, c, MATCH_LIMIT)) {
      if (writtenTo(c, h.index, h.text.length)) {
        matches.push({ index: h.index, message: 'Writes to a shell startup file (runs on every new shell)' });
      }
    }
    for (const { re, label } of PERSIST_DIRECT) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Startup persistence: ${label}` });
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-PERSIST-002 ------------------------------------------------------

const persistAgentConfig: Rule = {
  id: 'TM-PERSIST-002',
  title: 'Tampers with AI agent configuration',
  description:
    'Writes to an AI agent config, instruction file (CLAUDE.md, AGENTS.md), MCP config, skills/plugins directory or .git/hooks. Rewriting these makes an injection or a malicious tool persist across sessions.',
  category: 'persistence',
  severity: 'high',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const ind of AGENT_CONFIG_PATHS) {
      for (const h of findAll(ind.regex, c, MATCH_LIMIT)) {
        if (writtenTo(c, h.index, h.text.length)) {
          matches.push({ index: h.index, message: `Writes to AI agent configuration (${ind.name})` });
        }
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-DESTRUCT-001 -----------------------------------------------------

const RM_RECURSIVE = [
  /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b\s*([^\n]{0,60})/i,
  /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b\s*([^\n]{0,60})/i,
];
const DANGEROUS_TARGET = /^(?:--[a-z-]+\s+)*(?:\/\s|\/$|\/\*|~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%|\*|\.\s|\.\*|[A-Za-z]:[\\/])/i;
const REMOVE_ITEM = /Remove-Item\b[^\n]{0,160}-Recurse\b[^\n]{0,80}-Force\b|Remove-Item\b[^\n]{0,160}-Force\b[^\n]{0,80}-Recurse\b/i;
const REMOVE_ITEM_ROOT = /(?:[A-Za-z]:[\\/](?:["'\s]|$)|\$HOME|~[\\/]?|\$env:USERPROFILE|\$env:SystemDrive|[\\/]$)/i;

const DESTRUCT_DIRECT: readonly { re: RegExp; label: string; critical?: boolean }[] = [
  { re: /--no-preserve-root/i, label: 'rm --no-preserve-root', critical: true },
  { re: /\bdel\s+(?:\/[sqf]\s+){1,3}[^\n]{0,40}[A-Za-z]:\\/i, label: 'del /s /q on a drive root', critical: true },
  { re: /\bformat\s+[a-zA-Z]:/i, label: 'format of a drive', critical: true },
  { re: /\bmkfs(?:\.[a-z0-9]+)?\s+\/dev\//i, label: 'mkfs on a device' },
  { re: /\bdd\b[^\n]{0,60}if=\/dev\/(?:zero|urandom|random)[^\n]{0,60}of=\/dev\/(?:sd|nvme|hd|disk|vd)/i, label: 'dd wiping a disk', critical: true },
  { re: /\bdiskpart\b[^\n]{0,200}\bclean\b/i, label: 'diskpart clean' },
  { re: /\bvssadmin\s+delete\s+shadows/i, label: 'vssadmin delete shadows (destroys backups)' },
  { re: /\bwbadmin\s+delete\s+catalog/i, label: 'wbadmin delete catalog (destroys backups)' },
  { re: /\bcipher\s+\/w/i, label: 'cipher /w (wipes free space)' },
  { re: /\bshred\b[^\n]{0,40}(?:~|\$HOME|\/home\/|\/Users\/)/i, label: 'shred of home directory', critical: true },
];

const destructWipe: Rule = {
  id: 'TM-DESTRUCT-001',
  title: 'Destructive deletion or wiping',
  description:
    'Deletes or overwrites data at a system or home root, formats a disk, destroys backups/shadow copies or wipes a device. Catastrophic and irreversible.',
  category: 'destructive',
  severity: 'critical',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const re of RM_RECURSIVE) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        const target = (h.groups[0] ?? '').trimStart();
        if (/--no-preserve-root/i.test(h.text) || DANGEROUS_TARGET.test(target)) {
          matches.push({ index: h.index, severity: 'critical', message: 'Recursive force-delete of a root or home directory (rm -rf)' });
        }
      }
    }
    for (const h of findAll(REMOVE_ITEM, c, MATCH_LIMIT)) {
      if (REMOVE_ITEM_ROOT.test(h.text)) {
        matches.push({ index: h.index, severity: 'critical', message: 'Recursive force-delete of a drive root or home directory (Remove-Item)' });
      }
    }
    for (const { re, label, critical } of DESTRUCT_DIRECT) {
      for (const h of findAll(re, c, MATCH_LIMIT)) {
        matches.push({ index: h.index, severity: critical ? 'critical' : 'high', message: `Destructive operation: ${label}` });
      }
    }
    return oncePerLine(c, matches);
  },
};

// --- TM-DESTRUCT-002 -----------------------------------------------------

const ANTI_FORENSICS: readonly { re: RegExp; label: string }[] = [
  { re: /\bhistory\s+-c\b/i, label: 'clears shell history (history -c)' },
  { re: /\bunset\s+HISTFILE\b/i, label: 'unsets HISTFILE' },
  { re: /\bHISTFILESIZE=0\b/, label: 'sets HISTFILESIZE=0' },
  { re: /\b(?:rm|Remove-Item)\b[^\n]{0,40}\.(?:bash|zsh)_history\b/i, label: 'deletes shell history file' },
  { re: /\bClear-History\b/i, label: 'clears PowerShell history (Clear-History)' },
  { re: /\bwevtutil\s+cl\b/i, label: 'clears a Windows event log (wevtutil cl)' },
  { re: /\b(?:rm|del|Remove-Item)\b[^\n]{0,80}ConsoleHost_history\.txt/i, label: 'deletes PSReadLine history' },
];

const destructAntiForensics: Rule = {
  id: 'TM-DESTRUCT-002',
  title: 'Anti-forensics',
  description:
    'Clears shell, PowerShell or Windows event history to cover its tracks. Legitimate setup scripts do not wipe logs and command history.',
  category: 'destructive',
  severity: 'medium',
  kinds: CODE_KINDS,
  check(file) {
    const c = file.content;
    const matches: RuleMatch[] = [];
    for (const { re, label } of ANTI_FORENSICS) {
      for (const h of findAll(re, c, MATCH_LIMIT)) matches.push({ index: h.index, message: `Anti-forensics: ${label}` });
    }
    return oncePerLine(c, matches);
  },
};

const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const DISCUSSION =
  /\b(?:adversarial|payloads?|malicious|attackers?|attacks?|injection|exploits?|hostile|e\.g\.|for example|never|do not|don't|avoid|dangerous)\b/i;

/**
 * In skills and instruction files a command often appears as a warning or an
 * example ("never run `rm -rf ~`", "adversarial inputs: `; rm -rf ~`"). Lower
 * those one level instead of treating them as instructions. Only one level, so
 * an attacker sprinkling "e.g." over a real dropper still gets a high finding.
 */
function lowerInProse(rule: Rule): Rule {
  return {
    ...rule,
    check(file) {
      const matches = rule.check(file);
      if (file.kind !== 'skill' && file.kind !== 'instructions') return matches;
      return matches.map((m) => {
        if (m.index === undefined) return m;
        // URLs are not prose: a host like attacker.example must not count as discussion.
        const prose = lineAt(file.content, lineColAt(file.content, m.index).line).replace(/\bhttps?:\/\/\S{1,300}/g, '');
        if (!DISCUSSION.test(prose)) return m;
        return {
          ...m,
          severity: LOWER[m.severity ?? rule.severity],
          message: `${m.message} (mentioned as an example or warning, so severity is lowered)`,
        };
      });
    },
  };
}

export const codeRules: readonly Rule[] = [
  execDownloadPipe,
  execDownloadRun,
  execPasswordArchive,
  execDisableProtection,
  execReverseShell,
  obfDecodeExec,
  obfLargeBlob,
  obfExecFetched,
  credReadFiles,
  credBrowserKeychain,
  credWallet,
  credAgentTokens,
  exfilEndpoint,
  exfilEnvDump,
  persistStartup,
  persistAgentConfig,
  destructWipe,
  destructAntiForensics,
].map(lowerInProse);
