/**
 * Credential patterns shared by the TM-SEC rules, report redaction and the
 * proxy's egress guard. Every pattern must be linear-time: no nested
 * quantifiers and bounded repetition only.
 */
export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { id: 'private-key', name: 'Private key block', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: 'aws-access-key', name: 'AWS access key id', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'github-token', name: 'GitHub token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/ },
  { id: 'github-fine-grained', name: 'GitHub fine-grained token', regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/ },
  { id: 'anthropic-key', name: 'Anthropic API key', regex: /\bsk-ant-(?:api|admin|oat)[0-9]{2}-[A-Za-z0-9_-]{40,255}/ },
  { id: 'openai-key', name: 'OpenAI API key', regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}T3BlbkFJ[A-Za-z0-9_-]{20,255}\b/ },
  { id: 'openai-project-key', name: 'OpenAI project key', regex: /\bsk-proj-[A-Za-z0-9_-]{40,255}\b/ },
  { id: 'google-api-key', name: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'slack-token', name: 'Slack token', regex: /\bxox[abposr]-[A-Za-z0-9-]{10,255}\b/ },
  { id: 'slack-webhook', name: 'Slack webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{6,20}\/B[A-Za-z0-9_]{6,20}\/[A-Za-z0-9_]{20,40}/ },
  { id: 'stripe-live-key', name: 'Stripe live key', regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,255}\b/ },
  { id: 'npm-token', name: 'npm access token', regex: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'huggingface-token', name: 'Hugging Face token', regex: /\bhf_[A-Za-z0-9]{34,40}\b/ },
  { id: 'gitlab-token', name: 'GitLab token', regex: /\bglpat-[A-Za-z0-9_-]{20,64}\b/ },
  { id: 'telegram-bot-token', name: 'Telegram bot token', regex: /\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
  { id: 'google-oauth-secret', name: 'Google OAuth client secret', regex: /\bGOCSPX-[A-Za-z0-9_-]{20,40}\b/ },
  { id: 'groq-key', name: 'Groq API key', regex: /\bgsk_[A-Za-z0-9]{40,60}\b/ },
  { id: 'xai-key', name: 'xAI API key', regex: /\bxai-[A-Za-z0-9]{40,120}\b/ },
  { id: 'digitalocean-token', name: 'DigitalOcean token', regex: /\bdo[oprt]_v1_[a-f0-9]{64}\b/ },
  { id: 'supabase-token', name: 'Supabase access token', regex: /\bsbp_[a-f0-9]{40}\b/ },
  { id: 'sendgrid-key', name: 'SendGrid API key', regex: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,64}\b/ },
  { id: 'mailgun-key', name: 'Mailgun API key', regex: /\bkey-[0-9a-f]{32}\b/ },
  { id: 'shopify-token', name: 'Shopify access token', regex: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/ },
  { id: 'twilio-sid', name: 'Twilio account SID', regex: /\bAC[0-9a-fA-F]{32}\b/ },
  { id: 'twilio-api-key', name: 'Twilio API key SID', regex: /\bSK[0-9a-fA-F]{32}\b/ },
  { id: 'azure-storage-key', name: 'Azure storage account key', regex: /AccountKey=[A-Za-z0-9+/]{86}==/ },
  { id: 'discord-bot-token', name: 'Discord bot token', regex: /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b/ },
  { id: 'jwt', name: 'JSON Web Token', regex: /\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,2000}/ },
];

export interface SecretHit {
  patternId: string;
  name: string;
  index: number;
  length: number;
}

export function findSecrets(text: string, limit = 50): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const pattern of SECRET_PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : `${pattern.regex.flags}g`);
    let match: RegExpExecArray | null;
    while (hits.length < limit && (match = re.exec(text)) !== null) {
      hits.push({ patternId: pattern.id, name: pattern.name, index: match.index, length: match[0].length });
      if (match[0].length === 0) re.lastIndex++;
    }
  }
  hits.sort((a, b) => a.index - b.index);
  return dropOverlaps(hits);
}

function dropOverlaps(sorted: SecretHit[]): SecretHit[] {
  const out: SecretHit[] = [];
  let end = -1;
  for (const hit of sorted) {
    if (hit.index >= end) {
      out.push(hit);
      end = hit.index + hit.length;
    }
  }
  return out;
}

/** Keeps the first 4 characters of each secret so a reader can recognise it, and masks the rest. */
export function redactSecrets(text: string): string {
  const hits = findSecrets(text, 1000);
  if (hits.length === 0) return text;
  let out = '';
  let cursor = 0;
  for (const hit of hits) {
    out += text.slice(cursor, hit.index);
    const secret = text.slice(hit.index, hit.index + hit.length);
    out += hit.patternId === 'private-key' ? secret : `${secret.slice(0, 4)}${'*'.repeat(8)}[redacted]`;
    cursor = hit.index + hit.length;
  }
  return out + text.slice(cursor);
}
