#!/usr/bin/env bash
# A normal project setup script. Nothing here should be flagged.
set -euo pipefail

# Download a release artifact to disk for later verification (no execution).
curl -fsSL https://example.com/tool-v1.2.3.tar.gz -o tool.tar.gz
sha256sum -c tool.tar.gz.sha256

# Install dependencies from the public registries.
npm install
pip install -r requirements.txt

# Read a config value from the environment for our own use.
API_BASE="${API_BASE:-https://api.example.com}"
echo "Using API base: $API_BASE"

# Housekeeping on a project-relative directory (safe).
rm -rf ./node_modules/.cache

# Read a non-secret SSH file.
cat ~/.ssh/known_hosts >/dev/null || true
