#!/usr/bin/env bash

set -euo pipefail
sudo apt-get update -y
sudo apt-get install -y jq curl


# 0. Install TruffleHog (secret scanner)

set -euo pipefail
mkdir -p "$HOME/bin"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
| sh -s -- -b "$HOME/bin"
export PATH="$HOME/bin:$PATH"
trufflehog --version

# Find baseline-commit for relevant commits
set -euo pipefail

echo "Running on branch: $BUILD_SOURCEBRANCH"
# Default to first commit if we can't find a baseline
BASE_COMMIT="$(git rev-list --max-parents=0 HEAD | tail -n1)"

if [[ -n "${SYSTEM_PULLREQUEST_TARGETBRANCH:-}" ]]; then
echo "PR build: Finding merge-base for target branch: $SYSTEM_PULLREQUEST_TARGETBRANCH"
git fetch origin "$SYSTEM_PULLREQUEST_TARGETBRANCH" --depth=0
BASE_COMMIT="$(git merge-base HEAD "origin/$SYSTEM_PULLREQUEST_TARGETBRANCH")"
else
echo "CI build (push): Finding last SUCCEEDED build-commit on same branch"
: "${SYSTEM_ACCESSTOKEN:=$SYSTEM_ACCESSTOKEN}" 
AUTH_USER=":$SYSTEM_ACCESSTOKEN"

BASE="$(echo "$SYSTEM_COLLECTIONURI" | sed 's#/*$##')"
PROJECT_ENC="$(printf %s "$SYSTEM_TEAMPROJECT" | jq -sRr @uri)"
BRANCH_ENC="$(printf %s "$BUILD_SOURCEBRANCH" | jq -sRr @uri)"
API="$BASE/$PROJECT_ENC/_apis/build/builds"
URL="$API?definitions=$SYSTEM_DEFINITIONID&branchName=$BRANCH_ENC&resultFilter=succeeded&%24top=1&queryOrder=finishTimeDescending&api-version=7.1"

LAST_SHA="$(curl -sS -f \
-H "Authorization: Bearer $SYSTEM_ACCESSTOKEN" \
-H 'Accept: application/json' \
"$URL" | jq -r '.value[0].sourceVersion // empty')"
if [[ -n "$LAST_SHA" ]]; then
BASE_COMMIT="$LAST_SHA"
fi
fi

echo "Baseline commit: $BASE_COMMIT"
echo "##vso[task.setvariable variable=BASE_COMMIT]$BASE_COMMIT"

set -euo pipefail
export PATH="$HOME/bin:$PATH"
# Scan commit-range from baseline to HEAD in the local repos
trufflehog git file://. \
--since-commit "$BASE_COMMIT" \
--branch HEAD \
--json > results.json || true

set -Eeuo pipefail
trap 'echo "Error on line ${LINENO}. Last command: ${BASH_COMMAND}"; exit 1' ERR

if [[ ! -s results.json ]]; then
echo "✅ No findings."
exit 0
fi

# Normalize allow-list (supports newline/comma/space separated). Keep only 64-hex lines.
allow_file="$(mktemp)"
printenv | awk -F= '{print $2}' | grep -E '^[0-9A-Fa-f]{64}$' | tr 'A-F' 'a-f' | sort -u > "$allow_file" || true

echo "🔎 Evaluating findings against allow-list..."
violations=0

echo "Findings (JSONL) lines: $(wc -l < results.json || echo 0)"
echo "Allow-list entries: $(grep -c '' "$allow_file" || echo 0)"

# Process JSONL safely without echoing raw values
lineno=0
while IFS= read -r json; do
lineno=$((lineno+1))
[[ -z "$json" ]] && continue

raw=$(jq -r '.Raw // empty' <<<"$json") || {
echo "⚠️  Invalid JSON at line $lineno — skipping"; 
continue; 
}
[[ -z "$raw" ]] && continue

hash=$(printf '%s' "$raw" | sha256sum | awk '{print tolower($1)}') || {
echo "⚠️  Could not hash secret at line $lineno — skipping"
continue
}

# Skip if hash is in the allow-list
if grep -qx "$hash" "$allow_file"; then
continue
fi

# Not allow-listed → report safe fields + the hash and count a violation
filtered=$(jq -c \
--arg h "$hash" \
'{file: (.SourceMetadata.Data.Git.file // .SourceMetadata.Data.Filesystem.file),
  line: (.SourceMetadata.Data.Git.line // .SourceMetadata.Data.Filesystem.line),
  detector: .DetectorName,
  gitcommit: .SourceMetadata.Data.Git.commit,
  verified: .Verified,
  hash: $h}' <<<"$json")

echo "TH: $filtered"
violations=$((violations+1))

done < results.json


if (( violations > 0 )); then
echo ""
echo "❌ Unapproved secrets detected — failing pipeline."
exit 1
fi

echo "✅ All findings are allow-listed."
exit 0