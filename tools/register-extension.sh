#!/usr/bin/env bash
# Replace YOUR_EXTENSION_ID in installed manifests with the provided extension id
# Usage: ./tools/register-extension.sh <extension-id>
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <extension-id>"
  exit 1
fi
EXT_ID="$1"

CHROME_MANIFEST="$HOME/.config/google-chrome/NativeMessagingHosts/com.passwordmanager.native.json"
BRAVE_MANIFEST="$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/com.passwordmanager.native.json"
FIREFOX_MANIFEST="$HOME/.mozilla/native-messaging-hosts/com.passwordmanager.native.json"

for m in "$CHROME_MANIFEST" "$BRAVE_MANIFEST" "$FIREFOX_MANIFEST"; do
  if [ -f "$m" ]; then
    tmp="$m.tmp"
    jq --arg id "chrome-extension://$EXT_ID/" '.allowed_origins = [ $id ]' "$m" > "$tmp" && mv "$tmp" "$m"
    echo "Updated $m"
  fi
done

echo "Done. Manifests updated with extension id: $EXT_ID"
