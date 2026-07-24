#!/usr/bin/env bash
# install.sh — put `since` on your PATH and (optionally) run a daily snapshot.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/since"
PLIST="${HOME}/Library/LaunchAgents/dev.since.daily.plist"

# --- uninstall ---------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
  echo "since uninstaller"
  launchctl unload "${PLIST}" 2>/dev/null || true
  rm -f "${PLIST}" && echo "  removed LaunchAgent (if any)"
  [[ -L "${TARGET}" ]] && rm -f "${TARGET}" && echo "  removed symlink ${TARGET}"
  echo "  note: your snapshots in ~/.local/state/since are LEFT IN PLACE."
  echo "        remove them yourself with:  rm -rf ~/.local/state/since"
  exit 0
fi

echo "since installer"
echo "  repo: ${REPO_DIR}"

mkdir -p "${BIN_DIR}"
ln -sf "${REPO_DIR}/since.py" "${TARGET}"
chmod +x "${REPO_DIR}/since.py"
echo "  linked: ${TARGET} -> since.py"

case ":${PATH}:" in
  *":${BIN_DIR}:"*) : ;;
  *) echo "  ⚠  ${BIN_DIR} is not on your PATH — add:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# Establish the first baseline right away.
"${REPO_DIR}/since.py" snapshot || true

# Offer a daily snapshot LaunchAgent (runs `since snapshot` every morning at 09:00).
read -r -p "Install daily snapshot LaunchAgent (09:00 each day)? [y/N] " ans
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  PY="$(command -v python3)"
  mkdir -p "${HOME}/Library/LaunchAgents"
  cat > "${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.since.daily</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PY}</string>
    <string>${REPO_DIR}/since.py</string>
    <string>digest</string>
    <string>--notify</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>${HOME}/.local/state/since/daily.log</string>
  <key>StandardErrorPath</key><string>${HOME}/.local/state/since/daily.log</string>
</dict>
</plist>
EOF
  launchctl unload "${PLIST}" 2>/dev/null || true
  launchctl load "${PLIST}"
  echo "  loaded daily LaunchAgent: ${PLIST}"
  echo "  verify with:  launchctl list | grep cash.since"
else
  echo "  skipped daily job — run 'since snapshot' yourself, or re-run this installer."
fi

echo
echo "Done. Try:  since --help"
