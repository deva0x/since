#!/usr/bin/env bash
# install.sh — put `since` on your PATH and (optionally) run a daily digest.
# Works on macOS (LaunchAgent) and Linux (systemd --user timer).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname)"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/since"
STATE_DIR="${HOME}/.local/state/since"
PLIST="${HOME}/Library/LaunchAgents/dev.since.daily.plist"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

# --- uninstall ---------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
  echo "since uninstaller"
  if [[ "$OS" == "Darwin" ]]; then
    launchctl unload "${PLIST}" 2>/dev/null || true
    rm -f "${PLIST}" && echo "  removed LaunchAgent (if any)"
  else
    systemctl --user disable --now since.timer 2>/dev/null || true
    rm -f "${SYSTEMD_DIR}/since.service" "${SYSTEMD_DIR}/since.timer"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "  removed systemd user timer (if any)"
  fi
  [[ -L "${TARGET}" ]] && rm -f "${TARGET}" && echo "  removed symlink ${TARGET}"
  echo "  note: your snapshots in ${STATE_DIR} are LEFT IN PLACE."
  echo "        remove them yourself with:  rm -rf ${STATE_DIR}"
  exit 0
fi

echo "since installer  (${OS})"
echo "  repo: ${REPO_DIR}"

mkdir -p "${BIN_DIR}"
# Don't clobber an existing regular file (some other tool named 'since') — only
# overwrite our own symlink. Refuse otherwise so the user can decide.
if [[ -e "${TARGET}" && ! -L "${TARGET}" ]]; then
  echo "  ✗ ${TARGET} already exists and is not a symlink — refusing to overwrite it."
  echo "    Move it aside and re-run, or install elsewhere."
  exit 1
fi
ln -sf "${REPO_DIR}/since.py" "${TARGET}"
chmod +x "${REPO_DIR}/since.py"
echo "  linked: ${TARGET} -> since.py"

# Secure the state dir (snapshots hold secrets); pre-create the macOS daily log 0600.
mkdir -p "${STATE_DIR}" && chmod 700 "${STATE_DIR}"
if [[ "$OS" == "Darwin" ]]; then
  umask 077; : > "${STATE_DIR}/daily.log" || true; umask 022
fi

case ":${PATH}:" in
  *":${BIN_DIR}:"*) : ;;
  *) echo "  ⚠  ${BIN_DIR} is not on your PATH — add:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# Establish the first baseline right away.
"${REPO_DIR}/since.py" snapshot || true

read -r -p "Install daily digest job (09:00 each day, notifies if worth a look)? [y/N] " ans
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
  PY="$(command -v python3)"
  if [[ "$OS" == "Darwin" ]]; then
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
  <key>StandardOutPath</key><string>${STATE_DIR}/daily.log</string>
  <key>StandardErrorPath</key><string>${STATE_DIR}/daily.log</string>
</dict>
</plist>
EOF
    launchctl unload "${PLIST}" 2>/dev/null || true
    launchctl load "${PLIST}"
    echo "  loaded daily LaunchAgent: ${PLIST}"
    echo "  verify with:  launchctl list | grep dev.since"
  else
    mkdir -p "${SYSTEMD_DIR}"
    cat > "${SYSTEMD_DIR}/since.service" <<EOF
[Unit]
Description=since — daily change digest

[Service]
Type=oneshot
ExecStart=${PY} ${REPO_DIR}/since.py digest --notify
EOF
    cat > "${SYSTEMD_DIR}/since.timer" <<EOF
[Unit]
Description=Run since daily at 09:00

[Timer]
OnCalendar=*-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now since.timer
    echo "  enabled systemd user timer: since.timer  (output → journalctl --user -u since.service)"
    echo "  verify with:  systemctl --user list-timers since.timer"
    echo "  headless box? run once:  sudo loginctl enable-linger \"\$USER\"   (so it fires without a login session)"
  fi
else
  echo "  skipped daily job — run 'since snapshot' yourself, or re-run this installer."
fi

echo
echo "Done. Try:  since --help"
