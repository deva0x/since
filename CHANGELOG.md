# Changelog

All notable changes to `since`. Format loosely follows Keep a Changelog.

## [0.4.2] — 2026-07-25

Fixes for a second independent (Kimi) adversarial audit — the v0.3.1 fix round and the
v0.4 Linux code had introduced new bugs — plus a third independent review pass of this very
fix batch, which caught two redaction regressions the batch itself introduced. Each fix is
covered by a regression test (suite now 90 tests).

**Security / correctness (High):**
- **`redact()` no longer conceals the attacks it exists to surface, and no longer leaks
  the secrets it should mask.** The rule is now: a key that *names* a credential
  (`password=`, `SSHPASS=`, `_auth=`, `_authToken=`) has its value redacted unconditionally
  — including values that begin with `/` (base64 tokens), `$` (crypt/shadow hashes), or `~`;
  a key that merely *contains* a directive name (`AuthorizedKeysFile`, `AuthorizedKeysCommandUser`)
  keeps its value visible — including the default *relative-path* form `.ssh/authorized_keys`
  — so a malicious sshd/sudoers change stays visible.
- **`redact()` is no longer quadratic.** A long attacker-plantable rc-file line stalled the
  unattended `digest --notify` for minutes (8.4s @ 20KB → 0.5ms). Key-name runs are bounded.
- **Private-key / PEM bodies are masked on removed (`-`) diff lines too**, not only `+`.
- **Linux XDG autostart is fingerprinted by content hash**, so swapping `Exec=` in an
  existing `.desktop` (same `Name=`) is now detected instead of being invisible.

**Robustness (Medium/Low):**
- Linux proxy detection reads *system* config (`/etc/environment`, `/etc/profile.d`) instead
  of the caller's process environment — no more daily false ORANGE from timer-vs-shell.
- `clean()` neutralizes lone UTF-16 surrogates (a non-UTF-8 Linux filename no longer crashes
  the report) and now **keeps TAB** (it can't forge a line; stripping it mangled config diffs).
- `redact()` also masks `SSHPASS=`/bare `pass=` values.
- `_write_private` uses `mkstemp` — a stale temp from a crashed run (or reused PID) can't
  crash the next write.
- `since ignore` as the first-ever command now creates state at 0700 dir / 0600 file.
- `tilde()` collapses only a *leading* `$HOME`, not every occurrence.
- `/etc/ld.so.preload` (a rootkit hook) is treated as privilege-sensitive so a root/non-root
  mismatch can't fabricate an add/remove alarm.
- `--json` now surfaces the "N unreadable snapshot(s) skipped" / baseline note.
- `install.sh` quotes the systemd `ExecStart` (repo paths with spaces) and no longer aborts
  under `set -e` on a headless box with no user systemd session (writes units, reports how to
  finish).

**From a fourth pass — a full-tool independent audit of the whole file, and a fifth end-to-end
integration pass through the real pipeline:**
- `~/.curlrc` credentials (`user = "name:password"`, `-u user:pass`) are now redacted — a real
  leak in a tracked file that the URL-auth matcher missed, incl. on `+`/`-`-prefixed diff lines
  (the integration test caught the prefixed form leaking where the bare-line unit test did not).
- Linux systemd/init.d units now fold their effective `ExecStart` (via `systemctl show`, so
  drop-in overrides count) into the fingerprint — an `ExecStart` swap on an enabled unit was
  previously invisible (the macOS plist path already content-hashed; now Linux does too).
- Sensitive-file monitoring extended to `/etc/sudoers.d/*`, `cron.{daily,hourly,weekly,monthly}`,
  and the cron spool — the standard drop-in locations a real persistence entry would use.
- `since --since <absurd>` no longer crashes with an uncaught `OverflowError`.
- `clean()` also strips U+2028/U+2029 (line/paragraph separators); its comment now matches the
  code (TAB is kept, by design).

## [0.4.1] — 2026-07-24

- Linux desktop notifications via `notify-send` (was macOS `osascript` only).
- `install.sh` sets up a daily **systemd `--user` timer** on Linux (verified on Ubuntu:
  installs active, uninstalls clean) — previously only the macOS LaunchAgent.
- README documents that the tool runs **fully offline** (no network code, no deps, no
  telemetry; the one nuance is macOS `spctl` notarization checks for new signed items).

## [0.4.0] — 2026-07-24

**Linux support** — implemented and verified on a real box (Ubuntu 24.04).

- Collectors: XDG autostart (login items), enabled systemd units + `/etc/init.d`
  (startup jobs), `lsmod` (kernel modules), Chromium/Firefox browser extensions,
  `ss` listeners + outbound, `/etc/resolv.conf` DNS, and apt/dnf/pacman + snap +
  flatpak packages. npm/pip are shared cross-platform collectors.
- Sensitive-file diffs extended for Linux (`/etc/bash.bashrc`, `/etc/rc.local`,
  `/etc/ld.so.preload`, …) alongside the shared set.
- Platform-appropriate **labels** ("Autostart entries", "System packages") and
  **undo hints** (`systemctl disable`, `modprobe -r`, `apt/snap/flatpak remove`,
  `rm ~/.config/autostart/…`) — all still shlex-quoted.
- `since caps` and the "unsupported platform" notice are now platform-aware (Linux is
  supported; the notice only shows on genuinely-unknown OSes).
- CI now runs the suite + smoke on **ubuntu-latest** as well as macOS.

## [0.3.1] — 2026-07-24

Second hardening pass, from an independent adversarial audit that fuzzed the actual
functions (the first pass tested each fix's happy path and missed these).

### Security
- `clean()` now strips newlines/CR/tab **and** bidi overrides + zero-width chars. A
  newline in an attacker-chosen name previously injected extra output lines and could
  forge a `signature: Apple-signed` line or a fake `undo:` command.
- `redact()` rewritten: masks the whole value (so `Authorization: Bearer <jwt>` no
  longer leaks the token), plus AWS keys, basic-auth URLs, Stripe/GitHub/Slack tokens,
  JWTs and PEM bodies — and no longer false-redacts `NOPASSWD: ALL`. Applied to `why:`
  lines and the `--json` diff too.
- Snapshot state dirs are re-`chmod 700` on every write (not just at create); the
  installer pre-creates `daily.log` at `0600`.

### Correctness
- A port **removed** from a still-listening process is now reported (was silent in all
  modes, like the added-port case before it).
- `lsof` uses field mode (`-F`): fixes 9-char command truncation that merged distinct
  processes, and handles command names with spaces.
- `safe_load()` validates snapshot schema, so a stray valid-JSON file (`{}`, an editor
  autosave) no longer bricks every run with a `KeyError`.
- Homebrew **casks** are now tracked; big-file scan uses a PID-unique ref file (no
  cross-run race) and only notes real (non-permission) errors; same-name apps in
  `/Applications` vs `~/Applications` no longer collide; same-second snapshots don't
  clobber; login-item names with commas aren't split; launch-item fingerprint is a
  content hash (catches `cp -p` swaps, ignores `touch`); attribution matches whole words.
- `install.sh` refuses to clobber a non-symlink at the target; privilege guard now also
  covers `/etc/crontab` and `/etc/cron.d`.

## [0.3.0] — 2026-07-24

First public release.

### Security & correctness (hardening pass, from an adversarial review)
- Copy-paste `undo:` hints are injection-safe (`shlex.quote` everywhere; login-item
  name passed via `osascript … on run argv`).
- All echoed strings are stripped of terminal control/escape sequences, so a crafted
  name or diff line can't hide the change it describes or spoof a signature.
- Snapshots are written atomically at mode `0600` (no world-readable window) and loads
  tolerate a corrupt/truncated file instead of crashing.
- The privilege guard fails **closed**: an unstamped or mismatched-privilege baseline
  skips listening/outbound and `/etc/sudoers`/cron comparisons rather than firing false
  alarms.
- Secrets (`_authToken`, `PRIVATE KEY`, `export …KEY=`, …) are redacted from rendered
  diff lines and the daily log.
- Findings escalated to a higher severity (e.g. an unsigned app) are now ranked into the
  "Worth a look" section instead of rendering as a benign line.
- A new port opened on an already-listening process is surfaced; only full port turnover
  (random-port daemons) is suppressed.
- A missing checkpoint errors instead of silently diffing against ~now; a bad `--since`
  reports a clean error; the big-file scan reports a timeout instead of showing nothing.
- On a non-macOS platform the tool now prints a clear "unsupported platform" notice, so a
  "nothing changed" isn't mistaken for a full clean bill of health (found by running it on Linux).

### Added
- `--version`; `since caps` (coverage vs. what needs `sudo`); `mark`/`ack`/`ignore`;
  natural-language `--since`; `digest --notify`; `install.sh --uninstall`.
- Collectors: kernel/browser/system extensions, DNS/proxy, pip, Mac App Store, outbound.
- Runnable test suite (`pytest`) and CI.

## [0.2.0] — 2026-07-24
- 4-level severity, signing/trust checks, shell-history attribution, undo hints,
  malicious-pattern escalation. Platform-abstracted collectors (Linux backends deferred).

## [0.1.0] — 2026-07-24
- Initial tool: snapshot/diff of login items, LaunchAgents/Daemons, listeners, brew/npm,
  applications, system-file line-diffs, and big new files.
