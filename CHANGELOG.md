# Changelog

All notable changes to `since`. Format loosely follows Keep a Changelog.

## [0.4.3] — 2026-07-25

Fixes for a **third** independent (Kimi) adversarial audit, which re-verified every v0.4.2
fix as genuine and then found one new High in the collector layer. Every fix below was
reproduced by execution first and is covered by a regression test (suite 90 → **129**).

**Security / availability (High):**
- **A planted FIFO or device symlink no longer hangs the daily digest.** Four collectors
  (`~/Library/LaunchAgents` plists, XDG `.desktop` entries, and both browser-extension
  manifest readers) read glob-matched paths with no regular-file check, so a FIFO — or a
  symlink to `/dev/zero` — dropped into any of those *user-writable* directories blocked
  `read()` **forever**, inside `take_snapshot()`, before any output, snapshot or
  notification: `digest --notify` produced nothing and leaked one hung process per day.
  A watchdog that dies silently is the exact failure this tool exists to prevent.
  Regression-tested with real FIFOs under a SIGALRM deadline (the harness is self-checked:
  it does catch an unguarded read). A non-regular entry in a persistence directory is now
  *reported* ("not a regular file"), not silently skipped — such an entry is itself anomalous.
- **Every collector read is now bounded and race-proof (`safe_read_bytes`/`safe_read_text`).**
  Auditing the fix above showed a type check alone was not enough: a **2GB sparse file**
  planted as a plist costs an attacker nothing to create and drove **4.1GB peak RSS**
  (2GB → 62MB after the fix), and a symlink swapped to a FIFO *after* the check re-opened the
  hang. Reads now open with `O_NONBLOCK`, verify `S_ISREG` on the **file descriptor** (not the
  path, so the check-then-open race cannot be won), and stop at 8MB. Shell history is read
  from the *tail* (recency is what attribution needs) starting at a line boundary. Applied to
  every plist/`.desktop`/manifest/rc-file/`/etc` read — snapshot output on a real machine is
  byte-identical before and after.

**Secret hygiene / performance (Medium):**
- **`Authorization: <token>` is now masked.** The v0.4.2 HARD/SOFT key split had swept the
  `authoriz` keyword into "always show" to keep `AuthorizedKeysFile` visible, which left a
  raw `Authorization:` header (`.curlrc`/`.wgetrc`) printing in cleartext unless it happened
  to use the `Basic`/`Bearer`/JWT shapes. Whole-word `authorization` is HARD; the
  `Authorized*` sshd directives (absolute *and* relative paths) stay visible.
- **`redact()` cost is now bounded absolutely.** It was linear after v0.4.2 but carried a
  ~3–5µs/char constant, and `--json` redacts *every* diff line, so a few hundred KB of long
  lines in a tracked rc file stalled the digest for tens of seconds. A shared-keyword linear
  pre-filter short-circuits keyword-free lines (40KB: 128ms → 0.4ms) and every line is
  capped at 4KB before the regexes run — truncation also fails safe, since the dropped tail
  is never printed. The pre-filter and the matcher are generated from one keyword constant
  so they cannot drift apart.

**Correctness (Low):**
- A sudoers **`PASSWD:` tag** no longer hides the command list it prefixes (`PASSWD:
  /tmp/miner` was rendered `PASSWD: «redacted»` — the v0.4.2 carve-out covered only
  `NOPASSWD:`). Value-shape gated, so a real `PASSWD=<secret>` assignment still redacts.
- **XDG autostart entries no longer collide across directories.** Keys were bare basenames,
  so `/etc/xdg/autostart/x.desktop` silently overwrote — hid — a planted
  `~/.config/autostart/x.desktop`. System entries are now tagged ` (system)` and their undo
  hint points at the right directory with `sudo` (it previously pointed `rm` at `~/.config`,
  where the file isn't). *One-time effect on Linux: existing `/etc/xdg` entries appear once
  as removed+added as the keys change.*
- **Apps in `~/Applications` are trust-checked again.** The v0.4.2 same-name disambiguator
  made `_enrich` build `…/Foo (~/Applications).app`, a path that never exists, so
  `trust_of()` returned nothing and an unsigned/ad-hoc app there could never escalate to
  RED. The new `bare_key()` also restores "why" attribution for tagged keys — a
  `foo (cask)`/`foo (snap)` key could never whole-word-match a shell-history line.
- A **corrupt `labels.json`** that is valid JSON of the wrong type (`["a","b"]`) no longer
  crashes `since mark` (`TypeError`) or `prune_snapshots` (`AttributeError`) — `load_labels()`
  now shape-validates like `safe_load()`.
- `os.geteuid()`/`os.uname()` are no longer called at import, so on Windows the honest
  "UNSUPPORTED PLATFORM" notice can actually print instead of a traceback.
- The big-file scan excluded the state directory by *substring*, which also excluded any
  sibling directory whose name merely starts with it (`…/since_backup`) — now a path-prefix
  match. The Linux browser-extension collector skips the `Temp` staging dir (macOS parity).

**Docs:** `SECURITY.md` gains an explicit **threat model** — a process running as you can
tamper with the baselines in `~/.local/state/since` and erase its own tracks, and helper
binaries are `PATH`-resolved (the daily job's minimal `PATH` is unaffected). Stale
`CLAUDE.md` state lines corrected.

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
