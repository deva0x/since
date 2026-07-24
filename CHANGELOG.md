# Changelog

All notable changes to `since`. Format loosely follows Keep a Changelog.

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
