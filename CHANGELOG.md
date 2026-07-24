# Changelog

All notable changes to `since`. Format loosely follows Keep a Changelog.

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
