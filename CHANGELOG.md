# Changelog

All notable changes to `since`. Format loosely follows Keep a Changelog.

## [0.4.9] — 2026-07-27

Day 3 of the trial, and both fixes are things only a multi-day run on real machines could have
shown. Suite 689 → **692**.

**Upgrading to 0.4.8 set off a false alarm on every listener.** 0.4.8 started storing `*:5000`
where older snapshots held `5000`, and the diff compared those as opaque strings — so the first
run after the upgrade reported 11 "changed listener" findings on the trial Mac and 3 on the Linux
box, all at ORANGE, all of them notifying, and every single one a lie: the ports were identical.
The changelog had predicted this churn and waved it through as harmless, which it was not. The
listening diff now compares what both sides actually express — when either side predates the
change it compares port sets, so a pure representation change produces nothing. This is *not* a
blanket exemption: a genuinely new port arriving alongside the migration is still reported, and
once both snapshots carry addresses, `127.0.0.1:5000` → `*:5000` is a real exposure change and
stays a finding.

The general lesson, recorded in RULES.md: a change to how a collector *stores* a value must never
be able to look like a change in what it *observed*.

**The Linux installer no longer promises a daily job it cannot keep.** `systemctl --user enable
--now` succeeding proves only that a user manager exists at that moment — and it exists because
you are logged in. With lingering off, systemd tears that manager down at your last logout and
the timer goes with it, so the installer printed a confident "enabled systemd user timer" for a
job that then goes dormant on exactly the machine that needs it most: a server nobody logs into.
(`Persistent=true` means the run is deferred to the next login rather than lost.) The installer
now checks `loginctl show-user ... -p Linger` after a successful enable and prints the one-line
fix when lingering is off. Verified on a real Ubuntu box in both directions: the note appears
with `Linger=no` and is absent after `enable-linger`.

## [0.4.8] — 2026-07-26

Day 1 of a three-day trial on a real developer's Mac. Every fix below came from watching actual
output, not from review — and the biggest one is a capability the tool always had the data for
and threw away. Suite 667 → **689**.

**Listeners now record WHERE they are bound, and severity follows reachability.** `lsof` and `ss`
report `127.0.0.1:64991`; the collector kept only `64991`. So `claude` on loopback was reported at
the same severity as `*:4444` — and on a developer machine `java`, `node`, `claude` and `python`
bind loopback constantly, which was the dominant source of listener noise. A new listener bound
only to loopback is now YELLOW: visible in the report, below the `--notify` threshold. **Any**
non-local binding (`*`, `0.0.0.0`, a LAN address) stays ORANGE, a mixed set stays ORANGE, and a
bare port from an older snapshot is treated as *unknown* and stays ORANGE — unknown is never
assumed safe.

**Build outputs are pruned from the big-file scan.** One Rust workspace produced +772 MB across 15
`dep-graph.bin`/`.rlib` entries in a single day, crowding out anything a person would want to see.
`target`, `build`, `dist`, `Pods`, `__pycache__`, `.venv`, `venv` join `node_modules` and friends.

**Changed software gets its "why" too.** `claude-code 2.1.206 → 2.1.212` was reported with no
attribution while `brew upgrade claude-code` sat one line up in the shell history — attribution ran
only for `added`, not `changed`.

*Upgrade note: listener values change from `4444` to `addr:4444`, so listeners appear once as
removed+added.*

## [0.4.7] — 2026-07-25

Found by **dogfooding**, one hour into a three-day trial run on a real Mac — not by any of the six
adversarial review rounds.

**A listener rotating ephemeral ports no longer fires a notification every few hours.** Apple's
`rapportd` keeps one port and rotates the others (measured: `57905,65426,65427` →
`57905,65428,65429`). v0.4.6 judged churn by whether the port sets OVERLAP, so a rotation that
retained one port was treated as a real signal — ORANGE, which crosses the `--notify` threshold.
On a normal Mac that is a desktop notification every few hours, forever, which is precisely how a
digest teaches its reader to ignore it.

Churn is now a balanced **rotation** entirely inside the ephemeral range (≥32768), judged on what
*changed* rather than on set overlap. A net **gain** is never suppressed — whatever the port
number, including ephemeral ones, because malware binds those too. The four real rotations
measured on the trial machine are now regression fixtures, alongside the five gain/rebind cases
from v0.4.6 that must still report.

Suite 658 → **667**.

## [0.4.6] — 2026-07-25

A **fourth** adversarial round, pointed for the first time at the surfaces the previous five had
never examined — the collectors, the render path, and the ignore rules. It was the most productive
round of the project: 20 findings, and the worst were not in the heavily-audited `redact()` but in
code nobody had attacked. Suite 526 → **656**; **87/87 mutations** caught.

**A broken helper silently emptied its category.** `lsof`, `osascript`, `scutil`, `kextstat` and
`systemextensionsctl` returned `""` on a timeout or non-zero exit, so the collector reported an
EMPTY category. The diff reads that as "every listener / login item / DNS entry was removed", the
next day as "all of them are new" with the attacker's port among them — and if the tool stays
broken, both snapshots are empty and the report says **"Nothing changed 🎉" while a backdoor
listens**. `SECURITY.md` promises a skip *with a note*; only a raised error delivers that. All of
them now use `need()` + `run_checked`, and `coverage_lost` no longer requires a tool stamp — which
only 4 of 13 categories have, so the nine loudest categories could never reach ORANGE at all.

**An unsigned binary named `sh` fell out of RED (a regression from v0.4.5).** The interpreter
caveat added in 0.4.5 *cleared* the `suspicious` flag, and the basename is attacker-chosen — so
`cp miner ~/Library/.../sh` dropped an unsigned payload from RED to YELLOW, stopped `--notify`
firing, and replaced its "unsigned" label with a reassuring explanation. The caveat is now
appended, never substituted. Relatedly, an Apple-signed binary **copied outside** the system paths
(the `cp /bin/sh` laundering trick) is now suspicious in its own right.

**Collectors that could not see the attack at all:**
- **Browser extensions** were fingerprinted by display name, so overwriting `background.js`,
  adding `<all_urls>`/`cookies`/`webRequest`, or swapping the `.xpi` were invisible in a
  user-writable directory. Now version + manifest hash (size+mtime for Firefox `.xpi`), and
  version directories sort numerically — lexically, `1.10.0_0` read as older than `1.9.0_0`, so
  the OLD manifest was being reported.
- **Login items** were keyed *and* fingerprinted by display name with no path collected: planting
  an app named after an existing item, or retargeting an existing item, was invisible, and without
  a path no signature check was possible — they could never reach RED while the equivalent
  LaunchAgent did. Now keyed on path, trust-checked, with the name kept for the undo hint.
  *One-time effect: existing login items appear once as removed+added as the keys change.*
- **Kernel extensions**: `startswith("com.apple")` is a string test, not provenance, so naming a
  rootkit `com.apple.driver.AudioHelper` removed it from the report entirely — and real
  third-party prefixes (`co.`, `dev.`, `me.`) were never collected.
- **Listeners**: the anti-churn rule ("no port overlap ⇒ churn") silently dropped a single-port
  rebind (`8080 → 4444`) and a backdoor sharing a churny process name. Only an all-ephemeral
  multi-port set is churn now.
- **Linux `.socket` and `.path` units** — standard user-level persistence — were never collected.
- **Applications**: the trust check rebuilt the bundle path from the KEY, so `Calculator
  (cask).app` printed *another app's* signature and `Evil (snap).app` pointed at nothing; the
  collector now stores the real path.

**Severity and disclosure:**
- Creating a tracked config file was YELLOW while editing one was ORANGE — so planting `~/.zshenv`
  (sourced by every zsh) was the *quieter* attack. Now ORANGE, and rendered as "NEW FILE".
- An **ignore rule can no longer silence a critical finding**, and suppressions are disclosed
  ("N finding(s) hidden by M ignore rule(s)"). The README's own example rule can be matched by an
  attacker-chosen process name, and nothing previously said rules were even active.

**`redact()` leaks closed:** an unlisted auth scheme absorbed the mask and printed the credential
(`Authorization: SSWS <token>`, a real `.curlrc` line); a quoted value past the old 512-char bound
leaked its tail; a separator run (`:=`, `=>`, `==`, `=""`) left the secret as the next token.

**Three of my own attempted fixes were reverted after measuring them** — a whitespace-scheme rule
masked `pam_deny.so` and, worse, masked the wrong token while leaving real secrets; a mask-tail
pass broke compositionality by eating shell separators; and a payload-path exemption leaked base64
tokens, because base64 uses `/` so they match "looks like a path". All three are documented
residuals with the reasoning rather than silent reverts.

Also: `find`'s partial output is kept on timeout instead of discarded (a false all-clear on a large
HOME), and a corrupt `labels.json` no longer unprotects checkpoints from pruning.

## [0.4.5] — 2026-07-25

Two further adversarial rounds against v0.4.4, then a **restructure of `redact()`** and its first
**property tests**. 24 findings, each reproduced by execution before being fixed and pinned by a
mutation-tested regression test (**72/72 mutations caught**). Suite 228 → **463** (287
example-based + 176 property). Every Linux-only path is now verified on a real Ubuntu 24.04 box,
not just on CI's ubuntu runners.

**`redact()` restructured — the root cause, not another instance.** Its matcher took the value as
`(\S.*)$` — rest-of-line — and nearly every leak and hidden attack in this project's history
followed from that: a "show" decision exempted every later secret on the line, a "mask" decision
swallowed the rest of the attack, and the recursive rescan added to patch the first half became an
unprivileged kill switch. The value is now a **single token** (or an atomic quoted run), so
`re.sub` continues after each match and every assignment is decided **independently** — no
recursion, no depth cap, no tail semantics. Verified property:
`redact("a; b") == redact("a") + "; " + redact("b")` over 2700 random compositions.

**Property tests** (`tests/test_redact_properties.py`, stdlib-only with fixed seeds — no new
dependency, and failures replay from the printed seed) assert no-leak, no-hide, idempotence,
totality, bounded cost, marker-independence, pre-filter soundness and compositionality. They
immediately found three bugs 239 example tests had missed, including `redact("")` raising
**IndexError** — `line[:1] in "+-"` is true for the empty string.

**Fixed — credential leaks:** a `/`-preceded key exempted real assignments
(`//registry.npmjs.org/_authToken=<secret>`, `https://host/api_key=<secret>`) · a token passed as
argv to a credential-named script (`/opt/bin/refresh_token <secret>`) · `;`-chained secrets after
a shown path · `/`- and `$`-leading values under `*_FILE`/`*_PATH` keys · `sshpass -p <secret>`,
`mysql -u root -p<secret>`, `https://<token>@github.com`, `MYSQL_PWD=` · sudoers exemption
bypasses (a lowercase token posing as a tag; `ALL=<secret>`).

**Fixed — hidden attacks:** `SSH_AUTH_SOCK`/`*_ASKPASS`/`PGPASSFILE` hijacks were fully redacted ·
`SSH_ASKPASS=/evil` (a single-segment path) · `PasswordAuthentication=yes` (the `Key=value`
spelling) · sudoers command specs (`PASSWD:NOEXEC:`, `ALL, !/usr/bin/su`, and the account being
reset) · a payload past `BLOB_MAX` lost its RED escalation · the flag escalation was suppressible
by planting one benign decoy comment (flags are now **counts**, so any increase escalates) · a
malicious LaunchAgent reported `signature: Apple-signed` — that is the *interpreter's* signature,
and padding `argv[0]` evaded the payload scan entirely.

**Fixed — availability:** two more unprivileged **kill switches** (a `RecursionError` from ~800
credential keys on one line, and a non-container `blob_flags` value), each of which died before
saving a snapshot and therefore recurred **every day, forever** · `curl[^\n|]*\|` was still
unbounded and quadratic in line length (8 MB of 4096-column lines: **20.2 s → 13 ms** at snapshot
time) · a planted snapshot filename simply **became the baseline** · `safe_load` validated field
presence but not types, so an int `created` or blob value crashed the run permanently.

**Fixed — the capability guard's own bugs:** `recover_baselines` (added in 0.4.4 to stop a blind
day becoming its own baseline) recovered **ephemeral** categories across a **privilege
mismatch** — a 3-day-old root-taken listener set produced 27 fabricated ORANGE findings and fired
the notification, re-opening the exact flood the guard exists to prevent. It is now restricted to
durable inventory, requires a matching *stamped* privilege level, and may not reach forward of the
requested baseline. `run_checked` covered only half of `_mac_brew` and **none** of
`_linux_packages`; `CAT_TOOLS` stamped `brew` on Linux, where that category is dpkg/rpm/pacman —
so the whole guard was a **no-op on Linux**.

**Fixed — `install.sh` silently disabled all monitoring.** `[ -d "$1" ] || return` propagated
status 1 for a `PATH` entry that does not exist (`/snap/bin` on a box without snapd), and under
`set -euo pipefail` that aborted the installer immediately after the first snapshot: no prompt, no
units, no daily job, exit 1, **no error message**. Found on the real box; neither CI nor a
container check could see it.

**Verified on a real Ubuntu 24.04 box** (the three items outstanding since v0.4.0/v0.4.4 are now
discharged): the systemd `--user` timer installs, arms and **runs** with its pinned
`Environment=PATH=`; the headless-session guard writes the units and prints the finishing steps
instead of aborting; `_systemctl_execstart` parses **real** `systemctl show` output and a genuine
drop-in `ExecStart` override changes the fingerprint; all 8 Linux collectors work (763 packages);
`LOST VISIBILITY` fires when `dpkg-query` breaks; every undo hint carries its `--` guard.

## [0.4.4] — 2026-07-25

A security release fixing **16 issues found by reviewing v0.4.3 itself** — each reproduced by
execution before being fixed, and each pinned by a regression test that was *mutation-tested*
(revert the fix, confirm the test fails: **24/24 caught**). Suite 129 → **227**. Most of these sat
behind an architectural blind spot rather than inside any one function:

- Every previous audit round hardened the **snapshot** boundary; **diff-time enrichment had no
  isolation and no input validation at all**. Collectors are individually failure-isolated;
  `_enrich` was not, and `main` catches only `KeyboardInterrupt`.
- `redact()`'s "show" decisions exempted the **entire rest of the line** (its value group runs to
  end-of-line), and its `=`/`:` branch redacted unconditionally.
- Undo hints were quoted for the **shell** but not for the **invoked program's own option parser**.

**CRITICAL — the remediation advice could execute attacker code:**
- **`osascript` re-parsed the login-item name as its own options.** The name is passed as an argv
  parameter *and* shell-quoted, but neither stops `osascript` consuming a name that looks like an
  option: a login item called `-e property zz : (do shell script "…")` became a second `-e` chunk
  whose property initializer **ran at load** — so "delete this login item" executed the malware
  author's command while the delete silently no-opped on an empty `argv` (verified with a benign
  marker file). Every hint whose value can begin with `-` now ends option parsing with `--`.

**HIGH:**
- **One planted plist no longer kills the daily digest permanently.** A *valid* plist with a
  non-dict root makes `plutil` emit `["x"]`; `.get` on that raised, and with no isolation the
  digest died — **saving no snapshot**, so the plist stayed "added" and it failed identically every
  day. Shapes are now validated, and an enrichment failure degrades **one finding** (which still
  reports, tagged) instead of the whole run.
- **The daily job was blind to software changes, and the flood hid real installs.** launchd hands
  an agent a `PATH` with neither `/opt/homebrew/bin` nor `~/.local/bin`, so `brew`/`npm`/`pip3`
  silently vanished (`brew` 192 → 0) with **no error recorded**: 212 phantom findings, and a
  genuine new package was pushed past the 40-line render cap and never displayed. Three-part fix —
  collectors **declare their tools** (`need()`) so absence is recorded; the diff gained a
  **capability guard** that skips a category unavailable *or answered by a different binary* in
  either snapshot (snapshots now stamp tool identity, schema 4); and `install.sh` **pins the job's
  `PATH`**, copying the installing shell's resolution order. A transient `brew list` timeout caused
  the identical flood, so the guard — not the `PATH` — is the real fix.
- **Losing sight of a category is now a ranked finding, not a whisper.** Skipping an unusable
  category is right (comparing fabricates mass add/remove) — but a passive `note:` would have let
  an attacker buy *silence* by breaking a collector's tool, since neither the old phantom flood nor
  a note ever reached the `--notify` threshold. A category that was visible in the baseline and
  isn't now yields an ORANGE **"LOST VISIBILITY"** finding that ranks under "worth a look" and
  fires the notification — and that covers a tool that merely **changed** as well as one that
  vanished, because the pinned job `PATH` necessarily includes user-writable directories, so
  planting `~/.local/bin/brew` swaps the tool identity *without* erroring and was the cheapest
  suppression route of all. A first run, a legitimately absent tool, and the one-time pre-v0.4.4
  stamp transition stay quiet notes — all verified. (Both found by reviewing the capability guard
  added earlier in this same release.)
- **`difflib` was quadratic on a planted rc file** (~100 distinct repeated lines defeat its
  autojunk filter): a 0.74 MB `~/.zshrc` cost 32s of a real digest run. `MAX_READ` bounded the
  read; nothing bounded the diff. Above 20k lines / 1 MB the change is reported *with a content
  hash* instead of a line diff — same finding, same severity, 30.5s → 0.01s.
- **`redact()` concealed path-valued env hijacks entirely**: `SSH_AUTH_SOCK`, `SSH_ASKPASS`,
  `SUDO_ASKPASS`, `GIT_ASKPASS`, `PGPASSFILE` — each a known credential-theft technique in a
  tracked rc file, where the path *is* the finding — rendered as `«redacted»`.
- **The v0.4.3 sudoers `PASSWD:` carve-out was half-done**: a tag chain (`PASSWD:NOEXEC:`) or a
  comma list (`PASSWD: ALL, !/usr/bin/su`) still had the granted command list redacted away.
- **Three cleartext credential leaks** in files the tool diffs: `sshpass -p 'secret'` (the spaced
  form; the attached form was already masked), `https://<token>@github.com/` in `.gitconfig`, and
  `MYSQL_PWD=` (the `PWD` spelling was not a keyword).

**MEDIUM / LOW:**
- A planted FIFO `.app` made `codesign` block for its full 10s timeout *per item*; trust checks are
  now shape-gated (12 planted FIFOs: 120s → 0.00s).
- The three state-dir reads still using raw `read_text` (`safe_load`, `load_labels`,
  `load_ignores`) hung forever on a FIFO planted in `~/.local/state/since`.
- A "show" decision no longer exempts later secrets on the same line (`AuthorizedKeysCommand
  /usr/bin/fk --api-key=…` printed the key), and the `NOPASSWD` carve-out is gated on the exact
  uppercase tag — `export NOPASSWD_TOKEN=…` leaked through the old substring test.
- `PasswordAuthentication=yes` / `AuthorizedKeysFile=/tmp/evil/keys` — the valid `Key=value`
  spelling — are shown again instead of redacted.
- Every cask's undo hint named a nonexistent formula (`brew uninstall 'foo (cask)'`) → now
  `brew uninstall --cask foo`. `/Library/LaunchAgents` gets `sudo rm` (that directory is
  root-owned, so the unprivileged `rm` could never succeed). A wrong-type collector value in a
  baseline no longer crashes the diff.
- Blobs are stored capped at 256 KB plus a hash of the full content: 13 tracked files at the 8 MB
  read cap meant ~109 MB per snapshot and ~9.6 GB across `KEEP_SNAPSHOTS=90` → ~293 MB, with
  changes past the cap still detected.

**Second review round — 7 more issues, all in this very fix batch.** Re-attacking v0.4.4 before
publishing it found that the fixes above had introduced their own problems. Fixed, each with a
mutation-tested regression test (40/40 mutations caught cumulatively):
- **CRITICAL: the new `redact()` tail rescan was an unprivileged kill switch.** It recursed once per
  credential-ish key on a line, so a 2.5 KB comment of repeated `_pwd ` — under `_REDACT_MAX`, so
  the cap did not help — raised `RecursionError`. Nothing catches it, the digest died before saving
  a snapshot, the planted line stayed "added", and **every later run died identically**: one line in
  `~/.zshrc` disabled the tool permanently. The rescan depth is now bounded and fails *safe*
  (redact), and the cost is back to ~1.4× v0.4.3 instead of quadratic.
- **A skipped category no longer becomes its own baseline.** The capability guard skipped the blind
  day — but that snapshot still became tomorrow's baseline, so a package installed during the blind
  window was never reported by *any* run while the report said "Nothing changed. 🎉". A skipped
  category is now diffed against the newest earlier snapshot that could see it with the same tool,
  and the all-clear line no longer claims nothing changed when something could not be compared.
- **`need()` proved a tool RESOLVES, never that it RAN**, so the `brew list` timeout named as the
  guard's own motivation still produced the phantom flood. Collectors now use a checked runner that
  records a timeout or a failing exit as unavailability (tolerating `npm`'s non-zero-with-output).
- **The guard crashed on a wrong-typed `tools`/`errors` field** in a baseline — the same class this
  release had already fixed twice — killing the digest with no snapshot saved, permanently.
- **The storage cap silently disabled RED escalation.** A payload appended past `BLOB_MAX` (or past
  the diff cap) never reached the diff text, so a `curl | sh` line fell to ORANGE with no `why`.
  Malicious patterns are now scanned over the *full* content at snapshot time and diffed as flags.
- **The new full-content scan re-opened a quadratic DoS** (found by measuring my own round-2 fix
  rather than trusting it): two malicious-pattern regexes used unbounded `.*`, which is quadratic
  in the number of trigger tokens on one line — a planted line of repeated `base64 -d ` cost 55s at
  375 KB and hours at `MAX_READ`, at **snapshot** time, before anything is saved. The runs are now
  bounded and the scan is line-wise with a per-line cap: flat ~3 ms regardless of token count,
  detection unchanged. This was latent in the pre-v0.4.4 diff-text path too.
- **`plutil` was handed unbounded input** at diff time (a 500 MB plist measured 2.27 GB RSS); the
  plist is size-gated now, like every collector read.
- **A malicious LaunchAgent was labelled "signature: Apple-signed".** `ProgramArguments =
  ["/bin/sh","-c","curl …|sh"]` resolves to `/bin/sh`, which genuinely is — so the report reassured
  the user about the payload. The argv is now scanned for malicious patterns (which outrank any
  signature on the interpreter), and an overwritten *existing* plist — the classic hijack — is
  trust-checked and escalated instead of being a quiet YELLOW hash change.

**Docs:** `SECURITY.md`'s `PATH` paragraph was **wrong by omission** — it presented the daily job's
minimal `PATH` purely as a safety property when it was also the cause of the blindness above. It
now states the trade plainly: the pinned `PATH` includes user-writable directories, and `since`
does not attest to the integrity of the tools it asks.

**First run after upgrading:** snapshots taken before this version carry no tool-identity stamp, so
`brew`/`npm`/`pip` comparisons are skipped **once**, with a note, until a new baseline exists — the
same fail-closed transition the privilege stamp used.

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
