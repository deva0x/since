# Security Policy

`since` is a defensive awareness tool, and it treats its own input as potentially
hostile (a snapshot may capture malware-controlled names and file contents). If you
find a way to defeat that — command/escape injection through a crafted name or file,
a bypass of the privilege guard or secret redaction, or any way to make the tool
report a malicious change as benign — please report it.

## Reporting

- Preferred: open a **private** GitHub Security Advisory ("Report a vulnerability").
- Please include: the crafted input (plist name, hosts line, process name, …), the
  exact command run, and what the tool did vs. what it should have done.

Please do **not** open a public issue for an unpatched vulnerability.

## Scope & expectations

- In scope: injection into the copy-paste `undo:` hints or the notification, terminal-
  escape injection into rendered output, privilege-guard bypass, secret leakage into
  the terminal/log/JSON, or a crafted change that renders as a lower severity than it is.
- Out of scope: `since` is **not** an EDR/antivirus. Best-effort malicious-pattern
  matching (e.g. `curl | sh`) is intentionally incomplete and not a security boundary;
  gaps there are enhancements, not vulnerabilities. Requiring `sudo` for full listener
  visibility is by design (see `since caps`).
- Snapshots contain sensitive host data and are stored `0600` in `~/.local/state/since`;
  protecting that directory is the user's responsibility.

## Threat model — what `since` can and cannot detect

`since` compares the machine against **its own earlier snapshots**, which live in
`~/.local/state/since` (mode `0700`/`0600`) and are owned by the user who runs it. Two
consequences follow, and neither is fixable from inside the tool:

- **A process running as you can tamper with the baseline.** It can rewrite, delete or
  pre-poison snapshots and the label file so that its own changes never show up as a diff
  — the same privilege that lets it install persistence lets it erase the record of having
  done so. `since` reports *changes to the system*; it does not attest to the integrity of
  its own history. For a baseline an attacker on the box cannot reach, copy snapshots off
  the machine (or keep them on append-only/read-only storage) and diff them there.
- **Helper binaries are resolved through `PATH`.** `lsof`, `ss`, `systemctl`, `codesign`,
  `brew` and friends are invoked by name, so an interactive run with a hostile `PATH` (say
  a fake `lsof` earlier in it) can filter the very output the report is built from. The
  installed daily job runs under launchd/systemd with a minimal `PATH` and is not exposed
  to a hostile shell environment.

Also by design: without `sudo` the listener/outbound view is partial and `/etc/sudoers` is
unreadable (`since caps` lists exactly what is and isn't covered), and snapshots taken at
different privilege levels are never compared for those categories.
