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
