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
    since --json          machine-readable diff   |   since --all  include quiet churn

Zero dependencies: pure Python 3 stdlib + OS tools. No sudo required.
State lives in ~/.local/state/since/ (mode 600, never in the repo).

macOS is fully supported today. The collector layer is platform-abstracted; Linux
backends are stubs pending verification on a real Linux box (see PENDING.md).
"""

from __future__ import annotations

import argparse
import difflib
import fnmatch
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

SCHEMA_VERSION = 3
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
    return p.replace(str(HOME), "~")


# ---------------------------------------------------------------------------
# trust / signing (macOS) — used to enrich findings at diff time, not per snapshot
# ---------------------------------------------------------------------------

def trust_of(path: str):
    """Return (label, suspicious) for a binary/app path. Best-effort, macOS."""
    if PLATFORM != "macos" or not path or not os.path.exists(path):
        return (None, False)
    info = run(["codesign", "-dv", "--verbose=2", path], merge=True, timeout=10)
    low = info.lower()
    if "not signed" in low or "code object is not signed" in low:
        return ("unsigned", True)
    authorities = [l.split("=", 1)[1].strip() for l in info.splitlines() if l.startswith("Authority=")]
    if not authorities and ("adhoc" in low or "linker-signed" in low):
        return ("ad-hoc signed", True)
    if any("Apple" in a for a in authorities):
        return ("Apple-signed", False)
    if any("Developer ID" in a for a in authorities):
        acc = run(["spctl", "-a", "-vv", path], merge=True, timeout=10).lower()
        return ("Developer ID" + (", notarized" if "notarized" in acc else ""), False)
    if authorities:
        return (f"signed ({authorities[0][:24]})", False)
    return ("unknown", False)


def program_of_plist(plist_path: str):
    """Extract the executable a launchd plist runs, so we can trust-check it."""
    real = plist_path.replace("~", str(HOME), 1) if plist_path.startswith("~") else plist_path
    out = run(["plutil", "-convert", "json", "-o", "-", real], timeout=8)
    try:
        d = json.loads(out)
    except Exception:
        return None
    if isinstance(d.get("Program"), str):
        return d["Program"]
    args = d.get("ProgramArguments")
    if isinstance(args, list) and args:
        return args[0]
    return None


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
            lines = p.read_text("utf-8", "replace").splitlines()[-6000:]
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
    t = term.lower()
    for cmd in reversed(load_history()):
        cl = cmd.lower()
        if t in cl and any(v in cl for v in ("install", "add", "brew", "npm", "pip", "-g", "cask", "get")):
            return cmd.strip()[:80]
    return None


# ---------------------------------------------------------------------------
# collectors — common category names, per-platform backends feed a common schema.
# each returns {stable_key: fingerprint/display}. Linux backends are deferred stubs.
# ---------------------------------------------------------------------------

def _mac_login_items():
    out = run(["osascript", "-e",
               'tell application "System Events" to get the name of every login item'])
    return {x.strip(): x.strip() for x in out.split(",") if x.strip()}


def _mac_launch_items():
    dirs = [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons")]
    out = {}
    for d in dirs:
        try:
            for p in sorted(d.glob("*.plist")):
                st = p.stat()
                out[tilde(str(p))] = f"{st.st_size}:{int(st.st_mtime)}"
        except Exception:
            pass
    return out


def _mac_kexts():
    out = run(["kextstat", "-l"], timeout=10)
    res = {}
    for line in out.splitlines():
        m = re.search(r"\b((?:com|org|net|io)\.[\w.-]+)\s*\(([^)]*)\)", line)
        if m and not m.group(1).startswith("com.apple"):
            res[m.group(1)] = m.group(2)
    return res


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
            mans = sorted(glob.glob(os.path.join(ext_dir, "*/manifest.json")))
            if mans:
                try:
                    man = json.loads(Path(mans[-1]).read_text("utf-8", "replace"))
                    n = man.get("name", "")
                    if n and not n.startswith("__MSG_"):
                        name = n
                except Exception:
                    pass
            browser = base.name
            res[f"{browser}:{ext_id}"] = name
    # Firefox
    for ext in glob.glob(str(HOME / "Library/Application Support/Firefox/Profiles/*/extensions/*")):
        res[f"Firefox:{os.path.basename(ext)}"] = os.path.basename(ext)
    return res


def _mac_system_extensions():
    out = run(["systemextensionsctl", "list"])
    res = {}
    for line in out.splitlines():
        m = re.search(r"(\b[a-z0-9]+(?:\.[a-z0-9-]+){2,}\b).*\[([^\]]+)\]", line, re.I)
        if m:
            res[m.group(1)] = m.group(2).strip()
    return res


PORT_RE = re.compile(r":(\d+)\s*\(LISTEN\)")

def _listening():
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    by_cmd: dict[str, set] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        m = PORT_RE.search(line)
        by_cmd.setdefault(parts[0], set()).add(m.group(1) if m else "?")
    return {c: ",".join(sorted(p, key=lambda x: (len(x), x))) for c, p in by_cmd.items()}


def _outbound():
    """Processes with an established outbound TCP connection (churny — quiet tier)."""
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"])
    cmds = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts:
            cmds.add(parts[0])
    return {c: "connected" for c in sorted(cmds)}


def _mac_net_config():
    res = {}
    for line in run(["scutil", "--dns"]).splitlines():
        m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
        if m:
            res[f"DNS {m.group(1)}"] = "nameserver"
    proxy = run(["scutil", "--proxy"])
    for key, label in (("HTTPEnable", "HTTP proxy"), ("HTTPSEnable", "HTTPS proxy"),
                       ("SOCKSEnable", "SOCKS proxy"), ("ProxyAutoConfigEnable", "auto-proxy (PAC)")):
        m = re.search(rf"{key}\s*:\s*(\d)", proxy)
        if m and m.group(1) == "1":
            res[label] = "enabled"
    return res


def _mac_brew():
    res = {}
    for line in run(["brew", "list", "--versions"], timeout=40).splitlines():
        parts = line.split()
        if parts:
            res[parts[0]] = parts[-1] if len(parts) > 1 else ""
    return res


def _npm_global():
    out = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=25)
    if not out.strip():
        return {}
    try:
        deps = json.loads(out).get("dependencies", {}) or {}
        return {n: (v or {}).get("version", "") for n, v in deps.items()}
    except Exception:
        return {}


def _pip():
    out = run(["pip3", "list", "--format=freeze"], timeout=25)
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
                    res[entry[:-4]] = base
        except Exception:
            pass
    return res


def _mac_mas():
    out = run(["mas", "list"], timeout=15)
    res = {}
    for line in out.splitlines():
        m = re.match(r"(\d+)\s+(.*?)\s+\(([^)]+)\)\s*$", line)
        if m:
            res[m.group(2).strip()] = m.group(3)
    return res


# Category registry. Each: key, label, per-platform backend, class, tier.
#   cls: "persistence" | "network" | "software" | "config-fact"
#   tier: "loud" (ranked in the digest) | "inventory" | "quiet" (only with --all)
CATEGORIES = [
    # key,               label,                       macos,                    linux, cls,            tier
    ("login_items",      "Login items",               _mac_login_items,         None,  "persistence",  "loud"),
    ("launch_items",     "Startup/background jobs",    _mac_launch_items,        None,  "persistence",  "loud"),
    ("kernel_extensions","Kernel extensions",          _mac_kexts,               None,  "persistence",  "loud"),
    ("browser_extensions","Browser extensions",        _mac_browser_extensions,  None,  "persistence",  "loud"),
    ("system_extensions","System extensions",          _mac_system_extensions,   None,  "persistence",  "loud"),
    ("listening",        "Listening network services", _listening,               None,  "network",      "loud"),
    ("net_config",       "DNS / proxy settings",       _mac_net_config,          None,  "network",      "loud"),
    ("outbound",         "Outbound connections",       _outbound,                None,  "network",      "quiet"),
    ("brew",             "Homebrew packages",          _mac_brew,                None,  "software",     "inventory"),
    ("npm_global",       "Global npm packages",        _npm_global,              None,  "software",     "inventory"),
    ("pip",              "pip packages",               _pip,                     None,  "software",     "inventory"),
    ("applications",     "Applications",               _mac_applications,        None,  "software",     "inventory"),
    ("mac_app_store",    "Mac App Store apps",         _mac_mas,                 None,  "software",     "inventory"),
]
CAT = {c[0]: {"label": c[1], "cls": c[4], "tier": c[5]} for c in CATEGORIES}


def backend_for(cat_key: str):
    for key, _lbl, mac, lin, _cls, _tier in CATEGORIES:
        if key == cat_key:
            return mac if PLATFORM == "macos" else lin
    return None


# text files whose *contents* we track, so we can show the exact line that changed
def text_sources() -> dict[str, str]:
    out: dict[str, str] = {}

    def add(label, content):
        if content and content.strip():
            out[label] = content

    if PLATFORM == "macos":
        rc = [HOME / ".zshrc", HOME / ".zprofile", HOME / ".zshenv", HOME / ".bashrc",
              HOME / ".bash_profile", HOME / ".profile", HOME / ".config/fish/config.fish",
              Path("/etc/zshrc"), Path("/etc/zprofile"), Path("/etc/profile"),
              Path("/etc/bashrc"), Path("/etc/sudoers"), Path("/etc/ssh/sshd_config"),
              HOME / ".ssh/config", HOME / ".ssh/authorized_keys", HOME / ".gitconfig",
              HOME / ".npmrc", HOME / ".curlrc", HOME / ".wgetrc"]
    else:  # deferred; harmless on macOS
        rc = [HOME / ".bashrc", HOME / ".profile", Path("/etc/hosts")]
    for p in rc:
        try:
            if p.is_file():
                add(tilde(str(p)), p.read_text("utf-8", "replace"))
        except Exception:
            pass

    try:
        add("/etc/hosts", Path("/etc/hosts").read_text("utf-8", "replace"))
    except Exception:
        pass

    add("crontab (current user)", run(["crontab", "-l"]))
    for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        try:
            if Path(f).is_file():
                add(f, Path(f).read_text("utf-8", "replace"))
        except Exception:
            pass
    return out


# system files whose edits are high-severity, and content that screams "malicious"
SENSITIVE_TEXT = ("/etc/hosts", "/etc/sudoers", "sshd_config", "authorized_keys", "crontab")
MALICIOUS_PATTERNS = [
    (re.compile(r"curl[^\n|]*\|\s*(ba)?sh", re.I), "pipes a download straight into a shell"),
    (re.compile(r"wget[^\n|]*\|\s*(ba)?sh", re.I), "pipes a download straight into a shell"),
    (re.compile(r"\bbase64\b\s+-d.*\|\s*(ba)?sh", re.I), "decodes base64 and runs it"),
    (re.compile(r"\bnc\b.*-e\b", re.I), "netcat reverse shell"),
    (re.compile(r"^\s*0\.0\.0\.0\s+\S*[a-z]", re.I | re.M), "redirects a real domain (hosts)"),
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
        "host": (run(["scutil", "--get", "ComputerName"]).strip()
                 if PLATFORM == "macos" else os.uname().nodename),
        "collectors": {},
        "blobs": {},
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
        snap["blobs"] = text_sources()
    except Exception as e:
        snap["errors"]["blobs"] = str(e)
    return snap


def save_snapshot(snap: dict, label: str | None = None) -> Path:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{datetime.fromtimestamp(snap['epoch']):%Y%m%dT%H%M%S}-{snap['epoch']}.json"
    path = SNAP_DIR / name
    path.write_text(json.dumps(snap, indent=1))
    try:
        path.chmod(0o600)
    except Exception:
        pass
    if label:
        labels = load_labels()
        labels[label] = name
        LABELS_FILE.write_text(json.dumps(labels, indent=1))
    prune_snapshots()
    return path


def load_labels() -> dict:
    try:
        return json.loads(LABELS_FILE.read_text())
    except Exception:
        return {}


def prune_snapshots():
    snaps = list_snapshot_paths()
    protected = set(load_labels().values())
    prunable = [p for p in snaps if p.name not in protected]
    for p in prunable[:-KEEP_SNAPSHOTS] if len(prunable) > KEEP_SNAPSHOTS else []:
        try:
            p.unlink()
        except Exception:
            pass


def list_snapshot_paths() -> list[Path]:
    return sorted(SNAP_DIR.glob("*.json")) if SNAP_DIR.is_dir() else []


def load_snapshot(path: Path) -> dict:
    return json.loads(path.read_text())


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
            return int((now - timedelta(seconds=n * unit)).timestamp())
    raise ValueError(f"can't understand time '{s}' (try 1d, 12h, yesterday, monday, '3 hours ago')")


# backwards-compatible: duration string -> seconds of age
def parse_duration(s: str) -> int:
    return int(time.time()) - parse_when(s)


def resolve_baseline(arg: str | None) -> tuple[Path | None, str]:
    """Return (baseline_path, note). arg may be a label or a time expression."""
    snaps = list_snapshot_paths()
    if not snaps:
        return None, ""
    if arg:
        labels = load_labels()
        if arg in labels:
            p = SNAP_DIR / labels[arg]
            return (p if p.exists() else snaps[-1]), f"checkpoint '{arg}'"
        cutoff = parse_when(arg)
        older = [p for p in snaps if load_snapshot(p).get("epoch", 0) <= cutoff]
        if older:
            return older[-1], ""
        return snaps[0], "(no snapshot that old — using the oldest available)"
    return snaps[-1], ""


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
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        ref = STATE_DIR / ".bigfile_ref"
        ref.touch()
        os.utime(ref, (since_epoch, since_epoch))
    except Exception:
        return [], []
    cmd = (["find", str(HOME)] + prune
           + ["-type", "f", "-size", f"+{min_mb}M", "-newer", str(ref), "-print0"])
    out = run(cmd, timeout=25)
    try:
        ref.unlink()
    except Exception:
        pass
    files = []
    for path in out.split("\0"):
        if not path or str(STATE_DIR) in path:
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
    return files[:top], growing


# ---------------------------------------------------------------------------
# ignore rules
# ---------------------------------------------------------------------------

def load_ignores() -> list[tuple[str, str]]:
    rules = []
    try:
        for line in IGNORE_FILE.read_text().splitlines():
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
    real = key.replace("~", str(HOME), 1) if key.startswith("~") else key
    if category == "launch_items":
        return f"launchctl bootout gui/$UID '{real}' 2>/dev/null; rm '{real}'"
    if category == "login_items":
        return f"osascript -e 'tell application \"System Events\" to delete login item \"{key}\"'"
    if category == "brew":
        return f"brew uninstall {key}"
    if category == "npm_global":
        return f"npm rm -g {key}"
    if category == "pip":
        return f"pip3 uninstall {key}"
    if category == "browser_extensions":
        return "remove it from your browser's Extensions page"
    if category == "kernel_extensions":
        return f"sudo kmutil unload -b {key}   # then reboot"
    if category == "system_extensions":
        return "remove the owning app, or: systemextensionsctl uninstall <team> " + key
    return None


def build_findings(baseline: dict, current: dict, include_quiet=False) -> list[dict]:
    rules = load_ignores()
    findings: list[dict] = []
    for key, meta in CAT.items():
        if meta["tier"] == "quiet" and not include_quiet:
            continue
        base = baseline.get("collectors", {}).get(key, {})
        cur = current.get("collectors", {}).get(key, {})
        added, removed, changed = diff_dicts(base, cur)
        for action, items in (("added", {k: cur[k] for k in added}),
                              ("removed", {k: base[k] for k in removed}),
                              ("changed", {k: (base[k], cur[k]) for k in changed})):
            for k, v in items.items():
                if is_ignored(key, k, rules):
                    continue
                # port-set churn on an already-known listener is benign noise
                if key == "listening" and action == "changed":
                    continue
                f = {"category": key, "label": meta["label"], "cls": meta["cls"],
                     "action": action, "key": k, "value": v,
                     "level": base_level(meta["cls"], action), "trust": None,
                     "why": None, "undo": None}
                _enrich(f, current)
                findings.append(f)
    # text blobs (system files)
    bb, bc = baseline.get("blobs", {}), current.get("blobs", {})
    for key in sorted(set(bb) | set(bc)):
        ob, oc = bb.get(key), bc.get(key)
        if ob == oc:
            continue
        if is_ignored("config", key, rules):
            continue
        status = "added" if ob is None else "removed" if oc is None else "changed"
        udiff = list(difflib.unified_diff((ob or "").splitlines(), (oc or "").splitlines(),
                                          lineterm="", n=0))[2:]
        level = ORANGE if status == "changed" else YELLOW
        if any(s in key for s in SENSITIVE_TEXT):
            level = max(level, ORANGE)
        why = None
        added_text = "\n".join(l[1:] for l in udiff if l.startswith("+"))
        for pat, desc in MALICIOUS_PATTERNS:
            if pat.search(added_text):
                level, why = RED, desc
                break
        findings.append({"category": "config", "label": "System files", "cls": "config",
                         "action": status, "key": key, "value": None, "level": level,
                         "trust": None, "why": why, "undo": None, "diff": udiff})
    findings.sort(key=lambda f: (-f["level"], f["category"], f["key"]))
    return findings


def _enrich(f: dict, current: dict):
    cat, action, key = f["category"], f["action"], f["key"]
    # signing/trust for new persistence programs & apps
    if action == "added":
        prog = None
        if cat == "launch_items":
            prog = program_of_plist(key)
        elif cat == "applications":
            prog = f"{f['value']}/{key}.app"
        if prog:
            label, suspicious = trust_of(prog)
            f["trust"] = label
            if suspicious:
                f["level"] = RED
    # attribution for software installs
    if cat in ("brew", "npm_global", "pip", "applications", "mac_app_store") and action == "added":
        f["why"] = attribution_for(key)
    # undo hints for anything reversible we added
    if action == "added":
        f["undo"] = undo_hint(cat, key, f["value"])


# thin wrapper kept for the older test harness
def build_diff(baseline: dict, current: dict) -> dict:
    result = {"collectors": {}, "blobs": {}}
    for key in CAT:
        base = baseline.get("collectors", {}).get(key, {})
        cur = current.get("collectors", {}).get(key, {})
        a, r, c = diff_dicts(base, cur)
        if a or r or c:
            result["collectors"][key] = {"added": {k: cur[k] for k in a},
                                         "removed": {k: base[k] for k in r},
                                         "changed": {k: (base[k], cur[k]) for k in c}}
    bb, bc = baseline.get("blobs", {}), current.get("blobs", {})
    for key in sorted(set(bb) | set(bc)):
        ob, oc = bb.get(key), bc.get(key)
        if ob == oc:
            continue
        entry = {"status": "added" if ob is None else "removed" if oc is None else "changed"}
        entry["diff"] = list(difflib.unified_diff((ob or "").splitlines(),
                                                  (oc or "").splitlines(), lineterm="", n=0))[2:]
        result["blobs"][key] = entry
    return result


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
    cat, action, key, val = f["category"], f["action"], f["key"], f["value"]
    verb = {"added": "NEW", "removed": "removed", "changed": "changed"}[action]
    if cat == "listening" and action == "added":
        return f"{verb} listener: {paint(key, 'bold')} on port(s) {val}"
    if cat == "config":
        tag = {"added": "now tracked", "removed": "gone", "changed": "edited"}[action]
        return f"{key} ({tag})"
    if action == "changed" and isinstance(val, tuple):
        return f"{verb} {f['label'].lower()}: {tilde(key)} {paint(f'({val[0]} → {val[1]})', 'dim')}"
    return f"{verb} {f['label'].lower()}: {paint(tilde(key), 'bold')}"


def render(findings, baseline, current, big_files, growing, include_quiet=False) -> str:
    L: list[str] = []
    base_dt = datetime.fromisoformat(baseline["created"])
    cur_dt = datetime.fromisoformat(current["created"])
    span = human_duration(current["epoch"] - baseline["epoch"])
    L.append(paint("since — what changed on this computer", "bold"))
    L.append(paint(f"baseline {base_dt:%a %d %b %H:%M}  →  now {cur_dt:%a %d %b %H:%M}   ({span})", "dim"))

    loud = [f for f in findings if CAT.get(f["category"], {}).get("tier") == "loud"
            or f["category"] == "config"]
    inv = [f for f in findings if CAT.get(f["category"], {}).get("cls") == "software"]
    quiet = [f for f in findings if CAT.get(f["category"], {}).get("tier") == "quiet"]

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
                L.append("      " + paint(f"signature: {f['trust']}", tcol))
            if f.get("why"):
                L.append("      " + paint(f"why: {f['why']}", "dim"))
            if f["category"] == "config" and f.get("diff"):
                for line in f["diff"][:12]:
                    if line.startswith("+"):
                        L.append("      " + paint(line, "green"))
                    elif line.startswith("-"):
                        L.append("      " + paint(line, "red"))
                    elif line.startswith("@@"):
                        L.append("      " + paint(line, "dim"))
                if len(f["diff"]) > 12:
                    L.append(paint(f"      … {len(f['diff']) - 12} more changed lines", "dim"))
            if f.get("undo"):
                L.append("      " + paint(f"undo: {f['undo']}", "dim"))

    # ---- software inventory (compact) ----
    if inv:
        L.append("")
        L.append(paint("Software", "cyan"))
        for f in sorted(inv, key=lambda x: (x["category"], x["key"])):
            name = f"{f['key']} {f['value'][1] if f['action']=='changed' else ''}".strip()
            if f["action"] == "added":
                line = "  " + paint("+ installed  ", "green") + f["key"] + \
                       (f" {f['value']}" if f["category"] in ("brew", "npm_global", "pip") else "")
                if f.get("why"):
                    line += paint(f"   (from: {f['why']})", "dim")
                L.append(line)
            elif f["action"] == "changed" and isinstance(f["value"], tuple):
                L.append("  " + paint("~ updated    ", "yellow") + f"{f['key']} " +
                         paint(f"{f['value'][0]} → {f['value'][1]}", "dim"))
            else:
                L.append("  " + paint("- removed    ", "red") + f["key"])

    # ---- disk ----
    if big_files or growing:
        L.append("")
        L.append(paint("Disk — big new files", "cyan"))
        for size, path in big_files:
            L.append(f"  {human_size(size):>9}  {path}")
        if growing:
            L.append(paint("  fastest-growing folders:", "dim"))
            for size, d in growing:
                L.append(f"    +{human_size(size):>8}  {d}")
        L.append(paint("  (visible folders only — hidden/app-data dirs like ~/Library are skipped)", "dim"))

    if quiet:
        L.append("")
        L.append(paint("Outbound connections (noisy — shown because --all)", "cyan"))
        for f in quiet:
            v = "started connecting out" if f["action"] == "added" else "stopped"
            L.append(f"  {paint(LEVEL_DOT[GREEN],'dim')} {f['key']} {paint(v,'dim')}")

    if len(L) <= 2:
        L.append("")
        L.append(paint("Nothing changed. 🎉", "green"))
    return "\n".join(L).rstrip() + "\n"


def max_level(findings) -> int:
    return max((f["level"] for f in findings), default=GREEN)


def notify(title: str, message: str):
    if PLATFORM == "macos":
        msg = message.replace('"', "'")[:220]
        run(["osascript", "-e", f'display notification "{msg}" with title "{title}"'])


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
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(IGNORE_FILE, "a") as fh:
        fh.write(args.pattern.strip() + "\n")
    print(f"Ignoring: {args.pattern}")

def cmd_list(args):
    snaps = list_snapshot_paths()
    labels = {v: k for k, v in load_labels().items()}
    if not snaps:
        print("No snapshots yet. Run `since snapshot` (or just `since`).")
        return
    print(f"{len(snaps)} snapshot(s) in {SNAP_DIR}:")
    for p in snaps:
        s = load_snapshot(p)
        n = sum(len(v) for v in s.get("collectors", {}).values())
        lab = paint(f"  [{labels[p.name]}]", "cyan") if p.name in labels else ""
        print(f"  {s.get('created', '?'):20}  {n:>4} items  {p.name}{lab}")

def cmd_diff(args, notify_on=False):
    baseline_path, note = resolve_baseline(args.since)
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

    baseline = load_snapshot(baseline_path)
    findings = build_findings(baseline, current, include_quiet=args.all)
    big, growing = find_big_new_files(baseline.get("epoch", current["epoch"]))

    if args.json:
        print(json.dumps({
            "baseline": baseline["created"], "now": current["created"],
            "max_level": LEVEL_NAME[max_level(findings)],
            "findings": [{k: v for k, v in f.items() if k != "diff"} for f in findings],
            "big_new_files": [{"size": s, "path": p} for s, p in big],
            "growing_dirs": [{"bytes": s, "dir": d} for s, d in growing],
        }, indent=2))
    else:
        if note:
            print(paint(f"({note})", "dim"))
        sys.stdout.write(render(findings, baseline, current, big, growing, include_quiet=args.all))

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
        "ignore": cmd_ignore, "list": cmd_list, "digest": cmd_digest,
    }.get(args.cmd, cmd_diff)(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
