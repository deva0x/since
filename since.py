#!/usr/bin/env python3
"""
since — a plain-language daily diff of your Mac.

One command that answers: "what's different about my computer since I last looked?"
It snapshots the things that quietly change under you — startup/background items,
listening network services, installed software, big new files, and sensitive system
files (shell config, hosts, cron) — and shows you the delta in human language.

Good for catching *both* malware persistence (a new LaunchAgent, a new listener, an
edited ~/.zshrc) *and* your own forgotten `brew install` from three weeks ago.

Usage:
    since                 diff live state against the most recent snapshot, then save
    since --since 1d      diff against the newest snapshot at least 1 day old
    since --no-save       peek without saving a new snapshot (good for re-running)
    since snapshot        just capture a snapshot (no diff) — put this in a daily job
    since list            list saved snapshots
    since --json          machine-readable diff
    since --help          full help

Zero dependencies: pure Python 3 stdlib + macOS system tools. No sudo required.
State lives in ~/.local/state/since/ (never in the repo).
"""

from __future__ import annotations

import argparse
import difflib
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCHEMA_VERSION = 2
HOME = Path.home()
STATE_DIR = Path(os.environ.get("SINCE_STATE_DIR", HOME / ".local/state/since"))
SNAP_DIR = STATE_DIR / "snapshots"
KEEP_SNAPSHOTS = 90  # prune older than this many

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=15):
    """Run a command, return stdout (str) or "" on any failure. Never raises."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
        )
        return p.stdout
    except Exception:
        return ""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


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
    days = hours / 24
    return f"about {round(days)} days"


# ---------------------------------------------------------------------------
# collectors — each returns a dict {stable_key: fingerprint_or_display}
# a change in the value for a key is reported as "changed"
# every collector is wrapped so one failure can't sink the snapshot
# ---------------------------------------------------------------------------

# Visible directories to skip when hunting for big new files. These are large,
# app-owned, and churn constantly — not what a person means by "a big new file
# appeared on my computer." (Hidden dotdirs are pruned separately, below, which
# covers .git/.cache/.colima/.npm/... and keeps the scan fast.)
BIGFILE_PRUNE = {
    "Library", "node_modules", "DerivedData",
    "Photos Library.photoslibrary", "Music Library.musiclibrary",
}

# Text files whose *contents* we track, so we can show exactly what line changed.
# These are the classic persistence / redirection spots.
def text_sources() -> dict[str, str]:
    out: dict[str, str] = {}

    def add(label, content):
        if content and content.strip():
            out[label] = content

    # shell startup files (user + system)
    rc_files = [
        HOME / ".zshrc", HOME / ".zprofile", HOME / ".zshenv",
        HOME / ".bashrc", HOME / ".bash_profile", HOME / ".profile",
        HOME / ".config/fish/config.fish",
        Path("/etc/zshrc"), Path("/etc/zprofile"), Path("/etc/profile"),
        Path("/etc/bashrc"),
    ]
    for p in rc_files:
        try:
            if p.is_file():
                add(str(p).replace(str(HOME), "~"), p.read_text("utf-8", "replace"))
        except Exception:
            pass

    # /etc/hosts — DNS overrides / redirects
    try:
        add("/etc/hosts", Path("/etc/hosts").read_text("utf-8", "replace"))
    except Exception:
        pass

    # cron: user crontab + system cron
    add("crontab (current user)", run(["crontab", "-l"]))
    try:
        if Path("/etc/crontab").is_file():
            add("/etc/crontab", Path("/etc/crontab").read_text("utf-8", "replace"))
    except Exception:
        pass
    for f in sorted(glob.glob("/etc/cron.d/*")):
        try:
            add(f, Path(f).read_text("utf-8", "replace"))
        except Exception:
            pass

    return out


def collect_login_items() -> dict[str, str]:
    """Modern 'Open at Login' items via System Events."""
    out = run([
        "osascript", "-e",
        'tell application "System Events" to get the name of every login item',
    ])
    items = [x.strip() for x in out.split(",") if x.strip()]
    return {name: name for name in items}


def collect_launch_items() -> dict[str, str]:
    """LaunchAgents/LaunchDaemons plists (user + third-party system).

    Fingerprint = size:mtime so we catch a *modified* plist, not just a new one.
    We deliberately skip /System/... (Apple-signed, read-only, noise).
    """
    dirs = [
        HOME / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    out: dict[str, str] = {}
    for d in dirs:
        try:
            for p in sorted(d.glob("*.plist")):
                st = p.stat()
                key = str(p).replace(str(HOME), "~")
                out[key] = f"{st.st_size}:{int(st.st_mtime)}"
        except Exception:
            pass
    return out


PORT_RE = re.compile(r":(\d+)\s*\(LISTEN\)")

def collect_listening() -> dict[str, str]:
    """Processes listening on TCP, keyed by command name (not port).

    Keying by command avoids the huge daily churn from daemons like rapportd
    that bind random high ports every boot. A genuinely NEW listening process
    is the signal we care about; the value records which ports it holds.
    """
    out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    by_cmd: dict[str, set] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        cmd = parts[0]
        m = PORT_RE.search(line)
        port = m.group(1) if m else "?"
        by_cmd.setdefault(cmd, set()).add(port)
    return {
        cmd: ",".join(sorted(ports, key=lambda x: (len(x), x)))
        for cmd, ports in by_cmd.items()
    }


def collect_brew() -> dict[str, str]:
    out = run(["brew", "list", "--versions"], timeout=30)
    res: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if parts:
            res[parts[0]] = parts[-1] if len(parts) > 1 else ""
    return res


def collect_npm_global() -> dict[str, str]:
    out = run(["npm", "ls", "-g", "--depth=0", "--json"], timeout=20)
    if not out.strip():
        return {}
    try:
        data = json.loads(out)
        deps = data.get("dependencies", {}) or {}
        return {name: (v or {}).get("version", "") for name, v in deps.items()}
    except Exception:
        return {}


def collect_applications() -> dict[str, str]:
    out: dict[str, str] = {}
    for base in ("/Applications", str(HOME / "Applications")):
        try:
            for entry in sorted(os.listdir(base)):
                if entry.endswith(".app"):
                    out[entry[:-4]] = base
        except Exception:
            pass
    return out


def collect_system_extensions() -> dict[str, str]:
    """Third-party system extensions (network filters, endpoint security, etc.)."""
    out = run(["systemextensionsctl", "list"])
    res: dict[str, str] = {}
    for line in out.splitlines():
        # rows contain a bundle id like com.vendor.thing and a state in [brackets]
        m = re.search(r"(\b[a-z0-9]+(?:\.[a-z0-9-]+){2,}\b).*\[([^\]]+)\]", line, re.I)
        if m:
            res[m.group(1)] = m.group(2).strip()
    return res


# Registry of collectors. `sensitive` collectors surface first, under "Worth a look".
COLLECTORS = [
    # key,               fn,                       label,                    sensitive
    ("login_items",      collect_login_items,      "Login items",            True),
    ("launch_items",     collect_launch_items,     "Startup/background jobs", True),
    ("listening",        collect_listening,        "Listening network services", True),
    ("system_extensions", collect_system_extensions, "System extensions",    True),
    ("brew",             collect_brew,             "Homebrew packages",      False),
    ("npm_global",       collect_npm_global,       "Global npm packages",    False),
    ("applications",     collect_applications,     "Applications",           False),
]
COLLECTOR_LABEL = {k: lbl for k, _, lbl, _ in COLLECTORS}
COLLECTOR_SENSITIVE = {k: s for k, _, _, s in COLLECTORS}


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------

def take_snapshot() -> dict:
    snap = {
        "schema": SCHEMA_VERSION,
        "created": datetime.now().isoformat(timespec="seconds"),
        "epoch": int(time.time()),
        "host": run(["scutil", "--get", "ComputerName"]).strip() or os.uname().nodename,
        "collectors": {},
        "blobs": {},
        "errors": {},
    }
    for key, fn, _label, _sens in COLLECTORS:
        try:
            snap["collectors"][key] = fn()
        except Exception as e:  # pragma: no cover - defensive
            snap["collectors"][key] = {}
            snap["errors"][key] = str(e)
    try:
        snap["blobs"] = text_sources()
    except Exception as e:  # pragma: no cover
        snap["errors"]["blobs"] = str(e)
    return snap


def save_snapshot(snap: dict) -> Path:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    # filename sorts chronologically; epoch guarantees uniqueness within a second run
    name = f"{datetime.fromtimestamp(snap['epoch']):%Y%m%dT%H%M%S}-{snap['epoch']}.json"
    path = SNAP_DIR / name
    path.write_text(json.dumps(snap, indent=1))
    try:
        path.chmod(0o600)  # snapshots describe your machine; keep them private
    except Exception:
        pass
    prune_snapshots()
    return path


def prune_snapshots():
    snaps = list_snapshot_paths()
    for p in snaps[:-KEEP_SNAPSHOTS] if len(snaps) > KEEP_SNAPSHOTS else []:
        try:
            p.unlink()
        except Exception:
            pass


def list_snapshot_paths() -> list[Path]:
    if not SNAP_DIR.is_dir():
        return []
    return sorted(SNAP_DIR.glob("*.json"))


def load_snapshot(path: Path) -> dict:
    return json.loads(path.read_text())


def parse_duration(s: str) -> int:
    """'1d' '12h' '30m' '90s' 'yesterday' -> seconds."""
    s = s.strip().lower()
    if s in ("yesterday", "1day", "day"):
        return 86400
    m = re.fullmatch(r"(\d+)\s*([smhdw])", s)
    if not m:
        raise ValueError(f"can't understand duration '{s}' (try 1d, 12h, 30m, 7d)")
    n = int(m.group(1))
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def pick_baseline(snaps: list[Path], min_age_seconds: int | None) -> Path | None:
    """Newest snapshot at least min_age_seconds old; else newest available."""
    if not snaps:
        return None
    if min_age_seconds is None:
        return snaps[-1]
    cutoff = time.time() - min_age_seconds
    older = [p for p in snaps if load_snapshot(p).get("epoch", 0) <= cutoff]
    return older[-1] if older else snaps[0]


# ---------------------------------------------------------------------------
# big new files — computed live against the baseline's timestamp
# ---------------------------------------------------------------------------

def find_big_new_files(since_epoch: int, min_mb: int = 25, top: int = 15) -> list[tuple[int, str]]:
    # Prune hidden dotdirs/files (.git, .cache, .colima, LLM transcripts, …) and a
    # short list of visible app-data dirs. Hidden pruning is what keeps this fast
    # and focused on files a person would recognize as "theirs."
    prune_args: list[str] = ["-name", ".?*", "-prune", "-o"]
    for name in BIGFILE_PRUNE:
        prune_args += ["-name", name, "-prune", "-o"]
    # Use a reference file stamped to the baseline time + `-newer`. This is
    # portable across BSD find (macOS) and GNU find; the GNU-only `-newermt
    # @epoch` form is rejected by BSD find ("Can't parse date/time").
    ref = None
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        ref = STATE_DIR / ".bigfile_ref"
        ref.touch()
        os.utime(ref, (since_epoch, since_epoch))
    except Exception:
        return []
    cmd = (
        ["find", str(HOME)]
        + prune_args
        + ["-type", "f", "-size", f"+{min_mb}M", "-newer", str(ref), "-print0"]
    )
    out = run(cmd, timeout=25)
    try:
        ref.unlink()
    except Exception:
        pass
    results: list[tuple[int, str]] = []
    for path in out.split("\0"):
        if not path:
            continue
        # skip our own state dir
        if str(STATE_DIR) in path:
            continue
        try:
            results.append((os.path.getsize(path), path.replace(str(HOME), "~")))
        except Exception:
            pass
    results.sort(reverse=True)
    return results[:top]


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def diff_dicts(base: dict, cur: dict):
    b, c = set(base), set(cur)
    added = sorted(c - b)
    removed = sorted(b - c)
    changed = sorted(k for k in (b & c) if base[k] != cur[k])
    return added, removed, changed


def build_diff(baseline: dict, current: dict) -> dict:
    result = {"collectors": {}, "blobs": {}}
    for key, _fn, _label, _sens in COLLECTORS:
        base = baseline.get("collectors", {}).get(key, {})
        cur = current.get("collectors", {}).get(key, {})
        added, removed, changed = diff_dicts(base, cur)
        if added or removed or changed:
            result["collectors"][key] = {
                "added": {k: cur[k] for k in added},
                "removed": {k: base[k] for k in removed},
                "changed": {k: (base[k], cur[k]) for k in changed},
            }
    # text blobs: added / removed / changed with a real line diff
    bbase, bcur = baseline.get("blobs", {}), current.get("blobs", {})
    for key in sorted(set(bbase) | set(bcur)):
        ob, oc = bbase.get(key), bcur.get(key)
        if ob == oc:
            continue
        entry = {"status": "added" if ob is None else "removed" if oc is None else "changed"}
        udiff = list(difflib.unified_diff(
            (ob or "").splitlines(), (oc or "").splitlines(),
            lineterm="", n=0,
        ))
        entry["diff"] = udiff[2:]  # drop the +++/--- header lines
        result["blobs"][key] = entry
    return result


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"

def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def paint(s, code):
    return f"{code}{s}{C_RESET}" if _color_enabled() else s


def render(diff: dict, baseline: dict, current: dict, big_files: list) -> str:
    L: list[str] = []
    base_dt = datetime.fromisoformat(baseline["created"])
    cur_dt = datetime.fromisoformat(current["created"])
    span = human_duration(current["epoch"] - baseline["epoch"])

    L.append(paint("since — what changed on this Mac", C_BOLD))
    L.append(paint(
        f"baseline {base_dt:%a %d %b %H:%M}  →  now {cur_dt:%a %d %b %H:%M}   ({span})",
        C_DIM,
    ))
    L.append("")

    # ---- Worth a look: sensitive additions/changes ----
    alerts: list[str] = []
    for key in [k for k in diff["collectors"] if COLLECTOR_SENSITIVE.get(k)]:
        d = diff["collectors"][key]
        label = COLLECTOR_LABEL[key]
        for k, v in d["added"].items():
            detail = _describe_add(key, k, v)
            alerts.append(f"NEW {label.lower()}: {detail}")
        for k, (ov, nv) in d["changed"].items():
            # Port churn on an already-known daemon (rapportd et al. rebind random
            # high ports every boot) is benign noise, not a signal. Skip it.
            if key == "listening":
                continue
            alerts.append(f"CHANGED {label.lower()}: {_short(k)} {paint(f'({ov} → {nv})', C_DIM)}")
    for key, entry in diff["blobs"].items():
        if entry["status"] == "added":
            alerts.append(f"NEW system file tracked: {key}")
        elif entry["status"] == "changed":
            alerts.append(f"EDITED: {key}")

    if alerts:
        L.append(paint("⚠  Worth a look", C_YELLOW + C_BOLD))
        for a in alerts:
            L.append("   • " + a)
        L.append("")

    # ---- system file diffs (show the actual lines) ----
    if diff["blobs"]:
        L.append(paint("System files", C_CYAN + C_BOLD))
        for key, entry in diff["blobs"].items():
            tag = {"added": "now tracked", "removed": "gone", "changed": "edited"}[entry["status"]]
            L.append(f"   {key} ({tag})")
            for line in entry["diff"][:20]:
                if line.startswith("+"):
                    L.append("      " + paint(line, C_GREEN))
                elif line.startswith("-"):
                    L.append("      " + paint(line, C_RED))
                elif line.startswith("@@"):
                    L.append("      " + paint(line, C_DIM))
            if len(entry["diff"]) > 20:
                L.append(paint(f"      … {len(entry['diff']) - 20} more changed lines", C_DIM))
        L.append("")

    # ---- other sensitive removals (lower urgency) ----
    # ---- informational sections ----
    for key, _fn, label, sensitive in COLLECTORS:
        if key not in diff["collectors"]:
            continue
        d = diff["collectors"][key]
        # sensitive adds/changes already shown as alerts; here show the rest
        add = d["added"]
        rem = d["removed"]
        chg = d["changed"]
        if sensitive:
            # only removals remain to report for sensitive categories
            if not rem:
                continue
            L.append(paint(label, C_CYAN + C_BOLD))
            for k, v in rem.items():
                L.append("   " + paint("- ", C_RED) + _describe_add(key, k, v))
            L.append("")
            continue
        # informational category (brew, npm, apps)
        if not (add or rem or chg):
            continue
        L.append(paint(label, C_CYAN + C_BOLD))
        if add:
            for k, v in list(add.items())[:40]:
                L.append("   " + paint("+ installed  ", C_GREEN) + _pkg(key, k, v))
            if len(add) > 40:
                L.append(paint(f"   … +{len(add) - 40} more", C_DIM))
        if chg:
            for k, (ov, nv) in list(chg.items())[:40]:
                L.append("   " + paint("~ changed    ", C_YELLOW) + f"{k} {paint(f'{ov} → {nv}', C_DIM)}")
        if rem:
            for k, v in list(rem.items())[:40]:
                L.append("   " + paint("- removed    ", C_RED) + _pkg(key, k, v))
        L.append("")

    # ---- big new files ----
    if big_files:
        L.append(paint("Big new files", C_CYAN + C_BOLD))
        for size, path in big_files:
            L.append(f"   {human_size(size):>9}  {path}")
        L.append(paint("   (visible folders only — hidden/app-data dirs like ~/Library are skipped)", C_DIM))
        L.append("")

    if len(L) <= 3:  # only the header
        L.append(paint("Nothing changed. 🎉", C_GREEN))
        L.append("")

    return "\n".join(L).rstrip() + "\n"


def _short(k: str) -> str:
    return k.replace(str(HOME), "~")

def _describe_add(collector: str, key: str, value) -> str:
    if collector == "listening":
        return f"{paint(key, C_BOLD)} listening on port(s) {value}"
    if collector == "launch_items":
        return paint(_short(key), C_BOLD)
    return paint(_short(key), C_BOLD)

def _pkg(collector: str, key: str, value) -> str:
    if collector in ("brew", "npm_global"):
        return f"{key} {value}".strip()
    return key


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def cmd_snapshot(args):
    snap = take_snapshot()
    path = save_snapshot(snap)
    n = sum(len(v) for v in snap["collectors"].values())
    print(f"Snapshot saved: {path.name}  ({n} items across {len(snap['collectors'])} categories)")
    if snap["errors"]:
        print(paint(f"  note: {len(snap['errors'])} collector(s) had issues: "
                    + ", ".join(snap['errors']), C_DIM))


def cmd_list(args):
    snaps = list_snapshot_paths()
    if not snaps:
        print("No snapshots yet. Run `since snapshot` (or just `since`) to make one.")
        return
    print(f"{len(snaps)} snapshot(s) in {SNAP_DIR}:")
    for p in snaps:
        s = load_snapshot(p)
        n = sum(len(v) for v in s.get("collectors", {}).values())
        print(f"  {s.get('created', '?'):20}  {n:>4} items  {p.name}")


def cmd_diff(args):
    min_age = parse_duration(args.since) if args.since else None
    snaps = list_snapshot_paths()
    baseline_path = pick_baseline(snaps, min_age)

    current = take_snapshot()

    if baseline_path is None:
        # first ever run
        if not args.no_save:
            path = save_snapshot(current)
            print(paint("First snapshot saved — this is your baseline.", C_BOLD))
            print(f"  {path}")
            print("\nRun `since` again later (after installing something, or tomorrow)")
            print("to see what changed. Tip: add `since snapshot` to a daily job.")
        else:
            print("No baseline yet and --no-save given; nothing to compare.")
        return

    baseline = load_snapshot(baseline_path)
    diff = build_diff(baseline, current)
    big = find_big_new_files(baseline.get("epoch", current["epoch"]))

    if args.json:
        print(json.dumps({
            "baseline": baseline["created"],
            "now": current["created"],
            "diff": diff,
            "big_new_files": [{"size": s, "path": p} for s, p in big],
        }, indent=2))
    else:
        sys.stdout.write(render(diff, baseline, current, big))

    if not args.no_save:
        save_snapshot(current)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="since",
        description="A plain-language daily diff of your Mac — startup items, listening "
                    "services, packages, big new files, and sensitive system files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("snapshot", help="capture a snapshot without diffing (for a daily job)")
    sub.add_parser("list", help="list saved snapshots")

    # default (diff) options live on the top-level parser too
    for p in (ap,):
        p.add_argument("--since", metavar="AGE",
                       help="compare against the newest snapshot at least this old (e.g. 1d, 12h, 7d)")
        p.add_argument("--no-save", action="store_true",
                       help="don't save a new snapshot after diffing")
        p.add_argument("--json", action="store_true", help="machine-readable output")

    args = ap.parse_args(argv)
    if args.cmd == "snapshot":
        return cmd_snapshot(args)
    if args.cmd == "list":
        return cmd_list(args)
    return cmd_diff(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
