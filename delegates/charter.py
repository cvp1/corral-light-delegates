"""Charter files (plan §4.1): the grammar, the required keys, the box
binding, and signature verification with real `ssh-keygen`.

The collector reads a charter once and verifies and parses the same bytes.
"""
import json
import os
import re
import shlex
import shutil
import subprocess

from delegates import util

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,60}$")
KEY_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_LINE = re.compile(r"^([A-Za-z0-9_-]+):(?:[ \t]+(.*))?$")
UNDERSTOOD = ("name", "status", "approval", "issued", "expires", "box", "data-class",
              "capabilities", "tools", "budget-usd", "cost-box-usd-month", "cost-note",
              "created")
_CRED = re.compile(r"^credential-\d+-type$")
STATUSES = ("draft", "approved", "revoked")
DRAFT_APPROVALS = ("", "unsigned", "pending", "proposed", ">", "|")
DEFAULT_NAMESPACE = "corral-light-delegate-charter"
VERIFY_TIMEOUT_S = 5
CHARTER_CAP = 1 << 20
LOCAL = "local"            # the source id of this host's charters
DECLARED = "declared"      # the source id of boxes.toml


# ── grammar ────────────────────────────────────────────────────────────────

def _value(raw):
    raw = (raw or "").strip()
    if raw.startswith("["):
        if not raw.endswith("]"):
            return None, "unterminated list"
        inner = raw[1:-1].strip()
        if not inner:
            return [], None
        items = []
        for part in inner.split(","):
            v, err = _value(part)
            if err:
                return None, err
            if isinstance(v, list):
                return None, "nested list"
            items.append(v)
        return items, None
    if raw.startswith('"'):
        if len(raw) < 2 or not raw.endswith('"'):
            return None, "unterminated string"
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\"), None
    return raw, None


def parse(data):
    """Charter bytes -> {"keys", "other", "errors", "body"}. `errors` non-empty
    means `bad-charter`; every reason is listed. CRLF is read as LF for
    parsing only."""
    out = {"keys": {}, "other": {}, "errors": [], "body": ""}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        out["errors"].append("not UTF-8")
        return out
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        out["errors"].append("front matter must start at byte 0 with ---")
        return out
    rest = text[4:]
    if rest.startswith("---\n") or rest == "---":
        fm, body = "", rest[4:]
    else:
        end = rest.find("\n---\n")
        if end >= 0:
            fm, body = rest[:end], rest[end + 5:]
        elif rest.endswith("\n---"):
            fm, body = rest[:-4], ""
        else:
            out["errors"].append("front matter has no closing ---")
            return out
    out["body"] = body
    for line in fm.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _LINE.match(line.rstrip())
        if not m or not KEY_RE.match(m.group(1)):
            out["errors"].append(f"malformed key line: {s[:40]}")
            continue
        key = m.group(1).replace("_", "-")
        if key in out["keys"]:
            out["errors"].append(f"duplicate key {key}")
            continue
        v, err = _value(m.group(2))
        if err:
            out["errors"].append(f"{key}: {err}")
            continue
        out["keys"][key] = v
    for k, v in out["keys"].items():
        if k not in UNDERSTOOD and not _CRED.match(k):
            out["other"][k] = v
    return out


def box_ids(value, default_source):
    """A `box:` value -> ([qualified ids], error). A bare name is a box of
    `default_source`; `src/name` is explicit (plan §4.1)."""
    if value is None:
        return [], "box is missing"
    items = value if isinstance(value, list) else [value]
    out = []
    for it in items:
        if not isinstance(it, str) or not it.strip():
            return [], "box has an empty name"
        it = it.strip()
        if "/" in it:
            src, name = it.split("/", 1)
            if not SOURCE_ID_RE.match(src) or not NAME_RE.match(name):
                return [], f"box {it!r} is not <source-id>/<name>"
            q = f"{src}/{name}"
        else:
            if not NAME_RE.match(it):
                return [], f"box {it!r} is not a valid name"
            q = f"{default_source}/{it}"
        if q not in out:
            out.append(q)
    if not out:
        return [], "box lists nothing"
    return out, None


def approval_of(keys):
    """-> ('draft'|'approved'|'revoked', error). The more restrictive of
    `status` and `approval` wins (plan §2.1)."""
    st = keys.get("status")
    ap = keys.get("approval")
    if st is None and ap is None:
        return None, "neither status nor approval is present"
    levels = []
    if st is not None:
        if not isinstance(st, str) or st.strip().lower() not in STATUSES:
            return None, "status must be draft, approved or revoked"
        levels.append(st.strip().lower())
    if ap is not None:
        a = ap if isinstance(ap, str) else ""
        levels.append("draft" if a.strip().lower() in DRAFT_APPROVALS else "approved")
    rank = {"revoked": 0, "draft": 1, "approved": 2}
    return min(levels, key=lambda x: rank[x]), None


def check(parsed, stem, default_source=DECLARED):
    """Required keys, time bounds and the binding (plan §4.1, §2.5). Adds to
    parsed["errors"] and returns a dict of the derived fields."""
    keys = parsed["keys"]
    errs = parsed["errors"]
    d = {"name": None, "issued": None, "expires": None, "boxes": [], "approval": None}
    name = keys.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        errs.append("name is missing or not a valid name")
    elif name != stem:
        errs.append(f"name {name!r} differs from the filename")
    else:
        d["name"] = name
    for k, bare in (("issued", "start"), ("expires", "end")):
        v = keys.get(k)
        if v is None:
            errs.append(f"{k} is missing")
            continue
        ts, err = util.parse_time(v if isinstance(v, str) else "", bare=bare)
        if err:
            errs.append(f"{k}: {err}")
        d[k] = ts
    if d["issued"] is not None and d["expires"] is not None and d["issued"] > d["expires"]:
        errs.append("issued is later than expires")
    boxes, err = box_ids(keys.get("box"), default_source)
    if err:
        errs.append(err)
    d["boxes"] = boxes
    ap, err = approval_of(keys)
    if err:
        errs.append(err)
    d["approval"] = ap
    return d


# ── allowed_signers ────────────────────────────────────────────────────────

def signers_lines(text):
    """allowed_signers -> [(principals, options, keytype, key)] for every
    non-comment line; malformed lines are skipped."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) < 3:
            continue
        principals = parts[0].split(",")
        rest = parts[1:]
        options = []
        while rest and not rest[0].startswith(("ssh-", "sk-", "ecdsa-")):
            options.append(rest.pop(0))
        if len(rest) < 2:
            continue
        out.append((principals, options, rest[0], rest[1]))
    return out


def signer_check(signers_text, principal, namespace):
    """The module's own check before ssh-keygen (plan §4.1, Phase 0b):
    -> None when fine, else the "cannot verify" reason."""
    mine = [ln for ln in signers_lines(signers_text) if principal in ln[0]]
    if not mine:
        return "principal not in allowed_signers"
    for _p, options, _t, _k in mine:
        ns = [o for o in options if o.startswith("namespaces=")]
        if not ns:
            return "allowed_signers line has no namespaces="
        allowed = ns[0].split("=", 1)[1].strip('"').split(",")
        if namespace not in [a.strip() for a in allowed]:
            return f"allowed_signers line does not allow namespace {namespace}"
    return None


# ── verification ───────────────────────────────────────────────────────────

class SigCache:
    """<data>/sigcache.json: verify results keyed by the hash of everything
    that went into them (plan §4.1)."""
    CAP = 500

    def __init__(self, path):
        self.path = path
        self.entries = {}
        self.dirty = False
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("entries"), dict):
                self.entries = d["entries"]
        except (OSError, ValueError):
            pass

    def get(self, key):
        v = self.entries.get(key)
        return (v["state"], v["reason"]) if isinstance(v, dict) and "state" in v else None

    def put(self, key, state, reason, now):
        self.entries[key] = {"state": state, "reason": reason, "at": util.utc_iso(now)}
        self.dirty = True

    def save(self):
        if not self.dirty or not self.path:
            return
        if len(self.entries) > self.CAP:
            keep = sorted(self.entries.items(), key=lambda kv: kv[1].get("at", ""))[-self.CAP:]
            self.entries = dict(keep)
        util.atomic_write(self.path, json.dumps({"schema": "corral-light-delegates.sigcache/1",
                                                 "entries": self.entries}))
        self.dirty = False


def keygen_path():
    return shutil.which("ssh-keygen", path=os.environ.get("PATH") or "/usr/bin:/bin")


def _tool_stamp():
    p = keygen_path()
    if not p:
        return "absent"
    try:
        st = os.stat(p)
        return f"{p}:{st.st_size}:{int(st.st_mtime)}"
    except OSError:
        return p


def cache_key(charter, sig, signers, namespace, principal):
    h = util.sha256_hex
    return h(b"\0".join([h(charter).encode(), h(sig).encode(), h(signers).encode(),
                         namespace.encode(), principal.encode(), _tool_stamp().encode()]))


def verify(charter, sig, signers_text, signers_path, principal, namespace, *, env,
           cache=None, runner=None):
    """-> ("verified" | "failed" | "cannot", reason). `runner` replaces the
    ssh-keygen call in tests."""
    reason = signer_check(signers_text, principal, namespace)
    if reason:
        return "cannot", reason
    if not env.can_verify():
        return "cannot", "no subprocess in this sandbox"
    key = cache_key(charter, sig, signers_text.encode("utf-8", "replace"), namespace, principal)
    if cache is not None:
        hit = cache.get(key)
        if hit:
            return hit
    state, reason = _run_keygen(charter, sig, signers_path, principal, namespace, runner)
    if cache is not None and state != "cannot":
        cache.put(key, state, reason, env.now())
    return state, reason


def _run_keygen(charter, sig, signers_path, principal, namespace, runner=None):
    exe = keygen_path()
    if not exe and runner is None:
        return "cannot", "ssh-keygen is not available"
    import tempfile
    with tempfile.TemporaryDirectory(prefix="dsig-") as tmp:
        sp = os.path.join(tmp, "charter.md.sig")
        with open(sp, "wb") as f:
            f.write(sig)
        argv = [exe or "ssh-keygen", "-Y", "verify", "-f", signers_path, "-I", principal,
                "-n", namespace, "-s", sp]
        try:
            if runner is not None:
                rc, err = runner(argv, charter)
            else:
                p = subprocess.run(argv, input=charter, capture_output=True,
                                   timeout=VERIFY_TIMEOUT_S, check=False)
                rc, err = p.returncode, p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return "cannot", "ssh-keygen timed out"
        except OSError as e:
            return "cannot", f"ssh-keygen could not run: {type(e).__name__}"
    if rc == 0:
        return "verified", "signature verified"
    msg = err.strip().splitlines()[-1] if err.strip() else f"ssh-keygen exit {rc}"
    low = msg.lower()
    if "could not verify" in low and "signature" in low:
        msg = "principal or key not accepted by allowed_signers"
    return "failed", msg[:160]


def sign_command(key_file, namespace, path):
    """The exact `ssh-keygen -Y sign` line the operator runs (plan §6)."""
    return "ssh-keygen -Y sign -f " + shlex.quote(key_file) + " -n " + shlex.quote(namespace) \
        + " " + shlex.quote(path)
