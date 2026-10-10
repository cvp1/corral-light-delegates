"""Synthetic fixtures: a config folder, a data dir, a throwaway signing key.
Every charter and box here is made up."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import io

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True

from delegates import main, util  # noqa: E402
from delegates.charter import DEFAULT_NAMESPACE  # noqa: E402

KEYGEN = shutil.which("ssh-keygen")
# v1 verifies on Linux only (plan §4.1); the macOS CI runs the "cannot verify" case.
HAVE_KEYGEN = KEYGEN is not None and sys.platform != "darwin"
T0 = util.parse_time("2026-10-10T12:00:00Z", "start")[0]
NS = DEFAULT_NAMESPACE
PRINCIPAL = "tester@local"
DAY = util.DAY


def ts(s):
    return util.parse_time(s, "start")[0]


def iso(t):
    return util.utc_iso(t)


class Host:
    def __init__(self, require_sig=True, now=T0):
        self.tmp = tempfile.mkdtemp(prefix="dlg-")
        self.cfg = os.path.join(self.tmp, "config")
        self.charters = os.path.join(self.cfg, "charters")
        self.inbox = os.path.join(self.cfg, "inbox")
        self.data = os.path.join(self.tmp, "data")
        for d in (self.charters, self.inbox, self.data):
            os.makedirs(d, mode=0o700)
        self.now = now
        self.keydir = os.path.join(self.tmp, "key")
        self.key = None
        self.require_sig = require_sig
        self.sources = []
        if require_sig and HAVE_KEYGEN:
            os.makedirs(self.keydir)
            self.key = os.path.join(self.keydir, "k")
            subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", PRINCIPAL, "-f", self.key],
                           check=True, capture_output=True)
            self.write_signers()
        self.write_config()

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── config ──
    def pubkey(self):
        with open(self.key + ".pub", encoding="utf-8") as f:
            t, k = f.read().split()[:2]
        return t, k

    def write_signers(self, namespaces=NS, principal=PRINCIPAL, extra=""):
        t, k = self.pubkey()
        opt = f'namespaces="{namespaces}" ' if namespaces is not None else ""
        with open(os.path.join(self.cfg, "allowed_signers"), "w", encoding="utf-8") as f:
            f.write(f"{principal} {opt}{t} {k}\n{extra}")

    def write_config(self, require=None, notices="on", principal=PRINCIPAL, namespace=NS):
        if require is None:
            require = "yes" if (self.require_sig and HAVE_KEYGEN) else "no"
        lines = [f'require_signature = "{require}"', f'notices = "{notices}"', "", "[[charters]]",
                 'path = "charters"', f'principal = "{principal}"', f'namespace = "{namespace}"']
        for s in self.sources:
            lines += ["", "[[source]]", f'id = "{s["id"]}"', f'file = "{s["file"]}"',
                      f'label = "{s["label"]}"', f'stale_after_s = {s["stale_after_s"]}',
                      f'may_claim_complete = "{s["may_claim_complete"]}"']
        with open(os.path.join(self.cfg, "config.toml"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    @property
    def config_path(self):
        return os.path.join(self.cfg, "config.toml")

    def env(self, now=None, platform=None, sandboxed=False):
        return util.Env(data=self.data, config=self.config_path, sandboxed=sandboxed,
                        now=self.now if now is None else now, platform=platform or "linux")

    # ── charters ──
    def charter(self, name, box=None, status="approved", approval=None, issued="2026-10-01T00:00:00Z",
                expires="2026-12-01T00:00:00Z", extra="", body="Purpose.\n", sign=True, crlf=False,
                omit=(), raw=None):
        p = os.path.join(self.charters, name + ".md")
        if raw is None:
            lines = ["---"]
            if "name" not in omit:
                lines.append(f"name: {name}")
            if status is not None and "status" not in omit:
                lines.append(f"status: {status}")
            if approval is not None:
                lines.append(f"approval: {approval}")
            if "issued" not in omit:
                lines.append(f"issued: {issued}")
            if "expires" not in omit:
                lines.append(f"expires: {expires}")
            if box is None:
                box = name
            if box is not False and "box" not in omit:
                lines.append(f"box: {box}")
            if extra:
                lines += extra.rstrip("\n").split("\n")
            lines += ["---", "", body.rstrip("\n")]
            raw = "\n".join(lines) + "\n"
        data = raw.encode("utf-8")
        if crlf:
            data = data.replace(b"\n", b"\r\n")
        with open(p, "wb") as f:
            f.write(data)
        if sign and self.key:
            self.sign(name)
        return p

    def sign(self, name, namespace=NS, key=None):
        p = os.path.join(self.charters, name + ".md")
        subprocess.run([KEYGEN, "-q", "-Y", "sign", "-f", key or self.key, "-n", namespace, p],
                       check=True, capture_output=True)

    def remove_charter(self, name):
        for suffix in (".md", ".md.sig"):
            try:
                os.unlink(os.path.join(self.charters, name + suffix))
            except FileNotFoundError:
                pass

    def edit_charter(self, name, old, new, resign=False):
        p = os.path.join(self.charters, name + ".md")
        with open(p, "rb") as f:
            data = f.read()
        with open(p, "wb") as f:
            f.write(data.replace(old.encode(), new.encode()))
        if resign and self.key:
            self.sign(name)

    def unsign(self, name):
        try:
            os.unlink(os.path.join(self.charters, name + ".md.sig"))
        except FileNotFoundError:
            pass

    # ── boxes.toml and gone.toml ──
    def boxes(self, *names, cost=None, tier="delegate"):
        lines = []
        for n in names:
            lines += ["[[box]]", f'name = "{n}"', f'tier = "{tier}"', 'provider = "test"']
            if cost is not None:
                lines.append(f'cost_usd_month = "{cost}"')
            lines.append("")
        with open(os.path.join(self.cfg, "boxes.toml"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def remove_boxes_toml(self):
        try:
            os.unlink(os.path.join(self.cfg, "boxes.toml"))
        except FileNotFoundError:
            pass

    # ── inbox ──
    def source(self, sid, file=None, label=None, stale_after_s=7200, may_claim_complete="no"):
        self.sources = [s for s in self.sources if s["id"] != sid]
        self.sources.append({"id": sid, "file": file or f"{sid}.json", "label": label or sid,
                             "stale_after_s": stale_after_s, "may_claim_complete": may_claim_complete})
        self.write_config()

    def drop_source(self, sid):
        self.sources = [s for s in self.sources if s["id"] != sid]
        self.write_config()

    def inbox_file(self, sid, boxes=(), grants=(), generated_at=None, complete=False, raw=None,
                   file=None):
        if raw is None:
            doc = {"schema": "corral-light.delegates.inbox/1",
                   "generated_at": generated_at or iso(self.now), "complete": complete,
                   "boxes": [self.ibox(b) if isinstance(b, str) else b for b in boxes],
                   "grants": list(grants)}
            raw = json.dumps(doc)
        with open(os.path.join(self.inbox, file or f"{sid}.json"), "w", encoding="utf-8") as f:
            f.write(raw)

    @staticmethod
    def ibox(name, tier="delegate"):
        return {"name": name, "tier": tier, "provider": "test", "since": "2026-08-16"}

    @staticmethod
    def igrant(name, box, issued="2026-09-04T00:00:00Z", expires="2026-12-01T00:00:00Z",
               approved=True, signature="verified", revoked_at=None, state="LIVE", gid=None, **kw):
        g = {"name": name, "grant_id": gid or ("sha256:" + util.sha256_hex(f"{name}{issued}".encode())),
             "issued": issued, "expires": expires, "box": box, "approved": approved,
             "signature": signature, "revoked_at": revoked_at, "reports_state": state}
        g.update(kw)
        return g

    # ── runs ──
    def run(self, now=None, platform=None, sandboxed=False, runner=None):
        if now is not None:
            self.now = now
        return main.run(self.env(platform=platform, sandboxed=sandboxed), runner=runner)

    def collect(self, now=None):
        out = io.StringIO()
        rc = main.collector_main(["snapshot"], env=self.env(now=now), out=out)
        return rc, out.getvalue()

    def cli(self, *argv, ask=None, now=None):
        out = io.StringIO()
        rc = main.cli_main(list(argv), env=self.env(now=now), out=out, ask=ask)
        return rc, out.getvalue()

    def advance(self, seconds):
        self.now += seconds


def box(board, bid):
    b = next((b for b in board.boxes if b.id == bid), None)
    if b is None:
        raise AssertionError(f"{bid} not on the board; have {[x.id for x in board.boxes]}")
    return b


def grant(board, qname):
    g = next((g for g in board.grants if g.qname == qname and g.status != "ended:removed"), None)
    if g is None:
        g = next((g for g in board.grants if g.qname == qname), None)
    if g is None:
        raise AssertionError(f"{qname} not on the board; have {[x.qname for x in board.grants]}")
    return g


class HostCase(unittest.TestCase):
    require_sig = False

    def setUp(self):
        self.h = Host(require_sig=self.require_sig)

    def tearDown(self):
        self.h.close()
