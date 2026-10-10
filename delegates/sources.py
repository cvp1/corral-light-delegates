"""What the collector reads (plan §4): the operator config, the charter
folders, `boxes.toml`, `gone.toml`, and the declared inbox files.

The config lives where Light says (CORRAL_MODULE_CONFIG, a file in a folder
only the CLI may write), in the TOML subset Light's own reader takes:
strings, integers, comments and `[[name]]` tables.

    require_signature = "yes"          # "no" while you have no key yet
    notices = "on"

    [[charters]]
    path = "charters"                  # inside the config folder
    principal = "you@host"
    namespace = "corral-light-delegate-charter"

    [[source]]                         # an inbox file (plan §4.3)
    id = "ranch"
    file = "ranch.json"
    label = "ranch-server status"
    stale_after_s = 7200
    may_claim_complete = "no"
"""
import json
import os
import re

from delegates import tomlmini, util
from delegates.charter import DECLARED, DEFAULT_NAMESPACE, NAME_RE, SOURCE_ID_RE, CHARTER_CAP

INBOX_SCHEMA = "corral-light.delegates.inbox/1"
SIG_ENUM = ("verified", "failed", "absent", "unverified")
MAX_FILES, FILE_CAP, MAX_ROWS = 16, 1 << 20, 2000
DEFAULT_STALE_S = 7200
RESERVED_IDS = ("local", DECLARED)
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


class ConfigError(ValueError):
    pass


class Config:
    def __init__(self, path):
        self.path = path
        self.error = None
        self.require_signature = "auto"       # "yes" | "no" | "auto" (yes once allowed_signers exists)
        self.notices = "on"
        self.charters = []                    # [{"path", "principal", "namespace"}]
        self.sources = []                     # [{"id", "file", "label", "stale_after_s", "may_claim_complete"}]

    @property
    def dir(self):
        return os.path.dirname(self.path) if self.path else None

    @classmethod
    def load(cls, path):
        c = cls(path)
        if not path or not os.path.exists(path):
            c.charters = [c.default_folder()]
            return c
        try:
            with open(path, encoding="utf-8") as f:
                doc = tomlmini.loads_strict(f.read())
        except (OSError, ValueError) as e:
            c.error = f"the Delegates config could not be read: {e}"
            c.charters = [c.default_folder()]
            return c
        rs = doc.get("require_signature", "auto")
        c.require_signature = rs if rs in ("yes", "no", "auto") else "auto"
        c.notices = "off" if doc.get("notices") == "off" else "on"
        for t in doc.get("charters", []):
            if not isinstance(t, dict):
                continue
            folder = c.default_folder()
            for k in ("path", "principal", "namespace"):
                if isinstance(t.get(k), str) and t[k].strip():
                    folder[k] = t[k].strip()
            c.charters.append(folder)
        if not c.charters:
            c.charters = [c.default_folder()]
        seen = set()
        for t in doc.get("source", []):
            if not isinstance(t, dict):
                continue
            sid, fn = t.get("id"), t.get("file")
            if not isinstance(sid, str) or not SOURCE_ID_RE.match(sid) or sid in RESERVED_IDS \
                    or sid in seen or not isinstance(fn, str) or not _FILE_RE.match(fn):
                c.error = (c.error or "") + f" source {sid!r} is not usable (id or file);"
                continue
            seen.add(sid)
            stale = t.get("stale_after_s", DEFAULT_STALE_S)
            c.sources.append({
                "id": sid, "file": fn,
                "label": t["label"] if isinstance(t.get("label"), str) else sid,
                "stale_after_s": stale if isinstance(stale, int) and stale > 0 else DEFAULT_STALE_S,
                "may_claim_complete": "yes" if t.get("may_claim_complete") == "yes" else "no"})
        return c

    @staticmethod
    def default_folder():
        return {"path": "charters", "principal": "", "namespace": DEFAULT_NAMESPACE}

    def signers_path(self):
        return os.path.join(self.dir, "allowed_signers") if self.dir else None

    def signing_required(self):
        if self.require_signature == "auto":
            p = self.signers_path()
            return bool(p and os.path.exists(p))
        return self.require_signature == "yes"

    def folder_path(self, folder):
        p = folder["path"]
        return p if os.path.isabs(p) else os.path.join(self.dir or ".", p)

    def inbox_dir(self):
        return os.path.join(self.dir, "inbox") if self.dir else None

    def dumps(self):
        lines = ["# Delegates for Corral Light. Written by `corral-light delegates setup`;",
                 "# safe to edit by hand (strings, whole numbers, comments only).",
                 "", f"require_signature = {tomlmini.basic(self.require_signature)}",
                 f"notices = {tomlmini.basic(self.notices)}"]
        for f in self.charters:
            lines += ["", "[[charters]]", f"path = {tomlmini.basic(f['path'])}",
                      f"principal = {tomlmini.basic(f.get('principal', ''))}",
                      f"namespace = {tomlmini.basic(f.get('namespace', DEFAULT_NAMESPACE))}"]
        for s in self.sources:
            lines += ["", "[[source]]", f"id = {tomlmini.basic(s['id'])}",
                      f"file = {tomlmini.basic(s['file'])}", f"label = {tomlmini.basic(s['label'])}",
                      f"stale_after_s = {int(s['stale_after_s'])}",
                      f"may_claim_complete = {tomlmini.basic(s['may_claim_complete'])}"]
        return "\n".join(lines) + "\n"

    def save(self):
        if not self.path:
            raise ConfigError("no config path (CORRAL_MODULE_CONFIG is not set)")
        text = self.dumps()
        tomlmini.loads_strict(text)
        util.atomic_write(self.path, text)


class Source:
    """One source's reading for this run (plan §2.2, §4.3)."""

    def __init__(self, sid, kind, label):
        self.id = sid
        self.kind = kind                 # "declared" | "inbox" | "charters"
        self.label = label
        self.health = "missing"          # "fresh" | "stale" | "failed" | "missing"
        self.complete = False
        self.generated_at = None
        self.boxes = {}                  # qualified id -> box dict
        self.grants = []                 # inbox grant dicts
        self.errors = []
        self.notes = []
        self.rows = 0
        self.path = None

    def lists(self, bid):
        return bid in self.boxes

    def covers(self, bid):
        return bid.split("/", 1)[0] == self.id

    def age_text(self, now):
        if self.generated_at is None:
            return "-"
        return util.age_text(now - self.generated_at)


# ── charters ───────────────────────────────────────────────────────────────

def load_charters(cfg):
    """-> ([{"stem", "path", "data", "sig", "over", "folder"}], Source)."""
    src = Source("local", "charters", "charters")
    out = []
    for folder in cfg.charters:
        d = cfg.folder_path(folder)
        src.path = d
        if not os.path.isdir(d):
            src.notes.append(f"no folder {folder['path']}")
            continue
        src.health = "fresh"
        try:
            names = sorted(os.listdir(d))
        except OSError as e:
            src.errors.append(f"{folder['path']}: {type(e).__name__}")
            src.health = "failed"
            continue
        for fn in names:
            if not fn.endswith(".md"):
                continue
            stem = fn[:-3]
            if not NAME_RE.match(stem):
                continue
            p = os.path.join(d, fn)
            rec = {"stem": stem, "path": p, "folder": folder, "data": b"", "sig": None,
                   "over": False, "read_error": None}
            try:
                rec["data"], rec["over"] = util.read_capped(p, CHARTER_CAP)
            except OSError as e:
                rec["read_error"] = f"{type(e).__name__}"
            sp = p + ".sig"
            if os.path.lexists(sp):
                try:
                    rec["sig"], _ = util.read_capped(sp, 64 << 10)
                except OSError as e:
                    rec["sig"] = b""
                    rec["sig_error"] = f"{type(e).__name__}"
            out.append(rec)
        src.rows += len(out)
    return out, src


def read_signers(cfg):
    p = cfg.signers_path()
    if not p or not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


# ── boxes.toml ─────────────────────────────────────────────────────────────

def _cost(v):
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str) and re.match(r"^\d{1,7}(\.\d{1,2})?$", v.strip()):
        return v.strip()
    return None


def load_declared(cfg, now):
    src = Source(DECLARED, "declared", "boxes.toml (declared by hand)")
    p = os.path.join(cfg.dir, "boxes.toml") if cfg.dir else None
    src.path = p
    if not p or not os.path.exists(p):
        src.health = "missing"
        src.notes.append("no boxes.toml yet")
        return src
    try:
        with open(p, encoding="utf-8") as f:
            doc = tomlmini.loads_strict(f.read())
    except (OSError, ValueError) as e:
        src.health = "failed"
        src.errors.append(f"boxes.toml: {e}")
        return src
    src.health, src.complete, src.generated_at = "fresh", True, now
    for t in doc.get("box", []):
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            src.errors.append(f"boxes.toml: a box has no valid name ({name!r})")
            continue
        bid = f"{DECLARED}/{name}"
        if bid in src.boxes:
            src.errors.append(f"boxes.toml: {name} is listed twice")
            continue
        tier = t.get("tier") if isinstance(t.get("tier"), str) else "delegate"
        cost = _cost(t.get("cost_usd_month"))
        src.boxes[bid] = {"id": bid, "name": name, "tier": tier,
                          "provider": t.get("provider") if isinstance(t.get("provider"), str) else "",
                          "since": t.get("since") if isinstance(t.get("since"), str) else "",
                          "cost": {"usd_month": cost, "kind": "declared"} if cost else None}
        src.rows += 1
    return src


# ── gone.toml ──────────────────────────────────────────────────────────────

def load_gone(cfg):
    """-> ({qualified id: {"at": epoch, "note"}}, [errors])."""
    out, errors = {}, []
    p = os.path.join(cfg.dir, "gone.toml") if cfg.dir else None
    if not p or not os.path.exists(p):
        return out, errors
    try:
        with open(p, encoding="utf-8") as f:
            doc = tomlmini.loads_strict(f.read())
    except (OSError, ValueError) as e:
        errors.append(f"gone.toml: {e}")
        return out, errors
    for t in doc.get("gone", []):
        if not isinstance(t, dict):
            continue
        bid, at = t.get("box"), t.get("at")
        ts = util.parse_time(at, "start")[0] if isinstance(at, str) else None
        if not isinstance(bid, str) or "/" not in bid or ts is None:
            errors.append(f"gone.toml: a record needs box = \"<source>/<name>\" and at (RFC 3339)")
            continue
        cur = out.get(bid)
        if cur is None or ts > cur["at"]:
            out[bid] = {"at": ts, "note": t.get("note") if isinstance(t.get("note"), str) else ""}
    return out, errors


def append_gone(cfg, bid, now, note=""):
    p = os.path.join(cfg.dir, "gone.toml")
    block = ["", "[[gone]]", f"box = {tomlmini.basic(bid)}", f"at = {tomlmini.basic(util.utc_iso(now))}"]
    if note:
        block.append(f"note = {tomlmini.basic(note)}")
    text = ""
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            text = f.read()
    else:
        text = ("# Delegates gone-records: boxes you say are gone (plan §2.4). Written by\n"
                "# `corral-light delegates gone <source>/<name>`; safe to edit by hand.\n")
    text = text.rstrip("\n") + "\n" + "\n".join(block) + "\n"
    tomlmini.loads_strict(text)
    util.atomic_write(p, text)


# ── inbox ──────────────────────────────────────────────────────────────────

def _grant_row(raw, sid, errors_out):
    """One inbox grant -> dict. Field errors go to the grant's own list; a
    bad `signature` value fails the whole file (errors_out)."""
    g = {"source": sid, "errors": [], "raw": raw}
    if not isinstance(raw, dict):
        g["errors"].append("grant is not an object")
        g.update(name=None, grant_id=None, issued=None, expires=None, boxes=[],
                 approved=False, signature="unverified", revoked_at=None, reports_state="")
        return g
    name = raw.get("name")
    g["name"] = name if isinstance(name, str) and NAME_RE.match(name) else None
    if g["name"] is None:
        g["errors"].append("source gave no valid name")
    gid = raw.get("grant_id")
    g["grant_id"] = gid if isinstance(gid, str) and re.match(r"^sha256:[0-9a-f]{64}$", gid) else None
    if g["grant_id"] is None:
        g["errors"].append("source gave no grant_id")
    for k, bare in (("issued", "start"), ("expires", "end")):
        ts, err = util.parse_time(raw.get(k), bare)
        g[k] = ts
        if err:
            g["errors"].append(f"source gave no {k}" if err == "missing" else f"{k}: {err}")
    if g["issued"] is not None and g["expires"] is not None and g["issued"] > g["expires"]:
        g["errors"].append("issued is later than expires")
    from delegates.charter import box_ids
    if raw.get("box") is None:
        # the source knows no box for this grant (the ranch: no live box);
        # the grant is shown and covers nothing
        boxes, err = [], None
    else:
        boxes, err = box_ids(raw.get("box"), sid)
    if err:
        g["errors"].append(f"box: {err}")
    g["boxes"] = boxes
    g["approved"] = raw.get("approved") is True
    sig = raw.get("signature")
    if sig not in SIG_ENUM:
        errors_out.append(f"grant {name!r}: signature {sig!r} is not one of {', '.join(SIG_ENUM)}")
        sig = "unverified"
    g["signature"] = sig
    ra = raw.get("revoked_at")
    g["revoked_at"] = util.parse_time(ra, "start")[0] if isinstance(ra, str) else None
    if isinstance(ra, str) and g["revoked_at"] is None:
        g["errors"].append("revoked_at: unparseable")
    rs = raw.get("reports_state")
    g["reports_state"] = rs if isinstance(rs, str) else ""
    cost = raw.get("cost")
    g["cost"] = _cost(cost.get("usd_month")) if isinstance(cost, dict) else None
    return g


def _parse_inbox(obj, decl, now, budget):
    """A parsed inbox file -> (Source fields as dict, error or None).
    `budget` is the rows left under the 2,000 cap."""
    sid = decl["id"]
    if not isinstance(obj, dict) or obj.get("schema") != INBOX_SCHEMA:
        return None, f"schema is not {INBOX_SCHEMA}"
    gen, err = util.parse_time(obj.get("generated_at"), "start")
    if err:
        return None, f"generated_at: {err}"
    if gen > now + util.SKEW_S:
        return None, f"generated_at is {util.age_text(gen - now)} in the future"
    res = {"generated_at": gen, "boxes": {}, "grants": [], "errors": [], "notes": [],
           "rows": 0, "cut": False}
    boxes = obj.get("boxes") if isinstance(obj.get("boxes"), list) else []
    grants = obj.get("grants") if isinstance(obj.get("grants"), list) else []
    total = len(boxes) + len(grants)
    if total > budget:
        res["cut"] = True
        res["notes"].append(f"cut at {budget} of {total} rows (2,000 in all)")
        keep_b = min(len(boxes), budget)
        boxes, grants = boxes[:keep_b], grants[:max(0, budget - keep_b)]
    for b in boxes:
        if not isinstance(b, dict) or not isinstance(b.get("name"), str) \
                or not NAME_RE.match(b["name"]):
            res["errors"].append("a box has no valid name")
            continue
        bid = f"{sid}/{b['name']}"
        cost = b.get("cost") if isinstance(b.get("cost"), dict) else {}
        c = _cost(cost.get("usd_month"))
        res["boxes"][bid] = {"id": bid, "name": b["name"],
                             "tier": b.get("tier") if isinstance(b.get("tier"), str) else "",
                             "provider": b.get("provider") if isinstance(b.get("provider"), str) else "",
                             "since": b.get("since") if isinstance(b.get("since"), str) else "",
                             "cost": {"usd_month": c,
                                      "kind": cost.get("kind") if cost.get("kind") in
                                      ("vendor", "declared", "estimate") else "estimate"}
                             if c else None}
        res["rows"] += 1
    file_errors = []
    for g in grants:
        res["grants"].append(_grant_row(g, sid, file_errors))
        res["rows"] += 1
    if file_errors:
        return None, file_errors[0]
    complete = obj.get("complete") is True and decl["may_claim_complete"] == "yes" and not res["cut"]
    if obj.get("complete") is True and not complete:
        res["notes"].append("claims complete; not allowed for this source" if
                            decl["may_claim_complete"] != "yes" else "claims complete; cut short")
    res["complete"] = complete
    return res, None


def _lastgood_path(data_dir, sid):
    return os.path.join(data_dir, "lastgood", f"{sid}.json")


def load_inbox(cfg, now, data_dir):
    """-> [Source], one per declared source (plan §4.3)."""
    out = []
    budget = MAX_ROWS
    inbox = cfg.inbox_dir()
    declared = cfg.sources[:MAX_FILES]
    for decl in declared:
        src = Source(decl["id"], "inbox", decl["label"])
        src.stale_after_s = decl["stale_after_s"]
        p = os.path.join(inbox, decl["file"]) if inbox else None
        src.path = p
        err, obj = None, None
        if not p or not os.path.lexists(p):
            err = "no file"
            src.health = "missing"
        else:
            try:
                data, over = util.read_capped(p, FILE_CAP)
                if over:
                    err = "larger than 1 MiB"
                else:
                    obj = json.loads(data.decode("utf-8"))
            except OSError as e:
                err = f"{type(e).__name__}"
            except (ValueError, UnicodeDecodeError):
                err = "not JSON"
        res = None
        if err is None:
            res, perr = _parse_inbox(obj, decl, now, budget)
            if perr:
                err = perr
        if res is not None:
            src.health = "stale" if now - res["generated_at"] > decl["stale_after_s"] else "fresh"
            src.generated_at = res["generated_at"]
            src.complete = res["complete"] and src.health == "fresh"
            src.boxes, src.grants, src.rows = res["boxes"], res["grants"], res["rows"]
            src.errors += res["errors"]
            src.notes += res["notes"]
            budget = max(0, budget - res["rows"])
            if data_dir:
                try:
                    util.atomic_write(_lastgood_path(data_dir, decl["id"]),
                                      json.dumps({"read_at": util.utc_iso(now), "raw": obj}))
                except OSError:
                    pass
        else:
            src.health = "failed" if err != "no file" else "missing"
            src.errors.append(err)
            lg, st = (None, "absent")
            if data_dir:
                try:
                    with open(_lastgood_path(data_dir, decl["id"]), encoding="utf-8") as f:
                        lg = json.load(f)
                    st = "ok"
                except (OSError, ValueError):
                    pass
            if st == "ok" and isinstance(lg, dict):
                res2, perr2 = _parse_inbox(lg.get("raw"), decl, now, MAX_ROWS)
                if res2 is not None:
                    src.generated_at = res2["generated_at"]
                    src.boxes, src.grants, src.rows = res2["boxes"], res2["grants"], res2["rows"]
                    src.notes.append(f"showing the last good copy, read "
                                     f"{lg.get('read_at', '?')}; it can keep an alarm, not lower one")
                    src.last_good = True
        out.append(src)
    if len(cfg.sources) > MAX_FILES:
        out[-1].notes.append(f"{len(cfg.sources) - MAX_FILES} sources beyond the cap of "
                             f"{MAX_FILES} are ignored")
    return out


def undeclared_files(cfg):
    inbox = cfg.inbox_dir()
    if not inbox or not os.path.isdir(inbox):
        return []
    known = {s["file"] for s in cfg.sources}
    try:
        names = sorted(os.listdir(inbox))
    except OSError:
        return []
    return [n for n in names if n not in known and not n.startswith(".")]
