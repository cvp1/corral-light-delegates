"""The ledger, the tombstones and the damage record (plan §2.4).

Only the collector writes `ledger.json`, `tombstones.jsonl` and
`damage.json`, each to a temp file and then a rename. The CLI's one write
to the data dir is `ledger.ack`.
"""
import json
import os

from delegates import util

LEDGER_SCHEMA = "corral-light-delegates.ledger/1"
LEDGER = "ledger.json"
TOMBSTONES = "tombstones.jsonl"
DAMAGE = "damage.json"
ACK = "ledger.ack"


def _load_json(path):
    """-> (obj, state): state is 'absent', 'ok' or 'damaged'."""
    if not os.path.exists(path):
        return None, "absent"
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError):
        return None, "damaged"
    return obj, "ok"


class Ledger:
    def __init__(self, data_dir, now):
        self.dir = data_dir
        self.now = now
        self.boxes = {}          # qualified id -> entry
        self.grants = {}         # grant id -> entry
        self.expiry_marks = {}   # <source>/<name> -> issued (epoch)
        self.tombstones = {}     # <source>/<name> -> {"issued": epoch, "at": iso}
        self.last_run = None     # epoch of the previous run's generated_at
        self.damage = {}         # {"ledger": {...}, "tombstones": {...}}
        self.events = []         # this run's notes for Sources
        self.dirty = False
        self._load()

    # ── load and damage ────────────────────────────────────────────────

    def _move_aside(self, path):
        aside = f"{path}.damaged-{util.utc_date(self.now)}"
        n = 1
        while os.path.exists(aside):
            n += 1
            aside = f"{path}.damaged-{util.utc_date(self.now)}-{n}"
        try:
            os.replace(path, aside)
        except OSError:
            pass
        return os.path.basename(aside)

    def _load(self):
        os.makedirs(self.dir, exist_ok=True)
        dmg, st = _load_json(os.path.join(self.dir, DAMAGE))
        if st == "ok" and isinstance(dmg, dict):
            self.damage = {k: v for k, v in dmg.items() if isinstance(v, dict)}
        lp = os.path.join(self.dir, LEDGER)
        obj, st = _load_json(lp)
        if st == "damaged" or (st == "ok" and (not isinstance(obj, dict)
                                               or obj.get("schema") != LEDGER_SCHEMA)):
            aside = self._move_aside(lp)
            self.damage["ledger"] = {"at": util.utc_iso(self.now), "file": aside}
            self.events.append("ledger damaged; moved aside and rebuilt empty")
            self.dirty = True
        elif st == "ok":
            self.boxes = {k: v for k, v in (obj.get("boxes") or {}).items()
                          if isinstance(v, dict)}
            self.grants = {k: v for k, v in (obj.get("grants") or {}).items()
                           if isinstance(v, dict)}
            self.expiry_marks = {k: v for k, v in (obj.get("expiry_marks") or {}).items()
                                 if isinstance(v, (int, float))}
            lr = obj.get("last_run")
            self.last_run = util.parse_time(lr, "start")[0] if isinstance(lr, str) else None
        tp = os.path.join(self.dir, TOMBSTONES)
        if os.path.exists(tp):
            good, bad = 0, 0
            try:
                with open(tp, encoding="utf-8") as f:
                    lines = f.read().splitlines()
            except OSError:
                lines, bad = [], 1
            for ln in lines:
                if not ln.strip():
                    continue
                try:
                    t = json.loads(ln)
                    name, issued = t["name"], float(t["issued"])
                    if not isinstance(name, str):
                        raise ValueError
                except (ValueError, TypeError, KeyError):
                    bad += 1
                    continue
                good += 1
                cur = self.tombstones.get(name)
                if cur is None or issued > cur["issued"]:
                    self.tombstones[name] = {"issued": issued, "at": t.get("at")}
            if bad:
                aside = self._move_aside(tp)
                self.damage["tombstones"] = {"at": util.utc_iso(self.now), "file": aside,
                                             "salvaged": good, "of": good + bad}
                self.events.append(f"tombstones rebuilt; {good} of {good + bad} lines salvaged")
                self.dirty = True

    def acked_at(self):
        p = os.path.join(self.dir, ACK)
        try:
            with open(p, encoding="utf-8") as f:
                return util.parse_time(f.read().strip(), "start")[0]
        except (OSError, ValueError):
            return None

    def damage_rows(self):
        """-> [(level, text)] for Sources: bad until acknowledged, then info
        for 30 days."""
        ack = self.acked_at()
        out = []
        for what in ("ledger", "tombstones"):
            d = self.damage.get(what)
            if not d:
                continue
            at = util.parse_time(d.get("at"), "start")[0]
            if at is None:
                continue
            if what == "ledger":
                text = f"ledger damaged on {util.utc_date(at)}; alarm history lost"
            else:
                text = (f"tombstones rebuilt from a damaged file on {util.utc_date(at)}; "
                        f"{d.get('salvaged', 0)} of {d.get('of', 0)} lines salvaged")
            if ack is not None and ack >= at:
                if self.now - at <= util.RETENTION_S:
                    out.append(("info", text + " (acknowledged)"))
            else:
                out.append(("bad", text + "; acknowledge with `corral-light delegates ack-ledger`"))
        return out

    # ── tombstones and marks ───────────────────────────────────────────

    def tombstone(self, qname):
        t = self.tombstones.get(qname)
        return t["issued"] if t else None

    def add_tombstone(self, qname, issued):
        if issued is None:
            return
        cur = self.tombstones.get(qname)
        if cur is None or issued > cur["issued"]:
            self.tombstones[qname] = {"issued": issued, "at": util.utc_iso(self.now)}
            self.dirty = True

    def expiry_mark(self, qname):
        return self.expiry_marks.get(qname)

    def mark_expired(self, qname, issued):
        if issued is None:
            return
        if self.expiry_marks.get(qname, -1) < issued:
            self.expiry_marks[qname] = issued
            self.dirty = True

    # ── grants ─────────────────────────────────────────────────────────

    def grant(self, gid):
        return self.grants.get(gid)

    def see_grant(self, gid, qname, boxes, expires):
        e = self.grants.get(gid)
        if e is None:
            e = self.grants[gid] = {}
        e.update(name=qname, boxes=sorted(boxes),
                 expires=util.utc_iso(expires) if expires else None,
                 last_seen=util.utc_iso(self.now))
        if e.get("removed_at"):
            e["removed_at"] = None
        self.dirty = True

    def grant_ended(self, gid, now_ended):
        e = self.grants.get(gid)
        if e is None:
            return
        if now_ended and not e.get("ended_at"):
            e["ended_at"] = util.utc_iso(self.now)
            self.dirty = True

    def ended_at(self, gid):
        e = self.grants.get(gid)
        if not e or not e.get("ended_at"):
            return None
        return util.parse_time(e["ended_at"], "start")[0]

    def removed_grants(self, supplied):
        """Grant ids the ledger knows and nothing supplied this run ->
        [(gid, entry)], marking removed_at; entries past 30 days are dropped."""
        out = []
        for gid in list(self.grants):
            e = self.grants[gid]
            if gid in supplied:
                continue
            if not e.get("removed_at"):
                e["removed_at"] = util.utc_iso(self.now)
                self.dirty = True
            at = util.parse_time(e["removed_at"], "start")[0] or self.now
            if self.now - at > util.RETENTION_S:
                del self.grants[gid]
                self.dirty = True
                continue
            out.append((gid, e))
        return out

    # ── boxes ──────────────────────────────────────────────────────────

    def box(self, bid):
        return self.boxes.get(bid)

    def record_box(self, bid, *, grants, presence, source, level, how=None):
        e = self.boxes.get(bid)
        if e is None:
            e = self.boxes[bid] = {"grants": []}
        for g in grants:
            if g not in e["grants"]:
                e["grants"].append(g)
        if presence in ("listed", "listed-stale"):
            e.update(last_presence=presence, last_presence_at=util.utc_iso(self.now),
                     last_presence_source=source, not_listed_since=None, gone_how=None)
        elif presence == "not-listed":
            if not e.get("not_listed_since"):
                e["not_listed_since"] = util.utc_iso(self.now)
                e["gone_how"] = how
        e["last_level"] = level
        self.dirty = True

    def last_presence(self, bid):
        e = self.boxes.get(bid)
        if not e or not e.get("last_presence"):
            return None
        at = util.parse_time(e.get("last_presence_at"), "start")[0]
        return {"presence": e["last_presence"], "at": at,
                "source": e.get("last_presence_source") or "?"}

    def not_listed_since(self, bid):
        e = self.boxes.get(bid)
        if not e or not e.get("not_listed_since"):
            return None
        return util.parse_time(e["not_listed_since"], "start")[0]

    def prune_boxes(self, keep):
        """Drop entries 30 days after not-listed unless something still
        names the box (`keep`)."""
        for bid in list(self.boxes):
            since = self.not_listed_since(bid)
            if since is not None and self.now - since > util.RETENTION_S and bid not in keep:
                del self.boxes[bid]
                self.dirty = True

    # ── save ───────────────────────────────────────────────────────────

    def save(self):
        self.last_run = self.now
        obj = {"schema": LEDGER_SCHEMA, "last_run": util.utc_iso(self.now),
               "boxes": self.boxes, "grants": self.grants, "expiry_marks": self.expiry_marks}
        util.atomic_write(os.path.join(self.dir, LEDGER), json.dumps(obj, sort_keys=True))
        lines = [json.dumps({"name": k, "issued": v["issued"], "at": v.get("at")},
                            sort_keys=True) for k, v in sorted(self.tombstones.items())]
        util.atomic_write(os.path.join(self.dir, TOMBSTONES),
                          "\n".join(lines) + ("\n" if lines else ""))
        if self.damage:
            util.atomic_write(os.path.join(self.dir, DAMAGE), json.dumps(self.damage))
        self.dirty = False

    def size_text(self):
        return (f"{len(self.boxes)} boxes, {len(self.grants)} grants, "
                f"{len(self.tombstones)} tombstones")


def write_ack(data_dir, now):
    util.atomic_write(os.path.join(data_dir, ACK), util.utc_iso(now) + "\n")
