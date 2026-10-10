"""The model (plan §2): grant status, box identity and presence, coverage,
severity, and what the ledger carries between runs."""
import os

from delegates import charter, util
from delegates.charter import DECLARED, LOCAL, SigCache

STATUS_RANK = {"bad-sig": 0, "bad-charter": 1, "ended:revoked": 2, "ended:expired": 3,
               "ended:removed": 4, "unsigned": 5, "draft": 6, "valid": 7}
LEVEL_RANK = {"bad": 0, "warn": 1, "info": 2, "ok": 3}


class Grant:
    def __init__(self, source, name):
        self.source = source
        self.name = name
        self.qname = f"{source}/{name}" if name else f"{source}/?"
        self.gid = None
        self.issued = None
        self.expires = None
        self.expires_eff = None        # after an earlier `expires` from another source
        self.expires_per = None
        self.boxes = []
        self.approval = None           # draft | approved | revoked
        self.sig = "unverified"        # verified | failed | cannot | absent | unverified
        self.sig_reason = ""
        self.errors = []
        self.revoked_at = None         # inbox
        self.reports = {}              # inbox: approved, signature, reports_state
        self.cost = None
        self.other = {}
        self.path = ""
        self.shadowed_by = None
        self.shadows = None
        self.status = None
        self.reason = ""

    @property
    def is_local(self):
        return self.source == LOCAL

    def lists(self, bid):
        return bid in self.boxes


class Box:
    def __init__(self, bid):
        self.id = bid
        self.source, self.name = bid.split("/", 1)
        self.info = None               # the box dict from the source that lists it
        self.listed_by = []            # [(source id, health, generated_at)]
        self.presence = "unknown"
        self.how = ""                  # for not-listed: how it is known gone
        self.last = None               # ledger last presence, for unknown
        self.covered_by = []           # [Grant]
        self.named_by = []             # [Grant], any status
        self.level = "info"
        self.reason = ""
        self.label = ""
        self.gone = None               # gone-record dict
        self.reinstated = False

    def sources_text(self, now):
        if not self.listed_by:
            return "none"
        return "; ".join(f"{s} ({h}, {util.age_text(now - g) if g else '?'})"
                         for s, h, g in self.listed_by)


class Board:
    def __init__(self, now):
        self.now = now
        self.grants = []
        self.boxes = []
        self.sources = []
        self.gone = {}
        self.gone_errors = []
        self.undeclared = []
        self.notes = []
        self.clock_warning = False
        self.cannot_verify = False
        self.signing_required = True
        self.ledger = None
        self.config_error = None

    def alarms(self):
        return [b for b in self.boxes if b.level == "bad"]

    def expiring(self):
        return [g for g in self.grants if g.status == "valid" and g.expires_eff is not None
                and 0 <= g.expires_eff - self.now <= util.EXPIRING_S]


# ── grants ─────────────────────────────────────────────────────────────────

def local_grants(env, cfg, charters, signers_text, now, sigcache, runner=None):
    out = []
    required = cfg.signing_required()
    for rec in charters:
        g = Grant(LOCAL, rec["stem"])
        g.path = rec["path"]
        if rec.get("read_error"):
            g.errors.append(f"could not read: {rec['read_error']}")
            out.append(g)
            continue
        if rec.get("over"):
            g.errors.append("larger than 1 MiB")
            out.append(g)
            continue
        parsed = charter.parse(rec["data"])
        d = charter.check(parsed, rec["stem"], DECLARED)
        g.errors = list(parsed["errors"])
        g.other = parsed["other"]
        g.gid = "sha256:" + util.sha256_hex(rec["data"])
        g.issued, g.expires, g.boxes, g.approval = d["issued"], d["expires"], d["boxes"], d["approval"]
        g.expires_eff = g.expires
        if g.issued is not None and g.issued > now + util.SKEW_S:
            g.errors.append("issued is more than 10 min ahead of now")
        cost = parsed["keys"].get("cost-box-usd-month")
        g.cost = cost if isinstance(cost, str) and cost.strip() else None
        if required:
            if rec["sig"] is None:
                g.sig, g.sig_reason = "absent", "no .sig file"
            elif rec.get("sig_error"):
                g.sig, g.sig_reason = "cannot", f".sig unreadable: {rec['sig_error']}"
            elif signers_text is None:
                g.sig, g.sig_reason = "cannot", "no allowed_signers"
            else:
                folder = rec["folder"]
                principal = folder.get("principal") or _first_principal(signers_text)
                if not principal:
                    g.sig, g.sig_reason = "cannot", "no principal configured"
                else:
                    g.sig, g.sig_reason = charter.verify(
                        rec["data"], rec["sig"], signers_text, cfg.signers_path(), principal,
                        folder.get("namespace") or charter.DEFAULT_NAMESPACE, env=env,
                        cache=sigcache, runner=runner)
        else:
            g.sig, g.sig_reason = "unverified", "signing is off"
        out.append(g)
    return out


def _first_principal(signers_text):
    for principals, _o, _t, _k in charter.signers_lines(signers_text or ""):
        if principals:
            return principals[0]
    return None


def inbox_grants(inbox_sources):
    out = []
    for src in inbox_sources:
        for raw in src.grants:
            g = Grant(src.id, raw.get("name") or "?")
            g.gid = raw.get("grant_id")
            g.issued, g.expires = raw.get("issued"), raw.get("expires")
            g.expires_eff = g.expires
            g.boxes = raw.get("boxes") or []
            g.errors = list(raw.get("errors") or [])
            g.approval = "approved" if raw.get("approved") else "draft"
            g.revoked_at = raw.get("revoked_at")
            g.sig = raw.get("signature") or "unverified"
            g.sig_reason = f"source reports signature {g.sig}"
            g.reports = {"approved": raw.get("approved"), "signature": g.sig,
                         "reports_state": raw.get("reports_state") or ""}
            g.cost = raw.get("cost")
            g.path = src.path or ""
            out.append(g)
    return out


def apply_shadowing(grants):
    """A local charter with an inbox grant's name shadows it for approval
    and signature; the inbox grant's revocation or earlier expires still
    reaches a local grant whose issued is not later (plan §4.3)."""
    local = {g.name: g for g in grants if g.is_local and g.name}
    for g in grants:
        if g.is_local or not g.name or g.name not in local:
            continue
        lg = local[g.name]
        g.shadowed_by = lg
        lg.shadows = g
        if g.issued is None or lg.issued is None or lg.issued > g.issued:
            continue
        if g.expires is not None and lg.expires_eff is not None and g.expires < lg.expires_eff:
            lg.expires_eff, lg.expires_per = g.expires, g.source


def grant_status(g, now, ledger, signing_required):
    """Plan §2.1, first match wins."""
    if g.errors:
        return "bad-charter", "; ".join(g.errors)[:300]
    if g.is_local and signing_required and g.sig in ("failed", "cannot"):
        return "bad-sig", ("cannot verify: " if g.sig == "cannot" else "signature fails: ") + g.sig_reason
    if not g.is_local and g.sig == "failed":
        return "bad-sig", f"source reports signature failed"
    # revocation
    if g.is_local and g.approval == "revoked":
        return "ended:revoked", "status: revoked"
    if not g.is_local and g.revoked_at is not None:
        return "ended:revoked", f"revoked {util.utc_date(g.revoked_at)} per {g.source}"
    ts = ledger.tombstone(g.qname)
    if ts is not None and g.issued is not None and g.issued <= ts:
        return "ended:revoked", f"revoked: a later revocation (issued {util.utc_date(ts)}) stands"
    if g.is_local and g.shadows is not None:
        s = g.shadows
        if s.issued is not None and g.issued is not None and g.issued <= s.issued \
                and (s.revoked_at is not None or ledger.tombstone(s.qname) is not None
                     and s.issued <= ledger.tombstone(s.qname)):
            return "ended:revoked", f"revoked per {s.source}"
    # expiry
    if g.expires_eff is not None and now >= g.expires_eff:
        per = f" per {g.expires_per}" if g.expires_per else ""
        return "ended:expired", f"expired {util.age_text(now - g.expires_eff)} ago{per}"
    if g.gid and ledger.ended_at(g.gid) is not None:
        return "ended:expired", "expired (latched; the clock may have moved back)"
    mark = ledger.expiry_mark(g.qname)
    if mark is not None and g.issued is not None and g.issued <= mark:
        return "ended:expired", "expired: a copy with this issued already ended"
    if g.is_local:
        if signing_required and g.sig == "absent" and g.approval == "approved":
            return "unsigned", "approved but no .sig"
        if g.approval == "draft":
            return "draft", "not approved"
        if g.approval == "approved":
            return "valid", "valid" if g.sig == "verified" else "valid (signing off)"
        return "bad-charter", "no approval state"
    if g.sig in ("absent", "unverified"):
        return "unsigned", f"source reports signature {g.sig}"
    if g.approval != "approved":
        return "draft", "source reports not approved"
    return "valid", f"valid per {g.source}"


def removed_grants(ledger, supplied_ids):
    out = []
    for gid, e in ledger.removed_grants(supplied_ids):
        src, name = (e.get("name") or "local/?").split("/", 1)
        g = Grant(src, name)
        g.gid = gid
        g.boxes = list(e.get("boxes") or [])
        g.expires = util.parse_time(e.get("expires"), "start")[0] if e.get("expires") else None
        g.expires_eff = g.expires
        g.status, g.reason = "ended:removed", f"charter removed {util.utc_date(util.parse_time(e['removed_at'], 'start')[0])}"
        out.append(g)
    return out


# ── boxes ──────────────────────────────────────────────────────────────────

def _presence(box, sources, ledger, gone):
    fresh = [s for s in sources if s.health == "fresh" and s.lists(box.id)]
    # a failed source's last good copy is stale evidence (plan §4.3)
    stale = [s for s in sources if s.lists(box.id) and
             (s.health == "stale" or (s.health == "failed" and getattr(s, "last_good", False)))]
    omitting = [s for s in sources if s.health == "fresh" and s.complete and s.covers(box.id)
                and not s.lists(box.id)]
    box.listed_by = [(s.id, s.health, s.generated_at) for s in fresh + stale]
    for s in fresh + stale:
        if box.info is None and s.boxes.get(box.id):
            box.info = s.boxes[box.id]
    times = [s.generated_at for s in fresh + stale if s.generated_at is not None]
    latest = max(times) if times else None
    g = gone.get(box.id)
    box.gone = g
    seen = ledger.last_presence(box.id) is not None
    if g is not None and (latest is None or latest <= g["at"]):
        return "not-listed", f"gone-record of {util.utc_date(g['at'])}"
    if g is not None and latest is not None and latest > g["at"]:
        box.reinstated = True
    if omitting and seen:
        s = omitting[0]
        return "not-listed", ("removed from boxes.toml by hand" if s.id == DECLARED
                              else f"omitted by {s.id}")
    if fresh:
        return "listed", ""
    if stale:
        return "listed-stale", ""
    return "unknown", ""


def _reason(box):
    """Why an uncovered box is uncovered: its grants, worst first (§2.3)."""
    if not box.named_by:
        return "no charter names this box"
    g = sorted(box.named_by, key=lambda x: (STATUS_RANK.get(x.status, 9), x.qname))[0]
    st = g.status
    if st == "ended:expired":
        return f"{g.qname}: {g.reason}"
    if st == "ended:revoked":
        return f"{g.qname}: {g.reason}"
    if st == "ended:removed":
        return f"{g.qname}: charter removed"
    if st in ("draft", "unsigned"):
        return f"{g.qname}: never approved" if st == "draft" else f"{g.qname}: unsigned"
    if st == "bad-sig":
        return f"{g.qname}: " + ("cannot verify" if g.sig == "cannot" else "signature fails")
    if st == "bad-charter":
        return f"{g.qname}: charter unreadable"
    return f"{g.qname}: {st}"


def _severity(box, now):
    covered = bool(box.covered_by)
    cov = ", ".join(g.qname for g in box.covered_by)

    def for_presence(p):
        if p == "listed":
            return ("ok", f"covered by {cov}; box listed") if covered else \
                ("bad", f"box listed without a valid grant ({_reason(box)})")
        if p == "listed-stale":
            return ("warn", f"covered by {cov}; box listed by a stale source") if covered else \
                ("bad", f"box listed by a stale source without a valid grant ({_reason(box)})")
        return "info", ""

    p = box.presence
    if p in ("listed", "listed-stale"):
        level, label = for_presence(p)
        if box.reinstated:
            label += f"; listed again after the gone-record of {util.utc_date(box.gone['at'])}"
        return level, label
    if p == "not-listed":
        return "info", f"box gone: {box.how}"
    if box.last is not None:
        level, label = for_presence(box.last["presence"])
        age = util.age_text(now - box.last["at"]) if box.last["at"] else "?"
        return level, f"last listed {age} ago by {box.last['source']}; {label}"
    names = ", ".join(g.qname for g in box.named_by) or "a grant"
    return "warn", f"named by {names}; never listed by any source"


def evaluate(env, cfg, charters, declared, inbox_sources, gone, ledger, *, sigcache=None,
             signers_text=None, runner=None, charters_source=None):
    now = env.now()
    board = Board(now)
    board.ledger = ledger
    board.gone = gone
    board.charters_source = charters_source
    board.signing_required = cfg.signing_required()
    board.cannot_verify = board.signing_required and not env.can_verify()
    board.config_error = cfg.error
    if ledger.last_run is not None and now < ledger.last_run - util.CLOCK_BACK_S:
        board.clock_warning = True

    grants = local_grants(env, cfg, charters, signers_text, now, sigcache, runner=runner)
    grants += inbox_grants(inbox_sources)
    apply_shadowing(grants)
    supplied = set()
    for g in grants:
        g.status, g.reason = grant_status(g, now, ledger, board.signing_required)
        if g.gid:
            supplied.add(g.gid)
            ledger.see_grant(g.gid, g.qname, g.boxes, g.expires_eff)
        # tombstones and latches (plan §2.4)
        if g.status == "ended:revoked":
            if g.is_local and g.approval == "revoked":
                ledger.add_tombstone(g.qname, g.issued)
            elif not g.is_local and g.revoked_at is not None:
                ledger.add_tombstone(g.qname, g.issued)
        if g.status == "ended:expired":
            if g.gid:
                ledger.grant_ended(g.gid, True)
            ledger.mark_expired(g.qname, g.issued)
    grants += removed_grants(ledger, supplied)
    board.grants = grants

    sources = [declared] + list(inbox_sources)
    board.sources = sources
    boxes = {}

    def box_for(bid):
        b = boxes.get(bid)
        if b is None:
            b = boxes[bid] = Box(bid)
        return b

    for s in sources:
        for bid, info in s.boxes.items():
            if (info.get("tier") or "delegate") == "delegate":
                box_for(bid).info = box_for(bid).info or info
    for g in grants:
        if g.shadowed_by is not None:
            continue
        for bid in g.boxes:
            box_for(bid).named_by.append(g)
    for bid in list(ledger.boxes):
        box_for(bid)
    named = {bid for g in grants for bid in g.boxes}
    for b in boxes.values():
        b.presence, b.how = _presence(b, sources, ledger, gone)
        if b.presence == "unknown":
            b.last = ledger.last_presence(b.id)
        b.covered_by = [g for g in b.named_by if g.status == "valid"]
        b.level, b.label = _severity(b, now)
        b.reason = b.label
        listing_src = b.listed_by[0][0] if b.listed_by else None
        ledger.record_box(b.id, grants=[g.gid for g in b.named_by if g.gid], presence=b.presence,
                          source=listing_src, level=b.level, how=b.how)
    ledger.prune_boxes(keep=named)
    rows = [b for b in boxes.values() if b.id in ledger.boxes or b.named_by or b.listed_by]
    rows.sort(key=lambda b: (LEVEL_RANK[b.level], b.id))
    board.boxes = rows
    return board


def open_sigcache(env):
    return SigCache(os.path.join(env.data, "sigcache.json")) if env.data else None
