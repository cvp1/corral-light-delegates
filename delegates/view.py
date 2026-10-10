"""The snapshot (corral-light.module/1): typed blocks only, every value text
(plan §5). Null is unreported, never zero."""
import hashlib
import re

from delegates import util
from delegates.model import LEVEL_RANK, STATUS_RANK

SCHEMA = "corral-light.module/1"
DOCS = "https://github.com/cvp1/corral-light-delegates#how-the-board-is-made"
MAX_ROWS = 200
HONESTY = ("\"Box listed\" means a source says a box exists. It does not mean the box is "
           "up, is the machine the charter meant, or obeys the charter.")
_NOTICE_BAD = re.compile(r"[^a-z0-9._-]")


def notice_id(*parts):
    whole = _NOTICE_BAD.sub("-", ".".join(str(p) for p in parts).lower())
    if len(whole) <= 64:
        return whole
    return whole[:55] + "-" + hashlib.sha256(whole.encode()).hexdigest()[:8]


def _gen(ids):
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()[:12]


def _split(title, columns, rows, alarm_first=None):
    """Tables of at most MAX_ROWS rows; alarm rows fill the blocks first."""
    if not rows:
        return [{"type": "table", "title": title, "columns": columns, "rows": [["none"] + [""] * (len(columns) - 1)]}]
    blocks = [rows[i:i + MAX_ROWS] for i in range(0, len(rows), MAX_ROWS)]
    out = []
    for i, chunk in enumerate(blocks, 1):
        t = title if len(blocks) == 1 else f"{title} ({i} of {len(blocks)})"
        out.append({"type": "table", "title": t, "columns": columns, "rows": chunk})
    return out


def _money(v):
    return f"${v} / mo"


def notices(board):
    out = []
    alarms = board.alarms()
    if alarms:
        ids = [b.id for b in alarms]
        out.append({"id": notice_id("alarm", _gen(ids)), "level": "bad",
                    "title": (f"{len(ids)} box listed without a valid grant" if len(ids) == 1
                              else f"{len(ids)} boxes listed without a valid grant")[:80],
                    "text": "; ".join(f"{b.id}: {b.reason}" for b in alarms)[:300]})
    exp = board.expiring()
    if exp:
        ids = [g.gid or g.qname for g in exp]
        out.append({"id": notice_id("expiry", _gen(ids)), "level": "info",
                    "title": (f"{len(exp)} grant expires within 72 h" if len(exp) == 1
                              else f"{len(exp)} grants expire within 72 h")[:80],
                    "text": "; ".join(f"{g.qname} {util.in_text(g.expires_eff - board.now)}"
                                      for g in exp)[:300],
                    "expires_at": util.utc_iso(min(g.expires_eff for g in exp))})
    return out


def build(env, cfg, board, ledger):
    now = board.now
    gen = util.utc_iso(now)
    boxes, grants = board.boxes, board.grants
    alarms = board.alarms()
    covered = [b for b in boxes if b.level == "ok"]
    unknown = [b for b in boxes if b.presence == "unknown"]
    expiring = board.expiring()
    bad_sources = [s for s in board.sources if s.health == "failed" or s.errors
                   or (s.health == "missing" and s.kind == "inbox")]
    view = []

    # ── tiles ──
    if board.cannot_verify:
        cov_note = "signatures unverifiable on this host (no subprocess in the macOS sandbox); " + HONESTY
    elif not board.signing_required:
        cov_note = "covered (unsigned charters); " + HONESTY
    else:
        cov_note = HONESTY
    tiles = [{"label": "Covered boxes", "value": str(len(covered)), "kind": "declared",
              "level": "ok" if covered and not alarms else "info", "note": cov_note, "fresh_at": gen},
             {"label": "Boxes listed without a valid grant", "value": str(len(alarms)),
              "kind": "declared", "level": "bad" if alarms else "ok",
              "note": "; ".join(b.id for b in alarms)[:400] or "every listed box is covered",
              "fresh_at": gen},
             {"label": "Boxes unknown", "value": str(len(unknown)), "kind": "declared",
              "level": "warn" if any(b.level in ("warn", "bad") for b in unknown) else "info",
              "note": "no fresh complete source speaks for them" if unknown else "", "fresh_at": gen},
             {"label": "Grants expiring within 72 h", "value": str(len(expiring)), "kind": "declared",
              "level": "info", "note": "; ".join(g.qname for g in expiring)[:400], "fresh_at": gen},
             {"label": "Sources with problems", "value": str(len(bad_sources)), "kind": "declared",
              "level": "warn" if bad_sources else "ok",
              "note": "; ".join(s.label for s in bad_sources)[:400], "fresh_at": gen}]
    declared_cost = []
    for b in boxes:
        c = (b.info or {}).get("cost")
        if c and c.get("kind") == "declared" and b.presence in ("listed", "listed-stale"):
            try:
                declared_cost.append(float(c["usd_month"]))
            except (TypeError, ValueError):
                pass
    if declared_cost:
        tiles.append({"label": "Declared monthly cost", "value": _money(f"{sum(declared_cost):,.2f}"),
                      "kind": "declared", "level": "info",
                      "note": f"from boxes.toml, {len(declared_cost)} listed box(es)", "fresh_at": gen})
    else:
        tiles.append({"label": "Declared monthly cost", "value": "unreported", "kind": "unknown",
                      "level": "info", "note": "no listed box has a cost in boxes.toml", "fresh_at": gen})
    view.append({"type": "tiles", "items": tiles})

    # ── boxes ──
    rows = []
    for b in boxes:
        presence = b.presence
        if b.presence == "unknown" and b.last is not None and b.last["at"]:
            presence = f"unknown (last listed {util.age_text(now - b.last['at'])} ago)"
        rows.append([b.id, presence, ", ".join(g.qname for g in b.covered_by) or "-",
                     f"{b.level}: {b.label}", b.sources_text(now)])
    view += _split("Boxes", ["Box", "Presence", "Covered by", "Level and reason", "Sources"], rows)

    # ── grants ──
    grows = []
    for g in sorted(grants, key=lambda g: (STATUS_RANK.get(g.status, 9), g.qname)):
        status = g.status
        if g.shadowed_by is not None:
            status += " (shadowed by a local charter)"
        if g.reports:
            status += (f"; source reports approved={'yes' if g.reports.get('approved') else 'no'}, "
                       f"signature {g.reports.get('signature')}"
                       + (f", state {g.reports['reports_state']}" if g.reports.get("reports_state") else ""))
        exp = ""
        if g.expires_eff is not None:
            exp = util.utc_iso(g.expires_eff) + " (" + util.in_text(g.expires_eff - now) + ")"
            if g.expires_per:
                exp += f" per {g.expires_per}"
        for bid in g.boxes or ["-"]:
            grows.append([g.name or "?", util.short_id(g.gid), status + (f": {g.reason}" if g.reason and g.reason != status else ""),
                          util.utc_iso(g.issued) if g.issued is not None else "-", exp or "-", bid,
                          _money(g.cost) if g.cost else "unreported", g.source])
    view += _split("Grants", ["Name", "Grant id", "Status", "Issued", "Expires", "Box", "Cost", "Source"], grows)

    # ── sources ──
    srows = []
    for s in board.sources:
        state = s.health + (", complete" if s.complete else ", partial" if s.health in ("fresh", "stale") else "")
        detail = "; ".join(s.errors + s.notes)
        srows.append([s.label, state, s.age_text(now), f"{len(s.boxes)} boxes, {len(s.grants)} grants",
                      detail[:400] or "-"])
    srows.append(["charters", "fresh" if board.charters_source.health == "fresh" else board.charters_source.health,
                  "-", f"{board.charters_source.rows} files",
                  "; ".join(board.charters_source.errors + board.charters_source.notes)[:400] or "-"])
    srows.append(["ledger", "ok", "-", ledger.size_text(), "-"])
    for level, text in ledger.damage_rows():
        srows.append(["ledger", level, "-", "-", text])
    for b in boxes:
        since = ledger.not_listed_since(b.id)
        if b.presence == "not-listed" and since is not None and now - since <= util.SHOW_REMOVAL_S:
            srows.append(["operator", "info", util.age_text(now - since) + " ago", b.id, b.how])
    for bid, g in sorted(board.gone.items()):
        if now - g["at"] <= util.SHOW_REMOVAL_S and not any(b.id == bid and b.presence == "not-listed" for b in boxes):
            srows.append(["operator", "info", util.age_text(now - g["at"]) + " ago", bid,
                          f"gone-record of {util.utc_date(g['at'])}" + (": " + g["note"] if g.get("note") else "")])
    for e in board.gone_errors:
        srows.append(["gone.toml", "bad", "-", "-", e])
    for fn in board.undeclared:
        srows.append(["inbox", "info", "-", fn, "undeclared file; ignored"])
    if board.clock_warning:
        srows.append(["clock", "warn", "-", "-", "this host's clock is behind the last run; countdowns are uncertain"])
    if board.cannot_verify:
        srows.append(["signatures", "warn", "-", "-",
                      "cannot verify on this host: the macOS sandbox allows no child process, so every "
                      "signed charter reads bad-sig until the core-provided verifier (plan Phase 2)"])
    if board.config_error:
        srows.append(["config", "bad", "-", "-", board.config_error[:400]])
    view += _split("Sources", ["Source", "State", "Age", "Rows", "Detail"], srows)

    # ── notes ──
    notes = [HONESTY]
    if board.cannot_verify:
        notes.append("Signatures are not verified on this host in v1 (macOS sandbox); nothing is valid here "
                     "until Phase 2 or until the module runs on Linux.")
    if not board.signing_required:
        notes.append("Signing is off: charters are taken as approved without a signature. "
                     "Run `corral-light delegates setup` to require signatures.")
    if board.clock_warning:
        notes.append("Clock uncertain: this host's clock is behind the last run.")
    if not env.sandboxed:
        notes.append("This module runs unsandboxed on this host (acknowledged at install).")
    if board.config_error:
        notes.append(board.config_error)
    notes.append("The board is not proof. Every row names its sources and their ages.")
    for n in notes:
        view.append({"type": "note", "text": n[:500], "level": "info"})
    view.append({"type": "link", "label": "How the board is made", "url": DOCS})

    snap = {"schema": SCHEMA, "ok": True, "generated_at": gen, "error": None, "view": view}
    if getattr(cfg, "notices", "on") != "off":
        snap["notices"] = notices(board)
    return snap


def render_text(snap):
    lines = []
    for b in snap["view"]:
        t = b["type"]
        if t == "tiles":
            for it in b["items"]:
                lines.append(f"{it['label']:36} {it['value']:12} [{it['level']}] {it['note']}")
        elif t == "table":
            lines += ["", b["title"]]
            for r in [b["columns"]] + b["rows"]:
                lines.append("  " + " | ".join(str(c) for c in r))
        elif t == "note":
            lines.append("- " + b["text"])
        elif t == "link":
            lines.append(f"{b['label']}: {b['url']}")
    if snap.get("notices"):
        lines += ["", "Notices"]
        for n in snap["notices"]:
            lines.append(f"  [{n['level']}] {n['title']}: {n['text']}")
    return "\n".join(lines)
