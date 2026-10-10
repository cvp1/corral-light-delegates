#!/usr/bin/env python3
"""Turn the ranch's `delegates/status.py --json` into a Delegates inbox file
(plan §4.3). Runs on the ranch, beside `charters/`, from its own cron.

    python3 ranch_status_to_inbox.py --charters /path/to/charters \\
        --out /path/to/inbox/ranch.json \\
        --run python3 /path/to/delegates/status.py --json

or with the JSON already in hand:

    python3 status.py --json | python3 ranch_status_to_inbox.py --charters ... --out ... --stdin

What it does, and does not:
- reads each row's charter file once: its bytes give `grant_id`, its
  `created` key gives `issued`. A charter it cannot read gives a grant
  with null `grant_id` and `issued`, which the module reports as
  bad-charter;
- never writes `"complete": true`: status.py lists charters, not boxes;
- maps approval_signed -> approved; sig_ok -> verified, signed and not
  sig_ok -> failed, not signed -> absent;
- turns `last_event: revoke <stamp>` into revoked_at, parsing both the
  RFC 3339 and the compact `2026-08-16T000000Z` forms;
- passes `expires` through as given (an unparseable one is bad-charter
  at the module, a known difference from full Corral);
- on a non-zero status.py, leaves the previous output in place and exits
  non-zero itself, so the cron log carries the error.

Stdlib only; Python 3.9+.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = "corral-light.delegates.inbox/1"
_COMPACT = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})T(\d{2}):?(\d{2}):?(\d{2})(Z|[+-]\d{2}:?\d{2})?$")
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_KEY = re.compile(r"^([A-Za-z0-9_-]+):(?:[ \t]+(.*))?$")


def iso_utc(stamp):
    """Any of the ranch's time forms -> RFC 3339 Z, or None."""
    if not isinstance(stamp, str):
        return None
    s = stamp.strip()
    m = _DATE.match(s)
    if m:
        return f"{s}T00:00:00Z"
    m = _COMPACT.match(s)
    if not m:
        return None
    y, mo, d, h, mi, sec, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        from datetime import timedelta
        dt -= sign * timedelta(hours=hh, minutes=mm)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_charter(path):
    """-> (grant_id, created) from the charter file, or (None, None)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None, None
    gid = "sha256:" + hashlib.sha256(data).hexdigest()
    created = None
    text = data.decode("utf-8", "replace").replace("\r\n", "\n")
    if text.startswith("---\n"):
        fm = text[4:].split("\n---", 1)[0]
        for line in fm.split("\n"):
            m = _KEY.match(line.rstrip())
            if m and m.group(1).replace("_", "-") == "created":
                created = (m.group(2) or "").strip().strip('"')
                break
    return gid, created


def convert(rows, charters_dir, generated_at):
    boxes, grants = [], []
    for r in rows:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str):
            continue
        name = r["name"]
        box = r.get("box") if isinstance(r.get("box"), dict) else None
        box_name = box.get("manifest_key") if box else None
        if box and isinstance(box_name, str):
            boxes.append({"name": box_name, "tier": box.get("tier") or "",
                          "provider": box.get("domain") or "", "since": "",
                          "cost": _cost(r)})
        gid, created = read_charter(os.path.join(charters_dir, r.get("charter") or f"{name}.md"))
        issued = iso_utc(created) if created else None
        if created and issued is None:
            issued = created                      # let the module judge it
        signed, sig_ok = r.get("signed") is True, r.get("sig_ok") is True
        signature = "verified" if sig_ok else ("failed" if signed else "absent")
        revoked_at = None
        le = r.get("last_event")
        if isinstance(le, str) and le.startswith("revoke"):
            parts = le.split(None, 1)
            revoked_at = iso_utc(parts[1]) if len(parts) > 1 else generated_at
            if revoked_at is None:
                revoked_at = generated_at
        grants.append({"name": name, "grant_id": gid, "issued": issued,
                       "expires": r.get("expires"), "box": box_name,
                       "approved": r.get("approval_signed") is True, "signature": signature,
                       "revoked_at": revoked_at, "reports_state": r.get("state") or "",
                       "budget_usd": r.get("budget_usd"), "capabilities": r.get("capabilities")})
    return {"schema": SCHEMA, "generated_at": generated_at, "complete": False,
            "boxes": boxes, "grants": grants}


def _cost(row):
    spend = row.get("spend") if isinstance(row.get("spend"), dict) else {}
    b = spend.get("box") if isinstance(spend.get("box"), dict) else {}
    amt = b.get("amount_usd")
    if isinstance(amt, (int, float)) and not isinstance(amt, bool):
        return {"usd_month": f"{amt:.2f}", "kind": "vendor", "as_of": b.get("as_of") or ""}
    return None


def atomic_write(path, text):
    d = os.path.dirname(path) or "."
    tmp = os.path.join(d, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--charters", required=True, help="the ranch's charters/ folder")
    ap.add_argument("--out", required=True, help="the inbox file to write")
    ap.add_argument("--stdin", action="store_true", help="read status.py --json from stdin")
    ap.add_argument("--run", nargs=argparse.REMAINDER, help="command that prints status.py --json")
    a = ap.parse_args(argv)
    if a.run:
        p = subprocess.run(a.run, capture_output=True, timeout=60, check=False)
        if p.returncode != 0:
            print(f"ranch_status_to_inbox: status.py exited {p.returncode}; previous output kept",
                  file=sys.stderr)
            print(p.stderr.decode("utf-8", "replace")[-500:], file=sys.stderr)
            return 1
        raw = p.stdout
    elif a.stdin:
        raw = sys.stdin.buffer.read()
    else:
        ap.error("give --run CMD... or --stdin")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        print("ranch_status_to_inbox: status.py output is not JSON; previous output kept",
              file=sys.stderr)
        return 1
    rows = doc.get("delegates") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        print("ranch_status_to_inbox: no delegates list; previous output kept", file=sys.stderr)
        return 1
    gen = iso_utc(doc.get("generated_at")) if isinstance(doc, dict) else None
    gen = gen or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = convert(rows, a.charters, gen)
    atomic_write(a.out, json.dumps(out, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
