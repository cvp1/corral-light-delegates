"""Plan §12.1 "Converter": the ranch fixture through ranch_status_to_inbox.py
and the board, with the two known differences asserted by name."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import ROOT, HostCase, box, grant, ts

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                       "ranch-status-fixture.json")
SCRIPT = os.path.join(ROOT, "contrib", "ranch_status_to_inbox.py")
spec = importlib.util.spec_from_file_location("ranch_status_to_inbox", SCRIPT)
conv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(conv)

def expect(row):
    """Full Corral's state for a fixture row -> (grant status here, box level
    here). The selftest fixture refuses every signature, so each signed row
    is `bad-sig` here (§2.1 puts it before the ended states); a live box with
    a refused signature is `bad` on both boards."""
    if row["signed"] and not row["sig_ok"]:
        return "bad-sig", "bad"
    if row["state"] == "DRAFTED":
        return "unsigned", None
    return {"REVOKED": "ended:revoked", "EXPIRED": "ended:expired"}[row["state"]], None


def write_charters(d, rows, created="2025-06-01"):
    os.makedirs(d, exist_ok=True)
    for r in rows:
        with open(os.path.join(d, r["charter"]), "w", encoding="utf-8") as f:
            f.write(f"---\nname: {r['name']}\ncreated: {created}\nexpires: {r['expires'] or '2026-01-01'}\n"
                    f"approval: signed\n---\n\nFixture charter.\n")


class Converter(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, encoding="utf-8") as f:
            self.doc = json.load(f)
        self.tmp = tempfile.mkdtemp(prefix="conv-")
        self.charters = os.path.join(self.tmp, "charters")
        write_charters(self.charters, self.doc["delegates"])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_shape_and_value_types(self):
        out = conv.convert(self.doc["delegates"], self.charters, conv.iso_utc(self.doc["generated_at"]))
        self.assertEqual(out["schema"], "corral-light.delegates.inbox/1")
        self.assertFalse(out["complete"])
        self.assertEqual(out["generated_at"], "2026-10-10T00:59:49Z")      # -0700, colon-less
        self.assertEqual(len(out["grants"]), 16)
        self.assertEqual(sorted(b["name"] for b in out["boxes"]),
                         ["badprice-1-node", "dupbox-1-node", "gcp-live-1", "live-1-node",
                          "overdue-1-node", "priced-1-node"])
        by = {g["name"]: g for g in out["grants"]}
        self.assertEqual(by["revoked-1"]["revoked_at"], "2026-08-16T00:00:00Z")
        self.assertEqual(by["overdue-1"]["budget_usd"], "5")
        self.assertIsNone(by["overdue-1"]["capabilities"])
        self.assertEqual(by["overdue-1"]["signature"], "failed")
        self.assertEqual(by["drafted-1"]["signature"], "absent")
        self.assertTrue(by["overdue-1"]["approved"])
        self.assertTrue(all(g["grant_id"].startswith("sha256:") for g in out["grants"]))
        self.assertTrue(all(g["issued"] == "2025-06-01T00:00:00Z" for g in out["grants"]))
        self.assertEqual(by["overdue-1"]["box"], "overdue-1-node")
        self.assertIsNone(by["revoked-1"]["box"])

    def test_missing_charter_gives_null_grant_id_and_issued(self):
        os.unlink(os.path.join(self.charters, "soon-1.md"))
        out = conv.convert(self.doc["delegates"], self.charters, "2026-10-10T00:00:00Z")
        g = next(g for g in out["grants"] if g["name"] == "soon-1")
        self.assertIsNone(g["grant_id"])
        self.assertIsNone(g["issued"])

    def test_compact_and_rfc_stamps(self):
        self.assertEqual(conv.iso_utc("2026-08-16T000000Z"), "2026-08-16T00:00:00Z")
        self.assertEqual(conv.iso_utc("20260816T000000Z"), "2026-08-16T00:00:00Z")
        self.assertEqual(conv.iso_utc("2026-08-16T00:00:00Z"), "2026-08-16T00:00:00Z")
        self.assertEqual(conv.iso_utc("2026-08-16T00:00:00-0700"), "2026-08-16T07:00:00Z")
        self.assertEqual(conv.iso_utc("2026-08-16"), "2026-08-16T00:00:00Z")
        self.assertIsNone(conv.iso_utc("garbage"))

    def test_nonzero_status_keeps_the_previous_file(self):
        out = os.path.join(self.tmp, "ranch.json")
        with open(out, "w") as f:
            f.write("previous")
        p = subprocess.run([sys.executable, "-I", SCRIPT, "--charters", self.charters, "--out", out,
                            "--run", sys.executable, "-c", "import sys; sys.exit(2)"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("exited 2", p.stderr)
        with open(out) as f:
            self.assertEqual(f.read(), "previous")

    def test_run_writes_the_file(self):
        out = os.path.join(self.tmp, "ranch.json")
        p = subprocess.run([sys.executable, "-I", SCRIPT, "--charters", self.charters, "--out", out,
                            "--stdin"], input=json.dumps(self.doc), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(out) as f:
            self.assertEqual(json.load(f)["schema"], "corral-light.delegates.inbox/1")


class Board(HostCase):
    """The converted fixture through the module: levels match full Corral's
    except the two known differences."""

    def setUp(self):
        super().setUp()
        with open(FIXTURE, encoding="utf-8") as f:
            self.doc = json.load(f)
        self.charters = os.path.join(self.h.tmp, "ranch-charters")
        write_charters(self.charters, self.doc["delegates"])
        self.h.source("ranch")

    def feed(self, rows, now=None):
        gen = "2026-10-10T11:59:00Z"
        out = conv.convert(rows, self.charters, gen)
        self.h.inbox_file("ranch", raw=json.dumps(out))
        board, _ = self.h.run(now=now or ts("2026-10-10T12:00:00Z"))
        return board

    def test_levels_match_full_corral_with_known_differences(self):
        board = self.feed(self.doc["delegates"])
        for r in self.doc["delegates"]:
            g = grant(board, f"ranch/{r['name']}")
            if r["name"] == "naive-1":
                self.assertEqual(g.status, "bad-charter", "known difference: unparseable expires")
                self.assertIn("expires", g.reason)
                continue
            want_status, want_box = expect(r)
            self.assertEqual(g.status, want_status, r["name"])
            if r["box"]:
                self.assertEqual(box(board, f"ranch/{r['box']['manifest_key']}").level, want_box, r["name"])

    def test_unapproved_with_a_live_box_is_bad_here(self):
        rows = json.loads(json.dumps(self.doc["delegates"]))
        row = next(r for r in rows if r["name"] == "unapproved-1")
        self.assertIsNone(row["box"])                       # as captured
        row["box"] = {"tier": "delegate", "ip": "1.2.3.9", "domain": "gcp", "manifest_key": "unapproved-1"}
        row["sig_ok"], row["state"], row["approval_signed"] = True, "LIVE", False
        board = self.feed(rows)
        g = grant(board, "ranch/unapproved-1")
        self.assertEqual(g.status, "draft")
        self.assertEqual(box(board, "ranch/unapproved-1").level, "bad")

    def test_passing_signatures_give_the_ended_states(self):
        rows = json.loads(json.dumps(self.doc["delegates"]))
        for r in rows:
            if r["name"] in ("revoked-1", "expired-1"):
                r["sig_ok"] = True
        board = self.feed(rows)
        self.assertEqual(grant(board, "ranch/revoked-1").status, "ended:revoked")
        self.assertEqual(grant(board, "ranch/expired-1").status, "ended:expired")
        self.assertEqual(grant(board, "ranch/revoked-1").boxes, [])

    def test_a_passing_signature_covers_its_box(self):
        rows = json.loads(json.dumps(self.doc["delegates"]))
        row = next(r for r in rows if r["name"] == "live-1")
        row["sig_ok"], row["state"], row["expires"] = True, "LIVE", "2027-01-01T00:00:00Z"
        write_charters(self.charters, [row])
        board = self.feed(rows)
        self.assertEqual(grant(board, "ranch/live-1").status, "valid")
        self.assertEqual(box(board, "ranch/live-1-node").level, "ok")


if __name__ == "__main__":
    unittest.main()
