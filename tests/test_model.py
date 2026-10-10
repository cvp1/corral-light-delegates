"""Plan §12.1: severity, binding, alarm continuity, exit, unknown, reuse,
revocation order, time bounds, clock, damage, completeness, inbox grants.
Signing is off in these cases (the signature cases are in test_charter)."""
import json
import os
import unittest

from helpers import DAY, HostCase, T0, box, grant, iso


class Severity(HostCase):
    def test_listed_and_covered_is_ok(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1")
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual((b.presence, b.level), ("listed", "ok"))
        self.assertEqual(grant(board, "local/cal-1").status, "valid")
        self.assertIn("covered by local/cal-1", b.label)

    def test_listed_and_uncovered_is_bad(self):
        self.h.boxes("rogue")
        board, _ = self.h.run()
        b = box(board, "declared/rogue")
        self.assertEqual(b.level, "bad")
        self.assertIn("no charter names this box", b.reason)

    def test_stale_listing_covered_is_warn(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"], generated_at=iso(T0 - 3 * 3600))
        self.h.charter("cal-1", box="ranch/cal-1-node")
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("listed-stale", "warn"))

    def test_stale_listing_uncovered_is_bad(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"], generated_at=iso(T0 - 3 * 3600))
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/cal-1-node").level, "bad")

    def test_never_listed_is_unknown_warn(self):
        self.h.charter("cal-1", box="ghost")
        board, _ = self.h.run()
        b = box(board, "declared/ghost")
        self.assertEqual((b.presence, b.level), ("unknown", "warn"))
        self.assertIn("never listed", b.label)

    def test_not_listed_is_info(self):
        self.h.boxes("cal-1")
        self.h.run()
        self.h.boxes()
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual((b.presence, b.level), ("not-listed", "info"))
        self.assertIn("removed from boxes.toml by hand", b.label)

    def test_fleet_tier_box_is_not_shown(self):
        self.h.boxes("srv", tier="fleet")
        board, _ = self.h.run()
        self.assertEqual([b.id for b in board.boxes], [])


class Binding(HostCase):
    def test_missing_box_is_bad_charter_and_covers_nothing(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", box=False)
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("box is missing", g.reason)
        self.assertEqual(box(board, "declared/cal-1").level, "bad")

    def test_misspelled_box_is_missing(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", box=False, extra="boxx: cal-1")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "bad-charter")
        self.assertEqual(box(board, "declared/cal-1").level, "bad")

    def test_rename_with_same_box_keeps_coverage(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1")
        self.h.run()
        self.h.remove_charter("cal-1")
        self.h.charter("cal-2", box="cal-1")
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual(b.level, "ok")
        self.assertIn("covered by local/cal-2", b.label)

    def test_bare_name_covers_declared_only(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1", "cal-1-node"])
        self.h.charter("cal-1", box="cal-1")
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/cal-1").level, "bad")
        self.assertEqual(box(board, "ranch/cal-1-node").level, "bad")
        self.assertEqual(box(board, "declared/cal-1").presence, "unknown")

    def test_qualified_list_covers_both_rows(self):
        self.h.boxes("cal-1")
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"])
        self.h.charter("cal-1", box="[cal-1, ranch/cal-1-node]")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "ok")
        self.assertEqual(box(board, "ranch/cal-1-node").level, "ok")
        self.assertEqual(grant(board, "local/cal-1").boxes, ["declared/cal-1", "ranch/cal-1-node"])

    def test_two_workers_under_two_sources_are_two_boxes(self):
        self.h.source("a")
        self.h.source("b")
        self.h.inbox_file("a", boxes=["worker"])
        self.h.inbox_file("b", boxes=["worker"])
        self.h.charter("w", box="a/worker")
        board, _ = self.h.run()
        self.assertEqual(box(board, "a/worker").level, "ok")
        self.assertEqual(box(board, "b/worker").level, "bad")

    def test_other_source_qualified_name_does_not_cover(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1"])
        self.h.charter("cal-1", box="gcp/cal-1")
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/cal-1").level, "bad")


class Continuity(HostCase):
    """Each case starts from a bad box; the level and the reason are asserted."""

    def start_declared(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", expires="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual(b.level, "bad")
        self.assertIn("expired", b.reason)
        return board

    def start_ranch(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"])
        self.h.charter("cal-1", box="ranch/cal-1-node", expires="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/cal-1-node").level, "bad")

    def test_charter_deleted(self):
        self.start_declared()
        self.h.remove_charter("cal-1")
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual(b.level, "bad")
        self.assertIn("charter removed", b.reason)
        self.assertEqual(grant(board, "local/cal-1").status, "ended:removed")

    def test_box_edited_away(self):
        self.start_declared()
        self.h.edit_charter("cal-1", "box: cal-1", "box: other")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")

    def test_status_changed_to_draft(self):
        self.start_declared()
        self.h.edit_charter("cal-1", "status: approved", "status: draft")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")

    def test_tier_removed(self):
        self.start_declared()
        self.h.boxes("cal-1", tier="fleet")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")

    def test_only_source_fails_with_last_good_copy(self):
        self.start_ranch()
        self.h.inbox_file("ranch", raw="{not json")
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("listed-stale", "bad"))
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertEqual(src.health, "failed")
        self.assertTrue(any("last good copy" in n for n in src.notes))

    def test_only_source_goes_stale(self):
        self.start_ranch()
        self.h.advance(3 * 3600)
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("listed-stale", "bad"))

    def test_source_removed_from_config(self):
        self.start_ranch()
        self.h.drop_source("ranch")
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("unknown", "bad"))
        self.assertIn("last listed", b.label)

    def test_over_cap_complete_file_omits_the_box(self):
        self.h.source("ranch", may_claim_complete="yes")
        self.h.inbox_file("ranch", boxes=["cal-1-node"], complete=True)
        self.h.charter("cal-1", box="ranch/cal-1-node", expires="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/cal-1-node").level, "bad")
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[f"b{i}" for i in range(2001)], complete=True)
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertFalse(src.complete)
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("unknown", "bad"))

    def test_converter_output_omits_the_box(self):
        self.start_ranch()
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[])
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("unknown", "bad"))

    def test_lowered_only_by_a_valid_grant(self):
        self.start_declared()
        # a renewal needs a newer issued (the expiry mark, §2.4)
        self.h.charter("cal-1", expires="2026-12-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")
        self.h.charter("cal-1", issued="2026-10-09T00:00:00Z", expires="2026-12-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "ok")

    def test_lowered_by_hand_removal_and_shown_in_sources(self):
        self.start_declared()
        self.h.boxes()
        board, snap = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual((b.presence, b.level), ("not-listed", "info"))
        src_table = next(x for x in snap["view"] if x.get("title", "").startswith("Sources"))
        self.assertTrue(any("removed from boxes.toml by hand" in r[-1] for r in src_table["rows"]))


class Exit(HostCase):
    def setUp(self):
        super().setUp()
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"])
        self.h.charter("cal-1", box="ranch/cal-1-node", expires="2026-10-01T00:00:00Z")
        self.h.run()

    def test_ranch_only_box_stays_at_last_presence_without_a_clock(self):
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[])
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("unknown", "bad"))
        self.assertIsNone(board.ledger.not_listed_since("ranch/cal-1-node"))

    def test_gone_moves_it_to_not_listed_and_starts_the_clock(self):
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[])
        self.h.run()
        rc, out = self.h.cli("gone", "ranch/cal-1-node", "--note", "terminated")
        self.assertEqual(rc, 0, out)
        board, snap = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("not-listed", "info"))
        self.assertIn("gone-record", b.label)
        self.assertIsNotNone(board.ledger.not_listed_since("ranch/cal-1-node"))
        src_table = next(x for x in snap["view"] if x.get("title", "").startswith("Sources"))
        self.assertTrue(any("gone-record" in r[-1] for r in src_table["rows"]))
        # the 30-day clock: the removed grant names the box for 30 days too
        self.h.remove_charter("cal-1")
        self.h.run()
        self.h.advance(31 * DAY)
        board, _ = self.h.run()
        self.assertNotIn("ranch/cal-1-node", board.ledger.boxes)
        self.assertNotIn("ranch/cal-1-node", [b.id for b in board.boxes])

    def test_gone_refuses_a_box_a_fresh_source_lists(self):
        rc, out = self.h.cli("gone", "ranch/cal-1-node")
        self.assertEqual(rc, 1)
        self.assertIn("ranch lists", out)
        self.assertFalse(os.path.exists(os.path.join(self.h.cfg, "gone.toml")))

    def test_gone_refuses_an_unknown_name(self):
        rc, out = self.h.cli("gone", "ranch/nothing")
        self.assertEqual(rc, 1)
        self.assertIn("not an in-scope box", out)

    def test_later_listing_reinstates(self):
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[])
        self.h.run()
        self.h.cli("gone", "ranch/cal-1-node")
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=["cal-1-node"])
        board, _ = self.h.run()
        b = box(board, "ranch/cal-1-node")
        self.assertEqual((b.presence, b.level), ("listed", "bad"))
        self.assertIn("listed again after the gone-record", b.label)


class Unknown(HostCase):
    def test_grant_expiry_reaches_an_unknown_box(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", expires=iso(T0 + DAY))
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "ok")
        self.h.remove_boxes_toml()
        self.h.advance(2 * DAY)
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual((b.presence, b.level), ("unknown", "bad"))
        self.assertIn("last listed 2 d ago", b.label)

    def test_a_valid_grant_reaches_an_unknown_box(self):
        self.h.boxes("rogue")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/rogue").level, "bad")
        self.h.remove_boxes_toml()
        self.h.charter("rogue")
        board, _ = self.h.run()
        b = box(board, "declared/rogue")
        self.assertEqual((b.presence, b.level), ("unknown", "ok"))
        self.assertIn("last listed", b.label)


class ReuseRename(HostCase):
    def test_grant_b_covers_after_a_ends(self):
        self.h.boxes("cal-1")
        self.h.charter("a", box="cal-1", expires="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")
        self.h.charter("b", box="cal-1")
        board, _ = self.h.run()
        b = box(board, "declared/cal-1")
        self.assertEqual(b.level, "ok")
        self.assertIn("covered by local/b", b.label)
        self.assertEqual(grant(board, "local/a").status, "ended:expired")
        self.h.remove_charter("a")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/a").status, "ended:removed")

    def test_grant_c_on_another_box_leaves_the_first_bad(self):
        self.h.boxes("cal-1", "cal-2")
        self.h.charter("a", box="cal-1", expires="2026-10-01T00:00:00Z")
        self.h.charter("c", box="cal-2")
        board, _ = self.h.run()
        self.assertEqual(box(board, "declared/cal-1").level, "bad")
        self.assertEqual(box(board, "declared/cal-2").level, "ok")


class Revocation(HostCase):
    T = "2026-10-05T00:00:00Z"

    def test_order_by_issued(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", status="revoked", issued=self.T)
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        self.assertEqual(board.ledger.tombstone("local/cal-1"), T0 - 5 * DAY - 12 * 3600)
        # restoring an older approved file
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        self.assertEqual(box(board, "declared/cal-1").level, "bad")
        # an equal issued
        self.h.charter("cal-1", issued=self.T)
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        # a later issued
        self.h.charter("cal-1", issued="2026-10-06T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "valid")
        self.assertEqual(box(board, "declared/cal-1").level, "ok")

    def test_tombstone_outlives_the_ledger_retention(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", status="revoked", issued=self.T)
        self.h.run()
        self.h.remove_charter("cal-1")
        self.h.boxes()
        self.h.run()
        self.h.advance(45 * DAY)
        board, _ = self.h.run()
        self.assertNotIn("declared/cal-1", board.ledger.boxes)
        self.assertEqual(board.ledger.tombstone("local/cal-1"), T0 - 5 * DAY - 12 * 3600)
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z", expires="2027-06-01")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")

    def test_same_name_in_two_sources_has_separate_tombstones(self):
        self.h.boxes("cal-1")
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["cal-1-node"], grants=[
            self.h.igrant("cal-1", "cal-1-node", issued=self.T, revoked_at="2026-10-06T00:00:00Z")])
        self.h.charter("cal-1", issued="2026-10-07T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "valid")
        self.assertEqual(grant(board, "ranch/cal-1").status, "ended:revoked")
        self.assertIsNotNone(board.ledger.tombstone("ranch/cal-1"))
        self.assertIsNone(board.ledger.tombstone("local/cal-1"))
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "ended:revoked")
        self.assertIn("per ranch", g.reason)


class TimeBounds(HostCase):
    def test_issued_after_expires(self):
        self.h.charter("cal-1", issued="2026-12-02T00:00:00Z", expires="2026-12-01T00:00:00Z")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("issued is later than expires", g.reason)

    def test_issued_ahead_of_now(self):
        self.h.charter("cal-1", issued=iso(T0 + 11 * 60))
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "bad-charter")
        self.h.charter("cal-1", issued=iso(T0 + 9 * 60))
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "valid")

    def test_future_issued_does_not_outrank_a_tombstone(self):
        self.h.charter("cal-1", status="revoked", issued=iso(T0 + 5 * 60))
        self.h.run()
        self.h.charter("cal-1", issued=iso(T0 + 11 * 60))
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "bad-charter")
        self.h.charter("cal-1", issued=iso(T0 + 5 * 60))
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")

    def test_expiry_mark_catches_a_changed_copy(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", issued="2026-09-01T00:00:00Z", expires="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:expired")
        self.h.charter("cal-1", issued="2026-09-01T00:00:00Z", expires="2027-01-01T00:00:00Z",
                       body="Different bytes.\n")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "ended:expired")
        self.assertIn("already ended", g.reason)
        self.assertEqual(box(board, "declared/cal-1").level, "bad")
        self.h.charter("cal-1", issued="2026-10-09T00:00:00Z", expires="2027-01-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "valid")

    def test_bare_dates(self):
        self.h.charter("cal-1", issued="2026-10-01", expires="2026-10-10")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "valid")
        self.assertEqual(g.expires, T0 + 11 * 3600 + 59 * 60 + 59)
        self.assertEqual(g.issued, T0 - 9 * DAY - 12 * 3600)

    def test_no_zone_is_bad_charter(self):
        self.h.charter("cal-1", expires="2026-12-01T00:00:00")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("no zone", g.reason)

    def test_offsets(self):
        self.h.charter("cal-1", issued="2026-10-01T00:00:00-0700", expires="2026-12-01T00:00:00+00:00")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "valid")
        self.assertEqual(g.issued, T0 - 9 * DAY - 5 * 3600)


class Clock(HostCase):
    def test_expiry_latches_when_the_clock_goes_back(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", expires=iso(T0 - 3600))
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:expired")
        board, _ = self.h.run(now=T0 - DAY)
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "ended:expired")
        self.assertIn("latched", g.reason)
        self.assertTrue(board.clock_warning)
        self.assertEqual(box(board, "declared/cal-1").level, "bad")


class Damage(HostCase):
    def test_corrupt_ledger_is_moved_aside_until_acknowledged(self):
        self.h.boxes("cal-1")
        self.h.run()
        with open(os.path.join(self.h.data, "ledger.json"), "w") as f:
            f.write("{corrupt")
        board, snap = self.h.run()
        rows = board.ledger.damage_rows()
        self.assertEqual(rows[0][0], "bad")
        self.assertIn("ledger damaged", rows[0][1])
        self.assertTrue(any(fn.startswith("ledger.json.damaged-") for fn in os.listdir(self.h.data)))
        board, _ = self.h.run()
        self.assertEqual(board.ledger.damage_rows()[0][0], "bad")
        before = set(os.listdir(self.h.data))
        rc, out = self.h.cli("ack-ledger")
        self.assertEqual(rc, 0)
        self.assertEqual(set(os.listdir(self.h.data)) - before, {"ledger.ack"})
        board, _ = self.h.run()
        self.assertEqual(board.ledger.damage_rows()[0][0], "info")

    def test_tombstones_are_salvaged_and_survive_ack(self):
        self.h.boxes("cal-1")
        self.h.charter("cal-1", status="revoked", issued="2026-10-05T00:00:00Z")
        self.h.charter("x", status="revoked", issued="2026-10-05T00:00:00Z")
        self.h.charter("y", status="revoked", issued="2026-10-05T00:00:00Z")
        self.h.run()
        p = os.path.join(self.h.data, "tombstones.jsonl")
        with open(p, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 3)
        lines[1] = "garbage line"
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self.h.remove_charter("x")
        self.h.remove_charter("y")
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        d = board.ledger.damage["tombstones"]
        self.assertEqual((d["salvaged"], d["of"]), (2, 3))
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        rc, _ = self.h.cli("ack-ledger")
        self.assertEqual(rc, 0)
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        self.assertEqual(len(board.ledger.tombstones), 2)


class Completeness(HostCase):
    def test_complete_claim_not_allowed_is_partial(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["a"], complete=True)
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertFalse(src.complete)
        self.assertTrue(any("not allowed" in n for n in src.notes))

    def test_cut_at_2000_rows_is_partial(self):
        self.h.source("ranch", may_claim_complete="yes")
        self.h.inbox_file("ranch", boxes=[f"b{i}" for i in range(2001)], complete=True)
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertFalse(src.complete)
        self.assertEqual(src.rows, 2000)

    def test_fresh_complete_omission_is_not_listed(self):
        self.h.source("ranch", may_claim_complete="yes")
        self.h.inbox_file("ranch", boxes=["a"], complete=True)
        self.h.charter("a", box="ranch/a")
        board, _ = self.h.run()
        self.assertEqual(box(board, "ranch/a").presence, "listed")
        self.h.advance(60)
        self.h.inbox_file("ranch", boxes=[], complete=True)
        board, _ = self.h.run()
        b = box(board, "ranch/a")
        self.assertEqual((b.presence, b.level), ("not-listed", "info"))
        self.assertIn("omitted by ranch", b.label)

    def test_complete_omission_beats_a_stale_listing(self):
        self.h.source("a", may_claim_complete="yes")
        self.h.source("b")
        self.h.inbox_file("a", boxes=["x"], complete=True)
        self.h.inbox_file("b", boxes=["x"])
        self.h.run()
        # b stops being fresh, a (complete) omits a/x; b lists its own b/x, a different box
        self.h.advance(60)
        self.h.inbox_file("a", boxes=[], complete=True)
        board, _ = self.h.run()
        self.assertEqual(box(board, "a/x").presence, "not-listed")

    def test_never_listed_is_unknown_not_not_listed(self):
        self.h.boxes("other")
        self.h.charter("a", box="a")
        board, _ = self.h.run()
        b = box(board, "declared/a")
        self.assertEqual((b.presence, b.level), ("unknown", "warn"))


class InboxGrants(HostCase):
    def setUp(self):
        super().setUp()
        self.h.source("ranch")

    def one(self, **kw):
        self.h.inbox_file("ranch", boxes=["n"], grants=[self.h.igrant("g", "n", **kw)])
        board, _ = self.h.run()
        return grant(board, "ranch/g"), box(board, "ranch/n")

    def test_valid_per_source(self):
        g, b = self.one()
        self.assertEqual(g.status, "valid")
        self.assertIn("per ranch", g.reason)
        self.assertEqual(b.level, "ok")

    def test_not_approved(self):
        g, b = self.one(approved=False)
        self.assertEqual((g.status, b.level), ("draft", "bad"))

    def test_signature_failed(self):
        g, b = self.one(signature="failed")
        self.assertEqual((g.status, b.level), ("bad-sig", "bad"))

    def test_signature_absent_and_unverified(self):
        for sig in ("absent", "unverified"):
            g, b = self.one(signature=sig)
            self.assertEqual((g.status, b.level), ("unsigned", "bad"), sig)

    def test_live_but_expired(self):
        g, b = self.one(expires="2026-10-01T00:00:00Z", state="LIVE")
        self.assertEqual((g.status, b.level), ("ended:expired", "bad"))

    def test_missing_grant_id_or_issued(self):
        g, b = self.one(gid=None, grant_id=None)
        self.assertEqual((g.status, b.level), ("bad-charter", "bad"))
        self.assertIn("grant_id", g.reason)
        g, b = self.one(issued=None)
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("issued", g.reason)

    def test_unknown_signature_value_fails_the_file(self):
        self.h.inbox_file("ranch", boxes=["n"], grants=[self.h.igrant("g", "n", signature="yes")])
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertEqual(src.health, "failed")
        self.assertTrue(any("signature 'yes'" in e for e in src.errors))

    def test_inbox_revocation_reaches_a_local_charter(self):
        self.h.boxes("cal-1")
        self.h.inbox_file("ranch", grants=[self.h.igrant("cal-1", "cal-1-node", issued="2026-10-05T00:00:00Z",
                                                          revoked_at="2026-10-06T00:00:00Z")])
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "ended:revoked")
        self.assertEqual(grant(board, "ranch/cal-1").shadowed_by.name, "cal-1")
        self.h.charter("cal-1", issued="2026-10-07T00:00:00Z")
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/cal-1").status, "valid")

    def test_earlier_expires_from_a_source_applies(self):
        self.h.boxes("cal-1")
        self.h.inbox_file("ranch", grants=[self.h.igrant("cal-1", "cal-1-node", issued="2026-10-05T00:00:00Z",
                                                          expires="2026-10-09T00:00:00Z")])
        self.h.charter("cal-1", issued="2026-10-01T00:00:00Z", expires="2026-12-01T00:00:00Z")
        board, _ = self.h.run()
        g = grant(board, "local/cal-1")
        self.assertEqual(g.status, "ended:expired")
        self.assertIn("per ranch", g.reason)

    def test_generated_at_in_the_future_fails_the_source(self):
        self.h.inbox_file("ranch", boxes=["n"], generated_at=iso(T0 + 11 * 60))
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertEqual(src.health, "failed")
        self.assertTrue(any("future" in e for e in src.errors))

    def test_colonless_offset_parses(self):
        self.h.inbox_file("ranch", boxes=["n"], generated_at="2026-10-10T04:59:00-0700")
        board, _ = self.h.run()
        src = next(s for s in board.sources if s.id == "ranch")
        self.assertEqual(src.health, "fresh")
        self.assertEqual(src.generated_at, T0 - 60)

    def test_undeclared_and_symlinked_files(self):
        self.h.inbox_file("ranch", boxes=["n"])
        self.h.inbox_file("x", boxes=["z"], file="stray.json")
        os.symlink(os.path.join(self.h.inbox, "ranch.json"), os.path.join(self.h.inbox, "link.json"))
        self.h.source("lk", file="link.json")
        board, _ = self.h.run()
        self.assertIn("stray.json", board.undeclared)
        self.assertEqual(next(s for s in board.sources if s.id == "lk").health, "failed")
        self.assertNotIn("lk/n", [b.id for b in board.boxes])


if __name__ == "__main__":
    unittest.main()
