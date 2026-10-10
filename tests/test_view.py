"""Plan §12.1: truncation, notices, never zero; and the contract with Light
(the vendored validators)."""
import json
import os
import unittest

import light_contract
from helpers import ROOT, HostCase, iso, T0


class Contract(HostCase):
    def test_manifest_validates(self):
        with open(os.path.join(ROOT, "module.json"), encoding="utf-8") as f:
            m = light_contract.validate_manifest(json.load(f), root=light_contract.Path(ROOT))
        self.assertEqual(m["name"], "delegates")
        self.assertTrue(m["notices"])
        self.assertEqual(m["collector"]["every_s"], 300)

    def test_snapshots_validate_and_nothing_is_dropped(self):
        for populate in (False, True):
            if populate:
                self.h.boxes("cal-1", "rogue", cost="1.75")
                self.h.charter("cal-1", expires=iso(T0 + 3600))
                self.h.source("ranch")
                self.h.inbox_file("ranch", boxes=["n"], grants=[self.h.igrant("g", "n")])
            rc, raw = self.h.collect()
            self.assertEqual(rc, 0)
            v, err = light_contract.validate_snapshot(raw.encode(), notices=True)
            self.assertIsNone(err)
            self.assertTrue(v["ok"])
            self.assertNotIn("notices_dropped", v)
            self.assertFalse([b for b in v["view"] if "dropped" in b or b["type"] == "unsupported"])
            snap = json.loads(raw)
            self.assertEqual([n["id"] for n in v["notices"]], [n["id"] for n in snap["notices"]])
            for b in snap["view"]:
                for it in b.get("items", []):
                    self.assertIn(it["kind"], light_contract.KINDS)
                    self.assertIn(it["level"], light_contract.LEVELS)

    def test_collector_fails_closed_on_a_bad_data_dir(self):
        import io
        from delegates import main, util
        out = io.StringIO()
        env = util.Env(data=os.path.join(self.h.tmp, "nope", "x"), config=self.h.config_path, now=T0)
        os.makedirs(os.path.dirname(env.data))
        with open(env.data, "w") as f:
            f.write("a file, not a dir")
        rc = main.collector_main(["snapshot"], env=env, out=out)
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue(), "")


class Truncation(HostCase):
    def test_alarm_rows_fill_the_blocks_first(self):
        names = [f"a{i:03d}" for i in range(450)]
        self.h.boxes(*names)
        for n in names[210:]:
            self.h.charter(n)
        board, snap = self.h.run()
        tables = [b for b in snap["view"] if b["type"] == "table" and b["title"].startswith("Boxes")]
        self.assertEqual([t["title"] for t in tables], ["Boxes (1 of 3)", "Boxes (2 of 3)", "Boxes (3 of 3)"])
        rows = [r for t in tables for r in t["rows"]]
        self.assertEqual(len(rows), 450)
        self.assertEqual(len({r[0] for r in rows}), 450)
        self.assertTrue(all(r[3].startswith("bad") for r in rows[:210]))
        self.assertTrue(all(r[3].startswith("ok") for r in rows[210:]))
        self.assertEqual(snap["view"][0]["items"][1]["value"], "210")
        v, err = light_contract.validate_snapshot(json.dumps(snap).encode(), notices=True)
        self.assertIsNone(err)
        self.assertFalse([b for b in v["view"] if "dropped" in b])


class Notices(HostCase):
    def test_changed_set_with_same_count_is_a_new_id(self):
        self.h.boxes("a", "b")
        self.h.charter("b")
        _, s1 = self.h.run()                       # alarm set {declared/a}
        self.h.boxes("b", "c")
        _, s2 = self.h.run()                       # alarm set {declared/c}, same count
        self.assertEqual(len(s1["notices"]), 1)
        self.assertEqual(len(s2["notices"]), 1)
        self.assertNotEqual(s1["notices"][0]["id"], s2["notices"][0]["id"])
        self.assertTrue(s1["notices"][0]["id"].startswith("alarm."))

    def test_alarm_clears_with_the_condition(self):
        self.h.boxes("a")
        _, s1 = self.h.run()
        self.assertEqual(s1["notices"][0]["level"], "bad")
        self.h.charter("a")
        _, s2 = self.h.run()
        self.assertEqual(s2["notices"], [])

    def test_expiry_notice(self):
        self.h.boxes("a")
        self.h.charter("a", expires=iso(T0 + 41 * 3600))
        _, snap = self.h.run()
        n = snap["notices"]
        self.assertEqual(len(n), 1)
        self.assertEqual(n[0]["level"], "info")
        self.assertIn("in 41 h", n[0]["text"])
        self.assertEqual(n[0]["expires_at"], iso(T0 + 41 * 3600))

    def test_at_most_three_and_valid_ids(self):
        self.h.boxes("a", "b")
        self.h.charter("b", expires=iso(T0 + 3600))
        _, snap = self.h.run()
        self.assertLessEqual(len(snap["notices"]), 3)
        for n in snap["notices"]:
            self.assertRegex(n["id"], light_contract.NOTICE_ID_RE)

    def test_notices_off(self):
        self.h.write_config(notices="off")
        self.h.boxes("a")
        _, snap = self.h.run()
        self.assertNotIn("notices", snap)


class NeverZero(HostCase):
    def test_no_declared_cost_is_unreported(self):
        self.h.boxes("a")
        _, snap = self.h.run()
        tile = snap["view"][0]["items"][-1]
        self.assertEqual((tile["value"], tile["kind"]), ("unreported", "unknown"))
        self.h.boxes("a", cost="5")
        _, snap = self.h.run()
        tile = snap["view"][0]["items"][-1]
        self.assertEqual((tile["value"], tile["kind"]), ("$5.00 / mo", "declared"))


if __name__ == "__main__":
    unittest.main()
