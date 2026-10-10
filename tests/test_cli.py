"""The CLI verbs as Light runs them: setup, new, sign, check, show, doctor,
gone, ack-ledger."""
import json
import os
import unittest

import light_contract
from helpers import HAVE_KEYGEN, HostCase, NS, T0


class Setup(HostCase):
    def test_setup_writes_signers_with_namespaces_and_config(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN0rFbb/PHDnVKOOhNTaSy8D9DKt0u5PCmVSFO7EDaO4 craig@fleet"
        answers = iter([key, ""])
        rc, out = self.h.cli("setup", ask=lambda prompt: next(answers))
        self.assertEqual(rc, 0, out)
        with open(os.path.join(self.h.cfg, "allowed_signers"), encoding="utf-8") as f:
            line = f.read().strip()
        self.assertEqual(line, f'craig@fleet namespaces="{NS}" ssh-ed25519 '
                               "AAAAC3NzaC1lZDI1NTE5AAAAIN0rFbb/PHDnVKOOhNTaSy8D9DKt0u5PCmVSFO7EDaO4")
        with open(self.h.config_path, encoding="utf-8") as f:
            cfg = f.read()
        self.assertIn('require_signature = "yes"', cfg)
        self.assertIn('principal = "craig@fleet"', cfg)
        self.assertTrue(os.path.isdir(os.path.join(self.h.cfg, "inbox")))
        self.assertTrue(os.path.isdir(os.path.join(self.h.cfg, "charters")))

    def test_setup_without_a_key_leaves_signing_off(self):
        rc, out = self.h.cli("setup", ask=lambda prompt: "")
        self.assertEqual(rc, 0)
        self.assertIn("signing stays off", out)
        with open(self.h.config_path, encoding="utf-8") as f:
            self.assertIn('require_signature = "no"', f.read())

    def test_setup_rejects_a_non_key(self):
        rc, out = self.h.cli("setup", ask=lambda prompt: "not a key")
        self.assertEqual(rc, 1)
        self.assertIn("not a public key line", out)
        self.assertFalse(os.path.exists(os.path.join(self.h.cfg, "allowed_signers")))

    def test_setup_keeps_declared_sources(self):
        self.h.source("ranch")
        rc, _ = self.h.cli("setup", ask=lambda prompt: "")
        self.assertEqual(rc, 0)
        with open(self.h.config_path, encoding="utf-8") as f:
            self.assertIn('id = "ranch"', f.read())


class Verbs(HostCase):
    def test_new_and_sign(self):
        rc, out = self.h.cli("new", "cal-1")
        self.assertEqual(rc, 0, out)
        p = os.path.join(self.h.charters, "cal-1.md")
        self.assertTrue(os.path.exists(p))
        with open(p, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("name: cal-1", text)
        self.assertIn("box: cal-1", text)
        self.assertIn("issued: 2026-10-10T12:00:00Z", text)
        rc, out = self.h.cli("new", "cal-1")
        self.assertEqual(rc, 1)
        self.assertIn("not overwritten", out)
        rc, out = self.h.cli("sign", "cal-1")
        self.assertEqual(rc, 0)
        self.assertIn("ssh-keygen -Y sign -f KEYFILE -n " + NS + " " + p, out)
        self.assertIn("never signs", out)
        rc, out = self.h.cli("sign", "nope")
        self.assertEqual(rc, 1)

    def test_new_refuses_a_bad_name(self):
        rc, _ = self.h.cli("new", "Bad Name")
        self.assertEqual(rc, 2)

    def test_check_show_doctor(self):
        self.h.boxes("cal-1", "rogue")
        self.h.charter("cal-1")
        rc, out = self.h.cli("check")
        self.assertEqual(rc, 0)
        self.assertIn("local/cal-1", out)
        self.assertIn("declared/rogue", out)
        self.assertIn("1 without a valid grant", out)
        rc, out = self.h.cli("show", "--json")
        self.assertEqual(rc, 0)
        v, err = light_contract.validate_snapshot(out.encode(), notices=True)
        self.assertIsNone(err)
        rc, out = self.h.cli("show")
        self.assertIn("Boxes", out)
        rc, out = self.h.cli("doctor")
        self.assertEqual(rc, 0, out)
        self.assertIn("Delegates 0.1.0", out)
        self.assertIn("2 box(es) in scope, 1 without a valid grant", out)

    def test_cli_runs_do_not_write_the_ledger(self):
        self.h.boxes("cal-1")
        self.h.cli("show")
        self.h.cli("check")
        self.h.cli("doctor")
        self.assertFalse(os.path.exists(os.path.join(self.h.data, "ledger.json")))

    def test_doctor_warns_about_inbox_newer_than_the_run_after_setup(self):
        self.h.source("ranch")
        self.h.inbox_file("ranch", boxes=["n"])
        self.h.run()
        self.h.cli("setup", ask=lambda prompt: "", now=T0 + 10)
        self.h.inbox_file("ranch", boxes=["n", "m"])
        os.utime(os.path.join(self.h.inbox, "ranch.json"), (T0 + 60, T0 + 60))
        rc, out = self.h.cli("doctor", now=T0 + 120)
        self.assertIn("newer than the last collector run while `setup`", out)

    def test_ack_with_nothing_to_acknowledge(self):
        rc, out = self.h.cli("ack-ledger")
        self.assertEqual(rc, 0)
        self.assertIn("Nothing to acknowledge", out)
        self.assertFalse(os.path.exists(os.path.join(self.h.data, "ledger.ack")))

    def test_usage(self):
        rc, out = self.h.cli("help")
        self.assertEqual(rc, 0)
        self.assertIn("gone <source>/<name>", out)
        rc, _ = self.h.cli("bogus")
        self.assertEqual(rc, 2)


@unittest.skipUnless(HAVE_KEYGEN, "needs ssh-keygen on Linux")
class Doctor(HostCase):
    require_sig = True

    def test_doctor_reports_verification(self):
        rc, out = self.h.cli("doctor")
        self.assertEqual(rc, 0)
        self.assertIn("Signing required: yes", out)
        self.assertIn("ssh-keygen found", out)


if __name__ == "__main__":
    unittest.main()
