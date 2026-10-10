"""Plan §12.1: grammar, and signatures with real ssh-keygen (Linux)."""
import os
import subprocess
import unittest
from unittest import mock

from helpers import HAVE_KEYGEN, HostCase, KEYGEN, NS, box, grant
from delegates import charter


class Grammar(HostCase):
    def status(self, **kw):
        self.h.charter("c", **kw)
        board, _ = self.h.run()
        return grant(board, "local/c")

    def test_other_keys_are_accepted(self):
        extra = "\n".join(f"{k}: v" for k in ("note", "date", "lane", "job", "log", "os", "boxes",
                                              "bot", "mission", "payload", "ssh-key-file"))
        g = self.status(extra=extra)
        self.assertEqual(g.status, "valid")
        self.assertEqual(sorted(g.other), sorted(["note", "date", "lane", "job", "log", "os",
                                                  "boxes", "bot", "mission", "payload", "ssh-key-file"]))

    def test_capitalised_key_is_bad(self):
        g = self.status(extra="Status: approved")
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("malformed key line", g.reason)

    def test_duplicate_after_folding(self):
        g = self.status(extra="data_class: a\ndata-class: b")
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("duplicate key data-class", g.reason)

    def test_missing_required_keys(self):
        for key in ("issued", "expires", "box"):
            g = self.status(omit=(key,))
            self.assertEqual(g.status, "bad-charter", key)
            self.assertIn(f"{key} is missing", g.reason)
        g = self.status(status=None)
        self.assertEqual(g.status, "bad-charter")
        self.assertIn("neither status nor approval", g.reason)

    def test_ranch_approval_markers_are_draft(self):
        for a in (">", "|", "", "unsigned", "pending", "proposed"):
            g = self.status(status=None, approval=a)
            self.assertEqual(g.status, "draft", repr(a))
        g = self.status(status=None, approval="signed 2026-10-01 by hand")
        self.assertEqual(g.status, "valid")

    def test_more_restrictive_wins(self):
        g = self.status(status="approved", approval="pending")
        self.assertEqual(g.status, "draft")

    def test_name_must_match_filename(self):
        self.h.charter("c", raw="---\nname: d\nstatus: approved\nissued: 2026-10-01\nexpires: 2026-12-01\nbox: c\n---\n")
        board, _ = self.h.run()
        self.assertIn("differs from the filename", grant(board, "local/c").reason)

    def test_comments_and_quoted_values(self):
        g = self.status(extra='# a comment\ncost-note: "quoted, with comma"\ncapabilities: [a, "b c"]')
        self.assertEqual(g.status, "valid")

    def test_companion_files_are_ignored(self):
        with open(os.path.join(self.h.charters, "c.manifest.md"), "w") as f:
            f.write("not a charter")
        self.h.charter("c")
        board, _ = self.h.run()
        self.assertEqual([g.name for g in board.grants], ["c"])

    def test_bad_status_value(self):
        g = self.status(status="live")
        self.assertEqual(g.status, "bad-charter")

    def test_parse_front_matter_shapes(self):
        p = charter.parse(b"no front matter")
        self.assertTrue(p["errors"])
        p = charter.parse(b"---\nname: a\n---")
        self.assertEqual(p["keys"], {"name": "a"})
        p = charter.parse(b"---\n---\nbody")
        self.assertEqual((p["keys"], p["body"]), ({}, "body"))
        p = charter.parse("---\nname: \xff\n---\n".encode("latin-1"))
        self.assertIn("not UTF-8", p["errors"][0])


@unittest.skipUnless(HAVE_KEYGEN, "needs ssh-keygen on Linux (v1 verifies on Linux only)")
class Signatures(HostCase):
    require_sig = True

    def run_one(self, name="c"):
        board, _ = self.h.run()
        return grant(board, f"local/{name}")

    def test_good_signature_is_valid(self):
        self.h.boxes("c")
        self.h.charter("c")
        g = self.run_one()
        self.assertEqual((g.status, g.sig), ("valid", "verified"))

    def test_body_byte_changed(self):
        self.h.charter("c")
        self.h.edit_charter("c", "Purpose.", "Purpose!")
        g = self.run_one()
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("signature fails", g.reason)

    def test_front_matter_byte_changed(self):
        self.h.charter("c")
        self.h.edit_charter("c", "expires: 2026-12-01", "expires: 2027-12-01")
        self.assertEqual(self.run_one().status, "bad-sig")

    def test_wrong_namespace(self):
        self.h.charter("c", sign=False)
        self.h.sign("c", namespace="cc-handoff")
        self.assertEqual(self.run_one().status, "bad-sig")

    def test_unknown_signer(self):
        self.h.charter("c")
        self.h.write_config(principal="nobody@fleet")
        g = self.run_one()
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("principal not in allowed_signers", g.reason)

    def test_signers_line_without_namespaces_is_refused_by_the_module(self):
        self.h.charter("c")
        self.h.write_signers(namespaces=None)
        g = self.run_one()
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("no namespaces=", g.reason)
        # ssh-keygen alone accepts it for the signed namespace (Phase 0b)
        p = subprocess.run([KEYGEN, "-Y", "verify", "-f", self.h.cfg + "/allowed_signers", "-I",
                            "tester@local", "-n", NS, "-s", self.h.charters + "/c.md.sig"],
                           input=open(self.h.charters + "/c.md", "rb").read(), capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_signers_namespace_mismatch(self):
        self.h.charter("c")
        self.h.write_signers(namespaces="cc-handoff")
        g = self.run_one()
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("does not allow namespace", g.reason)

    def test_crlf_copy_of_an_lf_signed_file_fails(self):
        self.h.charter("c")
        p = os.path.join(self.h.charters, "c.md")
        with open(p, "rb") as f:
            data = f.read()
        with open(p, "wb") as f:
            f.write(data.replace(b"\n", b"\r\n"))
        self.assertEqual(self.run_one().status, "bad-sig")

    def test_a_file_signed_as_crlf_is_valid(self):
        self.h.charter("c", crlf=True)
        g = self.run_one()
        self.assertEqual(g.status, "valid")

    def test_missing_sig_is_unsigned(self):
        self.h.boxes("c")
        self.h.charter("c", sign=False)
        board, _ = self.h.run()
        self.assertEqual(grant(board, "local/c").status, "unsigned")
        self.assertEqual(box(board, "declared/c").level, "bad")

    def test_key_removed_from_signers(self):
        self.h.charter("c")
        self.assertEqual(self.run_one().status, "valid")
        with open(os.path.join(self.h.cfg, "allowed_signers"), "w") as f:
            f.write("")
        self.assertEqual(self.run_one().status, "bad-sig")

    def test_missing_ssh_keygen_cannot_verify(self):
        self.h.charter("c")
        with mock.patch.object(charter, "keygen_path", return_value=None):
            g = self.run_one()
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("cannot verify", g.reason)

    def test_board_uses_the_bytes_it_verified(self):
        """The file is swapped between the read and the verify: the parsed
        fields come from the same bytes the signature was checked on."""
        self.h.charter("c")
        p = os.path.join(self.h.charters, "c.md")
        real = charter.verify

        def swap(data, sig, *a, **k):
            with open(p, "wb") as f:
                f.write(data.replace(b"expires: 2026-12-01", b"expires: 2020-01-01"))
            return real(data, sig, *a, **k)
        with mock.patch.object(charter, "verify", side_effect=swap):
            g = self.run_one()
        self.assertEqual(g.status, "valid")

    def test_cache_is_used(self):
        self.h.charter("c")
        self.run_one()
        with mock.patch.object(charter, "_run_keygen", side_effect=AssertionError("must not run")):
            g = self.run_one()
        self.assertEqual(g.status, "valid")

    def test_sk_key_line_is_accepted_by_the_signers_parser(self):
        lines = charter.signers_lines('craig@fleet namespaces="cc-handoff" sk-ssh-ed25519@openssh.com AAAAGnNr comment\n'
                                      "# comment\n\n")
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0][2], "sk-ssh-ed25519@openssh.com")
        self.assertIsNone(charter.signer_check(lines and 'craig@fleet namespaces="cc-handoff" sk-ssh-ed25519@openssh.com AAAAGnNr', "craig@fleet", "cc-handoff"))


class MacOS(HostCase):
    require_sig = True

    def test_cannot_verify_in_the_darwin_sandbox(self):
        if not HAVE_KEYGEN:
            self.h.write_config(require="yes")
            with open(os.path.join(self.h.cfg, "allowed_signers"), "w") as f:
                f.write(f'tester@local namespaces="{NS}" ssh-ed25519 AAAAC3 x\n')
        self.h.boxes("c")
        self.h.charter("c", sign=False)
        with open(os.path.join(self.h.charters, "c.md.sig"), "wb") as f:
            f.write(b"-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n")
        board, snap = self.h.run(platform="darwin", sandboxed=True)
        g = grant(board, "local/c")
        self.assertEqual(g.status, "bad-sig")
        self.assertIn("no subprocess in this sandbox", g.reason)
        self.assertTrue(board.cannot_verify)
        self.assertEqual(box(board, "declared/c").level, "bad")
        tiles = snap["view"][0]["items"]
        self.assertIn("unverifiable on this host", tiles[0]["note"])
        src_table = next(x for x in snap["view"] if x.get("title", "").startswith("Sources"))
        self.assertTrue(any("cannot verify on this host" in r[-1] for r in src_table["rows"]))


if __name__ == "__main__":
    unittest.main()
