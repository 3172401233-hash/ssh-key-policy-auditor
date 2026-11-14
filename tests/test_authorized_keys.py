import unittest

from ssh_key_policy_auditor.authorized_keys import (
    fingerprint_blob,
    parse_authorized_keys_text,
)
from tests.helpers import fingerprint_of, make_key_line


def parse(text):
    diagnostics = []
    records = parse_authorized_keys_text(text, "testfile", diagnostics)
    return records, diagnostics


class AuthorizedKeysParserTest(unittest.TestCase):
    def test_plain_key_with_comment(self):
        records, diags = parse(make_key_line(1, comment="alice@laptop"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].algorithm, "ssh-ed25519")
        self.assertEqual(records[0].comment, "alice@laptop")
        self.assertEqual(records[0].options, ())
        self.assertEqual(diags, [])

    def test_fingerprint_matches_sha256_of_blob(self):
        records, _ = parse(make_key_line(42))
        self.assertEqual(records[0].fingerprint, fingerprint_of(42))
        self.assertTrue(records[0].fingerprint.startswith("SHA256:"))

    def test_quoted_command_with_commas_and_escapes(self):
        line = make_key_line(
            2,
            options='command="rsync --server \\"a,b\\" /data",no-pty,from="*.example.com,10.0.0.0/8"',
        )
        records, diags = parse(line)
        self.assertEqual(diags, [])
        key = records[0]
        self.assertEqual(key.command, 'rsync --server "a,b" /data')
        self.assertTrue(key.has_option("no-pty"))
        self.assertEqual(key.from_patterns, ["*.example.com", "10.0.0.0/8"])

    def test_command_with_whitespace(self):
        line = make_key_line(3, options='command="/opt/backup run --mode full"')
        (key,), _ = parse(line)
        self.assertEqual(key.command, "/opt/backup run --mode full")

    def test_permitopen_multiple(self):
        line = make_key_line(
            4, options='permitopen="db.internal:5432",permitopen="*"'
        )
        (key,), _ = parse(line)
        self.assertEqual(key.permitopen, ["db.internal:5432", "*"])

    def test_cert_authority_option_and_marker(self):
        (key1,), _ = parse(make_key_line(5, options="cert-authority,principals=\"ops\""))
        self.assertTrue(key1.is_cert_authority)
        (key2,), _ = parse("@cert-authority " + make_key_line(6))
        self.assertTrue(key2.is_cert_authority)
        self.assertEqual(key2.marker, "cert-authority")

    def test_rsa_and_ecdsa_algorithms(self):
        text = "\n".join(
            [
                make_key_line(7, algo="ssh-rsa"),
                make_key_line(8, algo="ecdsa-sha2-nistp256"),
                make_key_line(9, algo="ecdsa-sha2-nistp521"),
            ]
        )
        records, diags = parse(text)
        self.assertEqual(len(records), 3)
        self.assertEqual(diags, [])
        self.assertEqual(
            {r.algorithm for r in records},
            {"ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521"},
        )

    def test_bad_base64_and_unknown_algorithm_are_diagnosed(self):
        text = "\n".join(
            [
                make_key_line(10),
                "ssh-ed25519 !!!not-base64!!!",
                "ssh-dss AAAAB3NzaC1kc3MAAACB fake",
                "weird-options-without-key",
                make_key_line(11),
            ]
        )
        records, diags = parse(text)
        self.assertEqual(len(records), 2)
        codes = [d.code for d in diags]
        self.assertIn("BAD_BASE64", codes)
        self.assertIn("UNKNOWN_ALGORITHM", codes)
        self.assertIn("PARSE_ERROR", codes)
        # line numbers point at the offending lines
        bad64 = next(d for d in diags if d.code == "BAD_BASE64")
        self.assertEqual(bad64.line, 2)

    def test_comments_and_blank_lines_skipped(self):
        text = "# header\n\n" + make_key_line(12) + "\n   \n"
        records, diags = parse(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(diags, [])

    def test_restricted_detection(self):
        (restricted,), _ = parse(make_key_line(13, options='command="true"'))
        (unrestricted,), _ = parse(make_key_line(14))
        self.assertTrue(restricted.is_restricted)
        self.assertFalse(unrestricted.is_restricted)


if __name__ == "__main__":
    unittest.main()
