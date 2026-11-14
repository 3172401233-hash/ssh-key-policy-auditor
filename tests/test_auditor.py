import json
import os
import tempfile
import time
import unittest

from ssh_key_policy_auditor import (
    Auditor,
    ConnectionContext,
    UserRecord,
)
from tests.helpers import fingerprint_of, make_key_line, write


class AuditorTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def home(self, name):
        return os.path.join(self.root, "home", name)

    def make_auditor(self, config_text, users, **files):
        main = write(os.path.join(self.root, "sshd_config"), config_text)
        for rel, text in files.items():
            write(os.path.join(self.root, rel), text)
        return Auditor(users, main)

    def risk_codes(self, report, user):
        codes = set()
        for result in report.results:
            if result.user == user:
                codes.update(r.code for r in result.risks)
        return codes


class EffectiveFilesTest(AuditorTestBase):
    def test_merged_authorized_keys_files_from_include_and_match(self):
        alice_home = self.home("alice")
        users = [UserRecord("alice", alice_home, ("ops",))]
        auditor = self.make_auditor(
            "Include conf.d/*.conf\n"
            "Match Group ops\n"
            "  AuthorizedKeysFile .ssh/authorized_keys %h/extra.keys /etc/keys/%u.keys\n",
            users,
            **{
                "conf.d/00-base.conf": "PubkeyAuthentication yes\n",
                "home/alice/.ssh/authorized_keys": make_key_line(1),
                "home/alice/extra.keys": make_key_line(2),
            },
        )
        report = auditor.audit([ConnectionContext("alice")])
        result = report.results[0]
        self.assertEqual(
            sorted(result.loaded_files),
            sorted(
                [
                    os.path.join(alice_home, ".ssh/authorized_keys"),
                    os.path.join(alice_home, "extra.keys"),
                ]
            ),
        )
        # both existing files contribute keys; the /etc one is missing
        self.assertEqual(len(result.keys), 2)
        self.assertIn(
            "MISSING_AUTH_FILE", [d.code for d in report.diagnostics]
        )
        # a non-ops user falls back to the default locations
        other = UserRecord("mallory", self.home("mallory"))
        auditor.users["mallory"] = other
        report2 = auditor.audit([ConnectionContext("mallory")])
        self.assertEqual(
            report2.results[0].effective.authorized_keys_files,
            (
                os.path.join(self.home("mallory"), ".ssh/authorized_keys"),
                os.path.join(self.home("mallory"), ".ssh/authorized_keys2"),
            ),
        )

    def test_pubkey_authentication_no_suppresses_login(self):
        home = self.home("bob")
        users = [UserRecord("bob", home)]
        auditor = self.make_auditor(
            "PubkeyAuthentication no\n",
            users,
            **{"home/bob/.ssh/authorized_keys": make_key_line(1)},
        )
        report = auditor.audit([ConnectionContext("bob")])
        self.assertFalse(report.results[0].pubkey_login_allowed)
        # no per-key capability risks when pubkey auth is off
        self.assertEqual(report.results[0].risks, [])

    def test_root_login_risk_and_permit_root_login_no(self):
        users = [UserRecord("root", os.path.join(self.root, "root"))]
        auditor = self.make_auditor(
            "PermitRootLogin yes\n",
            users,
            **{"root/.ssh/authorized_keys": make_key_line(1)},
        )
        report = auditor.audit([ConnectionContext("root")])
        self.assertIn("ROOT_LOGIN", self.risk_codes(report, "root"))
        self.assertTrue(report.results[0].pubkey_login_allowed)

        auditor2 = self.make_auditor(
            "PermitRootLogin no\n",
            users,
        )
        report2 = auditor2.audit([ConnectionContext("root")])
        self.assertFalse(report2.results[0].pubkey_login_allowed)


class RiskTest(AuditorTestBase):
    def audit_one(self, key_lines, extra_config=""):
        home = self.home("eve")
        users = [UserRecord("eve", home)]
        auditor = self.make_auditor(
            extra_config or "PubkeyAuthentication yes\n",
            users,
            **{"home/eve/.ssh/authorized_keys": "\n".join(key_lines) + "\n"},
        )
        return auditor.audit([ConnectionContext("eve")])

    def test_unrestricted_key_flags(self):
        report = self.audit_one([make_key_line(1)])
        codes = self.risk_codes(report, "eve")
        self.assertIn("NO_COMMAND", codes)
        self.assertIn("BROAD_SOURCE", codes)
        self.assertIn("AGENT_FORWARDING", codes)
        self.assertIn("TCP_FORWARDING", codes)

    def test_fully_restricted_key_is_quiet(self):
        report = self.audit_one(
            [
                make_key_line(
                    1,
                    options='restrict,command="/opt/backup",from="10.1.2.3"',
                )
            ],
            extra_config="AllowAgentForwarding no\nAllowTcpForwarding no\n",
        )
        codes = self.risk_codes(report, "eve")
        self.assertNotIn("NO_COMMAND", codes)
        self.assertNotIn("BROAD_SOURCE", codes)
        self.assertNotIn("AGENT_FORWARDING", codes)
        self.assertNotIn("TCP_FORWARDING", codes)

    def test_permitopen_any(self):
        report = self.audit_one([make_key_line(1, options='permitopen="*"')])
        self.assertIn("PERMITOPEN_ANY", self.risk_codes(report, "eve"))
        report2 = self.audit_one(
            [make_key_line(2, options='permitopen="db:5432"')]
        )
        self.assertNotIn("PERMITOPEN_ANY", self.risk_codes(report2, "eve"))

    def test_agent_forwarding_disabled_by_config(self):
        report = self.audit_one(
            [make_key_line(1)],
            extra_config="AllowAgentForwarding no\n",
        )
        self.assertNotIn("AGENT_FORWARDING", self.risk_codes(report, "eve"))

    def test_agent_forwarding_disabled_by_key_option(self):
        report = self.audit_one(
            [make_key_line(1, options="no-agent-forwarding,no-port-forwarding")]
        )
        codes = self.risk_codes(report, "eve")
        self.assertNotIn("AGENT_FORWARDING", codes)
        self.assertNotIn("TCP_FORWARDING", codes)

    def test_cert_authority_flagged(self):
        report = self.audit_one(
            ["@cert-authority " + make_key_line(1, options='principals="ops"')]
        )
        self.assertIn("CERT_AUTHORITY", self.risk_codes(report, "eve"))

    def test_broad_from_cidr(self):
        report = self.audit_one([make_key_line(1, options='from="0.0.0.0/0"')])
        self.assertIn("BROAD_SOURCE", self.risk_codes(report, "eve"))
        report2 = self.audit_one(
            [make_key_line(2, options='from="10.9.8.0/24,!.badhost"')]
        )
        self.assertNotIn("BROAD_SOURCE", self.risk_codes(report2, "eve"))


class FingerprintIndexTest(AuditorTestBase):
    def test_cross_account_reuse_and_mixed_restriction(self):
        alice_home = self.home("alice")
        bob_home = self.home("bob")
        users = [
            UserRecord("alice", alice_home),
            UserRecord("bob", bob_home),
        ]
        auditor = self.make_auditor(
            "PubkeyAuthentication yes\n",
            users,
            **{
                "home/alice/.ssh/authorized_keys": make_key_line(
                    99, options='command="/bin/true"'
                ),
                "home/bob/.ssh/authorized_keys": make_key_line(99)
                + "\n"
                + make_key_line(100),
            },
        )
        report = auditor.audit(
            [ConnectionContext("alice"), ConnectionContext("bob")]
        )
        shared_fp = fingerprint_of(99)
        index = report.fingerprint_index
        self.assertIn(shared_fp, index)
        self.assertEqual(
            sorted(o["user"] for o in index[shared_fp]), ["alice", "bob"]
        )
        # per-occurrence options are preserved
        alice_keys = report.results[0].keys
        self.assertEqual(alice_keys[0].command, "/bin/true")
        bob_keys = report.results[1].keys
        self.assertIsNone(bob_keys[0].command)

        self.assertIn("CROSS_ACCOUNT", self.risk_codes(report, "alice"))
        self.assertIn("CROSS_ACCOUNT", self.risk_codes(report, "bob"))
        # restricted in alice's file, unrestricted in bob's
        self.assertIn("MIXED_RESTRICTION", self.risk_codes(report, "alice"))
        self.assertIn("MIXED_RESTRICTION", self.risk_codes(report, "bob"))
        # key 100 only exists once, unrestricted: no mixed restriction for it
        solo = fingerprint_of(100)
        mixed = [
            r
            for res in report.results
            for r in res.risks
            if r.code == "MIXED_RESTRICTION" and r.fingerprint == solo
        ]
        self.assertEqual(mixed, [])

    def test_same_key_twice_same_account_not_cross_account(self):
        home = self.home("alice")
        users = [UserRecord("alice", home)]
        auditor = self.make_auditor(
            "PubkeyAuthentication yes\n",
            users,
            **{
                "home/alice/.ssh/authorized_keys": make_key_line(5)
                + "\n"
                + make_key_line(5)
            },
        )
        report = auditor.audit([ConnectionContext("alice")])
        self.assertNotIn("CROSS_ACCOUNT", self.risk_codes(report, "alice"))
        self.assertEqual(len(report.fingerprint_index[fingerprint_of(5)]), 2)

    def test_stable_output(self):
        home = self.home("alice")
        users = [UserRecord("alice", home)]
        files = {
            "home/alice/.ssh/authorized_keys": "\n".join(
                make_key_line(i, options='from="*.example.com"') for i in range(50)
            )
        }
        auditor = self.make_auditor("PubkeyAuthentication yes\n", users, **files)
        ctx = [ConnectionContext("alice")]
        first = json.dumps(auditor.audit(ctx).to_dict(), sort_keys=True)
        auditor2 = self.make_auditor("PubkeyAuthentication yes\n", users, **files)
        second = json.dumps(auditor2.audit(ctx).to_dict(), sort_keys=True)
        self.assertEqual(first, second)


class DiagnosticsIsolationTest(AuditorTestBase):
    def test_one_broken_file_does_not_swallow_others(self):
        alice_home = self.home("alice")
        bob_home = self.home("bob")
        users = [UserRecord("alice", alice_home), UserRecord("bob", bob_home)]
        auditor = self.make_auditor(
            "PubkeyAuthentication yes\n",
            users,
            **{
                "home/alice/.ssh/authorized_keys": "ssh-ed25519 !!!broken!!!\n"
                + make_key_line(1),
                "home/bob/.ssh/authorized_keys": make_key_line(2),
            },
        )
        report = auditor.audit(
            [ConnectionContext("alice"), ConnectionContext("bob")]
        )
        self.assertEqual(len(report.results[0].keys), 1)
        self.assertEqual(len(report.results[1].keys), 1)
        self.assertIn("BAD_BASE64", [d.code for d in report.diagnostics])

    def test_unknown_user_diagnostic(self):
        auditor = self.make_auditor("PubkeyAuthentication yes\n", [])
        report = auditor.audit([ConnectionContext("ghost")])
        self.assertEqual(report.results, [])
        self.assertIn("UNKNOWN_USER", [d.code for d in report.diagnostics])


class ScaleTest(AuditorTestBase):
    def test_many_users_many_keys_linear(self):
        user_count = 400
        keys_per_user = 250  # 100k keys total
        users = []
        files = {}
        for i in range(user_count):
            name = "user%04d" % i
            users.append(UserRecord(name, self.home(name)))
            lines = []
            for j in range(keys_per_user):
                # ~10% of keys are shared with the previous user to exercise
                # the fingerprint index without O(n^2) comparisons
                seed = (i - 1) * keys_per_user + j if (i and j % 10 == 0) else i * keys_per_user + j
                lines.append(make_key_line(seed))
            files["home/%s/.ssh/authorized_keys" % name] = "\n".join(lines)
        auditor = self.make_auditor("PubkeyAuthentication yes\n", users, **files)
        contexts = [ConnectionContext(u.name) for u in users]

        start = time.monotonic()
        report = auditor.audit(contexts)
        elapsed = time.monotonic() - start

        total_keys = sum(len(r.keys) for r in report.results)
        self.assertEqual(total_keys, user_count * keys_per_user)
        self.assertLess(elapsed, 60)
        # shared seeds collapse into single fingerprint entries
        shared_fp = fingerprint_of(0 * keys_per_user + 10)
        self.assertIn(shared_fp, report.fingerprint_index)
        # index lookups, not pairwise scans: every occurrence recorded
        occurrences = sum(len(v) for v in report.fingerprint_index.values())
        self.assertEqual(occurrences, total_keys)


if __name__ == "__main__":
    unittest.main()
