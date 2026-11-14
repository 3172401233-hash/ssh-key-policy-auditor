import os
import tempfile
import unittest

from ssh_key_policy_auditor import (
    ConnectionContext,
    SshdConfig,
    UserRecord,
)
from tests.helpers import write


class SshdConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.user = UserRecord("alice", os.path.join(self.root, "home/alice"), ("dev",))
        self.ctx = ConnectionContext(
            "alice", source_address="192.0.2.10", source_host="ws.example.com"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def parse(self, main_text, **files):
        main = write(os.path.join(self.root, "sshd_config"), main_text)
        for rel, text in files.items():
            write(os.path.join(self.root, rel), text)
        return SshdConfig(main)

    def test_defaults(self):
        cfg = self.parse("PermitRootLogin no\n")
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertEqual(
            eff.authorized_keys_files,
            (
                os.path.join(self.root, "home/alice/.ssh/authorized_keys"),
                os.path.join(self.root, "home/alice/.ssh/authorized_keys2"),
            ),
        )
        self.assertTrue(eff.pubkey_authentication)
        self.assertEqual(eff.permit_root_login, "no")
        self.assertTrue(eff.allow_agent_forwarding)
        self.assertEqual(eff.allow_tcp_forwarding, "yes")

    def test_multi_level_include_and_glob(self):
        cfg = self.parse(
            "Include conf.d/*.conf\n",
            **{
                "conf.d/10-base.conf": "Include ../deep/more.conf\nPubkeyAuthentication no\n",
                "conf.d/20-extra.conf": "AllowAgentForwarding no\n",
                "deep/more.conf": "AllowTcpForwarding local\n",
            },
        )
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertFalse(eff.pubkey_authentication)
        self.assertFalse(eff.allow_agent_forwarding)
        self.assertEqual(eff.allow_tcp_forwarding, "local")

    def test_first_value_wins(self):
        cfg = self.parse(
            "PubkeyAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "Match all\n"
            "  PubkeyAuthentication yes\n"
        )
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertFalse(eff.pubkey_authentication)

    def test_match_user_and_address(self):
        cfg = self.parse(
            "Match User alice Address 192.0.2.0/24\n"
            "  AllowTcpForwarding no\n"
            "Match User bob\n"
            "  AllowAgentForwarding no\n"
        )
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertEqual(eff.allow_tcp_forwarding, "no")
        self.assertTrue(eff.allow_agent_forwarding)

        other_ctx = ConnectionContext("alice", source_address="203.0.113.9")
        eff2 = cfg.effective_config(self.user, other_ctx)
        self.assertEqual(eff2.allow_tcp_forwarding, "yes")

    def test_match_negation_and_group(self):
        cfg = self.parse(
            "Match Group dev Address !10.0.0.0/8,192.0.2.0/24\n"
            "  AllowTcpForwarding remote\n"
        )
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertEqual(eff.allow_tcp_forwarding, "remote")
        neg = cfg.effective_config(
            self.user, ConnectionContext("alice", source_address="10.1.2.3")
        )
        self.assertEqual(neg.allow_tcp_forwarding, "yes")

    def test_invalid_match_diagnostic_and_never_matches(self):
        cfg = self.parse(
            "Match User\n  AllowTcpForwarding no\nMatch Bogus x\n  PubkeyAuthentication no\n"
        )
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertEqual(eff.allow_tcp_forwarding, "yes")
        self.assertTrue(eff.pubkey_authentication)
        codes = [d.code for d in cfg.diagnostics]
        self.assertEqual(codes.count("INVALID_MATCH"), 2)

    def test_dangling_include_and_cycle(self):
        cfg = self.parse(
            "Include missing/*.conf\nInclude loop/a.conf\n",
            **{"loop/a.conf": "Include b.conf\n", "loop/b.conf": "Include a.conf\n"},
        )
        codes = [d.code for d in cfg.diagnostics]
        self.assertIn("DANGLING_INCLUDE", codes)
        self.assertIn("INCLUDE_CYCLE", codes)

    def test_authorized_keys_file_tokens(self):
        cfg = self.parse(
            "AuthorizedKeysFile .ssh/authorized_keys /keys/%u/%h/ak %%u-%r.keys\n"
        )
        eff = cfg.effective_config(self.user, self.ctx)
        home = self.user.home
        self.assertEqual(
            eff.authorized_keys_files,
            (
                os.path.join(home, ".ssh/authorized_keys"),
                os.path.join("/keys/alice", home.lstrip("/"), "ak"),
                os.path.join(home, "%u-alice.keys"),
            ),
        )

    def test_unknown_token_diagnostic(self):
        cfg = self.parse("AuthorizedKeysFile /keys/%d.keys\n")
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertIn("%d.keys", eff.authorized_keys_files[0])
        self.assertIn("UNKNOWN_TOKEN", [d.code for d in cfg.diagnostics])

    def test_unknown_directive_is_info_not_fatal(self):
        cfg = self.parse("PasswordAuthentication no\nPubkeyAuthentication no\n")
        eff = cfg.effective_config(self.user, self.ctx)
        self.assertFalse(eff.pubkey_authentication)
        infos = [d for d in cfg.diagnostics if d.code == "UNKNOWN_DIRECTIVE"]
        self.assertEqual(len(infos), 1)
        self.assertEqual(infos[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
