"""Audit engine: resolves effective config per connection, loads the
authorized_keys files sshd would actually read, and derives concrete
capabilities and risks. Fingerprint correlation is hash-index based, so it
scales linearly with the number of keys.
"""

from __future__ import annotations

import ipaddress
import os
from collections import defaultdict

from .authorized_keys import parse_authorized_keys_text
from .models import (
    ConnectionContext,
    Diagnostic,
    Risk,
    UserAuditResult,
)
from .sshd_config import SshdConfig

_BROAD_V4_PREFIXLEN = 8
_BROAD_V6_PREFIXLEN = 32


def _option_bool(options, positive, negative, default):
    """Fold ordered boolean-ish key options.

    'restrict' resets everything to False; later explicit options re-enable.
    """
    value = default
    for name, _ in options:
        if name == "restrict":
            value = False
        elif name == positive:
            value = True
        elif name == negative:
            value = False
    return value


def _from_is_broad(patterns):
    """True when a from= list (or its absence) barely limits the source."""
    if patterns is None:
        return True
    positives = [p for p in patterns if not p.startswith("!")]
    if not positives:
        return False
    for pattern in positives:
        if pattern == "*":
            return True
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                continue
            limit = (
                _BROAD_V4_PREFIXLEN
                if network.version == 4
                else _BROAD_V6_PREFIXLEN
            )
            if network.prefixlen < limit:
                return True
    return False


def _permitopen_is_any(values):
    for raw in values:
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if entry == "*":
                return True
            host, sep, port = entry.rpartition(":")
            if sep and (host in ("*", "") or port == "*"):
                return True
    return False


class AuditReport:
    """Aggregated, deterministic audit output."""

    def __init__(self, results, fingerprint_index, diagnostics):
        self.results = results
        self.fingerprint_index = fingerprint_index
        self.diagnostics = diagnostics

    def to_dict(self):
        index = {}
        for fingerprint in sorted(self.fingerprint_index):
            occurrences = sorted(
                self.fingerprint_index[fingerprint],
                key=lambda o: (o["user"] or "", o["path"], o["line"]),
            )
            index[fingerprint] = occurrences
        return {
            "users": [r.to_dict() for r in self.results],
            "fingerprint_index": index,
            "diagnostics": [
                d.to_dict() for d in sorted(self.diagnostics, key=lambda d: d.sort_key())
            ],
        }


class Auditor:
    def __init__(self, users, sshd_config_path):
        self.users = {u.name: u for u in users}
        self.diagnostics = []
        if not os.path.isfile(sshd_config_path):
            raise FileNotFoundError(sshd_config_path)
        self.config = SshdConfig(sshd_config_path, self.diagnostics)
        self._file_cache = {}

    def _load_authorized_keys(self, path):
        """Parse a key file once per audit run; missing files are diagnosed,
        never fatal. Only parsed records are cached, never raw lines."""
        if path in self._file_cache:
            return self._file_cache[path]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as exc:
            self.diagnostics.append(
                Diagnostic(
                    "MISSING_AUTH_FILE",
                    "cannot read authorized keys file: %s" % exc,
                    path,
                )
            )
            self._file_cache[path] = []
            return []
        records = parse_authorized_keys_text(text, path, self.diagnostics)
        self._file_cache[path] = records
        return records

    def _pubkey_login_allowed(self, user, effective):
        if not effective.pubkey_authentication:
            return False
        if user.name == "root":
            return effective.permit_root_login not in ("no",)
        return True

    def _key_capabilities(self, key, effective):
        agent = effective.allow_agent_forwarding and _option_bool(
            key.options, "agent-forwarding", "no-agent-forwarding", True
        )
        tcp_allowed = effective.allow_tcp_forwarding != "no" and _option_bool(
            key.options, "port-forwarding", "no-port-forwarding", True
        )
        return agent, tcp_allowed

    def _key_risks(self, key, effective, agent_allowed, tcp_allowed):
        risks = []

        def add(code, message, severity="warning"):
            risks.append(
                Risk(
                    code,
                    message,
                    fingerprint=key.fingerprint,
                    user=key.user,
                    path=key.path,
                    line=key.line,
                    severity=severity,
                )
            )

        if key.command is None:
            add("NO_COMMAND", "key has no forced command restriction")
        if _from_is_broad(key.from_patterns):
            add(
                "BROAD_SOURCE",
                "key is not limited to a narrow source (missing or broad from=)",
            )
        if _permitopen_is_any(key.permitopen):
            add(
                "PERMITOPEN_ANY",
                "permitopen allows forwarding to arbitrary targets",
                severity="high",
            )
        if agent_allowed:
            add("AGENT_FORWARDING", "agent forwarding is effective for this key")
        if tcp_allowed and not key.permitopen:
            add(
                "TCP_FORWARDING",
                "TCP forwarding is effective and not scoped by permitopen",
            )
        if key.is_cert_authority:
            add(
                "CERT_AUTHORITY",
                "key is trusted as a certificate authority",
                severity="high",
            )
        return risks

    def audit(self, contexts):
        results = []
        index = defaultdict(list)
        restricted_fps = set()
        unrestricted_fps = set()

        for context in contexts:
            user = self.users.get(context.user)
            if user is None:
                self.diagnostics.append(
                    Diagnostic("UNKNOWN_USER", "no such user %r" % context.user)
                )
                continue
            effective = self.config.effective_config(user, context)
            result = UserAuditResult(
                user=user.name,
                context=context,
                effective=effective,
                pubkey_login_allowed=self._pubkey_login_allowed(user, effective),
            )
            if user.name == "root" and effective.permit_root_login in (
                "yes",
                "without-password",
                "prohibit-password",
            ):
                result.risks.append(
                    Risk(
                        "ROOT_LOGIN",
                        "root public-key login permitted (PermitRootLogin %s)"
                        % effective.permit_root_login,
                        user="root",
                        severity="high",
                    )
                )

            for path in effective.authorized_keys_files:
                keys = self._load_authorized_keys(path)
                if not keys:
                    continue
                result.loaded_files.append(path)
                for key in keys:
                    key.user = user.name
                    result.keys.append(key)
                    index[key.fingerprint].append(
                        {
                            "user": user.name,
                            "path": key.path,
                            "line": key.line,
                            "restricted": key.is_restricted,
                        }
                    )
                    if key.is_restricted:
                        restricted_fps.add(key.fingerprint)
                    else:
                        unrestricted_fps.add(key.fingerprint)
                    if result.pubkey_login_allowed:
                        agent, tcp = self._key_capabilities(key, effective)
                        result.risks.extend(
                            self._key_risks(key, effective, agent, tcp)
                        )
            result.risks.sort(key=lambda r: r.sort_key())
            results.append(result)

        for fingerprint in restricted_fps & unrestricted_fps:
            for occurrence in index[fingerprint]:
                results_risk = Risk(
                    "MIXED_RESTRICTION",
                    "same fingerprint exists in restricted and unrestricted form",
                    fingerprint=fingerprint,
                    user=occurrence["user"],
                    path=occurrence["path"],
                    line=occurrence["line"],
                    severity="high",
                )
                for result in results:
                    if result.user == occurrence["user"]:
                        result.risks.append(results_risk)
                        break

        users_by_fp = {
            fp: {o["user"] for o in occ} for fp, occ in index.items()
        }
        for fingerprint, names in users_by_fp.items():
            if len(names) > 1:
                for occurrence in index[fingerprint]:
                    risk = Risk(
                        "CROSS_ACCOUNT",
                        "fingerprint shared across accounts: %s"
                        % ", ".join(sorted(names)),
                        fingerprint=fingerprint,
                        user=occurrence["user"],
                        path=occurrence["path"],
                        line=occurrence["line"],
                        severity="high",
                    )
                    for result in results:
                        if result.user == occurrence["user"]:
                            result.risks.append(risk)
                            break

        for result in results:
            result.risks.sort(key=lambda r: r.sort_key())
        results.sort(key=lambda r: (r.user, r.context.source_address or ""))
        return AuditReport(results, dict(index), self.diagnostics)
