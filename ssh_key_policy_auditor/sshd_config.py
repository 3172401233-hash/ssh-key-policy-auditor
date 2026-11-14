"""sshd_config parsing: Include resolution, Match blocks, defaults and the
"first obtained value wins" semantics used by OpenSSH for scalar keywords."""

from __future__ import annotations

import fnmatch
import glob
import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Optional

from .models import Diagnostic, EffectiveConfig


class SshdConfigError(Exception):
    """Raised only when the top-level config file itself cannot be read."""


SUPPORTED_KEYWORDS = {
    "include",
    "authorizedkeysfile",
    "pubkeyauthentication",
    "permitrootlogin",
    "allowagentforwarding",
    "allowtcpforwarding",
}

MATCH_CRITERIA = {"user", "group", "host", "address", "localaddress", "localport"}

_DEFAULT_AUTHORIZED_KEYS_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")

_TOKEN_RE = re.compile(r"%(.?)")


@dataclass
class _Item:
    keyword: str
    value: str
    match: Optional[tuple]
    path: str
    line: int


def _split_config_line(line):
    """Split a config line on whitespace, honouring double quotes."""
    tokens = []
    current = []
    in_quote = False
    for ch in line:
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch.isspace() and not in_quote:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def _parse_match_criteria(tokens, path, line, diagnostics):
    """Return a tuple of (criterion, frozenset(patterns)) or None on error."""
    if not tokens:
        diagnostics.append(
            Diagnostic("INVALID_MATCH", "Match block without criteria", path, line)
        )
        return None
    if tokens[0].lower() == "all":
        if len(tokens) > 1:
            diagnostics.append(
                Diagnostic(
                    "INVALID_MATCH",
                    "'all' cannot be combined with other Match criteria",
                    path,
                    line,
                )
            )
            return None
        return (("all", frozenset()),)
    if len(tokens) % 2 != 0:
        diagnostics.append(
            Diagnostic(
                "INVALID_MATCH",
                "Match criteria must be criterion/pattern pairs",
                path,
                line,
            )
        )
        return None
    criteria = []
    for i in range(0, len(tokens), 2):
        key = tokens[i].lower()
        if key not in MATCH_CRITERIA:
            diagnostics.append(
                Diagnostic(
                    "INVALID_MATCH",
                    "unsupported Match criterion %r" % tokens[i],
                    path,
                    line,
                )
            )
            return None
        patterns = frozenset(p for p in tokens[i + 1].split(",") if p)
        if not patterns:
            diagnostics.append(
                Diagnostic(
                    "INVALID_MATCH",
                    "empty pattern list for Match %s" % key,
                    path,
                    line,
                )
            )
            return None
        criteria.append((key, patterns))
    return tuple(criteria)


def _match_pattern_list(patterns, value):
    """OpenSSH pattern list: '!' negates, first matching entry decides."""
    if value is None:
        return False
    for pattern in patterns:
        negated = pattern.startswith("!")
        raw = pattern[1:] if negated else pattern
        if fnmatch.fnmatchcase(value.lower(), raw.lower()):
            return not negated
    return False


def _match_address_patterns(patterns, address):
    if address is None:
        return False
    for pattern in patterns:
        negated = pattern.startswith("!")
        raw = pattern[1:] if negated else pattern
        if "/" in raw:
            try:
                network = ipaddress.ip_network(raw, strict=False)
                hit = ipaddress.ip_address(address) in network
            except ValueError:
                hit = False
        else:
            hit = fnmatch.fnmatchcase(address.lower(), raw.lower())
        if hit:
            return not negated
    return False


class SshdConfig:
    """Parsed sshd_config with Include expansion and Match evaluation."""

    def __init__(self, main_config_path, diagnostics=None):
        self.main_config_path = os.path.abspath(main_config_path)
        self.diagnostics = diagnostics if diagnostics is not None else []
        self._items = []
        self._parse_file(self.main_config_path, (), None)

    def _parse_file(self, path, include_stack, match):
        path = os.path.abspath(path)
        if path in include_stack:
            chain = " -> ".join(include_stack + (path,))
            self.diagnostics.append(
                Diagnostic("INCLUDE_CYCLE", "cyclic Include: %s" % chain, path)
            )
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError as exc:
            code = "MISSING_CONFIG" if not include_stack else "DANGLING_INCLUDE"
            self.diagnostics.append(
                Diagnostic(code, "cannot read %s: %s" % (path, exc), path)
            )
            return

        stack = include_stack + (path,)
        for lineno, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens = _split_config_line(stripped)
            if not tokens:
                continue
            keyword = tokens[0].lower()
            value = " ".join(tokens[1:])

            if keyword == "include":
                self._handle_include(tokens[1:], path, lineno, stack, match)
                continue
            if keyword == "match":
                criteria = _parse_match_criteria(
                    tokens[1:], path, lineno, self.diagnostics
                )
                # An invalid Match block never matches; its body is kept but
                # tagged with an unsatisfiable criterion.
                match = criteria if criteria is not None else (("never", frozenset()),)
                continue
            if keyword not in SUPPORTED_KEYWORDS:
                self.diagnostics.append(
                    Diagnostic(
                        "UNKNOWN_DIRECTIVE",
                        "unsupported directive %r ignored" % tokens[0],
                        path,
                        lineno,
                        severity="info",
                    )
                )
                continue
            self._items.append(_Item(keyword, value, match, path, lineno))

    def _handle_include(self, patterns, path, lineno, include_stack, match):
        if not patterns:
            self.diagnostics.append(
                Diagnostic("DANGLING_INCLUDE", "Include without arguments", path, lineno)
            )
            return
        base = os.path.dirname(path)
        for pattern in patterns:
            candidate = pattern
            if not os.path.isabs(candidate):
                candidate = os.path.join(base, candidate)
            matches = sorted(glob.glob(candidate))
            if not matches:
                self.diagnostics.append(
                    Diagnostic(
                        "DANGLING_INCLUDE",
                        "Include pattern %r matched no files" % pattern,
                        path,
                        lineno,
                    )
                )
                continue
            for included in matches:
                self._parse_file(included, include_stack, match)

    def _criteria_match(self, criteria, user, groups, context):
        for criterion, patterns in criteria:
            if criterion == "all":
                continue
            if criterion == "never":
                return False
            if criterion == "user":
                if not _match_pattern_list(patterns, user.name):
                    return False
            elif criterion == "group":
                if not any(_match_pattern_list(patterns, g) for g in groups):
                    return False
            elif criterion == "host":
                if not _match_pattern_list(patterns, context.source_host):
                    return False
            elif criterion == "address":
                if not _match_address_patterns(patterns, context.source_address):
                    return False
            elif criterion == "localaddress":
                if not _match_address_patterns(patterns, context.local_address):
                    return False
            elif criterion == "localport":
                if port_str(context) is None:
                    return False
                if not _match_pattern_list(patterns, port_str(context)):
                    return False
            else:
                return False
        return True

    def effective_config(self, user, context):
        """Fold global + matching Match blocks into an EffectiveConfig.

        OpenSSH semantics: the first obtained value wins for the scalar
        keywords handled here, so global settings near the top of the file
        take precedence over later Match blocks.
        """
        groups = user.groups
        seen = set()
        values = {}
        for item in self._items:
            if item.keyword in seen:
                continue
            if item.match is not None and not self._criteria_match(
                item.match, user, groups, context
            ):
                continue
            seen.add(item.keyword)
            values[item.keyword] = (item.value, item.path, item.line)

        akf_raw = values.get("authorizedkeysfile")
        if akf_raw is None:
            paths = list(_DEFAULT_AUTHORIZED_KEYS_FILES)
        else:
            paths = akf_raw[0].split()
        expanded = tuple(
            self._expand_authorized_keys_path(p, user, akf_raw) for p in paths
        )

        pubkey = _as_bool(values, "pubkeyauthentication", True, self.diagnostics)
        permit_root = _as_value(values, "permitrootlogin", "prohibit-password").lower()
        agent = _as_bool(values, "allowagentforwarding", True, self.diagnostics)
        tcp = _as_value(values, "allowtcpforwarding", "yes").lower()
        if tcp not in ("yes", "no", "local", "remote"):
            src = values.get("allowtcpforwarding")
            self.diagnostics.append(
                Diagnostic(
                    "INVALID_VALUE",
                    "invalid AllowTcpForwarding value %r, assuming 'yes'" % tcp,
                    src[1] if src else None,
                    src[2] if src else None,
                )
            )
            tcp = "yes"
        return EffectiveConfig(
            authorized_keys_files=expanded,
            pubkey_authentication=pubkey,
            permit_root_login=permit_root,
            allow_agent_forwarding=agent,
            allow_tcp_forwarding=tcp,
        )

    def _expand_authorized_keys_path(self, path, user, source):
        def replace(match):
            token = match.group(1)
            if token == "%":
                return "%"
            if token == "h":
                return user.home
            if token in ("u", "r"):
                return user.name
            src_path, src_line = (source[1], source[2]) if source else (None, None)
            self.diagnostics.append(
                Diagnostic(
                    "UNKNOWN_TOKEN",
                    "unsupported token %%%s in AuthorizedKeysFile" % token,
                    src_path,
                    src_line,
                    severity="warning",
                )
            )
            return match.group(0)

        expanded = _TOKEN_RE.sub(replace, path)
        if not expanded.startswith("/"):
            expanded = os.path.join(user.home, expanded)
        return os.path.normpath(expanded)


def port_str(context):
    return None if context.local_port is None else str(context.local_port)


def _as_value(values, keyword, default):
    entry = values.get(keyword)
    return entry[0] if entry else default


def _as_bool(values, keyword, default, diagnostics):
    entry = values.get(keyword)
    if entry is None:
        return default
    raw = entry[0].strip().lower()
    if raw in ("yes", "true", "1"):
        return True
    if raw in ("no", "false", "0"):
        return False
    diagnostics.append(
        Diagnostic(
            "INVALID_VALUE",
            "invalid boolean %r for %s, assuming %r"
            % (entry[0], keyword, "yes" if default else "no"),
            entry[1],
            entry[2],
        )
    )
    return default
