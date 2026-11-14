"""Data model shared by the config parser, key parser and the auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class UserRecord:
    """One account from the user manifest."""

    name: str
    home: str
    groups: tuple = ()


@dataclass(frozen=True)
class ConnectionContext:
    """The connection under audit: who connects, from where, to which socket."""

    user: str
    source_address: Optional[str] = None
    source_host: Optional[str] = None
    local_address: Optional[str] = None
    local_port: Optional[int] = None


@dataclass(frozen=True)
class Diagnostic:
    """A structured, non-fatal problem found while parsing or auditing."""

    code: str
    message: str
    path: Optional[str] = None
    line: Optional[int] = None
    severity: str = "error"

    def sort_key(self):
        return (self.code, self.path or "", self.line or 0, self.message)

    def to_dict(self):
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True)
class EffectiveConfig:
    """The sshd settings that apply to one concrete connection."""

    authorized_keys_files: tuple = ()
    pubkey_authentication: bool = True
    permit_root_login: str = "prohibit-password"
    allow_agent_forwarding: bool = True
    allow_tcp_forwarding: str = "yes"  # yes | no | local | remote

    def to_dict(self):
        return {
            "authorized_keys_files": list(self.authorized_keys_files),
            "pubkey_authentication": self.pubkey_authentication,
            "permit_root_login": self.permit_root_login,
            "allow_agent_forwarding": self.allow_agent_forwarding,
            "allow_tcp_forwarding": self.allow_tcp_forwarding,
        }


@dataclass
class KeyRecord:
    """One parsed authorized_keys entry. Raw source lines are never retained."""

    fingerprint: str
    algorithm: str
    path: str
    line: int
    user: Optional[str] = None
    marker: Optional[str] = None  # e.g. "cert-authority" from @cert-authority
    comment: str = ""
    options: tuple = ()  # ordered (name, value-or-None) pairs, names lowercased

    def option_values(self, name):
        return [v for n, v in self.options if n == name]

    def has_option(self, name):
        return any(n == name for n, _ in self.options)

    def option(self, name):
        values = self.option_values(name)
        return values[-1] if values else None

    @property
    def command(self):
        return self.option("command")

    @property
    def from_patterns(self):
        raw = self.option("from")
        if raw is None:
            return None
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def permitopen(self):
        return self.option_values("permitopen")

    @property
    def is_cert_authority(self):
        return self.marker == "cert-authority" or self.has_option("cert-authority")

    @property
    def is_restricted(self):
        """True when the entry carries any confining option."""
        if self.command is not None or self.from_patterns is not None:
            return True
        confining = (
            "restrict",
            "no-agent-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
            "no-x11-forwarding",
            "permitopen",
            "permitlisten",
            "tunnel",
        )
        return any(self.has_option(name) for name in confining)

    def to_dict(self):
        return {
            "fingerprint": self.fingerprint,
            "algorithm": self.algorithm,
            "user": self.user,
            "path": self.path,
            "line": self.line,
            "marker": self.marker,
            "comment": self.comment,
            "options": [
                {"name": n, "value": v} for n, v in self.options
            ],
        }


@dataclass(frozen=True)
class Risk:
    code: str
    message: str
    fingerprint: Optional[str] = None
    user: Optional[str] = None
    path: Optional[str] = None
    line: Optional[int] = None
    severity: str = "warning"

    def sort_key(self):
        return (
            self.code,
            self.fingerprint or "",
            self.user or "",
            self.path or "",
            self.line or 0,
        )

    def to_dict(self):
        return {
            "code": self.code,
            "severity": self.severity,
            "fingerprint": self.fingerprint,
            "user": self.user,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class UserAuditResult:
    user: str
    context: ConnectionContext
    effective: EffectiveConfig
    loaded_files: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    risks: list = field(default_factory=list)
    pubkey_login_allowed: bool = True

    def to_dict(self):
        return {
            "user": self.user,
            "context": {
                "source_address": self.context.source_address,
                "source_host": self.context.source_host,
                "local_address": self.context.local_address,
                "local_port": self.context.local_port,
            },
            "effective_config": self.effective.to_dict(),
            "pubkey_login_allowed": self.pubkey_login_allowed,
            "loaded_files": sorted(self.loaded_files),
            "keys": [k.to_dict() for k in self.keys],
            "risks": [r.to_dict() for r in self.risks],
        }
