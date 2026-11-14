"""Static audit library for OpenSSH public-key authorization.

Resolves the effective sshd_config (Include / Match / defaults / first-value
wins), expands AuthorizedKeysFile tokens, parses authorized_keys files with a
real option parser, fingerprints keys (SHA256) and correlates identical keys
across accounts and files to surface concrete login capabilities and risks.
"""

from .models import (
    ConnectionContext,
    Diagnostic,
    EffectiveConfig,
    KeyRecord,
    Risk,
    UserAuditResult,
    UserRecord,
)
from .sshd_config import SshdConfig, SshdConfigError
from .authorized_keys import parse_authorized_keys_text, fingerprint_blob
from .auditor import Auditor, AuditReport

__all__ = [
    "Auditor",
    "AuditReport",
    "ConnectionContext",
    "Diagnostic",
    "EffectiveConfig",
    "KeyRecord",
    "Risk",
    "SshdConfig",
    "SshdConfigError",
    "UserAuditResult",
    "UserRecord",
    "fingerprint_blob",
    "parse_authorized_keys_text",
]

__version__ = "0.1.0"
