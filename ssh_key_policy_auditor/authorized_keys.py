"""authorized_keys parsing with a quote/escape aware option parser.

Lines look like:
    [@marker] [option,option="v a l",...] keytype base64 [comment]

The option field may contain quoted strings with embedded commas, whitespace
and backslash escapes, so naive str.split() is not an option.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from .models import Diagnostic, KeyRecord

KNOWN_ALGORITHMS = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    }
)

_ALGO_PREFIXES = ("ssh-", "ecdsa-", "sk-")
_KNOWN_MARKERS = {"cert-authority", "revoked"}


def fingerprint_blob(blob):
    """OpenSSH-style SHA256 fingerprint of a decoded key blob."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _scan_token(line, start):
    """Scan one whitespace-delimited token, respecting quotes and escapes.

    Returns (token_text, next_index); token_text keeps its quotes so the
    option parser can re-interpret them.
    """
    out = []
    in_quote = False
    escaped = False
    i = start
    while i < len(line):
        ch = line[i]
        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\":
            out.append(ch)
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
            out.append(ch)
        elif ch.isspace() and not in_quote:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out), i


def _split_options(text):
    """Split an option field on commas that are outside quoted strings."""
    parts = []
    current = []
    in_quote = False
    escaped = False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            current.append(ch)
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == "," and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p for p in (p.strip() for p in parts) if p]


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        body = value[1:-1]
        out = []
        escaped = False
        for ch in body:
            if escaped:
                out.append(ch)
                escaped = False
            elif ch == "\\":
                escaped = True
            else:
                out.append(ch)
        if escaped:
            out.append("\\")
        return "".join(out)
    return value


def _parse_options(text, path, lineno, diagnostics):
    options = []
    for raw in _split_options(text):
        if "=" in raw:
            name, value = raw.split("=", 1)
            name = name.strip().lower()
            if not name:
                diagnostics.append(
                    Diagnostic("BAD_OPTION", "empty option name", path, lineno)
                )
                continue
            options.append((name, _unquote(value)))
        else:
            options.append((raw.strip().lower(), None))
    return tuple(options)


def _looks_like_algorithm(token):
    return token in KNOWN_ALGORITHMS or token.startswith(_ALGO_PREFIXES)


def parse_authorized_keys_line(line, lineno, path, diagnostics):
    """Parse one authorized_keys line. Returns a KeyRecord or None."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    marker = None
    rest = stripped
    if rest.startswith("@"):
        token, idx = _scan_token(rest, 0)
        name = token[1:].lower()
        if name in _KNOWN_MARKERS:
            marker = name
            rest = rest[idx:].lstrip()
        else:
            diagnostics.append(
                Diagnostic("UNKNOWN_MARKER", "unknown marker %r" % token, path, lineno)
            )
            return None

    first, idx = _scan_token(rest, 0)
    if not first:
        return None
    if _looks_like_algorithm(first):
        options = ()
        remainder = rest
    else:
        options = _parse_options(first, path, lineno, diagnostics)
        remainder = rest[idx:].lstrip()
        if not remainder:
            diagnostics.append(
                Diagnostic("PARSE_ERROR", "options without a key blob", path, lineno)
            )
            return None

    parts = remainder.split(None, 2)
    if len(parts) < 2:
        diagnostics.append(
            Diagnostic("PARSE_ERROR", "expected '<type> <base64>'", path, lineno)
        )
        return None
    algorithm, blob64 = parts[0], parts[1]
    comment = parts[2].strip() if len(parts) > 2 else ""

    if algorithm not in KNOWN_ALGORITHMS:
        diagnostics.append(
            Diagnostic(
                "UNKNOWN_ALGORITHM",
                "unsupported key algorithm %r" % algorithm,
                path,
                lineno,
            )
        )
        return None
    try:
        blob = base64.b64decode(blob64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        diagnostics.append(
            Diagnostic("BAD_BASE64", "invalid base64 key blob", path, lineno)
        )
        return None
    if not blob:
        diagnostics.append(Diagnostic("BAD_BASE64", "empty key blob", path, lineno))
        return None

    return KeyRecord(
        fingerprint=fingerprint_blob(blob),
        algorithm=algorithm,
        path=path,
        line=lineno,
        marker=marker,
        comment=comment,
        options=options,
    )


def parse_authorized_keys_text(text, path, diagnostics):
    """Parse a whole authorized_keys file; bad lines never abort the file."""
    records = []
    for lineno, line in enumerate(text.splitlines(), 1):
        record = parse_authorized_keys_line(line, lineno, path, diagnostics)
        if record is not None:
            records.append(record)
    return records
