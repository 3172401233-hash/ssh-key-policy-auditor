import base64
import hashlib
import os


def make_blob(seed, algo="ssh-ed25519"):
    tag = algo.encode()
    body = (str(seed).encode() * 64)[:32]
    return len(tag).to_bytes(4, "big") + tag + body


def make_key_line(seed, algo="ssh-ed25519", options=None, comment=""):
    blob = base64.b64encode(make_blob(seed, algo)).decode()
    prefix = (options + " ") if options else ""
    suffix = (" " + comment) if comment else ""
    return "%s%s %s%s" % (prefix, algo, blob, suffix)


def fingerprint_of(seed, algo="ssh-ed25519"):
    digest = hashlib.sha256(make_blob(seed, algo)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)
    return path
