"""
crypto_utils.py — Improved AES-256-GCM helpers (environment-variable key)

Context:
  crypto.py uses a hardcoded pre-shared key (PSK) for simplicity — fine
  when you want the code to be self-contained and readable. This module is
  a cleaner alternative that reads the key from an environment variable
  (MINIC2_PSK) instead of embedding it in source code.

  Why this matters: hardcoded keys end up in version control, CI logs, and
  any copy of the repository. An env-var key stays out of source control and
  can be rotated without touching code.

  This module uses the `cryptography` library (hazmat primitives) instead of
  PyCryptodome, which is another common AES-GCM implementation. Both produce
  identical ciphertext for the same inputs — the choice is a matter of which
  library is already in your dependency tree.

Wire format:
  base64( nonce (12 bytes) || ciphertext || tag (16 bytes) )
  — a compact concatenated blob rather than the JSON envelope used in crypto.py.
  The nonce is always the first 12 bytes; the GCM tag is appended by AESGCM
  automatically at the end of the ciphertext.

Key setup (one-time):
  python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
  export MINIC2_PSK="<output above>"
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV_VAR = "MINIC2_PSK"  # environment variable holding the base64-encoded 32-byte key


def load_key() -> bytes:
    """
    Load the 256-bit pre-shared key from the MINIC2_PSK environment variable.

    Raises RuntimeError if the variable is unset, and ValueError if it decodes
    to anything other than exactly 32 bytes. This fails loudly on purpose —
    silently falling back to a default key would be exactly the kind of
    mistake that turns a lab tool into a real vulnerability if it's ever reused.
    """
    b64_key = os.environ.get(KEY_ENV_VAR)
    if not b64_key:
        raise RuntimeError(
            f"Set the {KEY_ENV_VAR} environment variable to a base64-encoded "
            f"32-byte key. Generate one with:\n"
            f"  python3 -c \"import os,base64; print(base64.b64encode(os.urandom(32)).decode())\""
        )
    key = base64.b64decode(b64_key)
    if len(key) != 32:
        raise ValueError(f"{KEY_ENV_VAR} must decode to exactly 32 bytes (AES-256).")
    return key


def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt a UTF-8 string and return base64(nonce || ciphertext+tag).

    A fresh 12-byte nonce is generated for every call. GCM nonces must never
    be reused under the same key — at 12 bytes of randomness the probability of
    a collision is negligible for lab-scale message volumes.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(b64_blob: str, key: bytes) -> str:
    """
    Decrypt a base64 blob produced by encrypt() and return the plaintext string.

    Raises cryptography.exceptions.InvalidTag if the GCM tag doesn't match,
    which means the ciphertext was tampered with or the wrong key was supplied.
    """
    raw = base64.b64decode(b64_blob)
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt.decode("utf-8")
