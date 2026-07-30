"""
crypto.py — AES-256-GCM encryption module (server copy)

This file is shared between the server and the agent — both sides must use
the same key and the same wire format, or decryption will fail.

Why AES-256-GCM?
  AES-GCM is an "authenticated encryption" mode, which means it provides two
  guarantees in a single pass:
    1. Confidentiality  — the ciphertext reveals nothing about the plaintext.
    2. Integrity        — the GCM authentication tag detects any tampering.
  Plain AES-CBC only gives you (1); without a separate MAC you can't tell
  whether an attacker modified the ciphertext in transit.

Key management:
  This lab uses a pre-shared key (PSK) — the same 32-byte value is hardcoded
  on both sides. In a production C2 the key would be negotiated per-session
  via asymmetric crypto (e.g. ECDH), so compromising one session's traffic
  doesn't expose any other session. For this lab, PSK keeps things readable.

  See also: crypto_utils.py — an improved version that reads the key from an
  environment variable instead of hardcoding it, which is a better practice
  even in a lab setting.

Wire format:
  encrypt() returns base64( JSON({ nonce, ciphertext, tag }) )
  — a single opaque string that travels safely inside JSON.
  Each call generates a fresh random nonce, so encrypting the same plaintext
  twice always produces different ciphertext.
"""

import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── Pre-shared key (PSK) ──────────────────────────────────────────────────────
# 64 hex digits = 32 bytes = 256-bit AES key.
# The agent/crypto.py must contain the identical value for messages to
# decrypt correctly. Replace this with a freshly generated key for any real use.
KEY = bytes.fromhex(
    "a3f1c2e5b47d9e6082b1d4f7a9c30e5f"
    "1b8d2c4e6f0a3b5c7d9e1f2a4b6c8d0e"
)
# ─────────────────────────────────────────────────────────────────────────────


def encrypt(data: dict) -> str:
    """
    Encrypt a dictionary and return a base64 string safe for JSON transport.

    Steps:
      1. Serialise the dict to a UTF-8 JSON string.
      2. Generate a random 16-byte nonce (never reuse a nonce with the same key).
      3. AES-256-GCM encrypt; the cipher appends a 16-byte authentication tag.
      4. Pack nonce + ciphertext + tag into a JSON envelope, then base64-encode
         the whole thing so it travels as a single string field in HTTP JSON.
    """
    plaintext = json.dumps(data).encode("utf-8")
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    envelope = {
        "nonce":      base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag":        base64.b64encode(tag).decode(),
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


def decrypt(encoded: str) -> dict:
    """
    Decrypt a base64 string produced by encrypt() and return the original dict.

    The GCM tag is verified before the plaintext is returned. If the tag check
    fails — because the ciphertext was modified in transit, or because the wrong
    key is being used — PyCryptodome raises ValueError. The caller should treat
    this as a fatal error for that message (drop it; do not process further).
    """
    envelope = json.loads(base64.b64decode(encoded).decode())

    nonce      = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    tag        = base64.b64decode(envelope["tag"])

    cipher    = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode("utf-8"))
