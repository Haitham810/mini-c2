#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# gen_cert.sh — Generate a self-signed TLS certificate for MiniC2
#
# Produces cert.pem and key.pem in the server/ directory.
# The cert is valid for 365 days and uses a 2048-bit RSA key.
#
# Why a self-signed cert?
#   In a real engagement you'd use a cert from a trusted CA (e.g. Let's
#   Encrypt) so the beacon traffic blends in with normal HTTPS. For this
#   lab, self-signed is fine — the agent is configured to skip verification
#   (session.verify = False), which is also a useful teaching point: it
#   means an adversary could MITM the TLS layer. The AES-256-GCM layer
#   underneath provides authenticity even if TLS is stripped.
#
# Usage:
#   chmod +x scripts/gen_cert.sh
#   ./scripts/gen_cert.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

OUTPUT_DIR="$(dirname "$0")/../server"
CERT="$OUTPUT_DIR/cert.pem"
KEY="$OUTPUT_DIR/key.pem"

echo "[*] Generating self-signed TLS certificate..."

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" \
    -out    "$CERT" \
    -days   365 \
    -subj   "/C=MY/ST=KualaLumpur/O=LabC2/CN=c2.local"

echo "[+] Certificate : $CERT"
echo "[+] Private key : $KEY"
echo "[*] Done. Run server.py from the server/ directory."
