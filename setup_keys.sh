#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CryptoJS PoC — Key Generation Script
# Generates RSA-4096 key pairs and a pre-shared AES-256 symmetric key.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"

SERVER_PASS="ServerKey@PoC2024"
PARTY_A_PASS="PartyA@PoC2024"
PARTY_B_PASS="PartyB@PoC2024"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CryptoJS PoC — Key Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

mkdir -p "$KEYS_DIR/asym" "$KEYS_DIR/sym"

# ── 1. Asymmetric demo: server key pair ──────────────────────────────────────
echo "[1/6] Generating RSA-4096 server key pair (asymmetric demo)..."
openssl genrsa -aes256 -passout pass:"$SERVER_PASS" \
    -out "$KEYS_DIR/asym/server_private.pem" 4096 2>/dev/null
openssl rsa -in "$KEYS_DIR/asym/server_private.pem" \
    -passin pass:"$SERVER_PASS" \
    -pubout -out "$KEYS_DIR/asym/server_public.pem" 2>/dev/null
echo "    ✓ keys/asym/server_private.pem  (password: $SERVER_PASS)"
echo "    ✓ keys/asym/server_public.pem"

# ── 2. Symmetric demo: Party A key pair ─────────────────────────────────────
echo ""
echo "[2/6] Generating RSA-4096 Party A key pair (symmetric demo)..."
openssl genrsa -aes256 -passout pass:"$PARTY_A_PASS" \
    -out "$KEYS_DIR/sym/partyA_private.pem" 4096 2>/dev/null
openssl rsa -in "$KEYS_DIR/sym/partyA_private.pem" \
    -passin pass:"$PARTY_A_PASS" \
    -pubout -out "$KEYS_DIR/sym/partyA_public.pem" 2>/dev/null
echo "    ✓ keys/sym/partyA_private.pem  (password: $PARTY_A_PASS)"
echo "    ✓ keys/sym/partyA_public.pem"

# ── 3. Symmetric demo: Party B key pair ─────────────────────────────────────
echo ""
echo "[3/6] Generating RSA-4096 Party B key pair (symmetric demo)..."
openssl genrsa -aes256 -passout pass:"$PARTY_B_PASS" \
    -out "$KEYS_DIR/sym/partyB_private.pem" 4096 2>/dev/null
openssl rsa -in "$KEYS_DIR/sym/partyB_private.pem" \
    -passin pass:"$PARTY_B_PASS" \
    -pubout -out "$KEYS_DIR/sym/partyB_public.pem" 2>/dev/null
echo "    ✓ keys/sym/partyB_private.pem  (password: $PARTY_B_PASS)"
echo "    ✓ keys/sym/partyB_public.pem"

# ── 4. Generate random AES-256 key ──────────────────────────────────────────
echo ""
echo "[4/6] Generating random AES-256 symmetric key (32 bytes)..."
openssl rand 32 > "$KEYS_DIR/sym/aes_key_tmp.bin"
echo "    ✓ Temporary raw key generated"

# ── 5. Encrypt AES key with Party A's RSA-4096 public key ───────────────────
echo ""
echo "[5/6] Encrypting AES key with Party A's RSA-4096 public key (OAEP-SHA256)..."
openssl pkeyutl -encrypt \
    -pubin -inkey "$KEYS_DIR/sym/partyA_public.pem" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in  "$KEYS_DIR/sym/aes_key_tmp.bin" \
    -out "$KEYS_DIR/sym/sym_key_encrypted_for_A.bin"

# Base64-encode (single line, no newlines)
base64 "$KEYS_DIR/sym/sym_key_encrypted_for_A.bin" | tr -d '\n' \
    > "$KEYS_DIR/sym/sym_key_encrypted_for_A.b64"
echo "    ✓ keys/sym/sym_key_encrypted_for_A.b64"

# ── 6. Clean up temporary files ─────────────────────────────────────────────
echo ""
echo "[6/6] Removing temporary files..."
rm -f "$KEYS_DIR/sym/aes_key_tmp.bin" "$KEYS_DIR/sym/sym_key_encrypted_for_A.bin"
echo "    ✓ Done"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Key setup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Passwords to use in the demo:"
echo "    Asymmetric — Server key : $SERVER_PASS"
echo "    Symmetric  — Party A    : $PARTY_A_PASS"
echo "    Symmetric  — Party B    : $PARTY_B_PASS"
echo ""
echo "  Next step:"
echo "    cd backend && cargo run --release"
echo "  Then open: http://localhost:3000"
echo ""
