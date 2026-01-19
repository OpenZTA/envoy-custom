#!/bin/bash
# Generate SSH keys for envoy-custom Docker demo
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}/../keys"
CONFIGS_DIR="${SCRIPT_DIR}/../configs"

mkdir -p "$KEYS_DIR"

echo "=== Generating SSH keys for envoy-custom ==="

# Generate SSH host key (server identity)
if [ ! -f "$KEYS_DIR/ssh_host_ed25519_key" ]; then
    echo "Generating SSH host key..."
    ssh-keygen -t ed25519 -f "$KEYS_DIR/ssh_host_ed25519_key" -N "" -C "envoy-custom-host-key"
else
    echo "SSH host key already exists, skipping..."
fi

# Generate User CA key (for signing user certificates)
if [ ! -f "$KEYS_DIR/user_ca_key" ]; then
    echo "Generating User CA key..."
    ssh-keygen -t ed25519 -f "$KEYS_DIR/user_ca_key" -N "" -C "envoy-custom-user-ca"
else
    echo "User CA key already exists, skipping..."
fi

# Set proper permissions
chmod 600 "$KEYS_DIR/ssh_host_ed25519_key"
chmod 600 "$KEYS_DIR/user_ca_key"
chmod 644 "$KEYS_DIR/ssh_host_ed25519_key.pub" 2>/dev/null || true
chmod 644 "$KEYS_DIR/user_ca_key.pub" 2>/dev/null || true

echo ""
echo "=== Generating TLS certificates for Pomerium ==="

# Generate self-signed TLS cert for Pomerium (demo only)
if [ ! -f "$CONFIGS_DIR/cert.pem" ]; then
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CONFIGS_DIR/key.pem" \
        -out "$CONFIGS_DIR/cert.pem" \
        -days 365 -nodes \
        -subj "/CN=localhost.pomerium.io" \
        -addext "subjectAltName=DNS:localhost.pomerium.io,DNS:*.localhost.pomerium.io,DNS:localhost,IP:127.0.0.1"
    chmod 600 "$CONFIGS_DIR/key.pem"
    chmod 644 "$CONFIGS_DIR/cert.pem"
else
    echo "TLS certificates already exist, skipping..."
fi

echo ""
echo "=== Generated files ==="
echo "SSH keys:"
ls -la "$KEYS_DIR/"
echo ""
echo "TLS certificates:"
ls -la "$CONFIGS_DIR/"*.pem 2>/dev/null || echo "  (none)"

echo ""
echo "=== Done ==="
echo "You can now run: docker compose up -d"
