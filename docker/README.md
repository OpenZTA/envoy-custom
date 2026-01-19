# Docker Compose Setup for envoy-custom + Pomerium

This directory contains a Docker Compose configuration for running envoy-custom with Pomerium authentication and sample backend services.

## Architecture

```
                    ┌─────────────────┐
                    │    Pomerium     │
                    │  (Auth/Authz)   │
                    │   :443 :5443    │
                    └────────┬────────┘
                             │ gRPC (StreamManagement)
                             │
┌──────────┐         ┌───────┴───────┐         ┌─────────────────┐
│SSH Client├────────►│ envoy-custom  ├────────►│  openssh-server │
└──────────┘  :2222  │  (SSH Proxy)  │         │   (upstream)    │
                     └───────────────┘         └─────────────────┘

┌──────────┐         ┌───────────────┐         ┌─────────────────┐
│  Browser ├────────►│   Pomerium    ├────────►│    httpbin      │
└──────────┘  :443   │  (HTTP Proxy) │         │   (upstream)    │
                     └───────────────┘         └─────────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| envoy-custom | 2222 | SSH proxy with native SSH filter |
| envoy-custom | 9901 | Envoy admin interface |
| pomerium | 443 | HTTPS proxy / authenticate |
| pomerium | 5443 | gRPC StreamManagement service |
| openssh-server | - | Upstream SSH server (internal) |
| httpbin | - | Sample HTTP service (internal) |
| verify | - | Pomerium verify service (internal) |

## Quick Start

### 1. Generate keys and certificates

```bash
./scripts/generate-keys.sh
```

This creates:
- `keys/ssh_host_ed25519_key` - Envoy's SSH server identity
- `keys/user_ca_key` - CA for signing user certificates
- `configs/cert.pem` / `configs/key.pem` - TLS cert for Pomerium

### 2. Configure Pomerium Identity Provider

Edit `configs/pomerium-config.yaml` and set your IdP credentials:

```yaml
idp_provider: "google"
idp_client_id: "YOUR_GOOGLE_CLIENT_ID"
idp_client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
```

Supported providers: google, azure, okta, github, onelogin, ping, etc.

### 3. Build envoy-custom

```bash
docker compose build envoy-custom
```

**Note**: This takes 30-60+ minutes as it builds Envoy from source.

### 4. Start services

```bash
docker compose up -d
```

### 5. Add hosts entries

Add to `/etc/hosts`:
```
127.0.0.1 localhost.pomerium.io
127.0.0.1 httpbin.localhost.pomerium.io
127.0.0.1 verify.localhost.pomerium.io
127.0.0.1 ssh.localhost
```

## Testing

### HTTP Service (through Pomerium)

```bash
# Will redirect to IdP for authentication
curl -k https://httpbin.localhost.pomerium.io/get
```

### SSH Service (through envoy-custom)

```bash
# Connect through envoy-custom SSH proxy
ssh -p 2222 demo@localhost

# Password: demo
```

### Envoy Admin

```bash
# View clusters
curl http://localhost:9901/clusters

# View stats
curl http://localhost:9901/stats
```

## Configuration Files

### envoy.yaml

The Envoy configuration uses the `generic_proxy` filter with `pomerium.extensions.ssh.CodecConfig`:

```yaml
codec_config:
  name: envoy.generic_proxy.codecs.ssh
  typed_config:
    "@type": type.googleapis.com/pomerium.extensions.ssh.CodecConfig
    host_keys:
      - filename: /etc/envoy/keys/ssh_host_ed25519_key
    user_ca_key:
      filename: /etc/envoy/keys/user_ca_key
    grpc_service:
      envoy_grpc:
        cluster_name: pomerium_mgmt
```

### pomerium-config.yaml

Pomerium configuration with gRPC service exposed:

```yaml
grpc_address: ":5443"
grpc_insecure: true
```

## Important Notes

### StreamManagement Service

The SSH filter communicates with Pomerium via the `StreamManagement` gRPC service for:
- Authentication decisions (`ManageStream` RPC)
- Hijacked channel handling (`ServeChannel` RPC)

Pomerium must implement this service for the SSH filter to work correctly.

### Build Caching

To speed up rebuilds, the Docker build uses Bazel's caching. For even faster iteration:

1. Build locally: `bazel build -c opt //:envoy`
2. Create a simpler Dockerfile that just copies the pre-built binary

### Security

For production use:
- Replace the demo secrets in `pomerium-config.yaml`
- Use proper TLS certificates (Let's Encrypt via `autocert`)
- Configure a real identity provider
- Review and restrict policies

## Troubleshooting

### Envoy fails to start

Check logs:
```bash
docker compose logs envoy-custom
```

Common issues:
- Missing keys: Run `./scripts/generate-keys.sh`
- gRPC connection failed: Ensure Pomerium is running and `grpc_address` is correct

### SSH connection fails

1. Check envoy-custom is running: `docker compose ps`
2. Check Envoy admin: `curl http://localhost:9901/clusters`
3. Verify SSH keys exist in `keys/` directory

### Build fails

Ensure you have sufficient resources:
- At least 8GB RAM
- At least 20GB disk space
- Stable internet connection (downloads ~2GB of dependencies)
