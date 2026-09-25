# ftybucks

Encrypted VPN tunnel disguised as PostgreSQL streaming replication. Traffic looks like a normal PG replica syncing WAL data.

## Architecture

Two deployment modes:

### Direct (client + server)

```
Client (Mac/Linux) ----[PG replication over TLS]----> Server (VPS abroad)
```

### Gateway (WireGuard + tunnel + GeoIP split-routing)

```
Phone/Laptop --> WireGuard --> Gateway (RU VPS) --> GeoIP routing
                                 |-- RU traffic --> direct
                                 |-- non-RU traffic --> ECMP across N tunnels --> VPS abroad #1
                                                                              `-> VPS abroad #2
                                                                              `-> VPS abroad #N
```

Any device connects via standard WireGuard client. The gateway handles all routing.

The gateway can fan out across multiple abroad servers — see `docs/MULTI_SERVER.md`. Failed peers are evicted from the ECMP route automatically and rejoin when reachable again.

## Documentation

- [`docs/TUNING.md`](docs/TUNING.md) — host sysctl tuning (BBR + TCP buffers)
- [`docs/MULTI_SERVER.md`](docs/MULTI_SERVER.md) — multi-upstream pool configuration, failover, log format

## Protocol Stack

```
TCP:5432 -> SSLRequest/TLS -> PG Startup (replication=true) -> MD5 auth (PSK)
-> START_REPLICATION -> CopyData framing -> smux -> X25519+HKDF handshake
-> ChaCha20-Poly1305 encrypted frames
```

## Quick Start

### 1. Generate PSK

```bash
openssl rand -base64 32
```

Use the same PSK for server, client, and gateway configs.

### 2. Deploy Server (VPS abroad)

```bash
cp configs/server.example.yaml configs/server.yaml
# Edit configs/server.yaml — set your PSK

docker compose up -d
```

The server listens on port 5432 and looks like PostgreSQL to any observer.

### 3a. Direct Client (Mac/Linux)

```bash
make client-mac   # or: make client
cp configs/client.example.yaml configs/client.yaml
# Edit configs/client.yaml — set server IP and PSK

sudo ./bin/shadowtunnel-client-mac connect
```

### 3b. Gateway (RU VPS with WireGuard)

```bash
cp configs/gateway.example.yaml configs/gateway.yaml
# Edit configs/gateway.yaml — set abroad server IP, PSK, exceptions

docker compose -f docker-compose.gateway.yaml up -d
```

Add WireGuard peers:

```bash
docker compose -f docker-compose.gateway.yaml exec gateway gateway -add-peer "iphone"
```

This prints a WireGuard client config + QR code. Scan it from the WireGuard app.

## Build

```bash
make server       # Linux amd64 server
make client       # Linux amd64 client
make client-mac   # macOS arm64 client
make gateway      # Linux amd64 gateway
```

## Config

See `configs/*.example.yaml` for annotated examples.

### Gateway exceptions

Force specific domains/CIDRs through tunnel or direct, overriding GeoIP:

```yaml
exceptions:
  - domain: "youtube.com"
    direction: "proxy"       # always through tunnel
  - domain: "vk.com"
    direction: "direct"      # always direct
  - cidr: "149.154.160.0/20"
    direction: "proxy"       # Telegram subnets
```

## GeoIP

The gateway uses [db-ip.com](https://db-ip.com/db/lite.php) free country database (no registration needed). It downloads automatically on first start and updates periodically.

## How It Works

1. Client connects to server on TCP:5432
2. Sends PostgreSQL SSLRequest, upgrades to TLS (uTLS mimics libpq/OpenSSL 3.x fingerprint)
3. Completes full PG streaming replication handshake (StartupMessage, MD5 auth, START_REPLICATION)
4. All further data is wrapped in PG CopyData frames
5. Inside CopyData: smux multiplexing, X25519 key exchange, ChaCha20-Poly1305 encryption
6. Random padding and timing jitter for traffic analysis resistance

To a DPI system, this looks like a PostgreSQL standby server receiving WAL stream from a primary.
