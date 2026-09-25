# Multi-server pool with failover

The gateway can connect to several abroad servers simultaneously and load-balance flows across them via Linux ECMP. When a peer fails, it is evicted from the active set and traffic continues over the remaining peers; when it recovers, it rejoins automatically.

## Why a pool

A single VPN tunnel multiplexes user TCP flows over one outer TCP connection. On a lossy RU↔EU peering path this single outer flow becomes the bottleneck — packet loss collapses CUBIC's window faster than it can grow. Three independent tunnels through three different peering paths give the kernel three congestion windows to push through, plus failover for free.

## Configuration

`gateway.yaml`:

```yaml
tunnel:
  # Single upstream — legacy form
  # server: "host:5432"

  # Multi-upstream pool — preferred
  servers:
    - "203.0.113.10:5432"
    - "198.51.100.20:5432"
    - "192.0.2.30:5432"

  psk: "<base64 PSK identical across all servers>"
  tun_name: "stun"   # device prefix → stun0, stun1, stun2 (or just "stun0" if you want a single device for the legacy form)
```

`tunnel.server` and `tunnel.servers` are mutually exclusive — set one, not both.

## What happens at startup

1. The gateway opens one independent VPN session per `servers` entry, in parallel.
2. Each session does its own PG handshake → encrypted handshake → `FrameAssign` → receives a tunnel IP from that server's address pool.
3. Each session creates a local TUN device `<tun_name><index>` (e.g. `stun0`, `stun1`, `stun2`) bound to its assigned IP.
4. Routing manager:
   - installs one `MASQUERADE` rule per TUN
   - installs the policy-routing `default` route in `table 100` as ECMP across **healthy** TUNs only:
     ```
     default
       nexthop dev stun0 weight 1
       nexthop dev stun1 weight 1
       nexthop dev stun2 weight 1
     ```
5. Each peer runs an independent reconnect loop — keeps trying with exponential backoff (1s → 30s) on failure.

## Flow distribution

Linux ECMP hashes each new flow's `(srcip, dstip, sport, dport, proto)` and maps it to one next-hop. Subsequent packets of the same flow always take the same path — there is no in-flight reordering. Different flows from the same WireGuard peer can land on different tunnels, which is exactly what we want for browsers (which open many parallel TCP streams to one site).

Weights are 1:1:1 — Linux does not auto-tune them. To prefer a faster peer, edit `internal/routing/routing.go` (`RebuildECMP`).

## Failover

Detection happens when the smux session reports `EOF` on read (typically when the underlying TCP times out — within ~30s on a quiet idle connection, faster under load):

```
[recv] decode error: read header: EOF
[POOL] n3 (192.0.2.30:5432) → unhealthy: session lost after 2m34s — evicting from active set
[routing] ECMP rebuilt across 2 tunnels: stun0, stun1
attempting reconnect (backoff=1s)
reconnect failed: dial: ... connect: connection refused
attempting reconnect (backoff=2s)
...
```

Recovery is automatic:

```
reconnect failed: dial: ... connection refused
attempting reconnect (backoff=16s)
reconnected successfully
[+] [n3] reconnected (15.523s)
[POOL] n3 (192.0.2.30:5432) → healthy, re-adding to active set
[+] [n3] session #2 established
[routing] ECMP rebuilt across 3 tunnels: stun0, stun1, stun2
```

Caveat: existing flows that were already going through the failed peer **break**. They show up as TCP resets / timeouts to the WireGuard peer, which retries — the retry is a new flow and gets re-hashed onto a healthy peer.

## Log format

| Prefix       | Meaning                                                   |
| ------------ | --------------------------------------------------------- |
| `[POOL]`     | pool membership changes — health flips, evictions, recovery |
| `[routing]`  | route table changes — bypass routes, ECMP rebuilds        |
| `[+] [n*]`   | per-member status (`n*` is the position in the array, not the inventory label) |
| `[PG]`       | server-side: PG-handshake events on incoming connections  |
| `[HS]`       | server-side: encrypted-tunnel handshake events            |

## Member naming

The gateway labels members `n1`, `n2`, `n3`, ... by their position in the `servers:` array. These names are position-based, not host names. To avoid confusion, also use the address itself when reading logs:

```
[POOL] n2 (198.51.100.20:5432) → connected
                ^^^^^^^^^^^^
                this is the authoritative identity
```

## Adding a fourth server

1. Provision the host (BBR + TCP-tuning sysctls — see `docs/TUNING.md`).
2. Copy the source tarball and run `docker compose up -d --build` (mount `configs/server.yaml` with the same PSK).
3. Verify port 5432 is open externally: `nc -vz <ip> 5432`.
4. Edit `/opt/ftybucks/configs/gateway.yaml` on the gateway, append the new entry to `tunnel.servers:`.
5. `sudo docker compose -f docker-compose.gateway.yaml up -d --force-recreate`.
6. Watch the logs — should see `pool connected (Xs) — 4/4 healthy` and `ECMP rebuilt across 4 tunnels`.

## Removing a server gracefully

1. Edit `gateway.yaml`, remove the entry.
2. `docker compose up -d --force-recreate` — the gateway will reload.
3. Stop the abroad container at your leisure.
