package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type GatewayConfig struct {
	Tunnel     GatewayTunnelConfig `yaml:"tunnel"`
	WireGuard  WireGuardConfig     `yaml:"wireguard"`
	GeoIP      GeoIPConfig         `yaml:"geoip"`
	Exceptions []ExceptionRule     `yaml:"exceptions"`
}

// Routing modes for GatewayTunnelConfig.RoutingMode.
const (
	RoutingECMP        = "ecmp"
	RoutingECMPSticky  = "ecmp-sticky"
	RoutingActiveStdby = "active-standby"
)

type GatewayTunnelConfig struct {
	// Server is the single-upstream form (legacy). Mutually exclusive with Servers.
	Server string `yaml:"server"`
	// Servers is the multi-upstream form. When set, the gateway opens one
	// independent VPN session per address and load-balances flows across
	// them via kernel ECMP. Failed peers are evicted from the ECMP route.
	Servers  []string      `yaml:"servers"`
	PSK      string        `yaml:"psk"`
	TunName  string        `yaml:"tun_name"`
	Padding  PaddingConfig `yaml:"padding"`
	JitterMs int           `yaml:"jitter_ms"`
	// RoutingMode selects how flows are steered across the upstream pool:
	//   "ecmp"           — kernel ECMP across all healthy tunnels (legacy default).
	//                      Fast, but any membership change rehashes live flows onto
	//                      a different exit IP and breaks them.
	//   "ecmp-sticky"    — ECMP for new flows, but each flow is pinned to its tunnel
	//                      in conntrack (CONNMARK), so evicting/re-adding a peer no
	//                      longer disturbs flows on the surviving tunnels.
	//   "active-standby" — all flows use a single primary tunnel; on primary failure
	//                      traffic fails over to the next healthy peer. No rehash at
	//                      all while the primary is up. Trades aggregate throughput
	//                      for maximum stability.
	// Empty defaults to "ecmp" (unchanged behavior).
	RoutingMode string `yaml:"routing_mode"`
	// OutboundMark is an SO_MARK value (decimal) that an external proxy on the
	// host (e.g. XRay) sets on its freedom-outbound sockets. When > 0, the
	// gateway installs a mangle OUTPUT rule that translates this SO_MARK into
	// the tunnel fwmark, so traffic from the proxy is steered through the pool.
	OutboundMark int `yaml:"outbound_mark"`
}

type WireGuardConfig struct {
	ListenPort int    `yaml:"listen_port"`
	Interface  string `yaml:"interface"`
	Address    string `yaml:"address"`
	Subnet     string `yaml:"subnet"`
	PrivateKey string `yaml:"private_key"`
	DNS        string `yaml:"dns"`
	PeersFile  string `yaml:"peers_file"`
}

type GeoIPConfig struct {
	DatabasePath   string `yaml:"database_path"`
	UpdateInterval string `yaml:"update_interval"`
	CountryCode    string `yaml:"country_code"`
}

type ExceptionRule struct {
	Domain    string `yaml:"domain"`
	CIDR      string `yaml:"cidr"`
	Direction string `yaml:"direction"` // "proxy" | "direct"
}

func LoadGateway(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg GatewayConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *GatewayConfig) Validate() error {
	// Tunnel: either tunnel.server (single) or tunnel.servers (pool) is required.
	if c.Tunnel.Server == "" && len(c.Tunnel.Servers) == 0 {
		return fmt.Errorf("tunnel.server or tunnel.servers is required")
	}
	if c.Tunnel.Server != "" && len(c.Tunnel.Servers) > 0 {
		return fmt.Errorf("set either tunnel.server or tunnel.servers, not both")
	}
	if c.Tunnel.PSK == "" {
		return fmt.Errorf("tunnel.psk is required")
	}
	pskBytes, err := base64.StdEncoding.DecodeString(c.Tunnel.PSK)
	if err != nil {
		return fmt.Errorf("tunnel.psk must be valid base64: %w", err)
	}
	if len(pskBytes) < 32 {
		return fmt.Errorf("tunnel.psk must be at least 32 bytes (got %d)", len(pskBytes))
	}
	if c.Tunnel.Padding.Min < 0 || c.Tunnel.Padding.Max < 0 {
		return fmt.Errorf("tunnel.padding min/max must be non-negative")
	}
	if c.Tunnel.Padding.Max > 0 && c.Tunnel.Padding.Min > c.Tunnel.Padding.Max {
		return fmt.Errorf("tunnel.padding min must be <= max")
	}
	switch c.Tunnel.RoutingMode {
	case "", RoutingECMP, RoutingECMPSticky, RoutingActiveStdby:
	default:
		return fmt.Errorf("tunnel.routing_mode must be one of %q, %q, %q (got %q)",
			RoutingECMP, RoutingECMPSticky, RoutingActiveStdby, c.Tunnel.RoutingMode)
	}

	// WireGuard — required only when there is no XRay-style outbound source
	// (i.e. the gateway accepts traffic from a wg0 interface). In transit
	// mode (tunnel.outbound_mark > 0), the gateway accepts traffic by
	// SO_MARK from a local proxy instead, and WG is optional.
	if c.Tunnel.OutboundMark == 0 {
		if c.WireGuard.Address == "" {
			return fmt.Errorf("wireguard.address is required (or set tunnel.outbound_mark for transit mode)")
		}
		if c.WireGuard.Subnet == "" {
			return fmt.Errorf("wireguard.subnet is required")
		}
	}

	// GeoIP
	if c.GeoIP.DatabasePath == "" {
		return fmt.Errorf("geoip.database_path is required")
	}
	if c.GeoIP.CountryCode == "" {
		return fmt.Errorf("geoip.country_code is required")
	}
	if c.GeoIP.UpdateInterval != "" {
		if _, err := time.ParseDuration(c.GeoIP.UpdateInterval); err != nil {
			return fmt.Errorf("geoip.update_interval: %w", err)
		}
	}

	// Exceptions
	for i, e := range c.Exceptions {
		if e.Domain == "" && e.CIDR == "" {
			return fmt.Errorf("exceptions[%d]: domain or cidr is required", i)
		}
		if e.Direction != "proxy" && e.Direction != "direct" {
			return fmt.Errorf("exceptions[%d].direction must be 'proxy' or 'direct'", i)
		}
	}

	return nil
}

func (c *GatewayConfig) PSKBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.Tunnel.PSK)
}

// IsTransitMode reports whether the gateway should run without WireGuard,
// accepting tunnel-bound traffic by SO_MARK from a local proxy (XRay) instead.
// In transit mode, GeoIP-based split routing still applies — RU subnets bypass
// the tunnel and exit directly via the gateway's ISP.
func (c *GatewayConfig) IsTransitMode() bool {
	return c.Tunnel.OutboundMark > 0 && c.WireGuard.Address == ""
}

// ServerList returns the configured upstream addresses. When tunnel.server
// (singular) is set, the slice contains exactly one entry. When tunnel.servers
// is set, the slice contains all entries in the order given.
func (c *GatewayConfig) ServerList() []string {
	if len(c.Tunnel.Servers) > 0 {
		out := make([]string, len(c.Tunnel.Servers))
		copy(out, c.Tunnel.Servers)
		return out
	}
	if c.Tunnel.Server != "" {
		return []string{c.Tunnel.Server}
	}
	return nil
}

// RoutingMode returns the normalized routing mode, defaulting to "ecmp".
func (c *GatewayConfig) RoutingMode() string {
	if c.Tunnel.RoutingMode == "" {
		return RoutingECMP
	}
	return c.Tunnel.RoutingMode
}

func (c *GatewayConfig) TunnelTunName() string {
	if c.Tunnel.TunName != "" {
		return c.Tunnel.TunName
	}
	return "stun0"
}

func (c *GatewayConfig) WireGuardInterface() string {
	if c.WireGuard.Interface != "" {
		return c.WireGuard.Interface
	}
	return "wg0"
}

func (c *GatewayConfig) WireGuardListenPort() int {
	if c.WireGuard.ListenPort > 0 {
		return c.WireGuard.ListenPort
	}
	return 51820
}

func (c *GatewayConfig) GeoIPUpdateInterval() time.Duration {
	if c.GeoIP.UpdateInterval != "" {
		d, err := time.ParseDuration(c.GeoIP.UpdateInterval)
		if err == nil {
			return d
		}
	}
	return 24 * time.Hour
}
