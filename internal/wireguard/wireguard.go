package wireguard

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"ftybucks/internal/config"
)

type Peer struct {
	Name       string `yaml:"name"`
	PublicKey  string `yaml:"public_key"`
	PrivateKey string `yaml:"private_key"`
	AllowedIP  string `yaml:"allowed_ip"`
}

type peersFile struct {
	Peers []Peer `yaml:"peers"`
}

type Manager struct {
	cfg       config.WireGuardConfig
	serverPub string // server public key (derived from private key)

	mu    sync.Mutex
	peers []Peer
}

func NewManager(cfg config.WireGuardConfig) *Manager {
	return &Manager{cfg: cfg}
}

// InitKeys loads or auto-generates the private key and derives the public key.
// Does NOT create the interface — safe to call when wg0 is already up.
func (m *Manager) InitKeys() error {
	if m.cfg.PrivateKey == "" {
		key, err := m.loadOrGenerateKey()
		if err != nil {
			return fmt.Errorf("auto-generate wg key: %w", err)
		}
		m.cfg.PrivateKey = key
	}

	pub, err := derivePublicKey(m.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	m.serverPub = pub
	return nil
}

// Setup creates the WireGuard interface, assigns address, and loads peers.
// If private_key is not set, auto-generates and persists one next to peers_file.
func (m *Manager) Setup() error {
	iface := m.iface()

	if err := m.InitKeys(); err != nil {
		return err
	}

	// Create interface
	if err := run("ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
		// Interface might already exist
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("create wg interface: %w", err)
		}
	}

	// Assign address (may already be assigned after container restart)
	if err := run("ip", "addr", "add", m.cfg.Address, "dev", iface); err != nil {
		if !strings.Contains(err.Error(), "exists") && !strings.Contains(err.Error(), "already assigned") {
			return fmt.Errorf("assign address: %w", err)
		}
	}

	// Configure WireGuard with private key and listen port
	if err := m.configureWG(); err != nil {
		return fmt.Errorf("configure wg: %w", err)
	}

	// Bring up
	if err := run("ip", "link", "set", "up", "dev", iface); err != nil {
		return fmt.Errorf("bring up: %w", err)
	}

	// Load existing peers
	if err := m.LoadPeers(); err != nil {
		// Not fatal — peers file might not exist yet
		if !os.IsNotExist(err) {
			return fmt.Errorf("load peers: %w", err)
		}
	}

	// Add loaded peers to WireGuard
	for _, p := range m.peers {
		if err := m.addPeerToWG(p); err != nil {
			return fmt.Errorf("add peer %s: %w", p.Name, err)
		}
	}

	return nil
}

func (m *Manager) configureWG() error {
	tmpFile, err := os.CreateTemp("", "wg-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(m.cfg.PrivateKey); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	return run("wg", "set", m.iface(),
		"listen-port", fmt.Sprint(m.listenPort()),
		"private-key", tmpFile.Name())
}

// AddPeer generates keys, assigns IP, adds to WireGuard, saves to peers file,
// and returns the client configuration.
func (m *Manager) AddPeer(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate name
	for _, p := range m.peers {
		if p.Name == name {
			return "", fmt.Errorf("peer %q already exists", name)
		}
	}

	// Generate keys
	privKey, err := generatePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	pubKey, err := derivePublicKey(privKey)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}

	// Allocate IP
	ip, err := m.allocateIP()
	if err != nil {
		return "", fmt.Errorf("allocate IP: %w", err)
	}

	peer := Peer{
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: privKey,
		AllowedIP:  ip + "/32",
	}

	// Add to WireGuard
	if err := m.addPeerToWG(peer); err != nil {
		return "", fmt.Errorf("add to wg: %w", err)
	}

	m.peers = append(m.peers, peer)

	// Save peers file
	if err := m.savePeers(); err != nil {
		return "", fmt.Errorf("save peers: %w", err)
	}

	// Generate client config
	clientCfg := m.generateClientConfig(peer)
	return clientCfg, nil
}

// RemovePeer removes a peer by name.
func (m *Manager) RemovePeer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, p := range m.peers {
		if p.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("peer %q not found", name)
	}

	peer := m.peers[idx]

	// Remove from WireGuard
	if err := run("wg", "set", m.iface(), "peer", peer.PublicKey, "remove"); err != nil {
		return fmt.Errorf("remove from wg: %w", err)
	}

	m.peers = append(m.peers[:idx], m.peers[idx+1:]...)

	return m.savePeers()
}

// LoadPeers loads peers from the peers file.
func (m *Manager) LoadPeers() error {
	data, err := os.ReadFile(m.cfg.PeersFile)
	if err != nil {
		return err
	}

	var pf peersFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse peers file: %w", err)
	}

	m.mu.Lock()
	m.peers = pf.Peers
	m.mu.Unlock()

	return nil
}

// Teardown removes the WireGuard interface.
func (m *Manager) Teardown() {
	run("ip", "link", "del", "dev", m.iface())
}

// ServerPublicKey returns the server's public key.
func (m *Manager) ServerPublicKey() string {
	return m.serverPub
}

// loadOrGenerateKey loads the WG private key from a persistent file,
// or generates a new one and saves it.
func (m *Manager) loadOrGenerateKey() (string, error) {
	keyPath := m.keyPath()

	data, err := os.ReadFile(keyPath)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return key, nil
		}
	}

	// Generate new key
	key, err := generatePrivateKey()
	if err != nil {
		return "", fmt.Errorf("wg genkey: %w", err)
	}

	dir := keyPath[:strings.LastIndex(keyPath, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0600); err != nil {
		return "", fmt.Errorf("save key: %w", err)
	}

	return key, nil
}

// keyPath returns the path for the persistent WG private key,
// stored next to peers_file (same volume).
func (m *Manager) keyPath() string {
	if m.cfg.PeersFile != "" {
		dir := m.cfg.PeersFile[:strings.LastIndex(m.cfg.PeersFile, "/")]
		return dir + "/wg-private.key"
	}
	return "/etc/gateway/wg-private.key"
}

func (m *Manager) addPeerToWG(p Peer) error {
	return run("wg", "set", m.iface(), "peer", p.PublicKey, "allowed-ips", p.AllowedIP)
}

func (m *Manager) savePeers() error {
	pf := peersFile{Peers: m.peers}
	data, err := yaml.Marshal(&pf)
	if err != nil {
		return err
	}

	dir := m.cfg.PeersFile[:strings.LastIndex(m.cfg.PeersFile, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(m.cfg.PeersFile, data, 0600)
}

func (m *Manager) allocateIP() (string, error) {
	_, subnet, err := net.ParseCIDR(m.cfg.Subnet)
	if err != nil {
		return "", fmt.Errorf("parse subnet: %w", err)
	}

	// Collect used IPs
	used := make(map[string]bool)
	// Gateway IP (from address field, e.g. "10.8.0.1/24")
	if gwIP, _, err := net.ParseCIDR(m.cfg.Address); err == nil {
		used[gwIP.String()] = true
	}
	for _, p := range m.peers {
		ip, _, _ := net.ParseCIDR(p.AllowedIP)
		if ip != nil {
			used[ip.String()] = true
		}
	}

	// Iterate through subnet, skip .0 (network) and .255 (broadcast for /24)
	ip := make(net.IP, 4)
	copy(ip, subnet.IP.To4())

	for inc(ip); subnet.Contains(ip); inc(ip) {
		// Skip broadcast (last IP)
		if ip[3] == 255 {
			continue
		}
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no free IPs in %s", m.cfg.Subnet)
}

func (m *Manager) generateClientConfig(p Peer) string {
	port := m.listenPort()

	dns := m.cfg.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}

	endpoint := detectPublicIP()
	if endpoint == "" {
		endpoint = "<GATEWAY_IP>"
	}

	// Address is /32: the client owns exactly one tunnel IP and routes
	// everything via AllowedIPs=0.0.0.0/0. A /24 here would wrongly mark the
	// whole tunnel subnet as on-link on the client.
	//
	// MTU 1380 leaves headroom for the full encapsulation chain (WG + the
	// PG/TLS/TCP tunnel) and matches the gateway/server MSS clamp, so large
	// transfers and QUIC don't stall on oversized packets being dropped.
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = 1380

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, p.PrivateKey, strings.TrimSuffix(p.AllowedIP, "/32"), dns, m.serverPub, endpoint, port)
}

func detectPublicIP() string {
	for _, url := range []string{
		"https://ifconfig.me",
		"https://api.ipify.org",
		"https://icanhazip.com",
	} {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func (m *Manager) iface() string {
	if m.cfg.Interface != "" {
		return m.cfg.Interface
	}
	return "wg0"
}

func (m *Manager) listenPort() int {
	if m.cfg.ListenPort > 0 {
		return m.cfg.ListenPort
	}
	return 51820
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func generatePrivateKey() (string, error) {
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func derivePublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
