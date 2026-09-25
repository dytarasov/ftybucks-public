package dns

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Resolver performs DNS-over-HTTPS resolution with a TTL-based cache.
type Resolver struct {
	endpoint string
	client   *http.Client
	cache    sync.Map // map[string]cacheEntry
}

type cacheEntry struct {
	response  []byte
	expiresAt time.Time
}

const defaultCacheTTL = 5 * time.Minute

// NewDoHResolver creates a DoH resolver with the given endpoint (e.g. "https://1.1.1.1/dns-query").
func NewDoHResolver(endpoint string) *Resolver {
	return &Resolver{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Resolve takes a raw DNS query packet and returns a raw DNS response packet.
func (r *Resolver) Resolve(query []byte) ([]byte, error) {
	// Extract cache key from query (domain + type from question section)
	key := extractQueryKey(query)
	if key != "" {
		if entry, ok := r.cache.Load(key); ok {
			ce := entry.(cacheEntry)
			if time.Now().Before(ce.expiresAt) {
				// Rewrite transaction ID from the original query
				resp := make([]byte, len(ce.response))
				copy(resp, ce.response)
				if len(query) >= 2 && len(resp) >= 2 {
					resp[0] = query[0]
					resp[1] = query[1]
				}
				return resp, nil
			}
			r.cache.Delete(key)
		}
	}

	// Make DoH request (RFC 8484 — POST with application/dns-message)
	req, err := http.NewRequest("POST", r.endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh response status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	// Cache the response
	if key != "" {
		r.cache.Store(key, cacheEntry{
			response:  body,
			expiresAt: time.Now().Add(defaultCacheTTL),
		})
	}

	return body, nil
}

// IsDNSPacket checks if the packet is a DNS query (destination port 53).
// pkt should be a raw IP packet.
func IsDNSPacket(pkt []byte) (bool, []byte) {
	if len(pkt) < 20 {
		return false, nil
	}

	// Check IPv4
	version := pkt[0] >> 4
	if version != 4 {
		return false, nil
	}

	headerLen := int(pkt[0]&0x0f) * 4
	if len(pkt) < headerLen+8 {
		return false, nil
	}

	proto := pkt[9]
	if proto != 17 { // UDP
		return false, nil
	}

	dstPort := uint16(pkt[headerLen+2])<<8 | uint16(pkt[headerLen+3])
	if dstPort != 53 {
		return false, nil
	}

	// Extract DNS payload (skip UDP header: 8 bytes)
	udpPayloadStart := headerLen + 8
	if len(pkt) < udpPayloadStart {
		return false, nil
	}

	return true, pkt[udpPayloadStart:]
}

// BuildDNSResponse wraps a DNS response payload back into a UDP/IP packet.
// srcIP is the DNS server IP (e.g. the original destination), dstIP is the client.
func BuildDNSResponse(dnsResp []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	udpLen := 8 + len(dnsResp)
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[1] = 0    // DSCP/ECN
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[4] = 0 // identification
	pkt[5] = 0
	pkt[6] = 0x40 // flags: Don't Fragment
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol: UDP
	// checksum filled below
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	// IP header checksum (required — macOS utun validates it)
	ipCsum := ipChecksum(pkt[:20])
	pkt[10] = byte(ipCsum >> 8)
	pkt[11] = byte(ipCsum)

	// UDP header
	pkt[20] = byte(srcPort >> 8)
	pkt[21] = byte(srcPort)
	pkt[22] = byte(dstPort >> 8)
	pkt[23] = byte(dstPort)
	pkt[24] = byte(udpLen >> 8)
	pkt[25] = byte(udpLen)

	// DNS payload
	copy(pkt[28:], dnsResp)

	// UDP checksum (over pseudo-header + UDP)
	udpCsum := udpChecksum(pkt[12:16], pkt[16:20], pkt[20:])
	pkt[26] = byte(udpCsum >> 8)
	pkt[27] = byte(udpCsum)

	return pkt
}

// ipChecksum computes the RFC 791 IP header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the pseudo-header and UDP segment.
func udpChecksum(srcIP, dstIP, udpSegment []byte) uint16 {
	var sum uint32
	// Pseudo-header: srcIP, dstIP, zero, proto(17), UDP length
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += 17 // protocol
	sum += uint32(len(udpSegment))

	// UDP segment
	for i := 0; i+1 < len(udpSegment); i += 2 {
		sum += uint32(udpSegment[i])<<8 | uint32(udpSegment[i+1])
	}
	if len(udpSegment)%2 == 1 {
		sum += uint32(udpSegment[len(udpSegment)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff // RFC 768: 0 means "no checksum", use 0xffff instead
	}
	return csum
}

// extractQueryKey builds a simple cache key from the DNS query's question section.
func extractQueryKey(query []byte) string {
	if len(query) < 12 {
		return ""
	}
	// Questions start at byte 12
	pos := 12
	var name []byte
	for pos < len(query) {
		labelLen := int(query[pos])
		if labelLen == 0 {
			pos++
			break
		}
		if pos+1+labelLen > len(query) {
			return ""
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, query[pos+1:pos+1+labelLen]...)
		pos += 1 + labelLen
	}
	// Append query type (2 bytes)
	if pos+2 > len(query) {
		return string(name)
	}
	qtype := uint16(query[pos])<<8 | uint16(query[pos+1])
	return fmt.Sprintf("%s/%d", name, qtype)
}

// ExtractDNSInfo extracts source IP, source port, and dest IP from a DNS query IP packet.
func ExtractDNSInfo(pkt []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16) {
	if len(pkt) < 28 {
		return
	}
	headerLen := int(pkt[0]&0x0f) * 4
	srcIP = net.IP(pkt[12:16]).To4()
	dstIP = net.IP(pkt[16:20]).To4()
	srcPort = uint16(pkt[headerLen])<<8 | uint16(pkt[headerLen+1])
	dstPort = uint16(pkt[headerLen+2])<<8 | uint16(pkt[headerLen+3])
	return
}
