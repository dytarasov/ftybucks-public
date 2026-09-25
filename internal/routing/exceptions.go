package routing

import (
	"context"
	"log"
	"net"
	"time"

	"ftybucks/internal/config"
)

const resolveInterval = 5 * time.Minute

type ExceptionResolver struct {
	routing *Manager
	rules   []config.ExceptionRule
}

func NewExceptionResolver(routing *Manager, rules []config.ExceptionRule) *ExceptionResolver {
	return &ExceptionResolver{
		routing: routing,
		rules:   rules,
	}
}

// Start applies CIDR rules immediately, then resolves domains periodically.
func (er *ExceptionResolver) Start(ctx context.Context) {
	// Apply static CIDRs once
	er.applyCIDRs()

	// Initial domain resolve
	er.resolveDomains()

	ticker := time.NewTicker(resolveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			er.resolveDomains()
		}
	}
}

func (er *ExceptionResolver) applyCIDRs() {
	for _, rule := range er.rules {
		if rule.CIDR == "" {
			continue
		}

		var err error
		switch rule.Direction {
		case "proxy":
			err = er.routing.AddProxyIP(rule.CIDR)
		case "direct":
			err = er.routing.AddDirectIP(rule.CIDR)
		}
		if err != nil {
			log.Printf("[exceptions] add cidr %s to %s: %v", rule.CIDR, rule.Direction, err)
		}
	}
}

func (er *ExceptionResolver) resolveDomains() {
	for _, rule := range er.rules {
		if rule.Domain == "" {
			continue
		}

		ips, err := net.LookupHost(rule.Domain)
		if err != nil {
			log.Printf("[exceptions] resolve %s: %v", rule.Domain, err)
			continue
		}

		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.To4() == nil {
				continue
			}

			var addErr error
			switch rule.Direction {
			case "proxy":
				addErr = er.routing.AddProxyIP(ipStr)
			case "direct":
				addErr = er.routing.AddDirectIP(ipStr)
			}
			if addErr != nil {
				log.Printf("[exceptions] add %s (%s) to %s: %v", rule.Domain, ipStr, rule.Direction, addErr)
			}
		}
	}
}
