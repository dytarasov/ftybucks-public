package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const configDir = ".config/ftybucks"
const configFile = "client.yaml"

func configSearchPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, configDir, configFile)
}

func findConfig() string {
	// 1. ~/.config/ftybucks/client.yaml
	if p := configSearchPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// 2. ./configs/client.yaml (dev)
	if _, err := os.Stat("configs/client.yaml"); err == nil {
		return "configs/client.yaml"
	}
	return ""
}

func runSetupWizard() string {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println()
	fmt.Println("==============================")
	fmt.Println("  FtyBucks — Setup")
	fmt.Println("==============================")
	fmt.Println()

	server := promptRequired(scanner, "Server (ip:port)", validateHostPort)
	psk := promptRequired(scanner, "PSK (base64)", validateBase64)
	tunCIDR := promptDefault(scanner, "TUN CIDR", "10.7.0.2/24", validateCIDR)
	dns := promptDefault(scanner, "DNS", "https://1.1.1.1/dns-query", nil)
	paddingMax := promptDefault(scanner, "Padding max", "64", validateInt)

	yaml := fmt.Sprintf(`server: "%s"
tun_name: "stun0"
tun_cidr: "%s"
dns: "%s"
psk: "%s"
jitter_ms: 0
padding:
  min: 0
  max: %s
`, server, tunCIDR, dns, psk, paddingMax)

	outPath := configSearchPath()
	if outPath == "" {
		fmt.Fprintln(os.Stderr, "error: cannot determine home directory")
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating config dir: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, []byte(yaml), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nConfig saved to %s\n\n", outPath)
	return outPath
}

func promptRequired(scanner *bufio.Scanner, label string, validate func(string) error) string {
	for {
		fmt.Printf("%s: ", label)
		if !scanner.Scan() {
			os.Exit(1)
		}
		val := strings.TrimSpace(scanner.Text())
		if val == "" {
			fmt.Println("  required, cannot be empty")
			continue
		}
		if validate != nil {
			if err := validate(val); err != nil {
				fmt.Printf("  %v\n", err)
				continue
			}
		}
		return val
	}
}

func promptDefault(scanner *bufio.Scanner, label, def string, validate func(string) error) string {
	for {
		fmt.Printf("%s [%s]: ", label, def)
		if !scanner.Scan() {
			os.Exit(1)
		}
		val := strings.TrimSpace(scanner.Text())
		if val == "" {
			return def
		}
		if validate != nil {
			if err := validate(val); err != nil {
				fmt.Printf("  %v\n", err)
				continue
			}
		}
		return val
	}
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid host:port format")
	}
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("port must be a number")
	}
	return nil
}

func validateBase64(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid base64")
	}
	if len(b) != 32 {
		return fmt.Errorf("PSK must be 32 bytes (got %d)", len(b))
	}
	return nil
}

func validateCIDR(s string) error {
	_, _, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation")
	}
	return nil
}

func validateInt(s string) error {
	_, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("must be a number")
	}
	return nil
}
