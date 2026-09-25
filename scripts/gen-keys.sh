#!/bin/bash
# Generate a random 32-byte PSK encoded as base64
PSK=$(openssl rand -base64 32)
echo "Generated PSK (add to both client.yaml and server.yaml):"
echo "  psk: \"$PSK\""
