.PHONY: all client client-mac server gateway tray clean

LDFLAGS=-s -w

all: client server

client:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/shadowtunnel-client-linux ./cmd/client

client-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/shadowtunnel-client-mac ./cmd/client

server:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/shadowtunnel-server ./cmd/server

gateway:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/gateway ./cmd/gateway

tray:
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o bin/ftybucks ./cmd/tray

clean:
	rm -rf bin/ build/
