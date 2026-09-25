FROM golang:1.24-alpine AS builder

RUN apk add --no-cache make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make server

FROM alpine:3.21

RUN apk add --no-cache iptables iproute2

COPY --from=builder /src/bin/shadowtunnel-server /usr/local/bin/shadowtunnel-server

EXPOSE 5432

ENTRYPOINT ["shadowtunnel-server"]
CMD ["-config", "/etc/shadowtunnel/server.yaml"]
