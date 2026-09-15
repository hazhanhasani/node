FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make install_xray

FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/hazhanhasani/node"
LABEL org.opencontainers.image.title="BluePanel Node"

# Tor runs as independent child processes owned by BluePanel Node. SOCKS and
# Control listeners are configured on loopback only; host networking is used by
# the existing deployment so Xray can route to the per-location listeners.
RUN apk update && apk add --no-cache wireguard-tools nftables iproute2 procps tor ca-certificates

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray

ENTRYPOINT ["./main"]
