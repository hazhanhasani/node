# BluePanel Node

BluePanel Node is the remote execution layer for BluePanel. It runs Xray/WireGuard backends and communicates with the BluePanel panel over the supported node protocol.

This repository is the canonical source for BluePanel Node changes and releases:

```text
https://github.com/hazhanhasani/node
```

## Local Docker deployment

```bash
git clone https://github.com/hazhanhasani/node.git
cd node
docker compose up -d --build
```

The default service port is `62050` using gRPC.

Persistent node data is stored under:

```text
/var/lib/bluepanel-node
```

## BluePanel integration

The main panel repository is:

```text
https://github.com/hazhanhasani/panel
```

BluePanel-specific Tor multi-exit and Xray egress functionality will be developed in this node layer.

## License

This project keeps the original open-source license and all legally required notices. Product branding, release feeds and deployment paths are maintained independently for BluePanel.
