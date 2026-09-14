# BluePanel Protocol Contract

`common/service.proto` in this repository is the canonical wire/API contract for the BluePanel node ecosystem.

Consumers of this contract:

- [`hazhanhasani/node_bridge`](https://github.com/hazhanhasani/node_bridge) — Go client bridge
- [`hazhanhasani/node_bridge_py`](https://github.com/hazhanhasani/node_bridge_py) — Python client bridge used by BluePanel
- [`hazhanhasani/panel`](https://github.com/hazhanhasani/panel) — management panel, through `BluePanelNodeBridge`

## Compatibility rule

Any wire/API change in `common/service.proto` must be reflected in both bridge repositories before a coordinated BluePanel release. The panel repository contains the cross-repository component contract and CI checks that validate protocol compatibility between all four repositories.

The generated protobuf files are implementation artifacts; `common/service.proto` is the source of truth.
