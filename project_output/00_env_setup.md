# Phase 0 - Environment Check and Setup

## Execution Context

The experiment was executed in a privileged Ubuntu 22.04 Docker container with the assignment directory mounted at `/root/project_output`.

- Host platform: Docker Desktop on macOS
- Lab OS inside container: Ubuntu 22.04 userspace on Linux kernel `6.12.76-linuxkit`
- Important OVS note: the kernel `openvswitch` module was unavailable, so the Mininet switch was run with the OVS userspace datapath (`datapath=netdev` / Mininet `datapath="user"`). This still allowed OpenFlow 1.0 flow inspection with `ovs-ofctl`.

## Verified Tool Versions

| Tool | Installed? | Version / Identifier |
| --- | --- | --- |
| Mininet | yes | `2.3.0` |
| POX | yes | commit `5f82461` |
| Scapy | yes | `2.4.4` |
| Open vSwitch | yes | `ovs-ofctl (Open vSwitch) 2.17.9` |
| tshark | yes | `TShark (Wireshark) 3.6.2` |
| Python | yes | `3.10` |

## Commands Used

```bash
apt-get update
apt-get install -y mininet openvswitch-switch tshark tcpdump git curl net-tools \
  iproute2 iputils-ping python3 python3-pip python3-scapy python3-twisted
git clone https://github.com/noxrepo/pox /root/pox
service dbus start
service openvswitch-switch start
ovs-vswitchd --pidfile --detach --log-file
```

## Verification Output

```text
mn --version                     -> 2.3.0
python3 -c "import scapy; print(scapy.__version__)" -> 2.4.4
ovs-ofctl --version             -> ovs-ofctl (Open vSwitch) 2.17.9
tshark --version                -> TShark (Wireshark) 3.6.2
git -C /root/pox rev-parse --short HEAD -> 5f82461
```

## Environment Constraints

- POX printed a Python compatibility warning because it prefers Python 3.6-3.9, but the controller still operated correctly on Python 3.10 for this assignment.
- Because the OVS kernel datapath was unavailable in Docker Desktop, the topology script was adjusted to run OVS in userspace mode. The experimental results reported later in this submission come from that real userspace-Ovs/Mininet execution, not from placeholder data.
