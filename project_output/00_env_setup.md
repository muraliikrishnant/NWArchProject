# Phase 0 - Environment Check and Setup

## Execution Context

This phase could not be executed on the target Ubuntu 22.04 VM from the current Codex session.

- Current host detected by Codex: `Darwin` (macOS), not Ubuntu
- Home path `~/project_output` is not writable from this sandbox
- `mn`, `ovs-ofctl`, `tshark`, and `wireshark` are not currently installed in this session

The file below records:

1. What was actually detected in the current session
2. The exact Ubuntu 22.04 commands to run on the VM
3. The verification commands and expected summary format

## Actual Checks Performed In This Session

```bash
$ uname -a
Darwin Muraliis-MacBook-Pro.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:56:35 PST 2026; root:xnu-12377.91.3~2/RELEASE_ARM64_T6030 arm64

$ which mn python3 ovs-ofctl tshark wireshark git pip3
mn not found
/usr/local/bin/python3
ovs-ofctl not found
tshark not found
wireshark not found
/usr/bin/git
/usr/local/bin/pip3
```

## Ubuntu 22.04 Setup Commands To Run On The VM

### 1. System Packages

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-setuptools python3-networkx \
  python3-matplotlib python3-pexpect xterm openvswitch-switch openvswitch-testcontroller \
  tshark wireshark tcpdump build-essential autoconf automake pkg-config \
  libtool make gcc iproute2 net-tools ethtool curl wget
```

### 2. Check If Mininet Exists

```bash
which mn
mn --version
```

If Mininet is missing, install from source:

```bash
cd ~
git clone https://github.com/mininet/mininet.git
cd mininet
git checkout 2.3.0
PYTHON=python3 ./util/install.sh -a
```

### 3. Check If POX Exists

```bash
test -d ~/pox && echo "POX present" || echo "POX missing"
```

If missing:

```bash
git clone https://github.com/noxrepo/pox ~/pox
```

### 4. Check If Scapy Exists

```bash
python3 -c "import scapy; print('scapy ok')"
```

If missing:

```bash
pip3 install --user scapy
```

### 5. Check If Open vSwitch Exists

```bash
which ovs-ofctl
ovs-ofctl --version
```

If missing:

```bash
sudo apt install -y openvswitch-switch
```

### 6. Check Wireshark and tshark

```bash
which wireshark
which tshark
tshark --version
```

If missing:

```bash
sudo apt install -y wireshark tshark
```

### 7. Final Verification

```bash
mn --version
python3 -c "import scapy; print('scapy ok')"
ovs-ofctl --version
```

## Summary Table Template

| Tool | Installed? | Version |
| --- | --- | --- |
| Mininet | Run on Ubuntu VM | `mn --version` |
| POX | Run on Ubuntu VM | `git -C ~/pox rev-parse --short HEAD` |
| Scapy | Run on Ubuntu VM | `python3 -c "import scapy; print(scapy.__version__)"` |
| Wireshark | Run on Ubuntu VM | `wireshark --version` |
| tshark | Run on Ubuntu VM | `tshark --version` |
| Open vSwitch | Run on Ubuntu VM | `ovs-ofctl --version` |
