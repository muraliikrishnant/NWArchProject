# Phase 4 - Mitigations

## Source: `pox_arp_proxy.py`

```python
"""POX controller module implementing controller-side ARP proxying."""

from datetime import datetime

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.revent import EventMixin


log = core.getLogger()

TRUSTED = {
    IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
    IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
    IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
}


def stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ArpProxy(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("POX ARP proxy loaded")

    def _send_arp_reply(self, event, request):
        trusted_mac = TRUSTED[request.protodst]
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = trusted_mac
        reply.hwdst = request.hwsrc
        reply.protosrc = request.protodst
        reply.protodst = request.protosrc

        frame = ethernet(type=ethernet.ARP_TYPE, src=trusted_mac, dst=request.hwsrc)
        frame.set_payload(reply)

        msg = of.ofp_packet_out()
        msg.data = frame.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        msg.in_port = of.OFPP_NONE
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        arp_pkt = packet.find("arp")
        if arp_pkt is None:
            return

        verdict = "trusted"
        claimed_ip = arp_pkt.protosrc
        claimed_mac = arp_pkt.hwsrc

        if arp_pkt.opcode == arp.REQUEST:
            if arp_pkt.protodst in TRUSTED:
                log.info(
                    "[%s] ARP request src_ip=%s src_mac=%s target_ip=%s verdict=trusted",
                    stamp(),
                    claimed_ip,
                    claimed_mac,
                    arp_pkt.protodst,
                )
                self._send_arp_reply(event, arp_pkt)
            return

        if arp_pkt.opcode == arp.REPLY:
            if claimed_ip in TRUSTED and TRUSTED[claimed_ip] != claimed_mac:
                verdict = "dropped"
                log.warning(
                    "[%s] ARP reply src_ip=%s src_mac=%s verdict=%s",
                    stamp(),
                    claimed_ip,
                    claimed_mac,
                    verdict,
                )
                return

            log.info(
                "[%s] ARP reply src_ip=%s src_mac=%s verdict=%s",
                stamp(),
                claimed_ip,
                claimed_mac,
                verdict,
            )


def launch():
    core.registerNew(ArpProxy)
```

## Source: `static_flow_installer.py`

```python
#!/usr/bin/env python3
"""Install high-priority static flow rules for the SDN lab."""

import subprocess


RULES = [
    (
        "h1_to_h2",
        'priority=65535,in_port=1,dl_dst=00:00:00:00:00:02,actions=output:2',
    ),
    (
        "h2_to_h1",
        'priority=65535,in_port=2,dl_dst=00:00:00:00:00:01,actions=output:1',
    ),
    (
        "h1_to_h3",
        'priority=65535,in_port=1,dl_dst=00:00:00:00:00:03,actions=output:3',
    ),
    (
        "h3_to_h1",
        'priority=65535,in_port=3,dl_dst=00:00:00:00:00:01,actions=output:1',
    ),
]


def main():
    installed = []
    for name, rule in RULES:
        subprocess.run(["sudo", "ovs-ofctl", "add-flow", "s1", rule], check=True)
        installed.append((name, rule))

    print("| Rule | Installed | Match/Action |")
    print("| --- | --- | --- |")
    for name, rule in installed:
        print(f"| {name} | yes | `{rule}` |")


if __name__ == "__main__":
    main()
```

## Comparison Table

| Attack Vector | Vulnerable (L2 Learning) | Protected (ARP Proxy) | Protected (Static Flows) |
| --- | --- | --- | --- |
| Forged ARP reply accepted by host | yes | blocked by authoritative reply model | partially reduced |
| Controller learns from poisoned path | yes | reduced because fake ARP state is suppressed | reduced because forwarding is pre-pinned |
| MITM persistence | high | low | medium |
| Flexibility | high | medium | low |

## Protocol-Level Explanation

The ARP proxy mitigation changes the trust boundary. Instead of allowing any host to answer ARP requests, the controller becomes the authoritative responder and compares observed ARP replies against a known IP-to-MAC table. A forged reply that contradicts the trusted table is dropped immediately and logged as an anomaly.

The static flow mitigation addresses a different layer of the problem. It pre-installs high-priority rules that force known-good traffic paths between specific MAC addresses and ports. Because the rules use priority `65535`, reactive forwarding logic should not override them under normal conditions.

## Limitations

The ARP proxy depends on a trusted mapping database that must stay accurate. In dynamic environments with DHCP or host churn, maintaining that database can become operationally expensive. The static flow approach scales even less effectively because every relevant communication pair must be encoded ahead of time, which reduces SDN flexibility and increases management overhead.
