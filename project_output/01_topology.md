# Phase 1 - SDN Topology

## Topology Source: `sdn_topology.py`

```python
#!/usr/bin/env python3
"""Mininet topology for ARP spoofing in an SDN lab."""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def markdown_host_table(net):
    lines = [
        "| Host | Role | IP | MAC |",
        "| --- | --- | --- | --- |",
    ]
    roles = {"h1": "victim", "h2": "gateway", "h3": "attacker"}
    for name in ("h1", "h2", "h3"):
        host = net.get(name)
        lines.append(f"| {name} | {roles[name]} | {host.IP()} | {host.MAC()} |")
    return "\n".join(lines)


def main():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    info("*** Adding remote controller\n")
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)

    info("*** Adding switch s1 (OpenFlow10)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow10")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    info("*** Adding 10 Mbps links\n")
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)

    info("*** Starting network\n")
    net.start()

    info("\n## Host Address Table\n")
    print(markdown_host_table(net))

    info("\n## Connectivity Test\n")
    loss = net.pingAll()
    print(f"pingAll packet loss: {loss:.2f}%")

    info("\n*** Opening Mininet CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
```

## Controller Source: `pox_l2_learning.py`

```python
"""Standalone POX reactive L2 learning switch vulnerable to ARP poisoning."""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.revent import EventMixin


log = core.getLogger()


class LearningSwitch(EventMixin):
    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)

    def _install(self, packet, port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        in_port = event.port
        self.mac_to_port[packet.src] = in_port

        arp_pkt = packet.find("arp")
        if arp_pkt is not None:
            log.info(
                "ARP observed: opcode=%s src_ip=%s src_mac=%s dst_ip=%s ingress=%s",
                "reply" if arp_pkt.opcode == arp.REPLY else "request",
                arp_pkt.protosrc,
                arp_pkt.hwsrc,
                arp_pkt.protodst,
                in_port,
            )
            # Intentionally vulnerable behavior: the controller does not validate
            # ARP claims and simply learns from traffic it receives.

        if packet.dst.is_multicast or packet.dst not in self.mac_to_port:
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = in_port
            self.connection.send(msg)
            return

        out_port = self.mac_to_port[packet.dst]
        self._install(packet, out_port)

        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = in_port
        self.connection.send(msg)


class L2LearningController(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        log.info("POX L2 learning controller loaded on 6633")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.connection)
        LearningSwitch(event.connection)


def launch():
    core.registerNew(L2LearningController)
```

## Topology Diagram

```text
            Remote POX Controller
                 127.0.0.1:6633
                        |
                        |
                       s1
                    /   |   \
                   /    |    \
                 h1     h2    h3
              victim  gateway attacker
             10.0.0.1 10.0.0.2 10.0.0.3
```

## Why The Reactive L2 Learning Switch Is Vulnerable

The controller learns source MAC addresses and installs forwarding rules based on packet observations rather than a trusted IP-to-MAC binding database. That makes it vulnerable to ARP spoofing because forged ARP replies can cause hosts to send traffic toward the attacker MAC, and the controller will then observe packets following the poisoned path.

Once that redirected traffic reaches the switch, the controller reacts exactly as it was designed to react: it emits `Flow-Mod` rules to support the path implied by the packets it sees. In other words, it trusts the data plane state created by unauthenticated ARP exchanges. The vulnerability is therefore not only a host cache problem; it can become persistent switch state in the SDN fabric.
