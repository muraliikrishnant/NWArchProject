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
