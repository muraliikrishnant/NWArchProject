#!/usr/bin/env python3
"""Mininet topology for ARP spoofing in an SDN lab."""

import os

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
    controller_ip = os.environ.get("SDN_CONTROLLER_IP", "127.0.0.1")
    controller_port = int(os.environ.get("SDN_CONTROLLER_PORT", "6633"))
    datapath = os.environ.get("SDN_OVS_DATAPATH")
    interactive = os.environ.get("SDN_NO_CLI", "0") != "1"

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    info("*** Adding remote controller\n")
    net.addController("c0", controller=RemoteController, ip=controller_ip, port=controller_port)

    info("*** Adding switch s1 (OpenFlow10)\n")
    switch_kwargs = {"protocols": "OpenFlow10"}
    if datapath:
        switch_kwargs["datapath"] = datapath
    net.addSwitch("s1", **switch_kwargs)

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

    if interactive:
        info("\n*** Opening Mininet CLI\n")
        CLI(net)
    else:
        info("\n*** SDN_NO_CLI=1 set, skipping CLI\n")

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
