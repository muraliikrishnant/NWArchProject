#!/usr/bin/env python3
"""Run the SDN ARP-spoofing experiment end-to-end and save artifacts."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


OUTPUT_DIR = Path(os.environ.get("PROJECT_OUTPUT_DIR", str(Path.home() / "project_output")))
POX_DIR = Path("/root/pox")
CONTROLLER_PORT = 6633


def sh(cmd: list[str], *, capture: bool = False, check: bool = True, stdout=None):
    kwargs = {
        "check": check,
        "text": True,
    }
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.STDOUT
    elif stdout is not None:
        kwargs["stdout"] = stdout
        kwargs["stderr"] = subprocess.STDOUT
    return subprocess.run(cmd, **kwargs)


def write(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def host_table(net: Mininet) -> str:
    lines = [
        "| Host | Role | IP | MAC |",
        "| --- | --- | --- | --- |",
    ]
    roles = {"h1": "victim", "h2": "gateway", "h3": "attacker"}
    for name in ("h1", "h2", "h3"):
        host = net.get(name)
        lines.append(f"| {name} | {roles[name]} | {host.IP()} | {host.MAC()} |")
    return "\n".join(lines) + "\n"


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.5)
    raise RuntimeError(f"Controller on port {port} did not become ready")


def start_controller(module: str, log_name: str) -> subprocess.Popen:
    log_path = OUTPUT_DIR / log_name
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{OUTPUT_DIR}:{env.get('PYTHONPATH', '')}"
    handle = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            "python3",
            str(POX_DIR / "pox.py"),
            "log.level",
            "--INFO",
            "openflow.of_01",
            f"--port={CONTROLLER_PORT}",
            module,
        ],
        cwd=POX_DIR,
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    wait_for_port(CONTROLLER_PORT)
    return proc


def stop_process(proc: subprocess.Popen | None):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def build_net() -> Mininet:
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=CONTROLLER_PORT)
    s1 = net.addSwitch("s1", protocols="OpenFlow10", datapath="user")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)
    net.start()
    time.sleep(2)
    return net


def cleanup_mininet():
    sh(["pkill", "-f", "/root/pox/pox.py"], check=False)
    sh(["mn", "-c"], check=False)


def save_cmd(host, command: str, outfile: str):
    write(OUTPUT_DIR / outfile, host.cmd(command))


def http_request(host, path: str, outfile: str):
    command = f"""python3 - <<'PY'
import socket
import sys

s = socket.create_connection(("10.0.0.2", 80), 3)
s.settimeout(3)
s.sendall(b"GET {path} HTTP/1.1\\r\\nHost: 10.0.0.2\\r\\nConnection: close\\r\\n\\r\\n")
parts = []
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        parts.append(chunk)
except socket.timeout:
    pass
s.close()
sys.stdout.write(b"".join(parts).decode("latin1", "ignore"))
PY"""
    write(OUTPUT_DIR / outfile, host.cmd(command))


def send_plaintext_http(host, path: str, outfile: str, dst_mac: str):
    command = f"""python3 - <<'PY'
from scapy.all import Ether, IP, TCP, get_if_hwaddr, sendp

iface = "{host.defaultIntf()}"
dst_mac = "{dst_mac}"
payload = (
    b"GET {path} HTTP/1.1\\r\\n"
    b"Host: 10.0.0.2\\r\\n"
    b"Authorization: Basic YWxpY2U6cnV0Z2Vycw==\\r\\n"
    b"Connection: close\\r\\n\\r\\n"
)
pkt = (
    Ether(src=get_if_hwaddr(iface), dst=dst_mac)
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=44444, dport=80, flags="PA", seq=1, ack=1)
    / payload
)
sendp(pkt, iface=iface, verbose=False)
print(f"iface={{iface}} dst_mac={{dst_mac}} path={path}")
PY"""
    write(OUTPUT_DIR / outfile, host.cmd(command))


def collect_baseline(net: Mininet):
    h1, h2 = net.get("h1", "h2")
    write(OUTPUT_DIR / "host_table.md", host_table(net))
    loss = net.pingAll()
    write(OUTPUT_DIR / "pingall.txt", f"pingAll packet loss: {loss:.2f}%\n")

    h2.cmd("pkill -f 'http.server 80' >/dev/null 2>&1 || true")
    h2.cmd("python3 -m http.server 80 >/root/project_output/http_server.log 2>&1 &")
    time.sleep(1)

    save_cmd(h1, "arp -n", "arp_h1_before.txt")
    save_cmd(h2, "arp -n", "arp_h2_before.txt")
    http_request(h1, "/", "http_baseline.txt")
    sh(["bash", str(OUTPUT_DIR / "dump_flows.sh"), "before"])


def run_attack_phase(net: Mininet):
    h1, h2, h3 = net.get("h1", "h2", "h3")
    capture_out = open(OUTPUT_DIR / "capture_credentials_stdout.log", "w", encoding="utf-8")
    attack_out = open(OUTPUT_DIR / "arp_spoof_attack.log", "w", encoding="utf-8")

    capture = h3.popen(
        ["python3", "/root/project_output/capture_credentials.py", "h3-eth0"],
        stdout=capture_out,
        stderr=subprocess.STDOUT,
    )
    attack = h3.popen(
        ["python3", "/root/project_output/arp_spoof_attack.py", "10.0.0.1", "10.0.0.2", "h3-eth0"],
        stdout=attack_out,
        stderr=subprocess.STDOUT,
    )

    time.sleep(6)
    save_cmd(h1, "arp -n", "arp_h1_after.txt")
    save_cmd(h2, "arp -n", "arp_h2_after.txt")
    send_plaintext_http(
        h1,
        "/?user=alice&password=rutgers-demo",
        "http_attack_response.txt",
        "00:00:00:00:00:03",
    )
    time.sleep(3)
    sh(["bash", str(OUTPUT_DIR / "dump_flows.sh"), "after"])

    stop_process(attack)
    time.sleep(3)
    stop_process(capture)
    time.sleep(1)

    save_cmd(h1, "arp -n", "arp_h1_restored.txt")
    save_cmd(h2, "arp -n", "arp_h2_restored.txt")


def run_mitigation_phase():
    cleanup_mininet()
    controller = start_controller("pox_arp_proxy", "controller_mitigation.log")
    net = build_net()
    try:
        h1, h2, h3 = net.get("h1", "h2", "h3")
        h2.cmd("pkill -f 'http.server 80' >/dev/null 2>&1 || true")
        h2.cmd("python3 -m http.server 80 >/root/project_output/http_server_mitigation.log 2>&1 &")
        time.sleep(1)

        with open(OUTPUT_DIR / "static_flows_installed.txt", "w", encoding="utf-8") as handle:
            sh(["python3", str(OUTPUT_DIR / "static_flow_installer.py")], stdout=handle)

        capture = h3.popen(
            ["python3", "/root/project_output/capture_credentials.py", "h3-eth0"],
            stdout=open(OUTPUT_DIR / "capture_credentials_mitigation.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        attack = h3.popen(
            ["python3", "/root/project_output/arp_spoof_attack.py", "10.0.0.1", "10.0.0.2", "h3-eth0"],
            stdout=open(OUTPUT_DIR / "arp_spoof_mitigation.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )

        time.sleep(6)
        save_cmd(h1, "arp -n", "arp_h1_mitigated.txt")
        save_cmd(h2, "arp -n", "arp_h2_mitigated.txt")
        send_plaintext_http(
            h1,
            "/?user=bob&password=blocked",
            "http_mitigation_response.txt",
            "00:00:00:00:00:02",
        )
        time.sleep(3)
        write(
            OUTPUT_DIR / "flows_mitigated.txt",
            sh(["ovs-ofctl", "dump-flows", "s1"], capture=True).stdout,
        )

        stop_process(attack)
        stop_process(capture)
    finally:
        net.stop()
        stop_process(controller)
        cleanup_mininet()


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_mininet()

    write(
        OUTPUT_DIR / "tool_versions.txt",
        "\n".join(
            [
                sh(["mn", "--version"], capture=True).stdout.strip(),
                sh(["python3", "-c", "import scapy; print(scapy.__version__)"], capture=True).stdout.strip(),
                sh(["ovs-ofctl", "--version"], capture=True).stdout.splitlines()[0],
                sh(["tshark", "--version"], capture=True).stdout.splitlines()[1],
                sh(["git", "-C", str(POX_DIR), "rev-parse", "--short", "HEAD"], capture=True).stdout.strip(),
            ]
        )
        + "\n",
    )

    baseline_controller = start_controller("pox_l2_learning", "controller_vulnerable.log")
    net = build_net()
    try:
        collect_baseline(net)
        run_attack_phase(net)
    finally:
        net.stop()
        stop_process(baseline_controller)
        cleanup_mininet()

    run_mitigation_phase()


if __name__ == "__main__":
    setLogLevel("warning")
    main()
