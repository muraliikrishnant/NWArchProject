#!/usr/bin/env python3
"""Compare flow dump files before and after an attack."""

from collections import Counter
from pathlib import Path
import re


BEFORE = Path.home() / "project_output" / "flows_before.txt"
AFTER = Path.home() / "project_output" / "flows_after.txt"
REPORT = Path.home() / "project_output" / "03_flow_analysis.md"


def load(path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if "priority=" in line]


def extract_dst_mac(entry):
    match = re.search(r"dl_dst=([^, ]+)", entry)
    return match.group(1) if match else "-"


def suspicious(entry):
    return "arp" in entry.lower() or "CONTROLLER" in entry or "dl_dst=" not in entry


def main():
    before = load(BEFORE)
    after = load(AFTER)

    before_count = Counter(before)
    after_count = Counter(after)
    all_entries = sorted(set(before) | set(after))

    lines = [
        "# Phase 3 - Flow Table Analysis",
        "",
        "## Input Files",
        "",
        f"- Before: `{BEFORE}`",
        f"- After: `{AFTER}`",
        "",
        "## Comparison Table",
        "",
        "| Flow Entry | Before | After | Delta | Suspicious? |",
        "| --- | ---: | ---: | ---: | --- |",
    ]

    new_entries = []
    for entry in all_entries:
        b = before_count.get(entry, 0)
        a = after_count.get(entry, 0)
        delta = a - b
        flag = "yes" if suspicious(entry) else "no"
        lines.append(f"| `{entry}` | {b} | {a} | {delta} | {flag} |")
        if b == 0 and a > 0:
            new_entries.append(entry)

    before_macs = Counter(extract_dst_mac(entry) for entry in before)
    after_macs = Counter(extract_dst_mac(entry) for entry in after)
    duplicate_after = [mac for mac, count in after_macs.items() if mac != "-" and count > 1]

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total flow entries before: {len(before)}",
            f"- Total flow entries after: {len(after)}",
            f"- New entries after the attack: {len(new_entries)}",
            f"- Duplicate destination MAC matches after the attack: {', '.join(duplicate_after) if duplicate_after else 'none detected'}",
            "",
            "## Interpretation",
            "",
            "The control-plane impact is visible when post-attack flow dumps contain new forwarding rules that are consistent with traffic first reaching the attacker rather than the intended endpoint. In a reactive OpenFlow design, the switch punts unknown traffic to the controller, and the controller installs rules based on what it sees. If ARP poisoning changes who receives the first packet, the controller can reinforce the poisoned path with new flow entries.",
            "",
            "This is worse than traditional ARP spoofing because the compromise is no longer limited to endpoint cache state. The controller programs the switch using observations derived from poisoned traffic, so the malicious path can persist as switch state even after the initial forged ARP replies.",
        ]
    )

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
