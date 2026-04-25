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
