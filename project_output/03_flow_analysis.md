# Phase 3 - Flow Table Analysis

## Input Files

- Before: `/root/project_output/flows_before.txt`
- After: `/root/project_output/flows_after.txt`

## Comparison Table

| Flow Entry | Before | After | Delta | Suspicious? |
| --- | ---: | ---: | ---: | --- |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=2 actions=output:2` | 0 | 1 | 1 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:03,arp_spa=10.0.0.1,arp_tpa=10.0.0.3,arp_op=2 actions=output:3` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=1 actions=output:1` | 0 | 1 | 1 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=2 actions=output:1` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:03,arp_spa=10.0.0.2,arp_tpa=10.0.0.3,arp_op=2 actions=output:3` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,arp_spa=10.0.0.2,arp_tpa=10.0.0.1,arp_op=2 actions=output:1` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,arp_spa=10.0.0.3,arp_tpa=10.0.0.1,arp_op=1 actions=output:1` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,arp_spa=10.0.0.3,arp_tpa=10.0.0.1,arp_op=2 actions=output:1` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,arp_spa=10.0.0.1,arp_tpa=10.0.0.2,arp_op=2 actions=output:2` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, arp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,arp_spa=10.0.0.3,arp_tpa=10.0.0.2,arp_op=2 actions=output:2` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:2` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:2` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.1,nw_dst=10.0.0.3,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:3` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.1,nw_dst=10.0.0.3,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:3` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:1` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:1` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.2,nw_dst=10.0.0.3,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:3` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.2,nw_dst=10.0.0.3,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:3` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.3,nw_dst=10.0.0.1,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:1` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.3,nw_dst=10.0.0.1,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:1` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.3,nw_dst=10.0.0.1,nw_tos=192,icmp_type=5,icmp_code=1 actions=output:1` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.3,nw_dst=10.0.0.2,nw_tos=0,icmp_type=0,icmp_code=0 actions=output:2` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.3,nw_dst=10.0.0.2,nw_tos=0,icmp_type=8,icmp_code=0 actions=output:2` | 1 | 1 | 0 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, icmp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.3,nw_dst=10.0.0.2,nw_tos=192,icmp_type=5,icmp_code=1 actions=output:2` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, tcp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,tp_src=49130,tp_dst=80 actions=output:2` | 1 | 1 | 0 | no |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, tcp,vlan_tci=0x0000,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,tp_src=44444,tp_dst=80 actions=output:3` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, tcp,vlan_tci=0x0000,dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:03,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,tp_src=80,tp_dst=44444 actions=output:3` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, tcp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,nw_src=10.0.0.2,nw_dst=10.0.0.1,nw_tos=0,tp_src=80,tp_dst=44444 actions=output:1` | 0 | 1 | 1 | yes |
| `cookie=0x0, table=0, idle_timeout=30, hard_timeout=60, tcp,vlan_tci=0x0000,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:02,nw_src=10.0.0.1,nw_dst=10.0.0.2,nw_tos=0,tp_src=44444,tp_dst=80 actions=output:2` | 0 | 1 | 1 | yes |

## Summary

- Total flow entries before: 16
- Total flow entries after: 29
- New entries after the attack: 13
- Duplicate destination MAC matches after the attack: 00:00:00:00:00:01, 00:00:00:00:00:02, 00:00:00:00:00:03

## Interpretation

The control-plane impact is visible when post-attack flow dumps contain new forwarding rules that are consistent with traffic first reaching the attacker rather than the intended endpoint. In a reactive OpenFlow design, the switch punts unknown traffic to the controller, and the controller installs rules based on what it sees. If ARP poisoning changes who receives the first packet, the controller can reinforce the poisoned path with new flow entries.

This is worse than traditional ARP spoofing because the compromise is no longer limited to endpoint cache state. The controller programs the switch using observations derived from poisoned traffic, so the malicious path can persist as switch state even after the initial forged ARP replies.
