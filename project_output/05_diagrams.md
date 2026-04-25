# Phase 5 - Protocol Diagrams

## Figure 1. ARP Packet Structure

```text
+----------------------+------------+----------------------------------+
| Field                | Bytes      | Description                      |
+----------------------+------------+----------------------------------+
| Hardware Type        | 2          | Ethernet = 0x0001                |
| Protocol Type        | 2          | IPv4 = 0x0800                    |
| HLEN                 | 1          | Hardware length = 6              |
| PLEN                 | 1          | Protocol length = 4              |
| Operation            | 2          | Request = 1, Reply = 2           |
| Sender MAC           | 6          | Claimed hardware source address  |
| Sender IP            | 4          | Claimed protocol source address  |
| Target MAC           | 6          | Target hardware address          |
| Target IP            | 4          | Target protocol address          |
+----------------------+------------+----------------------------------+
```

## Figure 2. Normal OpenFlow Control Plane Flow

```mermaid
sequenceDiagram
    participant h1
    participant s1
    participant Controller
    participant h2

    h1->>s1: Data packet
    s1->>Controller: Packet-In (no matching flow)
    Controller->>s1: Flow-Mod (install correct rule)
    s1->>h2: Forward packet
```

## Figure 3. Poisoned Control Plane Flow

```mermaid
sequenceDiagram
    participant h3 as h3 attacker
    participant h1
    participant s1
    participant Controller
    participant h2

    h3->>h1: Forged ARP reply "10.0.0.2 is at h3-MAC"
    h3->>h2: Forged ARP reply "10.0.0.1 is at h3-MAC"
    h1->>s1: Packet to h3-MAC believing it is h2
    s1->>Controller: Packet-In with poisoned path context
    Controller->>s1: Flow-Mod with poisoned forwarding entries
    s1->>h3: Traffic diverted to attacker
    h3->>h2: Relay packet onward
```

## Figure 4. ARP Proxy Defense Flow

```mermaid
sequenceDiagram
    participant h1
    participant s1
    participant Controller
    participant h3 as h3 attacker

    h1->>s1: ARP request for 10.0.0.2
    s1->>Controller: Packet-In containing ARP request
    Controller->>s1: Authoritative ARP reply for 10.0.0.2
    s1->>h1: Trusted ARP reply
    h3->>h1: Forged ARP reply
    s1->>Controller: Packet-In containing forged ARP
    Controller-->>s1: Drop forged reply
```

## Figure 5. Mininet Topology

```text
                       POX Controller
                      127.0.0.1:6633
                             |
                             |
                          +--+--+
                          | s1  |
                          +--+--+
                             |
          +------------------+------------------+
          |                  |                  |
      h1 victim          h2 gateway         h3 attacker
      10.0.0.1           10.0.0.2           10.0.0.3
      00:00:00:00:00:01  00:00:00:00:00:02  00:00:00:00:00:03
```
