# OSPFv2Forge Pro \- Architecture & Technical Specification

> **IETF RFC 2328 (OSPF Version 2), RFC 5709 (OSPF Cryptographic Authentication with HMAC-SHA-256) & Database Description (DBD) Deadlock Architecture**

---

## 1\. Executive Summary & Protocol Overview

The **Open Shortest Path First Version 2 (OSPFv2 / IETF RFC 2328\)** is the universal, open standard interior gateway link-state routing protocol deployed across enterprise campus backbones, data center access networks, financial trading infrastructures, and carrier backbones worldwide.

Unlike distance-vector protocols that route by rumor, OSPF routers build a complete, synchronized map of the network topology called the **Link State Database (LSDB)** and run the Dijkstra Shortest Path First (SPF) algorithm to calculate loop-free shortest paths to every destination prefix.

\+-----------------------------------------------------------------------------------------+

|                               OSPFv2 ARCHITECTURAL OVERVIEW                              |

\+--------------------------+---------------------------------------+----------------------+

| Domain                   | Standard Mechanism                    | Operational Impact   |

\+--------------------------+---------------------------------------+----------------------+

| Layer 3 Transport        | Native IP Protocol 89                 | Direct raw IP framing|

|                          | Multicast: 224.0.0.5 & 224.0.0.6      | with no TCP/UDP.     |

\+--------------------------+---------------------------------------+----------------------+

| Adjacency Exchange       | 2-Way \-\> ExStart \-\> Exchange \-\>       | Synchronizes LSDB    |

|                          | Loading \-\> FULL State Machine         | across neighbors.    |

\+--------------------------+---------------------------------------+----------------------+

| Deadlock Vulnerability   | Database Description (DBD) Interface  | Mismatched MTU hangs |

|                          | MTU Field Exchange                    | forever in ExStart.  |

\+--------------------------+---------------------------------------+----------------------+

| Cryptographic Security   | RFC 5709 HMAC-SHA-256 with 32-bit     | Thwarts LSA spoofing |

|                          | Cryptographic Sequence Numbers        | & replay attacks.    |

\+--------------------------+---------------------------------------+----------------------+

| Multi-Access Scalability | Designated Router (DR) & Backup DR    | Reduces adjacencies  |

|                          | (BDR) Election Algorithm              | from N(N-1)/2 to 2N. |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. RFC 2328 OSPFv2 Packet Anatomy & Fixed Header

Every OSPFv2 packet begins with an identical **24-octet fixed header**, followed by the specific packet body:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|   Version (2) |   Type (1-5)  |         Packet Length         |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                          Router ID                            |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                           Area ID                             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|           Checksum            |          AuType (0-2)         |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    Authentication (8 octets)                  |

|                                                               |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Packet Body (Hello, DBD, LSR, LSU, LSAck) ...

\+-+-+-+-+-+-+-+-+-+-+-+-+-

### 2.1 Fixed Header Fields

- **Version (8 bits)**: Set to `2` for IPv4 OSPF.  
- **Type (8 bits)**:  
  - `1`: `Hello` (Discovers and maintains neighbor adjacencies).  
  - `2`: `Database Description (DBD)` (Summarizes the LSDB during adjacency formation).  
  - `3`: `Link State Request (LSR)` (Requests specific out-of-date LSAs).  
  - `4`: `Link State Update (LSU)` (Floods full LSA payloads across the network).  
  - `5`: `Link State Acknowledgment (LSAck)` (Reliably acknowledges LSU receipt).  
- **Packet Length (16 bits)**: Total length in octets, including the 24-byte header.  
- **Router ID (32 bits)**: Highest active loopback IP or highest physical interface IP.  
- **Area ID (32 bits)**: 32-bit identifier of the OSPF area (`0.0.0.0` for Area 0 Backbone).  
- **Checksum (16 bits)**: Standard RFC 1071 internet checksum (set to 0 during AuType 2 calculation).  
- **AuType (16 bits)**:  
  - `0`: Null Authentication (Unauthenticated).  
  - `1`: Simple Password (8-byte cleartext password on wire).  
  - `2`: Cryptographic Authentication (RFC 2328 MD5 or RFC 5709 HMAC-SHA-256).  
- **Authentication (64 bits)**:  
  - For AuType 0: 8 zero bytes.  
  - For AuType 1: 8 bytes cleartext password.  
  - For AuType 2: Key ID (1 byte), Auth Data Length (1 byte), Cryptographic Sequence Number (4 bytes), Reserved (2 bytes). The actual HMAC digest (32 bytes) is appended at the end of the packet.

---

## 3\. The Database Description (DBD) MTU Deadlock Trap

During neighbor adjacency establishment, routers transition through: \$\$\\text{Down} \\longrightarrow \\text{Init} \\longrightarrow \\text{2-Way} \\longrightarrow \\text{ExStart} \\longrightarrow \\text{Exchange} \\longrightarrow \\text{Loading} \\longrightarrow \\text{FULL}\$\$

In the **ExStart** state, routers negotiate Master/Slave status and send **Database Description (DBD)** packets containing their **Interface MTU**:

\+-----------------------------------------------------------------------------------------+

|                               DBD MTU DEADLOCK SEQUENCE                                 |

\+--------------------------+---------------------------------------+----------------------+

| Router A (MTU 1500\)      | Action / Packet                       | Router B (MTU 1492\)  |

\+--------------------------+---------------------------------------+----------------------+

| 1\. Sends DBD             | DBD (MTU: 1500, I=1, M=1, MS=1) \----\> | Receives DBD         |

|                          |                                       | Checks: 1500 \> 1492\! |

\+--------------------------+---------------------------------------+----------------------+

| 2\. Drops DBD             | \<------------------------------------ | Drops Router A's DBD |

|                          |                                       | Stalls in ExStart\!   |

\+--------------------------+---------------------------------------+----------------------+

| 3\. Retransmits DBD       | DBD Retransmit (every 5 seconds) \---\> | Drops packet again.  |

|                          | Endlessly loops in ExStart / Exchange | 100% CPU exhaustion\! |

\+--------------------------+---------------------------------------+----------------------+

### 3.1 Why `ip ospf mtu-ignore` is a Hazardous Workaround

Configuring `ip ospf mtu-ignore` forces the router to ignore the MTU field in received DBDs, allowing the adjacency to reach state `FULL`. However:

- When a router later floods a large Link State Update (LSU) containing dozens of LSAs that exceeds 1492 bytes, the underlying Ethernet switch or PPPoE concentrator **drops the packet at Layer 2 without sending an ICMP message**.  
- OSPF will repeatedly attempt to retransmit the LSU, leading to silent link-state database desynchronization and phantom routing loops\!  
- **Root-Cause Fix**: Always match physical Layer 2 MTU (e.g., both configured to 1500 or both to 9000).

---

## 4\. DR / BDR Multi-Access Election Architecture

On broadcast multi-access segments (e.g., Ethernet VLANs), if every router formed adjacencies with every other router, \$N\$ routers would require \$\\frac{N(N-1)}{2}\$ adjacencies. OSPF elects a **Designated Router (DR)** and **Backup Designated Router (BDR)**:

- Non-DR routers (`DROTHER`) only form full adjacencies with the DR and BDR (\$2N\$ adjacencies).  
- `DROTHER` routers send updates to `224.0.0.6` (AllDRouters).  
- The DR floods updates to `224.0.0.5` (AllSPFRouters).

### 4.1 Election Rules (RFC 2328 Section 9.4)

1. **Priority 0 Disqualification**: Routers with `ip ospf priority 0` can **never** become DR or BDR. Crucial for leaf switches and edge routers.  
2. **Priority Tie-Breaker**: Highest priority wins (1–255). If priorities are equal, the router with the **highest Router ID** wins.  
3. **Non-Preemptive Stability**: If a router with Priority 255 boots after a router with Priority 100 has already assumed the DR role, the existing DR **remains active** to prevent topology recalculation flaps.

---

## 5\. Multi-Area Hierarchy & LSA Types

                    \[ Area 0 (Backbone Area) \]

                     /                      \\

            (ABR Router 1\)              (ABR Router 2\)

                 /                              \\

       \[ Area 1 (Standard) \]           \[ Area 2 (NSSA) \]

       LSA 1 (Router LSA)              LSA 7 (NSSA External)

       LSA 2 (Network LSA)             ABR translates to LSA 5 (P-bit)

       LSA 3 (Summary LSA)             Default route injected

- **LSA Type 1 (Router LSA)**: Flooded within local area; describes router's links.  
- **LSA Type 2 (Network LSA)**: Generated by DR; describes all routers connected to the multi-access segment.  
- **LSA Type 3 (Summary LSA)**: Generated by ABR; advertises inter-area prefixes into other areas.  
- **LSA Type 4 (ASBR Summary LSA)**: Generated by ABR; advertises reachability to an ASBR.  
- **LSA Type 5 (AS-External LSA)**: Generated by ASBR; advertises external routes redistributed from BGP or static routes.  
- **LSA Type 7 (NSSA External LSA)**: Used in Not-So-Stubby Areas. ABR translates Type 7 into Type 5 if the Propagate bit (P-bit) is set.

---

## 6\. 10-Point Zero-Trust Interior Routing (OSPFv2) Audit Framework

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **OSP-SEC-01** | RFC 5709 Cryptographic Authentication | 15 pts | Mandatory HMAC-SHA-256 with 32-bit sequence replay shield. |
| **OSP-SEC-02** | DBD Interface MTU Alignment | 12 pts | Matching MTU; eliminates ExStart deadlock traps. |
| **OSP-SEC-03** | Deterministic DR/BDR Priority Hardening | 12 pts | Priority 0 on leaf/access; high priority on aggregation core. |
| **OSP-SEC-04** | Passive-Interface Default Policy | 10 pts | Suppress Hellos on user subnets; prevent rogue peering. |
| **OSP-SEC-05** | Sub-Second Convergence (BFD / Timers) | 10 pts | Sub-50ms hardware fault detection via BFD. |
| **OSP-SEC-06** | Calibrated Reference Bandwidth | 9 pts | Scaled to 100G/400G; eliminates 1G/10G/100G metric saturation. |
| **OSP-SEC-07** | Area 0 Backbone Continuity & Hierarchy | 9 pts | Contiguous Area 0 attachment; Stub/NSSA boundary isolation. |
| **OSP-SEC-08** | CoPP & Multicast Control Plane Protection | 8 pts | IP protocol 89 traffic policed at Route Processor. |
| **OSP-SEC-09** | ABR Inter-Area Route Summarization | 8 pts | Area range summarization reduces SPF blast radius. |
| **OSP-SEC-10** | Max-Metric Router-LSA on Boot | 7 pts | Prevents blackholing transit traffic during reload. |

