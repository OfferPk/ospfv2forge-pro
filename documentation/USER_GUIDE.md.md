# OSPFv2Forge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for network engineers, infrastructure architects, and NetDevOps teams deploying Zero-Trust OSPFv2 (RFC 2328 & RFC 5709\) link-state routing.**

---

## 1\. Quickstart: Web Application Studio

The **OSPFv2Forge Pro Web Studio** runs 100% client-side with zero external dependencies. Open `source-code/index.html` directly in any modern web browser:

\# Optional local web server

cd product\_121/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Security & Topology Presets**: Switch between:  
   - **Enterprise Backbone HMAC-SHA-256 (Grade A+)**: Complete Zero-Trust OSPFv2 with RFC 5709 cryptographic authentication, calibrated 100G reference bandwidth, and BFD.  
   - **Data Center Campus NSSA (Grade A+)**: High-throughput 40G/400G deployment with 9000-byte Jumbo MTU and NSSA boundary.  
   - **Vulnerable Cleartext MTU Deadlock (Grade F)**: Insecure baseline exposing cleartext simple password, DBD MTU deadlock (1500B vs 1492B), and unpoliced Hellos.  
2. **RFC 2328 OSPFv2 Parameters**: Configure Packet Type (Hello, Database Description), Router ID, Area ID, Router Priority (0–255), Authentication (AuType 2 HMAC-SHA-256, AuType 2 MD5, AuType 1 Cleartext, AuType 0 Null), Interface Bandwidth, and Reference Bandwidth.  
3. **Database Description (DBD) MTU Deadlock Analyzer**: Real-time diagnostic comparing Local MTU vs Remote Neighbor MTU, pinpointing ExStart deadlocks and the hazards of `ip ospf mtu-ignore`.  
4. **DR / BDR Multi-Access Election Simulator**: Calculates elected DR, BDR, and DROTHER roles with Router Priority and Router ID tie-breakers.  
5. **10-Point Zero-Trust Scorecard**: Real-time compliance rating (0–100%, Grades A+ to F) with granular remediation instructions.  
6. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard export and binary `.pcap` capture generation.  
7. **Multi-Platform Synthesizer**: Instant production configuration generation for Cisco IOS-XE, Cisco NX-OS, Arista EOS, Juniper Junos, Linux FRRouting (ospfd), and Prometheus alerting rules.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/ospfv2forge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/ospfv2forge-cli.py \--dissect

### 2.2 Diagnosing Database Description (DBD) MTU Deadlocks

./build/ospfv2forge-cli.py \--preset build/presets/vulnerable-cleartext-mtu-deadlock.json \--mtu

### 2.3 Calculating Default vs Calibrated OSPF Costs

\# Calculate metrics for 10 Gbps interface with 100 Gbps reference bandwidth

./build/ospfv2forge-cli.py \--cost

### 2.4 Simulating DR / BDR Multi-Access Elections

./build/ospfv2forge-cli.py \--dr-election

### 2.5 Running 10-Point Zero-Trust OSPFv2 Audits

\# Audit Enterprise Backbone preset

./build/ospfv2forge-cli.py \--preset build/presets/enterprise-backbone-hmac-sha256.json \--audit

\# Audit vulnerable legacy deployment

./build/ospfv2forge-cli.py \--preset build/presets/vulnerable-cleartext-mtu-deadlock.json \--audit

### 2.6 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing network decoders or validating with Wireshark:

./build/ospfv2forge-cli.py \--preset build/presets/enterprise-backbone-hmac-sha256.json \--pcap enterprise-ospfv2.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r enterprise-ospfv2.pcap

### 2.7 Automated CI/CD Pipeline Gating (`--strict`)

Integrate OSPFv2Forge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit OSPFv2 Routing Security & MTU Compliance

  run: |

    python3 build/ospfv2forge-cli.py \\

      \--preset build/presets/production-ospf.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and MTU aligned. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or MTU deadlock detected. Pipeline halts.*

---

## 3\. Production Hardening & Configuration Guide

### 3.1 Cisco IOS-XE (RFC 5709 HMAC-SHA-256)

key chain KC-OSPF-SHA256

 key 1

  key-string 0spfV2\$ecureK3y2026\!

  cryptographic-algorithm hmac-sha-256

router ospf 1

 router-id 10.254.0.1

 auto-cost reference-bandwidth 100000

 passive-interface default

 no passive-interface GigabitEthernet0/0/1

 max-metric router-lsa on-startup 180

interface GigabitEthernet0/0/1

 ip address 10.100.0.1 255.255.255.252

 ip ospf 1 area 0

 ip ospf priority 100

 ip ospf hello-interval 1

 ip ospf dead-interval 4

 ip ospf authentication mode hmac-sha-256

 ip ospf authentication key-chain KC-OSPF-SHA256

 bfd interval 50 min\_rx 50 multiplier 3

 ip ospf bfd

---

## 4\. Troubleshooting & High-Impact Failure Modes

1. **Stuck in ExStart / Exchange State (MTU Deadlock)**:  
   - *Cause*: Local interface MTU differs from remote neighbor interface MTU (e.g., 1500 vs 1492).  
   - *Resolution*: Ensure identical MTU on both ends of the link. Avoid `ip ospf mtu-ignore` as it leads to silent LSU packet drops.  
2. **Metric Saturation Across High-Speed Links**:  
   - *Cause*: Default reference bandwidth (100 Mbps) assigns cost 1 to all interfaces \$\\ge 100\\text{ Mbps}\$.  
   - *Resolution*: Apply `auto-cost reference-bandwidth 100000` (100 Gbps) or `400000` (400 Gbps) across all routers in the area.  
3. **Accidental DR Election on Weak Access Switch**:  
   - *Cause*: Access switch left at default Priority 1 and booted first.  
   - *Resolution*: Configure `ip ospf priority 0` on all access/leaf switch ports.  
4. **Discontiguous Area 0 Inter-Area Blackholes**:  
   - *Cause*: Non-backbone area does not touch Area 0 directly.  
   - *Resolution*: Build a direct physical link to Area 0 or configure an OSPF Virtual Link through the transit area.