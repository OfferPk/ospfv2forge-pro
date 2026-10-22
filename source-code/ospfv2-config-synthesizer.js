/**
 * OSPFv2Forge Pro - Multi-Platform Configuration Synthesizer
 * 
 * Synthesizes production-hardened OSPFv2 stanzas for:
 * - Cisco IOS-XE
 * - Cisco Nexus NX-OS
 * - Arista EOS
 * - Juniper Junos
 * - Linux FRRouting (FRR ospfd)
 * - Prometheus Alertmanager Rules
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OSPFv2ConfigSynthesizer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(config) {
    const processId = config.processId || 1;
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0';
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const refBw = config.refBwMbps || 100000; // 100 Gbps default
    const bfd = config.bfdEnabled !== false;
    const priority = config.priority !== undefined ? config.priority : 100;
    const isStub = !!config.isStub;
    const isNssa = !!config.isNssa;

    let areaStanza = '';
    if (isNssa) {
      areaStanza = ` area ${areaId} nssa default-information-originate`;
    } else if (isStub) {
      areaStanza = ` area ${areaId} stub no-summary`;
    }

    return `! ==============================================================================
! Cisco IOS-XE Hardened OSPFv2 Configuration (RFC 2328 & RFC 5709)
! Platform: Cisco Catalyst 8000 / 9000 / ASR 1000 running IOS-XE 17.x+
! ==============================================================================

! 1. Global OSPF Process Definition
router ospf ${processId}
 router-id ${routerId}
 auto-cost reference-bandwidth ${refBw}  ! Eliminates 1G/10G/100G metric saturation
 passive-interface default               ! Suppress Hellos on user/access subnets
 no passive-interface GigabitEthernet0/0/1
 no passive-interface GigabitEthernet0/0/2
 max-metric router-lsa on-startup 180    ! Prevent blackholing transit traffic on boot
 ${areaStanza}
 area 0 range 10.100.0.0 255.255.0.0     ! ABR inter-area route summarization
 log-adjacency-changes detail
!
! 2. Transit Interface Hardening (RFC 5709 HMAC-SHA-256)
interface GigabitEthernet0/0/1
 description TRANSIT-UPLINK-PRIMARY
 ip address 10.100.0.1 255.255.255.252
 ip ospf ${processId} area ${areaId}
 ip ospf priority ${priority}            ! Deterministic DR/BDR election
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ip ospf authentication mode hmac-sha-256
 ip ospf authentication key-chain KC-OSPF-SHA256
 ${bfd ? 'bfd interval 50 min_rx 50 multiplier 3\n ip ospf bfd' : '! bfd disabled'}
!
! 3. Cryptographic Key-Chain Definition (RFC 5709 Section 3.1)
key chain KC-OSPF-SHA256
 key 1
  key-string ${authKey}
  cryptographic-algorithm hmac-sha-256
!
! 4. Control Plane Policing (CoPP) for OSPF (IP Protocol 89)
ip access-list extended ACL-COPP-OSPF
 permit ospf any host 224.0.0.5
 permit ospf any host 224.0.0.6
 permit ospf any any
!
class-map match-all CM-COPP-OSPF
 match access-group name ACL-COPP-OSPF
!
policy-map PM-COPP-CONTROL-PLANE
 class CM-COPP-OSPF
  police rate 200 pps burst 30 packets conform-action transmit exceed-action drop
!
control-plane
 service-policy input PM-COPP-CONTROL-PLANE
`;
  }

  function synthesizeCiscoNxos(config) {
    const processId = config.processId || 1;
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0.0.0.0';
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const refBw = config.refBwMbps || 100000;
    const bfd = config.bfdEnabled !== false;

    return `! ==============================================================================
! Cisco Nexus NX-OS Hardened OSPFv2 Configuration
! Platform: Cisco Nexus 9300 / 9500 running NX-OS 9.x / 10.x
! ==============================================================================

feature ospf
${bfd ? 'feature bfd' : ''}

key chain KC-NXOS-OSPF
 key 1
  key-string ${authKey}
  cryptographic-algorithm hmac-sha-256

router ospf ${processId}
 router-id ${routerId}
 auto-cost reference-bandwidth ${refBw} Mbps
 max-metric router-lsa on-startup 180

interface Ethernet1/1
 no switchport
 ip address 10.100.0.1/30
 ip router ospf ${processId} area ${areaId}
 ip ospf authentication hmac-sha-256 key-chain KC-NXOS-OSPF
 ip ospf priority 100
 ${bfd ? 'ip ospf bfd' : ''}
 no shutdown
`;
  }

  function synthesizeAristaEos(config) {
    const processId = config.processId || 1;
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0';
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const refBw = config.refBwMbps || 100000;
    const bfd = config.bfdEnabled !== false;

    return `! ==============================================================================
! Arista EOS Hardened OSPFv2 Configuration
! Platform: Arista 7050X3 / 7280R3 running EOS 4.28+
! ==============================================================================

router ospf ${processId}
 router-id ${routerId}
 auto-cost reference-bandwidth ${refBw} Mbps
 passive-interface default
 no passive-interface Ethernet1
 max-metric router-lsa on-startup 180
!
interface Ethernet1
 no switchport
 ip address 10.100.0.1/30
 ip ospf area ${areaId}
 ip ospf message-digest-key 1 md5 ${authKey}
 ${bfd ? 'ip ospf bfd' : ''}
`;
  }

  function synthesizeJuniperJunos(config) {
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0.0.0.0';
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const bfd = config.bfdEnabled !== false;

    return `# ==============================================================================
# Juniper Junos OSPFv2 Hardened Stanza
# Platform: Juniper MX / QFX / SRX running Junos OS 21.x+
# ==============================================================================

set routing-options router-id ${routerId}
set protocols ospf reference-bandwidth 100g
set protocols ospf area ${areaId} interface ge-0/0/1.0 interface-type p2p
set protocols ospf area ${areaId} interface ge-0/0/1.0 authentication md5 1 key "${authKey}"
set protocols ospf area ${areaId} interface ge-0/0/1.0 hello-interval 1
set protocols ospf area ${areaId} interface ge-0/0/1.0 dead-interval 4
${bfd ? 'set protocols ospf area ' + areaId + ' interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 50' : ''}
${bfd ? 'set protocols ospf area ' + areaId + ' interface ge-0/0/1.0 bfd-liveness-detection multiplier 3' : ''}
set protocols ospf area ${areaId} interface ge-0/0/2.0 passive
`;
  }

  function synthesizeLinuxFRR(config) {
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0';
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const refBw = config.refBwMbps || 100000;

    return `! ==============================================================================
! Linux FRRouting (FRR) ospfd Configuration
! File: /etc/frr/ospfd.conf
! ==============================================================================

frr version 8.x
frr defaults traditional
hostname host-ospfd-01
log syslog informational

interface eth0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 ${authKey}
 ip ospf hello-interval 1
 ip ospf dead-interval 4

router ospf
 ospf router-id ${routerId}
 auto-cost reference-bandwidth ${refBw}
 passive-interface default
 no passive-interface eth0
 network 10.100.0.0/24 area ${areaId}
 max-metric router-lsa on-startup 180
!
line vty
`;
  }

  function synthesizePrometheusAlerts(config) {
    const routerId = config.routerId || '10.254.0.1';

    return `# ==============================================================================
# Prometheus Alertmanager Rules for OSPFv2 Telemetry & Health
# File: /etc/prometheus/rules/ospf_alerts.yml
# ==============================================================================

groups:
  - name: OSPFv2_Routing_Alerts
    rules:
      - alert: OSPFNeighborDown
        expr: cisco_ospf_neighbor_state != 8  # 8 = FULL
        for: 15s
        labels:
          severity: critical
          tier: networking
        annotations:
          summary: "OSPF Neighbor Down on {{ $labels.instance }} (Neighbor {{ $labels.neighbor_id }})"
          description: "OSPF adjacency dropped from FULL state. Physical link down, MTU mismatch, or auth failure."

      - alert: OSPFExStartDeadlock
        expr: cisco_ospf_neighbor_state == 6  # 6 = ExStart
        for: 45s
        labels:
          severity: high
          tier: routing
        annotations:
          summary: "OSPF DBD MTU Deadlock Detected on {{ $labels.instance }} (Neighbor {{ $labels.neighbor_id }})"
          description: "Neighbor is stuck in ExStart state > 45s. Likely Database Description (DBD) interface MTU mismatch!"

      - alert: OSPFAuthFailureSpike
        expr: rate(cisco_ospf_auth_failures_total[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
          tier: security
        annotations:
          summary: "OSPF Cryptographic Authentication Failures on {{ $labels.instance }}"
          description: "High rate of OSPF packets with invalid RFC 5709 HMAC-SHA-256 or MD5 signatures. Rogue router or key mismatch."

      - alert: OSPFDrBdrFlap
        expr: rate(cisco_ospf_dr_changes_total[10m]) > 0.1
        for: 5m
        labels:
          severity: warning
          tier: routing
        annotations:
          summary: "OSPF DR/BDR Election Flap Detected on {{ $labels.instance }}"
          description: "Frequent DR election changes detected on multi-access segment. Priority tie-breaker instability."
`;
  }

  return {
    synthesizeCiscoIosXe: synthesizeCiscoIosXe,
    synthesizeCiscoNxos: synthesizeCiscoNxos,
    synthesizeAristaEos: synthesizeAristaEos,
    synthesizeJuniperJunos: synthesizeJuniperJunos,
    synthesizeLinuxFRR: synthesizeLinuxFRR,
    synthesizePrometheusAlerts: synthesizePrometheusAlerts
  };
});
