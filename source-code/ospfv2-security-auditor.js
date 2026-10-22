/**
 * OSPFv2Forge Pro - 10-Point Zero-Trust Interior Routing (OSPFv2) Security & DBD Resiliency Auditor
 * 
 * Implements a rigorous 100-point security rubric evaluating:
 * - RFC 5709 HMAC-SHA-256 Authentication & Crypto Replay Protection
 * - Database Description (DBD) MTU Match & Deadlock Prevention
 * - DR/BDR Priority Determinism (Priority 0 on Edge)
 * - Passive-Interface Defaulting
 * - Hardware BFD Sub-Second Convergence
 * - Calibrated Reference Bandwidth (No Metric Saturation)
 * - Area 0 Backbone Continuity & Stub/NSSA Boundaries
 * - Control Plane Policing (CoPP) for IP Protocol 89
 * - ABR Inter-Area Route Summarization
 * - Max-Metric Router-LSA (Stub Router) on Boot
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OSPFv2SecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditConfiguration(config) {
    const findings = [];
    let totalScore = 0;

    // Check 1: RFC 5709 HMAC-SHA-256 Cryptographic Authentication (15 pts)
    const authType = config.authType !== undefined ? config.authType : 0;
    const cryptoAlgo = (config.cryptoAlgo || '').toUpperCase();

    if (authType === 2 && (cryptoAlgo === 'HMAC-SHA-256' || cryptoAlgo === 'SHA256')) {
      totalScore += 15;
      findings.push({
        id: 'OSP-SEC-01',
        title: 'RFC 5709 HMAC-SHA-256 Cryptographic Authentication Enforced',
        score: 15,
        maxScore: 15,
        status: 'PASS',
        description: 'AuType 2 with HMAC-SHA-256 and 32-bit Cryptographic Sequence Numbers active. Immune to replay attacks and LSA spoofing.'
      });
    } else if (authType === 2) {
      totalScore += 6;
      findings.push({
        id: 'OSP-SEC-01',
        title: 'Legacy MD5 Authentication in Use',
        score: 6,
        maxScore: 15,
        status: 'WARN',
        description: 'MD5 is vulnerable to collision attacks (NIST SP 800-131A violation). Upgrade to RFC 5709 HMAC-SHA-256.'
      });
    } else if (authType === 1) {
      totalScore += 2;
      findings.push({
        id: 'OSP-SEC-01',
        title: 'Cleartext Simple Password (AuType 1) Detected',
        score: 2,
        maxScore: 15,
        status: 'FAIL',
        description: '8-byte cleartext password transmitted in the clear on wire. Easily intercepted by passive network snooping.'
      });
    } else {
      findings.push({
        id: 'OSP-SEC-01',
        title: 'VULNERABLE: Unauthenticated OSPFv2 (AuType 0)',
        score: 0,
        maxScore: 15,
        status: 'FAIL',
        description: 'Zero authentication enabled. Any rogue endpoint on the broadcast LAN can inject malicious LSAs and hijack traffic.'
      });
    }

    // Check 2: Database Description (DBD) MTU Alignment (12 pts)
    const localMtu = parseInt(config.localMtu, 10) || 1500;
    const remoteMtu = parseInt(config.remoteMtu, 10) || 1500;
    const mtuIgnore = !!config.mtuIgnore;

    if (localMtu === remoteMtu) {
      totalScore += 12;
      findings.push({
        id: 'OSP-SEC-02',
        title: 'DBD Interface MTU Aligned (ExStart Deadlock Immune)',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: `Local MTU (${localMtu}B) matches Remote MTU (${remoteMtu}B). Adjacency forms cleanly to state FULL without retransmission loops.`
      });
    } else if (mtuIgnore) {
      totalScore += 4;
      findings.push({
        id: 'OSP-SEC-02',
        title: 'HAZARD: MTU Mismatch Suppressed with mtu-ignore',
        score: 4,
        maxScore: 12,
        status: 'WARN',
        description: `Adjacency forms via 'ip ospf mtu-ignore', but large LSUs exceeding ${Math.min(localMtu, remoteMtu)} bytes will be dropped silently by Layer 2 switches!`
      });
    } else {
      findings.push({
        id: 'OSP-SEC-02',
        title: 'FATAL DEADLOCK: DBD Interface MTU Mismatch',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: `Local MTU (${localMtu}B) != Remote MTU (${remoteMtu}B). Neighbor permanently deadlocks in ExStart/Exchange, causing 100% CPU spikes and failed routing.`
      });
    }

    // Check 3: Deterministic DR/BDR Priority Hardening (12 pts)
    const priority = config.priority !== undefined ? config.priority : 1;
    const isEdgeOrLeaf = !!config.isEdgeOrLeaf;

    if (isEdgeOrLeaf && priority === 0) {
      totalScore += 12;
      findings.push({
        id: 'OSP-SEC-03',
        title: 'Priority 0 Configured on Edge/Access Router',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Router is explicitly disqualified from DR/BDR election, preventing accidental DR takeover and suboptimal transit paths.'
      });
    } else if (!isEdgeOrLeaf && priority >= 100) {
      totalScore += 12;
      findings.push({
        id: 'OSP-SEC-03',
        title: 'Deterministic High Priority on Core/Aggregation Node',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: `Priority ${priority} guarantees deterministic DR/BDR election on transit multi-access segment.`
      });
    } else if (isEdgeOrLeaf && priority > 0) {
      totalScore += 4;
      findings.push({
        id: 'OSP-SEC-03',
        title: 'Default Priority 1 on Edge/Access Node (DR Risk)',
        score: 4,
        maxScore: 12,
        status: 'WARN',
        description: 'Edge router could become DR if core routers reboot, funneling transit traffic through a weak access switch.'
      });
    } else {
      totalScore += 8;
      findings.push({
        id: 'OSP-SEC-03',
        title: `Priority ${priority} Configured`,
        score: 8,
        maxScore: 12,
        status: 'PASS',
        description: 'Standard DR/BDR priority in place.'
      });
    }

    // Check 4: Passive-Interface Default Policy (10 pts)
    if (config.passiveDefault) {
      totalScore += 10;
      findings.push({
        id: 'OSP-SEC-04',
        title: 'Passive-Interface Default Enforced',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'All interface subnets are passive by default; only explicitly configured router-to-router links emit Hellos.'
      });
    } else {
      totalScore += 3;
      findings.push({
        id: 'OSP-SEC-04',
        title: 'Unrestricted OSPF Hellos on User Subnets',
        score: 3,
        maxScore: 10,
        status: 'FAIL',
        description: 'Hellos emitted on access VLANs allow rogue endpoints to form OSPF adjacencies and inject routes.'
      });
    }

    // Check 5: Sub-Second Convergence with BFD / Tuned Timers (10 pts)
    if (config.bfdEnabled) {
      totalScore += 10;
      findings.push({
        id: 'OSP-SEC-05',
        title: 'Hardware BFD (Bidirectional Forwarding Detection) Active',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Sub-50ms fault detection enabled via BFD. Dead adjacencies torn down immediately without waiting for dead timer.'
      });
    } else if (config.tunedTimers) {
      totalScore += 6;
      findings.push({
        id: 'OSP-SEC-05',
        title: 'Fast Hello/Dead Timers (1s/4s) Configured',
        score: 6,
        maxScore: 10,
        status: 'PASS',
        description: 'Timers tuned down from default 10s/40s, but lacks hardware ASIC offload.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'OSP-SEC-05',
        title: 'Default 40-Second Dead Interval (Slow Convergence)',
        score: 2,
        maxScore: 10,
        status: 'WARN',
        description: 'Physical link cuts take up to 40 seconds to detect, causing extended blackholes for real-time traffic.'
      });
    }

    // Check 6: Calibrated Auto-Cost Reference Bandwidth (9 pts)
    const refBwMbps = parseInt(config.refBwMbps, 10) || 100;
    if (refBwMbps >= 100000) {
      totalScore += 9;
      findings.push({
        id: 'OSP-SEC-06',
        title: `Calibrated Reference Bandwidth (${refBwMbps / 1000} Gbps)`,
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Reference bandwidth scaled to 100G/400G. Accurately differentiates 1G, 10G, 40G, and 100G interfaces without metric saturation.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'OSP-SEC-06',
        title: 'Default 100 Mbps Reference Bandwidth (Metric Saturation)',
        score: 2,
        maxScore: 9,
        status: 'WARN',
        description: 'All interfaces >= 100 Mbps (1G, 10G, 100G) receive identical cost of 1, breaking ECMP and inducing link polarization.'
      });
    }

    // Check 7: Multi-Area Hierarchy & Area 0 Integrity (9 pts)
    if (config.area0Attached && (config.isStub || config.isNssa || config.isBackboneOnly)) {
      totalScore += 9;
      findings.push({
        id: 'OSP-SEC-07',
        title: 'Valid Multi-Area Hierarchy & Area 0 Integrity',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Direct Area 0 attachment verified. Stub/NSSA boundary configuration reduces LSDB memory footprint.'
      });
    } else if (config.area0Attached) {
      totalScore += 7;
      findings.push({
        id: 'OSP-SEC-07',
        title: 'Area 0 Attached (Standard Area)',
        score: 7,
        maxScore: 9,
        status: 'PASS',
        description: 'Router is connected to Area 0. Consider configuring Stub or NSSA on edge areas to limit LSA flooding.'
      });
    } else {
      totalScore += 1;
      findings.push({
        id: 'OSP-SEC-07',
        title: 'HAZARD: Discontiguous Area 0 or Missing Backbone Link',
        score: 1,
        maxScore: 9,
        status: 'FAIL',
        description: 'Router lacks direct or virtual-link attachment to Area 0. Traffic between areas will be dropped.'
      });
    }

    // Check 8: Control Plane Policing (CoPP) for IP Protocol 89 (8 pts)
    if (config.coppActive) {
      totalScore += 8;
      findings.push({
        id: 'OSP-SEC-08',
        title: 'CoPP (Control Plane Policing) Rate Limiting Enforced',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'IP Protocol 89 (OSPF) multicast packets to 224.0.0.5/6 are policed, protecting Route Processor from CPU starvation.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'OSP-SEC-08',
        title: 'Unpoliced OSPF Control Plane (CoPP Missing)',
        score: 2,
        maxScore: 8,
        status: 'WARN',
        description: 'Route processor vulnerable to denial-of-service from high-rate spoofed OSPF Hello or LSU packet floods.'
      });
    }

    // Check 9: Inter-Area Route Summarization & LSA Filtering (8 pts)
    if (config.summarizationActive) {
      totalScore += 8;
      findings.push({
        id: 'OSP-SEC-09',
        title: 'ABR Inter-Area Route Summarization Enforced',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: 'Area range summarization active on ABR. Prevents local area route flaps from triggering SPF across the entire backbone.'
      });
    } else {
      totalScore += 2;
      findings.push({
        id: 'OSP-SEC-09',
        title: 'Unsummarized Flat Link-State Flooding',
        score: 2,
        maxScore: 8,
        status: 'WARN',
        description: 'All /24 and /32 subnets flood into backbone. Any link flap in edge areas forces global Dijkstra SPF runs.'
      });
    }

    // Check 10: Max-Metric Router-LSA (Stub Router on Boot) (7 pts)
    if (config.maxMetricRouterLsa) {
      totalScore += 7;
      findings.push({
        id: 'OSP-SEC-10',
        title: 'Max-Metric Router-LSA (Stub Router) on Boot Active',
        score: 7,
        maxScore: 7,
        status: 'PASS',
        description: 'Advertises maximum metric (65535) during reload until BGP and core protocols converge, preventing transit blackholes.'
      });
    } else {
      totalScore += 1;
      findings.push({
        id: 'OSP-SEC-10',
        title: 'Immediate Transit Route Attraction on Boot',
        score: 1,
        maxScore: 7,
        status: 'WARN',
        description: 'Router immediately attracts transit traffic upon reload before BGP or applications are ready, blackholing packets.'
      });
    }

    let grade = 'F';
    if (totalScore >= 90) grade = 'A+';
    else if (totalScore >= 80) grade = 'A';
    else if (totalScore >= 70) grade = 'B';
    else if (totalScore >= 60) grade = 'C';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      findings: findings
    };
  }

  return {
    auditConfiguration: auditConfiguration
  };
});
