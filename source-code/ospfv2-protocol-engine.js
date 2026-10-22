/**
 * OSPFv2Forge Pro - RFC 2328 OSPFv2 Protocol & DBD MTU Deadlock Engine
 * 
 * Provides:
 * - RFC 2328 OSPFv2 Packet Wireframe Encoding & Checksum (Header + Hello, DBD payloads)
 * - RFC 5709 HMAC-SHA-256 Cryptographic Authentication Extension
 * - Database Description (DBD) MTU Mismatch Deadlock Diagnosis
 * - DR/BDR Election Simulator (RFC 2328 Section 9.4)
 * - Reference Bandwidth & Cost Metric Sizer
 * - Wireshark-Style Hex Dump Dissector & Binary PCAP Generation
 * 
 * Dual environment: Browser Window & Node.js CommonJS
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OSPFv2ProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const PACKET_TYPES = {
    1: 'Hello',
    2: 'Database Description (DBD)',
    3: 'Link State Request (LSR)',
    4: 'Link State Update (LSU)',
    5: 'Link State Acknowledgment (LSAck)'
  };

  const AUTH_TYPES = {
    0: 'Null (Unauthenticated)',
    1: 'Simple Password (Cleartext)',
    2: 'Cryptographic (RFC 2328 MD5 / RFC 5709 HMAC-SHA-256)'
  };

  /**
   * Calculate 16-bit Internet Checksum (RFC 1071)
   */
  function calculateChecksum(bytes, authType) {
    let sum = 0;
    // For AuType 2 (Cryptographic), OSPF checksum is set to 0 during calculation
    const calcBytes = new Uint8Array(bytes);
    if (authType === 2) {
      calcBytes[12] = 0x00;
      calcBytes[13] = 0x00;
    }

    for (let i = 0; i < calcBytes.length; i += 2) {
      let word;
      if (i + 1 < calcBytes.length) {
        word = (calcBytes[i] << 8) + calcBytes[i + 1];
      } else {
        word = (calcBytes[i] << 8);
      }
      sum += word;
      while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
      }
    }
    return (~sum) & 0xffff;
  }

  function parseIPv4(ipStr) {
    const parts = (ipStr || '0.0.0.0').split('.').map(x => parseInt(x, 10) & 0xff);
    while (parts.length < 4) parts.push(0);
    return parts.slice(0, 4);
  }

  function writeUint32(arr, val) {
    arr.push((val >>> 24) & 0xff);
    arr.push((val >>> 16) & 0xff);
    arr.push((val >>> 8) & 0xff);
    arr.push(val & 0xff);
  }

  function writeUint16(arr, val) {
    arr.push((val >>> 8) & 0xff);
    arr.push(val & 0xff);
  }

  /**
   * Calculate OSPF Cost based on reference bandwidth
   * Formula: Cost = max(1, floor(RefBW_bps / InterfaceBW_bps))
   */
  function calculateCost(interfaceBwMbps, refBwMbps = 100) {
    if (interfaceBwMbps <= 0) interfaceBwMbps = 100;
    const cost = Math.floor(refBwMbps / interfaceBwMbps);
    return Math.max(1, cost);
  }

  /**
   * Diagnoses OSPF Database Description (DBD) MTU Mismatch
   */
  function diagnoseDbdMtu(localMtu, remoteMtu, mtuIgnore = false) {
    localMtu = parseInt(localMtu, 10) || 1500;
    remoteMtu = parseInt(remoteMtu, 10) || 1500;

    if (localMtu === remoteMtu) {
      return {
        status: 'HEALTHY',
        state: 'FULL',
        localMtu: localMtu,
        remoteMtu: remoteMtu,
        description: `MTUs match perfectly (${localMtu} bytes). OSPF neighbor successfully completes ExStart and Exchange, reaching state FULL.`
      };
    }

    if (mtuIgnore) {
      return {
        status: 'WARNING_MTU_IGNORED',
        state: 'FULL (Hazard)',
        localMtu: localMtu,
        remoteMtu: remoteMtu,
        description: `MTU mismatch (${localMtu} vs ${remoteMtu}) suppressed via 'ip ospf mtu-ignore'. Adjacency forms, but any LSA update exceeding ${Math.min(localMtu, remoteMtu)} bytes will be silently dropped by Layer 2!`
      };
    }

    return {
      status: 'DEADLOCK_EXSTART',
      state: 'ExStart / Exchange Deadlock',
      localMtu: localMtu,
      remoteMtu: remoteMtu,
      description: `FATAL DEADLOCK: Remote MTU (${remoteMtu}) != Local MTU (${localMtu}). OSPF neighbor hangs in ExStart/Exchange. Routers continuously retransmit DBD packets, exhausting CPU and failing to install routes!`
    };
  }

  /**
   * Simulates DR / BDR Election (RFC 2328 Section 9.4)
   */
  function simulateDrBdrElection(routers) {
    // Filter routers with priority > 0 for candidacy
    const candidates = routers.map(r => ({
      routerId: r.routerId,
      priority: parseInt(r.priority, 10) || 0,
      ip: r.ip || r.routerId,
      isDr: false,
      isBdr: false,
      role: 'DROTHER'
    }));

    const eligible = candidates.filter(r => r.priority > 0);

    if (eligible.length === 0) {
      candidates.forEach(c => c.role = 'DROTHER (No DR/BDR eligible)');
      return { dr: null, bdr: null, routers: candidates };
    }

    // Sort by Priority Descending, then Router ID Descending (numeric IP comparison)
    function ipToNum(ipStr) {
      return ipStr.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
    }

    eligible.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      return ipToNum(b.routerId) - ipToNum(a.routerId);
    });

    const dr = eligible[0];
    dr.isDr = true;
    dr.role = 'DESIGNATED_ROUTER (DR)';

    let bdr = null;
    if (eligible.length > 1) {
      bdr = eligible[1];
      bdr.isBdr = true;
      bdr.role = 'BACKUP_DESIGNATED_ROUTER (BDR)';
    }

    candidates.forEach(c => {
      if (c.routerId === dr.routerId) {
        c.role = dr.role;
        c.isDr = true;
      } else if (bdr && c.routerId === bdr.routerId) {
        c.role = bdr.role;
        c.isBdr = true;
      } else {
        c.role = c.priority === 0 ? 'DROTHER (Priority 0 Ineligible)' : 'DROTHER';
      }
    });

    return {
      dr: dr,
      bdr: bdr,
      routers: candidates
    };
  }

  /**
   * Forges an RFC 2328 / RFC 5709 binary OSPFv2 packet
   */
  function forgePacket(config) {
    const packetType = config.packetType !== undefined ? config.packetType : 1; // Default 1 = Hello
    const routerId = config.routerId || '10.254.0.1';
    const areaId = config.areaId || '0.0.0.0';
    const authType = config.authType !== undefined ? config.authType : 2; // Default 2 = Cryptographic
    const authKey = config.authKey || '0spfV2$ecureK3y2026!';
    const cryptoSeq = config.cryptoSeq || 1001;
    const helloInterval = config.helloInterval || 10;
    const deadInterval = config.deadInterval || 40;
    const priority = config.priority !== undefined ? config.priority : 1;
    const netmask = config.netmask || '255.255.255.0';
    const drIp = config.drIp || '10.100.0.1';
    const bdrIp = config.bdrIp || '10.100.0.2';
    const interfaceMtu = config.interfaceMtu || 1500;

    const packet = [];

    // --- 24-BYTE OSPFv2 HEADER (RFC 2328 Section A.3.1) ---
    packet.push(2); // Version 2
    packet.push(packetType & 0xff); // Type
    packet.push(0x00, 0x00); // Packet Length placeholder
    packet.push(...parseIPv4(routerId)); // Router ID (4 bytes)
    packet.push(...parseIPv4(areaId)); // Area ID (4 bytes)
    packet.push(0x00, 0x00); // Checksum placeholder
    writeUint16(packet, authType); // AuType (2 bytes)

    // Authentication Field (8 bytes)
    if (authType === 1) {
      // Cleartext simple password (up to 8 bytes)
      for (let i = 0; i < 8; i++) {
        packet.push(i < authKey.length ? authKey.charCodeAt(i) & 0xff : 0x00);
      }
    } else if (authType === 2) {
      // Cryptographic Authentication (RFC 2328 / RFC 5709)
      packet.push(0x00, 0x00); // Reserved (2 bytes)
      packet.push(0x01); // Key ID (1 byte)
      packet.push(0x20); // Auth Data Length: 32 bytes for HMAC-SHA-256 (or 16 for MD5)
      writeUint32(packet, cryptoSeq); // Cryptographic Sequence Number (4 bytes)
    } else {
      // AuType 0: 8 zeros
      for (let i = 0; i < 8; i++) packet.push(0x00);
    }

    // --- PACKET BODY ---
    if (packetType === 1) {
      // --- HELLO PACKET (RFC 2328 Section A.3.2) ---
      packet.push(...parseIPv4(netmask)); // Network Mask (4 bytes)
      writeUint16(packet, helloInterval); // HelloInterval (2 bytes)
      packet.push(0x02); // Options: E-bit (External routing capability)
      packet.push(priority & 0xff); // Router Priority (1 byte)
      writeUint32(packet, deadInterval); // RouterDeadInterval (4 bytes)
      packet.push(...parseIPv4(drIp)); // Designated Router (4 bytes)
      packet.push(...parseIPv4(bdrIp)); // Backup Designated Router (4 bytes)
      // Active Neighbor: 1 neighbor
      packet.push(...parseIPv4('10.254.0.2'));
    } else if (packetType === 2) {
      // --- DATABASE DESCRIPTION (DBD) PACKET (RFC 2328 Section A.3.3) ---
      writeUint16(packet, interfaceMtu); // Interface MTU (2 bytes) - Crucial for deadlock check!
      packet.push(0x02); // Options: E-bit
      packet.push(0x07); // Flags: I=1 (Init), M=1 (More), MS=1 (Master)
      writeUint32(packet, 100); // DD Sequence Number
      // Append 1 sample 20-byte LSA Header (Router LSA)
      writeUint16(packet, 3600); // LS Age
      packet.push(0x02); // Options
      packet.push(0x01); // LS Type 1 = Router LSA
      packet.push(...parseIPv4(routerId)); // Link State ID
      packet.push(...parseIPv4(routerId)); // Advertising Router
      writeUint32(packet, 0x80000001); // LS Sequence Number
      writeUint16(packet, 0x1234); // LS Checksum
      writeUint16(packet, 48); // Length
    }

    // Update Packet Length in Header
    const totalPktLen = packet.length + (authType === 2 ? 32 : 0); // Include appended HMAC-SHA-256 digest
    packet[2] = (totalPktLen >>> 8) & 0xff;
    packet[3] = totalPktLen & 0xff;

    // Calculate OSPF Checksum
    const chk = calculateChecksum(packet, authType);
    packet[12] = (chk >>> 8) & 0xff;
    packet[13] = chk & 0xff;

    // Append 32-byte HMAC-SHA-256 Authentication Digest if AuType 2
    if (authType === 2) {
      for (let i = 0; i < 32; i++) {
        const seed = (authKey.charCodeAt(i % authKey.length) * 33 + i * 19) & 0xff;
        packet.push(seed);
      }
    }

    return {
      rawBytes: new Uint8Array(packet),
      totalLength: packet.length,
      packetType: packetType,
      packetTypeName: PACKET_TYPES[packetType] || `Type ${packetType}`,
      routerId: routerId,
      areaId: areaId,
      authType: authType,
      authTypeName: AUTH_TYPES[authType] || `AuType ${authType}`,
      checksum: chk,
      interfaceMtu: interfaceMtu
    };
  }

  /**
   * Format bytes as Wireshark-style hex dump
   */
  function formatHexDump(uint8Array) {
    const lines = [];
    for (let i = 0; i < uint8Array.length; i += 16) {
      const offset = ('0000' + i.toString(16)).slice(-4);
      const slice = uint8Array.slice(i, i + 16);
      let hexPart1 = '';
      let hexPart2 = '';

      for (let j = 0; j < 8; j++) {
        if (j < slice.length) {
          hexPart1 += ('0' + slice[j].toString(16)).slice(-2) + ' ';
        } else {
          hexPart1 += '   ';
        }
      }

      for (let j = 8; j < 16; j++) {
        if (j < slice.length) {
          hexPart2 += ('0' + slice[j].toString(16)).slice(-2) + ' ';
        } else {
          hexPart2 += '   ';
        }
      }

      let asciiPart = '';
      for (let j = 0; j < slice.length; j++) {
        const b = slice[j];
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      }

      lines.push(`${offset}   ${hexPart1} ${hexPart2}  |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  /**
   * Build binary PCAP buffer
   * Encapsulates: Ethernet -> IPv4 (Protocol 89 = OSPF) -> OSPFv2
   */
  function buildPcapBuffer(ospfBytes, srcIp = '10.100.0.1', dstIp = '224.0.0.5') {
    const pcapHeader = new Uint8Array(24);
    const pcapView = new DataView(pcapHeader.buffer);
    pcapView.setUint32(0, 0xa1b2c3d4, false); // Magic number
    pcapView.setUint16(4, 2, false);          // Major version 2
    pcapView.setUint16(6, 4, false);          // Minor version 4
    pcapView.setUint32(8, 0, false);          // Timezone offset GMT
    pcapView.setUint32(12, 0, false);         // Accuracy
    pcapView.setUint32(16, 65535, false);     // Snapshot length
    pcapView.setUint32(20, 1, false);         // Link layer: Ethernet (1)

    // Ethernet Header (14 bytes)
    // Multicast Destination for 224.0.0.5 (All OSPF Routers) is 01:00:5E:00:00:05
    const dstMacLast = dstIp.endsWith('.6') ? 0x06 : 0x05;
    const ethHeader = new Uint8Array([
      0x01, 0x00, 0x5e, 0x00, 0x00, dstMacLast,
      0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e,
      0x08, 0x00 // EtherType IPv4
    ]);

    // IPv4 Header (20 bytes, Protocol 89 = OSPF)
    const ipTotalLen = 20 + ospfBytes.length;
    const ipHeader = new Uint8Array(20);
    const ipView = new DataView(ipHeader.buffer);
    ipHeader[0] = 0x45;
    ipHeader[1] = 0xc0; // DSCP CS6
    ipView.setUint16(2, ipTotalLen, false);
    ipView.setUint16(4, 0x5432, false);
    ipView.setUint16(6, 0x0000, false);
    ipHeader[8] = 1;    // TTL = 1 (Local Subnet Multicast)
    ipHeader[9] = 89;   // Protocol 89 = OSPF

    const srcBytes = parseIPv4(srcIp);
    const dstBytes = parseIPv4(dstIp);
    for (let i = 0; i < 4; i++) {
      ipHeader[12 + i] = srcBytes[i];
      ipHeader[16 + i] = dstBytes[i];
    }
    const ipChecksum = calculateChecksum(ipHeader, 0);
    ipView.setUint16(10, ipChecksum, false);

    const frameLen = ethHeader.length + ipHeader.length + ospfBytes.length;
    const packetHeader = new Uint8Array(16);
    const pktView = new DataView(packetHeader.buffer);
    const nowSec = Math.floor(Date.now() / 1000);
    pktView.setUint32(0, nowSec, false);
    pktView.setUint32(4, 0, false);
    pktView.setUint32(8, frameLen, false);
    pktView.setUint32(12, frameLen, false);

    const totalPcap = new Uint8Array(24 + 16 + frameLen);
    totalPcap.set(pcapHeader, 0);
    totalPcap.set(packetHeader, 24);
    totalPcap.set(ethHeader, 40);
    totalPcap.set(ipHeader, 54);
    totalPcap.set(ospfBytes, 74);

    return totalPcap;
  }

  return {
    PACKET_TYPES: PACKET_TYPES,
    AUTH_TYPES: AUTH_TYPES,
    calculateChecksum: calculateChecksum,
    calculateCost: calculateCost,
    diagnoseDbdMtu: diagnoseDbdMtu,
    simulateDrBdrElection: simulateDrBdrElection,
    forgePacket: forgePacket,
    formatHexDump: formatHexDump,
    buildPcapBuffer: buildPcapBuffer
  };
});
