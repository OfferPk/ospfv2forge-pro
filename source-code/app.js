/**
 * OSPFv2Forge Pro - Studio Application Controller
 */

let currentTab = 'cisco-ios-xe';
let activeRouters = [];

const PRESETS = {
  backbone: {
    packetType: 1,
    routerId: '10.254.0.1',
    areaId: '0.0.0.0',
    priority: 100,
    authTypeOption: '2-sha256',
    authKey: '0spfV2$ecureK3y2026!',
    ifBwMbps: 10000,
    refBwMbps: 100000,
    localMtu: 1500,
    remoteMtu: 1500,
    mtuIgnore: false,
    passiveDefault: true,
    bfdEnabled: true,
    area0Attached: true,
    isBackboneOnly: true,
    coppActive: true,
    summarizationActive: true,
    maxMetricRouterLsa: true,
    isEdgeOrLeaf: false,
    routers: [
      { routerId: '10.254.0.1', priority: 100 },
      { routerId: '10.254.0.2', priority: 50 },
      { routerId: '10.254.0.3', priority: 0 }
    ]
  },
  nssa: {
    packetType: 2,
    routerId: '10.254.10.1',
    areaId: '0.0.0.10',
    priority: 100,
    authTypeOption: '2-sha256',
    authKey: 'NSSA_0spfV2$2026!',
    ifBwMbps: 40000,
    refBwMbps: 400000,
    localMtu: 9000,
    remoteMtu: 9000,
    mtuIgnore: false,
    passiveDefault: true,
    bfdEnabled: true,
    area0Attached: true,
    isNssa: true,
    coppActive: true,
    summarizationActive: true,
    maxMetricRouterLsa: true,
    isEdgeOrLeaf: false,
    routers: [
      { routerId: '10.254.10.1', priority: 100 },
      { routerId: '10.254.10.2', priority: 90 }
    ]
  },
  vulnerable: {
    packetType: 2,
    routerId: '192.168.1.1',
    areaId: '0.0.0.0',
    priority: 1,
    authTypeOption: '1',
    authKey: 'cisco123',
    ifBwMbps: 1000,
    refBwMbps: 100,
    localMtu: 1500,
    remoteMtu: 1492,
    mtuIgnore: false,
    passiveDefault: false,
    bfdEnabled: false,
    area0Attached: false,
    coppActive: false,
    summarizationActive: false,
    maxMetricRouterLsa: false,
    isEdgeOrLeaf: true,
    routers: [
      { routerId: '192.168.1.1', priority: 1 },
      { routerId: '192.168.1.2', priority: 1 }
    ]
  }
};

function loadPreset(name) {
  const p = PRESETS[name] || PRESETS.backbone;

  document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
  const btn = document.getElementById(`btn-preset-${name}`);
  if (btn) btn.classList.add('active');

  document.getElementById('input-packet-type').value = p.packetType;
  document.getElementById('input-router-id').value = p.routerId;
  document.getElementById('input-area-id').value = p.areaId;
  document.getElementById('input-priority').value = p.priority;
  document.getElementById('input-auth-type').value = p.authTypeOption;
  document.getElementById('input-auth-key').value = p.authKey;
  document.getElementById('input-if-bw').value = p.ifBwMbps;
  document.getElementById('input-ref-bw').value = p.refBwMbps;
  document.getElementById('input-local-mtu').value = p.localMtu;
  document.getElementById('input-remote-mtu').value = p.remoteMtu;
  document.getElementById('chk-mtu-ignore').checked = p.mtuIgnore;

  document.getElementById('chk-passive').checked = p.passiveDefault;
  document.getElementById('chk-bfd').checked = p.bfdEnabled;
  document.getElementById('chk-area0').checked = p.area0Attached;
  document.getElementById('chk-copp').checked = p.coppActive;
  document.getElementById('chk-summary').checked = p.summarizationActive;
  document.getElementById('chk-max-metric').checked = p.maxMetricRouterLsa;

  activeRouters = JSON.parse(JSON.stringify(p.routers));
  updateAll();
}

function updateAll() {
  const packetType = parseInt(document.getElementById('input-packet-type').value, 10);
  const routerId = document.getElementById('input-router-id').value || '10.254.0.1';
  const areaId = document.getElementById('input-area-id').value || '0.0.0.0';
  const priority = parseInt(document.getElementById('input-priority').value, 10) || 0;
  const authTypeOption = document.getElementById('input-auth-type').value;
  const authKey = document.getElementById('input-auth-key').value;
  const ifBw = parseInt(document.getElementById('input-if-bw').value, 10) || 1000;
  const refBw = parseInt(document.getElementById('input-ref-bw').value, 10) || 100000;
  const localMtu = parseInt(document.getElementById('input-local-mtu').value, 10) || 1500;
  const remoteMtu = parseInt(document.getElementById('input-remote-mtu').value, 10) || 1500;
  const mtuIgnore = document.getElementById('chk-mtu-ignore').checked;

  const passiveDefault = document.getElementById('chk-passive').checked;
  const bfdEnabled = document.getElementById('chk-bfd').checked;
  const area0Attached = document.getElementById('chk-area0').checked;
  const coppActive = document.getElementById('chk-copp').checked;
  const summarizationActive = document.getElementById('chk-summary').checked;
  const maxMetricRouterLsa = document.getElementById('chk-max-metric').checked;

  // Resolve AuthType and CryptoAlgo
  let authType = 0;
  let cryptoAlgo = '';
  if (authTypeOption === '2-sha256') {
    authType = 2;
    cryptoAlgo = 'HMAC-SHA-256';
  } else if (authTypeOption === '2-md5') {
    authType = 2;
    cryptoAlgo = 'MD5';
  } else if (authTypeOption === '1') {
    authType = 1;
  }

  // 1. Calculate Cost Metrics
  const costDefault = OSPFv2ProtocolEngine.calculateCost(ifBw, 100);
  const costCalibrated = OSPFv2ProtocolEngine.calculateCost(ifBw, refBw);
  document.getElementById('cost-default').textContent = costDefault;
  document.getElementById('cost-calibrated').textContent = costCalibrated;
  document.getElementById('ref-bw-text').textContent = (refBw >= 1000) ? `${refBw / 1000}G` : `${refBw}M`;

  // 2. Diagnose DBD MTU Deadlock
  const dbdDiag = OSPFv2ProtocolEngine.diagnoseDbdMtu(localMtu, remoteMtu, mtuIgnore);
  const diagBox = document.getElementById('dbd-diag-box');
  diagBox.textContent = dbdDiag.description;
  if (dbdDiag.status === 'HEALTHY') {
    diagBox.className = 'diag-box diag-healthy';
  } else if (dbdDiag.status === 'DEADLOCK_EXSTART') {
    diagBox.className = 'diag-box diag-deadlock';
  } else {
    diagBox.className = 'diag-box diag-warning';
  }

  // 3. Simulate DR / BDR Election
  const electionResult = OSPFv2ProtocolEngine.simulateDrBdrElection(activeRouters);
  renderDrTable(electionResult);

  // 4. Forge Binary Packet & Wireshark Hex Dump
  const forged = OSPFv2ProtocolEngine.forgePacket({
    packetType: packetType,
    routerId: routerId,
    areaId: areaId,
    authType: authType,
    authKey: authKey,
    priority: priority,
    interfaceMtu: localMtu
  });

  document.getElementById('wire-length-badge').textContent = `Length: ${forged.totalLength} B`;
  document.getElementById('hex-box').textContent = OSPFv2ProtocolEngine.formatHexDump(forged.rawBytes);
  window._lastOspfBytes = forged.rawBytes;

  // 5. Run 10-Point Zero-Trust Security Audit
  const auditResult = OSPFv2SecurityAuditor.auditConfiguration({
    authType: authType,
    cryptoAlgo: cryptoAlgo,
    localMtu: localMtu,
    remoteMtu: remoteMtu,
    mtuIgnore: mtuIgnore,
    priority: priority,
    isEdgeOrLeaf: (priority === 0),
    passiveDefault: passiveDefault,
    bfdEnabled: bfdEnabled,
    refBwMbps: refBw,
    area0Attached: area0Attached,
    isBackboneOnly: (areaId === '0.0.0.0' || areaId === '0'),
    coppActive: coppActive,
    summarizationActive: summarizationActive,
    maxMetricRouterLsa: maxMetricRouterLsa
  });

  renderAuditScorecard(auditResult);

  // 6. Update Configuration Synthesizer Output
  renderConfig({
    routerId: routerId,
    areaId: areaId,
    authKey: authKey,
    refBwMbps: refBw,
    bfdEnabled: bfdEnabled,
    priority: priority
  });
}

function renderDrTable(election) {
  const tbody = document.getElementById('dr-table-tbody');
  tbody.innerHTML = '';

  election.routers.forEach(r => {
    const tr = document.createElement('tr');
    let badgeClass = 'badge-drother';
    if (r.isDr) badgeClass = 'badge-dr';
    else if (r.isBdr) badgeClass = 'badge-bdr';

    tr.innerHTML = `
      <td><strong>${r.routerId}</strong></td>
      <td>${r.priority}</td>
      <td><span class="status-badge ${badgeClass}">${r.role}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAuditScorecard(audit) {
  const banner = document.getElementById('score-banner');
  const circle = document.getElementById('grade-circle');
  const header = document.getElementById('score-header');
  const subtext = document.getElementById('score-subtext');
  const gradeBadge = document.getElementById('score-grade-badge');

  circle.textContent = audit.grade;
  gradeBadge.textContent = `GRADE ${audit.grade}`;

  if (audit.score >= 80) {
    banner.className = 'score-banner score-banner-green';
    circle.className = 'grade-circle';
    gradeBadge.className = 'badge badge-emerald';
    header.textContent = `${audit.score} / 100 Points — Production-Grade Zero-Trust OSPFv2`;
    subtext.textContent = 'RFC 5709 HMAC-SHA-256 enforced, DBD MTU aligned, and passive-default active.';
  } else {
    banner.className = 'score-banner score-banner-red';
    circle.className = 'grade-circle grade-circle-red';
    gradeBadge.className = 'badge badge-amber';
    header.textContent = `${audit.score} / 100 Points — Critical Routing Risks Detected`;
    subtext.textContent = 'Unauthenticated peering, DBD MTU deadlock, or unpoliced control plane present.';
  }

  const container = document.getElementById('findings-container');
  container.innerHTML = '';

  audit.findings.forEach(f => {
    const item = document.createElement('div');
    item.className = 'finding-item';

    let statusClass = 'finding-pass';
    if (f.status === 'FAIL') statusClass = 'finding-fail';
    else if (f.status === 'WARN') statusClass = 'finding-warn';

    item.innerHTML = `
      <div class="finding-title">
        <span class="${statusClass}">[${f.status}] ${f.id}</span>
        <span>${f.score}/${f.maxScore} pts</span>
      </div>
      <div style="font-weight:600; color:#fff; font-size:11px; margin-bottom:2px;">${f.title}</div>
      <div class="finding-desc">${f.description}</div>
    `;
    container.appendChild(item);
  });
}

function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  updateAll();
}

function renderConfig(params) {
  const box = document.getElementById('config-box');
  let content = '';

  if (currentTab === 'cisco-ios-xe') {
    content = OSPFv2ConfigSynthesizer.synthesizeCiscoIosXe(params);
  } else if (currentTab === 'cisco-nxos') {
    content = OSPFv2ConfigSynthesizer.synthesizeCiscoNxos(params);
  } else if (currentTab === 'arista-eos') {
    content = OSPFv2ConfigSynthesizer.synthesizeAristaEos(params);
  } else if (currentTab === 'juniper-junos') {
    content = OSPFv2ConfigSynthesizer.synthesizeJuniperJunos(params);
  } else if (currentTab === 'linux-frr') {
    content = OSPFv2ConfigSynthesizer.synthesizeLinuxFRR(params);
  } else if (currentTab === 'prometheus') {
    content = OSPFv2ConfigSynthesizer.synthesizePrometheusAlerts(params);
  }

  box.textContent = content;
}

function copyHexDump() {
  const text = document.getElementById('hex-box').textContent;
  navigator.clipboard.writeText(text).then(() => alert('Wireshark Hex Dump copied to clipboard!'));
}

function copyConfig() {
  const text = document.getElementById('config-box').textContent;
  navigator.clipboard.writeText(text).then(() => alert('Configuration copied to clipboard!'));
}

function downloadPcap() {
  if (!window._lastOspfBytes) return;
  const pcap = OSPFv2ProtocolEngine.buildPcapBuffer(window._lastOspfBytes);
  const blob = new Blob([pcap], { type: 'application/vnd.tcpdump.pcap' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'ospfv2-traffic.pcap';
  a.click();
  URL.revokeObjectURL(url);
}

// Initial boot
window.addEventListener('DOMContentLoaded', () => {
  loadPreset('backbone');
});
