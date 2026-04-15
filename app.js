/* ═══════════════════════════════════════════════════════════
   CFIP – Cyber Forensic Intelligence Platform
   Real-Time + Real-Data Engine  |  app.js
   ════════════════════════════════════════════════════════════ */
'use strict';

/* ─── Configuration ─────────────────────────────────────────── */
const CFG = {
  API_BASE:         'http://127.0.0.1:5000',
  METRICS_INTERVAL: 3500,
  CHART_INTERVAL:   5000,
  SIM_MIN:          900,
  SIM_MAX:          2500,
  MAX_LOG_ROWS:     300,
  MAX_MINI_ROWS:    10,
  BRUTE_WINDOW:     60000,
  BRUTE_WARN:       5,
  BRUTE_CRIT:       10,
};

/* ─── App State ─────────────────────────────────────────────── */
const STATE = {
  useServer:      false,
  dataMode:       'simulation',  // 'simulation' | 'real'
  running:        true,
  simTimer:       null,
  logs:           [],
  threats:        [],
  timeline:       [],
  notifications:  [],
  failedLogins:   [],
  sevFilter:      'all',
  searchQuery:    '',
  totalEvents:    0,
  criticalCount:  0,
  warningCount:   0,
  infoCount:      0,
  bruteCount:     0,
  metrics:        {},
  prevMetrics:    {},
  sparkData:      { threats:[], logs:[], risk:[] },
  chartLabels:    [],
  chartThreats:   [],
  chartBenign:    [],
  anomalyData:    [],
  predValues:     { malware:72,phishing:55,ddos:38,insider:15,supply_chain:62 },
  notifOpen:      false,
  chartPaused:    false,
  currentJobId:   null,
  uploadedFiles:  [],
  charts:         { line:null, pie:null, anomaly:null },
  _chartTick:     { t:0, b:0 },
  _toastCount:    0,
};

/* ─── Simulation pool ───────────────────────────────────────── */
const POOL = {
  ips:   ['192.168.1.105','10.0.0.88','172.16.0.42','198.51.100.3',
          '203.0.113.77','10.0.0.50','45.33.32.156','91.108.4.1','185.220.101.3'],
  users: ['admin','root','svc_backup','webserver','oracle','ec2-user','guest'],
  events:{
    critical:[
      {e:'SSH Brute-force Attack',         p:'SSH',   t:'failed_login'},
      {e:'Reverse Shell Detected',         p:'TCP',   t:'malware'},
      {e:'GeoIP Anomaly – Foreign Source', p:'TCP',   t:'geoip'},
      {e:'Lateral Movement via RDP',       p:'RDP',   t:'lateral'},
      {e:'C2 Beacon on Port 4444',         p:'TCP',   t:'c2'},
      {e:'Privilege Escalation via Sudo',  p:'SYS',   t:'privesc'},
      {e:'Ransomware Signature Detected',  p:'N/A',   t:'malware'},
    ],
    warning:[
      {e:'Multiple Failed Logins (5+)',    p:'SSH',   t:'failed_login'},
      {e:'Port Scan Detected',             p:'TCP',   t:'scan'},
      {e:'Unusual DNS Query Volume',       p:'UDP',   t:'dns'},
      {e:'Outbound Traffic Spike',         p:'TCP',   t:'exfil'},
      {e:'API Rate Limit Exceeded',        p:'HTTPS', t:'api'},
    ],
    info:[
      {e:'User Auth Success',              p:'SSH',   t:null},
      {e:'VPN Tunnel Established',         p:'UDP',   t:null},
      {e:'File Transfer Completed',        p:'SMB',   t:null},
      {e:'Certificate Renewed',            p:'TLS',   t:null},
    ],
  },
  kc:[
    {phase:'Reconnaissance', sev:'warning'},  {phase:'Weaponization', sev:'warning'},
    {phase:'Delivery',       sev:'critical'}, {phase:'Exploitation',  sev:'critical'},
    {phase:'Installation',   sev:'critical'}, {phase:'C2 Callback',   sev:'critical'},
    {phase:'Exfiltration',   sev:'critical'},
  ],
};
let _kcIdx = 0;

/* ══════════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  startClock();
  buildLineChart();
  buildPieChart();
  buildAnomalyChart();
  renderPlaybooks();

  STATE.useServer = await checkServer();
  if (STATE.useServer) {
    startSSE();
    startMetricsPoll();
    checkServerCapabilities();
    toast('Connected to CFIP server · Upload logs for real analysis', 'success');
  } else {
    toast('Standalone simulation mode · Start server for real data', 'info');
    scheduleSimEvent();
  }

  startChartRefresh();
  startPredRefresh();
  startBruteMonitor();
  updateModeIndicator();
});

async function checkServer() {
  try {
    const r = await fetch(`${CFG.API_BASE}/api/metrics`, {signal: AbortSignal.timeout(1500)});
    return r.ok;
  } catch { return false; }
}

async function checkServerCapabilities() {
  try {
    const r = await fetch(`${CFG.API_BASE}/api/status`);
    if (!r.ok) return;
    const s = await r.json();
    const caps = [];
    if (s.has_pandas)   caps.push('pandas');
    if (s.has_requests) caps.push('geolocation');
    if (s.has_fpdf)     caps.push('PDF reports');
    if (caps.length)    toast(`Features enabled: ${caps.join(', ')}`, 'info');
    else                toast('Warning: Install pandas/fpdf2/requests for full features', 'warning');
  } catch {}
}

/* ══════════════════════════════════════════════════════════════
   CLOCK
   ═══════════════════════════════════════════════════════════ */
function startClock() {
  const tick = () => {
    const el = document.getElementById('live-clock');
    if (el) el.textContent = new Date().toLocaleTimeString('en-IN', {hour12:false});
  };
  tick();
  setInterval(tick, 1000);
}

/* ══════════════════════════════════════════════════════════════
   SSE + METRICS (server mode)
   ═══════════════════════════════════════════════════════════ */
function startSSE() {
  try {
    const src = new EventSource(`${CFG.API_BASE}/api/stream`);
    src.onmessage = e => { try { ingestEvent(JSON.parse(e.data)); } catch {} };
    src.onerror   = () => {
      src.close();
      STATE.useServer = false;
      scheduleSimEvent();
      updateModeIndicator();
    };
  } catch {
    STATE.useServer = false;
    scheduleSimEvent();
  }
}

function startMetricsPoll() {
  const poll = async () => {
    if (!STATE.useServer) return;
    try {
      const r = await fetch(`${CFG.API_BASE}/api/metrics`);
      if (!r.ok) return;
      const m = await r.json();
      applyMetrics(m);
      STATE.dataMode = m.mode || 'simulation';
      updateModeIndicator();
    } catch {}
  };
  poll();
  setInterval(poll, CFG.METRICS_INTERVAL);
}

/* ══════════════════════════════════════════════════════════════
   STANDALONE SIMULATION
   ═══════════════════════════════════════════════════════════ */
function scheduleSimEvent() {
  if (!STATE.running) { setTimeout(scheduleSimEvent, 500); return; }
  STATE.simTimer = setTimeout(() => { simulateEvent(); scheduleSimEvent(); },
    rand(CFG.SIM_MIN, CFG.SIM_MAX));
}

function simulateEvent() {
  const now = new Date();
  const ts  = now.toISOString().replace('T',' ').slice(0,19);
  const r   = Math.random();
  const sev = r<0.22 ? 'critical' : r<0.50 ? 'warning' : 'info';
  const pool = POOL.events[sev];
  const item = pool[Math.floor(Math.random()*pool.length)];
  const src  = POOL.ips[Math.floor(Math.random()*POOL.ips.length)];
  ingestEvent({
    ts, src, dst: '10.0.0.1',
    user:   Math.random()<0.4 ? POOL.users[Math.floor(Math.random()*POOL.users.length)] : null,
    event:  item.e, proto: item.p, type: item.t,
    bytes: `${rand(100,999)} KB`, status: sev, file: '[simulation]',
  });
  if (!STATE.useServer) {
    const prev = STATE.metrics;
    const risk = Math.max(10, Math.min(99, (prev.risk_score||45) + (sev==='critical'?rand(1,4):sev==='info'?-rand(0,2):rand(-1,2))));
    applyMetrics({
      active_threats: Math.max(0,(prev.active_threats||7) + (sev==='critical'?rand(0,2):sev==='info'?-rand(0,1):0)),
      logs_analyzed:  (prev.logs_analyzed||0)+1,
      mttp:           Math.max(1,Math.min(15,+((prev.mttp||4.2)+(Math.random()-.4)*.5).toFixed(1))),
      risk_score:     +risk.toFixed(1),
      risk_level:     risk>=70?'High':risk>=40?'Medium':'Low',
      mode:           'simulation',
    });
  }
}

/* ══════════════════════════════════════════════════════════════
   EVENT INGESTION
   ═══════════════════════════════════════════════════════════ */
function ingestEvent(entry) {
  STATE.totalEvents++;
  if      (entry.status==='critical') { STATE.criticalCount++; STATE._chartTick.t++; }
  else if (entry.status==='warning')  { STATE.warningCount++;  STATE._chartTick.t++; }
  else                                { STATE.infoCount++;     STATE._chartTick.b++; }

  STATE.logs.unshift(entry);
  if (STATE.logs.length > CFG.MAX_LOG_ROWS) STATE.logs.pop();

  if (entry.type==='failed_login') {
    STATE.failedLogins.push(Date.now());
    checkBruteForce(entry);
  }

  updateBadges();
  updateLiveTick();
  renderMiniLog();
  renderFullLogRow(entry);

  if (STATE.totalEvents % 8 === 0) {
    const kc = POOL.kc[_kcIdx % POOL.kc.length]; _kcIdx++;
    const tl = { ts:entry.ts, phase:kc.phase, detail:`${entry.event} from ${entry.src}`, status:kc.sev };
    STATE.timeline.unshift(tl);
    if (STATE.timeline.length > 50) STATE.timeline.pop();
    renderTimelines();
  }

  if (entry.status==='critical' || entry.status==='warning') addThreat(entry);

  if (entry.status==='critical') {
    toast(`Critical: ${entry.event} · ${entry.src}`, 'critical');
    addNotification(entry);
    showBanner(`CRITICAL: ${entry.event} from ${entry.src}`);
  } else if (entry.status==='warning' && Math.random()<0.25) {
    addNotification(entry);
  }
}

/* ══════════════════════════════════════════════════════════════
   METRICS UI
   ═══════════════════════════════════════════════════════════ */
function applyMetrics(m) {
  const prev = STATE.metrics;
  if (prev.active_threats !== undefined && prev.active_threats !== m.active_threats) flashCard('mc-threats');
  if (prev.risk_score     !== undefined && Math.abs((prev.risk_score||0)-m.risk_score)>3) flashCard('mc-risk');
  STATE.metrics = {...m};

  animVal('m-threats', m.active_threats);
  animVal('m-logs',    m.logs_analyzed, true);
  setText('m-mttp',   `${m.mttp||0} min`);
  animVal('m-risk',    Math.round(m.risk_score||0));

  const rEl = document.getElementById('m-risk-level');
  if (rEl) { rEl.textContent = m.risk_level||riskLabel(m.risk_score); rEl.className='metric-delta '+(m.risk_score>=70?'negative':m.risk_score>=40?'':'positive'); }
  const mE  = document.getElementById('m-mttp-d');
  if (mE) { const d=+(m.mttp||0)-(+(prev.mttp||m.mttp||0)); mE.textContent=d>0?`↑ ${d.toFixed(1)} worse`:`↓ ${Math.abs(d).toFixed(1)} min faster`; mE.className='metric-delta '+(d>0?'negative':'positive'); }

  updateRiskArc(m.risk_score||0);
  updateCircularProgress(m.risk_score||0);
  sparkPush(m);
}

function riskLabel(s) { return s>=70?'High':s>=40?'Medium':'Low'; }
function flashCard(id) { const e=document.getElementById(id); if(!e) return; e.classList.remove('flash'); void e.offsetWidth; e.classList.add('flash'); }

function animVal(id, target, large=false) {
  const el = document.getElementById(id);
  if (!el) return;
  const cur = parseInt(el.textContent.replace(/,/g,''))||0;
  const diff = (target||0)-cur; if(!diff) return;
  let i=0; const s=diff/12;
  const t=setInterval(()=>{ i++; const v=Math.round(cur+s*i); el.textContent=large?v.toLocaleString():v; if(i>=12){el.textContent=large?(target||0).toLocaleString():(target||0);clearInterval(t);} },30);
}
function setText(id,v){ const e=document.getElementById(id); if(e) e.textContent=v; }

function updateRiskArc(score) {
  const arc=document.getElementById('risk-arc'); if(!arc) return;
  arc.style.strokeDashoffset=(188*(1-score/100));
  arc.style.stroke=score>=70?'#dc2626':score>=40?'#ca8a04':'#16a34a';
}
function updateCircularProgress(score) {
  ['cp-fill','cp-fill-2'].forEach(id=>{ const e=document.getElementById(id); if(e){ e.style.strokeDashoffset=314*(1-score/100); e.style.stroke=score>=70?'#dc2626':score>=40?'#ca8a04':'#16a34a'; } });
  ['cp-value','cp-value-2'].forEach(id=>setText(id,Math.round(score)+'%'));
  ['cp-level','cp-level-2'].forEach(id=>setText(id,riskLabel(score)));
}

function sparkPush(m) {
  STATE.sparkData.threats.push(m.active_threats||0);
  STATE.sparkData.risk.push(m.risk_score||0);
  if (STATE.sparkData.threats.length>20) { STATE.sparkData.threats.shift(); STATE.sparkData.risk.shift(); }
}

/* ══════════════════════════════════════════════════════════════
   FILE UPLOAD + REAL ANALYSIS
   ═══════════════════════════════════════════════════════════ */
async function handleFileSelect(file) {
  if (!file) return;
  const preview  = document.getElementById('upload-preview');
  const bar      = document.getElementById('upload-progress-bar');
  const statusEl = document.getElementById('upload-status');
  document.getElementById('upload-filename').textContent = file.name;
  document.getElementById('upload-filesize').textContent = fmtBytes(file.size);
  preview.style.display = 'block';
  bar.style.width='0%';
  statusEl.textContent='Uploading file…';

  if (!STATE.useServer) {
    // Simulate upload for demo
    let p=0; const t=setInterval(()=>{ p+=rand(5,18); if(p>=100){p=100;clearInterval(t);statusEl.textContent='[Demo] File ready – start server for real analysis';} bar.style.width=p+'%'; },120);
    return;
  }

  // Real upload
  try {
    const fd = new FormData(); fd.append('file', file);
    const uploadRes = await fetch(`${CFG.API_BASE}/api/upload`, {method:'POST', body:fd});
    const uploadData = await uploadRes.json();

    if (!uploadData.success) {
      bar.style.width='100%'; bar.style.background='var(--red)';
      statusEl.textContent = `Upload failed: ${uploadData.error}`;
      toast(uploadData.error, 'critical'); return;
    }

    bar.style.width='40%';
    statusEl.textContent = `File uploaded (${fmtBytes(uploadData.size)}). Running analysis…`;
    STATE.uploadedFiles.push(uploadData.filename);

    // Trigger analysis
    const analyzeRes  = await fetch(`${CFG.API_BASE}/api/analyze`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({files: [uploadData.filename]})
    });
    const analyzeData = await analyzeRes.json();
    if (!analyzeData.success) { statusEl.textContent=`Analysis failed: ${analyzeData.error}`; return; }

    STATE.currentJobId = analyzeData.job_id;
    bar.style.width = '65%';
    statusEl.textContent = 'Analysis running… polling for results';
    showAnalysisLoader(true);
    pollAnalysisResult(analyzeData.job_id, bar, statusEl);
  } catch(err) {
    statusEl.textContent = `Error: ${err.message}`;
    toast('Upload error: ' + err.message, 'critical');
  }
}

async function pollAnalysisResult(jobId, barEl, statusEl) {
  let attempts = 0;
  const poll = async () => {
    attempts++;
    try {
      const r = await fetch(`${CFG.API_BASE}/api/analysis/${jobId}`);
      const d = await r.json();
      if (d.status === 'done') {
        if (barEl) barEl.style.width = '100%';
        if (statusEl) statusEl.textContent = `Analysis complete: ${d.total_events} events, ${d.alerts?.length||0} threats detected`;
        showAnalysisLoader(false);
        displayRealAnalysis(d);
        toast(`Real analysis complete: ${d.total_events.toLocaleString()} events, ${d.alerts?.length||0} threats`, 'success');
        return;
      }
      if (attempts < 40) { setTimeout(poll, 800); }
      else { if(statusEl) statusEl.textContent='Analysis timed out'; showAnalysisLoader(false); }
    } catch { if(attempts<30) setTimeout(poll,1000); }
  };
  poll();
}

function showAnalysisLoader(show) {
  const el = document.getElementById('analysis-loader');
  if (el) el.style.display = show ? 'flex' : 'none';
}

/* ─── Display real analysis results ─────────────────────────── */
function displayRealAnalysis(result) {
  STATE.dataMode = 'real';
  updateModeIndicator();

  const m = result.metrics || {};
  // Apply real metrics to cards
  applyMetrics({
    active_threats: m.active_threats || 0,
    logs_analyzed:  m.total_events   || 0,
    mttp:           m.mttp           || 0,
    risk_score:     m.risk_score     || 0,
    risk_level:     m.risk_level     || 'Low',
    mode:           'real',
  });

  // Update timeline from real events
  STATE.timeline = (result.timeline || []).map(e => ({
    ts: e.ts, phase: e.type||e.event?.slice(0,20)||'Event',
    detail: e.event, status: e.status,
  }));
  renderTimelines();

  // Update threat feed from real alerts
  STATE.threats = (result.alerts || []).map(a => ({
    src: a.src, dst: '—', event: a.rule,
    event_detail: a.detail, status: a.severity,
    proto: '—', ts: new Date().toISOString().slice(0,19).replace('T',' '),
    mitre: a.mitre,
  }));
  renderThreatFeed();

  // Inject real events into log tables
  const events = result.top_events || [];
  events.forEach(ev => { STATE.logs.unshift(ev); if(STATE.logs.length>CFG.MAX_LOG_ROWS) STATE.logs.pop(); });
  renderMiniLog();
  renderFullLogBatch(events.slice(0,100));
  updateBadges();

  // Update pie chart from real threat distribution
  updatePieFromReal(m.threat_dist || {});

  // Update line chart from real timeline data
  const tl = m.timeline || [];
  if (tl.length >= 2) updateLineFromReal(tl);

  // Render results panel in upload page
  renderAnalysisResults(result);

  // Update prediction bars from real distribution
  if(m.threat_dist) {
    const dist = m.threat_dist;
    const total = Object.values(dist).reduce((a,b)=>a+b,0)||1;
    STATE.predValues = {
      malware:      Math.round((dist.malware||dist.failed_login||0)/total*100),
      phishing:     Math.round((dist.api||dist.api_error||0)/total*100),
      ddos:         Math.round((dist.dos||dist.scan||0)/total*100),
      insider:      Math.round((dist.privesc||dist.credential||0)/total*100),
      supply_chain: Math.round((dist.tamper||dist.persistence||0)/total*100),
    };
    renderPredBars();
  }

  // Brute-force count from real alerts
  const bruteAlert = (result.alerts||[]).find(a=>a.rule.includes('Brute'));
  if (bruteAlert) { STATE.bruteCount = bruteAlert.count||0; updateBruteDisplay(); }

  // Threat feed page counters
  setText('tf-critical', (result.alerts||[]).filter(a=>a.severity==='critical').length);
  setText('tf-warning',  (result.alerts||[]).filter(a=>a.severity==='warning').length);
  setText('tf-contained', m.info_count||0);
  setText('tf-brute',    brut(result.alerts||[]));

  // Render geo table if IPs available
  const topIPs = m.top_ips || [];
  renderTopIPs(topIPs);
}

function brut(alerts) { const a=alerts.find(x=>x.rule.includes('Brute')); return a?a.count:0; }

function renderAnalysisResults(result) {
  const el = document.getElementById('analysis-results-panel');
  if (!el) return;
  el.style.display = 'block';
  const m = result.metrics || {};
  const files = result.files || [];
  const alerts= result.alerts|| [];
  const corr  = result.correlation||[];

  el.innerHTML = `
  <div class="ar-header">
    <div>
      <h3 class="chart-title">Real Analysis Results</h3>
      <p class="chart-sub">${files.map(f=>`<strong>${f.file}</strong> (${f.format}: ${f.events} events)`).join(' · ')}</p>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-primary" onclick="downloadReport('csv')">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        CSV Report
      </button>
      <button class="btn-primary" style="background:var(--purple)" onclick="downloadReport('pdf')">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        PDF Report
      </button>
      <button class="btn-sm" onclick="resetToSimulation()">Reset to Sim mode</button>
    </div>
  </div>

  <div class="ar-stats-grid">
    ${statCard('Total Events',    m.total_events?.toLocaleString()||0, 'blue')}
    ${statCard('Critical Events', m.critical_count||0, 'red')}
    ${statCard('Threats Detected',alerts.length,        'red')}
    ${statCard('Risk Score',       m.risk_score||0,      m.risk_score>=70?'red':m.risk_score>=40?'yellow':'green')}
    ${statCard('Unique IPs',       m.unique_ips||0,      'blue')}
    ${statCard('Unique Users',     m.unique_users||0,    'purple')}
    ${statCard('MTTP',             (m.mttp||0)+' min',   m.mttp>10?'red':'green')}
    ${statCard('Warnings',         m.warning_count||0,   'yellow')}
  </div>

  ${alerts.length ? `
  <div class="ar-section">
    <h4 class="ar-section-title">Detected Threats (${alerts.length})</h4>
    <div class="ar-threat-list">
      ${alerts.map(a=>`
        <div class="ar-threat-item">
          <div style="flex:1">
            <div class="ar-threat-rule">${a.rule}</div>
            <div class="ar-threat-mitre">${a.mitre||''}</div>
            <div class="ar-threat-detail">${a.detail}</div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
            ${badge(a.severity)}
            ${a.src&&a.src!=='—'?`<button class="btn-sm" style="font-size:10px;padding:3px 8px" onclick="geoLookup('${a.src}')">GeoIP</button>`:''}
          </div>
        </div>`).join('')}
    </div>
  </div>` : '<div class="ar-section" style="color:var(--green);font-weight:600">No threats detected in this log file.</div>'}

  ${corr.length ? `
  <div class="ar-section">
    <h4 class="ar-section-title">Cross-File IP Correlation (${corr.length} IPs appear in multiple files)</h4>
    <div class="ar-table-wrap">
      <table class="log-table">
        <thead><tr><th>IP Address</th><th>Appears in Files</th><th>Count</th><th>Type</th><th>GeoIP</th></tr></thead>
        <tbody>
          ${corr.map(c=>`<tr>
            <td class="mono">${c.ip}</td>
            <td style="font-size:11px">${c.files.join(', ')}</td>
            <td>${c.count}</td>
            <td>${badge(c.private?'info':'warning')}</td>
            <td><button class="btn-sm" style="font-size:10px;padding:3px 8px" onclick="geoLookup('${c.ip}')">Lookup</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>` : ''}

  ${result.errors?.length ? `
  <div class="ar-section">
    <h4 class="ar-section-title" style="color:var(--red)">Parse Errors</h4>
    ${result.errors.map(e=>`<p style="font-size:12px;color:var(--text-2)">${e}</p>`).join('')}
  </div>` : ''}`;
}

function statCard(label, val, color) {
  return `<div class="ar-stat-card ar-stat-${color}"><div class="ar-stat-val">${val}</div><div class="ar-stat-lbl">${label}</div></div>`;
}

function renderTopIPs(ips) {
  const el = document.getElementById('top-ips-container');
  if (!el || !ips.length) return;
  el.innerHTML = `<h4 class="ar-section-title" style="margin-bottom:10px">Top Source IPs</h4>`+
    ips.slice(0,8).map(item=>`
      <div class="net-bar-row">
        <span class="net-bar-label mono" style="cursor:pointer" onclick="geoLookup('${item.ip}')">${item.ip}</span>
        <div class="net-bar-track"><div class="net-bar-fill" style="width:${Math.round(item.count/ips[0].count*100)}%"></div></div>
        <span class="net-bar-val">${item.count}</span>
      </div>`).join('');
}

/* ─── Geolocation lookup UI ─────────────────────────────────── */
async function geoLookup(ip) {
  if (!STATE.useServer) { toast('Start server for geolocation', 'info'); return; }
  toast(`Looking up ${ip}…`, 'info');
  try {
    const r = await fetch(`${CFG.API_BASE}/api/geolocate/${ip}`);
    const d = await r.json();
    if (d.error) { toast(`GeoIP failed: ${d.error}`, 'warning'); return; }
    showGeoModal(ip, d);
  } catch(e) { toast('Geolocation error', 'warning'); }
}

function showGeoModal(ip, geo) {
  let modal = document.getElementById('geo-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'geo-modal';
    modal.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:800;display:flex;align-items:center;justify-content:center';
    modal.onclick = e => { if(e.target===modal) modal.remove(); };
    document.body.appendChild(modal);
  }
  modal.innerHTML = `
    <div style="background:var(--surface);border-radius:var(--radius);padding:28px;min-width:320px;box-shadow:var(--shadow-lg);border:1px solid var(--border)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h3 class="chart-title">GeoIP: ${ip}</h3>
        <button onclick="document.getElementById('geo-modal').remove()" style="border:none;background:none;font-size:18px;color:var(--text-3);cursor:pointer">✕</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:10px;font-size:13px">
        <div class="geo-row"><span class="geo-lbl">Country</span><span class="geo-val">${geo.country||'?'}</span></div>
        <div class="geo-row"><span class="geo-lbl">City</span><span class="geo-val">${geo.city||'?'}</span></div>
        <div class="geo-row"><span class="geo-lbl">Organization</span><span class="geo-val">${geo.org||'?'}</span></div>
        <div class="geo-row"><span class="geo-lbl">Coordinates</span><span class="geo-val">${geo.loc||'—'}</span></div>
        <div class="geo-row"><span class="geo-lbl">Type</span><span>${geo.country==='LOCAL'?badge('info'):badge('warning')}</span></div>
      </div>
    </div>`;
  modal.style.display='flex';
}

/* ─── Download report ───────────────────────────────────────── */
async function downloadReport(fmt) {
  if (!STATE.currentJobId) { toast('Upload and analyze a file first', 'info'); return; }
  if (!STATE.useServer)     { toast('Start the server to download reports', 'info'); return; }
  const url = `${CFG.API_BASE}/api/report/${STATE.currentJobId}/${fmt}`;
  toast(`Generating ${fmt.toUpperCase()} report…`, 'info');
  try {
    const r = await fetch(url);
    if (!r.ok) { const e=await r.json(); toast(e.error||'Report failed','warning'); return; }
    const blob = await r.blob();
    const a    = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(blob),
      download: `cfip_report.${fmt}`,
    });
    a.click(); URL.revokeObjectURL(a.href);
    toast(`${fmt.toUpperCase()} report downloaded`, 'success');
  } catch(e) { toast('Download failed: '+e.message,'critical'); }
}
window.downloadReport = downloadReport;

/* ─── Windows live events ───────────────────────────────────── */
async function loadWindowsEvents(logName='Security') {
  if (!STATE.useServer) { toast('Start server to read Windows events', 'info'); return; }
  toast(`Reading Windows ${logName} Event Log…`, 'info');
  try {
    const r = await fetch(`${CFG.API_BASE}/api/windows-events?log=${logName}&count=200`);
    const d = await r.json();
    if (d.success) {
      STATE.currentJobId = d.job_id;
      displayRealAnalysis(d);
      toast(`Loaded ${d.total_events} Windows ${logName} events`, 'success');
      renderAnalysisResults(d);
    } else {
      toast(d.error || 'Failed to read Windows events', 'warning');
    }
  } catch(e) { toast('Error: '+e.message, 'critical'); }
}
window.loadWindowsEvents = loadWindowsEvents;

/* ─── Reset to simulation ───────────────────────────────────── */
async function resetToSimulation() {
  STATE.dataMode = 'simulation';
  STATE.currentJobId = null;
  const panel = document.getElementById('analysis-results-panel');
  if (panel) panel.style.display = 'none';
  if (STATE.useServer) {
    try { await fetch(`${CFG.API_BASE}/api/control`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_mode:true})}); } catch {}
  }
  toast('Switched to simulation mode', 'info');
  updateModeIndicator();
}
window.resetToSimulation = resetToSimulation;

/* ─── Mode indicator ────────────────────────────────────────── */
function updateModeIndicator() {
  const pill  = document.getElementById('live-pill');
  const label = document.getElementById('live-label');
  const badge = document.getElementById('data-mode-badge');
  const isReal= STATE.dataMode === 'real';
  if (pill)  pill.className = `live-pill${!STATE.running?' paused':''}`;
  if (label) label.textContent = STATE.running ? (isReal ? 'REAL DATA' : 'LIVE SIM') : 'PAUSED';
  if (badge) { badge.textContent=isReal?'Real Data Mode':'Simulation Mode'; badge.className=`badge ${isReal?'green':'blue'}`; }
}

/* ─── Chart updates from real data ──────────────────────────── */
function updatePieFromReal(dist) {
  if (!STATE.charts.pie || !Object.keys(dist).length) return;
  const labelMap = {
    failed_login:'Brute-Force',malware:'Malware',scan:'Port Scan',
    privesc:'Privilege Esc.',api:'API Abuse',dos:'DoS/DDoS',
    exfil:'Exfiltration',geoip:'GeoIP Anomaly',lateral:'Lateral Mvmt',
    login_ok:'Normal Auth',process:'Process',policy:'Policy Viol.',
    firewall:'Firewall Block',tamper:'Log Tamper',persistence:'Persistence',
    credential:'Credential Abuse',iam_change:'IAM Change',api_error:'API Error',
    server_error:'Server Error',access_denied:'Access Denied',lockout:'Account Lockout',
  };
  const colors=['#dc2626','#ca8a04','#2563eb','#7c3aed','#ea580c','#16a34a','#94a3b8','#0891b2'];
  const entries=Object.entries(dist).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const labels=entries.map(([k])=>labelMap[k]||k);
  const data=entries.map(([,v])=>v);
  STATE.charts.pie.data.labels=labels;
  STATE.charts.pie.data.datasets[0].data=data;
  STATE.charts.pie.data.datasets[0].backgroundColor=colors.slice(0,data.length);
  STATE.charts.pie.update();
  const legend=document.getElementById('pie-legend');
  if(legend) legend.innerHTML=labels.map((l,i)=>`<div class="legend-item"><div class="legend-dot" style="background:${colors[i]}"></div><span>${l} ${data[i]}</span></div>`).join('');
}

function updateLineFromReal(tl) {
  if (!STATE.charts.line || tl.length<2) return;
  const labels=tl.map(x=>x.label?.slice(11,16)||x.label);
  const counts=tl.map(x=>x.count);
  STATE.charts.line.data.labels=labels;
  STATE.charts.line.data.datasets[0].data=counts;
  STATE.charts.line.data.datasets[1].data=counts.map(v=>Math.max(0,v-rand(0,5)));
  STATE.charts.line.update();
  setText('event-rate-badge',`${Math.max(...counts)} peak/hr`);
}

function renderFullLogBatch(events) {
  const tbody = document.getElementById('full-log-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  events.forEach((ev,i) => {
    const row = document.createElement('tr');
    row.className = `row-${ev.status}`;
    row.innerHTML = `
      <td class="mono" style="color:var(--text-3)">${i+1}</td>
      <td class="mono">${ev.ts}</td>
      <td class="mono">${ev.src}</td>
      <td class="mono" style="color:var(--text-3)">${ev.dst}</td>
      <td style="color:var(--text-3);font-size:11px">${ev.user||'—'}</td>
      <td style="max-width:220px;white-space:normal;font-size:12px">${ev.event}</td>
      <td><span class="mono" style="background:var(--surface-2);padding:2px 6px;border-radius:5px">${ev.proto}</span></td>
      <td class="mono" style="color:var(--text-3)">${ev.bytes||'—'}</td>
      <td>${badge(ev.status)}</td>`;
    tbody.appendChild(row);
  });
  const cnt=document.getElementById('full-log-count');
  if(cnt) cnt.textContent=`${events.length} events from real file analysis`;
}

/* ══════════════════════════════════════════════════════════════
   BRUTE FORCE DETECTION (real-time client-side)
   ═══════════════════════════════════════════════════════════ */
function checkBruteForce(entry) {
  const now=Date.now();
  const recent=STATE.failedLogins.filter(t=>now-t<CFG.BRUTE_WINDOW);
  STATE.bruteCount=recent.length;
  if (recent.length>=CFG.BRUTE_CRIT) {
    toast(`CRITICAL: Brute-force – ${recent.length} failures in 60s from ${entry.src}`, 'critical');
    showBanner(`BRUTE-FORCE ATTACK: ${recent.length} failed logins from ${entry.src}`);
  } else if (recent.length>=CFG.BRUTE_WARN) {
    toast(`Brute-force warning: ${recent.length} failures · ${entry.src}`, 'warning');
  }
  updateBruteDisplay();
}
function startBruteMonitor() {
  setInterval(()=>{ STATE.failedLogins=STATE.failedLogins.filter(t=>Date.now()-t<CFG.BRUTE_WINDOW); STATE.bruteCount=STATE.failedLogins.length; updateBruteDisplay(); },5000);
}
function updateBruteDisplay() {
  const el=document.getElementById('brute-count'); const bar=document.getElementById('brute-bar');
  if(el) el.textContent=STATE.bruteCount;
  if(bar){ bar.style.width=Math.min(100,STATE.bruteCount/CFG.BRUTE_CRIT*100)+'%'; bar.style.background=STATE.bruteCount>=CFG.BRUTE_CRIT?'var(--red)':STATE.bruteCount>=CFG.BRUTE_WARN?'var(--yellow)':'var(--green)'; }
}

/* ══════════════════════════════════════════════════════════════
   LOG RENDERING
   ═══════════════════════════════════════════════════════════ */
function renderMiniLog() {
  const tbody=document.getElementById('mini-log-tbody'); if(!tbody) return;
  const data=applyFilter(STATE.logs).slice(0,CFG.MAX_MINI_ROWS);
  tbody.innerHTML=data.map((r,i)=>`<tr class="row-${r.status}${i===0?' row-new':''}">
    <td class="mono">${r.ts?.slice(11)||'—'}</td>
    <td class="mono">${r.src}</td>
    <td style="max-width:240px;white-space:normal;font-size:12px">${r.event}</td>
    <td><span class="mono" style="background:var(--surface-2);padding:2px 6px;border-radius:5px">${r.proto}</span></td>
    <td>${badge(r.status)}</td></tr>`).join('');
}

function renderFullLogRow(entry) {
  const tbody=document.getElementById('full-log-tbody'); const scroll=document.getElementById('full-log-scroll');
  if(!tbody) return;
  while(tbody.children.length>=CFG.MAX_LOG_ROWS) tbody.removeChild(tbody.lastChild);
  const n=tbody.children.length;
  const row=document.createElement('tr');
  row.className=`row-${entry.status} row-new`;
  row.innerHTML=`<td class="mono" style="color:var(--text-3)">${n+1}</td><td class="mono">${entry.ts}</td><td class="mono">${entry.src}</td><td class="mono" style="color:var(--text-3)">${entry.dst}</td><td style="color:var(--text-3);font-size:11px">${entry.user||'—'}</td><td style="max-width:220px;white-space:normal;font-size:12px">${entry.event}</td><td><span class="mono" style="background:var(--surface-2);padding:2px 6px;border-radius:5px">${entry.proto}</span></td><td class="mono" style="color:var(--text-3)">${entry.bytes||'—'}</td><td>${badge(entry.status)}</td>`;
  tbody.insertBefore(row,tbody.firstChild);
  if(scroll&&document.getElementById('autoscroll-cb')?.checked) scroll.scrollTop=0;
  const cnt=document.getElementById('full-log-count'); if(cnt) cnt.textContent=`${tbody.children.length} events streamed`;
}

function applyFilter(arr) {
  let out=arr;
  if(STATE.sevFilter!=='all')  out=out.filter(r=>r.status===STATE.sevFilter);
  if(STATE.searchQuery) out=out.filter(r=>JSON.stringify(r).toLowerCase().includes(STATE.searchQuery.toLowerCase()));
  return out;
}

/* ══════════════════════════════════════════════════════════════
   TIMELINE
   ═══════════════════════════════════════════════════════════ */
function renderTimelines() {
  ['dashboard-timeline','full-timeline'].forEach(id=>{
    const el=document.getElementById(id); if(!el) return;
    const data=STATE.timeline.slice(0,id==='dashboard-timeline'?6:50);
    if(!data.length){el.innerHTML='<div class="tl-empty">Awaiting events…</div>';return;}
    el.innerHTML=data.map(t=>`<div class="tl-item"><div class="tl-dot ${t.status}"></div><div style="flex:1"><div class="tl-header"><span class="tl-time">${t.ts?.slice(11)||'—'}</span><span class="badge ${t.status==='critical'?'red':t.status==='warning'?'yellow':'blue'}">${t.phase}</span></div><div class="tl-event">${t.detail}</div></div></div>`).join('');
  });
}

/* ══════════════════════════════════════════════════════════════
   THREAT FEED
   ═══════════════════════════════════════════════════════════ */
function addThreat(ev) {
  STATE.threats.unshift(ev);
  if(STATE.threats.length>40) STATE.threats.pop();
  renderThreatFeed();
}
function renderThreatFeed() {
  const el=document.getElementById('threat-feed'); if(!el) return;
  if(!STATE.threats.length){el.innerHTML='<div class="notif-empty">Monitoring…</div>';return;}
  const ico=`<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  el.innerHTML=STATE.threats.slice(0,20).map(t=>`
    <div class="threat-item">
      <div class="threat-item-icon ${t.status==='critical'?'bg-red':'bg-yellow'}">${ico}</div>
      <div class="threat-item-body">
        <div class="threat-item-title">${t.event||t.rule||'—'}</div>
        <div class="threat-item-sub">${t.event_detail||`${t.src} → ${t.dst} · ${t.ts?.slice(11)||''} · ${t.proto}`}</div>
        ${t.mitre?`<div style="font-size:10px;color:var(--text-3);margin-top:2px">${t.mitre}</div>`:''}
      </div>
      <div style="flex-shrink:0;display:flex;flex-direction:column;gap:4px;align-items:flex-end">
        ${badge(t.status)}
        ${t.src&&t.src!=='—'?`<button class="btn-sm" style="font-size:10px;padding:3px 8px" onclick="geoLookup('${t.src}')">GeoIP</button>`:''}
      </div>
    </div>`).join('');
}
function clearThreats() { STATE.threats=[]; STATE.criticalCount=0; STATE.warningCount=0; renderThreatFeed(); updateBadges(); }
window.clearThreats=clearThreats;

/* ══════════════════════════════════════════════════════════════
   NOTIFICATIONS
   ═══════════════════════════════════════════════════════════ */
function addNotification(ev) {
  STATE.notifications.unshift({msg:`${ev.event} · ${ev.src}`,status:ev.status,ts:ev.ts?.slice(11)||'—'});
  if(STATE.notifications.length>60) STATE.notifications.pop();
  renderNotifications();
  const dot=document.getElementById('notif-dot'); if(dot) dot.style.display='block';
}
function renderNotifications() {
  const el=document.getElementById('notif-list'); if(!el) return;
  if(!STATE.notifications.length){el.innerHTML='<div class="notif-empty">No alerts</div>';return;}
  el.innerHTML=STATE.notifications.slice(0,40).map(n=>`<div class="notif-item ${n.status}"><div class="ni-dot ${n.status}"></div><div><strong style="font-size:12px">${n.msg}</strong><br><small style="color:var(--text-3)">${n.ts}</small></div></div>`).join('');
}
function clearAlerts() { STATE.notifications=[]; renderNotifications(); const d=document.getElementById('notif-dot'); if(d) d.style.display='none'; }
function toggleNotifPanel() { STATE.notifOpen=!STATE.notifOpen; document.getElementById('notif-drawer')?.classList.toggle('open',STATE.notifOpen); }
window.clearAlerts=clearAlerts; window.toggleNotifPanel=toggleNotifPanel;
document.addEventListener('click',e=>{ if(!e.target.closest('#notif-drawer')&&!e.target.closest('#notif-btn')){ document.getElementById('notif-drawer')?.classList.remove('open'); STATE.notifOpen=false; } });

/* ══════════════════════════════════════════════════════════════
   BANNER
   ═══════════════════════════════════════════════════════════ */
let _bannerTimer;
function showBanner(msg) {
  const b=document.getElementById('alert-banner'); const m=document.getElementById('alert-banner-msg');
  if(!b||!m) return; m.textContent=msg; b.style.display='block';
  clearTimeout(_bannerTimer); _bannerTimer=setTimeout(()=>b.style.display='none',7000);
}
function dismissBanner() { const b=document.getElementById('alert-banner'); if(b) b.style.display='none'; }
window.dismissBanner=dismissBanner;

/* ══════════════════════════════════════════════════════════════
   CHARTS
   ═══════════════════════════════════════════════════════════ */
function buildLineChart() {
  const ctx=document.getElementById('lineChart'); if(!ctx) return;
  const labels=[]; const now=new Date();
  for(let i=29;i>=0;i--){const d=new Date(now-i*5000);labels.push(d.toLocaleTimeString('en-IN',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'}));}
  STATE.chartLabels=labels; STATE.chartThreats=Array(30).fill(0); STATE.chartBenign=Array(30).fill(0);
  STATE.charts.line=new Chart(ctx,{
    type:'line',
    data:{labels,datasets:[
      {label:'Threats',data:STATE.chartThreats,borderColor:'#dc2626',backgroundColor:'rgba(220,38,38,.07)',borderWidth:2,pointRadius:2.5,pointBorderColor:'#fff',pointBorderWidth:1.5,tension:.4,fill:true},
      {label:'Normal', data:STATE.chartBenign, borderColor:'#2563eb',backgroundColor:'rgba(37,99,235,.05)',borderWidth:2,pointRadius:2.5,pointBorderColor:'#fff',pointBorderWidth:1.5,tension:.4,fill:true},
    ]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},interaction:{mode:'index',intersect:false},
      plugins:{legend:{display:true,position:'top',align:'end',labels:{boxWidth:10,boxHeight:10,borderRadius:3,useBorderRadius:true,color:'#475569',font:{size:11}}},
        tooltip:{backgroundColor:'#fff',titleColor:'#0f172a',bodyColor:'#475569',borderColor:'#e2e8f0',borderWidth:1,padding:10}},
      scales:{x:{grid:{color:'#f1f5f9'},ticks:{color:'#94a3b8',font:{size:10},maxTicksLimit:8}},y:{grid:{color:'#f1f5f9'},ticks:{color:'#94a3b8',font:{size:10}},beginAtZero:true}}}});
}

function buildPieChart() {
  const ctx=document.getElementById('pieChart'); if(!ctx) return;
  const labels=['Malware','Phishing','DDoS','Insider','Ransomware','Other'];
  const colors=['#dc2626','#ca8a04','#2563eb','#7c3aed','#ea580c','#94a3b8'];
  STATE.charts.pie=new Chart(ctx,{
    type:'doughnut',
    data:{labels,datasets:[{data:[34,22,18,8,12,6],backgroundColor:colors,borderWidth:3,borderColor:'#fff',hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'65%',animation:{duration:600},
      plugins:{legend:{display:false},tooltip:{backgroundColor:'#fff',titleColor:'#0f172a',bodyColor:'#475569',borderColor:'#e2e8f0',borderWidth:1,padding:10,callbacks:{label:c=>` ${c.label}: ${c.parsed}`}}}}});
  const lg=document.getElementById('pie-legend');
  if(lg) lg.innerHTML=labels.map((l,i)=>`<div class="legend-item"><div class="legend-dot" style="background:${colors[i]}"></div><span>${l}</span></div>`).join('');
}

function buildAnomalyChart() {
  const ctx=document.getElementById('anomalyChart'); if(!ctx) return;
  STATE.anomalyData=Array(30).fill(0).map(()=>rand(5,40));
  STATE.charts.anomaly=new Chart(ctx,{
    type:'line',
    data:{labels:Array(30).fill(''),datasets:[{data:STATE.anomalyData,borderColor:'#7c3aed',backgroundColor:'rgba(124,58,237,.08)',borderWidth:2,pointRadius:0,tension:.4,fill:true}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:200},plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{display:false},y:{display:false,beginAtZero:true}}}});
}

function startChartRefresh() {
  setInterval(()=>{
    if(STATE.chartPaused||!STATE.charts.line) return;
    const now=new Date();
    const lbl=now.toLocaleTimeString('en-IN',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
    STATE.chartLabels.push(lbl); STATE.chartThreats.push(STATE._chartTick.t); STATE.chartBenign.push(STATE._chartTick.b);
    if(STATE.chartLabels.length>30){STATE.chartLabels.shift();STATE.chartThreats.shift();STATE.chartBenign.shift();}
    STATE._chartTick={t:0,b:0};
    const total=(STATE.chartThreats.slice(-1)[0]||0)+(STATE.chartBenign.slice(-1)[0]||0);
    setText('event-rate-badge',`${total*12}/min`);
    STATE.charts.line.data.labels=STATE.chartLabels;
    STATE.charts.line.data.datasets[0].data=STATE.chartThreats;
    STATE.charts.line.data.datasets[1].data=STATE.chartBenign;
    STATE.charts.line.update('none');
    STATE.anomalyData.push(rand(STATE.criticalCount,STATE.criticalCount+rand(5,30)));
    STATE.anomalyData.shift();
    if(STATE.charts.anomaly){STATE.charts.anomaly.data.datasets[0].data=STATE.anomalyData;STATE.charts.anomaly.update('none');}
  },CFG.CHART_INTERVAL);
}

function toggleChartPause(){
  STATE.chartPaused=!STATE.chartPaused;
  const btn=document.getElementById('chart-pause-btn'); if(btn) btn.textContent=STATE.chartPaused?'▶ Resume':'⏸ Pause';
}
window.toggleChartPause=toggleChartPause;

/* ══════════════════════════════════════════════════════════════
   PREDICTION
   ═══════════════════════════════════════════════════════════ */
function startPredRefresh() {
  renderPredBars();
  setInterval(()=>{ if(STATE.dataMode==='simulation'){Object.keys(STATE.predValues).forEach(k=>{STATE.predValues[k]=Math.max(5,Math.min(99,STATE.predValues[k]+rand(-3,5)));});renderPredBars();} },8000);
}
function renderPredBars() {
  const cm=v=>v>=70?'red':v>=40?'yellow':'green';
  const lm={malware:'Malware',phishing:'Phishing',ddos:'DDoS',insider:'Insider',supply_chain:'Supply Chain'};
  ['pred-bars-dash','pred-bars-full'].forEach(id=>{
    const el=document.getElementById(id); if(!el) return;
    el.innerHTML=Object.keys(STATE.predValues).map(k=>`<div class="pred-bar-row"><span>${lm[k]||k}</span><div class="pred-bar-track"><div class="pred-bar ${cm(STATE.predValues[k])}" style="width:${STATE.predValues[k]}%"></div></div><span class="pred-pct">${STATE.predValues[k]}%</span></div>`).join('');
  });
  updateCircularProgress(Math.round(Object.values(STATE.predValues).reduce((a,b)=>a+b,0)/Object.keys(STATE.predValues).length));
}
window.forceMetricsUpdate=()=>{ Object.keys(STATE.predValues).forEach(k=>{STATE.predValues[k]=Math.max(5,Math.min(99,STATE.predValues[k]+rand(-8,10)));});renderPredBars();toast('Prediction refreshed','info'); };

/* ══════════════════════════════════════════════════════════════
   SIMULATION CONTROLS
   ═══════════════════════════════════════════════════════════ */
function toggleSimulation() {
  STATE.running=!STATE.running;
  const btn=document.getElementById('sim-toggle-btn'); const lbl=document.getElementById('sim-toggle-label');
  const pill=document.getElementById('live-pill');
  if(STATE.running){ if(!STATE.useServer) scheduleSimEvent(); if(btn) btn.className='btn-sim stop'; if(lbl) lbl.textContent='Pause'; toast('Simulation resumed','success'); }
  else { clearTimeout(STATE.simTimer); if(btn) btn.className='btn-sim play'; if(lbl) lbl.textContent='Resume'; toast('Simulation paused','info'); }
  updateModeIndicator();
  if(STATE.useServer) fetch(`${CFG.API_BASE}/api/control`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({running:STATE.running})}).catch(()=>{});
}
window.toggleSimulation=toggleSimulation;

function setSpeed(val) {
  const d=parseFloat(val)*1000; CFG.SIM_MIN=d*.6; CFG.SIM_MAX=d*1.4;
  if(STATE.useServer) fetch(`${CFG.API_BASE}/api/control`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({speed:parseFloat(val)})}).catch(()=>{});
  const lbl={3:'Slow',1.5:'Normal',0.7:'Fast',0.3:'Turbo'}; toast(`Speed: ${lbl[val]||val}x`,'info');
}
window.setSpeed=setSpeed;

/* ══════════════════════════════════════════════════════════════
   NAVIGATION + BADGES
   ═══════════════════════════════════════════════════════════ */
const PAGE_META={
  dashboard: ['Security Dashboard','Real-time threat overview'],
  logs:      ['Live Log Stream','Real-time event log'],
  threats:   ['Threat Intel Feed','Live IOC watch'],
  timeline:  ['Kill-Chain Timeline','Recon → Exfil progression'],
  prediction:['AI Threat Prediction','Risk forecast'],
  incidents: ['Response Playbooks','Automated remediation'],
  upload:    ['File Upload & Analysis','Real log parsing & threat detection'],
};
function navigateTo(page,el) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const t=document.getElementById('page-'+page); if(t) t.classList.add('active');
  if(el) el.classList.add('active');
  const [h,s]=PAGE_META[page]||['Dashboard',''];
  setText('page-heading',h); setText('page-sub',s);
  document.getElementById('notif-drawer')?.classList.remove('open');
}
window.navigateTo=navigateTo;

function toggleSidebar() {
  const sb=document.getElementById('sidebar'); const main=document.getElementById('main-content');
  if(window.innerWidth<=768) sb.classList.toggle('mobile-open');
  else { sb.classList.toggle('collapsed'); main.classList.toggle('expanded'); }
}
window.toggleSidebar=toggleSidebar;

function updateBadges() {
  const lb=document.getElementById('log-badge'); const tb=document.getElementById('threat-badge');
  if(lb) lb.textContent=STATE.totalEvents>999?'999+':STATE.totalEvents;
  if(tb){tb.textContent=STATE.criticalCount;tb.className='nav-badge'+(STATE.criticalCount>0?' critical':'');}
  setText('tf-critical',STATE.criticalCount); setText('tf-warning',STATE.warningCount);
  setText('tf-contained',STATE.infoCount);    setText('tf-brute',STATE.bruteCount);
}
function updateLiveTick(){const e=document.getElementById('live-tick');if(e) e.textContent=`● ${STATE.totalEvents.toLocaleString()} events`;}

/* ══════════════════════════════════════════════════════════════
   FILTER / SEARCH / EXPORT
   ═══════════════════════════════════════════════════════════ */
function setSeverityFilter(v){STATE.sevFilter=v;renderMiniLog();}
window.setSeverityFilter=setSeverityFilter;
function onGlobalSearch(v){STATE.searchQuery=v.trim();renderMiniLog();}
window.onGlobalSearch=onGlobalSearch;
function clearLogs(){STATE.logs=[];STATE.totalEvents=0;STATE.criticalCount=0;STATE.warningCount=0;STATE.infoCount=0;const tb=document.getElementById('full-log-tbody');if(tb) tb.innerHTML='';renderMiniLog();updateBadges();toast('Logs cleared','info');}
window.clearLogs=clearLogs;
function clearTimeline(){STATE.timeline=[];renderTimelines();}
window.clearTimeline=clearTimeline;
function exportLogs() {
  const rows=applyFilter(STATE.logs);
  const hdr='Timestamp,Source IP,Destination,User,Event,Protocol,Bytes,Status,Source File\n';
  const body=rows.map(r=>`"${r.ts}","${r.src}","${r.dst}","${r.user||''}","${r.event}","${r.proto}","${r.bytes||''}","${r.status}","${r.file||''}"`).join('\n');
  const a=Object.assign(document.createElement('a'),{href:URL.createObjectURL(new Blob([hdr+body],{type:'text/csv'})),download:`cfip_logs_${Date.now()}.csv`});
  a.click();URL.revokeObjectURL(a.href);toast(`${rows.length} logs exported`,'success');
}
window.exportLogs=exportLogs;

/* ══════════════════════════════════════════════════════════════
   FILE UPLOAD (drag-drop)
   ═══════════════════════════════════════════════════════════ */
function handleDragOver(e){e.preventDefault();document.getElementById('dropzone').classList.add('drag-over');}
function handleDragLeave(){document.getElementById('dropzone').classList.remove('drag-over');}
function handleDrop(e){e.preventDefault();document.getElementById('dropzone').classList.remove('drag-over');const f=e.dataTransfer.files[0];if(f) handleFileSelect(f);}
window.handleDragOver=handleDragOver;window.handleDragLeave=handleDragLeave;window.handleDrop=handleDrop;window.handleFileSelect=handleFileSelect;

/* ══════════════════════════════════════════════════════════════
   PLAYBOOKS
   ═══════════════════════════════════════════════════════════ */
const PLAYBOOKS=[
  {n:1,t:'Ransomware Containment',   s:'Isolate host → Kill process → Restore snapshot',    sev:'critical'},
  {n:2,t:'Brute-force Mitigation',   s:'Block IP → Enable CAPTCHA → Audit account',         sev:'warning'},
  {n:3,t:'Lateral Movement Response',s:'Kill session → Force re-auth → Network segmentation',sev:'critical'},
  {n:4,t:'Phishing Email Handling',  s:'Quarantine mail → Extract IOCs → Block domain',     sev:'warning'},
  {n:5,t:'DDoS Traffic Scrubbing',   s:'Rate-limit → CDN scrub → Upstream blackhole',       sev:'info'},
  {n:6,t:'Insider Threat Protocol',  s:'Log collection → Manager alert → Access revocation',sev:'info'},
  {n:7,t:'Zero-Day Emergency',       s:'Emergency patch → WAF rule → Threat share',         sev:'critical'},
];
function renderPlaybooks() {
  const el=document.getElementById('playbook-list'); if(!el) return;
  el.innerHTML=PLAYBOOKS.map(p=>`<div class="playbook-item" onclick="runPlaybook('${p.t}')"><div class="playbook-num">${p.n}</div><div style="flex:1"><div class="playbook-title">${p.t}</div><div class="playbook-sub">${p.s}</div></div><div>${badge(p.sev)}</div></div>`).join('');
}
function runPlaybook(name){toast(`Running: ${name}…`,'info');setTimeout(()=>toast(`Completed: ${name}`,'success'),rand(1500,3000));}
window.runPlaybook=runPlaybook;

/* ══════════════════════════════════════════════════════════════
   TOAST
   ═══════════════════════════════════════════════════════════ */
function toast(msg,type='info'){
  if(STATE._toastCount>4) return; STATE._toastCount++;
  const c=document.getElementById('toast-container');
  const e=document.createElement('div'); e.className=`toast ${type}`;
  e.innerHTML=`<div class="toast-icon"></div><span>${msg}</span>`;
  c.appendChild(e);
  setTimeout(()=>{e.style.animation='toastOut .25s ease forwards';setTimeout(()=>{e.remove();STATE._toastCount=Math.max(0,STATE._toastCount-1);},250);},type==='critical'?6000:3500);
}
window.toast=toast;

/* ══════════════════════════════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════════════════════════ */
function rand(min,max){return Math.floor(Math.random()*(max-min+1))+min;}
function fmtBytes(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';}
function badge(s){const m={critical:['red','Critical'],warning:['yellow','Warning'],info:['blue','Info'],success:['green','Resolved']};const [cls,lbl]=m[s]||['blue','Info'];return `<span class="badge ${cls}">${lbl}</span>`;}
window.geoLookup=geoLookup;
