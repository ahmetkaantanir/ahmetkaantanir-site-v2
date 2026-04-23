/* ===================================================
   Log Intelligence Lab — script.js v2.0
   =================================================== */
'use strict';

// ── Config ──────────────────────────────────────────
const API_BASE = resolveApiBase();

const DATASET_MAP = { apache: 'apache.log', auth: 'auth.log', mixed: 'mixed.log' };

// ── State ────────────────────────────────────────────
let latestAnalysis = null;
let latestAnalysisId = null;
let trafficChartInst = null;
let ipChartInst = null;

// ── DOM References ───────────────────────────────────
const els = {
  menuToggle:      q('#menuToggle'),
  navLinks:        q('#navLinks'),
  rawLogs:         q('#rawLogs'),
  logFile:         q('#logFile'),
  pickFileBtn:     q('#pickFileBtn'),
  fileName:        q('#fileName'),
  fileNameBadge:   q('#fileNameBadge'),
  dropZone:        q('#dropZone'),
  uploadInfo:      q('#uploadInfo'),
  apiInput:        q('#apiInput'),
  appendApiData:   q('#appendApiData'),
  runAnalysis:     q('#runAnalysis'),
  clearLogs:       q('#clearLogs'),
  alertsList:      q('#alertsList'),
  alertsBadge:     q('#alertsBadge'),
  correlationList: q('#correlationList'),
  corrBadge:       q('#corrBadge'),
  kpiTotal:        q('#kpiTotal'),
  kpiFailed:       q('#kpiFailed'),
  kpiError:        q('#kpiError'),
  kpiTopIp:        q('#kpiTopIp'),
  kpiTotalBar:     q('#kpiTotalBar'),
  kpiFailedBar:    q('#kpiFailedBar'),
  kpiErrorBar:     q('#kpiErrorBar'),
  statLogs:        q('#statLogs'),
  statAlerts:      q('#statAlerts'),
  statRisk:        q('#statRisk'),
  riskIconWrap:    q('#riskIconWrap'),
  reportOutput:    q('#reportOutput'),
  generateDaily:   q('#generateDaily'),
  generateWeekly:  q('#generateWeekly'),
  downloadReport:  q('#downloadReport'),
  trafficChart:    q('#trafficChart'),
  trafficBadge:    q('#trafficBadge'),
  ipChart:         q('#ipChart'),
  ipBadge:         q('#ipBadge'),
  anomalyList:     q('#anomalyList'),
  anomalyBadge:    q('#anomalyBadge'),
  reputationList:  q('#reputationList'),
  repBadge:        q('#repBadge'),
  historyBody:     q('#historyBody'),
  refreshHistory:  q('#refreshHistory'),
};

// ── Boot ─────────────────────────────────────────────
bindEvents();
bootRevealAnimation();
initActiveNavHighlight();
initBgCanvas();
loadHistory();

// ── Event Binding ─────────────────────────────────────
function bindEvents() {
  // Menu toggle
  if (els.menuToggle) {
    els.menuToggle.addEventListener('click', () => {
      const isOpen = els.navLinks.classList.toggle('open');
      els.menuToggle.setAttribute('aria-expanded', String(isOpen));
    });
  }

  // Close menu on link click
  document.querySelectorAll('.nav-link, .dock-item').forEach(link => {
    link.addEventListener('click', () => {
      els.navLinks.classList.remove('open');
      els.menuToggle?.setAttribute('aria-expanded', 'false');
    });
  });

  // Close menu on outside click
  document.addEventListener('click', e => {
    if (!els.navLinks.classList.contains('open')) return;
    if (!e.target.closest('.nav')) {
      els.navLinks.classList.remove('open');
      els.menuToggle?.setAttribute('aria-expanded', 'false');
    }
  });

  // Dataset buttons
  document.querySelectorAll('[data-dataset]').forEach(btn => {
    btn.addEventListener('click', () => loadDataset(btn.getAttribute('data-dataset')));
  });

  // File picking & drag-drop
  if (els.pickFileBtn && els.logFile) {
    els.pickFileBtn.addEventListener('click', () => els.logFile.click());
    els.logFile.addEventListener('change', () => {
      const file = els.logFile.files?.[0];
      handleFileSelected(file);
    });
  }
  initDragDrop();

  // Dropzone click → file dialog
  if (els.dropZone) {
    els.dropZone.addEventListener('click', e => {
      if (e.target !== els.pickFileBtn && !e.target.closest('#pickFileBtn')) {
        els.logFile.click();
      }
    });
    els.dropZone.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); els.logFile.click(); }
    });
  }

  // Tool actions
  els.appendApiData?.addEventListener('click', appendApiPayload);
  els.runAnalysis?.addEventListener('click', runAnalysis);
  els.clearLogs?.addEventListener('click', clearAll);
  els.generateDaily?.addEventListener('click', () => generateReport('Daily'));
  els.generateWeekly?.addEventListener('click', () => generateReport('Weekly'));
  els.downloadReport?.addEventListener('click', downloadReport);
  els.refreshHistory?.addEventListener('click', loadHistory);
}

// ── Drag & Drop ───────────────────────────────────────
function initDragDrop() {
  const zone = els.dropZone;
  if (!zone) return;

  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', e => {
    if (!zone.contains(e.relatedTarget)) zone.classList.remove('drag-over');
  });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      // Validate
      const ext = file.name.split('.').pop().toLowerCase();
      if (!['log','txt','json'].includes(ext)) {
        toast('Sadece .log, .txt, .json dosyaları desteklenir.', 'error');
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        toast('Dosya boyutu 5 MB\'ı aşamaz.', 'error');
        return;
      }
      // Put into file input
      const dt = new DataTransfer();
      dt.items.add(file);
      els.logFile.files = dt.files;
      handleFileSelected(file);
      toast(`${file.name} sürüklenerek yüklendi.`, 'success');
    }
  });
}

function handleFileSelected(file) {
  if (!file) return;
  els.fileNameBadge?.removeAttribute('hidden');
  if (els.fileName) els.fileName.textContent = `${file.name} (${Math.ceil(file.size / 1024)} KB)`;
}

// ── Dataset Loader ────────────────────────────────────
async function loadDataset(key) {
  const fileName = DATASET_MAP[key];
  if (!fileName) { toast('Dataset tanımı yok.', 'warning'); return; }
  try {
    const res = await fetch(`${API_BASE}/api/datasets/${encodeURIComponent(fileName)}`);
    const payload = await parseJsonResponse(res);
    if (!res.ok || !payload) throw new Error(resolveApiError(payload, `Dataset yüklenemedi (HTTP ${res.status})`));
    els.rawLogs.value = payload.content || '';
    toast(`${payload.name} başarıyla yüklendi.`, 'success');
  } catch {
    toast('Dataset yüklenemedi. Flask sunucusu çalışıyor mu?', 'error');
  }
}

// ── API Data ──────────────────────────────────────────
function appendApiPayload() {
  const payload = els.apiInput.value.trim();
  if (!payload) { toast('API simülasyon alanı boş.', 'warning'); return; }
  const lines = payload.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.some(l => !safeJsonParse(l))) { toast('Her satır geçerli JSON olmalı.', 'error'); return; }
  els.rawLogs.value = [els.rawLogs.value.trim(), ...lines].filter(Boolean).join('\n');
  els.apiInput.value = '';
  toast(`${lines.length} API kaydı eklendi.`, 'success');
}

// ── Analysis ──────────────────────────────────────────
async function runAnalysis() {
  const hasFile = els.logFile.files?.length > 0;
  const raw = els.rawLogs.value.trim();
  if (!hasFile && !raw) { toast('Analiz için dosya yükleyin veya log girin.', 'warning'); return; }

  setLoading(true);

  try {
    let response;
    if (hasFile) {
      const fd = new FormData();
      fd.append('file', els.logFile.files[0]);
      response = await fetch(`${API_BASE}/api/analyze`, { method: 'POST', body: fd });
    } else {
      response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_logs: raw, api_lines: parseApiLines(raw) }),
      });
    }

    const payload = await parseJsonResponse(response);
    if (!response.ok || !payload) throw new Error(resolveApiError(payload, friendlyHttpError(response.status, `Analiz başarısız (HTTP ${response.status})`)));

    latestAnalysis   = payload.analysis;
    latestAnalysisId = payload.analysis_id;

    renderKpis(latestAnalysis);
    renderAlerts(latestAnalysis.alerts || []);
    renderCorrelation(latestAnalysis.correlations || []);
    renderAnomalies(latestAnalysis.anomaly_detection || {});
    renderReputation(latestAnalysis.ip_reputation || []);
    drawTrafficChart(latestAnalysis.hourly_traffic || []);
    drawIpChart(latestAnalysis.top_ips || []);
    loadHistory();

    const risk = latestAnalysis.risk || 'low';
    toast(`Analiz tamamlandı — Risk: ${toRiskLabel(risk).toUpperCase()}`, risk === 'high' ? 'error' : risk === 'medium' ? 'warning' : 'success');
  } catch (err) {
    toast(err.message || 'Analiz sırasında hata oluştu.', 'error');
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  const btn = els.runAnalysis;
  if (!btn) return;
  const label   = btn.querySelector('.btn-label');
  const spinner = btn.querySelector('.btn-spinner');
  btn.disabled = on;
  if (label)   label.hidden   = on;
  if (spinner) spinner.hidden = !on;
}

function parseApiLines(rawText) {
  return rawText.split('\n').map(l => l.trim()).filter(Boolean)
    .map(l => safeJsonParse(l)).filter(Boolean);
}

// ── Render: KPIs ──────────────────────────────────────
function renderKpis(result) {
  const total   = result.total       || 0;
  const failed  = result.failed_login || 0;
  const errRate = Number(result.error_rate  || 0);
  const topIp   = result.top_ip      || '-';
  const risk    = result.risk        || 'low';

  countUp(els.kpiTotal,  total,   0);
  countUp(els.kpiFailed, failed,  0);
  countUp(els.statLogs,  total,   0);
  countUp(els.statAlerts, (result.alerts||[]).length, 0);

  els.kpiError.textContent = `${errRate.toFixed(1)}%`;
  els.kpiTopIp.textContent  = shortIp(topIp);

  if (els.kpiTotalBar)  els.kpiTotalBar.style.width  = total > 0   ? '80%' : '0%';
  if (els.kpiFailedBar) els.kpiFailedBar.style.width = failed > 0  ? Math.min(100, (failed/Math.max(total,1))*100*5)+'%' : '0%';
  if (els.kpiErrorBar)  els.kpiErrorBar.style.width  = Math.min(100, errRate * 2)+'%';

  // Risk stat
  const riskEl = els.statRisk;
  if (riskEl) {
    riskEl.textContent = toRiskLabel(risk);
    riskEl.className = `stat-num stat-risk risk-${risk}`;
  }
  if (els.riskIconWrap) {
    els.riskIconWrap.className = `stat-icon stat-icon--${risk === 'high' ? 'red' : risk === 'medium' ? 'blue' : 'green'}`;
  }
}

// ── Render: Alerts ────────────────────────────────────
function renderAlerts(alerts) {
  if (els.alertsBadge) els.alertsBadge.textContent = String(alerts.length);
  if (!els.alertsList) return;
  els.alertsList.innerHTML = '';
  if (!alerts.length) {
    els.alertsList.innerHTML = '<li class="alert-item">Alarm üretilmedi.</li>';
    return;
  }
  alerts.slice(0, 50).forEach(a => {
    const li = document.createElement('li');
    li.className = `alert-item ${a.severity || 'medium'}`;
    li.textContent = `[${String(a.severity||'medium').toUpperCase()}] ${a.reason}  ·  IP: ${a.ip || '-'}`;
    els.alertsList.appendChild(li);
  });
}

// ── Render: Correlation ───────────────────────────────
function renderCorrelation(correlations) {
  if (els.corrBadge) els.corrBadge.textContent = String(correlations.length);
  if (!els.correlationList) return;
  els.correlationList.innerHTML = '';
  if (!correlations.length) {
    els.correlationList.innerHTML = '<li class="scenario-item">Korelasyon senaryosu tespit edilmedi.</li>';
    return;
  }
  correlations.forEach(s => {
    const li = document.createElement('li');
    li.className = 'scenario-item';
    li.textContent = s;
    els.correlationList.appendChild(li);
  });
}

// ── Render: Anomaly Detection ─────────────────────────
function renderAnomalies(data) {
  const container = els.anomalyList;
  if (!container) return;
  container.innerHTML = '';
  const anomalies = data.anomalies || [];
  if (els.anomalyBadge) {
    els.anomalyBadge.textContent = anomalies.length > 0 ? `${anomalies.length} anomali` : 'Z-Score';
  }
  if (!anomalies.length) {
    container.innerHTML = '<p class="empty-state">Anormallik tespit edilmedi.</p>';
    return;
  }
  anomalies.forEach(a => {
    const div = document.createElement('div');
    div.className = 'anomaly-item';
    div.innerHTML = `
      <span class="anomaly-hour">Saat ${String(a.hour).padStart(2,'0')}:00</span>
      <span>${a.value} istek</span>
      <span class="anomaly-z">z=${a.z_score}</span>
    `;
    container.appendChild(div);
  });
}

// ── Render: IP Reputation ─────────────────────────────
function renderReputation(items) {
  const container = els.reputationList;
  if (!container) return;
  container.innerHTML = '';
  const malCount = items.filter(i => i.level === 'malicious').length;
  if (els.repBadge) els.repBadge.textContent = malCount > 0 ? `${malCount} zararlı` : `${items.length} IP`;
  if (!items.length) {
    container.innerHTML = '<p class="empty-state">IP verisi yok.</p>';
    return;
  }
  items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'rep-item';
    div.innerHTML = `
      <span class="rep-ip">${item.ip}</span>
      <span class="rep-score" style="color:${item.level==='malicious'?'var(--danger)':item.level==='suspicious'?'var(--warn)':'var(--ok)'}">Skor: ${item.score}</span>
      <span class="rep-badge ${item.level}">${item.level}</span>
    `;
    container.appendChild(div);
  });
}

// ── Charts (Chart.js) ─────────────────────────────────
const CHART_COLORS = {
  brand:    '#00d1b7',
  accent:   '#ffb347',
  danger:   '#ff5f5f',
  info:     '#67b8ff',
  grid:     'rgba(110,160,210,0.12)',
  text:     '#7a97b8',
};

function chartDefaults() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0d1f32', titleColor: '#e6efff', bodyColor: '#b5cadf', borderColor: 'rgba(110,160,210,0.3)', borderWidth: 1, cornerRadius: 8 } },
    scales: {
      x: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text, font: { size: 10 } } },
      y: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text, font: { size: 10 } } },
    },
  };
}

function drawTrafficChart(data) {
  const canvas = els.trafficChart;
  if (!canvas) return;
  const safeData = data.length ? data : new Array(24).fill(0);
  const labels   = safeData.map((_, i) => `${String(i).padStart(2,'0')}h`);
  const peakHour = safeData.indexOf(Math.max(...safeData));
  if (els.trafficBadge) els.trafficBadge.textContent = `Peak: ${String(peakHour).padStart(2,'0')}:00`;

  if (trafficChartInst) trafficChartInst.destroy();
  const ctx = canvas.getContext('2d');

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, 220);
  grad.addColorStop(0, 'rgba(0,209,183,0.35)');
  grad.addColorStop(1, 'rgba(0,209,183,0.0)');

  trafficChartInst = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: safeData,
        borderColor: CHART_COLORS.brand,
        backgroundColor: grad,
        borderWidth: 2.5,
        pointRadius: 3,
        pointHoverRadius: 6,
        pointBackgroundColor: CHART_COLORS.brand,
        tension: 0.4,
        fill: true,
      }],
    },
    options: { ...chartDefaults(), animation: { duration: 700, easing: 'easeOutQuart' } },
  });
}

function drawIpChart(topIps) {
  const canvas = els.ipChart;
  if (!canvas) return;
  const safe = topIps.length ? topIps.slice(0, 6) : [{ ip: 'no-data', count: 0 }];
  const labels = safe.map(r => shortIp(r.ip));
  const values = safe.map(r => r.count);
  if (els.ipBadge) els.ipBadge.textContent = `${safe.length} IP`;

  if (ipChartInst) ipChartInst.destroy();
  const ctx = canvas.getContext('2d');

  const colors = safe.map((_, i) => [
    CHART_COLORS.accent, CHART_COLORS.brand, CHART_COLORS.info,
    CHART_COLORS.danger, '#a78bfa', '#f472b6'
  ][i % 6]);

  ipChartInst = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor: colors,
        borderWidth: 1.5,
        borderRadius: 6,
        borderSkipped: false,
      }],
    },
    options: {
      ...chartDefaults(),
      animation: { duration: 700, easing: 'easeOutQuart' },
      scales: {
        x: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text, font: { size: 10 } } },
        y: { grid: { color: CHART_COLORS.grid }, ticks: { color: CHART_COLORS.text, font: { size: 10 }, stepSize: 1 }, beginAtZero: true },
      },
    },
  });
}

// ── Report ────────────────────────────────────────────
async function generateReport(reportType) {
  if (!latestAnalysis && !latestAnalysisId) {
    toast('Önce analiz çalıştırın.', 'warning');
    return;
  }
  try {
    const body = latestAnalysisId
      ? { report_type: reportType, analysis_id: latestAnalysisId }
      : { report_type: reportType, analysis: latestAnalysis };
    const res = await fetch(`${API_BASE}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const payload = await parseJsonResponse(res);
    if (!res.ok || !payload) throw new Error(resolveApiError(payload, `Rapor üretilemedi (HTTP ${res.status})`));
    els.reportOutput.value = payload.report || '';
    toast(`${reportType} raporu oluşturuldu.`, 'success');
  } catch (err) {
    toast(err.message || 'Rapor oluşturulurken hata oluştu.', 'error');
  }
}

function downloadReport() {
  const text = els.reportOutput?.value?.trim();
  if (!text) { toast('İndirmek için önce rapor üretin.', 'warning'); return; }
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: `log-report-${Date.now()}.txt` });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast('Rapor indirildi.', 'success');
}

// ── History ───────────────────────────────────────────
async function loadHistory() {
  const tbody = els.historyBody;
  if (!tbody) return;
  try {
    const res = await fetch(`${API_BASE}/api/analysis/history`);
    const payload = await parseJsonResponse(res);
    if (!res.ok || !payload) throw new Error('History yüklenemedi.');
    const items = payload.items || [];
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Henüz analiz kaydı yok.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map(item => `
      <tr>
        <td>${item.id}</td>
        <td>${formatDate(item.created_at)}</td>
        <td>${sourceLabel(item.source)}</td>
        <td>${item.total_logs.toLocaleString()}</td>
        <td>${item.total_alerts}</td>
        <td><span class="risk-badge ${item.risk}">${toRiskLabel(item.risk)}</span></td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Geçmiş yüklenemedi. Sunucu çalışıyor mu?</td></tr>';
  }
}

function formatDate(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    return d.toLocaleString('tr-TR', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
  } catch { return iso; }
}

function sourceLabel(s) {
  return { file_upload:'Dosya', api_ingest:'API', manual:'Manuel' }[s] || s;
}

// ── Clear All ─────────────────────────────────────────
function clearAll() {
  if (els.rawLogs)      els.rawLogs.value = '';
  if (els.apiInput)     els.apiInput.value = '';
  if (els.logFile)      els.logFile.value = '';
  if (els.fileName)     els.fileName.textContent = '-';
  if (els.fileNameBadge) els.fileNameBadge.hidden = true;
  if (els.reportOutput) els.reportOutput.value = '';
  if (els.alertsList)   els.alertsList.innerHTML = '';
  if (els.correlationList) els.correlationList.innerHTML = '';
  if (els.anomalyList)  els.anomalyList.innerHTML = '<p class="empty-state">Analiz çalıştırın.</p>';
  if (els.reputationList) els.reputationList.innerHTML = '<p class="empty-state">Analiz çalıştırın.</p>';

  latestAnalysis = null;
  latestAnalysisId = null;

  ['kpiTotal','kpiFailed'].forEach(id => { if (els[id]) els[id].textContent = '0'; });
  if (els.kpiError)  els.kpiError.textContent  = '0%';
  if (els.kpiTopIp)  els.kpiTopIp.textContent  = '-';
  if (els.statLogs)  els.statLogs.textContent  = '0';
  if (els.statAlerts) els.statAlerts.textContent = '0';
  if (els.statRisk) { els.statRisk.textContent = 'Düşük'; els.statRisk.className = 'stat-num stat-risk risk-low'; }
  if (els.alertsBadge) els.alertsBadge.textContent = '0';
  if (els.corrBadge)   els.corrBadge.textContent   = '0';

  ['kpiTotalBar','kpiFailedBar','kpiErrorBar'].forEach(id => { if (els[id]) els[id].style.width = '0%'; });

  if (trafficChartInst) { trafficChartInst.destroy(); trafficChartInst = null; }
  if (ipChartInst)      { ipChartInst.destroy();      ipChartInst = null; }

  toast('Tüm alanlar temizlendi.', 'info');
}

// ── Helpers ───────────────────────────────────────────
function toRiskLabel(v) {
  return { high: 'Yüksek', medium: 'Orta', low: 'Düşük' }[v] || 'Düşük';
}

function shortIp(ip) {
  if (!ip || !ip.includes('.')) return ip || '-';
  const parts = ip.split('.');
  return `${parts[0]}.${parts[1]}.*.*`;
}

function safeJsonParse(text) {
  try { return JSON.parse(text); } catch { return null; }
}

async function parseJsonResponse(response) {
  const raw = await response.text().catch(() => '');
  if (!raw?.trim()) return null;
  return safeJsonParse(raw);
}

function resolveApiError(payload, fallback) {
  if (typeof payload?.error === 'string' && payload.error.trim()) return payload.error;
  if (typeof payload?.message === 'string' && payload.message.trim()) return payload.message;
  return fallback;
}

function resolveApiBase() {
  const { protocol, hostname, port } = window.location;
  if (protocol === 'file:') return 'http://127.0.0.1:5000';
  if ((hostname === '127.0.0.1' || hostname === 'localhost') && port && port !== '5000') return 'http://127.0.0.1:5000';
  return '';
}

function friendlyHttpError(status, fallback) {
  if (status === 405) return 'HTTP 405: Yanlış sunucuya istek gidiyor. Flask backendi 5000 portunda çalıştırın.';
  if (status === 429) return 'Rate limit aşıldı. Lütfen biraz bekleyin.';
  return fallback;
}

function q(selector) { return document.querySelector(selector); }

// ── CountUp Animation ─────────────────────────────────
function countUp(el, target, decimals = 0) {
  if (!el) return;
  const start    = 0;
  const duration = 800;
  const startTs  = performance.now();
  function step(ts) {
    const progress = Math.min((ts - startTs) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const value    = start + (target - start) * eased;
    el.textContent = decimals ? value.toFixed(decimals) : Math.round(value).toLocaleString();
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = decimals ? target.toFixed(decimals) : target.toLocaleString();
  }
  requestAnimationFrame(step);
}

// ── Toast Notification ────────────────────────────────
const TOAST_ICONS = {
  success: '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 6l3 3 5-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warning: '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M6 1l-5 9h10L6 1z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M6 5v2M6 8.5v.01" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
  error:   '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M9 3l-6 6M3 3l6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  info:    '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.4"/><path d="M6 5v4M6 3.5v.01" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
};

function toast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span class="toast-icon">${TOAST_ICONS[type] || TOAST_ICONS.info}</span><span>${message}</span>`;
  container.appendChild(el);

  const remove = () => {
    el.classList.add('toast-exit');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  };

  const timer = setTimeout(remove, duration);
  el.addEventListener('click', () => { clearTimeout(timer); remove(); });
}

// Keep info() as alias for backward compatibility
function info(msg) { toast(msg, 'info'); }

// ── Reveal on Scroll ──────────────────────────────────
function bootRevealAnimation() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
  }, { threshold: 0.08 });
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

// ── Active Nav Highlight ──────────────────────────────
function initActiveNavHighlight() {
  const sections = document.querySelectorAll('main section[id]');
  const links    = document.querySelectorAll('.nav-link');
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === `#${e.target.id}`));
      }
    });
  }, { threshold: 0.3 });
  sections.forEach(s => observer.observe(s));
}

// ── Background Particle Canvas ────────────────────────
function initBgCanvas() {
  const canvas = document.getElementById('bgCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', debounce(resize, 200));

  const particles = Array.from({ length: 40 }, () => ({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    r: Math.random() * 1.5 + 0.5,
    vx: (Math.random() - 0.5) * 0.25,
    vy: (Math.random() - 0.5) * 0.25,
    alpha: Math.random() * 0.5 + 0.1,
  }));

  function frame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = canvas.width;
      if (p.x > canvas.width) p.x = 0;
      if (p.y < 0) p.y = canvas.height;
      if (p.y > canvas.height) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,209,183,${p.alpha})`;
      ctx.fill();
    });
    requestAnimationFrame(frame);
  }
  frame();
}

// ── Debounce ──────────────────────────────────────────
function debounce(fn, delay) {
  let t = null;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), delay); };
}
