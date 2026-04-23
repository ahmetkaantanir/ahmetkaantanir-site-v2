const API_BASE = resolveApiBase();
let latestAnalysis = null;
let latestAnalysisId = null;

const DATASET_MAP = {
  apache: 'apache.log',
  auth: 'auth.log',
  mixed: 'mixed.log'
};

const els = {
  menuToggle: document.getElementById('menuToggle'),
  navLinks: document.getElementById('navLinks'),
  rawLogs: document.getElementById('rawLogs'),
  logFile: document.getElementById('logFile'),
  pickFileBtn: document.getElementById('pickFileBtn'),
  fileName: document.getElementById('fileName'),
  uploadInfo: document.getElementById('uploadInfo'),
  apiInput: document.getElementById('apiInput'),
  appendApiData: document.getElementById('appendApiData'),
  runAnalysis: document.getElementById('runAnalysis'),
  clearLogs: document.getElementById('clearLogs'),
  alertsList: document.getElementById('alertsList'),
  correlationList: document.getElementById('correlationList'),
  kpiTotal: document.getElementById('kpiTotal'),
  kpiFailed: document.getElementById('kpiFailed'),
  kpiError: document.getElementById('kpiError'),
  kpiTopIp: document.getElementById('kpiTopIp'),
  statLogs: document.getElementById('statLogs'),
  statAlerts: document.getElementById('statAlerts'),
  statRisk: document.getElementById('statRisk'),
  reportOutput: document.getElementById('reportOutput'),
  generateDaily: document.getElementById('generateDaily'),
  generateWeekly: document.getElementById('generateWeekly'),
  downloadReport: document.getElementById('downloadReport'),
  trafficChart: document.getElementById('trafficChart'),
  ipChart: document.getElementById('ipChart')
};

bindEvents();
bootRevealAnimation();
bindResponsiveRedraw();

function bindEvents() {
  if (els.menuToggle) {
    els.menuToggle.addEventListener('click', () => {
      els.navLinks.classList.toggle('open');
    });
  }

  if (els.pickFileBtn && els.logFile) {
    els.pickFileBtn.addEventListener('click', () => {
      els.logFile.click();
    });
    els.logFile.addEventListener('change', () => {
      const file = els.logFile.files && els.logFile.files[0];
      els.fileName.textContent = file ? `${file.name} (${Math.ceil(file.size / 1024)} KB)` : 'Henüz bir dosya yüklenmedi';
    });
  }

  document.querySelectorAll('.nav-links a').forEach((link) => {
    link.addEventListener('click', () => {
      els.navLinks.classList.remove('open');
    });
  });

  document.querySelectorAll('.mobile-dock a').forEach((link) => {
    link.addEventListener('click', () => {
      els.navLinks.classList.remove('open');
    });
  });

  document.addEventListener('click', (event) => {
    if (!els.navLinks.classList.contains('open')) {
      return;
    }
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const insideNav = target.closest('.nav');
    if (!insideNav) {
      els.navLinks.classList.remove('open');
    }
  });

  document.querySelectorAll('[data-dataset]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const key = btn.getAttribute('data-dataset');
      const fileName = DATASET_MAP[key];
      if (!fileName) {
        info('Dataset tanimi yok.');
        return;
      }
      try {
        const res = await fetch(`${API_BASE}/api/datasets/${encodeURIComponent(fileName)}`);
        const payload = await parseJsonResponse(res);
        if (!payload) {
          if (!res.ok) {
            throw new Error(friendlyHttpError(res.status, `Dataset okunamadi (HTTP ${res.status})`));
          }
          throw new Error(`Sunucu gecerli JSON donmedi (HTTP ${res.status})`);
        }
        if (!res.ok) {
          throw new Error(resolveApiError(payload, friendlyHttpError(res.status, 'Dataset okunamadi')));
        }
        els.rawLogs.value = payload.content || '';
        info(`${payload.name} yuklendi.`);
      } catch {
        info('Dataset yuklenemedi. Sunucu calisiyor mu?');
      }
    });
  });

  els.appendApiData.addEventListener('click', appendApiPayload);
  els.runAnalysis.addEventListener('click', runAnalysis);
  els.clearLogs.addEventListener('click', clearAll);
  els.generateDaily.addEventListener('click', () => generateReport('Daily'));
  els.generateWeekly.addEventListener('click', () => generateReport('Weekly'));
  els.downloadReport.addEventListener('click', downloadReport);
}

function appendApiPayload() {
  const payload = els.apiInput.value.trim();
  if (!payload) {
    info('API simulasyon alani bos.');
    return;
  }

  const lines = payload.split('\n').map((line) => line.trim()).filter(Boolean);
  const invalid = lines.some((line) => !safeJsonParse(line));
  if (invalid) {
    info('Her satir gecerli JSON olmali.');
    return;
  }

  els.rawLogs.value = [els.rawLogs.value.trim(), ...lines].filter(Boolean).join('\n');
  els.apiInput.value = '';
  info(`${lines.length} API kaydi eklendi.`);
}

async function runAnalysis() {
  const hasFile = els.logFile.files && els.logFile.files.length > 0;
  const raw = els.rawLogs.value.trim();
  const apiLines = parseApiLines(raw);

  if (!hasFile && !raw) {
    info('Analiz icin dosya yukleyin veya log girin.');
    return;
  }

  try {
    let response;

    if (hasFile) {
      const fd = new FormData();
      fd.append('file', els.logFile.files[0]);
      response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        body: fd
      });
    } else {
      response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_logs: raw,
          api_lines: apiLines
        })
      });
    }

    const payload = await parseJsonResponse(response);
    if (!payload) {
      if (!response.ok) {
        throw new Error(friendlyHttpError(response.status, `Analiz istegi basarisiz (HTTP ${response.status})`));
      }
      throw new Error(`Sunucu gecerli JSON donmedi (HTTP ${response.status})`);
    }
    if (!response.ok) {
      throw new Error(resolveApiError(payload, friendlyHttpError(response.status, 'Analiz istegi basarisiz')));
    }

    latestAnalysis = payload.analysis;
    latestAnalysisId = payload.analysis_id;

    renderKpis(latestAnalysis);
    renderAlerts(latestAnalysis.alerts || []);
    renderCorrelation(latestAnalysis.correlations || []);
    drawTrafficChart(latestAnalysis.hourly_traffic || []);
    drawIpChart(latestAnalysis.top_ips || []);

    info(`Analiz tamamlandi. Risk: ${(latestAnalysis.risk || 'low').toUpperCase()}`);
  } catch (err) {
    info(err.message || 'Analiz sirasinda hata olustu.');
  }
}

function parseApiLines(rawText) {
  const lines = rawText.split('\n').map((line) => line.trim()).filter(Boolean);
  const parsed = [];
  lines.forEach((line) => {
    const obj = safeJsonParse(line);
    if (obj) {
      parsed.push(obj);
    }
  });
  return parsed;
}

function renderKpis(result) {
  els.kpiTotal.textContent = String(result.total || 0);
  els.kpiFailed.textContent = String(result.failed_login || 0);
  els.kpiError.textContent = `${Number(result.error_rate || 0).toFixed(2)}%`;
  els.kpiTopIp.textContent = result.top_ip || '-';

  els.statLogs.textContent = String(result.total || 0);
  els.statAlerts.textContent = String((result.alerts || []).length);
  els.statRisk.textContent = toRiskLabel(result.risk || 'low');
}

function renderAlerts(alerts) {
  els.alertsList.innerHTML = '';
  if (!alerts.length) {
    els.alertsList.innerHTML = '<li class="alert-item">Alarm uretilmedi.</li>';
    return;
  }

  alerts.slice(0, 40).forEach((alert) => {
    const li = document.createElement('li');
    li.className = `alert-item ${alert.severity || 'medium'}`;
    li.textContent = `[${String(alert.severity || 'medium').toUpperCase()}] ${alert.reason} | IP: ${alert.ip || '-'}`;
    els.alertsList.appendChild(li);
  });
}

function renderCorrelation(correlations) {
  els.correlationList.innerHTML = '';
  if (!correlations.length) {
    els.correlationList.innerHTML = '<li class="scenario-item">Korelasyon senaryosu tespit edilmedi.</li>';
    return;
  }

  correlations.forEach((scenario) => {
    const li = document.createElement('li');
    li.className = 'scenario-item';
    li.textContent = scenario;
    els.correlationList.appendChild(li);
  });
}

function drawTrafficChart(data) {
  const canvas = els.trafficChart;
  const metrics = fitCanvasToContainer(canvas, 230);
  const ctx = canvas.getContext('2d');
  clearCanvas(canvas);

  const safeData = data.length ? data : new Array(24).fill(0);
  const w = metrics.cssWidth;
  const h = metrics.cssHeight;
  const max = Math.max(...safeData, 1);

  ctx.strokeStyle = '#1f3f5c';
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i += 1) {
    const y = 20 + i * ((h - 40) / 4);
    ctx.beginPath();
    ctx.moveTo(30, y);
    ctx.lineTo(w - 12, y);
    ctx.stroke();
  }

  ctx.strokeStyle = '#00d1b7';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  safeData.forEach((val, i) => {
    const x = 30 + i * ((w - 50) / 23);
    const y = h - 20 - (val / max) * (h - 45);
    if (i === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();
}

function drawIpChart(topIps) {
  const canvas = els.ipChart;
  const metrics = fitCanvasToContainer(canvas, 230);
  const ctx = canvas.getContext('2d');
  clearCanvas(canvas);

  const safe = topIps.length ? topIps.slice(0, 5) : [{ ip: 'no-data', count: 1 }];
  const max = Math.max(...safe.map((x) => x.count), 1);
  const barW = 60;
  const gap = 26;
  const h = metrics.cssHeight;

  safe.forEach((row, idx) => {
    const x = 24 + idx * (barW + gap);
    const barH = (row.count / max) * 140;
    const y = h - 30 - barH;

    ctx.fillStyle = '#ffb347';
    ctx.fillRect(x, y, barW, barH);
    ctx.fillStyle = '#c4d9f3';
    ctx.font = '11px monospace';
    ctx.fillText(String(row.count), x + 20, y - 6);
    ctx.fillText(shortIp(row.ip), x, h - 12);
  });
}

async function generateReport(reportType) {
  if (!latestAnalysis && !latestAnalysisId) {
    els.reportOutput.value = 'Once analiz calistirin.';
    return;
  }

  try {
    const body = latestAnalysisId
      ? { report_type: reportType, analysis_id: latestAnalysisId }
      : { report_type: reportType, analysis: latestAnalysis };

    const res = await fetch(`${API_BASE}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const payload = await parseJsonResponse(res);
    if (!payload) {
      if (!res.ok) {
        throw new Error(friendlyHttpError(res.status, `Rapor uretilemedi (HTTP ${res.status})`));
      }
      throw new Error(`Sunucu gecerli JSON donmedi (HTTP ${res.status})`);
    }
    if (!res.ok) {
      throw new Error(resolveApiError(payload, friendlyHttpError(res.status, 'Rapor uretilemedi')));
    }
    els.reportOutput.value = payload.report || '';
    info(`${reportType} raporu olusturuldu.`);
  } catch (err) {
    info(err.message || 'Rapor olusturulurken hata olustu.');
  }
}

function downloadReport() {
  const text = els.reportOutput.value.trim();
  if (!text) {
    info('Indirme icin once rapor uretin.');
    return;
  }
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `akt-log-report-${Date.now()}.txt`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function clearAll() {
  els.rawLogs.value = '';
  els.apiInput.value = '';
  els.logFile.value = '';
  if (els.fileName) {
    els.fileName.textContent = 'Henüz bir dosya yüklenmedi';
  }
  els.reportOutput.value = '';
  els.alertsList.innerHTML = '';
  els.correlationList.innerHTML = '';
  latestAnalysis = null;
  latestAnalysisId = null;

  els.kpiTotal.textContent = '0';
  els.kpiFailed.textContent = '0';
  els.kpiError.textContent = '0%';
  els.kpiTopIp.textContent = '-';
  els.statLogs.textContent = '0';
  els.statAlerts.textContent = '0';
  els.statRisk.textContent = 'Dusuk';

  clearCanvas(els.trafficChart);
  clearCanvas(els.ipChart);
  info('Alanlar temizlendi.');
}

function toRiskLabel(value) {
  if (value === 'high') {
    return 'Yuksek';
  }
  if (value === 'medium') {
    return 'Orta';
  }
  return 'Dusuk';
}

function shortIp(ip) {
  if (!ip || !ip.includes('.')) {
    return ip || '-';
  }
  return `${ip.split('.').slice(0, 2).join('.')}..`;
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function parseJsonResponse(response) {
  const raw = await response.text();
  if (!raw || !raw.trim()) {
    return null;
  }
  return safeJsonParse(raw);
}

function resolveApiError(payload, fallbackMessage) {
  if (!payload || typeof payload !== 'object') {
    return fallbackMessage;
  }
  if (typeof payload.error === 'string' && payload.error.trim()) {
    return payload.error;
  }
  if (payload.error && typeof payload.error.message === 'string' && payload.error.message.trim()) {
    return payload.error.message;
  }
  if (typeof payload.message === 'string' && payload.message.trim()) {
    return payload.message;
  }
  return fallbackMessage;
}

function resolveApiBase() {
  const { protocol, hostname, port } = window.location;
  const isLocalHost = hostname === '127.0.0.1' || hostname === 'localhost';

  // If page runs from file:// or a local static server, target Flask API directly.
  if (protocol === 'file:') {
    return 'http://127.0.0.1:5000';
  }
  if (isLocalHost && port && port !== '5000') {
    return 'http://127.0.0.1:5000';
  }
  return '';
}

function friendlyHttpError(status, fallbackMessage) {
  if (status === 405) {
    return 'HTTP 405: API istegi yanlis sunucuya gidiyor. Flask backendi 127.0.0.1:5000 uzerinde calistirin.';
  }
  return fallbackMessage;
}

function clearCanvas(canvas) {
  if (!canvas) {
    return;
  }
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
}

function fitCanvasToContainer(canvas, preferredHeight) {
  if (!canvas) {
    return { cssWidth: 0, cssHeight: 0 };
  }
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const cssWidth = Math.max(220, Math.floor(rect.width || canvas.clientWidth || 320));
  const fluidHeight = Math.round(cssWidth * 0.56);
  const cssHeight = Math.max(170, Math.min(preferredHeight, fluidHeight));
  canvas.width = Math.floor(cssWidth * dpr);
  canvas.height = Math.floor(cssHeight * dpr);
  canvas.style.height = `${cssHeight}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { cssWidth, cssHeight };
}

function bindResponsiveRedraw() {
  const redraw = debounce(() => {
    if (!latestAnalysis) {
      return;
    }
    drawTrafficChart(latestAnalysis.hourly_traffic || []);
    drawIpChart(latestAnalysis.top_ips || []);
  }, 140);

  window.addEventListener('resize', redraw);
  window.addEventListener('orientationchange', redraw);
}

function debounce(fn, delay) {
  let timer = null;
  return (...args) => {
    if (timer) {
      window.clearTimeout(timer);
    }
    timer = window.setTimeout(() => fn(...args), delay);
  };
}

function info(message) {
  els.uploadInfo.textContent = message;
}

function bootRevealAnimation() {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
        }
      });
    },
    { threshold: 0.1 }
  );
  document.querySelectorAll('.reveal').forEach((el) => observer.observe(el));
}
