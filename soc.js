'use strict';
/* SOC Workspace v5 — safe text rendering and authenticated requests; no localStorage. */
const $ = (s) => document.querySelector(s);
let apiKey = '';
let workspaceRevision = 0;

let demoMode = false;
// All data below is synthetic and is only used to preview the user interface.
// No real logs or secrets are downloaded, uploaded, stored, or represented as live.
const demoRules = [
  ["AUTH-001", "Possible brute force", "high", "T1110"],
  ["AUTH-002", "Possible password spraying", "high", "T1110.003"],
  ["AUTH-003", "Login after repeated failures", "high", "T1078"],
  ["WEB-001", "Web attack indicator", "high", "T1190"],
  ["WEB-002", "High volume web requests", "medium", "T1595"],
  ["NET-001", "Possible port scanning", "medium", "T1046"],
  ["WIN-001", "Windows audit log cleared", "critical", "T1070.001"],
  ["IDS-001", "IDS rule alert", "medium", null],
  ["PROC-001", "Encoded PowerShell command indicator", "high", "T1059.001"],
  ["WIN-002", "Windows user account created", "medium", "T1136.001"],
  ["WIN-003", "Windows scheduled task created", "medium", "T1053.005"],
].map(([id, name, severity, mitre]) => ({ id, name, severity, mitre }));
const demoEvents = Array.from({ length: 18 }, (_, index) => {
  const timestamp = new Date(Date.UTC(2026, 9, 31, 9, 0, index * 12)).toISOString();
  const source = index < 12 ? "windows" : index < 15 ? "web" : "suricata";
  const action = source === "windows" ? "login" : source === "web" ? "GET /admin" : "alert";
  return {
    event_id: "example-" + String(index + 1).padStart(3, "0"),
    timestamp, source, ip: "192.0.2.25",
    user: source === "windows" ? (index % 3 === 0 ? "analyst" : "admin") : null,
    host: "example-lab-01",
    action, outcome: index < 12 ? "failure" : "unknown",
    status: source === "web" ? 403 : null,
    raw: '[SYNTHETIC DEMO] ' + source + ' ' + action + ' event ' + (index + 1),
    tags: index >= 15 ? ["ids_alert"] : [],
  };
});
const demoCases = [
  {
    id: 1001, rule_id: "AUTH-001", severity: "high",
    status: "investigating", ip: "192.0.2.25",
    reason: "12 failed logins in a five-minute synthetic test window.",
    notes: "Synthetic training case; not a real incident.",
    created_at: "2026-10-31T09:04:00Z",
    evidence_json: JSON.stringify(demoEvents.slice(0, 12).map(e => e.event_id)),
  },
  {
    id: 1002, rule_id: "IDS-001", severity: "medium",
    status: "new", ip: "192.0.2.25",
    reason: "Synthetic Suricata IDS alert for investigation practice.",
    notes: "", created_at: "2026-10-31T09:05:00Z",
    evidence_json: JSON.stringify(demoEvents.slice(15).map(e => e.event_id)),
  },
];
async function demoAPI(path, opts = {}) {
  if (opts.method && opts.method !== "GET") {
    throw new Error("Örnek SOC görünümü salt okunurdur. Gerçek işlem için özel API bağlantısı gerekir.");
  }
  const [endpoint, query] = path.split("?");
  const p = new URLSearchParams(query || "");
  if (endpoint === "intelligence") return {total:18, missing_time:0, missing_ip:0, unparsed:0, severities:{high:1,medium:1}, timeline:[{hour:'2026-10-31T09',events:18}],
    ips:[{ip:'192.0.2.25',scope:'documentation',events:18,alerts:2,reputation:'unknown'}]};
  if (endpoint === "summary") return {
    batches: 1, events: demoEvents.length, alerts: 2,
    cases: { new: 1, investigating: 1 },
    sources: { windows: 12, web: 3, suricata: 3 },
    recent: [{ created_at: "2026-10-31T09:05:00Z", risk: "high", event_count: 18, alert_count: 2 }],
  };
  if (endpoint === "source-health") return {items:[{source:'windows',events:12,missing_time:0,missing_ip:0,last_event:'2026-10-31T09:02:12Z',last_ingested:'2026-10-31T09:05:00Z'},{source:'web',events:3,missing_time:0,missing_ip:0,last_event:'2026-10-31T09:02:48Z',last_ingested:'2026-10-31T09:05:00Z'},{source:'suricata',events:3,missing_time:0,missing_ip:0,last_event:'2026-10-31T09:03:24Z',last_ingested:'2026-10-31T09:05:00Z'}]};
  if (endpoint === "watchlist") return {items:[{id:1,kind:'ip',value:'192.0.2.25',label:'Sentetik inceleme IP',matches:18,last_seen:'2026-10-31T09:03:24Z'}]};
  if (endpoint === "events") {
    const all=demoEvents.filter(e=>['ip','source','user','host','outcome','action'].every(k=>!p.get(k)||e[k]===p.get(k))&&(!p.get('q')||JSON.stringify(e).toLowerCase().includes(p.get('q').toLowerCase()))&&(!p.get('start')||(e.timestamp&&Date.parse(e.timestamp)>=Date.parse(p.get('start'))))&&(!p.get('end')||(e.timestamp&&Date.parse(e.timestamp)<=Date.parse(p.get('end')))));
    const offset=Number(p.get('offset')||0),limit=Number(p.get('limit')||100);return {items:all.slice(offset,offset+limit),total:all.length,offset,limit,has_more:offset+limit<all.length};
  }
  if (endpoint === "cases") return {
    items: demoCases.filter(c => !p.get("status") || c.status === p.get("status")),
  };
  if (endpoint === "rules") return { rules: demoRules };
  if (endpoint === "audit") return {
    items: [{ at: "2026-10-31T09:05:00Z", action: "synthetic_demo_loaded",
              subject: "18 local example records; no real data" }],
  };
  const timeline = endpoint.match(/^cases\/(\d+)\/timeline$/);
  if (timeline) {
    const c = demoCases.find(x => x.id === Number(timeline[1]));
    if (!c) throw new Error("Örnek vaka bulunamadı.");
    const ids = new Set(JSON.parse(c.evidence_json));
    return { case_id: c.id, items: demoEvents.filter(e => ids.has(e.event_id)) };
  }
  const explain = endpoint.match(/^cases\/(\d+)\/explain$/);
  if (explain) {
    const c = demoCases.find(x => x.id === Number(explain[1]));
    if (!c) throw new Error("Örnek vaka bulunamadı.");
    return {
      type: "synthetic_explanation", ai_generated: false,
      headline: c.rule_id + " / " + c.severity,
      summary: c.reason,
      mitre: demoRules.find(r => r.id === c.rule_id)?.mitre || null,
      next_steps: ["Kaynak zamanlarını doğrula", "İlişkili hesap ve sunucu kayıtlarını karşılaştır",
                   "Analist notuyla sonucu belgele"],
      warning: "EĞİTİM AMAÇLI SENTETİK ÖRNEK; gerçek güvenlik olayı veya AI çıktısı değildir.",
    };
  }
  throw new Error("Örnek modunda desteklenmeyen işlem.");
}

const statuses = {new:'Yeni', investigating:'İnceleniyor', resolved:'Çözüldü', false_positive:'Yanlış pozitif'};
const put = (el, value) => { el.textContent = value == null ? '—' : String(value); };
const element = (tag, className, value) => {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (value !== undefined) put(el, value);
  return el;
};
function message(text, error=false) {
  const box = $('#message'); put(box,text); box.classList.toggle('error',error);
}
async function api(path, opts={}) {
  const revision = workspaceRevision;
  if (demoMode) return demoAPI(path, opts);
  const headers = {...(opts.headers || {}), 'X-API-Key':apiKey};
  if (opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/soc/' + path, {...opts, headers, cache:'no-store'});
  const data = await response.json().catch(() => ({error:'Beklenmeyen sunucu yanıtı'}));
  if(revision!==workspaceRevision)throw new Error('Bağlantı değişti; eski yanıt kullanılmadı.');
  if (!response.ok) throw new Error(data.error || 'HTTP ' + response.status);
  return data;
}
function renderSources(sources) {
  const root = $('#sources'); root.replaceChildren();
  const entries = Object.entries(sources).sort((a,b)=>b[1]-a[1]);
  if (!entries.length){put(root,'Henüz veri bulunmuyor.');return;}
  const max = Math.max(...entries.map(x=>x[1]),1);
  for (const [name,count] of entries){
    const row = element('div','source-row');
    row.append(element('span','',name));
    const track = element('div','bar');const fill=element('i');
    fill.style.width=(100*count/max)+'%';track.append(fill);
    row.append(track,element('strong','',count));root.append(row);
  }
}
function renderRecent(items) {
  const root=$('#recent');root.replaceChildren();
  if(!items.length){put(root,'Henüz analiz bulunmuyor.');return;}
  for(const item of items){
    const row=element('div','activity-row');
    const left=element('div');left.append(element('strong','',item.event_count+' olay · '+item.alert_count+' alarm'),element('small','',item.created_at));
    row.append(left,element('b','risk '+item.risk,item.risk.toUpperCase()));root.append(row);
  }
}
async function refreshSummary(){
  const r=await api('summary');
  put($('#sEvents'),r.events.toLocaleString('tr-TR'));put($('#sAlerts'),r.alerts.toLocaleString('tr-TR'));
  put($('#sBatches'),r.batches.toLocaleString('tr-TR'));
  put($('#sCases'),(r.cases.new||0)+(r.cases.investigating||0));
  renderSources(r.sources);renderRecent(r.recent);
}
function renderEvents(items){
  const body=$('#eventsBody');body.replaceChildren();
  if(!items.length){const tr=body.insertRow();const c=tr.insertCell();c.colSpan=6;put(c,'Kriterlerle eşleşen olay bulunamadı.');return;}
  for(const e of items){
    const tr=body.insertRow();
    for(const val of [e.timestamp||'Bilinmiyor',e.source,e.ip||'—',e.action||'—',e.outcome])put(tr.insertCell(),val);
    const btn=element('button','','Kanıt');
    btn.addEventListener('click',()=>{
      const pre=$('#evidence');pre.hidden=false;
      put(pre,JSON.stringify(e,null,2));pre.scrollIntoView({behavior:'smooth',block:'nearest'});
    });
    tr.insertCell().append(btn);
  }
}
let eventOffset=0, eventPageItems=[], eventPageFilters={};
function eventFilters() {
  const fields={ip:$('#fIp').value.trim(),source:$('#fSource').value,q:$('#fQuery').value.trim(),user:$('#fUser').value.trim(),host:$('#fHost').value.trim(),outcome:$('#fOutcome').value,action:$('#fAction').value.trim()};
  for(const [key,id] of [['start','#fStart'],['end','#fEnd']]) if($(id).value)fields[key]=new Date($(id).value).toISOString();
  return fields;
}
function renderEventPage(data, filters={}) {
  eventPageFilters={...filters};
  eventOffset=data.offset||0;eventPageItems=data.items;renderEvents(data.items);
  put($('#eventCount'),data.items.length ? `${eventOffset+1}–${eventOffset+data.items.length} / ${data.total??data.items.length} olay` : 'Eşleşen olay yok.');
  $('#prevEvents').disabled=eventOffset===0;$('#nextEvents').disabled=!data.has_more;$('#exportEvents').disabled=!data.items.length;
}
async function refreshEvents(filter=false, offset=0, filters=null){
  const q=new URLSearchParams({limit:'100',offset:String(offset)});
  const active=filters || (filter?eventFilters():{});
  for(const [k,v] of Object.entries(active))if(v)q.set(k,v);
  renderEventPage(await api('events?'+q.toString()),active);
}
function renderCases(items){
  const root=$('#cases');root.replaceChildren();
  if(!items.length){root.append(element('p','muted','Bu filtrede açık vaka bulunmuyor.'));return;}
  for(const c of items){
    const wrap=element('article','case');
    const info=element('div');
    info.append(element('span','severity '+c.severity,c.severity.toUpperCase()+' · '+c.rule_id),
      element('strong','','#'+c.id+' · '+c.reason),
      element('small','','IP: '+(c.ip||'bilinmiyor')+' · '+c.created_at));
    const select=element('select');
    select.setAttribute('aria-label','#'+c.id+' vaka durumu');
    for(const [value,label] of Object.entries(statuses)){
      const o=element('option','',label);o.value=value;o.selected=value===c.status;select.append(o);
    }
    select.disabled = demoMode;
    const notes=element('input');notes.value=c.notes||'';
    notes.disabled = demoMode;notes.placeholder='Analist notları';
    notes.maxLength=4000;notes.setAttribute('aria-label','#'+c.id+' analist notları');
    const actions=element('div','case-actions');
    const save=element('button','smallbutton','Kaydet');
    save.disabled = demoMode;
    save.addEventListener('click',async()=>{
      save.disabled=true;
      try{await api('cases/'+c.id,{method:'PATCH',body:JSON.stringify({status:select.value,notes:notes.value})});
        message('#'+c.id+' vaka kaydedildi.');await Promise.all([refreshCases(),refreshSummary(),refreshAudit()]);}
      catch(e){message(e.message,true);}finally{save.disabled=false;}
    });
    const evidence=element('button','smallbutton','Zaman çizelgesi');
    evidence.addEventListener('click',async()=>{
      try{const r=await api('cases/'+c.id+'/timeline');const pre=$('#caseEvidence');pre.hidden=false;
        put(pre,JSON.stringify(r,null,2));pre.scrollIntoView({behavior:'smooth',block:'nearest'});}
      catch(e){message(e.message,true);}
    });
    const explain=element('button','smallbutton','Yorum');
    explain.addEventListener('click',async()=>{
      try{const r=await api('cases/'+c.id+'/explain');const pre=$('#caseEvidence');pre.hidden=false;
        put(pre,JSON.stringify(r,null,2));pre.scrollIntoView({behavior:'smooth',block:'nearest'});}
      catch(e){message(e.message,true);}
    });
    actions.append(save,evidence,explain);
    wrap.append(info,select,notes,actions);root.append(wrap);
  }
}
async function refreshCases(){
  const state=$('#caseStatus').value;
  const data=await api('cases'+(state?'?status='+encodeURIComponent(state):''));
  renderCases(data.items);
}
function renderRules(items){
  const root=$('#rulesList');root.replaceChildren();
  for(const r of items){
    const article=element('article','rule');
    article.append(element('span','',r.id+' · '+r.severity.toUpperCase()),element('strong','',r.name),
      element('small','','MITRE ATT&CK: '+(r.mitre||'Eşleme yok')));
    root.append(article);
  }
}
function renderAudit(items) {
  const root = $('#auditList');
  root.replaceChildren();
  if (!items.length) {
    put(root, 'İşlem kaydı henüz bulunmuyor.');
    return;
  }
  for (const item of items) {
    const row = element('div', 'audit-item');
    row.append(
      element('strong', '', item.action + ' · ' + item.subject),
      element('span', '', item.at)
    );
    root.append(row);
  }
}
async function refreshAudit() {
  const data = await api('audit');
  renderAudit(data.items);
}

async function refreshAll(){
  const revision = workspaceRevision;
  clearEventFilters();
  try{
    const [summary, events, cases, rules, audit, intelligence, watchlist, health]=await Promise.all([
      api('summary'),api('events?limit=100'),api('cases'),api('rules'),api('audit'),api('intelligence'),api('watchlist'),api('source-health')
    ]);
    if(revision!==workspaceRevision)return;
    put($('#sEvents'),summary.events.toLocaleString('tr-TR'));
    put($('#sAlerts'),summary.alerts.toLocaleString('tr-TR'));
    put($('#sBatches'),summary.batches.toLocaleString('tr-TR'));
    put($('#sCases'),(summary.cases.new||0)+(summary.cases.investigating||0));
    renderSources(summary.sources);renderRecent(summary.recent);
    renderIntelligence(intelligence);
    renderEventPage(events);renderCases(cases.items);renderRules(rules.rules);renderAudit(audit.items);
    renderWatchlist(watchlist);renderHealth(health);
    const status=$('#connection');put(status,demoMode ? '● Örnek veriler' : '● Güvenli bağlantı');status.classList.add('online');
    message(demoMode ? 'ÖRNEK MODU: 18 sentetik log, iki örnek alarm; hiçbir gerçek olay sunucuya yüklenmez. Gerçek analiz için Render API anahtarıyla bağlanın.' : 'Bağlantı hazır. Analizler özel SOC veritabanına kaydedilir; yalnızca izinli verileri yükleyin.');
  }catch(error){
    if(revision!==workspaceRevision)return;
    $('#connection').classList.remove('online');put($('#connection'),'● Bağlı değil');
    message(error.message,true);
  }
}
$('#demoWorkspace').addEventListener('click',async()=>{
  workspaceRevision++;clearWorkspace();
  demoMode = true;
  apiKey = '';
  await refreshAll();
});
$('#connect').addEventListener('click',async()=>{
  workspaceRevision++;clearWorkspace();
  demoMode = false;
  apiKey=$('#apiKey').value.trim();$('#apiKey').value='';
  if(!apiKey){message('API anahtarı gerekli.',true);return;}
  await refreshAll();
});
$('#analyze').addEventListener('click',async()=>{
  if (demoMode) { message('Örnek mod salt okunurdur. Gerçek log analizi için önce API anahtarıyla bağlanın veya ana sayfadaki halka açık analiz aracını kullanın.',true); return; }
  const button=$('#analyze');button.disabled=true;
  try{
    const f=$('#file').files[0];
    let body;
    if(f){
      if(f.size>5*1024*1024)throw new Error('Dosya 5 MB sınırını aşıyor.');
      body=new FormData();body.append('file',f);
    }else{
      const raw=$('#raw').value;if(!raw.trim())throw new Error('Log girin veya dosya seçin.');
      body=JSON.stringify({raw_logs:raw});
    }
    const r=await api('ingest',{method:'POST',body});
    const result=$('#ingestResult');result.hidden=false;
    put(result,JSON.stringify(r,null,2));
    message(r.duplicate?'Dosya daha önce analiz edilmiş; tekrarlı kayıt oluşturulmadı.':
      'İçe alma tamamlandı: '+r.events+' olay, '+r.alert_count+' alarm.');
    await refreshAll();
  }catch(e){message(e.message,true);}finally{button.disabled=false;}
});
$('#demo').addEventListener('click',()=>{
  const records=[];
  for(let i=0;i<12;i++) records.push({
    timestamp:new Date(Date.UTC(2026,9,31,9,0,i*15)).toISOString(),
    EventID:4625,ip:'192.0.2.25',user:i%3===0?'analyst':'admin',host:'lab-server'
  });
  records.push({timestamp:'2026-10-31T09:04:00Z',EventID:4624,ip:'192.0.2.25',user:'admin',host:'lab-server'});
  records.push({timestamp:'2026-10-31T09:05:00Z',EventID:1102,ip:'192.0.2.25',host:'lab-server'});
  records.push({timestamp:'2026-10-31T09:06:00Z',EventID:4720,ip:'192.0.2.25',user:'new-lab-user',host:'lab-server'});
  records.push({timestamp:'2026-10-31T09:07:00Z',EventID:4698,ip:'192.0.2.25',user:'admin',host:'lab-server'});
  records.push({timestamp:'2026-10-31T09:08:00Z',EventID:1,provider:'Microsoft-Windows-Sysmon',CommandLine:'powershell.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA==',user:'analyst',host:'lab-endpoint'});
  records.push({eventTime:'2026-10-31T09:09:00Z',eventSource:'signin.amazonaws.com',eventName:'ConsoleLogin',sourceIPAddress:'198.51.100.20',userIdentity:{userName:'cloud-lab-user'},responseElements:{ConsoleLogin:'Failure'}});
  $('#raw').value=records.map(r=>JSON.stringify(r)).join('\n');
  $('#file').value='';
  message('Örnek olaylar hazır. API anahtarıyla bağlanıp Analiz başlat seçeneğine basın.');
});
function bindButton(id, fn){
  $(id).addEventListener('click',async()=>{
    try{await fn();}catch(e){message(e.message,true);}
  });
}
bindButton('#search',()=>refreshEvents(true));
bindButton('#reloadEvents',()=>refreshEvents(true));
bindButton('#reloadCases',refreshCases);
bindButton('#reloadAudit',refreshAudit);
$('#caseStatus').addEventListener('change',async()=>{
  try{await refreshCases();}catch(e){message(e.message,true);}
});
document.querySelectorAll('.navitem').forEach(a=>a.addEventListener('click',()=>{
  document.querySelectorAll('.navitem').forEach(x=>x.classList.remove('active'));a.classList.add('active');
}));

function renderIntelligence(data) {
  renderInvestigationInsights(data);
  put($('#intelMode'), demoMode ? 'SENTETİK ÖRNEK' : 'KAYITLI VERİ');
  const quality = $('#quality'); quality.replaceChildren();
  for (const [label, count] of [['Toplam olay',data.total],['Zamanı eksik',data.missing_time],['IP eksik',data.missing_ip],['Ayrıştırılamayan',data.unparsed]]) {
    const card = element('article','quality-card');
    card.append(element('strong','',count.toLocaleString('tr-TR')),element('small','',label));quality.append(card);
  }
  const body = $('#ipBody');body.replaceChildren();
  const scopes = {documentation:'Dokümantasyon',private:'Özel ağ',public:'Genel internet',loopback:'Loopback',link_local:'Yerel bağlantı',multicast:'Multicast',reserved:'Ayrılmış',unspecified:'Belirtilmemiş'};
  if (!data.ips.length) {const cell=body.insertRow().insertCell();cell.colSpan=6;put(cell,'IP içeren olay bulunmuyor.');}
  for (const ip of data.ips) {
    const row=body.insertRow();
    for (const value of [ip.ip,scopes[ip.scope]||ip.scope,ip.events,ip.alerts,'Bilinmiyor']) put(row.insertCell(),value);
    const button=element('button','smallbutton','Kayıtları aç');button.addEventListener('click',async()=>{
      $('#fIp').value=ip.ip;$('#fSource').value='';$('#fQuery').value='';
      try {await refreshEvents(true);$('#explorer').scrollIntoView({behavior:'smooth'});}catch(e){message(e.message,true);}
    });row.insertCell().append(button);
  }
}

// Static geographic reference points. No event counts or reputation are inferred.
const atlasPlaces = [
  ['tr','Türkiye','İstanbul','Avrupa / Asya',28.98,41.01,'Kimlik, VPN ve sınır ağ kayıtlarını aynı zaman çizelgesinde inceleyin.'],
  ['de','Almanya','Frankfurt','Avrupa',8.68,50.11,'Web erişimi, DNS çözümleme ve TLS oturumlarını kaynak IP üzerinden ilişkilendirin.'],
  ['gb','Birleşik Krallık','Londra','Avrupa',-.13,51.51,'Bulut kontrol düzlemi ve kullanıcı oturumlarında kimlik değişikliklerini araştırın.'],
  ['nl','Hollanda','Amsterdam','Avrupa',4.90,52.37,'Ağ akışları, hedef portlar ve izin/engelleme kararlarını birlikte değerlendirin.'],
  ['fr','Fransa','Paris','Avrupa',2.35,48.86,'WAF alarmlarını HTTP yanıtı ve uygulama loglarıyla doğrulayın.'],
  ['us','ABD','Ashburn','Amerika',-77.49,39.04,'CloudTrail benzeri denetim izlerinde API çağrısı, kimlik ve kaynak değişimini inceleyin.'],
  ['ca','Kanada','Toronto','Amerika',-79.38,43.65,'VPN oturumlarını hesap, cihaz ve zaman bağlamında karşılaştırın.'],
  ['br','Brezilya','São Paulo','Amerika',-46.63,-23.55,'Web ve kimlik doğrulama olaylarının ortak IP ve kullanıcılarını araştırın.'],
  ['jp','Japonya','Tokyo','Asya',139.69,35.68,'Endpoint süreçleri ile DNS ve dış ağ bağlantılarını ilişkilendirin.'],
  ['sg','Singapur','Singapur','Asya',103.82,1.35,'Servis hesapları ve bulut yönetim işlemlerinde beklenmeyen değişiklikleri inceleyin.'],
  ['in','Hindistan','Mumbai','Asya',72.88,19.08,'Yüksek istek hacmini HTTP sonuçları, kullanıcı ve zaman penceresiyle değerlendirin.'],
  ['kr','Güney Kore','Seul','Asya',126.98,37.57,'EDR, Sysmon ve oturum kayıtlarında süreç başlangıçlarını karşılaştırın.'],
  ['au','Avustralya','Sidney','Okyanusya',151.21,-33.87,'Kaynak zaman dilimi ve UTC normalizasyonunu kontrol edin.'],
].map(([id,country,city,region,lon,lat,guide])=>({id,country,city,region,lon,lat,guide}));
function renderInvestigationInsights(data) {
  const trend=$('#eventTrend');trend.replaceChildren();
  const timeline=data.timeline||[],max=Math.max(1,...timeline.map(x=>x.events));
  if(!timeline.length)trend.append(element('p','muted','Zaman bilgisi olan olay bulunmuyor.'));
  else {
    const bars=element('div','trend-bars');
    for(const point of timeline){
      const bar=element('div','trend-column'),fill=element('div','trend-fill');fill.style.height=Math.max(3,point.events/max*90)+'px';
      bar.title=point.hour+':00 UTC · '+point.events+' olay';
      bar.tabIndex=0;bar.setAttribute('aria-label',bar.title);
      bar.append(element('small','',point.events),fill,element('small','',point.hour.slice(11)+':00'));bars.append(bar);
    }
    trend.append(bars,element('p','disclaimer','Son 24 dolu saat dilimi · UTC · Boş saatler gösterilmez.'));
  }
  const severity=$('#severityBreakdown');severity.replaceChildren();
  const labels={critical:'Kritik',high:'Yüksek',medium:'Orta',low:'Düşük'},counts=data.severities||{};
  const total=Object.values(counts).reduce((a,b)=>a+b,0);
  for(const [name,label] of Object.entries(labels)){
    const row=element('div','severity-row');row.append(element('span','severity '+name,label),element('strong','',counts[name]||0));severity.append(row);
  }
  severity.append(element('p','disclaimer',total+' kayıtlı alarm · Çözülen vakalar dahil.'));
  const guide=$('#investigationGuide');guide.replaceChildren();
  const steps=[];
  if(!data.total)steps.push('Log yükleyerek kaynak görünürlüğünü ve zaman dağılımını ölçün.');
  if(data.missing_time)steps.push(data.missing_time+' olayın zamanı eksik. UTC ve kaynak saat dilimini doğrulayın.');
  if(data.unparsed)steps.push(data.unparsed+' kayıt ayrıştırılamadı. Üretici formatını ve parser kapsamını kontrol edin.');
  if((counts.critical||0)+(counts.high||0)>0)steps.push('Kritik ve yüksek alarmların ham kanıtını Incident Center üzerinden inceleyin.');
  if(data.missing_ip)steps.push(data.missing_ip+' olay IP içermiyor. Host ve kullanıcı üzerinden inceleme gerekebilir.');
  if(data.total&&!data.missing_time&&!data.unparsed)steps.push('Zaman ve kaynak alanları mevcut. Kullanıcı, host ve IP bağlamıyla bulguları doğrulayın.');
  steps.push('Coğrafi referans noktaları olay konumu veya zararlılık göstergesi değildir.');
  for(const [i,text] of steps.entries()){const row=element('div','guide-step');row.append(element('span','',String(i+1).padStart(2,'0')),element('p','',text));guide.append(row);}
}

function clearEventFilters(){for(const id of ['fIp','fSource','fQuery','fUser','fHost','fOutcome','fAction','fStart','fEnd'])$('#'+id).value='';}
const huntPacks=[
  {title:'Başarısız kimlik doğrulama',mitre:'T1110',fields:{action:'login',outcome:'failure'},text:'IP, kullanıcı ve zaman aralığını daraltın. Tek başarısız oturum saldırı kanıtı değildir.'},
  {title:'PowerShell komutları',mitre:'T1059.001',fields:{q:'powershell'},text:'Komut satırı, parent process ve kodlama bayraklarını ham kanıt üzerinde karşılaştırın.'},
  {title:'Yeni Windows hesapları',mitre:'T1136.001',fields:{source:'windows',action:'event_4720'},text:'Hesap açma olaylarını değişiklik onayı ve oluşturan kullanıcı bağlamında inceleyin.'},
  {title:'Zamanlanmış görevler',mitre:'T1053.005',fields:{source:'windows',action:'event_4698'},text:'Görev içeriğini ve çalıştırılan dosyayı inceleyin; meşru otomasyonu ayırın.'},
  {title:'Bulut kontrol düzlemi',mitre:'CLOUDTRAIL',fields:{source:'cloudtrail'},text:'AWS JSONL olaylarını kimlik, API aksiyonu, kaynak IP ve UTC zamanıyla araştırın.'},
  {title:'Görünürlük boşlukları',mitre:'DATA QUALITY',fields:{source:'unknown'},text:'Ayrıştırılamayan kayıtları bulun. Eksik parser desteği tespit kapsamını azaltır.'},
];
for(const pack of huntPacks){const card=element('article','hunt-card');card.append(element('span','fieldlabel',pack.mitre),element('h3','',pack.title),element('p','',pack.text));const b=element('button','button ghost','Sorguyu çalıştır →');b.addEventListener('click',async()=>{clearEventFilters();const ids={action:'fAction',outcome:'fOutcome',source:'fSource',q:'fQuery'};for(const [k,v] of Object.entries(pack.fields))$('#'+ids[k]).value=v;try{await refreshEvents(true);$('#explorer').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});}catch(e){message(e.message,true);}});card.append(b);$('#huntPacks').append(card);}
async function refreshWatchlist(){renderWatchlist(await api('watchlist'));}
function renderWatchlist(data){
  const body=$('#watchBody');body.replaceChildren();
  $('#watchAdd').disabled=demoMode;
  if(!data.items.length){const c=body.insertRow().insertCell();c.colSpan=5;put(c,'İzleme listesi boş. İncelenecek bir varlık ekleyin.');}
  for(const item of data.items){const row=body.insertRow();for(const value of [item.kind+' / '+item.value,item.label||'—',item.matches,item.last_seen||'Zaman bilinmiyor'])put(row.insertCell(),value);
    const actions=element('div','case-actions'),view=element('button','smallbutton','Olaylar');view.addEventListener('click',async()=>{clearEventFilters();$('#'+{ip:'fIp',user:'fUser',host:'fHost'}[item.kind]).value=item.value;try{await refreshEvents(true);$('#explorer').scrollIntoView({behavior:'smooth'});}catch(e){message(e.message,true);}});
    const remove=element('button','smallbutton','Listeden çıkar');remove.disabled=demoMode;remove.addEventListener('click',async()=>{remove.disabled=true;try{await api('watchlist/'+item.id,{method:'DELETE'});await Promise.all([refreshWatchlist(),refreshAudit()]);message('Varlık izleme listesinden çıkarıldı.');}catch(e){message(e.message,true);remove.disabled=false;}});actions.append(view,remove);row.insertCell().append(actions);
  }
}
$('#watchForm').addEventListener('submit',async e=>{e.preventDefault();if(demoMode){message('Örnek mod salt okunur. İzleme listesi için özel API bağlantısı gerekli.',true);return;}const button=$('#watchAdd');button.disabled=true;try{await api('watchlist',{method:'POST',body:JSON.stringify({kind:$('#watchKind').value,value:$('#watchValue').value.trim(),label:$('#watchLabel').value.trim()})});$('#watchValue').value='';$('#watchLabel').value='';await Promise.all([refreshWatchlist(),refreshAudit()]);message('Varlık izleme listesine eklendi; kayıtlı olay eşleşmeleri hesaplandı.');}catch(error){message(error.message,true);}finally{button.disabled=false;}});
async function refreshHealth(){renderHealth(await api('source-health'));}
function renderHealth(data){
  const root=$('#healthCards');root.replaceChildren();
  if(!data.items.length)root.append(element('p','muted','Kaynak görünürlüğü için önce log içe alın.'));
  for(const source of data.items){const card=element('article','health-card'),pct=source.events?Math.round(100*(source.events-source.missing_time)/source.events):0;
    card.append(element('span','tag',source.source==='unknown'?'PARSER GEREKLİ':'KAYITLI KAYNAK'),element('h3','',source.source),element('strong','',source.events.toLocaleString('tr-TR')+' olay'));
    const meter=element('div','bar'),fill=element('i');fill.style.width=pct+'%';meter.append(fill);card.append(meter,element('p','',`Zaman kapsaması %${pct} · IP eksik ${source.missing_ip}`),element('small','','Son kaynak olayı: '+(source.last_event||'Bilinmiyor')),element('small','','Son içe alma: '+source.last_ingested));
    const b=element('button','smallbutton','Kaynağı incele');b.addEventListener('click',async()=>{clearEventFilters();$('#fSource').value=source.source;try{await refreshEvents(true);$('#explorer').scrollIntoView({behavior:'smooth'});}catch(e){message(e.message,true);}});card.append(b);root.append(card);
  }
}
bindButton('#reloadWatchlist',refreshWatchlist);bindButton('#reloadHealth',refreshHealth);
bindButton('#clearFilters',async()=>{clearEventFilters();await refreshEvents(false);});
bindButton('#prevEvents',()=>refreshEvents(true,Math.max(0,eventOffset-100),eventPageFilters));
bindButton('#nextEvents',()=>refreshEvents(true,eventOffset+100,eventPageFilters));
$('#exportEvents').addEventListener('click',()=>{
  if(!eventPageItems.length)return;
  const payload={schema_version:'1.0',exported_at:new Date().toISOString(),synthetic:demoMode,filters:eventPageFilters,offset:eventOffset,count:eventPageItems.length,scope:'current_page_only',events:eventPageItems};
  const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'})),a=element('a');a.href=url;a.download='log-evidence-'+Date.now()+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});

function clearWorkspace(){
  clearEventFilters();$('#caseStatus').value='';
  for(const id of ['sEvents','sAlerts','sBatches','sCases'])put($('#'+id),'—');
  for(const id of ['sources','recent','quality','ipBody','cases','rulesList','auditList','watchBody','healthCards','eventTrend','severityBreakdown','investigationGuide'])$('#'+id).replaceChildren();
  for(const id of ['evidence','caseEvidence','ingestResult']){$('#'+id).hidden=true;put($('#'+id),'');}
  put($('#intelMode'),'Veri bekleniyor');put($('#connection'),'● Bağlı değil');$('#connection').classList.remove('online');
  $('#watchAdd').disabled=true;renderEventPage({items:[],total:0});
}
