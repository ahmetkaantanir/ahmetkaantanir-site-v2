'use strict';
/* SOC Workspace v5 — safe text rendering and authenticated requests; no localStorage. */
const $ = (s) => document.querySelector(s);
let apiKey = '';
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
  const headers = {...(opts.headers || {}), 'X-API-Key':apiKey};
  if (opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/soc/' + path, {...opts, headers, cache:'no-store'});
  const data = await response.json().catch(() => ({error:'Beklenmeyen sunucu yanıtı'}));
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
async function refreshEvents(filter=false){
  const q=new URLSearchParams({limit:'150'});
  if(filter){
    const fields={ip:$('#fIp').value.trim(),source:$('#fSource').value,q:$('#fQuery').value.trim()};
    for(const [k,v] of Object.entries(fields))if(v)q.set(k,v);
  }
  const r=await api('events?'+q.toString());renderEvents(r.items);
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
    const notes=element('input');notes.value=c.notes||'';notes.placeholder='Analist notları';
    notes.maxLength=4000;notes.setAttribute('aria-label','#'+c.id+' analist notları');
    const actions=element('div','case-actions');
    const save=element('button','smallbutton','Kaydet');
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
async function refreshAudit(){
  const data=await api('audit');const root=$('#auditList');root.replaceChildren();
  if(!data.items.length){put(root,'İşlem kaydı henüz bulunmuyor.');return;}
  for(const item of data.items){
    const row=element('div','audit-item');row.append(element('strong','',item.action+' · '+item.subject),
      element('span','',item.at));root.append(row);
  }
}
async function refreshAll(){
  try{
    const [summary, events, cases, rules, audit]=await Promise.all([
      api('summary'),api('events?limit=150'),api('cases'),api('rules'),api('audit')
    ]);
    put($('#sEvents'),summary.events.toLocaleString('tr-TR'));
    put($('#sAlerts'),summary.alerts.toLocaleString('tr-TR'));
    put($('#sBatches'),summary.batches.toLocaleString('tr-TR'));
    put($('#sCases'),(summary.cases.new||0)+(summary.cases.investigating||0));
    renderSources(summary.sources);renderRecent(summary.recent);
    renderEvents(events.items);renderCases(cases.items);renderRules(rules.rules);renderAudit(audit.items);
    const status=$('#connection');put(status,'● Güvenli bağlantı');status.classList.add('online');
    message('Bağlantı hazır. Analizler özel SOC veritabanına kaydedilir; yalnızca izinli verileri yükleyin.');
  }catch(error){
    $('#connection').classList.remove('online');put($('#connection'),'● Bağlı değil');
    message(error.message,true);
  }
}
$('#connect').addEventListener('click',async()=>{
  apiKey=$('#apiKey').value.trim();$('#apiKey').value='';
  if(!apiKey){message('API anahtarı gerekli.',true);return;}
  await refreshAll();
});
$('#analyze').addEventListener('click',async()=>{
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
bindButton('#reloadEvents',()=>refreshEvents(false));
bindButton('#reloadCases',refreshCases);
bindButton('#reloadAudit',refreshAudit);
$('#caseStatus').addEventListener('change',async()=>{
  try{await refreshCases();}catch(e){message(e.message,true);}
});
document.querySelectorAll('.navitem').forEach(a=>a.addEventListener('click',()=>{
  document.querySelectorAll('.navitem').forEach(x=>x.classList.remove('active'));a.classList.add('active');
}));
