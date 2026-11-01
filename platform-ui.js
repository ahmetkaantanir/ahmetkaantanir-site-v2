'use strict';
Object.assign(window.labEnglish||{}, {
  'Henüz veri yok':'No data yet',
  'Entegrasyon ve araştırma merkezi':'Integrations and research center',
  'Aynı log, aynı cihaz, aynı kanıt üzerinden inceleme.':'Investigate the same logs, devices and evidence.',
  'Durumu yenile':'Refresh status', '◈ Entegrasyon ve Lab':'◈ Integrations and Lab',
  'Özel API bağlantısı veya örnek görünüm ile başlayın.':'Start with a private API connection or sample workspace.',
  'Bir modül seçin. Harici servisler sunucu ortamından yapılandırılır.':'Select a module. External services are configured on the server.',
  'Loki sorgula':'Query Loki', 'Grafana panelini aç':'Open Grafana dashboard',
  'Canlı izleme':'Live monitoring', 'Kapalı':'Off', '10 saniyede yenile':'Refresh every 10 seconds',
  'GNS3 projesi':'GNS3 project', 'Proje seçin':'Select a project', 'Projeleri getir':'Load projects',
  'Topolojiyi aç':'Open topology', 'Wazuh ajanları':'Wazuh agents', 'Kanıt paketi ID':'Evidence batch ID',
  'Hash doğrula ve paketi indir':'Verify hash and download batch', 'SOC raporunu indir':'Download SOC report',
  'Kural JSON':'Rule JSON', 'Kuralı kayıtlı kanıtta dene':'Test rule against stored evidence',
  'IP istihbaratı':'IP intelligence', 'Yerel feed sorgula':'Query local feed', 'Harici sağlayıcı':'External provider',
  'Girilen IP’nin seçili sağlayıcıya gönderilmesini onaylıyorum.':'I consent to sending this IP to the selected provider.',
  'Harici IP sorgusu gönder':'Send external IP query', 'Yapılandırılmadı':'Not configured',
  'Yapılandırıldı · bağlantı test edilmedi':'Configured · connection not tested', 'Bağlantıyı test et':'Test connection',
  'Bağlantı bekleniyor.':'Waiting for connection.', 'Grafana / Lab bağlamı':'Grafana / Lab context',
  'Yapılandırılmış modele özetlet':'Request summary from configured model',
  'Tüm seviyeler':'All severities', 'Kural eşleşmesi yok':'No rule match', 'Tüm zamanlar':'All times',
  'Zamanı oynat':'Play timeline', 'Oynatmayı durdur':'Stop playback', 'Zaman çizelgesi':'Timeline',
  'GeoIP · Tahmini konum':'GeoIP · Approximate location', 'GeoIP kullanılamıyor':'GeoIP unavailable',
  'GEOIP · TAHMİNİ KONUM':'GEOIP · APPROXIMATE LOCATION',
  'GEOIP TAHMİNİ · Kaynak log kanıtı veya saldırgan kimliği değildir.':'GEOIP ESTIMATE · Not source-log evidence or attacker identity.',
  'SENTETİK SİMÜLASYON · Gerçek trafik değildir.':'SYNTHETIC SIMULATION · Not real traffic.',
  'Son yüklenen sayfa · Seviye/zaman filtresi uygulanır.':'Last loaded page · Severity/time filters apply.',
  'Zeek bağlantıları, Suricata alarmları ve firewall kayıtları.':'Zeek connections, Suricata alerts and firewall records.',
  'Wazuh, Windows ve Sysmon kanıtları.':'Wazuh, Windows and Sysmon evidence.',
  'AWS CloudTrail ve Cloudflare Logpush.':'AWS CloudTrail and Cloudflare Logpush.',
  'DNS sorguları ve uzun etiket göstergeleri.':'DNS queries and long-label indicators.',
  'Web erişim kayıtları ve şüpheli istek göstergeleri.':'Web access records and suspicious request indicators.',
  '4624 / 4625 / 4740 ve diğer Windows kayıtları.':'4624 / 4625 / 4740 and other Windows records.',
  'Ayrı kurulmuş Cowrie laboratuvarından alınan kayıtlar.':'Records from a separately deployed Cowrie lab.',
  'Paket metaverisi, özgün loglar, hash ve vaka notları.':'Packet metadata, original logs, hashes and case notes.',
  'En az dört gözlenen gün üzerinden deneysel hacim karşılaştırması.':'Experimental volume comparison over at least four observed days.',
  'Modüller en son 2.000 kayıt üzerinde çalışır; ekranda en fazla 200 olay gösterilir. Ham PCAP yerine tshark JSONL metaverisi alınır.':'Modules inspect the latest 2,000 records and show at most 200 events. Import tshark JSONL metadata for packet analysis.',
  'JSON alt kümesi: tek selection, alanlar arası AND, değerler arası OR; exact, contains ve endswith. Diğer Sigma özellikleri reddedilir.':'JSON subset: one selection, AND across fields, OR across values; exact, contains and endswith. Other Sigma features are rejected.',
  'Dosya seç (.log, .txt, .json, .jsonl)':'Choose file (.log, .txt, .json, .jsonl)'
});
/* Shared investigation context for the standalone and embedded SOC. */
window.initPlatformUI = function({root, $, api, element, message, explore, evidence}) {
  const section=element('section','panel spacious');section.id='platform';section.hidden=true;
  section.innerHTML=`<div class="panelhead"><div><span>SECURITY OPERATIONS & DIGITAL FORENSICS</span><h2>Entegrasyon ve araştırma merkezi</h2><p>Aynı log, aynı cihaz, aynı kanıt üzerinden inceleme.</p></div><button id="platformRefresh" class="button ghost">Durumu yenile</button></div>
  <div id="integrationCards" class="rulesgrid"><p>Özel API bağlantısı veya örnek görünüm ile başlayın.</p></div>
  <div class="platform-tabs" role="group" aria-label="Araştırma modülleri"></div>
  <div class="platform-workbench">
    <div id="moduleIntro" class="atlas-purpose">Bir modül seçin. Harici servisler sunucu ortamından yapılandırılır.</div>
    <div class="platform-tools">
      <label>LogQL<input id="lokiQuery" value='{job="linux-auth"} |= "Failed password"' maxlength="2000"></label>
      <button id="queryLoki" class="button ghost">Loki sorgula</button><button id="openGrafana" class="button ghost">Grafana panelini aç</button>
      <label>Canlı izleme<select id="liveMonitor"><option value="off">Kapalı</option><option value="on">10 saniyede yenile</option></select></label>
    </div>
    <div class="platform-tools"><label>GNS3 projesi<select id="gnsProject"><option value="">Proje seçin</option></select></label><button id="loadGns" class="button ghost">Projeleri getir</button><button id="loadTopology" class="button ghost">Topolojiyi aç</button><button id="wazuhAgents" class="button ghost">Wazuh ajanları</button></div>
    <div id="networkTopology" class="network-topology" aria-label="Sanal ağ cihazları"></div>
    <div class="platform-tools"><label>Kanıt paketi ID<input id="manifestBatch" type="number" min="1" value="1"></label><button id="manifestExport" class="button ghost">Hash doğrula ve paketi indir</button><button id="platformReport" class="button ghost">SOC raporunu indir</button></div>
    <details><summary>Sigma Detection Lab</summary><p>JSON alt kümesi: tek selection, alanlar arası AND, değerler arası OR; exact, contains ve endswith. Diğer Sigma özellikleri reddedilir.</p><label for="sigmaRule">Kural JSON</label><textarea id="sigmaRule" rows="9" spellcheck="false">{"title":"Encoded PowerShell","detection":{"selection":{"command_line|contains":"-EncodedCommand"},"condition":"selection"}}</textarea><button id="testSigma" class="button ghost">Kuralı kayıtlı kanıtta dene</button></details>
    <div class="platform-tools"><label>IP istihbaratı<input id="feedIp" placeholder="192.0.2.25"></label><button id="checkFeed" class="button ghost">Yerel feed sorgula</button></div>
    <div class="platform-tools"><label>Harici sağlayıcı<select id="intelProvider"><option value="abuseipdb">AbuseIPDB</option><option value="virustotal">VirusTotal</option></select></label><label><input id="intelConsent" type="checkbox">Girilen IP’nin seçili sağlayıcıya gönderilmesini onaylıyorum.</label><button id="externalIntel" class="button ghost">Harici IP sorgusu gönder</button></div>
    <p id="platformScope" class="disclaimer">Modüller en son 2.000 kayıt üzerinde çalışır; ekranda en fazla 200 olay gösterilir. Ham PCAP yerine tshark JSONL metaverisi alınır.</p>
    <div id="platformResults" class="platform-results"></div><pre id="platformOutput" class="output" hidden></pre>
  </div>`;
  root.querySelector('.main > footer').before(section);
  const nav=element('a','navitem','◈ Entegrasyon ve Lab');nav.href='#platform';root.querySelector('.sidebar nav').append(nav);
  for(const name of ['zeek','wazuh','cloudflare','cowrie','pcap']){const option=element('option','',name);option.value=name;$('#fSource').append(option);}
  let active='network', timer, revision=0, currentContext={};
  const definitions={network:['Network Security','Zeek bağlantıları, Suricata alarmları ve firewall kayıtları.'],endpoint:['Endpoint Security','Wazuh, Windows ve Sysmon kanıtları.'],cloud:['Cloud Security','AWS CloudTrail ve Cloudflare Logpush.'],dns:['DNS Threat Lab','DNS sorguları ve uzun etiket göstergeleri.'],web:['Web Attack Analytics','Web erişim kayıtları ve şüpheli istek göstergeleri.'],ad:['Active Directory Lab','4624 / 4625 / 4740 ve diğer Windows kayıtları.'],honeypot:['Honeypot Lab','Ayrı kurulmuş Cowrie laboratuvarından alınan kayıtlar.'],forensics:['Digital Forensics','Paket metaverisi, özgün loglar, hash ve vaka notları.'],ueba:['UEBA Lab','En az dört gözlenen gün üzerinden deneysel hacim karşılaştırması.']};
  const output=data=>{const pre=$('#platformOutput');pre.hidden=false;pre.textContent=JSON.stringify(data,null,2);};
  const run=fn=>async()=>{try{await fn();}catch(error){message(error.message,true);output({error:error.message});}};
  const bind=(id,fn)=>$('#'+id).addEventListener('click',run(fn));
  function download(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=element('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function renderRows(data){
    const results=$('#platformResults');results.replaceChildren();
    for(const event of data.items||data.matches||[]){
      const button=element('button','geo-evidence',`${event.timestamp||'—'} · ${event.source||event.state||'—'} · ${event.host||event.user||event.ip||'—'}`);
      if(event.event_id)button.addEventListener('click',()=>evidence(event));else button.addEventListener('click',()=>output(event));results.append(button);
    }
    output({...data,items:undefined,matches:undefined});
  }
  function drawTopology(data){
    const panel=$('#networkTopology');panel.replaceChildren();
    const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 800 420');svg.setAttribute('role','img');svg.setAttribute('aria-label','GNS3 sanal ağ topolojisi');
    const positions=new Map(),nodes=data.nodes.slice(0,200);
    const xs=nodes.map((n,i)=>Number.isFinite(n.x)?n.x:i%8*100),ys=nodes.map((n,i)=>Number.isFinite(n.y)?n.y:Math.floor(i/8)*100);
    const minX=Math.min(...xs),maxX=Math.max(...xs),minY=Math.min(...ys),maxY=Math.max(...ys);
    nodes.forEach((n,i)=>positions.set(n.node_id,[70+(xs[i]-minX)/Math.max(1,maxX-minX)*660,55+(ys[i]-minY)/Math.max(1,maxY-minY)*300]));
    for(const link of data.links){const ends=link.nodes||[],a=positions.get(ends[0]?.node_id),b=positions.get(ends[1]?.node_id);if(!a||!b)continue;const line=document.createElementNS(ns,'line');for(const [key,value]of Object.entries({x1:a[0],y1:a[1],x2:b[0],y2:b[1]}))line.setAttribute(key,String(value));line.setAttribute('stroke','currentColor');line.setAttribute('opacity','.5');svg.append(line);}
    for(const node of nodes){const [x,y]=positions.get(node.node_id),group=document.createElementNS(ns,'g'),circle=document.createElementNS(ns,'circle'),text=document.createElementNS(ns,'text');circle.setAttribute('cx',String(x));circle.setAttribute('cy',String(y));circle.setAttribute('r','12');circle.setAttribute('fill',node.status==='started'?'#1cd4bb':'#8ca2ba');text.setAttribute('x',String(x));text.setAttribute('y',String(y+30));text.setAttribute('text-anchor','middle');text.setAttribute('fill','currentColor');text.setAttribute('font-size','11');text.textContent=String(node.name||'unknown').slice(0,24);group.append(circle,text);svg.append(group);}
    panel.append(svg);
    for(const node of nodes){const button=element('button','network-node',node.name+' · '+node.status);button.addEventListener('click',()=>{currentContext={host:node.name};explore({host:node.name});});panel.append(button);}
  }
  async function loadModule(name){active=name;$('#moduleIntro').textContent=definitions[name].join(' · ');for(const b of section.querySelectorAll('[data-module]'))b.setAttribute('aria-pressed',String(b.dataset.module===name));renderRows(await api('platform/'+(name==='ueba'?'ueba':'modules/'+name)));}
  for(const [name,[label]]of Object.entries(definitions)){const b=element('button','smallbutton',label);b.dataset.module=name;b.addEventListener('click',run(()=>loadModule(name)));section.querySelector('.platform-tabs').append(b);}
  async function refresh(){const generation=revision;const data=await api('platform/integrations');if(generation!==revision)return;const cards=$('#integrationCards');cards.replaceChildren();for(const item of data.items){const card=element('article','rule');card.append(element('strong','',item.service.toUpperCase()),element('span','',item.state==='configured'?'Yapılandırıldı · bağlantı test edilmedi':'Yapılandırılmadı'));const probe=element('button','smallbutton','Bağlantıyı test et');probe.disabled=item.state!=='configured';probe.addEventListener('click',run(async()=>output(await api('platform/integrations/'+item.service+'/health'))));card.append(probe);cards.append(card);}}
  bind('platformRefresh',refresh);
  bind('queryLoki',async()=>output(await api('platform/loki/query?'+new URLSearchParams({query:$('#lokiQuery').value}))));
  bind('openGrafana',async()=>{const data=await api('platform/grafana/link?'+new URLSearchParams(currentContext));const target=new URL(data.url);if(!['http:','https:'].includes(target.protocol)||target.username||target.password)throw new Error('Geçersiz panel adresi');const a=element('a','button ghost','Grafana paneline devam et ↗');a.href=target.href;a.target='_blank';a.rel='noopener noreferrer';$('#platformResults').replaceChildren(a);});
  bind('loadGns',async()=>{const data=await api('platform/gns3/projects');const select=$('#gnsProject');select.replaceChildren();for(const p of data.items){const o=element('option','',p.name);o.value=p.project_id;select.append(o);}if(!data.items.length)output({message:'GNS3 projesi bulunamadı.'});});
  bind('loadTopology',async()=>{const id=$('#gnsProject').value;if(!id)throw new Error('Önce proje seçin.');const data=await api('platform/gns3/projects/'+encodeURIComponent(id)+'/topology');drawTopology(data);output({links:data.links,scope:'Cihaza tıklayın: aynı host adıyla log filtresi açılır. Sanal cihaz konumu coğrafi konum değildir.'});});
  bind('wazuhAgents',async()=>output(await api('platform/wazuh/agents')));
  bind('manifestExport',async()=>{const id=$('#manifestBatch').value;if(!/^[1-9]\d*$/.test(id))throw new Error('Geçerli paket ID gerekli.');const data=await api('platform/forensics/batches/'+id);output(data);download(data,'evidence-batch-'+id+'.json');});
  bind('platformReport',async()=>download(await api('platform/report'),'soc-report.json'));
  bind('testSigma',async()=>renderRows(await api('platform/sigma/test',{method:'POST',body:JSON.stringify({rule:JSON.parse($('#sigmaRule').value)})})));
  bind('checkFeed',async()=>output(await api('platform/intelligence/'+encodeURIComponent($('#feedIp').value.trim()))));
  bind('externalIntel',async()=>{if(!$('#intelConsent').checked)throw new Error('IP paylaşımını onaylayın.');output(await api('platform/intelligence/enrich',{method:'POST',body:JSON.stringify({ip:$('#feedIp').value.trim(),provider:$('#intelProvider').value,consent:true})}));});
  $('#liveMonitor').addEventListener('change',()=>{clearTimeout(timer);const generation=revision;async function poll(){if(generation!==revision||$('#liveMonitor').value!=='on')return;try{if(!document.hidden&&!section.hidden)await loadModule(active);}catch(error){message(error.message,true);$('#liveMonitor').value='off';return;}timer=setTimeout(poll,10000);}if($('#liveMonitor').value==='on')timer=setTimeout(poll,10000);});
  return {refresh:run(refresh),context(event){currentContext={};if(event.host)currentContext.host=event.host;if(event.timestamp&&Number.isFinite(Date.parse(event.timestamp))){currentContext.start=String(Date.parse(event.timestamp)-300000);currentContext.end=String(Date.parse(event.timestamp)+300000);}},reset(){revision++;clearTimeout(timer);currentContext={};$('#liveMonitor').value='off';$('#integrationCards').replaceChildren(element('p','','Bağlantı bekleniyor.'));$('#platformResults').replaceChildren();$('#networkTopology').replaceChildren();$('#gnsProject').replaceChildren();$('#platformOutput').textContent='';$('#platformOutput').hidden=true;}};
};

window.labPlatformDemo = function(endpoint, events) {
  if(endpoint==='platform/integrations')return {items:['loki','grafana','gns3','wazuh'].map(service=>({service,state:'not_configured'}))};
  if(endpoint.startsWith('platform/modules/')){const name=endpoint.split('/').pop(),sources={network:['suricata'],endpoint:['windows'],ad:['windows'],web:['web'],forensics:['windows','suricata','web']};const items=events.filter(e=>(sources[name]||[]).includes(e.source));return {items,count:items.length,synthetic:true,scope:'18_local_synthetic_events'};}
  if(endpoint==='platform/ueba')return {items:[],state:'insufficient_baseline',synthetic:true};
  throw new Error('Bu işlem özel API ve yapılandırılmış servis gerektirir.');
};
