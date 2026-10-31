'use strict';
(() => {
  const copy=window.labEnglish||{}, roots=new Set(), originals=new WeakMap();
  const read=key=>{try{return localStorage.getItem(key);}catch{return null;}};
  const save=(key,value)=>{try{localStorage.setItem(key,value);}catch{/* Preferences are optional. */}};
  let language=read('lab-language') || (navigator.language?.startsWith('tr')?'tr':'en');
  if(!['tr','en'].includes(language))language='tr';
  let theme=read('lab-theme') || (matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
  if(!['light','dark'].includes(theme))theme='dark';
  const normalize=text=>text.trim().replace(/\s+/g,' ');
  function english(text) {
    const value=normalize(text);
    if(copy[value])return text.replace(text.trim(),copy[value]);
    const patterns=[
      [/^(\d+) olay$/, '$1 events'],[/^(\d+) anomali$/, '$1 anomalies'],[/^(\d+) istek$/, '$1 requests'],
      [/^(\d+) \/ (\d+) konumlu olay$/,'$1 / $2 events with coordinates'],
      [/^(\d+) API kaydı eklendi\.$/,'$1 JSON records appended.'],
      [/^(.+) başarıyla yüklendi\.$/,'$1 loaded successfully.'],[/^(.+) sürüklenerek yüklendi\.$/,'$1 loaded.'],
      [/^(Daily|Weekly) raporu oluşturuldu\.$/,'$1 report generated.'],
      [/^Analiz tamamlandı — Risk: (.+)$/,'Analysis complete — Risk: $1'],
      [/^(\d+[–-]\d+) \/ (\d+) olay$/,'$1 / $2 events'],
      [/^(\d+) kayıtlı alarm · Çözülen vakalar dahil\.$/,'$1 stored alerts · Includes resolved cases.'],
      [/^Son kaynak olayı: (.+)$/,'Last source event: $1'],[/^Son içe alma: (.+)$/,'Last ingestion: $1'],
      [/^Zaman kapsaması %(\d+) · IP eksik (\d+)$/,'Time coverage $1% · Missing IP $2'],
      [/^#(\d+) vaka durumu$/,'Case #$1 status'],[/^#(\d+) analist notları$/,'Case #$1 analyst notes'],
      [/^Saat (.+)$/,'Hour $1'],[/^Skor: (.+)$/,'Score: $1'],
      [/^Analiz başarısız \(HTTP (\d+)\)$/,'Analysis failed (HTTP $1)'],
      [/^Rapor üretilemedi \(HTTP (\d+)\)$/,'Could not generate report (HTTP $1)']
    ];
    for(const [pattern,replacement] of patterns)if(pattern.test(value))return value.replace(pattern,replacement).replace('YÜKSEK','HIGH').replace('DÜŞÜK','LOW').replace('ORTA','MEDIUM');
    if(value.includes(' · ')||value.includes(' / '))return value.split(/( · | \/ )/).map(part=>/^( · | \/ )$/.test(part)?part:english(part)).join('');
    if(value.startsWith('MITRE ATT&CK: '))return text.replace('Eşleme yok','Not mapped');
    return text;
  }
  // Keep originals per DOM node so toggling language never edits user input or loses text.
  function translated(owner,key,current,write) {
    let record=originals.get(owner);if(!record){record=new Map();originals.set(owner,record);}
    let entry=record.get(key);
    if(!entry || (current!==entry.original && current!==entry.rendered))entry={original:current,rendered:current};
    const next=language==='en'?english(entry.original):entry.original;
    entry.rendered=next;record.set(key,entry);if(current!==next)write(next);
  }
  function visit(node) {
    if(node.nodeType===3){
      const parent=node.parentElement;
      if(!parent||!node.nodeValue.trim()||parent.closest('script,style,pre,code,textarea,[data-no-translate],.maplibregl-map'))return;
      // Cell data and case evidence are source material, not interface copy.
      if(parent.closest('tbody')&&!parent.closest('button')&&!parent.closest('td[colspan]'))return;
      if(parent.closest('.case')&&!parent.closest('button,label,select'))return;
      translated(node,'text',node.nodeValue,next=>{node.nodeValue=next;});return;
    }
    if(node.nodeType!==1&&node.nodeType!==9&&node.nodeType!==11)return;
    if(node.nodeType===1){
      if(node.matches('script,style,pre,code,[data-no-translate],.maplibregl-map'))return;
      for(const key of ['placeholder','aria-label','title'])if(node.hasAttribute(key))translated(node,key,node.getAttribute(key),next=>node.setAttribute(key,next));
      if(node.shadowRoot)attach(node.shadowRoot);
    }
    for(const child of node.childNodes)visit(child);
  }
  function attach(root){
    if(roots.has(root))return;roots.add(root);visit(root);
    new MutationObserver(records=>{
      for(const change of records){
        if(change.type==='characterData')visit(change.target);
        else if(change.type==='attributes')visit(change.target);
        else for(const added of change.addedNodes)visit(added);
      }
    }).observe(root,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['placeholder','aria-label','title']});
  }
  function sync(){
    document.documentElement.lang=language;document.documentElement.dataset.theme=theme;
    const mount=document.querySelector('#socMount');if(mount)mount.dataset.theme=theme;
    for(const root of roots){
      const select=root.querySelector('#languageSelect');if(select)select.value=language;
      const button=root.querySelector('#themeToggle');if(button){
        button.textContent=theme==='dark'?'Açık tema':'Koyu tema';
        button.setAttribute('aria-label',theme==='dark'?'Açık temaya geç':'Koyu temaya geç');
        button.setAttribute('aria-pressed',String(theme==='light'));
      }
      visit(root);
    }
  }
  document.querySelector('#languageSelect')?.addEventListener('change',event=>{
    language=event.target.value;save('lab-language',language);sync();document.dispatchEvent(new Event('lab-language-change'));
  });
  document.querySelector('#themeToggle')?.addEventListener('click',()=>{
    theme=theme==='dark'?'light':'dark';save('lab-theme',theme);sync();
  });
  // Open collapsed documentation for direct links and keyboard navigation.
  function revealHash(){
    if(!location.hash)return;
    let target;try{target=document.getElementById(decodeURIComponent(location.hash.slice(1)));}catch{return;}
    if(!target)return;
    if(target.tagName==='DETAILS')target.open=true;
    for(let p=target.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;
  }
  document.addEventListener('click',event=>{
    const link=event.target.closest('a[href^="#"]');if(!link)return;
    const id=link.getAttribute('href').slice(1),target=document.getElementById(id);
    if(!target)return;
    if(target.tagName==='DETAILS')target.open=true;
    for(let p=target.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;
  });
  window.addEventListener('hashchange',revealHash);revealHash();
  document.addEventListener('soc-workspace-ready',()=>{const shadow=document.querySelector('#socMount')?.shadowRoot;if(shadow)attach(shadow);sync();});
  window.labUI={attach,translate:english,get language(){return language;},get theme(){return theme;}};
  attach(document);sync();
})();
