'use strict';
/* One-page integration. An open shadow root isolates legacy and SOC styles/IDs. */
(() => {
  const mount=document.querySelector('#socMount');if(!mount)return;
  let loading=false,loaded=false;
  const scriptPromises=new Map();
  function script(src){
    if(scriptPromises.has(src))return scriptPromises.get(src);
    const promise=new Promise((resolve,reject)=>{const node=document.createElement('script');node.src=src;node.onload=resolve;node.onerror=()=>{node.remove();scriptPromises.delete(src);reject(new Error('Bir çalışma alanı bileşeni yüklenemedi.'));};document.head.append(node);});
    scriptPromises.set(src,promise);return promise;
  }
  async function load(){
    if(loading||loaded)return;loading=true;
    const placeholder=mount.querySelector('.workspace-loading');
    if(placeholder){placeholder.setAttribute('aria-busy','true');placeholder.querySelector('p').textContent='Harita ve güvenlik araçları hazırlanıyor…';placeholder.querySelector('button').disabled=true;}
    try{
      const response=await fetch('/soc.html');if(!response.ok)throw new Error('SOC içeriği yüklenemedi. HTTP '+response.status);
      const doc=new DOMParser().parseFromString(await response.text(),'text/html'),app=doc.querySelector('.app');
      if(!app||!app.querySelector('#apiKey'))throw new Error('SOC içeriği doğrulanamadı.');
      // The header and public analysis tool remain in the main document.
      app.querySelector('.brand').setAttribute('href','#hero');
      app.querySelector('.top-actions a')?.remove();
      const title=app.querySelector('h1'),heading=document.createElement('h2');heading.className='workspace-title';heading.textContent=title.textContent;title.replaceWith(heading);
      const shadow=mount.shadowRoot||mount.attachShadow({mode:'open'});shadow.replaceChildren();
      const css=[];
      for(const href of ['/vendor/maplibre/maplibre-gl.css','/soc.css']){
        const link=document.createElement('link');link.rel='stylesheet';link.href=href;
        css.push(new Promise((resolve,reject)=>{link.onload=resolve;link.onerror=()=>reject(new Error('Çalışma alanı stilleri yüklenemedi.'));}));shadow.append(link);
      }
      const scoped=document.createElement('style');scoped.textContent=`
        :host{display:block;min-width:0;color-scheme:dark;--bg:#080e18;--panel:#101b2a;--panel2:#142235;--stroke:#26364a;--text:#eaf2fb;--muted:#8ca2ba;--teal:#1cd4bb;--blue:#6aafff;--red:#ff7789;--amber:#ffc47b;font:14px/1.55 system-ui,-apple-system,Segoe UI,Arial,sans-serif;color:var(--text)}
        .app{display:block;min-height:0;background:#080e18;border:1px solid #26364a;border-radius:20px;overflow:clip}.main{max-width:none;padding:24px;width:100%;margin:0}.sidebar{position:static;height:auto;padding:12px;background:#0b1420;border:0;border-bottom:1px solid #26364a;display:block;overflow:visible}.sidebar .brand,.sidebar .navhead,.sidebar .side-foot{display:none}.sidebar nav{display:flex;gap:6px;overflow-x:auto}.navitem{white-space:nowrap;padding:9px 12px;font-size:12px;flex-shrink:0}.workspace-title{font-size:32px;line-height:1.2;margin:12px 0;color:#eaf2fb}.topbar{margin-bottom:22px}.credential{flex-wrap:wrap}.credential input{flex:1;min-width:180px}.side-foot{margin:0}.panel.spacious{scroll-margin-top:90px}.globe-stage{min-width:0}#globe{min-width:0}.intel-layout{grid-template-columns:minmax(0,1.3fr) minmax(260px,1fr)}
        @media(max-width:1100px){.intel-layout{grid-template-columns:1fr}.main{padding:18px}}@media(max-width:600px){.main{padding:12px}.workspace-title{font-size:25px}.app{border-radius:12px}.credential input{width:100%}}
      `;shadow.append(scoped,document.importNode(app,true));
      // Let the atlas keep its location cards and fallback when WebGL assets fail.
      await Promise.all([...css,script('/vendor/maplibre/maplibre-gl-csp.js').catch(()=>{}),script('/soc.js')]);
      await script('/atlas.js');
      window.initSocWorkspace(shadow);loaded=true;mount.dataset.ready='true';
      document.dispatchEvent(new CustomEvent('soc-workspace-ready'));
    }catch(error){
      const root=mount.shadowRoot||mount;root.replaceChildren();
      const box=document.createElement('div');box.className='workspace-loading';box.setAttribute('role','status');
      const text=document.createElement('p');text.textContent=error.message+' Yeniden deneyebilirsiniz.';
      const retry=document.createElement('button');retry.type='button';retry.textContent='Yeniden yükle';retry.addEventListener('click',load);
      box.append(text,retry);root.append(box);root.__socInitialized=false;
    }finally{loading=false;}
  }
  document.querySelector('#loadWorkspace').addEventListener('click',load);
  const observer=new IntersectionObserver(entries=>{if(entries.some(e=>e.isIntersecting)){observer.disconnect();load();}},{rootMargin:'400px'});observer.observe(mount);
})();
