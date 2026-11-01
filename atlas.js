'use strict';
/* MapLibre 5.24.0: local CSP build, real raster globe, no SOC data in map requests. */
window.initSocAtlas = function({$, atlasPlaces, put, element, onEvidence, onExplore, onGeoIP}) {
  const root = $('#globe'), motion = matchMedia('(prefers-reduced-motion: reduce)');
  let map, selected = atlasPlaces[0], paused = motion.matches, frame = 0, last = 0, layer = '', tileErrors = 0, visible = false, ready = false;
  let refreshSelection = () => {};
  const markers=[],eventMarkers=[];
  let items=[],geo=window.labGeo.summarize([]),context={},geoSelected=false;
  let allItems=[], geoipItems=[], geoipRevision=0, replayTimer;
  const geoipOption=element('option','','GeoIP · Tahmini konum');geoipOption.value='geoip';$('#atlasMode').append(geoipOption);
  const geoipMode=()=>$('#atlasMode').value==='geoip';
  const filters=element('div','atlas-data-bar');
  const severity=element('select');severity.setAttribute('aria-label','Alarm seviyesi');
  for(const [value,label] of [['','Tüm seviyeler'],['critical','Critical'],['high','High'],['medium','Medium'],['low','Low'],['unknown','Kural eşleşmesi yok']]){const o=element('option','',label);o.value=value;severity.append(o);}
  const time=element('input');time.type='range';time.min='0';time.max='100';time.value='100';time.setAttribute('aria-label','Zaman çizelgesi');
  const timeLabel=element('span','','Tüm zamanlar'),play=element('button','button ghost','Zamanı oynat');
  filters.append(severity,time,timeLabel,play);$('.atlas-toolbar').before(filters);
  function applyFilters(){
    const base=geoipMode()?geoipItems:allItems;
    const dates=base.map(e=>Date.parse(e.timestamp)).filter(Number.isFinite),first=Math.min(...dates),lastTime=Math.max(...dates);
    const cutoff=first+(lastTime-first)*Number(time.value)/100;
    items=base.filter(e=>(!severity.value||(severity.value==='unknown'?!e.severity:e.severity===severity.value))&&(time.value==='100'||(Number.isFinite(Date.parse(e.timestamp))&&Date.parse(e.timestamp)<=cutoff)));
    timeLabel.textContent=time.value==='100'?'Tüm zamanlar':Number.isFinite(cutoff)?new Date(cutoff).toISOString():'Zaman bilgisi yok';
    geo=window.labGeo.summarize(items);renderGeo();if(eventMode())geoOverview();
    $('#geoCoverage').replaceChildren(element('strong','',`${geo.located} / ${geo.total} konumlu olay`),element('small','',geoipMode()?'GEOIP TAHMİNİ · Kaynak log kanıtı veya saldırgan kimliği değildir.':context.synthetic?'SENTETİK SİMÜLASYON · Gerçek trafik değildir.':'Son yüklenen sayfa · Seviye/zaman filtresi uygulanır.'));
  }
  function stopReplay(){clearTimeout(replayTimer);replayTimer=undefined;play.textContent='Zamanı oynat';}
  severity.addEventListener('change',applyFilters);time.addEventListener('input',()=>{stopReplay();applyFilters();});
  play.addEventListener('click',()=>{if(replayTimer){stopReplay();return;}time.value='0';play.textContent='Oynatmayı durdur';function tick(){if(document.hidden||$('#intelligence').hidden){stopReplay();return;}applyFilters();if(Number(time.value)>=100){stopReplay();return;}time.value=String(Number(time.value)+5);replayTimer=setTimeout(tick,motion.matches?1000:500);}replayTimer=setTimeout(tick,50);});
  const eventMode=()=>$('#atlasMode').value!=='reference';
  async function loadGeoIP(){
    const revision=++geoipRevision;geoipItems=[];applyFilters();
    const ips=[...new Set(allItems.map(e=>e.ip).filter(Boolean))].slice(0,50);
    if(!ips.length)return;
    try{
      const response=await onGeoIP(ips);if(revision!==geoipRevision||!geoipMode())return;
      const matches=new Map(response.items.map(item=>[item.ip,item]));
      geoipItems=allItems.map(event=>{const match=matches.get(event.ip);return match?{...event,_original:event,_geoip:match,raw:JSON.stringify({source:{geo:{location:match.location}}})}:event.raw?{...event,_original:event,raw:'{}'}:event;});applyFilters();
    }catch(error){if(revision!==geoipRevision||!geoipMode())return;$('#geoDetail').replaceChildren(element('h3','','GeoIP kullanılamıyor'),element('p','',error.message));}
  }
  function locationControls(enabled){
    for(const id of ['flyCity','flyStreet'])$('#'+id).disabled=!enabled||!map;
    $('#externalMap').setAttribute('aria-disabled',String(!enabled));
  }
  $('#externalMap').addEventListener('click',event=>{if($('#externalMap').getAttribute('aria-disabled')==='true')event.preventDefault();});
  function showGeo(group,fly=true){
    geoSelected=true;selected={id:'event',lon:group.point[0],lat:group.point[1]};
    const detail=$('#geoDetail');detail.replaceChildren();
    detail.append(element('span','fieldlabel',geoipMode()?'GEOIP · TAHMİNİ KONUM':'LOGDA BEYAN EDİLEN KONUM'),element('h3','',`${selected.lat.toFixed(3)}° / ${selected.lon.toFixed(3)}°`),element('p','', 'Konum doğrulanmış fiziksel adres veya saldırgan kimliği değildir.'));
    for(const index of group.indices.slice(0,10)){
      const event=items[index],button=element('button','geo-evidence','Kanıtı aç');
      const record=element('code','',event.event_id||String(index+1));
      const fields=Object.entries(window.labGeo.coordinates(event)).filter(([,point])=>point[0]===group.point[0]&&point[1]===group.point[1]).map(([side])=>side+'.geo.location');
      button.append(record,element('code','',geoipMode()?`${event._geoip?.source} · ${event._geoip?.updated_at}`:fields.join(' + ')));button.addEventListener('click',()=>onEvidence(event._original||event));detail.append(button);
    }
    put($('#mapLocation'),`${selected.lat.toFixed(3)}° / ${selected.lon.toFixed(3)}°`);
    $('#externalMap').href=`https://www.openstreetmap.org/#map=10/${selected.lat}/${selected.lon}`;
    locationControls(true);setPaused(true);
    if(fly&&ready)map.flyTo({center:group.point,zoom:3.6,duration:reducedDuration()});
    for(const entry of eventMarkers)entry.pin.classList.toggle('event-pin-selected',entry.key===group.key);
  }
  function geoOverview(){
    geoSelected=false;locationControls(false);put($('#mapLocation'),'Konum seçilmedi');
    const detail=$('#geoDetail');detail.replaceChildren();
    detail.append(element('span','fieldlabel',context.synthetic?'SENTETİK ÖRNEK':'LOG KONUM KAPSAMI'),element('h3','',geo.located?'Konumdan kanıta.':'Koordinat bulunamadı.'),element('p','',geo.located?'Bir konum seçip dayandığı logu inceleyin.':'IP adresi tek başına konum değildir. ECS koordinat alanı olmayan kayıtlar haritaya yerleştirilmez.'));
    for(const group of geo.groups.slice(0,12)){
      const button=element('button','geo-location',`${group.point[1].toFixed(2)}° / ${group.point[0].toFixed(2)}° · ${group.indices.length} olay`);
      button.addEventListener('click',()=>showGeo(group));detail.append(button);
    }
  }
  function renderGeo(){
    for(const entry of eventMarkers)entry.marker.remove();eventMarkers.length=0;
    if(map)for(const group of geo.groups){
      const pin=element('button','event-pin',String(group.indices.length));pin.type='button';
      pin.classList.add(group.sides.length>1?'event-pin-mixed':group.sides.includes('source')?'event-pin-source':'event-pin-destination');
      pin.setAttribute('aria-label',`${group.point[1].toFixed(3)}° / ${group.point[0].toFixed(3)}° · ${group.indices.length} olay`);pin.hidden=!eventMode();
      pin.addEventListener('click',event=>{event.stopPropagation();showGeo(group);});
      eventMarkers.push({key:group.key,pin,marker:new maplibregl.Marker({element:pin,opacityWhenCovered:0}).setLngLat(group.point).addTo(map)});
    }
    if(ready)map.getSource('event-connections')?.setData(geo.links);
  }
  function setMode(){
    if(geoipMode())loadGeoIP();else{geoipRevision++;applyFilters();}
    const events=eventMode();$('#geoDetail').hidden=!events;$('#referenceControls').hidden=events;
    $('.geo-legend').hidden=!events;
    for(const entry of markers)entry.marker.getElement().hidden=events;
    for(const entry of eventMarkers)entry.pin.hidden=!events;
    if(ready)map.setLayoutProperty('event-connections','visibility',events?'visible':'none');
    if(events)geoOverview();else{showCountry(atlasPlaces.find(p=>p.id===$('#countrySelect').value)||atlasPlaces[0]);locationControls(true);}
  }
  function updateEvents(events,scope={}){
    stopReplay();geoipRevision++;allItems=events;geoipItems=[];context=scope;time.value='100';applyFilters();if(geoipMode())loadGeoIP();
  }
  $('#atlasMode').addEventListener('change',setMode);
  $('#atlasExplorer').addEventListener('click',()=>onExplore());
  const status = $('#mapStatus'), select = $('#countrySelect');
  const codes = {de:'eu-central-1',gb:'eu-west-2',fr:'eu-west-3',us:'us-east-1',br:'sa-east-1',jp:'ap-northeast-1',sg:'ap-southeast-1',in:'ap-south-1',kr:'ap-northeast-2',au:'ap-southeast-2'};
  const reducedDuration = () => motion.matches ? 0 : 1400;
  function showCountry(place, fly = false) {
    if (!place) return;
    selected = place; select.value = place.id;
    refreshSelection();
    const detail = $('#countryDetail'); detail.replaceChildren();
    detail.append(element('span','fieldlabel',place.region.toLocaleUpperCase('tr')+' / COĞRAFİ REFERANS'),element('h3','',place.country),element('strong','',place.city),element('p','coordinates',`${place.lat.toFixed(2)}° / ${place.lon.toFixed(2)}°`),element('p','',place.guide));
    if (codes[place.id]) {
      const ref=element('div','infra-reference');ref.append(element('span','fieldlabel','AWS BÖLGE REFERANSI'),element('code','',codes[place.id]));
      const a=element('a','source-link','Resmi bölge listesi ↗');a.href='https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html';a.target='_blank';a.rel='noopener noreferrer';ref.append(a);detail.append(ref);
    }
    put($('#mapLocation'),place.city+' · '+place.country);
    $('#externalMap').href=`https://www.openstreetmap.org/#map=14/${place.lat}/${place.lon}`;
    if(fly && ready) {setPaused(true);map.flyTo({center:[place.lon,place.lat],zoom:4.5,duration:reducedDuration()});}
  }
  for (const place of atlasPlaces) {const o=element('option','',place.country+' · '+place.city);o.value=place.id;select.append(o);}
  select.addEventListener('change',()=>showCountry(atlasPlaces.find(p=>p.id===select.value),true));showCountry(selected);
  function setPaused(value) {
    paused=value;put($('#globeToggle'),paused?'Otomatik dönüşü başlat':'Otomatik dönüşü durdur');$('#globeToggle').setAttribute('aria-pressed',String(paused));
    if (frame) cancelAnimationFrame(frame);
    frame=0;last=performance.now();
    if(!paused&&ready&&!document.hidden&&visible)frame=requestAnimationFrame(rotate);
  }
  function rotate(t) {frame=0;if(document.hidden||!visible||paused||!map)return;if(map.getZoom()<3&&!map.isMoving()){const center=map.getCenter();map.jumpTo({center:[center.lng+Math.min(t-last,50)*.001,center.lat]});}last=t;if(!paused)frame=requestAnimationFrame(rotate);}
  const regions={Dünya:[20,20,1.3],Avrupa:[15,48,3],Asya:[105,30,2.5],Amerika:[-85,25,2.2],Okyanusya:[140,-25,3]};
  for(const [name,[lon,lat,zoom]] of Object.entries(regions)){
    const b=element('button','region-tab',name);b.dataset.region=name;b.setAttribute('aria-pressed',String(name==='Dünya'));b.addEventListener('click',()=>{if(!map)return;setPaused(true);map.flyTo({center:[lon,lat],zoom,pitch:0,bearing:0,duration:reducedDuration()});for(const child of $('#regionTabs').children)child.setAttribute('aria-pressed',String(child===b));});$('#regionTabs').append(b);
  }
  try {
    if(!window.maplibregl)throw new Error('Harita kütüphanesi yüklenemedi.');
    maplibregl.setWorkerUrl('/vendor/maplibre/maplibre-gl-csp-worker.js');
    map=new maplibregl.Map({container:root,center:[29,25],zoom:1.3,minZoom:0.7,maxZoom:19,attributionControl:false,
      style:{version:8,projection:{type:'globe'},sky:{'sky-color':'#030c18','horizon-color':'#4d9ebd','fog-color':'#0b2031','atmosphere-blend':['interpolate',['linear'],['zoom'],0,.85,3,.7,6,0]},sources:{
        land:{type:'geojson',data:'/vendor/world-land.geojson',attribution:'<a href="https://www.naturalearthdata.com/" target="_blank" rel="noopener noreferrer">Natural Earth</a>'},
        'event-connections':{type:'geojson',data:geo.links},
        satellite:{type:'raster',tiles:['https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless-2020_3857/default/g/{z}/{y}/{x}.jpg'],tileSize:256,maxzoom:13,attribution:'Sentinel-2 cloudless 2020 © <a href="https://maps.eox.at/" target="_blank" rel="noopener noreferrer">EOX</a> / Copernicus'},
        street:{type:'raster',tiles:['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],tileSize:256,maxzoom:19,attribution:'© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap contributors</a>'}
      },layers:[{id:'background',type:'background',paint:{'background-color':'#081e30'}},{id:'land-fill',type:'fill',source:'land',paint:{'fill-color':'#24546a','fill-opacity':.96}},{id:'coastline',type:'line',source:'land',paint:{'line-color':'#70b7bf','line-width':.65,'line-opacity':.6}},{id:'satellite',type:'raster',source:'satellite',layout:{visibility:'none'},paint:{'raster-fade-duration':300}},{id:'street',type:'raster',source:'street',layout:{visibility:'none'}},{id:'event-connections',type:'line',source:'event-connections',paint:{'line-color':'#f4bf74','line-width':2,'line-opacity':.8,'line-dasharray':[2,3]}}]},
      transformRequest:(url)=>({url,credentials:'omit'}),maxTileCacheSize:128,renderWorldCopies:false});
    map.addControl(new maplibregl.NavigationControl({visualizePitch:true}),'top-right');
    map.addControl(new maplibregl.AttributionControl({compact:false}),'bottom-right');
    map.addControl(new maplibregl.ScaleControl({maxWidth:120,unit:'metric'}),'bottom-left');
    // Map instance is exposed only for camera inspection, not private log data.
    root.atlasMap=map;
    for(const place of atlasPlaces){
      const pin=element('button','atlas-pin','');pin.type='button';pin.setAttribute('aria-label',place.city+' · '+place.country);pin.title=place.city+' · '+place.country;
      pin.addEventListener('click',e=>{e.stopPropagation();showCountry(place,true);});
      markers.push({place,marker:new maplibregl.Marker({element:pin,opacityWhenCovered:0}).setLngLat([place.lon,place.lat]).addTo(map)});
    }
    function updateView(){
      const zoom=map.getZoom(),center=map.getCenter(),choice=$('#mapStyle').value;
      const next=choice==='auto'?(zoom<3?'vector':zoom<5?'satellite':'street'):choice;
      if(map.getLayer('satellite')&&layer!==next){map.setLayoutProperty('satellite','visibility',next==='satellite'?'visible':'none');map.setLayoutProperty('street','visibility',next==='street'?'visible':'none');layer=next;tileErrors=0;status.classList.remove('map-error');}
      put($('#zoomLevel'),'z '+zoom.toFixed(1));put($('#atlasCoordinates'),`${center.lat.toFixed(3)}° / ${center.lng.toFixed(3)}°`);
      const detail=zoom<3?'KÜRE':zoom<6?'ÜLKE':zoom<11?'ŞEHİR':'SOKAK';
      put($('#mapScaleInfo'),`${detail} · ${next==='vector'?'Yerel analitik harita · Natural Earth':next==='satellite'?'Sentinel-2 uydu mozaiği (2020, en fazla z13 kaynak ayrıntısı)':'OpenStreetMap sokak haritası'} · zoom ${zoom.toFixed(1)}`);
      root.dataset.longitude=center.lng.toFixed(3);root.dataset.latitude=center.lat.toFixed(3);root.dataset.zoom=zoom.toFixed(2);
      for(const {place,marker} of markers){const pin=marker.getElement();pin.classList.toggle('city-scale',zoom>9);pin.classList.toggle('atlas-pin-selected',place.id===selected.id);pin.classList.toggle('atlas-pin-secondary',zoom<3&&!['tr','de','us','br','sg','jp','au'].includes(place.id)&&place.id!==selected.id);}
    }
    refreshSelection=updateView;
    map.on('load',()=>{ready=true;put(status,'YEREL ANALİTİK HARİTA · NATURAL EARTH');updateView();renderGeo();setMode();setPaused(paused);});
    map.on('move',updateView);
    map.on('idle',()=>{if(tileErrors===0){status.classList.remove('map-error');put(status,layer==='vector'?'YEREL ANALİTİK HARİTA · NATURAL EARTH':layer==='street'?'SOKAK KATMANI · OPENSTREETMAP':'UYDU MOZAIĞI · SENTINEL-2 / EOX');}});
    map.on('error',e=>{if(e.sourceId&&layer&&e.sourceId!==(layer==='vector'?'land':layer))return;tileErrors++;put(status,'Harita verisi yüklenemedi. Ağ bağlantısını kontrol edin veya katman değiştirin.');status.classList.add('map-error');if(tileErrors>=3&&layer!=='vector'){$('#mapStyle').value='vector';updateView();}});
    map.on('sourcedata',e=>{if(e.isSourceLoaded&&e.sourceId===(layer==='vector'?'land':layer)){tileErrors=0;status.classList.remove('map-error');}});
    // Native MapLibre controls stop propagation; also pause on direct camera gestures.
    for(const type of ['dragstart','zoomstart','rotatestart','pitchstart'])map.on(type,e=>{if(e.originalEvent)setPaused(true);});
    for(const type of ['mousedown','touchstart','wheel','keydown'])root.addEventListener(type,()=>setPaused(true),{passive:true});
    $('#mapStyle').addEventListener('change',()=>{tileErrors=0;status.classList.remove('map-error');updateView();});
    $('#zoomIn').addEventListener('click',()=>{setPaused(true);map.zoomIn({duration:motion.matches?0:300});});
    $('#zoomOut').addEventListener('click',()=>{setPaused(true);map.zoomOut({duration:motion.matches?0:300});});
    $('#globeReset').addEventListener('click',()=>{setPaused(true);map.flyTo({center:[29,25],zoom:1.3,bearing:0,pitch:0,duration:reducedDuration()});for(const child of $('#regionTabs').children)child.setAttribute('aria-pressed',String(child.dataset.region==='Dünya'));});
    $('#flyCity').addEventListener('click',()=>{setPaused(true);map.flyTo({center:[selected.lon,selected.lat],zoom:11,duration:reducedDuration()});});
    $('#flyStreet').addEventListener('click',()=>{setPaused(true);$('#mapStyle').value='street';updateView();map.flyTo({center:[selected.lon,selected.lat],zoom:16,duration:reducedDuration()});});
    $('#globeToggle').addEventListener('click',()=>{if(paused&&map.getZoom()>=3)map.jumpTo({zoom:1.3,pitch:0});setPaused(!paused);});
    motion.addEventListener('change',e=>setPaused(e.matches));document.addEventListener('visibilitychange',()=>setPaused(paused));
    new ResizeObserver(()=>map.resize()).observe(root);
    new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;setPaused(paused);},{threshold:.05}).observe(root);
  } catch(error) {
    map=undefined;
    put(status,'Bu cihazda WebGL haritası açılamadı. Konum kartları ve dış harita bağlantısı kullanılabilir.');status.classList.add('map-error');
    root.append(element('p','map-unavailable','Gerçek harita için WebGL destekli bir tarayıcı ve internet bağlantısı gerekir.'));
    for(const id of ['zoomIn','zoomOut','globeToggle','globeReset','mapStyle','flyCity','flyStreet'])$('#'+id).disabled=true;
  }
  setMode();updateEvents([]);
  return {updateEvents};
};
if(document.querySelector('#apiKey'))window.initSocWorkspace(document);
