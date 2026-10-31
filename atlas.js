'use strict';
/* MapLibre 5.24.0: local CSP build, real raster globe, no SOC data in map requests. */
(() => {
  const root = $('#globe'), motion = matchMedia('(prefers-reduced-motion: reduce)');
  let map, selected = atlasPlaces[0], paused = motion.matches, frame = 0, last = 0, layer = '', tileErrors = 0, visible = false;
  const status = $('#mapStatus'), select = $('#countrySelect');
  const codes = {de:'eu-central-1',gb:'eu-west-2',fr:'eu-west-3',us:'us-east-1',br:'sa-east-1',jp:'ap-northeast-1',sg:'ap-southeast-1',in:'ap-south-1',kr:'ap-northeast-2',au:'ap-southeast-2'};
  const reducedDuration = () => motion.matches ? 0 : 1400;
  function showCountry(place, fly = false) {
    selected = place; select.value = place.id;
    const detail = $('#countryDetail'); detail.replaceChildren();
    detail.append(element('span','fieldlabel',place.region.toLocaleUpperCase('tr')+' / COĞRAFİ REFERANS'),element('h3','',place.country),element('strong','',place.city),element('p','coordinates',`${place.lat.toFixed(2)}° / ${place.lon.toFixed(2)}°`),element('p','',place.guide));
    if (codes[place.id]) {
      const ref=element('div','infra-reference');ref.append(element('span','fieldlabel','AWS BÖLGE REFERANSI'),element('code','',codes[place.id]));
      const a=element('a','source-link','Resmi bölge listesi ↗');a.href='https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html';a.target='_blank';a.rel='noopener noreferrer';ref.append(a);detail.append(ref);
    }
    put($('#mapLocation'),place.city+' · '+place.country);
    $('#externalMap').href=`https://www.openstreetmap.org/#map=14/${place.lat}/${place.lon}`;
    if(fly && map) {setPaused(true);map.flyTo({center:[place.lon,place.lat],zoom:4.5,duration:reducedDuration()});}
  }
  for (const place of atlasPlaces) {const o=element('option','',place.country+' · '+place.city);o.value=place.id;select.append(o);}
  select.addEventListener('change',()=>showCountry(atlasPlaces.find(p=>p.id===select.value),true));showCountry(selected);
  function setPaused(value) {
    paused=value;put($('#globeToggle'),paused?'Otomatik dönüşü başlat':'Otomatik dönüşü durdur');$('#globeToggle').setAttribute('aria-pressed',String(paused));
    if(!paused&&!frame&&!document.hidden&&visible)frame=requestAnimationFrame(rotate);
  }
  function rotate(t) {frame=0;if(document.hidden||!visible||paused||!map)return;if(map.getZoom()<3&&!map.isMoving()){const center=map.getCenter();map.jumpTo({center:[center.lng+Math.min(t-last,50)*.001,center.lat]});}last=t;if(!paused)frame=requestAnimationFrame(rotate);}
  const regions={Dünya:[20,20,1.3],Avrupa:[15,48,3],Asya:[105,30,2.5],Amerika:[-85,25,2.2],Okyanusya:[140,-25,3]};
  for(const [name,[lon,lat,zoom]] of Object.entries(regions)){
    const b=element('button','region-tab',name);b.setAttribute('aria-pressed',String(name==='Dünya'));b.addEventListener('click',()=>{if(!map)return;setPaused(true);map.flyTo({center:[lon,lat],zoom,pitch:0,bearing:0,duration:reducedDuration()});for(const child of $('#regionTabs').children)child.setAttribute('aria-pressed',String(child===b));});$('#regionTabs').append(b);
  }
  try {
    if(!window.maplibregl)throw new Error('Harita kütüphanesi yüklenemedi.');
    maplibregl.setWorkerUrl('/vendor/maplibre/maplibre-gl-csp-worker.js');
    map=new maplibregl.Map({container:root,center:[29,25],zoom:1.3,minZoom:0.7,maxZoom:19,attributionControl:false,
      style:{version:8,projection:{type:'globe'},sources:{
        satellite:{type:'raster',tiles:['https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless-2020_3857/default/g/{z}/{y}/{x}.jpg'],tileSize:256,maxzoom:13,attribution:'Sentinel-2 cloudless 2020 © <a href="https://maps.eox.at/" target="_blank" rel="noopener noreferrer">EOX</a> / Copernicus'},
        street:{type:'raster',tiles:['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],tileSize:256,maxzoom:19,attribution:'© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap contributors</a>'}
      },layers:[{id:'background',type:'background',paint:{'background-color':'#071421'}},{id:'satellite',type:'raster',source:'satellite',paint:{'raster-fade-duration':200}},{id:'street',type:'raster',source:'street',layout:{visibility:'none'}}]},
      transformRequest:(url)=>({url,credentials:'omit'}),maxTileCacheSize:128,renderWorldCopies:false});
    map.addControl(new maplibregl.NavigationControl({visualizePitch:true}),'top-right');
    map.addControl(new maplibregl.AttributionControl({compact:false}),'bottom-right');
    map.addControl(new maplibregl.ScaleControl({maxWidth:120,unit:'metric'}),'bottom-left');
    // Map instance is exposed only for camera inspection, not private log data.
    root.atlasMap=map;
    const markers=[];
    for(const place of atlasPlaces){
      const pin=element('button','atlas-pin','');pin.type='button';pin.setAttribute('aria-label',place.city+' · '+place.country);pin.title=place.city+' · '+place.country;
      pin.addEventListener('click',e=>{e.stopPropagation();showCountry(place,true);});
      markers.push({place,marker:new maplibregl.Marker({element:pin,opacityWhenCovered:0}).setLngLat([place.lon,place.lat]).addTo(map)});
    }
    function updateView(){
      const zoom=map.getZoom(),center=map.getCenter(),choice=$('#mapStyle').value;
      const next=choice==='auto'?(zoom<5?'satellite':'street'):choice;
      if(map.getLayer('satellite')&&layer!==next){map.setLayoutProperty('satellite','visibility',next==='satellite'?'visible':'none');map.setLayoutProperty('street','visibility',next==='street'?'visible':'none');layer=next;tileErrors=0;}
      put($('#zoomLevel'),'z '+zoom.toFixed(1));put($('#atlasCoordinates'),`${center.lat.toFixed(3)}° / ${center.lng.toFixed(3)}°`);
      const detail=zoom<3?'KÜRE':zoom<6?'ÜLKE':zoom<11?'ŞEHİR':'SOKAK';
      put($('#mapScaleInfo'),`${detail} · ${next==='satellite'?'Sentinel-2 uydu mozaiği (2020, en fazla z13 kaynak ayrıntısı)':'OpenStreetMap sokak haritası'} · zoom ${zoom.toFixed(1)}`);
      root.dataset.longitude=center.lng.toFixed(3);root.dataset.latitude=center.lat.toFixed(3);root.dataset.zoom=zoom.toFixed(2);
      for(const {place,marker} of markers){const pin=marker.getElement();pin.classList.toggle('city-scale',zoom>9);pin.classList.toggle('atlas-pin-selected',place.id===selected.id);pin.classList.toggle('atlas-pin-secondary',zoom<3&&!['tr','de','us','br','sg','jp','au'].includes(place.id)&&place.id!==selected.id);}
    }
    map.on('load',()=>{put(status,'UYDU HARİTASI · GERÇEK COĞRAFYA');updateView();setPaused(paused);});
    map.on('move',updateView);
    map.on('idle',()=>{if(tileErrors===0)put(status,layer==='street'?'SOKAK KATMANI · OPENSTREETMAP':'UYDU MOZAIĞI · SENTINEL-2 / EOX');});
    map.on('error',e=>{tileErrors++;put(status,'Harita verisi yüklenemedi. Ağ bağlantısını kontrol edin veya katman değiştirin.');status.classList.add('map-error');});
    map.on('sourcedata',e=>{if(e.isSourceLoaded&&e.sourceId===layer){tileErrors=0;status.classList.remove('map-error');}});
    for(const type of ['mousedown','touchstart','wheel','keydown'])root.addEventListener(type,()=>setPaused(true),{passive:true});
    $('#mapStyle').addEventListener('change',()=>{tileErrors=0;status.classList.remove('map-error');updateView();});
    $('#zoomIn').addEventListener('click',()=>{setPaused(true);map.zoomIn({duration:motion.matches?0:300});});
    $('#zoomOut').addEventListener('click',()=>{setPaused(true);map.zoomOut({duration:motion.matches?0:300});});
    $('#globeReset').addEventListener('click',()=>{setPaused(true);map.flyTo({center:[29,25],zoom:1.3,bearing:0,pitch:0,duration:reducedDuration()});for(const child of $('#regionTabs').children)child.setAttribute('aria-pressed',String(child.textContent==='Dünya'));});
    $('#flyCity').addEventListener('click',()=>{setPaused(true);map.flyTo({center:[selected.lon,selected.lat],zoom:11,duration:reducedDuration()});});
    $('#flyStreet').addEventListener('click',()=>{setPaused(true);$('#mapStyle').value='street';updateView();map.flyTo({center:[selected.lon,selected.lat],zoom:16,duration:reducedDuration()});});
    $('#globeToggle').addEventListener('click',()=>{if(paused&&map.getZoom()>=3)map.jumpTo({zoom:1.3,pitch:0});setPaused(!paused);});
    motion.addEventListener('change',e=>setPaused(e.matches));document.addEventListener('visibilitychange',()=>{last=performance.now();if(!document.hidden)setPaused(paused);});
    new ResizeObserver(()=>map.resize()).observe(root);
    new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(visible)setPaused(paused);},{threshold:.05}).observe(root);
  } catch(error) {
    put(status,'Bu cihazda WebGL haritası açılamadı. Konum kartları ve dış harita bağlantısı kullanılabilir.');status.classList.add('map-error');
    root.append(element('p','map-unavailable','Gerçek harita için WebGL destekli bir tarayıcı ve internet bağlantısı gerekir.'));
    for(const id of ['zoomIn','zoomOut','globeToggle','globeReset','mapStyle','flyCity','flyStreet'])$('#'+id).disabled=true;
  }
})();
