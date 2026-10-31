'use strict';
// Deliberately reads only declared ECS locations. Never guesses a location from an IP.
(function(root){
  function location(value){
    let lon,lat;
    if(Array.isArray(value)&&value.length===2)[lon,lat]=value;
    else if(value&&typeof value==='object'){lon=value.lon;lat=value.lat;}
    if(typeof lon!=='number'||typeof lat!=='number'||!Number.isFinite(lon)||!Number.isFinite(lat)||Math.abs(lon)>180||Math.abs(lat)>90)return null;
    return [lon,lat];
  }
  function coordinates(event){
    let raw=event.raw;
    if(typeof raw==='string'){try{raw=JSON.parse(raw);}catch{return {};}}
    if(!raw||typeof raw!=='object'||Array.isArray(raw))return {};
    const result={};
    for(const side of ['source','destination']){
      const value=raw[side+'.geo.location']??raw[side]?.geo?.location;
      const point=location(value);if(point)result[side]=point;
    }
    return result;
  }
  function summarize(events){
    const groups=new Map(),links=[];let located=0;
    events.forEach((event,index)=>{
      const coords=coordinates(event);if(Object.keys(coords).length)located++;
      for(const [side,point]of Object.entries(coords)){
        const key=point.join(',');
        if(!groups.has(key))groups.set(key,{key,point,indices:new Set(),sides:new Set()});
        const group=groups.get(key);group.indices.add(index);group.sides.add(side);
      }
      if(coords.source&&coords.destination){
        const a=coords.source,b=[...coords.destination];
        // A connecting line denotes reported endpoints, never a measured packet route.
        if(Math.abs(a[0]-b[0])>180)b[0]+=a[0]>b[0]?360:-360;
        links.push({type:'Feature',properties:{index},geometry:{type:'LineString',coordinates:[a,b]}});
      }
    });
    return {total:events.length,located,missing:events.length-located,groups:[...groups.values()].map(g=>({...g,indices:[...g.indices],sides:[...g.sides]})),links:{type:'FeatureCollection',features:links}};
  }
  const api={location,coordinates,summarize};
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.labGeo=api;
})(globalThis);
