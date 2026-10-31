import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const geo=createRequire(import.meta.url)('../geo.js');
test('nested and dotted ECS fields support declared numeric locations',()=>{
  assert.deepEqual(geo.coordinates({raw:JSON.stringify({source:{geo:{location:{lat:41,lon:29}}},'destination.geo.location':[-74,40]})}),{source:[29,41],destination:[-74,40]});
});
test('zero coordinates are valid; missing, malformed and out-of-range values are not',()=>{
  assert.deepEqual(geo.location({lon:0,lat:0}),[0,0]);
  for(const value of [null,{},[],[1],['29','41'],[181,0],[0,91],[NaN,0],[Infinity,0],{lat:'',lon:null}])assert.equal(geo.location(value),null);
});
test('IPs and countries never fabricate coordinates',()=>{
  for(const raw of ['not JSON','{"ip":"8.8.8.8","country":"US"}','null','[]'])assert.deepEqual(geo.coordinates({raw}),{});
});
test('coverage counts events once and keeps evidence indices without copying raw logs into map data',()=>{
  const raw={source:{geo:{location:[29,41]}},destination:{geo:{location:[29,41]}},secret:'must-stay-out-of-map'};
  const events=[{raw:JSON.stringify(raw)},{raw:JSON.stringify(raw)},{raw:'bad'}];
  const result=geo.summarize(events);
  assert.equal(result.located,2);assert.equal(result.missing,1);assert.equal(result.groups.length,1);
  assert.deepEqual(result.groups[0].indices,[0,1]);
  assert.doesNotMatch(JSON.stringify(result),/must-stay-out-of-map/);
  assert.equal(events[0].raw,JSON.stringify(raw));
});
test('connections cross the dateline by the short path and require both endpoints',()=>{
  const r=geo.summarize([{raw:{source:{geo:{location:[170,0]}},destination:{geo:{location:[-170,1]}}}},{raw:{source:{geo:{location:[1,1]}}}}]);
  assert.equal(r.links.features.length,1);
  assert.equal(Math.abs(r.links.features[0].geometry.coordinates[0][0]-r.links.features[0].geometry.coordinates[1][0]),20);
});
