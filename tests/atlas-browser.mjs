import assert from 'node:assert/strict';
import {chromium,expect}from'playwright/test';
const base=process.env.TEST_BASE_URL||'http://127.0.0.1:5056';
const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'tr-TR',reducedMotion:'reduce'});
const errors=[],tileRequests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/tiles\.maps\.eox|tile\.openstreetmap/.test(r.url()))tileRequests.push(r.url());});
try{
  await page.goto(new URL('/soc',base).href,{waitUntil:'domcontentloaded'});
  await page.locator('#globe').scrollIntoViewIfNeeded();
  await page.waitForFunction(()=>document.querySelector('#globe').atlasMap?.isStyleLoaded());
  await expect(page.locator('#geoCoverage')).toContainText('0 / 0');
  assert.equal(await page.locator('.event-pin').count(),0);
  await page.locator('#demoWorkspace').click();await expect(page.locator('#geoCoverage')).toContainText('3 / 18');
  assert.equal(await page.locator('.event-pin').count(),4);
  assert.equal(await page.locator('.event-pin-mixed').count(),1);
  assert.equal(tileRequests.length,0,'Local analytical globe must not require external tiles');
  const connections=await page.evaluate(()=>{
    const data=document.querySelector('#globe').atlasMap.getSource('event-connections').serialize().data;
    return typeof data==='string'?JSON.parse(data):data;
  });
  assert.equal(connections.features.length,3);
  assert.doesNotMatch(JSON.stringify(connections),/192\.0\.2|SYNTHETIC DEMO|raw/,'Map features must not contain raw logs or IPs');
  await page.locator('.geo-location').first().click();
  await expect(page.locator('#geoDetail')).toContainText('source.geo.location');
  await page.locator('.geo-evidence').first().click();
  await expect(page.locator('#explorer')).toBeVisible();
  const evidence=JSON.parse(await page.locator('#evidence').textContent());
  assert.equal(evidence.event_id,'example-016');assert.equal(JSON.parse(evidence.raw).synthetic,true);
  await page.locator('#evidenceActions button').filter({hasText:'Çevre olayları'}).click();
  const downloadPromise=page.waitForEvent('download');await page.locator('#exportEvents').click();
  const stream=await(await downloadPromise).createReadStream();const chunks=[];for await(const chunk of stream)chunks.push(chunk);
  const exported=JSON.parse(Buffer.concat(chunks).toString());
  assert.equal(exported.synthetic,true);assert.equal(exported.count,18);assert.equal(exported.scope,'current_page_only');
  assert.equal(exported.filters.start,'2026-10-31T08:58:00.000Z');assert.equal(exported.filters.end,'2026-10-31T09:08:00.000Z');
  await page.locator('#fSource').selectOption('windows');await page.locator('#search').click();
  await page.locator('.navitem[href="#intelligence"]').click();
  await expect(page.locator('#geoCoverage')).toContainText('0 / 12');assert.equal(await page.locator('.event-pin').count(),0);
  await expect(page.locator('#geoDetail')).toContainText('Koordinat bulunamadı.');await expect(page.locator('#flyCity')).toBeDisabled();
  await page.locator('#languageSelect').selectOption('en');await expect(page.locator('#geoDetail')).toContainText('No coordinates found.');
  await page.locator('#atlasMode').selectOption('reference');await page.locator('#countrySelect').selectOption('jp');
  await expect(page.locator('#countryDetail h3')).toHaveText('Japan');await expect(page.locator('#geoCoverage')).toContainText('0 / 12');
  for(const width of [360,390,768,1024,1440]){
    await page.setViewportSize({width,height:900});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${width}px atlas overflow`);
  }
  await page.route('**/vendor/maplibre/maplibre-gl-csp.js',route=>route.abort());
  await page.goto(new URL('/soc',base).href,{waitUntil:'domcontentloaded'});
  await page.locator('#demoWorkspace').click();await expect(page.locator('#geoCoverage')).toContainText('3 / 18');
  await page.locator('.geo-location').first().click();await page.locator('.geo-evidence').first().click();
  await expect(page.locator('#evidence')).toContainText('example-016');
  assert.deepEqual(errors,[]);
  console.log('Atlas passed: declared coordinates, coverage, local basemap, no fabricated GeoIP, raw evidence, context/export filters, EN, mobile and WebGL fallback.');
}catch(error){console.error('Client exceptions:',errors);throw error;}finally{await browser.close();}
