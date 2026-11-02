import assert from 'node:assert/strict';
import {chromium,expect} from 'playwright/test';
const base=process.env.TEST_BASE_URL||'http://127.0.0.1:5056',key=process.env.SOC_TEST_KEY||'v7-browser-test-token-longer-than-24-characters';
const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'tr-TR',reducedMotion:'reduce'});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
const open=async id=>{await page.locator('.navitem[href="#'+id+'"]').click();await expect(page.locator('#'+id)).toBeVisible();};
try{
  await page.goto(base+'/soc',{waitUntil:'domcontentloaded'});
  await expect(page.locator('#overview')).toBeVisible();
  await page.locator('#demoWorkspace').click();await expect(page.locator('#sEvents')).toHaveText('18');
  await expect(page.locator('#v7OverviewTimeline svg')).toHaveCount(1);
  await page.locator('#v7GlobalSearch').fill('192.0.2.25');await page.locator('#v7GlobalForm button').click();
  await expect(page.locator('#v7GlobalResults')).toContainText('18 olay');
  await page.locator('#v7GlobalResults .v7-record').first().click();
  await expect(page.locator('#v7EvidenceDrawer')).toBeVisible();await expect(page.locator('#v7ContextTokens')).toContainText('192.0.2.25');
  await page.locator('#v7EvidenceCharts').click();await expect(page.locator('#grafana-view')).toBeVisible();
  await expect(page.locator('#v7ChartTimeline svg')).toHaveCount(1);
  await open('copilot');await page.locator('[data-question]').first().click();await page.locator('#v7Ask').click();
  await expect(page.locator('#v7CopilotResult')).toContainText('olay eşleşti');
  // Real private API: same IDs across batches, case creation and research state.
  const host='v7-browser-'+Date.now(),t=Date.now()-60000;
  const lines=Array.from({length:10},(_,i)=>JSON.stringify({timestamp:new Date(t+i*1000).toISOString(),EventID:4625,ip:'192.0.2.17',host,user:'v7-user'}));
  for(const raw_logs of [lines.slice(0,5).join('\n'),lines.slice(5).join('\n')]){
    const r=await page.request.post(base+'/api/soc/ingest',{headers:{'X-API-Key':key},data:{raw_logs}});assert.equal(r.status(),201);
  }
  await page.locator('#apiKey').fill(key);await page.locator('#connect').click();await expect(page.locator('#connection')).toContainText('Güvenli');
  await open('explorer');await page.locator('#fHost').fill(host);await page.locator('#search').click();await expect(page.locator('#eventsBody tr')).toHaveCount(10);
  await page.locator('#eventsBody input[type=checkbox]').nth(0).check();await page.locator('#eventsBody input[type=checkbox]').nth(1).check();
  await page.locator('#v7CaseTitle').fill('V7 browser evidence');await page.locator('#v7CreateCase').click();await expect(page.locator('#cases-section')).toBeVisible();
  await expect(page.locator('#v7Assignments .v7-record')).not.toHaveCount(0);
  await open('investigations');await page.locator('#v7InvestigationTitle').fill('Browser investigation '+host);await page.locator('#v7InvestigationNotes').fill('Evidence-linked research');
  await page.locator('#v7SaveInvestigation').click();await expect(page.locator('#v7InvestigationList')).toContainText(host);
  await open('network-lab');await page.locator('#v7Projects').click();await expect(page.locator('#v7NetworkState')).toContainText('yapılandırılmadı');
  await open('endpoints');await page.locator('#v7Agents').click();await expect(page.locator('#v7AgentState')).toContainText('yapılandırılmadı');
  await open('evidence-center');await page.locator('#v7ReloadCustody').click();await expect(page.locator('#v7CustodyStatus')).toContainText('doğrulandı');
  await open('grafana-view');await page.locator('#v7RunCharts').click();await expect(page.locator('#v7ChartMetrics')).toContainText('10');
  // Private Loki data stays in-site; no popup navigation is needed.
  await page.route('**/api/soc/workspace/loki',route=>route.fulfill({json:{items:[{event_id:'loki-test',source:'windows',host,raw:lines[0],timestamp:new Date(t).toISOString(),loki_timestamp:String(BigInt(Date.now())*1000000n),outcome:'failure',action:'login',provenance:'loki'}],series:[],state:'ready'}}));
  await page.locator('#v7ChartSource').selectOption('loki');await page.locator('#v7RunCharts').click();await expect(page.locator('#v7ChartLogs')).toContainText(host);assert.equal(page.url(),base+'/soc');
  for(const width of [360,768,1440]){await page.setViewportSize({width,height:900});await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'V7 overflow '+width);}
  // Main-page upload -> local workspace uses the uploaded records, not the synthetic demo.
  await page.goto(base,{waitUntil:'domcontentloaded'});
  await page.locator('#rawLogs').fill(lines[0]);await page.locator('#runAnalysis').click();await expect(page.locator('#dashboard')).toBeVisible();
  await page.locator('#soc-workspace').scrollIntoViewIfNeeded();await expect(page.locator('#socMount')).toHaveAttribute('data-ready','true');
  await page.locator('#v7OpenPreview').click();await expect(page.locator('#v7Mode')).toHaveText('SEKME ANALİZİ');await expect(page.locator('#sEvents')).toHaveText('1');
  await page.locator('.navitem[href="#grafana-view"]').click();await expect(page.locator('#v7ChartLogs')).toContainText(host);
  const raw=await page.locator('#v7ChartLogs').textContent();await page.locator('#languageSelect').selectOption('en');assert.equal(await page.locator('#v7ChartLogs').textContent(),raw,'Evidence survives language changes');
  assert.deepEqual(errors,[]);
  console.log('V7 passed: site-contained graphs, context, Copilot, global search, canonical ingest, cases, saved research, custody, offline services, local upload handoff and responsive layouts.');
}catch(error){console.error('V7 browser errors:',errors);throw error;}finally{await browser.close();}
