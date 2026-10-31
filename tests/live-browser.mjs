import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.env.TEST_BASE_URL || "https://dev.ahmetkaantanir.com";
const browser = await chromium.launch({ headless: true });
for (const path of ["/", "/soc"]) {
const url = new URL(path, base).href;
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
await page.addInitScript(() => {
  window.socTestRoot = () => document.querySelector('#socMount')?.shadowRoot || document;
});
const errors = [];

page.on("pageerror", err => errors.push(err.message));
try {
  // Cloudflare deployments can be slightly behind the GitHub commit;
  // Wait for the atlas + hunting release rather than accepting an old SOC page.
  let found = false;
  for (let i = 0; i < 36; i++) {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
    if (path === '/') await page.locator('#soc-workspace').scrollIntoViewIfNeeded();
    await page.locator('#mapStyle').waitFor({ timeout: 20000 }).catch(() => {});
    if (await page.locator("#mapStyle").count() && await page.locator("#watchlist").count()) { found = true; break; }
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  assert.equal(found, true, "Atlas and hunting release has not reached the live site");
  await page.locator("#demoWorkspace").click();
  await page.waitForFunction(() => window.socTestRoot().querySelector("#sEvents")?.textContent === "18", null, { timeout: 15000 });
  assert.equal(await page.locator("#eventsBody tr").count(), 18, "Synthetic demo event rows");
  assert.equal(await page.locator("#cases .case").count(), 2, "Synthetic demo case cards");
  assert.equal(await page.locator("#huntPacks .hunt-card").count(), 6);
  assert.equal(await page.locator("#healthCards .health-card").count(), 3);
  assert.equal(await page.locator("#watchBody tr").count(), 1);
  await page.locator('#globe').scrollIntoViewIfNeeded();
  await page.waitForFunction(() => window.socTestRoot().querySelector('#globe').atlasMap?.isStyleLoaded(), null, { timeout: 20000 });
  const rotation = await page.evaluate(async () => {
    const root = window.socTestRoot(), map = root.querySelector('#globe').atlasMap;
    const toggle = root.querySelector('#globeToggle');
    if (toggle.getAttribute('aria-pressed') === 'true') toggle.click();
    const start = map.getCenter().lng;
    await new Promise(resolve => setTimeout(resolve, 900));
    const end = map.getCenter().lng;
    toggle.click();
    const stopped = map.getCenter().lng;
    await new Promise(resolve => setTimeout(resolve, 250));
    return { start, end, stopped, afterPause: map.getCenter().lng, projection: map.getProjection().type };
  });
  assert.equal(rotation.projection, 'globe');
  assert.notEqual(rotation.start, rotation.end, 'Globe must rotate');
  assert.equal(rotation.stopped, rotation.afterPause, 'Pause must stop rotation');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.locator('#countrySelect').selectOption('jp');
  await page.locator('#flyStreet').click();
  await page.waitForFunction(() => window.socTestRoot().querySelector('#globe').atlasMap.getZoom() === 16);
  assert.equal(await page.evaluate(() => window.socTestRoot().querySelector('#globe').atlasMap.getLayoutProperty('street', 'visibility')), 'visible');
  assert.match(await page.locator("#message").textContent(), /ÖRNEK MODU/, "Demo must be clearly labeled");

  await page.locator("#fSource").selectOption("windows");
  await page.locator("#search").click();
  assert.equal(await page.locator("#eventsBody tr").count(), 12, "Filter should work");

  await page.locator("#caseStatus").selectOption("new");
  await page.waitForFunction(() => window.socTestRoot().querySelectorAll("#cases .case").length === 1);
  const timeline = page.locator("#cases .case .case-actions button").nth(1);
  await timeline.click();
  assert.match(await page.locator("#caseEvidence").textContent(), /example-/, "Evidence timeline should open");

  for (const width of [360, 390, 768, 1024, 1440, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await page.locator('#globe').scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Page must fit ${width}px viewport`);
    assert.equal(await page.locator('#connect').evaluate(button => {
      const bounds = button.getBoundingClientRect();
      return bounds.left >= 0 && bounds.right <= innerWidth;
    }), true, `Connection button must fit ${width}px viewport`);
  }

  assert.deepEqual(errors, [], "Client-side JavaScript errors");
  console.log(`Browser E2E passed (${url}): rotation, pause, globe, street layer, hunting, filters, evidence and mobile layout.`);
} finally {
  await page.close();
}
}
await browser.close();
