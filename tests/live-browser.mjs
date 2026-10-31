import assert from "node:assert/strict";
import { chromium } from "playwright";

const url = "https://dev.ahmetkaantanir.com/soc";
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errors = [];

page.on("pageerror", err => errors.push(err.message));
try {
  // Cloudflare deployments can be slightly behind the GitHub commit;
  // only proceed after the expected new demo button is present.
  let found = false;
  for (let i = 0; i < 9; i++) {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
    if (await page.locator("#demoWorkspace").count()) { found = true; break; }
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  assert.equal(found, true, "Latest SOC demo button has not reached the live site");
  await page.locator("#demoWorkspace").click();
  await page.waitForFunction(() => document.querySelector("#sEvents")?.textContent === "18", { timeout: 15000 });
  assert.equal(await page.locator("#eventsBody tr").count(), 18, "Synthetic demo event rows");
  assert.equal(await page.locator("#cases .case").count(), 2, "Synthetic demo case cards");
  assert.match(await page.locator("#message").textContent(), /ÖRNEK MODU/, "Demo must be clearly labeled");

  await page.locator("#fSource").selectOption("windows");
  await page.locator("#search").click();
  assert.equal(await page.locator("#eventsBody tr").count(), 12, "Filter should work");

  await page.locator("#caseStatus").selectOption("new");
  await page.waitForFunction(() => document.querySelectorAll("#cases .case").length === 1);
  const timeline = page.locator("#cases .case .case-actions button").nth(1);
  await timeline.click();
  assert.match(await page.locator("#caseEvidence").textContent(), /example-/, "Evidence timeline should open");

  assert.deepEqual(errors, [], "Client-side JavaScript errors");
  console.log("Browser E2E passed: live SOC demo, 18 synthetic events, 2 cases, filters, evidence, no JS exceptions.");
} finally {
  await browser.close();
}
