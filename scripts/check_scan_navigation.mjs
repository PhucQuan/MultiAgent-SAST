import assert from "node:assert/strict";
import { chromium } from "playwright";

const baseUrl = process.env.BASE_URL || "http://localhost:3000";
const scanId = process.env.SCAN_ID;

if (!scanId) {
  throw new Error("Set SCAN_ID to a completed persisted scan before running this check.");
}

const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage();
const findingsUrl = `${baseUrl}/scans/${scanId}/findings?report=${encodeURIComponent(`api:${scanId}`)}&status=actionable`;
const records = [];
async function waitForRoute(pattern) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (pattern.test(page.url())) {
      return;
    }
    await page.waitForTimeout(500);
  }
  assert.match(page.url(), pattern);
}

try {
  await page.goto(findingsUrl);
  await page.getByText(/Completed report/).waitFor({ timeout: 30000 });
  await page.locator("tbody tr").nth(11).waitFor({ timeout: 30000 });
  await page.waitForTimeout(1000);

  for (let index = 0; index < 5; index += 1) {
    await page.locator("tbody tr").nth(index).dispatchEvent("click");
    await waitForRoute(/\/scans\/[^/]+\/findings\/[^/?]+/);
    await page.getByText("Loading verified source-to-sink evidence...").waitFor({
      state: "detached",
      timeout: 30000,
    }).catch(() => undefined);

    const detailText = await page.locator("main").innerText();
    records.push({
      url: page.url(),
      heading: await page.locator("h1").first().innerText(),
      trace: detailText.match(/Source to Sink\)[\s\S]{0,700}/)?.[0] || detailText,
    });

    await page.getByRole("button", { name: "Back to Findings", exact: true }).click();
    await waitForRoute(/\/scans\/[^/]+\/findings\?/);
    await page.locator("tbody tr").nth(11).waitFor({ timeout: 30000 });
    assert.match(page.url(), /status=actionable/);
    assert.ok(!page.url().includes("page=") || page.url().includes("page=1"));
  }

  assert.equal(new Set(records.map((record) => record.url)).size, 5);
  assert.equal(new Set(records.map((record) => record.trace)).size, 5);

  await page.goto(`${findingsUrl}&page=2`, { waitUntil: "networkidle" });
  await page.locator("tbody tr").nth(11).waitFor({ timeout: 30000 });
  await page.locator("tbody tr").first().dispatchEvent("click");
  await waitForRoute(/\/scans\/[^/]+\/findings\/[^/?]+/);
  const pageTwoDetailUrl = page.url();
  await page.reload({ waitUntil: "networkidle" });
  await page.getByText("Loading verified source-to-sink evidence...").waitFor({
    state: "detached",
    timeout: 30000,
  }).catch(() => undefined);
  assert.notEqual(await page.locator("h1").first().innerText(), "Vulnerability Investigation");

  await page.goBack();
  await waitForRoute(/\/scans\/[^/]+\/findings\?/);
  assert.match(page.url(), /page=2/);
  await page.locator("tbody tr").nth(11).waitFor({ timeout: 30000 });
  const backUrl = page.url();
  await page.goForward();
  await waitForRoute(/\/scans\/[^/]+\/findings\/[^/?]+/);
  assert.equal(page.url(), pageTwoDetailUrl);

  console.log("Scan navigation browser regression passed.");
} finally {
  await browser.close();
}
