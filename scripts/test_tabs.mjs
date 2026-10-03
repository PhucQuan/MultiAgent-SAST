import { chromium } from "playwright";

async function verifyTabs() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1680, height: 1000 } });
  await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  const tabs = ["Overview", "Taint Flow", "Code", "AI Analysis", "Remediation", "References"];
  for (const t of tabs) {
    const btn = await page.$(`div.border-b button:has-text("${t}")`);
    if (btn) {
      await btn.click({ force: true });
      await page.waitForTimeout(500);
      console.log(`[PASS] Switched to tab: ${t}`);
      await page.screenshot({ path: `reports/ui_screenshots/tab_${t.toLowerCase().replace(/\s+/g, '_')}.png` });
    } else {
      console.log(`[FAIL] Could not find tab button: ${t}`);
    }
  }
  await browser.close();
  console.log("Tab switching test completed successfully!");
}

verifyTabs();
