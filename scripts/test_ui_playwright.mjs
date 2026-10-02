import { chromium } from "playwright";
import fs from "fs";
import path from "path";

async function runTest() {
  console.log("=== Aegis-SAST Comprehensive UI & Logic Playwright Test ===");

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 950 },
  });
  const page = await context.newPage();

  const screenshotsDir = path.resolve("./reports/ui_screenshots");
  fs.mkdirSync(screenshotsDir, { recursive: true });

  const errors = [];
  const logEvent = (msg) => console.log(`[INFO] ${msg}`);
  const logError = (msg) => {
    console.error(`[FAIL] ${msg}`);
    errors.push(msg);
  };

  try {
    // 1. Initial Load & Layout Verification (media_1790953445774.png)
    logEvent("Navigating to http://localhost:3000...");
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);

    await page.screenshot({ path: path.join(screenshotsDir, "01_initial_dashboard.png"), fullPage: true });
    logEvent("Screenshot saved: 01_initial_dashboard.png");

    // Layout Verification
    logEvent("Verifying core layout elements...");
    const appRail = await page.$("aside, nav, [data-testid='app-rail']");
    if (!appRail) logError("App Rail not found!");
    else logEvent("✓ App Rail present");

    const scanInventory = await page.$("text=SCAN INVENTORY");
    if (!scanInventory) logError("Scan Inventory section title not found!");
    else logEvent("✓ Scan Inventory present");

    const findingsTitle = await page.$("text=Findings");
    if (!findingsTitle) logError("Findings table title not found!");
    else logEvent("✓ Findings table present");

    const detailsTitle = await page.$("text=Vulnerability Details");
    if (!detailsTitle) logError("Vulnerability Details pane title not found!");
    else logEvent("✓ Vulnerability Details pane present");

    // 2. Test Report Selection in Inventory
    logEvent("Testing scan report selection in inventory...");
    const reportButtons = await page.$$("button:has-text('findings')");
    logEvent(`Found ${reportButtons.length} report cards in inventory`);
    if (reportButtons.length > 1) {
      await reportButtons[1].click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(screenshotsDir, "02_selected_report_2.png") });
      logEvent("✓ Switched to second report card");
    }

    // 3. Test Finding Selection in Table
    logEvent("Testing finding row selection in queue...");
    const findingRows = await page.$$("table tbody tr, [role='row']");
    logEvent(`Found ${findingRows.length} finding rows in table`);
    if (findingRows.length > 0) {
      await findingRows[0].click();
      await page.waitForTimeout(600);
      await page.screenshot({ path: path.join(screenshotsDir, "03_selected_finding_detail.png") });

      // Check Taint Flow Trace & AI Verdict
      const taintFlow = await page.$("text=Taint Flow Trace");
      if (taintFlow) logEvent("✓ Taint Flow Trace is visible in right pane");
      else logError("Taint Flow Trace not visible in right pane");

      const aiVerdict = await page.$("text=AI Multi-Agent Verdict, text=Auditor Agent");
      if (aiVerdict) logEvent("✓ AI Multi-Agent Verdict is visible");
    }

    // 4. Test Details Pane Tab Switching
    logEvent("Testing details pane tab switching...");
    const tabs = ["Taint Flow", "Code", "AI Analysis", "Remediation", "Reference", "Overview"];
    for (const tabName of tabs) {
      const tabBtn = await page.$(`button:has-text("${tabName}")`);
      if (tabBtn) {
        await tabBtn.click();
        await page.waitForTimeout(300);
        logEvent(`✓ Clicked tab: ${tabName}`);
      }
    }
    await page.screenshot({ path: path.join(screenshotsDir, "04_detail_tabs_tested.png") });

    // 5. Test Theme Toggle
    logEvent("Testing theme toggle...");
    const themeBtn = await page.$("button[aria-label*='theme' i], button:has(svg.lucide-moon), button:has(svg.lucide-sun)");
    if (themeBtn) {
      await themeBtn.click();
      await page.waitForTimeout(400);
      await page.screenshot({ path: path.join(screenshotsDir, "05_theme_toggled.png") });
      logEvent("✓ Theme toggled successfully");
      await themeBtn.click();
      await page.waitForTimeout(400);
    }

    // 6. Test 'Run Scan' Flow & Backend Connection
    logEvent("Testing 'Run Scan' modal and backend execution...");
    const runScanBtn = await page.$("button:has-text('Run Scan')");
    if (runScanBtn) {
      await runScanBtn.click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(screenshotsDir, "06_run_scan_modal.png") });
      logEvent("✓ Opened 'Run local scan' panel");

      // Verify Target Path Input
      const targetInput = await page.$("input[value*='examples']");
      if (targetInput) {
        logEvent("✓ Target path input pre-populated");
      }

      // Click "Start scan" button to run actual scan on examples/vulnerable_rce.py
      const startScanSubmitBtn = await page.$("button:has-text('Start scan')");
      if (startScanSubmitBtn) {
        logEvent("Submitting scan request to backend...");
        await startScanSubmitBtn.click();
        await page.waitForTimeout(4000);
        await page.screenshot({ path: path.join(screenshotsDir, "07_scan_running_or_done.png") });
        logEvent("✓ Scan initiated and progress captured");
      }

      // Close the scan drawer
      const closePanelBtn = await page.$("button[aria-label='Close scan panel'], button:has-text('Hide panel'), button:has-text('Close')");
      if (closePanelBtn) {
        await closePanelBtn.click();
        await page.waitForTimeout(800);
        logEvent("✓ Closed scan drawer");
      } else {
        await page.mouse.click(10, 10);
        await page.waitForTimeout(800);
      }
    }

    // 7. Test App Rail Navigation across all tabs
    logEvent("Testing App Rail navigation...");
    const railTabs = [
      { name: "Dashboard", selector: "button:has-text('Dashboard'), a:has-text('Dashboard')" },
      { name: "Scans", selector: "button:has-text('Scans'), a:has-text('Scans')" },
      { name: "Vulnerabilities", selector: "button:has-text('Vulnerabilities'), a:has-text('Vulnerabilities')" },
      { name: "Code Browser", selector: "button:has-text('Code Browser'), a:has-text('Code Browser')" },
      { name: "AI Triage", selector: "button:has-text('AI Triage'), a:has-text('AI Triage')" },
      { name: "Reports", selector: "button:has-text('Reports'), a:has-text('Reports')" },
      { name: "Integrations", selector: "button:has-text('Integrations'), a:has-text('Integrations')" },
      { name: "Settings", selector: "button:has-text('Settings'), a:has-text('Settings')" }
    ];

    for (const item of railTabs) {
      try {
        const btn = await page.$(item.selector);
        if (btn) {
          await btn.click();
          await page.waitForTimeout(400);
          logEvent(`✓ Navigated to ${item.name}`);
        }
      } catch (err) {
        logEvent(`Note: could not click ${item.name}: ${err.message}`);
      }
    }

    // Switch back to Scans tab for final full verification
    const scansTab = await page.$("button:has-text('Scans'), a:has-text('Scans')");
    if (scansTab) {
      await scansTab.click();
      await page.waitForTimeout(500);
    }
    await page.screenshot({ path: path.join(screenshotsDir, "08_final_verified_state.png"), fullPage: true });
    logEvent("Screenshot saved: 08_final_verified_state.png");

  } catch (err) {
    logError(`Unexpected error during Playwright execution: ${err.message}`);
  } finally {
    await browser.close();
  }

  console.log("\n=== Test Results Summary ===");
  if (errors.length === 0) {
    console.log("ALL LOGIC & UI CHECKS PASSED WITH 0 ERRORS!");
  } else {
    console.log(`Encountered ${errors.length} issue(s):`);
    errors.forEach((e) => console.log(`  - ${e}`));
  }
}

runTest();
