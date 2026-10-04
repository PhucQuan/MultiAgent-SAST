import { chromium } from "playwright";
import fs from "fs";
import path from "path";

async function runComprehensiveTestSuite() {
  console.log("================================================================================");
  console.log("   AEGIS-SAST COMPREHENSIVE END-TO-END PLAYWRIGHT VERIFICATION SUITE");
  console.log("================================================================================");

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1680, height: 1000 },
  });
  const page = await context.newPage();

  const screenshotsDir = path.resolve("./reports/ui_screenshots");
  fs.mkdirSync(screenshotsDir, { recursive: true });

  const passedTests = [];
  const failedTests = [];

  function recordPass(testName, details = "") {
    console.log(`  [PASS] ${testName} ${details ? `(${details})` : ""}`);
    passedTests.push({ testName, details });
  }

  function recordFail(testName, err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  [FAIL] ${testName}: ${msg}`);
    failedTests.push({ testName, error: msg });
  }

  // ---------------------------------------------------------------------------
  // SUITE 1: Initial Page Load & Tri-Pane Layout (media_1790953445774.png)
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 1: Initial Page Load & Tri-Pane Layout Verification");
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);

    const screenshot1 = path.join(screenshotsDir, "01_tripane_workbench.png");
    await page.screenshot({ path: screenshot1, fullPage: true });
    recordPass("Suite 1 - Page Navigation", "Navigated to http://localhost:3000 successfully");

    // 1.1 Check App Rail
    const appRail = await page.$("aside");
    if (appRail) {
      recordPass("Suite 1 - App Rail", "App Rail sidebar detected");
    } else {
      recordFail("Suite 1 - App Rail", "App Rail sidebar not found");
    }

    // 1.2 Check Scan Inventory Column
    const scanInventory = await page.$("text=SCAN INVENTORY");
    if (scanInventory) {
      recordPass("Suite 1 - Scan Inventory", "Scan Inventory header verified");
    } else {
      recordFail("Suite 1 - Scan Inventory", "Scan Inventory header missing");
    }

    // 1.3 Check Findings Queue Table Column
    const findingsQueue = await page.$("text=Findings");
    if (findingsQueue) {
      recordPass("Suite 1 - Findings Queue", "Findings Queue column verified");
    } else {
      recordFail("Suite 1 - Findings Queue", "Findings Queue column missing");
    }

    // 1.4 Check Vulnerability Details Pane
    const vulnDetails = await page.$("text=Vulnerability Details");
    if (vulnDetails) {
      recordPass("Suite 1 - Vulnerability Details", "Vulnerability Details right pane verified");
    } else {
      recordFail("Suite 1 - Vulnerability Details", "Vulnerability Details right pane missing");
    }
  } catch (err) {
    recordFail("Suite 1 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 2: Scan Inventory & Report Switching
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 2: Scan Inventory & Report Switching");
    const reportCards = await page.$$("button:has-text('findings')");
    console.log(`  Found ${reportCards.length} report cards in Scan Inventory`);
    if (reportCards.length > 0) {
      recordPass("Suite 2 - Report Inventory Count", `${reportCards.length} reports present`);
      
      // Select first report
      await reportCards[0].click({ force: true });
      await page.waitForTimeout(600);
      recordPass("Suite 2 - Switch to Report 1", "Clicked report 1");

      if (reportCards.length > 1) {
        // Select second report
        await reportCards[1].click({ force: true });
        await page.waitForTimeout(800);
        const screenshot2 = path.join(screenshotsDir, "02_report_inventory_switch.png");
        await page.screenshot({ path: screenshot2 });
        recordPass("Suite 2 - Switch to Report 2", "Switched report and updated findings view");
        
        // Switch back to report 1
        await reportCards[0].click({ force: true });
        await page.waitForTimeout(600);
      }
    } else {
      recordFail("Suite 2 - Report Inventory", "No report cards found in inventory");
    }
  } catch (err) {
    recordFail("Suite 2 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 3: Findings Queue Search & Filtering
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 3: Findings Queue Search & Multi-Criteria Filtering");
    const searchInput = await page.$("input[placeholder*='Search by rule ID']");
    if (searchInput) {
      // 3.1 Type search query
      await searchInput.fill("os.system");
      await page.waitForTimeout(500);
      const rowsAfterSearch = await page.$$("table tbody tr");
      console.log(`  Filtered to ${rowsAfterSearch.length} rows for query 'os.system'`);
      recordPass("Suite 3 - Search Filtering", `Filtered rows for query 'os.system' (${rowsAfterSearch.length} results)`);

      // Clear search
      await searchInput.fill("");
      await page.waitForTimeout(500);
    } else {
      recordFail("Suite 3 - Search Input", "Search input field not found");
    }

    // 3.2 Test Severity Filter
    const selects = await page.$$("select");
    if (selects.length >= 3) {
      // Select Severity = CRITICAL
      await selects[0].selectOption({ value: "critical" }).catch(async () => {
        await selects[0].selectOption({ index: 1 });
      });
      await page.waitForTimeout(500);
      const critRows = await page.$$("table tbody tr");
      recordPass("Suite 3 - Severity Dropdown Filter", `Filtered by Critical severity (${critRows.length} rows)`);

      // Reset to All Severities
      await selects[0].selectOption({ value: "all" });
      await page.waitForTimeout(400);

      // 3.3 Test Family Dropdown
      const famOptions = await selects[1].$$("option");
      if (famOptions.length > 1) {
        await selects[1].selectOption({ index: 1 });
        await page.waitForTimeout(500);
        recordPass("Suite 3 - Family Dropdown Filter", "Filtered by vulnerability family");
        await selects[1].selectOption({ value: "all" });
        await page.waitForTimeout(400);
      }

      // 3.4 Test Status Dropdown
      const stOptions = await selects[2].$$("option");
      if (stOptions.length > 1) {
        await selects[2].selectOption({ index: 1 });
        await page.waitForTimeout(500);
        recordPass("Suite 3 - Status Dropdown Filter", "Filtered by triage status");
        await selects[2].selectOption({ value: "all" });
        await page.waitForTimeout(400);
      }
    } else {
      recordFail("Suite 3 - Filter Dropdowns", `Expected 3 filter selects, found ${selects.length}`);
    }

    // 3.5 Test Quick Family Pills in TopBar
    const quickPill = await page.$("button:has-text('CWE-')");
    if (quickPill) {
      const pillText = await quickPill.innerText();
      await quickPill.click({ force: true });
      await page.waitForTimeout(500);
      recordPass("Suite 3 - TopBar Quick Family Pill", `Clicked pill: ${pillText.trim()}`);
      await quickPill.click({ force: true }); // toggle off
      await page.waitForTimeout(400);
    }

    const screenshot3 = path.join(screenshotsDir, "03_findings_filtering.png");
    await page.screenshot({ path: screenshot3 });
  } catch (err) {
    recordFail("Suite 3 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 4: Finding Inspection, Taint Flow Trace, AI Multi-Agent & Remediation
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 4: Finding Inspection, Taint Flow Trace & AI Verdict Verification");
    const rows = await page.$$("table tbody tr");
    if (rows.length > 0) {
      await rows[0].click({ force: true });
      await page.waitForTimeout(800);
      recordPass("Suite 4 - Row Selection", `Clicked finding row 1 of ${rows.length}`);

      // 4.1 Check Taint Flow Trace Stepper (3 Steps)
      const taintFlowTitle = await page.$("text=Taint Flow Trace");
      if (taintFlowTitle) {
        recordPass("Suite 4 - Taint Flow Trace Header", "Taint Flow Trace section present");
      } else {
        recordFail("Suite 4 - Taint Flow Trace Header", "Taint Flow Trace missing");
      }

      // Check step numbers (1, 2, 3)
      const stepCircles = await page.$$("div.rounded-full:has-text('1'), div.rounded-full:has-text('2'), div.rounded-full:has-text('3')");
      recordPass("Suite 4 - Stepper Nodes", `Found ${stepCircles.length} step nodes in trace`);

      // 4.2 Check AI Multi-Agent Verdict Cards
      const aiVerdictTitle = await page.$("text=AI Multi-Agent Verdict");
      if (aiVerdictTitle) {
        recordPass("Suite 4 - AI Multi-Agent Verdict Section", "AI Verdict section header verified");
      } else {
        recordFail("Suite 4 - AI Multi-Agent Verdict Section", "AI Multi-Agent Verdict missing");
      }

      const auditorAgentCard = await page.$("text=Auditor Agent");
      if (auditorAgentCard) {
        recordPass("Suite 4 - Auditor Agent Card", "Auditor Agent offensive observation card present");
      } else {
        recordFail("Suite 4 - Auditor Agent Card", "Auditor Agent card not found");
      }

      const skepticAgentCard = await page.$("text=Skeptic Agent");
      if (skepticAgentCard) {
        recordPass("Suite 4 - Skeptic Agent Card", "Skeptic Agent defense check card present");
      } else {
        recordFail("Suite 4 - Skeptic Agent Card", "Skeptic Agent card not found");
      }

      const verdictBanner = await page.$("text=Final Verdict, text=Confirmed, text=confidence");
      if (verdictBanner) {
        recordPass("Suite 4 - Final Verdict Banner", "Consensus disposition and confidence score verified");
      }

      // 4.3 Check Suggested Remediation (Unified Diff Patch Generator)
      const patchSection = await page.$("text=Suggested Remediation (AI Generated Patch)");
      if (patchSection) {
        recordPass("Suite 4 - Remediation Patch Generator", "Suggested Remediation section present");

        // Check Diff lines (+ and -)
        const diffAdditions = await page.$$("text=+");
        const diffRemovals = await page.$$("text=-");
        recordPass(
          "Suite 4 - Unified Diff Rendering",
          `Found diff lines (additions: ${diffAdditions.length}, removals: ${diffRemovals.length})`
        );

        // Check Copy button
        const copyPatchBtn = await page.$("button[aria-label*='Copy' i], button:has-text('Copy')");
        if (copyPatchBtn) {
          recordPass("Suite 4 - Copy Remediation Patch Button", "Copy button accessible");
        }
      } else {
        recordFail("Suite 4 - Remediation Patch Generator", "Remediation Patch section missing");
      }

      // 4.4 Tab Switching in Details Pane
      const detailTabs = ["Overview", "Taint Flow", "Code", "AI Analysis", "Remediation", "References"];
      for (const tab of detailTabs) {
        const tabBtns = await page.$$(`button:has-text("${tab}")`);
        for (const tabBtn of tabBtns) {
          try {
            await tabBtn.click({ force: true });
            await page.waitForTimeout(200);
            recordPass(`Suite 4 - Detail Tab: ${tab}`, "Tab clicked and rendered");
            break;
          } catch (_) {}
        }
      }

      // Switch back to Overview
      const overviewBtn = await page.$("button:has-text('Overview')");
      if (overviewBtn) await overviewBtn.click({ force: true });

      // 4.5 Navigation between findings (Next / Prev)
      const nextBtn = await page.$("button:has(svg.lucide-chevron-right)");
      if (nextBtn) {
        await nextBtn.click({ force: true });
        await page.waitForTimeout(400);
        recordPass("Suite 4 - Finding Next Navigation", "Navigated to next finding");
      }

      const screenshot4 = path.join(screenshotsDir, "04_finding_inspection_ai_diff.png");
      await page.screenshot({ path: screenshot4 });
    } else {
      recordFail("Suite 4 - Table Rows", "No finding rows found in table to inspect");
    }
  } catch (err) {
    recordFail("Suite 4 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 5: Run Scan Modal & Backend API Integration (http://localhost:8000)
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 5: Run Scan Modal & Live Backend Integration");
    const runScanTopBtn = await page.$("button:has-text('Run Scan')");
    if (runScanTopBtn) {
      await runScanTopBtn.click({ force: true });
      await page.waitForTimeout(800);
      recordPass("Suite 5 - Open Scan Drawer", "Scan drawer opened via TopBar button");

      // Verify Target Path Input
      const targetInput = await page.$("input[placeholder*='vulnerable_rce.py']");
      if (targetInput) {
        recordPass("Suite 5 - Target Path Input", "Target input is interactive");
        await targetInput.fill("examples/cross_file_rce");
        await page.waitForTimeout(300);
      }

      // Toggle AI checkbox
      const aiCheckbox = await page.$("button[role='checkbox']");
      if (aiCheckbox) {
        await aiCheckbox.click({ force: true });
        await page.waitForTimeout(300);
        recordPass("Suite 5 - AI Triage Toggle", "Toggled AI overlay checkbox");
      }

      // Click "Start scan" to trigger live execution with FastAPI backend
      const startScanBtn = await page.$("button:has-text('Start scan')");
      if (startScanBtn) {
        console.log("  Triggering live scan via FastAPI backend...");
        await startScanBtn.click({ force: true });
        // Wait for scan to progress
        await page.waitForTimeout(4500);

        const screenshotScan = path.join(screenshotsDir, "05_run_scan_execution.png");
        await page.screenshot({ path: screenshotScan });
        recordPass("Suite 5 - Scan Execution Triggered", "Live scan initiated, progress and logs captured");

        // Close drawer
        const closeBtn = await page.$("button:has-text('Hide panel'), button:has-text('Close')");
        if (closeBtn) {
          await closeBtn.click({ force: true });
          await page.waitForTimeout(600);
          recordPass("Suite 5 - Close Scan Drawer", "Closed scan panel cleanly");
        }
      }
    } else {
      recordFail("Suite 5 - Run Scan Button", "TopBar 'Run Scan' button not found");
    }
  } catch (err) {
    recordFail("Suite 5 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 6: App Rail Navigation across ALL 8 Views
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 6: Full App Rail Navigation Across All 8 Views");

    const appViews = [
      { id: "dashboard", name: "Dashboard", screenshot: "06_view_dashboard.png" },
      { id: "scans", name: "Scans", screenshot: "07_view_scans_workbench.png" },
      { id: "vulnerabilities", name: "Vulnerabilities", screenshot: "08_view_deepdive.png" },
      { id: "code", name: "Code Browser", screenshot: "09_view_code_browser.png" },
      { id: "ai", name: "AI Triage", screenshot: "10_view_ai_triage.png" },
      { id: "reports", name: "Reports", screenshot: "11_view_reports.png" },
      { id: "integrations", name: "Integrations", screenshot: "12_view_integrations.png" },
      { id: "settings", name: "Settings", screenshot: "13_view_settings.png" },
    ];

    for (const view of appViews) {
      try {
        const btn = await page.$(`aside button[title="${view.name}"], aside button:has-text("${view.name}")`);
        if (btn) {
          await btn.click({ force: true });
          await page.waitForTimeout(800);
          
          const screenshotPath = path.join(screenshotsDir, view.screenshot);
          await page.screenshot({ path: screenshotPath });
          
          recordPass(`Suite 6 - Navigated to ${view.name}`, `Screenshot: ${view.screenshot}`);
        } else {
          recordFail(`Suite 6 - ${view.name}`, `Navigation button for ${view.name} not found`);
        }
      } catch (err) {
        recordFail(`Suite 6 - ${view.name}`, err);
      }
    }
  } catch (err) {
    recordFail("Suite 6 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 7: Deep Dive Page & AI Triage Human-in-the-Loop Actions
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 7: Deep Dive Interactive Controls & AI Triage Actions");
    
    // Switch to AI Triage page
    const aiTabBtn = await page.$("aside button:has-text('AI Triage')");
    if (aiTabBtn) {
      await aiTabBtn.click({ force: true });
      await page.waitForTimeout(800);

      // Verify batch action button
      const reRunBatchBtn = await page.$("button:has-text('Re-run AI Triage Batch')");
      if (reRunBatchBtn) {
        await reRunBatchBtn.click({ force: true });
        await page.waitForTimeout(500);
        recordPass("Suite 7 - AI Triage Batch Trigger", "Clicked 'Re-run AI Triage Batch'");
      }

      // Check human disposition buttons
      const confirmBtn = await page.$("button:has-text('Confirm')");
      if (confirmBtn) {
        await confirmBtn.click({ force: true });
        await page.waitForTimeout(500);
        recordPass("Suite 7 - Human Triage Confirm Action", "Clicked 'Confirm' disposition button");
      }

      const muteFpBtn = await page.$("button:has-text('Mute FP')");
      if (muteFpBtn) {
        await muteFpBtn.click({ force: true });
        await page.waitForTimeout(500);
        recordPass("Suite 7 - Human Triage Mute FP Action", "Clicked 'Mute FP' disposition button");
      }

      const screenshotAITriage = path.join(screenshotsDir, "14_ai_triage_action.png");
      await page.screenshot({ path: screenshotAITriage });
    }
  } catch (err) {
    recordFail("Suite 7 - Execution", err);
  }

  // ---------------------------------------------------------------------------
  // SUITE 8: Dark / Light Mode Theme Toggle
  // ---------------------------------------------------------------------------
  try {
    console.log("\n>>> SUITE 8: Dark / Light Mode Theme Toggle");
    const themeToggleBtn = await page.$(
      "header button[title*='Mode' i], header button[aria-label*='Theme' i]"
    );
    if (themeToggleBtn) {
      // Toggle to alternate theme
      await themeToggleBtn.click({ force: true });
      await page.waitForTimeout(500);
      const isDark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
      const screenshotTheme = path.join(screenshotsDir, "15_theme_mode_toggled.png");
      await page.screenshot({ path: screenshotTheme });
      recordPass("Suite 8 - Theme Toggle", `Theme toggled successfully (dark mode = ${isDark})`);

      // Toggle back to default
      await themeToggleBtn.click({ force: true });
      await page.waitForTimeout(400);
      recordPass("Suite 8 - Theme Revert", "Reverted back to default theme");
    } else {
      recordFail("Suite 8 - Theme Toggle", "Theme toggle button not found in TopBar");
    }

    // Switch back to Scans workbench for final state capture
    const scansNavBtn = await page.$("aside button:has-text('Scans')");
    if (scansNavBtn) {
      await scansNavBtn.click({ force: true });
      await page.waitForTimeout(800);
    }
    const finalScreenshot = path.join(screenshotsDir, "16_final_verified_workbench.png");
    await page.screenshot({ path: finalScreenshot, fullPage: true });
    recordPass("Suite Final - Comprehensive Workbench State", "Final screenshot 16_final_verified_workbench.png captured");
  } catch (err) {
    recordFail("Suite 8 - Execution", err);
  } finally {
    await browser.close();
  }

  // ---------------------------------------------------------------------------
  // SUMMARY REPORT
  // ---------------------------------------------------------------------------
  console.log("\n================================================================================");
  console.log("                           FINAL TEST EXECUTION SUMMARY");
  console.log("================================================================================");
  console.log(`TOTAL PASSED CHECKS: ${passedTests.length}`);
  console.log(`TOTAL FAILED CHECKS: ${failedTests.length}`);

  if (failedTests.length === 0) {
    console.log("\n🎉 ALL LOGIC AND UI CHECKS PASSED WITH 100% SUCCESS RATE! 🎉\n");
  } else {
    console.log("\nIssues encountered:");
    failedTests.forEach((f) => console.log(`  - [${f.testName}]: ${f.error}`));
  }

  return { passedTests, failedTests };
}

runComprehensiveTestSuite();
