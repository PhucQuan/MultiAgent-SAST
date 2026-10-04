import { test, expect } from '@playwright/test';

test.describe('Aegis-SAST Dashboard & Security Workbench E2E Test Suite', () => {

  test.beforeEach(async ({ page }) => {
    // Access Aegis-SAST Dashboard at http://localhost:3000
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test('TC1_Dashboard_UI_and_Navigation', async ({ page }) => {
    // 1. Check Header / Brand logo & title
    const headerTitle = page.locator('span:has-text("Aegis-SAST")');
    await expect(headerTitle.first()).toBeVisible({ timeout: 10000 });

    const brandSubtitle = page.locator('text=Code Security Workbench');
    await expect(brandSubtitle.first()).toBeVisible();

    // 2. Check overview metrics in top bar / dashboard
    const actionableMetric = page.locator('text=Actionable');
    await expect(actionableMetric.first()).toBeVisible();

    const suppressedMetric = page.locator('text=Suppressed');
    await expect(suppressedMetric.first()).toBeVisible();

    // 3. Check Scan Inventory Section in sidebar
    const scanInventorySection = page.locator('text=SCAN INVENTORY');
    await expect(scanInventorySection.first()).toBeVisible();

    // 4. Check Findings table title / column header
    const findingsQueueTitle = page.locator('text=Findings');
    await expect(findingsQueueTitle.first()).toBeVisible();

    // 5. Check Vulnerability Details Pane
    const vulnDetailsPane = page.locator('text=Vulnerability Details');
    await expect(vulnDetailsPane.first()).toBeVisible();

    console.log('✓ Test Case 1 Passed: Giao diện Dashboard & các thành phần điều hướng hiển thị đầy đủ.');
  });

  test('TC2_Open_Modal_and_Trigger_Scan', async ({ page }) => {
    // 1. Click "Run Scan" button in TopBar
    const runScanButton = page.getByRole('button', { name: /Run Scan/i });
    await expect(runScanButton).toBeVisible();
    await runScanButton.click();

    // 2. Verify Scan Modal / Sheet opened
    const modalTitle = page.locator('#run-local-scan-title');
    await expect(modalTitle).toBeVisible();

    // 3. Enter Target Path: C:\2026-2027\NCKH\SAST_tool4pentester\examples
    const targetInput = page.locator('input[placeholder*="examples"]').first();
    await expect(targetInput).toBeVisible();
    await targetInput.fill('C:\\2026-2027\\NCKH\\SAST_tool4pentester\\examples');

    // 4. Click "Start scan" button inside modal
    const startScanButton = page.getByRole('button', { name: 'Start scan' });
    await expect(startScanButton).toBeVisible();
    await startScanButton.click();

    // 5. Wait for scan execution to complete
    await page.waitForTimeout(3000);
    await expect(startScanButton).toBeEnabled({ timeout: 30000 });

    // 6. Close / Hide panel modal
    const closeButton = page.getByRole('button', { name: /Close|Hide panel/i }).first();
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }

    console.log('✓ Test Case 2 Passed: Đã trigger scan mới thành công và hoàn tất.');
  });

  test('TC3_Scan_Inventory_and_Findings_Table', async ({ page }) => {
    // 1. Check Scan Inventory list has report items/cards
    const scanInventoryHeader = page.locator('text=SCAN INVENTORY');
    await expect(scanInventoryHeader.first()).toBeVisible();

    const inventoryItems = page.locator('button:has-text("findings"), button:has-text("vulnerable"), button:has-text("examples")');
    const itemCount = await inventoryItems.count();
    expect(itemCount).toBeGreaterThan(0);

    // Select the first inventory item
    await inventoryItems.first().click();
    await page.waitForTimeout(500);

    // 2. Interact with vulnerability family filter pills if available
    const cwe89Filter = page.locator('button:has-text("CWE-89")').first();
    if (await cwe89Filter.isVisible()) {
      await cwe89Filter.click({ force: true });
      await page.waitForTimeout(400);
      // Toggle back to all
      await cwe89Filter.click({ force: true });
      await page.waitForTimeout(400);
    }

    // 3. Verify Findings table has rows populated
    const findingRows = page.locator('table tbody tr, [role="row"]');
    const rowCount = await findingRows.count();
    console.log(`Found ${rowCount} finding rows in table.`);
    expect(rowCount).toBeGreaterThan(0);

    // Check presence of CWE tags (CWE-22, CWE-78, CWE-89, etc.)
    const cweTags = page.locator('text=/CWE-\\d+/');
    const cweCount = await cweTags.count();
    expect(cweCount).toBeGreaterThan(0);

    console.log('✓ Test Case 3 Passed: Tương tác Scan Inventory & Bảng Findings dữ liệu chính xác.');
  });

  test('TC4_Code_Viewer_and_Vulnerability_Details', async ({ page }) => {
    // 1. Select a finding row in table
    const findingRows = page.locator('table tbody tr, [role="row"]');
    await expect(findingRows.first()).toBeVisible();
    await findingRows.first().click();
    await page.waitForTimeout(600);

    // 2. Verify Vulnerability Details pane / Side drawer updates
    const detailsPane = page.locator('text=Vulnerability Details');
    await expect(detailsPane.first()).toBeVisible();

    // 3. Test Detail Tabs (Code, Remediation, Taint Flow, AI Analysis)
    const tabsToTest = ['Code', 'Remediation', 'Taint Flow', 'Overview'];
    for (const tabName of tabsToTest) {
      const tabButton = page.locator(`button:has-text("${tabName}")`).first();
      if (await tabButton.isVisible()) {
        await tabButton.click();
        await page.waitForTimeout(300);
      }
    }

    // 4. Verify presence of Rule ID / Remediation tips or Code snippet
    const codeSnippetOrRuleInfo = page.locator('text=/AEGIS-|CWE-|Rule|Remediation|Taint Flow/i');
    await expect(codeSnippetOrRuleInfo.first()).toBeVisible();

    console.log('✓ Test Case 4 Passed: Code Viewer & Vulnerability Details hiển thị đúng thông tin vi phạm.');
  });

});
