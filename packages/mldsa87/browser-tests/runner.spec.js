import { expect, test } from '@playwright/test';

const timeoutMs = 600000;
const logIntervalMs = 30000;

test('mldsa87 browser test suite', async ({ page }) => {
  const logs = [];
  page.on('console', (msg) => {
    const line = `[console:${msg.type()}] ${msg.text()}`;
    logs.push(line);
    console.log(`[mldsa87] ${line}`);
  });
  page.on('pageerror', (err) => {
    const line = `[pageerror] ${err.message || String(err)}`;
    logs.push(line);
    console.log(`[mldsa87] ${line}`);
  });

  await page.goto('/packages/mldsa87/browser-tests/runner.html');

  const start = Date.now();
  let lastLog = 0;
  let result = null;

  while (true) {
    result = await page.evaluate(() => window.__mochaDone);
    if (result) break;

    const elapsed = Date.now() - start;
    if (elapsed - lastLog >= logIntervalMs) {
      const progress = await page.evaluate(() => window.__mochaProgress);
      if (progress) {
        console.log(
          `[mldsa87] ${progress.passed} passed, ${progress.failed} failed, ` +
            `${progress.pending} pending, ${progress.started} started. ` +
            `Current: ${progress.current || 'unknown'}`,
        );
      } else {
        console.log('[mldsa87] waiting for mocha to start...');
      }
      lastLog = elapsed;
    }

    if (elapsed > timeoutMs) {
      const progress = await page.evaluate(() => window.__mochaProgress);
      const progressLine = progress
        ? `Progress: ${progress.passed} passed, ${progress.failed} failed, ${progress.pending} pending, ${progress.started} started. Current: ${progress.current || 'unknown'}`
        : 'Progress: unavailable';
      const logOutput = logs.length ? `\nConsole:\n${logs.join('\n')}` : '';
      throw new Error(`Browser tests timed out after ${timeoutMs}ms.\n${progressLine}${logOutput}`);
    }

    await page.waitForTimeout(1000);
  }

  const details = Array.isArray(result.details) ? result.details.join('\n') : '';
  const logOutput = logs.length ? `\nConsole:\n${logs.join('\n')}` : '';
  expect(result.failures, `${details}${logOutput}`).toBe(0);
});
