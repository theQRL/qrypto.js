import { defineConfig } from '@playwright/test';

const port = 4174;

export default defineConfig({
  testDir: './browser-tests',
  timeout: 600000,
  expect: {
    timeout: 600000,
  },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
  },
  webServer: {
    command: `node ../../scripts/browser-test-server.js --port ${port}`,
    port,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
