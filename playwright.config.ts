import { defineConfig } from '@playwright/test';

const port = 4173;
const base = '/ot-iot-security-intelligence/';

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  retries: 0,
  forbidOnly: !!process.env.CI,
  use: {
    baseURL: `http://127.0.0.1:${port}${base}`,
    trace: 'off',
    launchOptions: process.env.PW_CHROMIUM_PATH
      ? { executablePath: process.env.PW_CHROMIUM_PATH }
      : undefined,
  },
  webServer: {
    // --host 127.0.0.1: i CI kan "localhost" annars bindas till IPv6 (::1) och hälsokontrollen mot
    // 127.0.0.1 får "connection refused" tills timeout.
    command: `npx vite preview --host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}${base}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
