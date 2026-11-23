// Launches a Chromium-family browser for the Playwright tests.
// Order: the channel from the configuration (BF_BROWSER_CHANNEL), then
// Playwright's bundled Chromium, then an installed Edge or Chrome.
import { chromium } from 'playwright';

export async function launchBrowser(cfg, options = {}) {
  const attempts = [];
  if (cfg.browser_channel) attempts.push({ channel: cfg.browser_channel });
  attempts.push({}, { channel: 'msedge' }, { channel: 'chrome' });
  let lastError;
  for (const attempt of attempts) {
    try {
      const browser = await chromium.launch({ headless: true, ...attempt, ...options });
      browser.bfChannel = attempt.channel ?? 'chromium (bundled)';
      return browser;
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`No Chromium-family browser could be started. Run "npx playwright install chromium" or set BF_BROWSER_CHANNEL. ${lastError.message.split('\n')[0]}`);
}
