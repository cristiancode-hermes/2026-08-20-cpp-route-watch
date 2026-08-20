import puppeteer from 'puppeteer';
import { mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function resolveChrome() {
  const candidates = [
    '/opt/data/.agent-browser/browsers/chromium/chrome-linux/chrome',
    '/opt/data/.agent-browser/browsers/chrome-149.0.7827.55/chrome',
    '/opt/data/chrome-linux64/chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return undefined;
}

async function captureCppTerminal() {
  const htmlPath = join(__dirname, 'screenshot.html');
  const assetsDir = '/opt/data/portafolio/public/assets';
  mkdirSync(assetsDir, { recursive: true });

  const executablePath = resolveChrome();
  const browser = await puppeteer.launch({
    executablePath,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });

  try {
    const page = await browser.newPage();

    // Desktop
    await page.setViewport({ width: 1440, height: 1200 });
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0', timeout: 20000 });
    await page.waitForSelector('.terminal', { timeout: 5000 });
    await new Promise(r => setTimeout(r, 800));

    const terminalEl = await page.$('.terminal');
    const box = await terminalEl.boundingBox();
    const deskH = Math.min(Math.ceil(box.height + 40), 1200);

    await page.screenshot({
      path: join(assetsDir, 'route-watch.png'),
      clip: {
        x: Math.max(0, box.x - 40),
        y: Math.max(0, box.y - 20),
        width: Math.min(box.width + 80, 1440),
        height: deskH,
      },
    });
    console.log('Desktop screenshot saved: route-watch.png', 'h=', deskH);

    // Mobile
    await page.setViewport({ width: 390, height: 1100 });
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0', timeout: 20000 });
    await page.waitForSelector('.terminal', { timeout: 5000 });
    await new Promise(r => setTimeout(r, 800));

    const mobileTerminal = await page.$('.terminal');
    const mobileBox = await mobileTerminal.boundingBox();
    const mobH = Math.min(Math.ceil(mobileBox.height + 20), 1100);

    await page.screenshot({
      path: join(assetsDir, 'route-watch-m.png'),
      clip: {
        x: Math.max(0, mobileBox.x - 10),
        y: Math.max(0, mobileBox.y - 10),
        width: Math.min(mobileBox.width + 20, 390),
        height: mobH,
      },
    });
    console.log('Mobile screenshot saved: route-watch-m.png', 'h=', mobH);
  } finally {
    await browser.close();
  }
}

captureCppTerminal().catch((e) => {
  console.error(e);
  process.exit(1);
});
