// Live session of Layer 2: the first check of one recording, before the next shot.
//
//   node tests/live/check-recording.mjs <recording.mp4> --out <folder> [--frames 6]
//
// Opens the recording in Microsoft Edge (headless), which plays H.264 without ffmpeg, and reports
// whether it opens, its length and its picture size against the recording standard of the runbook
// (1920 x 1080). It also saves evenly spaced frames, the first and the last among them, into
// <folder>, for a person or the assistant to look at: does the shot show what the shot list asks,
// and nothing private?
//
// The frames show whatever was on the screen. Keep <folder> outside the repository (a temporary
// folder); the script refuses a folder inside it.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { basename, join, relative, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { ROOT } from '../lib/config.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : fallback;
};
const file = args.find((arg, index) => !arg.startsWith('--') && !['--out', '--frames'].includes(args[index - 1]));
const out = option('--out');
const frames = Math.max(2, Number(option('--frames', 6)));
if (!file || !out) throw new Error('Usage: node tests/live/check-recording.mjs <recording.mp4> --out <folder> [--frames 6]');
if (!existsSync(file)) throw new Error(`No such file: ${file}`);
const outside = relative(ROOT, resolve(out));
if (!outside.startsWith('..') && !isAbsolute(outside)) throw new Error('The frames folder must be outside the repository.');
mkdirSync(out, { recursive: true });

const bytes = readFileSync(file);
const report = {
  file: basename(file),
  bytes: statSync(file).size,
  sha256: createHash('sha256').update(bytes).digest('hex'),
};

const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  // The browser opens the file itself, in its own media page: one <video> element.
  await page.goto(pathToFileURL(resolve(file)).href);
  await page.evaluate(() => { const v = document.querySelector('video'); v.id = 'v'; v.muted = true; v.controls = false; v.pause(); });
  const meta = await page.evaluate(() => new Promise((done) => {
    const v = document.getElementById('v');
    const finish = () => done({ ok: true, duration: v.duration, width: v.videoWidth, height: v.videoHeight });
    if (v.readyState >= 1) finish();
    v.addEventListener('loadedmetadata', finish, { once: true });
    v.addEventListener('error', () => done({ ok: false, error: v.error ? `media error ${v.error.code}: ${v.error.message}` : 'media error' }), { once: true });
    setTimeout(() => done({ ok: false, error: 'no metadata after 20 s' }), 20000);
  }));
  Object.assign(report, meta);
  if (meta.ok) {
    report.standard = meta.width === 1920 && meta.height === 1080 ? '1920 x 1080: as the runbook asks' : `${meta.width} x ${meta.height}: NOT the 1920 x 1080 of the runbook`;
    report.frames = [];
    const video = page.locator('#v');
    for (let i = 0; i < frames; i += 1) {
      // The last frame is taken a little before the end: seeking to the exact end shows nothing.
      const at = Math.max(0, Math.min(meta.duration - 0.05, (meta.duration * i) / (frames - 1)));
      const drawn = await page.evaluate((time) => new Promise((done) => {
        const v = document.getElementById('v');
        v.addEventListener('seeked', () => done(true), { once: true });
        v.currentTime = time;
        setTimeout(() => done(false), 10000);
      }), at);
      const name = `${basename(file).replace(/\.[^.]+$/, '')}-${String(i + 1).padStart(2, '0')}-at-${at.toFixed(1)}s.png`;
      if (drawn) await video.screenshot({ path: join(out, name) });
      report.frames.push({ at: Number(at.toFixed(2)), file: drawn ? join(out, name) : null });
    }
  }
} finally {
  await browser.close();
}
console.log(JSON.stringify(report, null, 2));
if (!report.ok) process.exitCode = 1;
