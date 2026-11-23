// Makes the images of README.md from the screenshots in /evidence. Each one is
// a crop of a screenshot, reduced in size. Nothing is drawn on them and nothing
// is retouched: to see the original, open the file named in the left column.
//
//   node scripts/readme-images.mjs
//
// Run it again after a new run of the lab, because the runner retakes the
// screenshots. The crop is given in pixels of the original, as rows from the top.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadConfig, ROOT } from '../tests/lib/config.mjs';
import { launchBrowser } from '../tests/lib/browser.mjs';

const IMAGES = [
  // source screenshot                                      first row, rows kept, width of the result, result
  { from: 'evidence/app/03-vote-receipt.png',               top: 0,    rows: 2090, width: 1760, to: 'assets/readme/vote-receipt.png' },
  { from: 'evidence/app/04-what-the-database-sees.png',     top: 0,    rows: 2160, width: 1320, to: 'assets/readme/what-the-database-sees.png' },
  { from: 'evidence/app/06-tally-decrypted.png',            top: 1776, rows: 2160, width: 1320, to: 'assets/readme/tally-decrypted.png' },
  { from: 'evidence/h2-blindness/dba-select.png',           top: 0,    rows: 1590, width: 1760, to: 'assets/readme/dba-select.png' },
  { from: 'evidence/h4-ballot-stuffing/01-stuffed-tally.png', top: 2850, rows: 1140, width: 1760, to: 'assets/readme/stuffed-tally.png' },
];

// The lab configuration only says which browser to prefer; any Chromium will do.
let cfg = {};
try {
  cfg = loadConfig();
} catch {
  // no lab configuration on this machine
}

const browser = await launchBrowser(cfg);
try {
  const page = await browser.newPage();
  for (const image of IMAGES) {
    const source = `data:image/png;base64,${readFileSync(join(ROOT, image.from)).toString('base64')}`;
    const result = await page.evaluate(async ({ src, top, rows, width }) => {
      const original = new Image();
      original.src = src;
      await original.decode();
      if (top + rows > original.naturalHeight) throw new Error(`the crop ends at row ${top + rows}, the image has ${original.naturalHeight}`);
      const height = Math.round((rows * width) / original.naturalWidth);
      const reduced = await createImageBitmap(original, 0, top, original.naturalWidth, rows, { resizeWidth: width, resizeHeight: height, resizeQuality: 'high' });
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      canvas.getContext('2d').drawImage(reduced, 0, 0);
      return { png: canvas.toDataURL('image/png').split(',')[1], height, from: `${original.naturalWidth}x${original.naturalHeight}` };
    }, { src: source, top: image.top, rows: image.rows, width: image.width });
    const file = join(ROOT, image.to);
    mkdirSync(dirname(file), { recursive: true });
    const bytes = Buffer.from(result.png, 'base64');
    writeFileSync(file, bytes);
    console.log(`${image.to}: ${image.width}x${result.height}, ${Math.round(bytes.length / 1024)} KB, rows ${image.top} to ${image.top + image.rows} of ${image.from} (${result.from})`);
  }
} finally {
  await browser.close();
}
