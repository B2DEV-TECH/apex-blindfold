// Prepares a screenshot for publication: paints solid rectangles over parts of
// it (a host name, an account name) and, optionally, keeps only one area of it
// (the page, without the browser's tabs and address bar). Saves a PNG.
// The pixels under a rectangle are replaced, not blurred, and the pixels
// outside the kept area are not in the output: nothing can be recovered.
//
//   node tests/live/mask-image.mjs <input> <output.png> [--crop <x,y,width,height>] [<x,y,width,height> ...]
//
// Coordinates are pixels of the original image, from its top left corner.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, extname } from 'node:path';
import { loadConfig } from '../lib/config.mjs';
import { launchBrowser } from '../lib/browser.mjs';

const USAGE = 'Usage: node tests/live/mask-image.mjs <input> <output.png> [--crop <x,y,width,height>] [<x,y,width,height> ...]';
const rectangle = (text) => {
  const parts = String(text).split(',').map(Number);
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value < 0)) throw new Error(`Not a rectangle: ${text}`);
  return parts;
};

const args = process.argv.slice(2);
const cropAt = args.indexOf('--crop');
const crop = cropAt >= 0 ? rectangle(args[cropAt + 1]) : null;
const [input, output, ...boxes] = args.filter((arg, index) => cropAt < 0 || (index !== cropAt && index !== cropAt + 1));
if (!input || !output || (boxes.length === 0 && !crop)) throw new Error(USAGE);
const rectangles = boxes.map(rectangle);
const types = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };
const type = types[extname(input).toLowerCase()];
if (!type) throw new Error('The input must be a PNG, JPEG or WebP image.');

const browser = await launchBrowser(loadConfig());
try {
  const page = await browser.newPage();
  const source = `data:${type};base64,${readFileSync(input).toString('base64')}`;
  const result = await page.evaluate(async ({ src, rects, keep }) => {
    const image = new Image();
    image.src = src;
    await image.decode();
    const canvas = document.createElement('canvas');
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext('2d');
    context.drawImage(image, 0, 0);
    context.fillStyle = '#1b1b1b';
    for (const [x, y, width, height] of rects) context.fillRect(x, y, width, height);
    if (!keep) return { png: canvas.toDataURL('image/png').split(',')[1], width: canvas.width, height: canvas.height };

    const [x, y] = keep;
    const width = Math.min(keep[2], canvas.width - x);
    const height = Math.min(keep[3], canvas.height - y);
    if (width <= 0 || height <= 0) throw new Error('The area to keep is outside the image.');
    const kept = document.createElement('canvas');
    kept.width = width;
    kept.height = height;
    kept.getContext('2d').drawImage(canvas, x, y, width, height, 0, 0, width, height);
    return { png: kept.toDataURL('image/png').split(',')[1], width, height };
  }, { src: source, rects: rectangles, keep: crop });
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, Buffer.from(result.png, 'base64'));
  console.log(`${output}: ${result.width}x${result.height}, ${rectangles.length} area(s) masked${crop ? ', cropped' : ''}`);
} finally {
  await browser.close();
}
