// Paints solid rectangles over parts of a screenshot (an address bar, a host
// name, an account name) and saves the result as PNG. The pixels under a
// rectangle are replaced, not blurred: nothing can be recovered from the output.
//
//   node tests/live/mask-image.mjs <input> <output.png> <x,y,width,height> [<x,y,width,height> ...]
//
// Coordinates are pixels of the original image, from its top left corner.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, extname } from 'node:path';
import { loadConfig } from '../lib/config.mjs';
import { launchBrowser } from '../lib/browser.mjs';

const [input, output, ...boxes] = process.argv.slice(2);
if (!input || !output || boxes.length === 0) throw new Error('Usage: node tests/live/mask-image.mjs <input> <output.png> <x,y,width,height> ...');
const rectangles = boxes.map((box) => {
  const parts = box.split(',').map(Number);
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value < 0)) throw new Error(`Not a rectangle: ${box}`);
  return parts;
});
const types = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };
const type = types[extname(input).toLowerCase()];
if (!type) throw new Error('The input must be a PNG, JPEG or WebP image.');

const browser = await launchBrowser(loadConfig());
try {
  const page = await browser.newPage();
  const source = `data:${type};base64,${readFileSync(input).toString('base64')}`;
  const result = await page.evaluate(async ({ src, rects }) => {
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
    return { png: canvas.toDataURL('image/png').split(',')[1], width: canvas.width, height: canvas.height };
  }, { src: source, rects: rectangles });
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, Buffer.from(result.png, 'base64'));
  console.log(`${output}: ${result.width}x${result.height}, ${rectangles.length} area(s) masked`);
} finally {
  await browser.close();
}
