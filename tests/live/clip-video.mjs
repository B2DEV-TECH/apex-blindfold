// Cuts one segment out of a screen recording, for publication.
//
// A recording of a whole desktop shows more than the lab: browser tabs, the
// address bar, the taskbar, whatever else was open. This keeps one area of the
// picture (the page), paints solid rectangles over what must not be read in it
// (a host name, a session identifier), drops the sound and writes an MP4.
// Every cut is appended to clips.txt next to the output, with the hash of the
// recording it came from, so that the cut can be repeated from the original.
//
//   node tests/live/clip-video.mjs <recording> <output.mp4> <start> <end>
//        [--crop <x,y,width,height>] [--mask <x,y,width,height>[@<from>-<to>]] ... [--note "<text>"]
//
// <start> and <end> are seconds of the recording. Mask coordinates are pixels
// of the recording, before the crop; @from-to limits a mask to some seconds of
// the recording. The default crop fits a 1920x1080 desktop with a maximized
// browser: the page between the browser's own bars and the taskbar, without the
// strip at the bottom where a browser shows the address of a link. The picture
// is not scaled, so that small text stays as sharp as it was recorded.
//
// Needs ffmpeg: on the PATH, or its full path in the FFMPEG environment variable.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const FFMPEG = process.env.FFMPEG || 'ffmpeg';
const USAGE = 'Usage: node tests/live/clip-video.mjs <recording> <output.mp4> <start> <end> [--crop x,y,w,h] [--mask x,y,w,h[@from-to]] ... [--note "<text>"]';
const DEFAULT_CROP = '0,86,1920,914';
const FPS = 30;

const args = process.argv.slice(2);
const positional = [];
const masks = [];
let crop = DEFAULT_CROP;
let note = '';
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--crop') crop = args[++i];
  else if (args[i] === '--mask') masks.push(args[++i]);
  else if (args[i] === '--note') note = args[++i];
  else positional.push(args[i]);
}
const [recording, output, startText, endText] = positional;
const start = Number(startText);
const end = Number(endText);
if (!recording || !output || !(end > start) || start < 0) throw new Error(USAGE);

const four = (text) => {
  const parts = String(text).split(',').map(Number);
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value < 0)) throw new Error(`Not a rectangle: ${text}`);
  return parts;
};
const [cropX, cropY, cropW, cropH] = four(crop);
if (cropW % 2 || cropH % 2) throw new Error(`The kept area needs an even width and height: ${crop}`);
const boxes = masks.map((mask) => {
  const [area, window] = mask.split('@');
  const [x, y, w, h] = four(area);
  let enable = '';
  if (window) {
    const [from, to] = window.split('-').map(Number);
    if (!(to > from)) throw new Error(`Not a time window: ${window}`);
    // Times of a mask are seconds of the recording; the filter counts from the cut.
    enable = `:enable='between(t,${(from - start).toFixed(3)},${(to - start).toFixed(3)})'`;
  }
  return `drawbox=x=${x}:y=${y}:w=${w}:h=${h}:color=0x1b1b1b:t=fill${enable}`;
});
const filters = [...boxes, `crop=${cropW}:${cropH}:${cropX}:${cropY}`, `fps=${FPS}`, 'setsar=1'].join(',');

mkdirSync(dirname(output), { recursive: true });
const run = spawnSync(FFMPEG, [
  '-hide_banner', '-loglevel', 'error', '-y',
  '-ss', String(start), '-t', String(end - start), '-i', recording,
  '-vf', filters,
  '-an', // no sound: a recording may hold a microphone track
  '-map_metadata', '-1', // no metadata from the recording either
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '26', '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
  output,
], { encoding: 'utf8' });
if (run.error) throw new Error(`ffmpeg could not be started (${run.error.message}). Put it on the PATH or set FFMPEG.`);
if (run.status !== 0) throw new Error(`ffmpeg failed: ${run.stderr.trim().split('\n').slice(-3).join(' ')}`);

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const manifest = join(dirname(output), 'clips.txt');
if (!existsSync(manifest)) {
  writeFileSync(manifest, [
    '# Segments cut from screen recordings by tests/live/clip-video.mjs',
    '# The recordings themselves are not published: they show a whole desktop. Each segment keeps one area',
    '# of the picture, has the listed areas painted over, has no sound, and is encoded again, so its hash is',
    '# not the hash of the recording. Times are seconds of the recording; areas are x,y,width,height in',
    '# pixels of the recording.',
    '',
  ].join('\n'));
}
appendFileSync(manifest, [
  `${basename(output)}`,
  `  from:     ${basename(recording)}, sha256 ${sha256(recording)}`,
  `  seconds:  ${start} to ${end}`,
  `  kept:     ${crop}`,
  `  painted:  ${masks.length ? masks.join('  ') : 'nothing'}`,
  ...(note ? [`  note:     ${note}`] : []),
  `  result:   ${statSync(output).size} bytes, sha256 ${sha256(output)}`,
  '',
].join('\n'));
console.log(`${output}: ${(end - start).toFixed(1)} s, ${statSync(output).size} bytes`);
