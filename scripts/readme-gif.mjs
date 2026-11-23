// Makes the animation of README.md from a segment of the live session.
// GitHub does not play a video that sits in the repository, so the README
// shows a reduced GIF and links to the MP4 it was made from. Nothing is drawn
// on it: it is the same picture, smaller and with fewer frames.
//
//   node scripts/readme-gif.mjs
//
// Needs ffmpeg: on the PATH, or its full path in the FFMPEG environment variable.
import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from '../tests/lib/config.mjs';

const FFMPEG = process.env.FFMPEG || 'ffmpeg';
const GIFS = [
  // segment of the live session                                          width, frames per second, result
  { from: 'evidence/live-session/video/07-election-b-stuffed-tally.mp4', width: 880, fps: 10, to: 'assets/readme/live-stuffed-tally.gif' },
];

for (const gif of GIFS) {
  // One palette for the whole animation, taken from the parts of the picture that change.
  const filter = `fps=${gif.fps},scale=${gif.width}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle`;
  const run = spawnSync(FFMPEG, ['-hide_banner', '-loglevel', 'error', '-y', '-i', join(ROOT, gif.from), '-vf', filter, '-loop', '0', join(ROOT, gif.to)], { encoding: 'utf8' });
  if (run.error) throw new Error(`ffmpeg could not be started (${run.error.message}). Put it on the PATH or set FFMPEG.`);
  if (run.status !== 0) throw new Error(`ffmpeg failed: ${run.stderr.trim().split('\n').slice(-3).join(' ')}`);
  console.log(`${gif.to}: ${gif.width} px wide, ${gif.fps} frames per second, ${Math.round(statSync(join(ROOT, gif.to)).size / 1024)} KB, from ${gif.from}`);
}
