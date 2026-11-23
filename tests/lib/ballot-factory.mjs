// Encrypts many ballots in parallel worker threads (see ballot-worker.mjs).
import { Worker } from 'node:worker_threads';
import { availableParallelism } from 'node:os';

const WORKER = new URL('./ballot-worker.mjs', import.meta.url);
const CHUNK = 48;

export class BallotFactory {
  constructor(size = Math.max(1, availableParallelism() - 1)) {
    this.size = size;
    this.idle = [];
    this.waiting = [];
    this.pending = new Map();
    this.nextId = 1;
    this.workers = Array.from({ length: size }, () => {
      const worker = new Worker(WORKER);
      worker.on('message', (message) => {
        const task = this.pending.get(message.id);
        this.pending.delete(message.id);
        this.release(worker);
        if (message.error) task.reject(new Error(message.error));
        else task.resolve(message);
      });
      worker.on('error', (error) => {
        for (const task of this.pending.values()) task.reject(error);
        this.pending.clear();
      });
      this.idle.push(worker);
      return worker;
    });
  }

  release(worker) {
    const next = this.waiting.shift();
    if (next) next(worker);
    else this.idle.push(worker);
  }

  acquire() {
    const worker = this.idle.pop();
    return worker ? Promise.resolve(worker) : new Promise((resolve) => this.waiting.push(resolve));
  }

  async run(payload) {
    const worker = await this.acquire();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ id, ...payload });
    });
  }

  /**
   * choices: zero-based option index per ballot.
   * pureCount: how many leading ballots must use the pure BigInt path.
   * verifyEvery: recompute one accelerated ciphertext in this many on the pure path.
   * Returns { ballots: [[c1, c2, c3], ...], stats: { pure, accelerated, verified } }.
   */
  async encrypt(nHex, choices, { pureCount = 0, verifyEvery = 100 } = {}) {
    const jobs = choices.map((choice, index) => ({ choice, pure: index < pureCount }));
    const chunks = [];
    // A pure BigInt ballot costs about as much as a whole accelerated chunk,
    // so each one travels alone and the workers share them.
    const pureJobs = Math.min(pureCount, jobs.length);
    for (let i = 0; i < pureJobs; i++) chunks.push([jobs[i]]);
    for (let i = pureJobs; i < jobs.length; i += CHUNK) chunks.push(jobs.slice(i, i + CHUNK));
    const results = await Promise.all(chunks.map((chunk) => this.run({ nHex, jobs: chunk, verifyEvery })));
    const stats = { pure: 0, accelerated: 0, verified: 0 };
    const ballots = [];
    for (const result of results) {
      ballots.push(...result.ballots);
      for (const key of Object.keys(stats)) stats[key] += result.stats[key];
    }
    return { ballots, stats, openSsl: results.some((r) => r.accelerated) };
  }

  async close() {
    await Promise.all(this.workers.map((worker) => worker.terminate()));
  }
}
