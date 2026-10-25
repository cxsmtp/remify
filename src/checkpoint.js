import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const fileName = (key) => `${createHash('sha1').update(String(key)).digest('hex')}.json`;

export class Checkpoint {
  /** @param {string} dir  the run directory; made if missing */
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
  }

  #file(engine, key) {
    return path.join(this.dir, engine, fileName(key));
  }

  /** The findings saved for one unit, or null when it was not finished. */
  load(engine, key) {
    try {
      const saved = JSON.parse(fs.readFileSync(this.#file(engine, key), 'utf8'));
      return saved?.key === String(key) && Array.isArray(saved.findings) ? saved.findings : null;
    } catch {
      return null;
    }
  }

  save(engine, key, findings) {
    const file = this.#file(engine, key);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(temp, JSON.stringify({ key: String(key), savedAt: new Date().toISOString(), findings }));
    fs.renameSync(temp, file);
  }

  /** How many units of an engine are saved. */
  count(engine) {
    try {
      return fs.readdirSync(path.join(this.dir, engine)).filter((name) => name.endsWith('.json')).length;
    } catch {
      return 0;
    }
  }
}
