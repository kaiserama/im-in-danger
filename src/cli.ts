#!/usr/bin/env node
/**
 * content-airlock CLI.
 *
 *   echo "<content>" | content-airlock check      # verdict as JSON
 *   content-airlock check --file page.html
 *   content-airlock hook                          # Claude Code hook mode
 */
import { readFileSync } from 'node:fs';
import { Airlock } from './check.js';
import { JevDetector } from './detectors/jev.js';
import { LocalDetector } from './detectors/local.js';
import { HeuristicDetector } from './detectors/heuristic.js';
import type { Detector } from './types.js';

function pickDetector(argv: string[]): Detector {
  const want = value(argv, '--detector') ?? (process.env.TYPESAFE_API_KEY ? 'jev' : 'heuristic');
  if (want === 'jev') return new JevDetector({ model: value(argv, '--model') });
  if (want === 'local') return new LocalDetector({ baseUrl: value(argv, '--base-url'), model: value(argv, '--model') });
  return new HeuristicDetector();
}

function value(argv: string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.from(c));
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const [cmd = 'check', ...argv] = process.argv.slice(2);

  if (cmd === 'hook') {
    await import('../integrations/claude-code-hook.js');
    return;
  }
  if (cmd !== 'check') {
    process.stderr.write('usage: content-airlock check [--file F] [--detector jev|local|heuristic]\n');
    process.exit(2);
  }

  const file = value(argv, '--file');
  const content = file ? readFileSync(file, 'utf8') : await readStdin();
  if (!content.trim()) {
    process.stderr.write('nothing to check: pass --file or pipe content on stdin\n');
    process.exit(2);
  }

  const verdict = await new Airlock({ detector: pickDetector(argv) }).check(content, file);
  process.stdout.write(JSON.stringify(verdict, null, 2) + '\n');
  // Exit code doubles as a shell-friendly signal.
  process.exit(verdict.trust === 'clean' ? 0 : verdict.trust === 'suspect' ? 1 : 2);
}

main().catch((e) => {
  process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(3);
});
