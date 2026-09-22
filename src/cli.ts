#!/usr/bin/env node
/**
 * im-in-danger CLI.
 *
 *   echo "<content>" | im-in-danger check        # verdict as JSON
 *   im-in-danger check --file page.html
 *   im-in-danger tools --file tools.json         # review a tool surface
 *   im-in-danger tools --file tools.json --approve
 *   im-in-danger hook                            # Claude Code hook mode
 */
import { readFileSync } from 'node:fs';
import { ToolLockfile, reviewTools, type ToolDescriptor } from './tools.js';
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
    await import('./integrations/claude-code-hook.js');
    return;
  }
  if (cmd === 'tools') {
    await toolsCommand(argv);
    return;
  }
  if (cmd !== 'check') {
    process.stderr.write(
      'usage: im-in-danger check [--file F] [--detector jev|local|heuristic]\n' +
        '       im-in-danger tools --file tools.json [--lockfile F] [--approve] [--approve-flagged] [--by NAME]\n' +
        '       im-in-danger hook\n',
    );
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
  // Stderr only, so the JSON on stdout stays machine-readable.
  if (verdict.trust === 'quarantine') process.stderr.write("(chuckles) I'm in danger.\n");
  // Exit code doubles as a shell-friendly signal.
  process.exit(verdict.trust === 'clean' ? 0 : verdict.trust === 'suspect' ? 1 : 2);
}

/**
 * Review a tool surface against the lockfile.
 *
 * Exit codes are meant for a wrapper script: 0 means every tool is unchanged
 * and clean, 2 means at least one tool was quarantined or its description
 * changed after approval, 1 means something else needs a person.
 */
async function toolsCommand(argv: string[]) {
  const file = value(argv, '--file');
  const lockPath = value(argv, '--lockfile') ?? 'im-in-danger.lock.json';
  const raw = file ? readFileSync(file, 'utf8') : await readStdin();
  if (!raw.trim()) {
    process.stderr.write('nothing to review: pass --file or pipe a JSON array of tools\n');
    process.exit(2);
  }
  const parsed = JSON.parse(raw) as ToolDescriptor[] | { tools: ToolDescriptor[] };
  const tools = Array.isArray(parsed) ? parsed : parsed.tools;
  if (!Array.isArray(tools)) {
    process.stderr.write('expected a JSON array of tools, or an object with a "tools" array\n');
    process.exit(2);
  }

  const lock = ToolLockfile.load(lockPath);
  const reviews = await reviewTools(tools, lock, { detector: pickDetector(argv) });

  for (const r of reviews) {
    const flags = [r.status, r.verdict.trust].filter((x) => x !== 'unchanged' && x !== 'clean');
    process.stdout.write(
      `${flags.length ? '!' : ' '} ${r.key.padEnd(34)} ${r.status.padEnd(9)} ${r.verdict.trust}` +
        `${r.verdict.reasons.length ? `  (${r.verdict.reasons.join('; ')})` : ''}\n`,
    );
  }
  for (const gone of lock.missingFrom(tools)) {
    process.stdout.write(`  ${gone.padEnd(34)} in lockfile, not offered by the server\n`);
  }

  if (argv.includes('--approve')) {
    const by = value(argv, '--by');
    // Approving a flagged description is the mistake this command exists to
    // prevent, so --approve only pins tools the battery called clean.
    // --approve-flagged is the deliberate override, and quarantine is never
    // approvable by flag at all.
    const allowFlagged = argv.includes('--approve-flagged');
    const approved: string[] = [];
    const skipped: string[] = [];
    for (const r of reviews) {
      const tool = tools.find((t) => (t.source ? `${t.source}/${t.name}` : t.name) === r.key);
      if (!tool) continue;
      const ok =
        r.verdict.trust === 'clean' || (allowFlagged && r.verdict.trust === 'suspect');
      if (!ok) {
        skipped.push(`${r.key} (${r.verdict.trust})`);
        continue;
      }
      lock.approve(tool, by);
      approved.push(r.key);
    }
    lock.save();
    process.stdout.write(`\napproved ${approved.length} tool(s) into ${lockPath}\n`);
    for (const sk of skipped) process.stdout.write(`  NOT approved: ${sk}\n`);
    if (skipped.length && !allowFlagged) {
      process.stdout.write(
        '  a flagged description is not pinned by --approve; read it, then use --approve-flagged if it is genuinely fine\n',
      );
    }
  }

  // After an --approve run the exit code describes what is LEFT, not what was
  // just resolved: pinning a tool and then exiting nonzero reads as a failure.
  const outstanding = argv.includes('--approve')
    ? reviews.filter((r) => r.verdict.trust !== 'clean')
    : reviews.filter((r) => r.needsHuman);
  const blocked = outstanding.some(
    (r) => r.verdict.trust === 'quarantine' || (!argv.includes('--approve') && r.status === 'changed'),
  );
  process.exit(blocked ? 2 : outstanding.length ? 1 : 0);
}

main().catch((e) => {
  process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(3);
});
