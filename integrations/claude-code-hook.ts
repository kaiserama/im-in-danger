#!/usr/bin/env node
/**
 * Claude Code PostToolUse hook: check what a tool BROUGHT BACK before the model
 * reads it, and surface the verdict.
 *
 * Wire it up in .claude/settings.json:
 *
 *   {
 *     "hooks": {
 *       "PostToolUse": [
 *         {
 *           "matcher": "WebFetch|Read|Bash",
 *           "hooks": [{ "type": "command",
 *                       "command": "npx -y content-airlock hook" }]
 *         }
 *       ]
 *     }
 *   }
 *
 * What this can and cannot do, stated plainly:
 *   - It CAN flag fetched content that carries instructions, and it can block
 *     the result from reaching the model at all.
 *   - It CANNOT withdraw capabilities mid-session. A hook is not a sandbox.
 *     For real capability control, put the airlock inside your own fetch tool
 *     (see integrations/fetch.ts) where you own the dispatch path.
 *
 * Reads a hook payload on stdin, writes a hook response on stdout.
 */
import { Airlock } from '../src/check.js';
import { JevDetector } from '../src/detectors/jev.js';
import { HeuristicDetector } from '../src/detectors/heuristic.js';

interface HookPayload {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
}

const TEXT_KEYS = ['content', 'text', 'output', 'stdout', 'result', 'body'];

function extractText(response: unknown, depth = 0): string {
  if (depth > 4 || response == null) return '';
  if (typeof response === 'string') return response;
  if (Array.isArray(response)) return response.map((r) => extractText(r, depth + 1)).join('\n');
  if (typeof response === 'object') {
    const obj = response as Record<string, unknown>;
    const picked = TEXT_KEYS.filter((k) => k in obj).map((k) => extractText(obj[k], depth + 1));
    return picked.length ? picked.join('\n') : '';
  }
  return '';
}

async function main() {
  const raw = await new Promise<string>((resolve) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => (buf += d));
    process.stdin.on('end', () => resolve(buf));
  });

  let payload: HookPayload = {};
  try {
    payload = JSON.parse(raw) as HookPayload;
  } catch {
    process.exit(0); // Not our payload shape. Never break the session.
  }

  const text = extractText(payload.tool_response);
  if (!text || text.length < 40) process.exit(0);

  const detector = process.env.TYPESAFE_API_KEY ? new JevDetector() : new HeuristicDetector();
  const airlock = new Airlock({ detector });
  const verdict = await airlock.check(text, payload.tool_name);

  if (verdict.trust === 'clean') process.exit(0);

  const block = verdict.trust === 'quarantine' && process.env.AIRLOCK_BLOCK !== '0';
  const summary =
    `content-airlock: ${verdict.trust} (${verdict.detector}) on ${payload.tool_name ?? 'tool'} output. ` +
    verdict.reasons.join('; ');

  // additionalContext states a fact about the fetch. It is not an instruction,
  // and it is not what protects you — capability control lives in the runtime.
  const out = block
    ? { decision: 'block', reason: `${summary}. Result withheld for human review.` }
    : { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: summary } };

  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

main().catch(() => process.exit(0));
