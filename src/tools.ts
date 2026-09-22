import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Airlock } from './check.js';
import type { AirlockOptions, Verdict } from './types.js';

/**
 * Tool and skill metadata is untrusted content that an agent reads.
 *
 * A tool description arrives in the model's context exactly like a fetched web
 * page does, and it is read every single turn. The difference that matters:
 * **a real tool description DESCRIBES what the tool does; a poisoned one
 * INSTRUCTS the agent.** That is the same distinction the question battery is
 * built on, so it applies here unchanged.
 *
 * What this does NOT do is judge whether a package's CODE is malicious. Most
 * registry attacks ship ordinary-looking metadata and hide the payload in an
 * install script. That is a job for package auditing and sandboxing, not for a
 * text classifier, and pretending otherwise would be the exact overreach this
 * project argues against.
 */
export interface ToolDescriptor {
  /** Tool name as the agent sees it. */
  name: string;
  /** The description the model reads. The main attack surface. */
  description?: string;
  /** JSON Schema for the tool's input. Parameter descriptions are read too. */
  inputSchema?: unknown;
  /** Server, plugin or skill pack this came from, used for the lock key. */
  source?: string;
}

/** Collect every `description` string in a JSON Schema, at any depth. */
function schemaText(node: unknown, depth = 0, out: string[] = []): string[] {
  if (depth > 8 || node === null || typeof node !== 'object') return out;
  if (Array.isArray(node)) {
    for (const v of node) schemaText(v, depth + 1, out);
    return out;
  }
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if ((k === 'description' || k === 'title') && typeof v === 'string') out.push(v);
    else if (typeof v === 'object') schemaText(v, depth + 1, out);
  }
  return out;
}

/** The text an agent actually reads for this tool, flattened for checking. */
export function toolText(tool: ToolDescriptor): string {
  const parts = [`tool name: ${tool.name}`];
  if (tool.description) parts.push(`description: ${tool.description}`);
  const params = schemaText(tool.inputSchema);
  if (params.length) parts.push(`parameter descriptions:\n${params.join('\n')}`);
  return parts.join('\n');
}

/** Stable identity for a tool: source-qualified name. */
export function toolKey(tool: ToolDescriptor): string {
  return tool.source ? `${tool.source}/${tool.name}` : tool.name;
}

/** Canonical JSON with sorted keys, so formatting changes do not look like edits. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/**
 * Hash of everything the agent reads. Changing a description after approval —
 * the "rug pull" — changes this, which is the whole point.
 */
export function descriptorHash(tool: ToolDescriptor): string {
  return createHash('sha256')
    .update(
      canonical({
        name: tool.name,
        description: tool.description ?? '',
        inputSchema: tool.inputSchema ?? null,
      }),
    )
    .digest('hex');
}

/** Check one tool's metadata with the same battery used for fetched content. */
export async function checkTool(
  tool: ToolDescriptor,
  options: AirlockOptions = {},
): Promise<Verdict> {
  return new Airlock(options).check(toolText(tool), toolKey(tool));
}

export type LockStatus =
  /** Never approved. Treat as untrusted until a person looks. */
  | 'new'
  /** Byte-identical to what was approved. */
  | 'unchanged'
  /** Approved before, but the text the agent reads has changed since. */
  | 'changed';

export interface LockEntry {
  hash: string;
  approvedAt: string;
  approvedBy?: string;
  note?: string;
}

export interface LockFileShape {
  version: 1;
  tools: Record<string, LockEntry>;
}

/**
 * A record of tool descriptions a human has approved.
 *
 * This is the part of the design that needs no model at all, and it closes a
 * hole no classifier can: a skill that was honest when it was reviewed and
 * changed its description afterwards. Approval is pinned to a hash; anything
 * else is a change that needs looking at again.
 */
export class ToolLockfile {
  private data: LockFileShape;

  constructor(
    private readonly path: string,
    data?: LockFileShape,
  ) {
    this.data = data ?? { version: 1, tools: {} };
  }

  static load(path: string): ToolLockfile {
    if (!existsSync(path)) return new ToolLockfile(path);
    const raw = JSON.parse(readFileSync(path, 'utf8')) as LockFileShape;
    if (raw?.version !== 1 || typeof raw.tools !== 'object') {
      throw new Error(`${path} is not a valid im-in-danger lockfile`);
    }
    return new ToolLockfile(path, raw);
  }

  save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    const tools = Object.fromEntries(
      Object.entries(this.data.tools).sort(([a], [b]) => (a < b ? -1 : 1)),
    );
    writeFileSync(this.path, `${JSON.stringify({ version: 1, tools }, null, 2)}\n`);
  }

  status(tool: ToolDescriptor): LockStatus {
    const entry = this.data.tools[toolKey(tool)];
    if (!entry) return 'new';
    return entry.hash === descriptorHash(tool) ? 'unchanged' : 'changed';
  }

  entry(tool: ToolDescriptor): LockEntry | undefined {
    return this.data.tools[toolKey(tool)];
  }

  /** Record that a person accepted this exact text. */
  approve(tool: ToolDescriptor, approvedBy?: string, note?: string): void {
    const e: LockEntry = { hash: descriptorHash(tool), approvedAt: new Date().toISOString() };
    if (approvedBy) e.approvedBy = approvedBy;
    if (note) e.note = note;
    this.data.tools[toolKey(tool)] = e;
  }

  forget(tool: ToolDescriptor): void {
    delete this.data.tools[toolKey(tool)];
  }

  get size(): number {
    return Object.keys(this.data.tools).length;
  }

  /** Keys present in the lockfile that are not in the supplied set. */
  missingFrom(tools: readonly ToolDescriptor[]): string[] {
    const seen = new Set(tools.map(toolKey));
    return Object.keys(this.data.tools).filter((k) => !seen.has(k));
  }
}

export interface ToolReview {
  key: string;
  status: LockStatus;
  verdict: Verdict;
  /** True when the runtime should refuse to load this tool without a human. */
  needsHuman: boolean;
}

/**
 * Review a whole tool surface at load time.
 *
 * `needsHuman` is deliberately blunt: anything new, anything changed since it
 * was approved, and anything the battery flags. A tool that is unchanged and
 * clean loads silently, which is the common case and should stay cheap.
 */
export async function reviewTools(
  tools: readonly ToolDescriptor[],
  lock: ToolLockfile,
  options: AirlockOptions = {},
): Promise<ToolReview[]> {
  const airlock = new Airlock(options);
  return Promise.all(
    tools.map(async (tool) => {
      const status = lock.status(tool);
      const verdict = await airlock.check(toolText(tool), toolKey(tool));
      return {
        key: toolKey(tool),
        status,
        verdict,
        needsHuman: status !== 'unchanged' || verdict.trust !== 'clean',
      };
    }),
  );
}
