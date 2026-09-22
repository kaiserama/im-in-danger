import { Airlock } from '../check.js';
import type { AirlockOptions, Envelope } from '../types.js';
import { renderForTool } from './fetch.js';

/**
 * MCP middleware: check every tool RESULT before it is handed back.
 *
 * An MCP server is a trust boundary an agent crosses constantly, and most
 * servers return third-party content verbatim. Wrapping the dispatch means the
 * check applies to every tool the server exposes, including ones added later.
 */
export interface McpGuardOptions extends AirlockOptions {
  /** Tools whose output is trusted and should skip the check. */
  skipTools?: string[];
  /** Replace quarantined content with a notice. Default true. */
  blockQuarantine?: boolean;
  onVerdict?: (toolName: string, env: Envelope) => void;
}

type ToolResult = { content?: { type: string; text?: string }[]; [k: string]: unknown };
type ToolHandler = (args: unknown) => Promise<ToolResult>;

/** Wrap one tool handler. */
export function guardTool(
  name: string,
  handler: ToolHandler,
  options: McpGuardOptions = {},
): ToolHandler {
  const airlock = new Airlock(options);
  const skip = new Set(options.skipTools ?? []);
  const block = options.blockQuarantine ?? true;

  return async (args: unknown) => {
    const result = await handler(args);
    if (skip.has(name) || !Array.isArray(result.content)) return result;

    const checked = await Promise.all(
      result.content.map(async (part) => {
        if (part.type !== 'text' || !part.text || part.text.length < 40) return part;
        const env = await airlock.wrap(part.text, name);
        options.onVerdict?.(name, env);
        if (block && env.verdict.trust === 'quarantine') {
          return {
            ...part,
            text:
              `[im-in-danger] Output of ${name} was quarantined and is not shown.\n` +
              `Reasons: ${env.verdict.reasons.join('; ')}`,
          };
        }
        return { ...part, text: renderForTool(env) };
      }),
    );
    return { ...result, content: checked };
  };
}

/** Wrap a whole map of handlers at once. */
export function guardTools(
  handlers: Record<string, ToolHandler>,
  options: McpGuardOptions = {},
): Record<string, ToolHandler> {
  return Object.fromEntries(
    Object.entries(handlers).map(([name, fn]) => [name, guardTool(name, fn, options)]),
  );
}
