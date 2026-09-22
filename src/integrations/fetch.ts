import { Airlock } from '../check.js';
import type { AirlockOptions, Envelope } from '../types.js';

/**
 * Wrap a fetching function so the check is NOT OPTIONAL.
 *
 * This is the shape that matters. A check the agent chooses to call is not a
 * control: the agent has to read the content to decide, and by then the content
 * is in its context. Put the airlock inside the tool that does the fetching,
 * and hand back an envelope instead of a string.
 */
export interface GuardedFetchOptions extends AirlockOptions {
  /** Refuse to return quarantined content at all. Default false. */
  blockQuarantine?: boolean;
  /** Called for every verdict, for logging and telemetry. */
  onVerdict?: (env: Envelope) => void;
}

export function createGuardedFetch(options: GuardedFetchOptions = {}) {
  const airlock = new Airlock(options);

  return async function guardedFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Envelope> {
    const res = await fetch(input, init);
    const body = await res.text();
    const origin = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const env = await airlock.wrap(body, origin);
    options.onVerdict?.(env);

    if (options.blockQuarantine && env.verdict.trust === 'quarantine') {
      return {
        ...env,
        content:
          `[im-in-danger] Content from ${origin} was quarantined and is not shown.\n` +
          `Reasons: ${env.verdict.reasons.join('; ')}\n` +
          `A person must review it before an agent reads it.`,
      };
    }
    return env;
  };
}

/**
 * Render an envelope for a tool result. Two rules are load-bearing:
 *
 *  1. The verdict is stated as a FACT ABOUT THE FETCH, never as an instruction
 *     to the model. Telling a model "be careful" is just more text for an
 *     attacker to argue with.
 *  2. Suspect content is fenced so the model can see where untrusted text
 *     begins and ends. The fence is a readability aid, not a security control.
 *     The control is that the runtime has already withdrawn the capabilities.
 */
export function renderForTool(env: Envelope): string {
  const { verdict } = env;
  if (verdict.trust === 'clean') return env.content;
  const header = [
    `[im-in-danger] trust=${verdict.trust} detector=${verdict.detector}`,
    verdict.reasons.length ? `signals: ${verdict.reasons.join('; ')}` : '',
    'Side effects, egress and secrets are withdrawn for this content by the runtime.',
  ]
    .filter(Boolean)
    .join('\n');
  return `${header}\n--- begin untrusted content ---\n${env.content}\n--- end untrusted content ---`;
}
