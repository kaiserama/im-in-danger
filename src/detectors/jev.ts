import type { Detector, Scores, QuestionId } from '../types.js';
import { QUESTIONS, QUESTION_IDS } from '../questions.js';

export interface JevOptions {
  /** Defaults to process.env.TYPESAFE_API_KEY. */
  apiKey?: string;
  /** Pin a version rather than an alias so thresholds stay meaningful. */
  model?: string;
  baseUrl?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Retries on 429 and 5xx. Default 3. */
  retries?: number;
  /**
   * Tell the model that content which DESCRIBES or QUOTES an attack is not itself
   * issuing one. Default FALSE, by measurement: on the benchmark it removes every
   * false alarm at 0.7 but lets three injections through as clean, including half
   * the quoted-injection items. In this design a false alarm costs a capability
   * downgrade and a miss costs a clean pass, so misses are the worse error.
   * Turn it on when your agents routinely read security advisories, AI
   * documentation or test fixtures and the downgrades hurt more than they help.
   */
  framingRule?: boolean;
}

export const FRAMING_RULE =
  'Judge only what the text itself instructs. Text that merely describes, reports, ' +
  'quotes or documents an attack, in an article, advisory, ticket, log, test fixture or ' +
  'documentation, is not itself issuing that instruction and does not count.';

const RETRYABLE = new Set([429, 500, 502, 503, 504]);

/**
 * TypeSafe Jev. One request carries the whole battery, because output tokens
 * are free and questions are answered in parallel against one read of the
 * content — so seven questions cost barely more than one.
 *
 * Note for anyone handling regulated data: this sends the untrusted content to
 * a third party. That is itself an egress event. Use the local detector where
 * that matters.
 */
export class JevDetector implements Detector {
  readonly name: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly framingRule: boolean;

  constructor(opts: JevOptions = {}) {
    this.apiKey = opts.apiKey ?? process.env.TYPESAFE_API_KEY ?? '';
    this.model = opts.model ?? 'jev-1.13.0';
    this.baseUrl = opts.baseUrl ?? 'https://api.typesafe.ai/v1/systemone';
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.retries = opts.retries ?? 3;
    this.framingRule = opts.framingRule ?? false;
    this.name = `jev:${this.model}${this.framingRule ? ':framing' : ''}`;
  }

  async score(text: string): Promise<Scores> {
    if (!this.apiKey) throw new Error('TYPESAFE_API_KEY is not set');
    const questions = Object.fromEntries(
      QUESTION_IDS.map((id) => [
        id,
        {
          type: 'noul',
          instructions: this.framingRule
            ? { statement: QUESTIONS[id], rule: FRAMING_RULE }
            : QUESTIONS[id],
        },
      ]),
    );
    const body = JSON.stringify({
      model: this.model,
      state: { untrusted_content: text },
      questions,
    });

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(this.baseUrl, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${this.apiKey}`,
            'content-type': 'application/json',
          },
          body,
          signal: ac.signal,
        });
        if (!res.ok) {
          const detail = (await res.text()).slice(0, 200);
          if (RETRYABLE.has(res.status) && attempt < this.retries) {
            await sleep(2 ** attempt * 250);
            continue;
          }
          throw new Error(`Jev request failed (${res.status}): ${detail}`);
        }
        const json = (await res.json()) as {
          answers?: Record<string, { noul?: number }>;
        };
        const answers = json.answers ?? {};
        const scores: Scores = {};
        for (const id of QUESTION_IDS) {
          const v = answers[id]?.noul;
          if (typeof v === 'number' && Number.isFinite(v)) scores[id as QuestionId] = v;
        }
        if (Object.keys(scores).length === 0) throw new Error('Jev returned no usable answers');
        return scores;
      } catch (err) {
        lastError = err;
        if (attempt < this.retries && isTransient(err)) {
          await sleep(2 ** attempt * 250);
          continue;
        }
        throw err;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Jev request failed');
  }
}

function isTransient(err: unknown): boolean {
  const name = (err as { name?: string })?.name;
  return name === 'AbortError' || name === 'TypeError';
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}
