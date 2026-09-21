import { createHash } from 'node:crypto';
import type {
  AirlockOptions, CapabilityAdvice, Detector, Envelope, QuestionId, Scores, Trust, Verdict,
} from './types.js';
import { sanitize, detectorInput } from './sanitize.js';
import { REASON_TEXT } from './questions.js';
import { HeuristicDetector } from './detectors/heuristic.js';

const DEFAULTS = {
  suspectAt: 0.7,
  quarantineAt: 0.9,
  chunkChars: 12_000,
  cache: true,
  hiddenTextIsSuspect: true,
};

/** Capability advice per trust level. The caller must ENFORCE this. */
export function capabilitiesFor(trust: Trust): CapabilityAdvice {
  switch (trust) {
    case 'clean':
      return {
        allowSideEffects: true, allowEgress: true, allowSecrets: true,
        requireHumanForDerivedActions: false,
      };
    case 'suspect':
      return {
        allowSideEffects: false, allowEgress: false, allowSecrets: false,
        requireHumanForDerivedActions: true,
      };
    case 'quarantine':
      return {
        allowSideEffects: false, allowEgress: false, allowSecrets: false,
        requireHumanForDerivedActions: true,
      };
  }
}

export const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export class Airlock {
  private readonly detector: Detector;
  private readonly opts: Required<Omit<AirlockOptions, 'detector'>>;
  private readonly memo = new Map<string, Verdict>();

  constructor(options: AirlockOptions = {}) {
    this.detector = options.detector ?? new HeuristicDetector();
    this.opts = {
      suspectAt: options.suspectAt ?? DEFAULTS.suspectAt,
      quarantineAt: options.quarantineAt ?? DEFAULTS.quarantineAt,
      chunkChars: options.chunkChars ?? DEFAULTS.chunkChars,
      cache: options.cache ?? DEFAULTS.cache,
      hiddenTextIsSuspect: options.hiddenTextIsSuspect ?? DEFAULTS.hiddenTextIsSuspect,
    };
  }

  /**
   * Check one piece of untrusted content.
   *
   * Never throws for detector failure. A detector that is down produces a
   * `degraded` verdict at `suspect`, because unknown must not read as clean.
   */
  async check(content: string, origin?: string): Promise<Verdict> {
    const hash = sha256(content);
    if (this.opts.cache) {
      const hit = this.memo.get(hash);
      if (hit) return hit;
    }

    const report = sanitize(content);
    const text = detectorInput(report);
    const chunks = chunk(text, this.opts.chunkChars);

    let scores: Scores = {};
    let degraded = false;
    const started = Date.now();
    try {
      const results = await Promise.all(chunks.map((c) => this.detector.score(c)));
      scores = mergeMax(results);
    } catch {
      degraded = true;
    }
    const ms = Date.now() - started;

    const entries = Object.entries(scores) as [QuestionId, number][];
    const best = entries.reduce<[QuestionId | null, number]>(
      (acc, [id, v]) => (v > acc[1] ? [id, v] : acc),
      [null, 0],
    );
    const [topQuestion, top] = best;

    const reasons: string[] = [];
    for (const [id, v] of entries) {
      if (v >= this.opts.suspectAt) reasons.push(`${REASON_TEXT[id]} (${v.toFixed(2)})`);
    }
    if (report.hadHidden) {
      reasons.push(`content was concealed in the source (${report.signals.join(', ')})`);
    }
    if (degraded) reasons.push('detector unavailable, treated as suspect');

    let trust: Trust = 'clean';
    if (degraded) trust = 'suspect';
    if (this.opts.hiddenTextIsSuspect && report.hadHidden && trust === 'clean') trust = 'suspect';
    if (top >= this.opts.suspectAt) trust = 'suspect';
    if (top >= this.opts.quarantineAt) trust = 'quarantine';
    // Concealment plus any model signal is the strongest combination there is.
    if (report.hadHidden && top >= this.opts.suspectAt) trust = 'quarantine';

    const verdict: Verdict = {
      trust, top, topQuestion, scores, sanitize: report,
      capabilities: capabilitiesFor(trust),
      reasons, detector: this.detector.name, ms, hash, degraded,
    };
    if (this.opts.cache) this.memo.set(hash, verdict);
    return verdict;
  }

  /** Check content and return it wrapped with its verdict. */
  async wrap(content: string, origin?: string): Promise<Envelope> {
    return { content, verdict: await this.check(content, origin), origin };
  }
}

/** Split on paragraph boundaries where possible, so an instruction is not cut in half. */
export function chunk(text: string, max: number): string[] {
  if (text.length <= max) return [text];
  const out: string[] = [];
  let buf = '';
  for (const para of text.split(/\n\n+/)) {
    if (para.length > max) {
      if (buf) { out.push(buf); buf = ''; }
      for (let i = 0; i < para.length; i += max) out.push(para.slice(i, i + max));
      continue;
    }
    if ((buf + '\n\n' + para).length > max) { out.push(buf); buf = para; }
    else buf = buf ? `${buf}\n\n${para}` : para;
  }
  if (buf) out.push(buf);
  return out;
}

/** A page is as suspicious as its most suspicious chunk. */
function mergeMax(list: Scores[]): Scores {
  const out: Scores = {};
  for (const s of list) {
    for (const [k, v] of Object.entries(s) as [QuestionId, number][]) {
      if (out[k] === undefined || v > (out[k] as number)) out[k] = v;
    }
  }
  return out;
}
