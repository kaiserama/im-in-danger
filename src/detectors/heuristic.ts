import type { Detector, Scores } from '../types.js';

/**
 * No-model fallback. Deliberately crude, and shipped for three reasons:
 *  - the airlock must still return a verdict when no detector is configured;
 *  - it is the baseline the model detectors have to beat in eval/RESULTS.md;
 *  - it is a fair default for people who will never call an API.
 *
 * It is a keyword matcher. It will miss paraphrases and it will flag articles
 * that merely discuss injection. Both failures are visible in the benchmark,
 * which is the point of including it.
 */
const PATTERNS: [keyof Scores, RegExp[]][] = [
  ['instructs_ai', [
    /\b(you are|act as)\s+(now\s+)?(an?\s+)?(ai|assistant|agent|language model|chatbot)\b/i,
    /\b(ai|assistant|agent|llm|model|chatbot|copilot)\s*[:,-]\s*(please\s+)?(do|read|note|ignore|send|call|fetch|execute)/i,
    /\b(if|when)\s+you\s+are\s+(an?\s+)?(ai|assistant|agent|language model|bot)\b/i,
    /\b(instruction|note|directive|message)s?\s+(to|for)\s+(the\s+)?(ai|assistant|agent|model|bot)\b/i,
  ]],
  ['overrides_rules', [
    /\bignore\s+(all\s+|any\s+)?(previous|prior|earlier|above|preceding)\s+(instruction|prompt|rule|direction)/i,
    /\bdisregard\s+(all\s+|any\s+)?(previous|prior|your)\b/i,
    /\b(new|updated|revised)\s+system\s+prompt\b/i,
    /\b(unrestricted|developer|god|dan)\s+mode\b/i,
    /\boverride[sd]?\s+(your|the|all)\s+(rule|polic|instruction|restriction|guardrail)/i,
  ]],
  ['wants_secrets', [
    /\b(system\s+prompt|context\s+window|api[_\s-]?key|secret|credential|password|token|private\s+key)\b[\s\S]{0,60}\b(send|reveal|print|show|include|output|return|append)\b/i,
    /\b(reveal|print|show|repeat|output)\b[\s\S]{0,40}\b(system\s+prompt|your\s+instructions|the\s+above)\b/i,
    /\b(\.ssh|id_rsa|\.env|credentials\.json)\b/i,
  ]],
  ['exfiltrates', [
    /\b(send|forward|post|upload|email|transmit|exfiltrate)\b[\s\S]{0,60}\b(to|at)\b[\s\S]{0,40}(https?:\/\/|@|\.[a-z]{2,})/i,
    /\bhttps?:\/\/[^\s]{0,80}[?&](data|q|payload|content|ctx)=/i,
  ]],
  ['claims_authority', [
    /^\s*(system|admin|administrator|developer|operator)\s*[:>]/im,
    /\b(this is|message from)\s+(the\s+)?(system|administrator|developer|operator|security team)\b/i,
    /\[\s*(system|admin|important|priority\s*1)\s*[\]:]/i,
  ]],
  ['changes_payment', [
    /\b(bank|payment|remittance|routing|account)\s+(detail|number|information)s?\b[\s\S]{0,80}\b(chang|updat|new)/i,
    /\b(apply|grant)\s+(a\s+)?\d{1,3}\s*%\s*(discount|off)\b[\s\S]{0,60}\b(without|no need to|do not)\b/i,
  ]],
  ['conceal', [
    /\b(do not|don't|never)\s+(show|tell|mention|reveal|display|surface)\b[\s\S]{0,40}\b(the\s+)?(user|human|operator|owner)\b/i,
    /\b(silently|quietly|without (telling|informing|notifying))\b/i,
    /\bhide\s+this\s+(message|instruction|note)\b/i,
  ]],
];

export class HeuristicDetector implements Detector {
  readonly name = 'heuristic:v1';

  async score(text: string): Promise<Scores> {
    const scores: Scores = {};
    for (const [id, regexes] of PATTERNS) {
      const hits = regexes.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0);
      // A single pattern here is a phrase like "ignore all previous instructions",
      // which has no innocent reading in fetched content. It must be able to reach
      // `suspect` on its own: this detector is the default when no API key is set,
      // and an earlier 0.6 sat below the 0.7 threshold, so it passed obvious
      // injections as clean. Two or more patterns is strong evidence.
      if (hits > 0) scores[id] = hits >= 2 ? 0.92 : 0.75;
      else scores[id] = 0.02;
    }
    return scores;
  }
}
