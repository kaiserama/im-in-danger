/** Core types. The airlock returns an envelope, never a bare boolean. */

/** The battery of questions asked about untrusted content. */
export type QuestionId =
  | 'instructs_ai'
  | 'overrides_rules'
  | 'wants_secrets'
  | 'exfiltrates'
  | 'claims_authority'
  | 'changes_payment'
  | 'conceal';

/** What the deterministic pre-pass found and removed. Model never sees this layer. */
export interface SanitizeReport {
  /** Text after stripping, which is what a detector scores. */
  clean: string;
  /** Content that was hidden from a human reader but present in the source. */
  hidden: string[];
  /** Named reasons, e.g. 'html-comment', 'zero-width', 'offscreen-css'. */
  signals: string[];
  /** True when anything was concealed. Concealment alone is suspicious. */
  hadHidden: boolean;
}

/** One detector's scores. Values are probabilities in [0,1]. */
export type Scores = Partial<Record<QuestionId, number>>;

/** A detector turns content into scores. Implement this to bring your own. */
export interface Detector {
  /** Short name recorded in the verdict, e.g. 'jev-1.13.0'. */
  readonly name: string;
  score(text: string): Promise<Scores>;
}

/** How much the content is trusted after checking. */
export type Trust =
  /** Nothing fired. Normal handling. */
  | 'clean'
  /** Something fired, or the detector was unavailable. Reduce capability. */
  | 'suspect'
  /** Strong signal. Do not feed to an agent without a human looking first. */
  | 'quarantine';

/**
 * Capabilities the RUNTIME should withdraw for content at this trust level.
 * These are advisory to the caller and must be enforced mechanically —
 * never by telling the model to be careful.
 */
export interface CapabilityAdvice {
  /** Allow tools with side effects while this content is in context. */
  allowSideEffects: boolean;
  /** Allow outbound network calls derived from this content. */
  allowEgress: boolean;
  /** Allow secrets to remain in context alongside this content. */
  allowSecrets: boolean;
  /** Any privileged call using values from this content needs a person. */
  requireHumanForDerivedActions: boolean;
}

export interface Verdict {
  trust: Trust;
  /** Highest score across the battery. */
  top: number;
  /** Which question produced `top`. */
  topQuestion: QuestionId | null;
  scores: Scores;
  sanitize: SanitizeReport;
  capabilities: CapabilityAdvice;
  /** Human-readable reasons, safe to log and show in a review queue. */
  reasons: string[];
  detector: string;
  /** Milliseconds spent in the detector. */
  ms: number;
  /** sha256 of the original content, for caching and audit. */
  hash: string;
  /** True when the detector failed and the verdict defaulted to suspect. */
  degraded: boolean;
}

/** Content plus its verdict. Fetchers return this instead of a string. */
export interface Envelope {
  content: string;
  verdict: Verdict;
  /** Where the content came from, for logs and cache keys. */
  origin?: string;
}

export interface AirlockOptions {
  detector?: Detector;
  /** Any score at or above this is suspect. Default 0.7. */
  suspectAt?: number;
  /** Any score at or above this is quarantine. Default 0.9. */
  quarantineAt?: number;
  /** Cap on characters sent to the detector per chunk. Default 12000. */
  chunkChars?: number;
  /** Cache verdicts by content hash. Default true. */
  cache?: boolean;
  /** Treat hidden text as an automatic suspect regardless of scores. Default true. */
  hiddenTextIsSuspect?: boolean;
}
