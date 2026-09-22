export { Airlock, capabilitiesFor, chunk, sha256 } from './check.js';
export { sanitize, detectorInput } from './sanitize.js';
export { QUESTIONS, QUESTION_IDS, REASON_TEXT } from './questions.js';
export { JevDetector, type JevOptions } from './detectors/jev.js';
export { LocalDetector, type LocalOptions } from './detectors/local.js';
export { HeuristicDetector } from './detectors/heuristic.js';
export type {
  AirlockOptions, CapabilityAdvice, Detector, Envelope, QuestionId,
  SanitizeReport, Scores, Trust, Verdict,
} from './types.js';
export {
  checkTool, reviewTools, ToolLockfile, descriptorHash, toolText, toolKey,
  type ToolDescriptor, type ToolReview, type LockStatus, type LockEntry, type LockFileShape,
} from './tools.js';
