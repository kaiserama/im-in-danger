import type { SanitizeReport } from './types.js';

/**
 * Deterministic pre-pass. Runs BEFORE any model sees the content.
 *
 * Two jobs, and the second matters more than the first:
 *  1. Give the detector the text a human would actually read.
 *  2. Surface text that was present but concealed. A page that hides
 *     instructions from the reader has already told you something no
 *     classifier needs to infer.
 */

const ZERO_WIDTH = /[​-‍⁠﻿᠎]/g;
/** Unicode tag block: invisible, and a known carrier for hidden instructions. */
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const BIDI = /[‪-‮⁦-⁩]/g;

/** Elements with no closing tag, so they never open a subtree. */
const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

function push(list: string[], value: string | undefined) {
  const v = (value ?? '').trim();
  if (v) list.push(v);
}

/** Strip an HTML attribute value, tolerating single or double quotes. */
function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null;
}

/**
 * `hidden` as an ATTRIBUTE NAME, not as a substring.
 * Must not fire on aria-hidden="false", data-hidden-label="x", or
 * class="hidden-md-up", none of which hide anything.
 */
const HIDDEN_ATTR = /(^|\s)hidden(\s|=|\/|$)/i;
const ARIA_HIDDEN_TRUE = /(^|\s)aria-hidden\s*=\s*["']?\s*true/i;

/**
 * A CSS length or number that is exactly zero: 0, 0.0, 0px, 0em.
 * Deliberately excludes 0.5 and 0.9em, which are visible.
 */
const ZERO_VALUE = String.raw`0(?:\.0+)?(?:px|pt|em|rem|%)?(?![\d.])`;

const DISPLAY_NONE = /display\s*:\s*none/i;
const VISIBILITY_HIDDEN = /visibility\s*:\s*hidden/i;
const ZERO_OPACITY = new RegExp(String.raw`opacity\s*:\s*${ZERO_VALUE}`, 'i');
const ZERO_FONT = new RegExp(String.raw`font-size\s*:\s*${ZERO_VALUE}`, 'i');
const FAR_INDENT = /text-indent\s*:\s*-\d{3,}/i;
const CLIP_ZERO = /clip\s*:\s*rect\(\s*0/i;
const ABSOLUTE = /position\s*:\s*absolute/i;
/**
 * Pushed off-screen. Checked INDEPENDENTLY of `position: absolute`, because the
 * two declarations are separated by a ";" that a single character class cannot
 * cross — the earlier combined pattern could never match a real style.
 */
const FAR_OFFSCREEN = /(?:left|top)\s*:\s*-\d{3,}/i;

function isInvisibleStyle(style: string): boolean {
  if (!style) return false;
  if (DISPLAY_NONE.test(style) || VISIBILITY_HIDDEN.test(style)) return true;
  if (ZERO_OPACITY.test(style) || ZERO_FONT.test(style)) return true;
  if (FAR_INDENT.test(style) || CLIP_ZERO.test(style)) return true;
  return ABSOLUTE.test(style) && FAR_OFFSCREEN.test(style);
}

/**
 * Text the same colour as the page. The lookbehind keeps this off
 * `background-color: #fff`, which hides nothing on its own.
 */
const WHITE_ON_WHITE =
  /(?<![a-z0-9_-])color\s*:\s*(#fff(fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)/i;

/** Why an element is concealed, or null when it is visible. */
function hiddenReason(attrs: string): string | null {
  if (HIDDEN_ATTR.test(attrs) || ARIA_HIDDEN_TRUE.test(attrs)) return 'invisible-element';
  const style = attr(`<x ${attrs}>`, 'style') ?? '';
  if (isInvisibleStyle(style)) return 'invisible-element';
  if (WHITE_ON_WHITE.test(style)) return 'same-colour-text';
  return null;
}

/**
 * Find the index range of `<tag …>…</tag>`, honouring nesting of the same tag.
 * Returns the position of the closing tag and the position after it.
 */
function findClose(input: string, tag: string, from: number): { start: number; after: number } | null {
  const re = new RegExp(`<(/?)${tag}(\\s[^>]*)?>`, 'gi');
  re.lastIndex = from;
  let depth = 1;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input))) {
    depth += m[1] ? -1 : 1;
    if (depth === 0) return { start: m.index, after: re.lastIndex };
  }
  return null;
}

/**
 * Remove concealed elements, DESCENDING into elements it does not claim.
 *
 * The earlier version matched `<tag …>…</tag>` in one pass. On a visible outer
 * element wrapping a hidden inner one, the match began at the outer tag, ended
 * at the inner element's closing tag, saw only the OUTER attributes, and
 * resumed after the whole match — so the hidden inner element was never
 * examined. Scanning tag by tag fixes that: a visible element is stepped into
 * rather than stepped over.
 */
function stripHiddenElements(input: string, hidden: string[], signals: Set<string>): string {
  const open = /<([a-z][a-z0-9]*)\b([^>]*?)(\/?)>/gi;
  let out = '';
  let copiedTo = 0;
  let m: RegExpExecArray | null;

  while ((m = open.exec(input))) {
    const tag = (m[1] ?? '').toLowerCase();
    const attrs = m[2] ?? '';
    const selfClosing = m[3] === '/';
    if (VOID_ELEMENTS.has(tag) || selfClosing) continue;

    const reason = hiddenReason(attrs);
    if (!reason) continue; // visible: keep scanning inside it

    const close = findClose(input, tag, open.lastIndex);
    if (!close) continue; // unbalanced markup: leave it to the tag stripper

    push(hidden, input.slice(open.lastIndex, close.start).replace(/<[^>]+>/g, ' '));
    signals.add(reason);
    out += input.slice(copiedTo, m.index) + ' ';
    copiedTo = close.after;
    open.lastIndex = close.after;
  }

  return out + input.slice(copiedTo);
}

export function sanitize(input: string): SanitizeReport {
  const hidden: string[] = [];
  const signals = new Set<string>();
  let text = input;

  // --- HTML comments
  text = text.replace(/<!--([\s\S]*?)-->/g, (_m, body: string) => {
    push(hidden, body);
    signals.add('html-comment');
    return ' ';
  });

  // --- script/style/template/noscript bodies
  text = text.replace(
    /<(script|style|template|noscript)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi,
    (_m, tag: string, body: string) => {
      push(hidden, body);
      signals.add(`${String(tag).toLowerCase()}-body`);
      return ' ';
    },
  );

  // --- elements hidden by attribute or inline style, at any depth
  text = stripHiddenElements(text, hidden, signals);

  // --- image alt/title text: read by agents, unseen by people
  text = text.replace(/<img\b([^>]*)>/gi, (_m, attrs: string) => {
    const alt = attr(`<x ${attrs}>`, 'alt');
    const title = attr(`<x ${attrs}>`, 'title');
    const carried = [alt, title].filter(Boolean).join(' ').trim();
    // Only treat as hidden when it is long enough to carry an instruction.
    if (carried.length > 80) {
      push(hidden, carried);
      signals.add('long-alt-text');
      return ' ';
    }
    return carried ? ` ${carried} ` : ' ';
  });

  // --- invisible characters
  if (ZERO_WIDTH.test(text)) signals.add('zero-width');
  if (TAG_CHARS.test(text)) signals.add('unicode-tag-chars');
  if (BIDI.test(text)) signals.add('bidi-override');
  text = text.replace(ZERO_WIDTH, '').replace(TAG_CHARS, '').replace(BIDI, '');

  // --- remaining markup, then entities, then whitespace
  text = text.replace(/<[^>]+>/g, ' ');
  text = text
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, body: string) => {
      if (body.startsWith('#')) {
        const code = body[1]?.toLowerCase() === 'x'
          ? parseInt(body.slice(2), 16)
          : parseInt(body.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : m;
      }
      const named: Record<string, string> = {
        amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
      };
      return named[body.toLowerCase()] ?? m;
    })
    .replace(/[ \t ]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return {
    clean: text,
    hidden,
    signals: [...signals],
    hadHidden: hidden.length > 0,
  };
}

/**
 * The text a detector should score: what a human would read, plus anything
 * that was concealed, clearly fenced. Concealed text still gets checked —
 * it is the most likely place for the payload.
 */
export function detectorInput(report: SanitizeReport): string {
  if (!report.hidden.length) return report.clean;
  return `${report.clean}\n\n[concealed in source]\n${report.hidden.join('\n')}`;
}
