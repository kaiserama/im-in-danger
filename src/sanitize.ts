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

function push(list: string[], value: string | undefined) {
  const v = (value ?? '').trim();
  if (v) list.push(v);
}

/** Strip an HTML attribute value, tolerating single or double quotes. */
function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null;
}

const INVISIBLE_STYLE =
  /(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\b|font-size\s*:\s*0|text-indent\s*:\s*-\d{3,}|position\s*:\s*absolute[^";]*(left|top)\s*:\s*-\d{3,}|clip\s*:\s*rect\(0)/i;

const WHITE_ON_WHITE = /color\s*:\s*(#fff(fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)/i;

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

  // --- elements hidden by attribute or inline style
  text = text.replace(
    /<([a-z][a-z0-9]*)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi,
    (match, _tag: string, attrs: string, body: string) => {
      const style = attr(`<x ${attrs}>`, 'style') ?? '';
      const isHidden =
        /\bhidden\b/i.test(attrs) ||
        /aria-hidden\s*=\s*["']?true/i.test(attrs) ||
        INVISIBLE_STYLE.test(style) ||
        WHITE_ON_WHITE.test(style);
      if (!isHidden) return match;
      push(hidden, body.replace(/<[^>]+>/g, ' '));
      if (WHITE_ON_WHITE.test(style)) signals.add('same-colour-text');
      else signals.add('invisible-element');
      return ' ';
    },
  );

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
