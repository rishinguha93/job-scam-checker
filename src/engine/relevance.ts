/**
 * Input relevance gate.
 *
 * Runs before the red-flag rules. Its job is to notice when the user has not
 * actually given us a recruiting message — a keysmash, a paste in a language we
 * cannot read, or some unrelated text — so the UI can say "we couldn't read
 * this" instead of the dangerously reassuring "no strong signal found".
 */

import type { InputIssue } from "./types";

/** Common English function words. Natural prose is full of them; junk has none. */
const STOPWORDS = new Set([
  "the", "a", "an", "and", "or", "but", "if", "to", "of", "in", "on", "for",
  "with", "at", "by", "from", "is", "are", "was", "were", "be", "been", "am",
  "have", "has", "had", "do", "does", "did", "will", "would", "can", "could",
  "you", "your", "we", "our", "us", "i", "me", "my", "it", "its", "this",
  "that", "they", "them", "he", "she", "his", "her", "not", "no", "as", "so",
  "about", "please", "thanks", "thank", "hi", "hello", "dear", "there", "here",
]);

/**
 * Vocabulary that indicates the text is about work or hiring. Deliberately
 * generous: wrongly calling a real scam message "off-topic" would be far worse
 * than letting an unrelated one through.
 */
const RECRUITING_TERMS =
  /\b(job|jobs|role|roles|position|positions|hiring|hire|recruit|recruiter|recruiting|recruitment|opportunit(y|ies)|interview|apply|application|applicant|candidate|resume|cv|salary|wage|compensation|payroll|employment|employer|employee|career|vacancy|vacancies|opening|openings|onboard|onboarding|offer|hr|human resources|talent|staffing|contract|freelance|internship|placement|profile|experience|qualifications?|remote|work from home|full[- ]time|part[- ]time|company|team|start date|shift|training)\b/i;

/** Strip surrounding punctuation from a whitespace-delimited token. */
function cleanToken(raw: string): string {
  return raw.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "");
}

/**
 * Does this token look like a real word? Rejects keysmashes via long consonant
 * runs, missing vowels, and implausible length.
 */
function isWordLike(token: string): boolean {
  if (token.length > 24) return false;
  if (!/[aeiouy]/i.test(token)) return token.length <= 3; // "hr", "by", "n"
  if (/[^aeiouy\W\d_]{5,}/i.test(token)) return false; // 5+ consonants in a row
  return true;
}

/**
 * Assess whether the text is something we can meaningfully check.
 * Returns `null` when the input looks like a readable message worth scanning.
 */
export function assessInput(text: string): InputIssue | null {
  const trimmed = text.trim();
  if (!trimmed) return "gibberish";

  // 1. Script check first, so a Bengali or Arabic message is never called junk.
  const letters = trimmed.match(/\p{L}/gu) ?? [];
  const latin = trimmed.match(/\p{Script=Latin}/gu) ?? [];
  if (letters.length >= 20 && latin.length / letters.length < 0.4) {
    return "non-english";
  }

  // 2. Keysmash / filler detection.
  if (/([a-z])\1{5,}/i.test(trimmed)) return "gibberish";

  const tokens = trimmed
    .split(/\s+/)
    .map(cleanToken)
    .filter((t) => /[a-z]/i.test(t)); // only alphabetic tokens count

  if (tokens.length === 0) return "gibberish";

  const wordLike = tokens.filter(isWordLike).length;
  if (wordLike / tokens.length < 0.5) return "gibberish";

  const stopwordHits = tokens.filter((t) => STOPWORDS.has(t.toLowerCase())).length;
  if (tokens.length >= 8 && stopwordHits === 0) return "gibberish";

  // 3. Readable, but is it about work at all? Only judge this once there is
  //    enough text to be confident — short real messages get the benefit of
  //    the doubt.
  if (tokens.length >= 25 && !RECRUITING_TERMS.test(trimmed)) {
    return "off-topic";
  }

  return null;
}
