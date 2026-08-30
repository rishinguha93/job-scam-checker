/**
 * Shared types for the detection engine.
 *
 * The engine is deliberately free of any DOM or React dependency so it can be
 * unit-tested in isolation and, later, reused in a browser extension or a
 * server-side check.
 */

export type Channel = "email" | "linkedin" | "text" | "whatsapp" | "other";

/** What the user gives us to analyze, after light normalization. */
export interface CheckInput {
  /** The pasted message or full thread. Required. */
  text: string;
  /** Optional "From" address the user supplies. Enables sender-domain rules. */
  fromEmail?: string;
  /** Optional "Reply-To" address. Enables the mismatch rule. */
  replyToEmail?: string;
  /** Optional company name the sender claims to represent. */
  claimedCompany?: string;
  /** Where the message arrived. */
  channel?: Channel;
}

export type Severity = "critical" | "high" | "medium" | "low";

export type FindingCategory =
  | "money"
  | "personal-data"
  | "sender-identity"
  | "offer-content"
  | "process";

/** One triggered red flag. */
export interface Finding {
  /** Stable rule id, e.g. "crypto-topup". */
  id: string;
  category: FindingCategory;
  severity: Severity;
  /** Short human-readable headline. */
  title: string;
  /** One or two sentences explaining why this matters. */
  detail: string;
  /** Exact snippet(s) from the user's input that triggered the rule. */
  evidence: string[];
  /** The single most important next action for this specific flag. */
  advice: string;
}

export type Verdict =
  | "very-likely-scam"
  | "high-risk"
  | "caution"
  | "no-strong-signal";

export interface AnalysisResult {
  verdict: Verdict;
  /** Aggregate weighted score (before the critical-override). */
  score: number;
  findings: Finding[];
  /** Verdict-level guidance shown at the top of the result. */
  summary: string;
}

/** A rule inspects the input and returns a Finding when it matches. */
export type Rule = (input: CheckInput) => Finding | null;
