/**
 * Orchestrator: normalize the input, run the rules, aggregate a verdict.
 */

import { assessInput } from "./relevance";
import { runRules } from "./rules";
import type {
  AnalysisResult,
  CheckInput,
  Finding,
  InputIssue,
  Severity,
  Verdict,
} from "./types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 0, // handled by override, not the score
  high: 30,
  medium: 15,
  low: 7,
};

const VERDICT_SUMMARY: Record<Verdict, string> = {
  "very-likely-scam":
    "This matches known recruiting-scam patterns that rarely, if ever, appear " +
    "together in a legitimate hiring process. Don't send money, personal " +
    "information, or documents, and stop contact.",
  "high-risk":
    "Several strong warning signs are present. Do not proceed until you have " +
    "independently verified the employer through its official website.",
  caution:
    "Some warning signs are present. Verify the recruiter and the role before " +
    "sharing anything or taking next steps.",
  "no-strong-signal":
    "No strong red flags were detected in this text. That is not proof it is " +
    "genuine — still verify the employer independently before proceeding.",
  "not-checkable":
    "We couldn't read this as a message, so nothing was checked.",
};

const ISSUE_SUMMARY: Record<InputIssue, string> = {
  gibberish:
    "This doesn't read as a written message, so no check was run — treat it " +
    "as no result at all, not as a clean one. Paste the recruiter's email, " +
    "LinkedIn message, or text exactly as you received it.",
  "non-english":
    "The rules only cover English at the moment, so this wasn't checked. " +
    "An English translation of the message will work, or use the " +
    "“Verify a recruiter” checklist instead — it isn't language-specific.",
  "off-topic":
    "This reads as ordinary text with nothing about a job, a role, or hiring " +
    "in it, and no scam patterns matched. If you meant to paste a recruiter " +
    "message, it may not have copied across.",
};

/** Trim, and drop obviously empty optional fields. */
export function normalizeInput(raw: CheckInput): CheckInput {
  const clean = (s?: string) => {
    const t = s?.trim();
    return t ? t : undefined;
  };
  return {
    text: raw.text ?? "",
    fromEmail: clean(raw.fromEmail),
    replyToEmail: clean(raw.replyToEmail),
    claimedCompany: clean(raw.claimedCompany),
    channel: raw.channel,
  };
}

function scoreOf(findings: Finding[]): number {
  return findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
}

function verdictFor(findings: Finding[], score: number): Verdict {
  if (findings.some((f) => f.severity === "critical")) return "very-likely-scam";

  // A pile of independent red flags is itself scam-level, even when no single
  // "red line" (money / personal data) has been crossed yet.
  const highCount = findings.filter((f) => f.severity === "high").length;
  if (score >= 80 && findings.length >= 4) return "very-likely-scam";
  if (highCount >= 2 && findings.length >= 5) return "very-likely-scam";

  if (score >= 45) return "high-risk";
  if (score >= 20) return "caution";
  return "no-strong-signal";
}

/** Severity order for sorting findings, most serious first. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function notCheckable(issue: InputIssue): AnalysisResult {
  return {
    verdict: "not-checkable",
    score: 0,
    findings: [],
    summary: ISSUE_SUMMARY[issue],
    issue,
  };
}

export function analyze(raw: CheckInput): AnalysisResult {
  const input = normalizeInput(raw);

  // Unreadable input can't produce a meaningful verdict either way, so stop
  // before the rules rather than reporting a reassuring empty result.
  const issue = assessInput(input.text);
  if (issue === "gibberish" || issue === "non-english") {
    return notCheckable(issue);
  }

  const findings = runRules(input).sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  );

  // "Off-topic" is only worth reporting when nothing matched anyway. A message
  // that trips real rules gets a real verdict, whatever it appears to be about.
  if (issue === "off-topic" && findings.length === 0) {
    return notCheckable(issue);
  }

  const score = scoreOf(findings);
  const verdict = verdictFor(findings, score);
  return {
    verdict,
    score,
    findings,
    summary: VERDICT_SUMMARY[verdict],
  };
}
