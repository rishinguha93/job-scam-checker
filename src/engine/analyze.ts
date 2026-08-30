/**
 * Orchestrator: normalize the input, run the rules, aggregate a verdict.
 */

import { runRules } from "./rules";
import type {
  AnalysisResult,
  CheckInput,
  Finding,
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

export function analyze(raw: CheckInput): AnalysisResult {
  const input = normalizeInput(raw);
  const findings = runRules(input).sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  );
  const score = scoreOf(findings);
  const verdict = verdictFor(findings, score);
  return {
    verdict,
    score,
    findings,
    summary: VERDICT_SUMMARY[verdict],
  };
}
