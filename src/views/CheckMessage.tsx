import { useEffect, useMemo, useRef, useState } from "react";
import { analyze } from "../engine/analyze";
import type {
  AnalysisResult,
  Channel,
  Finding,
  InputIssue,
  Verdict,
} from "../engine/types";

const VERDICT_META: Record<Verdict, { label: string; tone: string }> = {
  "very-likely-scam": { label: "Very likely a scam", tone: "danger" },
  "high-risk": { label: "High risk", tone: "danger" },
  caution: { label: "Caution — verify first", tone: "warn" },
  "no-strong-signal": { label: "No strong signal found", tone: "ok" },
  "not-checkable": { label: "Nothing to check", tone: "neutral" },
};

const ISSUE_LABEL: Record<InputIssue, string> = {
  gibberish: "That doesn't look like a message",
  "non-english": "Can't check this language yet",
  "off-topic": "That doesn't look like a recruiting message",
};

/**
 * The "no strong signal" band can still carry sub-threshold findings. Showing
 * those under a green "no strong signal found" heading reads as an all-clear
 * for something we did flag, so that combination gets its own wording and a
 * neutral colour instead.
 */
function isInconclusive(result: AnalysisResult): boolean {
  return result.verdict === "no-strong-signal" && result.findings.length > 0;
}

function labelFor(result: AnalysisResult): string {
  if (result.issue) return ISSUE_LABEL[result.issue];
  if (isInconclusive(result)) return "Nothing decisive — but check these";
  return VERDICT_META[result.verdict].label;
}

function toneFor(result: AnalysisResult): string {
  if (isInconclusive(result)) return "neutral";
  return VERDICT_META[result.verdict].tone;
}

interface NextStep {
  href: string;
  label: string;
  help: string;
  primary?: boolean;
}

/**
 * A verdict is not the end of the task. Someone told "very likely a scam" has
 * an immediate next question — usually "I already replied, what now?" — and
 * should not have to find the answer in the nav bar themselves.
 */
function nextStepsFor(result: AnalysisResult): NextStep[] {
  const alreadyEngaged: NextStep = {
    href: "#/scammed",
    label: "I already replied, paid, or shared details",
    help: "Get the recovery steps in order — some of them are time-limited.",
  };
  const verify: NextStep = {
    href: "#/verify",
    label: "Check the recruiter and company",
    help: "Nine checks covering the things a message alone can't tell you.",
  };

  switch (result.verdict) {
    case "very-likely-scam":
    case "high-risk":
      return [{ ...alreadyEngaged, primary: true }, verify];
    case "caution":
      return [{ ...verify, primary: true }, alreadyEngaged];
    case "no-strong-signal":
      return [{ ...verify, primary: true }];
    default:
      return [];
  }
}

const CATEGORY_LABEL: Record<string, string> = {
  money: "Money",
  "personal-data": "Personal information",
  "sender-identity": "Sender & identity",
  "offer-content": "The offer",
  process: "Hiring process",
};

const CHANNELS: { value: Channel; label: string }[] = [
  { value: "email", label: "Email" },
  { value: "linkedin", label: "LinkedIn" },
  { value: "text", label: "Text / SMS" },
  { value: "whatsapp", label: "WhatsApp / Telegram" },
  { value: "other", label: "Other" },
];

/** A real-shaped lure, so a first-time visitor can see the tool work at once. */
const EXAMPLE = {
  text:
    "Hello Dear,\n\nWe came across your resume and are pleased to offer you a " +
    "remote position with our company. No experience is needed and the role is " +
    "simple — you will earn $450 a day completing basic tasks.\n\nTo get " +
    "started you must pay a refundable deposit of $200 for your training kit. " +
    "Once your balance goes negative, simply top up your USDT wallet to unlock " +
    "withdrawals.\n\nKindly revert back with your Social Security number and " +
    "bank account so we can set up payroll. Contact me on WhatsApp at " +
    "+1-555-0142 to continue. Only 3 slots left — respond within 20 minutes!",
  fromEmail: "hr.recruiting2024@gmail.com",
  claimedCompany: "Meridian Global",
  channel: "email" as Channel,
};

/** Plain-text version of a result, for sharing with someone else. */
function resultAsText(result: AnalysisResult): string {
  const lines = [
    `Job Scam Checker — ${labelFor(result)}`,
    "",
    result.summary,
  ];
  if (result.findings.length) {
    lines.push("", `What it found (${result.findings.length}):`);
    for (const f of result.findings) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`  ${f.advice}`);
    }
  }
  lines.push(
    "",
    "Checked with https://rishinguha93.github.io/job-scam-checker/",
  );
  return lines.join("\n");
}

export function CheckMessage() {
  const [text, setText] = useState("");
  const [fromEmail, setFromEmail] = useState("");
  const [claimedCompany, setClaimedCompany] = useState("");
  const [channel, setChannel] = useState<Channel | "">("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [showMinor, setShowMinor] = useState(false);
  const [copied, setCopied] = useState(false);

  const resultRef = useRef<HTMLDivElement>(null);

  const canSubmit = text.trim().length >= 20;

  // A result rendered below the fold looks like nothing happened, especially on
  // a phone after pasting a long message.
  useEffect(() => {
    if (!result || !resultRef.current) return;
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    resultRef.current.scrollIntoView({
      behavior: reduced ? "auto" : "smooth",
      block: "start",
    });
    resultRef.current.focus({ preventScroll: true });
  }, [result]);

  function run(input: {
    text: string;
    fromEmail?: string;
    claimedCompany?: string;
    channel?: Channel | "";
  }) {
    setShowMinor(false);
    setCopied(false);
    setResult(
      analyze({
        text: input.text,
        fromEmail: input.fromEmail || undefined,
        claimedCompany: input.claimedCompany || undefined,
        channel: input.channel || undefined,
      }),
    );
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    run({ text, fromEmail, claimedCompany, channel });
  }

  function loadExample() {
    setText(EXAMPLE.text);
    setFromEmail(EXAMPLE.fromEmail);
    setClaimedCompany(EXAMPLE.claimedCompany);
    setChannel(EXAMPLE.channel);
    run(EXAMPLE);
  }

  function onReset() {
    setResult(null);
    setCopied(false);
  }

  async function onCopy() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(resultAsText(result));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(false);
    }
  }

  // Minor points are worth listing but shouldn't bury the serious ones.
  const { major, minor } = useMemo(() => {
    const all = result?.findings ?? [];
    const low = all.filter((f) => f.severity === "low");
    // Nothing to hide behind if that's all there is.
    if (!low.length || low.length === all.length) {
      return { major: all, minor: [] as Finding[] };
    }
    return { major: all.filter((f) => f.severity !== "low"), minor: low };
  }, [result]);

  const groupedMajor = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of major) {
      const list = map.get(f.category) ?? [];
      list.push(f);
      map.set(f.category, list);
    }
    return [...map.entries()];
  }, [major]);

  const nextSteps = result ? nextStepsFor(result) : [];

  return (
    <section className="view">
      <h1>Check a recruiter message</h1>
      <p className="view__lead">
        Paste the email, LinkedIn message, or text you received — or the whole
        back-and-forth. The check looks for known scam patterns and shows you
        exactly what it found.
      </p>

      <form className="form" onSubmit={onSubmit}>
        <label className="field">
          <span className="field__label">
            Message or conversation
            <button
              className="field__example"
              type="button"
              onClick={loadExample}
            >
              See an example
            </button>
          </span>
          <textarea
            className="field__control field__control--area"
            rows={10}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste the recruiter's message here…"
          />
        </label>

        <div className="form__row">
          <label className="field">
            <span className="field__label">
              Sender's email <span className="field__opt">(optional)</span>
            </span>
            <input
              className="field__control"
              type="text"
              value={fromEmail}
              onChange={(e) => setFromEmail(e.target.value)}
              placeholder="name@company.com"
            />
          </label>

          <label className="field">
            <span className="field__label">
              Company they claim <span className="field__opt">(optional)</span>
            </span>
            <input
              className="field__control"
              type="text"
              value={claimedCompany}
              onChange={(e) => setClaimedCompany(e.target.value)}
              placeholder="e.g. Northwind Software"
            />
          </label>

          <label className="field">
            <span className="field__label">
              Where it arrived <span className="field__opt">(optional)</span>
            </span>
            <select
              className="field__control"
              value={channel}
              onChange={(e) => setChannel(e.target.value as Channel | "")}
            >
              <option value="">—</option>
              {CHANNELS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="form__actions">
          <button className="btn btn--primary" type="submit" disabled={!canSubmit}>
            Check it
          </button>
          {result && (
            <button className="btn" type="button" onClick={onReset}>
              Clear result
            </button>
          )}
          {!canSubmit && (
            <span className="form__hint">
              Paste at least a sentence or two to check.
            </span>
          )}
        </div>
      </form>

      {result && (
        <div
          className={`result result--${toneFor(result)}`}
          ref={resultRef}
          tabIndex={-1}
          role="status"
          aria-live="polite"
        >
          <div className="result__verdict">
            <span className="result__badge">{labelFor(result)}</span>
            <p className="result__summary">{result.summary}</p>
          </div>

          {result.verdict === "not-checkable" ? null : result.findings.length >
            0 ? (
            <div className="findings">
              <div className="findings__head">
                <h2 className="findings__title">
                  What we found ({result.findings.length})
                </h2>
                <button className="btn btn--small" type="button" onClick={onCopy}>
                  {copied ? "Copied" : "Copy summary"}
                </button>
              </div>

              {groupedMajor.map(([category, items]) => (
                <div key={category} className="findings__group">
                  <h3 className="findings__group-title">
                    {CATEGORY_LABEL[category] ?? category}
                  </h3>
                  <ul className="findings__list">
                    {items.map((f) => (
                      <Card key={f.id} finding={f} />
                    ))}
                  </ul>
                </div>
              ))}

              {minor.length > 0 && (
                <div className="findings__minor">
                  <button
                    className="findings__toggle"
                    type="button"
                    onClick={() => setShowMinor((v) => !v)}
                    aria-expanded={showMinor}
                  >
                    {showMinor ? "Hide" : "Show"} {minor.length} more minor point
                    {minor.length > 1 ? "s" : ""}
                  </button>
                  {showMinor && (
                    <ul className="findings__list">
                      {minor.map((f) => (
                        <Card key={f.id} finding={f} />
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          ) : (
            <p className="findings__empty">
              No known scam patterns matched. That is not the same as safe —
              confirm the recruiter and the role independently before you reply.
            </p>
          )}

          {nextSteps.length > 0 && (
            <div className="next">
              <h2 className="next__title">What to do next</h2>
              <ul className="next__list">
                {nextSteps.map((s) => (
                  <li key={s.href}>
                    <a
                      className={"next__step" + (s.primary ? " next__step--primary" : "")}
                      href={s.href}
                    >
                      <span className="next__label">{s.label}</span>
                      <span className="next__help">{s.help}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.verdict !== "not-checkable" && (
            <p className="result__disclaimer">
              This is an automated heuristic check, not a verdict from a person.
              Scammers change tactics; a clean result is not a guarantee.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function Card({ finding }: { finding: Finding }) {
  return (
    <li className={`finding finding--${finding.severity}`}>
      <div className="finding__head">
        <span className="finding__severity">{finding.severity}</span>
        <span className="finding__title">{finding.title}</span>
      </div>
      <p className="finding__detail">{finding.detail}</p>
      {finding.evidence.length > 0 && (
        <ul className="finding__evidence">
          {finding.evidence.map((e, i) => (
            <li key={i}>
              <q>{e}</q>
            </li>
          ))}
        </ul>
      )}
      <p className="finding__advice">→ {finding.advice}</p>
    </li>
  );
}
