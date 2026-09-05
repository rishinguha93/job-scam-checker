import { useMemo, useState } from "react";
import { analyze } from "../engine/analyze";
import type {
  AnalysisResult,
  Channel,
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

export function CheckMessage() {
  const [text, setText] = useState("");
  const [fromEmail, setFromEmail] = useState("");
  const [claimedCompany, setClaimedCompany] = useState("");
  const [channel, setChannel] = useState<Channel | "">("");
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const canSubmit = text.trim().length >= 20;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setResult(
      analyze({
        text,
        fromEmail: fromEmail || undefined,
        claimedCompany: claimedCompany || undefined,
        channel: channel || undefined,
      }),
    );
  }

  function onReset() {
    setResult(null);
  }

  const grouped = useMemo(() => {
    if (!result) return [];
    const map = new Map<string, typeof result.findings>();
    for (const f of result.findings) {
      const list = map.get(f.category) ?? [];
      list.push(f);
      map.set(f.category, list);
    }
    return [...map.entries()];
  }, [result]);

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
          <span className="field__label">Message or conversation</span>
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
        <div className={`result result--${VERDICT_META[result.verdict].tone}`}>
          <div className="result__verdict">
            <span className="result__badge">
              {result.issue
                ? ISSUE_LABEL[result.issue]
                : VERDICT_META[result.verdict].label}
            </span>
            <p className="result__summary">{result.summary}</p>
          </div>

          {result.verdict === "not-checkable" ? null : result.findings.length >
            0 ? (
            <div className="findings">
              <h2 className="findings__title">
                What we found ({result.findings.length})
              </h2>
              {grouped.map(([category, items]) => (
                <div key={category} className="findings__group">
                  <h3 className="findings__group-title">
                    {CATEGORY_LABEL[category] ?? category}
                  </h3>
                  <ul className="findings__list">
                    {items.map((f) => (
                      <li key={f.id} className={`finding finding--${f.severity}`}>
                        <div className="finding__head">
                          <span className="finding__severity">{f.severity}</span>
                          <span className="finding__title">{f.title}</span>
                        </div>
                        <p className="finding__detail">{f.detail}</p>
                        {f.evidence.length > 0 && (
                          <ul className="finding__evidence">
                            {f.evidence.map((e, i) => (
                              <li key={i}>
                                <q>{e}</q>
                              </li>
                            ))}
                          </ul>
                        )}
                        <p className="finding__advice">→ {f.advice}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          ) : (
            <p className="findings__empty">
              No known scam patterns matched. Still confirm the recruiter and the
              role independently — use the “Verify a recruiter” checklist.
            </p>
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
