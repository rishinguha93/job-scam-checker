import { useState } from "react";

interface CheckItem {
  id: string;
  prompt: string;
  help: string;
  /** A "no" answer is a strong warning, not just a missing tick. */
  weighted?: boolean;
}

const ITEMS: CheckItem[] = [
  {
    id: "domain",
    prompt:
      "The sender's email uses the company's real domain (not Gmail/Outlook or a look-alike).",
    help: "Type the domain into your browser yourself. recruiter@acme.com is fine; recruiter@acme-careers.online is not.",
    weighted: true,
  },
  {
    id: "careers-page",
    prompt: "The exact role appears on the company's own careers page.",
    help: "Go to the company website directly — don't use a link from the message — and search for the title.",
    weighted: true,
  },
  {
    id: "profile-real",
    prompt:
      "The recruiter has an established LinkedIn profile that lists this employer.",
    help: "A profile created in the last few months with very few connections and a stock photo is a red flag.",
  },
  {
    id: "photo",
    prompt: "A reverse image search of their photo doesn't show a stock or stolen image.",
    help: "Save the profile photo and search it on Google Images or TinEye.",
  },
  {
    id: "independent-contact",
    prompt:
      "You reached the company through a phone number or email you looked up yourself, and they confirmed the person and role.",
    help: "Never use contact details supplied in the suspicious message to 'verify' it.",
    weighted: true,
  },
  {
    id: "no-money",
    prompt: "You have not been asked to pay for anything or move any money.",
    help: "Equipment, training, certifications, and background checks are always the employer's cost — and so is a CV rewrite. No genuine recruiter sends you to a paid service to be considered.",
    weighted: true,
  },
  {
    id: "survives-scrutiny",
    prompt:
      "You told them you'd verify their details — and they engaged, rather than going quiet or vanishing.",
    help: "Saying \"I'll confirm this with the company directly\" is a cheap, powerful test. Fake profiles often stop replying or disappear within hours.",
  },
  {
    id: "no-pii",
    prompt:
      "You have not been asked for your SSN, bank details, or ID before a written, verified offer.",
    help: "Payroll and verification details come after you accept a real offer.",
    weighted: true,
  },
  {
    id: "real-interview",
    prompt:
      "There has been (or will be) a video or phone interview with an identifiable person.",
    help: "Text-only interviews on WhatsApp, Telegram, or Skype chat are a common scam pattern.",
  },
];

type State = Record<string, "yes" | "no" | "unsure">;

export function VerifyRecruiter() {
  const [state, setState] = useState<State>({});

  const answered = Object.keys(state).length;
  const failedWeighted = ITEMS.filter(
    (i) => i.weighted && state[i.id] === "no",
  );
  const anyUnsure = ITEMS.some((i) => state[i.id] === "unsure");
  const allYes = ITEMS.every((i) => state[i.id] === "yes");

  function set(id: string, value: "yes" | "no" | "unsure") {
    setState((s) => ({ ...s, [id]: value }));
  }

  return (
    <section className="view">
      <h1>Verify a recruiter or company</h1>
      <p className="view__lead">
        No single detail proves a recruiter is genuine. Work through these checks
        — the more you can answer “yes” to, the safer you are. Any “no” on a
        highlighted item is reason to stop.
      </p>

      <ol className="checklist">
        {ITEMS.map((item) => (
          <li
            key={item.id}
            className={
              "checklist__item" +
              (item.weighted ? " checklist__item--weighted" : "")
            }
          >
            <p className="checklist__prompt">{item.prompt}</p>
            <p className="checklist__help">{item.help}</p>
            <div className="checklist__answers" role="group">
              {(["yes", "no", "unsure"] as const).map((v) => (
                <label key={v} className="checklist__answer">
                  <input
                    type="radio"
                    name={item.id}
                    checked={state[item.id] === v}
                    onChange={() => set(item.id, v)}
                  />
                  <span>{v === "unsure" ? "Not sure" : v[0].toUpperCase() + v.slice(1)}</span>
                </label>
              ))}
            </div>
          </li>
        ))}
      </ol>

      {answered > 0 && (
        <div
          className={
            "result " +
            (failedWeighted.length
              ? "result--danger"
              : anyUnsure || !allYes
                ? "result--warn"
                : "result--ok")
          }
        >
          <div className="result__verdict">
            {failedWeighted.length > 0 ? (
              <>
                <span className="result__badge">Stop and do not proceed</span>
                <p className="result__summary">
                  You answered “no” to {failedWeighted.length} critical check
                  {failedWeighted.length > 1 ? "s" : ""}:
                </p>
                <ul className="result__list">
                  {failedWeighted.map((i) => (
                    <li key={i.id}>{i.prompt}</li>
                  ))}
                </ul>
              </>
            ) : allYes ? (
              <>
                <span className="result__badge">Checks passed</span>
                <p className="result__summary">
                  Every check passed. That is a good sign — but stay alert if the
                  situation changes, especially any later request for money or
                  personal data.
                </p>
              </>
            ) : (
              <>
                <span className="result__badge">Keep verifying</span>
                <p className="result__summary">
                  Don’t proceed while anything is unanswered or “not sure”.
                  Resolve each item before sharing information or doing tasks.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
