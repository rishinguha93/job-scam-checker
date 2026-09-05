import { useState } from "react";
import { recoveryPlan, type Exposure } from "../data/reportingLinks";

const OPTIONS: { value: Exposure; label: string; help: string }[] = [
  {
    value: "money",
    label: "I sent money",
    help: "Wire, bank transfer, crypto, gift cards, or deposited a check they sent.",
  },
  {
    value: "personal-data",
    label: "I shared personal information",
    help: "SSN, date of birth, bank account / routing number, or a photo of an ID.",
  },
  {
    value: "credentials",
    label: "I shared a password or login code",
    help: "A password, or a one-time / verification code from a text or app.",
  },
  {
    value: "nothing-yet",
    label: "Nothing yet — but I'm worried",
    help: "You've been in contact but haven't handed anything over.",
  },
];

export function Scammed() {
  const [exposure, setExposure] = useState<Exposure | null>(null);
  const steps = exposure ? recoveryPlan(exposure) : [];

  return (
    <section className="view">
      <h1>I think I've been scammed</h1>
      <p className="view__lead">
        Take a breath — acting in the next day or two matters more than acting in
        the next minute, and none of this is your fault. Tell us what was shared
        and we’ll list the steps in order.
      </p>

      <div className="options">
        {OPTIONS.map((o) => (
          <button
            key={o.value}
            type="button"
            className={
              "option" + (exposure === o.value ? " option--selected" : "")
            }
            onClick={() => setExposure(o.value)}
          >
            <span className="option__label">{o.label}</span>
            <span className="option__help">{o.help}</span>
          </button>
        ))}
      </div>

      {exposure && (
        <ol className="steps">
          {steps.map((step, i) => (
            <li
              key={i}
              className={"step" + (step.urgent ? " step--urgent" : "")}
            >
              <h2 className="step__action">
                {step.urgent && <span className="step__flag">Do now</span>}
                {step.action}
              </h2>
              <p className="step__detail">{step.detail}</p>
              {step.resources && step.resources.length > 0 && (
                <ul className="step__resources">
                  {step.resources.map((r) => (
                    <li key={r.url}>
                      <a href={r.url} target="_blank" rel="noreferrer noopener">
                        {r.label}
                      </a>
                      <span className="step__resource-when"> — {r.when}</span>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ol>
      )}

      <p className="note">
        Reporting links are US agencies. If you're elsewhere, report to your
        national consumer-protection or cybercrime agency and your bank.
      </p>
    </section>
  );
}
