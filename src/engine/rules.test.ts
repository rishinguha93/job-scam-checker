import { describe, expect, it } from "vitest";
import { runRules, rules } from "./rules";
import type { CheckInput } from "./types";

/** Convenience: which rule ids fired for this input. */
function firedIds(input: CheckInput): string[] {
  return runRules(input).map((f) => f.id);
}

describe("rule registry", () => {
  it("has unique rule ids", () => {
    const ids = runRules({
      text:
        "You are hired! Pay a refundable deposit via gift card and top up your " +
        "USDT wallet. Send your SSN and bank account. Contact me on Telegram.",
    }).map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("exposes every rule as a function", () => {
    expect(rules.length).toBeGreaterThanOrEqual(25);
    expect(rules.every((r) => typeof r === "function")).toBe(true);
  });
});

describe("money rules", () => {
  it("pay-to-start: fee for equipment/training", () => {
    expect(
      firedIds({ text: "You must pay for your training equipment upfront." }),
    ).toContain("pay-to-start");
  });

  it("wire-or-forward-funds: deposit check then wire the balance", () => {
    expect(
      firedIds({
        text: "Deposit the check we send, then wire the remaining balance to our vendor.",
      }),
    ).toContain("wire-or-forward-funds");
  });

  it("crypto-topup: negative balance, top up wallet to withdraw", () => {
    expect(
      firedIds({
        text: "Your balance is negative — top up your crypto wallet to unlock withdrawals.",
      }),
    ).toContain("crypto-topup");
  });

  it("gift-cards", () => {
    expect(firedIds({ text: "Please send payment as an Apple gift card." })).toContain(
      "gift-cards",
    );
  });

  it("cv-service-referral: sent to Fiverr for a rewrite", () => {
    expect(
      firedIds({
        text: "Your CV needs work — go to Fiverr and find a writer to fix it first.",
      }),
    ).toContain("cv-service-referral");
  });

  it("cv-service-referral: named CV writing service", () => {
    expect(
      firedIds({ text: "I'll pass you to our CV writing service before we submit." }),
    ).toContain("cv-service-referral");
  });

  it("cv-service-referral: CV work attached to a fee", () => {
    expect(
      firedIds({
        text: "We can get your resume reworked for a small fee before submission.",
      }),
    ).toContain("cv-service-referral");
  });

  it("cv-service-referral ignores a job that merely mentions Fiverr", () => {
    expect(
      firedIds({
        text:
          "The role involves managing Fiverr freelancers and agency partners. " +
          "Please send your CV if that sounds interesting.",
      }),
    ).not.toContain("cv-service-referral");
  });

  it("does not fire money rules on a clean note", () => {
    const ids = firedIds({
      text: "We cover all equipment costs and reimburse home-office expenses.",
    });
    expect(ids).not.toContain("pay-to-start");
    expect(ids).not.toContain("wire-or-forward-funds");
  });
});

describe("personal-data rules", () => {
  it("pii-before-offer", () => {
    expect(
      firedIds({ text: "Send your Social Security number and routing number to onboard." }),
    ).toContain("pii-before-offer");
  });

  it("account-credentials", () => {
    expect(
      firedIds({ text: "Reply with the one-time verification code we just sent you." }),
    ).toContain("account-credentials");
  });
});

describe("sender-identity rules", () => {
  it("freemail-sender when a company is claimed", () => {
    expect(
      firedIds({
        text: "I'm on the talent team.",
        fromEmail: "recruiter@gmail.com",
        claimedCompany: "Globex Inc",
      }),
    ).toContain("freemail-sender");
  });

  it("domain-company-mismatch", () => {
    expect(
      firedIds({
        text: "Reaching out from the hiring team.",
        fromEmail: "hr@totally-different.com",
        claimedCompany: "Initech",
      }),
    ).toContain("domain-company-mismatch");
  });

  it("lookalike-domain: bolt-on word", () => {
    expect(
      firedIds({ text: "Job offer attached.", fromEmail: "hr@initech-careers.com" }),
    ).toContain("lookalike-domain");
  });

  it("lookalike-domain: suspicious TLD", () => {
    expect(
      firedIds({ text: "Job offer attached.", fromEmail: "jobs@initech.online" }),
    ).toContain("lookalike-domain");
  });

  it("lookalike-domain: brand token that isn't the real domain", () => {
    expect(
      firedIds({ text: "Hello.", fromEmail: "careers@google-hiring-team.com" }),
    ).toContain("lookalike-domain");
  });

  it("replyto-mismatch", () => {
    expect(
      firedIds({
        text: "Thanks for your interest.",
        fromEmail: "recruiter@acme.com",
        replyToEmail: "collector@mail.ru",
      }),
    ).toContain("replyto-mismatch");
  });

  it("offplatform-push", () => {
    expect(
      firedIds({ text: "Please contact me on WhatsApp to continue the process." }),
    ).toContain("offplatform-push");
  });

  it("does not flag a matching corporate domain", () => {
    const ids = firedIds({
      text: "From the recruiting team.",
      fromEmail: "jane@initech.com",
      claimedCompany: "Initech",
    });
    expect(ids).not.toContain("freemail-sender");
    expect(ids).not.toContain("domain-company-mismatch");
    expect(ids).not.toContain("lookalike-domain");
  });
});

describe("offer-content and process rules", () => {
  it("unrealistic-pay: high pay for simple tasks", () => {
    expect(
      firedIds({ text: "Earn $400 a day doing simple data entry tasks from home." }),
    ).toContain("unrealistic-pay");
  });

  it("unrealistic-pay: high hourly rate for simple tasks", () => {
    expect(
      firedIds({ text: "Earn $60/hr doing simple, easy data entry tasks." }),
    ).toContain("unrealistic-pay");
  });

  it("unrealistic-pay stays quiet on an ordinary rate ($18/hr research study)", () => {
    const text =
      "Paid Research Study for Fluent Bengali Speakers - Remote, up to $18/hr. " +
      "It's a simple, easy online survey and I came across your profile.";
    expect(firedIds({ text })).not.toContain("unrealistic-pay");
  });

  it("no-experience-high-pay", () => {
    expect(
      firedIds({
        text: "No experience is needed and the salary starts at $5,000 per month.",
      }),
    ).toContain("no-experience-high-pay");
  });

  it("hired-no-interview", () => {
    expect(
      firedIds({ text: "Congratulations, you are hired. You can start immediately." }),
    ).toContain("hired-no-interview");
  });

  it("hired-no-interview stays quiet when a real interview is described", () => {
    expect(
      firedIds({
        text:
          "We would like to offer you the role after your video call with the hiring panel.",
      }),
    ).not.toContain("hired-no-interview");
  });

  it("urgency-pressure", () => {
    expect(
      firedIds({ text: "Only 2 slots left — respond within 15 minutes to secure yours." }),
    ).toContain("urgency-pressure");
  });

  it("unsolicited-contact", () => {
    expect(
      firedIds({ text: "We came across your resume and think you're a great fit." }),
    ).toContain("unsolicited-contact");
  });

  it('unsolicited-contact also catches "seen your profile on LinkedIn"', () => {
    expect(
      firedIds({
        text: "I have seen your profile on LinkedIn and you have great experience.",
      }),
    ).toContain("unsolicited-contact");
  });

  it("recruiter-phone-harvest: asked to leave a number", () => {
    expect(
      firedIds({
        text: "If you are interested, please leave your phone number and we will call you.",
      }),
    ).toContain("recruiter-phone-harvest");
  });

  it("unnamed-leader-handoff: passed to 'my leader'", () => {
    expect(
      firedIds({
        text: "I will forward it to my leadership and my leader will contact you shortly.",
      }),
    ).toContain("unnamed-leader-handoff");
  });

  it("offplatform-push: handoff to an SMS thread", () => {
    expect(
      firedIds({
        text: "My leader just added your text message, so reply to my leader's message.",
      }),
    ).toContain("offplatform-push");
  });

  it("job-desc-attachment: job description sent as a .docx", () => {
    expect(
      firedIds({
        text: "Here is your job description Support Specialist role.docx 11 KB Download",
      }),
    ).toContain("job-desc-attachment");
  });

  it("cv-criticism-pressure: your CV is run down", () => {
    expect(
      firedIds({ text: "Honestly your CV is weak and needs to be rewritten." }),
    ).toContain("cv-criticism-pressure");
  });

  it("cv-criticism-pressure: ATS fear framing", () => {
    expect(
      firedIds({ text: "Your resume won't get past the ATS in its current state." }),
    ).toContain("cv-criticism-pressure");
  });

  it("flattery-hook: stacked praise", () => {
    expect(
      firedIds({
        text:
          "You are a brilliant, exceptional candidate — truly impressed by what " +
          "I saw. You are exactly what we are looking for.",
      }),
    ).toContain("flattery-hook");
  });

  it("flattery-hook stays quiet on a single ordinary compliment", () => {
    expect(
      firedIds({
        text:
          "Your background is a strong match and I was impressed by your work at " +
          "Northwind. Would you be open to a call about the backend role?",
      }),
    ).not.toContain("flattery-hook");
  });

  it('unnamed-leader-handoff also catches "my boss will email you"', () => {
    expect(
      firedIds({ text: "Send me your email address and my boss will email you." }),
    ).toContain("unnamed-leader-handoff");
  });

  it('urgency-pressure also catches "remember to reply in time"', () => {
    expect(
      firedIds({ text: "Thanks, remember to reply in time so we can proceed." }),
    ).toContain("urgency-pressure");
  });

  it("unsolicited-contact stays quiet if the person applied", () => {
    expect(
      firedIds({
        text: "Thanks for the application you submitted; we came across your resume in our system.",
      }),
    ).not.toContain("unsolicited-contact");
  });

  it("vague-role: long message about an 'opportunity' with no job title", () => {
    const text =
      "Hello, we have a fantastic remote opportunity with our growing organisation. " +
      "The position offers flexible hours, weekly pay, and full support from our friendly " +
      "onboarding staff. Reply to express your interest and we will share the next steps " +
      "with you shortly. We look forward to welcoming you to the team very soon.";
    expect(firedIds({ text })).toContain("vague-role");
  });

  it("vague-role stays quiet when a title is named", () => {
    const text =
      "Hello, we have a fantastic remote opportunity for a marketing analyst with our " +
      "growing organisation. The position offers flexible hours and weekly pay plus full " +
      "support from our onboarding staff. Reply to express your interest and we will share " +
      "the next steps with you shortly.";
    expect(firedIds({ text })).not.toContain("vague-role");
  });

  it("generic-greeting", () => {
    expect(firedIds({ text: "Dear Candidate, we are pleased to contact you." })).toContain(
      "generic-greeting",
    );
  });

  it("grammar-artifacts: multiple template tells", () => {
    expect(
      firedIds({ text: "Kindly revert back to us with your details at the earliest." }),
    ).toContain("grammar-artifacts");
  });
});
