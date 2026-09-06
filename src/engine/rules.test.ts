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
    expect(rules.length).toBeGreaterThanOrEqual(37);
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

  it('pay-to-start catches the spelled-out "you will need to"', () => {
    expect(
      firedIds({
        text: "You will need to purchase your equipment before your start date.",
      }),
    ).toContain("pay-to-start");
  });

  it('pay-to-start catches the "buy it and we\'ll reimburse you" framing', () => {
    expect(
      firedIds({
        text:
          "Please buy the laptop from our approved vendor and we will reimburse " +
          "you with your first paycheck.",
      }),
    ).toContain("pay-to-start");
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

  it("offplatform-push: directed at a third party, not just 'me'", () => {
    expect(
      firedIds({
        text: "Please message our lead talent coordinator directly on WhatsApp.",
      }),
    ).toContain("offplatform-push");
  });

  it("offplatform-push: phone number written with hyphens", () => {
    expect(
      firedIds({ text: "You can reach the team on WhatsApp at +1-555-0199 today." }),
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

describe("link rules", () => {
  it("shortened-link", () => {
    expect(
      firedIds({ text: "Apply through this link: https://bit.ly/3xY9qL today." }),
    ).toContain("shortened-link");
  });

  it("shortened-link ignores LinkedIn's own shortener", () => {
    expect(
      firedIds({ text: "The posting is here: https://lnkd.in/abcd1234 have a look." }),
    ).not.toContain("shortened-link");
  });

  it("suspicious-link-host: look-alike domain", () => {
    expect(
      firedIds({ text: "Apply at https://amazon-careers-hiring.online/apply" }),
    ).toContain("suspicious-link-host");
  });

  it("suspicious-link-host: bare IP address", () => {
    expect(firedIds({ text: "Portal is at http://192.168.44.9/onboarding" })).toContain(
      "suspicious-link-host",
    );
  });

  it("suspicious-link-host stays quiet on real applicant-tracking links", () => {
    const ids = firedIds({
      text:
        "Here is the posting: https://boards.greenhouse.io/acme/jobs/12345 and " +
        "you can book a slot at https://calendly.com/acme-recruiting/30min",
    });
    expect(ids).not.toContain("suspicious-link-host");
  });

  it("form-host-link: Google Form used for onboarding", () => {
    expect(
      firedIds({
        text:
          "Complete your onboarding and direct deposit details here: " +
          "https://docs.google.com/forms/d/e/1FAIpQ/viewform",
      }),
    ).toContain("form-host-link");
  });
});

describe("software and code rules", () => {
  it("remote-access-tool", () => {
    expect(
      firedIds({ text: "Please install AnyDesk so I can set up your workstation." }),
    ).toContain("remote-access-tool");
  });

  it("executable-file: a .scr disguised as a PDF", () => {
    expect(
      firedIds({ text: "Please use the attached Job_Specs_PDF.scr to continue." }),
    ).toContain("executable-file");
  });

  it("executable-file: double extension", () => {
    expect(
      firedIds({ text: "Open the attached offer_letter.pdf.exe for details." }),
    ).toContain("executable-file");
  });

  it("executable-file stays quiet on ordinary documents", () => {
    expect(
      firedIds({
        text:
          "I've attached the job description as briefing.pdf and the team " +
          "structure in overview.docx for you to look through.",
      }),
    ).not.toContain("executable-file");
  });

  it("install-software-request", () => {
    expect(
      firedIds({ text: "Download our interview platform to attend the assessment." }),
    ).toContain("install-software-request");
  });

  it("install-software-request stays quiet for Zoom and Teams", () => {
    expect(
      firedIds({ text: "Please install Zoom before the call if you don't have it." }),
    ).not.toContain("install-software-request");
  });

  it("run-code-request", () => {
    expect(
      firedIds({
        text:
          "Before the technical interview, please clone the repository and run " +
          "npm install to review the codebase.",
      }),
    ).toContain("run-code-request");
  });
});

describe("onboarding, interview format and illegal roles", () => {
  it("onboarding-paperwork-early: W-4 and direct deposit", () => {
    expect(
      firedIds({ text: "Complete the attached W-4 and your direct deposit form." }),
    ).toContain("onboarding-paperwork-early");
  });

  it("interview-bypass: moving forward without the screening call", () => {
    expect(
      firedIds({
        text:
          "The hiring manager wants to move forward immediately without a " +
          "standard screening call.",
      }),
    ).toContain("interview-bypass");
  });

  it("interview-bypass: no interview required", () => {
    expect(
      firedIds({ text: "Good news — no interview is required for this role." }),
    ).toContain("interview-bypass");
  });

  it('interview-bypass: "no formal interview is needed"', () => {
    expect(
      firedIds({
        text: "No formal interview is needed with the hiring manager for this role.",
      }),
    ).toContain("interview-bypass");
  });

  it("interview-bypass is not tripped by an unrelated 'no'", () => {
    expect(
      firedIds({
        text:
          "There is no cost to you, and an interview with the team is required " +
          "before any offer is made.",
      }),
    ).not.toContain("interview-bypass");
  });

  it("interview-bypass stays quiet when a real process is described", () => {
    expect(
      firedIds({
        text:
          "The process is a screening call with me, then a technical interview " +
          "with the team, then a final conversation with the director.",
      }),
    ).not.toContain("interview-bypass");
  });

  it("confidential-role", () => {
    expect(
      firedIds({ text: "This is a confidential position with one of our clients." }),
    ).toContain("confidential-role");
  });

  it("chat-only-interview: interview over Teams chat", () => {
    expect(
      firedIds({ text: "Your interview will be conducted via chat on Microsoft Teams." }),
    ).toContain("chat-only-interview");
  });

  it("chat-only-interview: no video required", () => {
    expect(
      firedIds({ text: "This is a written screening — no video is required." }),
    ).toContain("chat-only-interview");
  });

  it("reshipping-role: receive packages at home and forward them", () => {
    expect(
      firedIds({
        text:
          "You will receive packages at your home address and forward them to " +
          "our clients using labels we provide.",
      }),
    ).toContain("reshipping-role");
  });

  it("reshipping-role: package inspector title", () => {
    expect(
      firedIds({ text: "We are hiring a remote package inspector for our team." }),
    ).toContain("reshipping-role");
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

  it("unrealistic-pay: a high rate attached to no named role", () => {
    expect(
      firedIds({
        text:
          "We have an urgent remote opening for a [Your Field] position. The pay " +
          "is $95/hour with flexible hours.",
      }),
    ).toContain("unrealistic-pay");
  });

  it("unrealistic-pay stays quiet on a high rate for a named senior role", () => {
    // $95/hr is ordinary contractor pay when the job actually exists.
    expect(
      firedIds({
        text:
          "We're hiring a senior backend engineer on a 6-month contract at " +
          "$95/hour. The team works on payments infrastructure.",
      }),
    ).not.toContain("unrealistic-pay");
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

  it('flattery-hook: "very impressed" plus "fits perfectly"', () => {
    expect(
      firedIds({
        text:
          "I am very impressed by your background, and this role fits your " +
          "experience perfectly.",
      }),
    ).toContain("flattery-hook");
  });

  it('urgency-pressure: "complete this within 24 hours"', () => {
    expect(
      firedIds({ text: "Please complete this review within 24 hours to continue." }),
    ).toContain("urgency-pressure");
  });

  it('urgency-pressure: "time is critical" and review groups', () => {
    expect(
      firedIds({ text: "Time is critical for the first review group!" }),
    ).toContain("urgency-pressure");
  });

  it('onboarding-paperwork-early: "onboarding questionnaire"', () => {
    expect(
      firedIds({ text: "Please fill out our onboarding questionnaire to continue." }),
    ).toContain("onboarding-paperwork-early");
  });

  it('job-desc-attachment: "download the job specs"', () => {
    expect(
      firedIds({ text: "Click the link to download the job specs and review them." }),
    ).toContain("job-desc-attachment");
  });

  it("vague-role is not satisfied by the sender's own job title", () => {
    const text =
      "Hi, I came across your profile and I am impressed by your background. " +
      "We are recruiting for a high-level, confidential remote position with an " +
      "incredible salary that suits you. The hiring manager wants to move ahead " +
      "and our lead talent coordinator will be in touch with you very shortly.";
    expect(firedIds({ text })).toContain("vague-role");
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
