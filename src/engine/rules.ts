/**
 * Individual red-flag rules.
 *
 * Each rule is a pure function: it inspects a {@link CheckInput} and returns a
 * {@link Finding} on a match, or `null`. Keep this file in sync with
 * `docs/ruleset.md`.
 */

import type { CheckInput, Finding, Rule } from "./types";

/* -------------------------------------------------------------------------- */
/* Matching helpers                                                            */
/* -------------------------------------------------------------------------- */

const FREEMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "yahoo.com",
  "ymail.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "mail.com",
  "icloud.com",
  "zoho.com",
]);

/** Pull the domain from an email address, lowercased. */
export function emailDomain(email: string | undefined): string | null {
  if (!email) return null;
  const match = email.trim().toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})$/);
  return match ? match[1] : null;
}

/** Loose slug of a company name: lowercase alphanumerics only. */
export function companySlug(name: string | undefined): string | null {
  if (!name) return null;
  const slug = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  return slug.length >= 3 ? slug : null;
}

/**
 * Return a short, trimmed snippet of `text` around the first match of `re`,
 * suitable for showing the user as evidence. Returns `null` if no match.
 */
export function snippetAround(text: string, re: RegExp): string | null {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  const rx = new RegExp(re.source, flags);
  const m = rx.exec(text);
  if (!m) return null;
  const pad = 45;
  const start = Math.max(0, m.index - pad);
  const end = Math.min(text.length, m.index + m[0].length + pad);
  let out = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (start > 0) out = "…" + out;
  if (end < text.length) out = out + "…";
  return out;
}

/** All distinct snippets for a list of patterns that actually matched. */
function evidenceFor(text: string, patterns: RegExp[]): string[] {
  const seen = new Set<string>();
  for (const p of patterns) {
    const s = snippetAround(text, p);
    if (s && !seen.has(s)) seen.add(s);
  }
  return [...seen];
}

/** Does any pattern match the text? */
function anyMatch(text: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(text));
}

/* -------------------------------------------------------------------------- */
/* Money — critical                                                           */
/* -------------------------------------------------------------------------- */

const payToStartPatterns = [
  /\bpay(?:ment)?\b[^.]{0,40}\b(equipment|training|certification|certificate|background check|starter kit|onboarding fee|registration fee|processing fee|activation fee)\b/i,
  /\b(you(?:'| a)?ll? need to|please|kindly)\b[^.]{0,30}\b(pay|purchase|buy|cover|send)\b[^.]{0,30}\b(fee|equipment|kit|software|license)\b/i,
  /\brefundable (deposit|fee)\b/i,
];

const payToStart: Rule = (input) => {
  const ev = evidenceFor(input.text, payToStartPatterns);
  if (!ev.length) return null;
  return {
    id: "pay-to-start",
    category: "money",
    severity: "critical",
    title: "Asks you to pay to get started",
    detail:
      "A legitimate employer never asks you to pay for equipment, training, " +
      "certifications, or a background check. The cost is theirs, not yours.",
    evidence: ev,
    advice: "Do not pay anything. This alone is enough to walk away.",
  };
};

const wireForwardPatterns = [
  /\b(wire|western union|moneygram|zelle|cash ?app|venmo)\b[^.]{0,40}\b(us|me|the vendor|the supplier|this account)\b/i,
  /\b(send|forward|transfer|return) (back |the )?(remaining|balance|difference|excess|overpayment)\b/i,
  /\bdeposit (the )?check\b[^.]{0,40}\b(then|and) (send|wire|transfer)\b/i,
];

const wireOrForwardFunds: Rule = (input) => {
  const ev = evidenceFor(input.text, wireForwardPatterns);
  if (!ev.length) return null;
  return {
    id: "wire-or-forward-funds",
    category: "money",
    severity: "critical",
    title: "Asks you to move or forward money",
    detail:
      "Being sent a check and asked to wire part of it back is the classic " +
      "fake-check scam: the check bounces days later and you owe the bank.",
    evidence: ev,
    advice: "Do not deposit checks or forward funds. Stop contact.",
  };
};

const cryptoTopupPatterns = [
  /\b(deposit|recharge|top ?up|add funds)\b[^.]{0,40}\b(to (unlock|withdraw|continue)|balance|wallet)\b/i,
  /\b(usdt|tether|bitcoin|btc|ethereum|eth|crypto(currency)?)\b[^.]{0,40}\b(wallet|deposit|recharge)\b/i,
  /\bnegative balance\b[^.]{0,40}\b(pay|deposit|top ?up)\b/i,
  /\bcombo tasks?\b/i,
];

const cryptoTopup: Rule = (input) => {
  const ev = evidenceFor(input.text, cryptoTopupPatterns);
  if (!ev.length) return null;
  return {
    id: "crypto-topup",
    category: "money",
    severity: "critical",
    title: 'Asks you to deposit or "top up" funds to get paid',
    detail:
      "This is the core mechanic of task scams: your balance goes negative and " +
      'you are told to deposit crypto to "unlock" withdrawals. The money is gone.',
    evidence: ev,
    advice: "Send nothing. Do not try to recover a balance by depositing more.",
  };
};

const giftCardPatterns = [
  /\b(gift ?card|steam card|apple card|google play card|amazon card|vanilla card)\b/i,
];

const giftCards: Rule = (input) => {
  const ev = evidenceFor(input.text, giftCardPatterns);
  if (!ev.length) return null;
  return {
    id: "gift-cards",
    category: "money",
    severity: "critical",
    title: "Mentions gift cards",
    detail:
      "Gift cards are never used in a real hiring or payroll process. Any " +
      "request involving them is a scam.",
    evidence: ev,
    advice: "Do not buy gift cards or share their codes.",
  };
};

/* -------------------------------------------------------------------------- */
/* Personal data — critical                                                   */
/* -------------------------------------------------------------------------- */

const piiPatterns = [
  /\b(social security( number)?|ssn)\b/i,
  /\b(bank account|routing number|account and routing)\b/i,
  /\b(date of birth|dob)\b/i,
  /\b(passport|driver'?s? licen[sc]e|national id)\b/i,
  /\bvoided check\b/i,
];

const piiBeforeOffer: Rule = (input) => {
  const ev = evidenceFor(input.text, piiPatterns);
  if (!ev.length) return null;
  return {
    id: "pii-before-offer",
    category: "personal-data",
    severity: "critical",
    title: "Requests sensitive personal information",
    detail:
      "Social Security numbers, bank details, and ID scans are only needed " +
      "after you have accepted a written offer and verified the employer. " +
      "Asking earlier points to identity theft.",
    evidence: ev,
    advice:
      "Do not send any of this until you have independently confirmed the " +
      "employer and signed a real offer.",
  };
};

const credentialPatterns = [
  /\b(your )?(password|passcode)\b/i,
  /\b(one[- ]time|verification|security|2fa|authentication) code\b/i,
  /\blog ?in (to|with) (your|the)\b/i,
];

const accountCredentials: Rule = (input) => {
  const ev = evidenceFor(input.text, credentialPatterns);
  if (!ev.length) return null;
  return {
    id: "account-credentials",
    category: "personal-data",
    severity: "critical",
    title: "Asks for a password or verification code",
    detail:
      "No employer needs your passwords or one-time codes. This is an attempt " +
      "to take over one of your accounts.",
    evidence: ev,
    advice: "Never share passwords or codes. Ignore and block.",
  };
};

/* -------------------------------------------------------------------------- */
/* Sender / identity                                                          */
/* -------------------------------------------------------------------------- */

const freemailSender: Rule = (input) => {
  const domain = emailDomain(input.fromEmail);
  if (!domain || !FREEMAIL_DOMAINS.has(domain)) return null;
  const companyMentioned =
    !!companySlug(input.claimedCompany) ||
    /\b(inc|llc|ltd|corp|company|team at)\b/i.test(input.text);
  if (!companyMentioned) return null;
  return {
    id: "freemail-sender",
    category: "sender-identity",
    severity: "high",
    title: `Sent from a personal ${domain} address`,
    detail:
      "A recruiter representing a real company almost always writes from that " +
      "company's own domain, not a free personal mailbox.",
    evidence: [input.fromEmail ?? domain],
    advice:
      "Find the company's real careers contact on its official website and " +
      "verify there.",
  };
};

const domainCompanyMismatch: Rule = (input) => {
  const domain = emailDomain(input.fromEmail);
  const slug = companySlug(input.claimedCompany);
  if (!domain || !slug) return null;
  if (FREEMAIL_DOMAINS.has(domain)) return null; // covered by freemail rule
  const domainCore = domain.split(".").slice(0, -1).join("");
  if (domainCore.includes(slug) || slug.includes(domainCore)) return null;
  return {
    id: "domain-company-mismatch",
    category: "sender-identity",
    severity: "high",
    title: `Email domain (${domain}) does not match "${input.claimedCompany}"`,
    detail:
      "The sending domain has no obvious relationship to the company the " +
      "sender claims to represent.",
    evidence: [input.fromEmail ?? domain],
    advice:
      "Treat the domain, not the display name, as the identity. Verify on the " +
      "company's official site.",
  };
};

const offPlatformPatterns = [
  /\b(contact|message|reach|add|text|dm) (me|us|the hiring manager)\b[^.]{0,30}\b(on|via|through|at)\b[^.]{0,15}\b(whats ?app|telegram|signal|skype|wechat)\b/i,
  /\b(whats ?app|telegram|signal|skype)\b[^.]{0,20}\b(number|handle|id|\+?\d{6,})\b/i,
  /\bwe (only )?(interview|hire|onboard) (via|through|on)\b[^.]{0,15}\b(whats ?app|telegram|signal|skype)\b/i,
];

const offPlatformPush: Rule = (input) => {
  const ev = evidenceFor(input.text, offPlatformPatterns);
  if (!ev.length) return null;
  return {
    id: "offplatform-push",
    category: "sender-identity",
    severity: "high",
    title: "Pushes you to chat on WhatsApp / Telegram / Signal",
    detail:
      "Scammers move fast to an unmonitored app where there is no employer " +
      "record and no way to verify who you are talking to.",
    evidence: ev,
    advice:
      "Keep communication on the original platform or company email until the " +
      "employer is verified.",
  };
};

/* -------------------------------------------------------------------------- */
/* Offer / content                                                            */
/* -------------------------------------------------------------------------- */

const unrealisticPayPatterns = [
  /\$\s?\d{2,4}(?:[.,]\d{2})?\s*(?:\/|per |a )\s?(?:hour|hr|day)\b/i,
  /\bearn(?:ing)?s? (?:up to )?\$\s?\d{3,4}\b[^.]{0,30}\b(daily|per day|a day|weekly|per week)\b/i,
  /\$\s?\d,\d{3}\s*(?:\/|per |a )\s?week\b/i,
];

const simpleWorkNearby =
  /\b(simple|easy|basic|no experience|entry[- ]level|part[- ]time|data entry|copy[- ]?paste|reviewing|liking|rating|clicking)\b/i;

const unrealisticPay: Rule = (input) => {
  if (!anyMatch(input.text, unrealisticPayPatterns)) return null;
  if (!simpleWorkNearby.test(input.text)) return null;
  return {
    id: "unrealistic-pay",
    category: "offer-content",
    severity: "high",
    title: "Pay is far above market for the work described",
    detail:
      "Offers of several hundred dollars a day for simple, low-skill tasks are " +
      "a lure. The pay does not correspond to any real job.",
    evidence: evidenceFor(input.text, unrealisticPayPatterns),
    advice: "Compare the rate to real listings for the same work. Be skeptical.",
  };
};

const hiredNoInterviewPatterns = [
  /\b(you(?:'| a)?re hired|congratulations[,!]? you|we would like to offer you|offer you (the|this) (position|role|job))\b/i,
  /\bstart (immediately|today|tomorrow|right away)\b/i,
];

const hiredNoInterview: Rule = (input) => {
  const ev = evidenceFor(input.text, hiredNoInterviewPatterns);
  if (!ev.length) return null;
  const realInterview =
    /\b(interview|phone screen|video call|meet the team|hiring panel)\b/i.test(
      input.text,
    ) && !/\b(interview) (via|on|through) (whats ?app|telegram|skype)\b/i.test(input.text);
  if (realInterview) return null;
  return {
    id: "hired-no-interview",
    category: "process",
    severity: "high",
    title: "Offers the job with no real interview",
    detail:
      "Being hired after a few chat messages, with no interview with an " +
      "identifiable person, is not how legitimate hiring works.",
    evidence: ev,
    advice:
      "Insist on a video interview with someone whose identity you can verify " +
      "on the company site.",
  };
};

const urgencyPatterns = [
  /\b(limited (slots|spots|positions)|positions? (are )?filling fast|only \d+ (slots|spots) left)\b/i,
  /\b(respond|reply|confirm|act) (with)?in (the next )?\d+ ?(min(ute)?s?|hours?|hrs?)\b/i,
  /\b(today only|act now|don'?t miss (this|out)|immediate start required)\b/i,
];

const urgencyPressure: Rule = (input) => {
  const ev = evidenceFor(input.text, urgencyPatterns);
  if (!ev.length) return null;
  return {
    id: "urgency-pressure",
    category: "offer-content",
    severity: "medium",
    title: "Uses time pressure to rush your decision",
    detail:
      "Manufactured urgency is designed to stop you from checking details or " +
      "asking other people.",
    evidence: ev,
    advice: "Slow down. A real employer will wait a day while you verify.",
  };
};

const genericGreetingPatterns = [
  /^(\s*)(dear (candidate|applicant|job seeker|sir\/madam|hiring candidate)|hello dear|hi dear|dear valued applicant)\b/im,
];

const genericGreeting: Rule = (input) => {
  const ev = evidenceFor(input.text, genericGreetingPatterns);
  if (!ev.length) return null;
  return {
    id: "generic-greeting",
    category: "offer-content",
    severity: "low",
    title: "Impersonal, mass-mail greeting",
    detail:
      'A recruiter who genuinely reviewed your profile usually uses your name, ' +
      'not "Dear Candidate".',
    evidence: ev,
    advice: "Weak on its own, but note it alongside the other signals.",
  };
};

/* -------------------------------------------------------------------------- */
/* Registry                                                                   */
/* -------------------------------------------------------------------------- */

/** All rules, in display order. */
export const rules: Rule[] = [
  payToStart,
  wireOrForwardFunds,
  cryptoTopup,
  giftCards,
  piiBeforeOffer,
  accountCredentials,
  freemailSender,
  domainCompanyMismatch,
  offPlatformPush,
  unrealisticPay,
  hiredNoInterview,
  urgencyPressure,
  genericGreeting,
];

/** Run every rule against the input and collect the findings. */
export function runRules(input: CheckInput): Finding[] {
  const out: Finding[] = [];
  for (const rule of rules) {
    const finding = rule(input);
    if (finding) out.push(finding);
  }
  return out;
}
