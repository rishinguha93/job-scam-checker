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

/** Any mention of the applicant's CV — context gate for the CV-upsell rules. */
const cvMention = /\b(cv|resume|résumé)\b/i;

const cvServiceReferralPatterns = [
  // Pointed at a freelance marketplace. Requires a directive verb so a job
  // description that merely mentions managing Fiverr freelancers won't match.
  /\b(go to|head (to|over)|check out|use|try|visit|sign up (on|to|for)|find (someone|a writer) on|there'?s (a|someone) on|i (use|recommend)|recommended?)\b[^.]{0,50}\b(fiverr|upwork|freelancer\.com|peopleperhour)\b/i,
  // A named CV-writing service.
  /\b(cv|resume|résumé)[- ]?(writer|writing service|writing agency|specialist|consultant|expert)\b/i,
  // "I know someone who can sort your CV out."
  /\b(i (can )?(recommend|refer|connect you (to|with))|i know (a|someone)|my (colleague|contact|friend|partner))\b[^.]{0,70}\b(cv|resume|résumé|rewrite|rewriting)\b/i,
  // CV work attached to a price.
  /\b(cv|resume|résumé)\b[^.]{0,70}\b((small|nominal|one[- ]time|modest) (fee|charge|cost)|costs? (only |just )?\$|starts? (at|from) \$|payment plan)\b/i,
];

const cvServiceReferral: Rule = (input) => {
  if (!cvMention.test(input.text)) return null;
  const ev = evidenceFor(input.text, cvServiceReferralPatterns);
  if (!ev.length) return null;
  return {
    id: "cv-service-referral",
    category: "money",
    severity: "critical",
    title: "Routes you to a paid CV/resume service",
    detail:
      "A real recruiter is paid by the employer and has no reason to send you " +
      "somewhere to buy a CV rewrite. In this scam the “recruiter” and the " +
      "writer are often the same person, and the job never existed.",
    evidence: ev,
    advice:
      "Do not pay anyone to rewrite your CV in order to be considered. Walk " +
      "away and report the profile.",
  };
};

const cvCriticismPatterns = [
  /\byour (cv|resume|résumé)\b[^.]{0,50}\b(is|isn'?t|looks|seems|won'?t|will not|needs?|requires?)\b[^.]{0,40}\b(weak|poor|bad|terrible|outdated|old[- ]fashioned|not (good|strong) enough|improve[md]?|improvement|rewritten|rewrite|revamp(ed)?|updating|optimi[sz]ed?|reformatted|professionally (written|formatted))\b/i,
  /\b(cv|resume|résumé)\b[^.]{0,40}\b(won'?t|will not|does ?n'?t|failed to) (pass|get (past|through)|make it (past|through)|beat)\b[^.]{0,25}\b(ats|applicant tracking|our system|the system|screening)\b/i,
  /\b(ats)[- ](friendly|optimi[sz]ed|compliant|ready)\b/i,
  /\b(before (i|we) (can|could) (submit|proceed|send|forward)|in order to (proceed|submit))\b[^.]{0,60}\b(cv|resume|résumé)\b/i,
];

const cvCriticismPressure: Rule = (input) => {
  const ev = evidenceFor(input.text, cvCriticismPatterns);
  if (!ev.length) return null;
  return {
    id: "cv-criticism-pressure",
    category: "process",
    severity: "medium",
    title: "Runs down your CV and pushes you to get it rewritten",
    detail:
      "Manufacturing a problem with your CV is the setup step for a paid " +
      "rewrite pitch. Genuine recruiters give feedback for free, or submit you " +
      "as you are.",
    evidence: ev,
    advice:
      "If a paid service is suggested next, stop. Ask instead which specific " +
      "role they are submitting you for.",
  };
};

const flatteryPatterns = [
  /\b(brilliant|outstanding|exceptional|remarkable|extraordinary|stellar|phenomenal)\b/i,
  /\b(rare (talent|find|combination)|one in a million|perfect (candidate|fit|match)|exactly what (we|our client)('| a)?(re| is)? (looking for|need))\b/i,
  /\b(blown away|truly impressed|really impressed|so impressed|highly impressed)\b/i,
  /\byour (profile|background|experience|career)\b[^.]{0,30}\b(stood out|caught my eye|really stands out)\b/i,
];

const flatteryHook: Rule = (input) => {
  // One compliment is ordinary recruiter language; a pile of them is a hook.
  const ev = evidenceFor(input.text, flatteryPatterns);
  if (ev.length < 2) return null;
  return {
    id: "flattery-hook",
    category: "offer-content",
    severity: "low",
    title: "Lays on heavy praise before saying anything concrete",
    detail:
      "Stacked flattery early in an unsolicited approach is a rapport-building " +
      "tactic — it makes the ask that follows harder to refuse.",
    evidence: ev,
    advice:
      "Weak on its own. Note what they actually offer: a named role, a company, " +
      "and a written description.",
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
  // Handoff to SMS / an intermediary's chat thread.
  /\b(reply to|replied to|respond to|check|see|read) (my|the|your) (leader|manager|colleague|supervisor|boss)('?s)? (message|text)\b/i,
  /\b(added|sent|shared) your (text message|number|contact|whats ?app)\b/i,
  /\b(continue|chat|talk|speak|communicate|keep in touch) (with (me|us|my leader|him|her) )?(by|via|over|through|on) (text|sms|text message)\b/i,
];

const offPlatformPush: Rule = (input) => {
  const ev = evidenceFor(input.text, offPlatformPatterns);
  if (!ev.length) return null;
  return {
    id: "offplatform-push",
    category: "sender-identity",
    severity: "high",
    title: "Moves the conversation onto an unmonitored channel",
    detail:
      "Scammers move fast to WhatsApp, Telegram, Signal, or a plain SMS thread " +
      "with a third party — somewhere there is no employer record and no way to " +
      "verify who you are talking to.",
    evidence: ev,
    advice:
      "Keep communication on the original platform or company email until the " +
      "employer is verified.",
  };
};

/* -------------------------------------------------------------------------- */
/* Offer / content                                                            */
/* -------------------------------------------------------------------------- */

type PayUnit = "hour" | "day" | "week";

/**
 * Pay-figure patterns, each with a capture group around the numeric amount so
 * the amount itself — not just the presence of a dollar sign — can be judged
 * against a market-rate threshold below.
 */
const payFigurePatterns: { re: RegExp; unit: PayUnit }[] = [
  { re: /\$\s?(\d{1,4}(?:\.\d{2})?)\s*(?:\/|per |a )\s?(?:hour|hr)\b/gi, unit: "hour" },
  { re: /\$\s?(\d{1,4}(?:\.\d{2})?)\s*(?:\/|per |a )\s?day\b/gi, unit: "day" },
  {
    re: /\bearn(?:ing)?s? (?:up to )?\$\s?(\d{1,3}(?:,\d{3})?)\b[^.]{0,30}\b(?:daily|per day|a day)\b/gi,
    unit: "day",
  },
  {
    re: /\bearn(?:ing)?s? (?:up to )?\$\s?(\d{1,3}(?:,\d{3})?)\b[^.]{0,30}\b(?:weekly|per week)\b/gi,
    unit: "week",
  },
  { re: /\$\s?(\d{1,2},\d{3})\s*(?:\/|per |a )\s?week\b/gi, unit: "week" },
];

/**
 * Above these, pay for "simple"/low-skill work is implausible enough to be a
 * lure. Below them it's ordinary gig/hourly pay (e.g. paid research studies
 * commonly run $10-25/hr) and should not be flagged.
 */
const PAY_THRESHOLD: Record<PayUnit, number> = {
  hour: 40,
  day: 200,
  week: 1200,
};

const simpleWorkNearby =
  /\b(simple|easy|basic|no experience|entry[- ]level|part[- ]time|data entry|copy[- ]?paste|reviewing|liking|rating|clicking)\b/i;

/** Snippet of `text` around a specific match position/length. */
function snippetAt(text: string, index: number, length: number): string {
  const pad = 45;
  const start = Math.max(0, index - pad);
  const end = Math.min(text.length, index + length + pad);
  let out = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (start > 0) out = "…" + out;
  if (end < text.length) out = out + "…";
  return out;
}

/** Pay-figure matches whose amount clears the market-rate threshold for its unit. */
function findUnrealisticPay(text: string): string[] {
  const hits: string[] = [];
  for (const { re, unit } of payFigurePatterns) {
    for (const m of text.matchAll(re)) {
      const amount = Number(m[1].replace(/,/g, ""));
      if (!Number.isNaN(amount) && amount >= PAY_THRESHOLD[unit]) {
        hits.push(snippetAt(text, m.index, m[0].length));
      }
    }
  }
  return [...new Set(hits)];
}

const unrealisticPay: Rule = (input) => {
  const evidence = findUnrealisticPay(input.text);
  if (!evidence.length) return null;
  if (!simpleWorkNearby.test(input.text)) return null;
  return {
    id: "unrealistic-pay",
    category: "offer-content",
    severity: "high",
    title: "Pay is far above market for the work described",
    detail:
      "Offers of several hundred dollars a day (or tens of dollars an hour) for " +
      "simple, low-skill tasks are a lure. The pay does not correspond to any " +
      "real job.",
    evidence,
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
  /\b(remember to|make sure to|be sure to|please) (reply|respond|get back to (me|us))\b[^.]{0,20}\b(in time|promptly|quickly|right away|asap)\b/i,
  /\b(reply|respond|get back to (me|us))\b[^.]{0,15}\b(in time|promptly)\b/i,
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

/** TLDs disproportionately used for throwaway impersonation domains. */
const SUSPICIOUS_TLDS = new Set([
  "online",
  "info",
  "site",
  "xyz",
  "top",
  "click",
  "buzz",
  "work",
  "shop",
  "icu",
  "cyou",
  "sbs",
]);

/** Well-known employer/brand tokens people try to impersonate. */
const BRAND_TOKENS = [
  "google",
  "microsoft",
  "apple",
  "amazon",
  "meta",
  "linkedin",
  "netflix",
  "oracle",
  "deloitte",
  "accenture",
  "pwc",
  "kpmg",
  "cisco",
  "adobe",
  "salesforce",
];

const lookalikeDomain: Rule = (input) => {
  const domain = emailDomain(input.fromEmail);
  if (!domain || FREEMAIL_DOMAINS.has(domain)) return null;

  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  const core = parts.slice(0, -1).join(".");
  const reasons: string[] = [];

  if (/[-.](careers?|hr|jobs?|recruit(ing|ment)?|talent|hiring|apply)$/.test(core) ||
      /^(careers?|hr|jobs?|recruit(ing|ment)?|talent|hiring|apply)[-.]/.test(core)) {
    reasons.push('bolt-on word like "-careers" or "hr-"');
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(`unusual .${tld} domain ending`);
  }
  for (const brand of BRAND_TOKENS) {
    if (core.includes(brand) && core !== brand && !core.endsWith(`.${brand}`)) {
      reasons.push(`contains "${brand}" but is not that company's real domain`);
      break;
    }
  }
  if (/\d/.test(core.replace(/\d{4,}/g, "")) && /[a-z]/.test(core)) {
    // digits mixed into an otherwise alphabetic name (e.g. g00gle, amaz0n)
    if (/[a-z]\d|\d[a-z]/.test(core)) reasons.push("digits substituted for letters");
  }

  if (!reasons.length) return null;
  return {
    id: "lookalike-domain",
    category: "sender-identity",
    severity: "high",
    title: `Sending domain "${domain}" looks like an impersonation`,
    detail:
      "The domain is built to resemble a real company at a glance: " +
      reasons.join("; ") +
      ". Real recruiters use the company's plain primary domain.",
    evidence: [input.fromEmail ?? domain],
    advice:
      "Type the company's name into a search engine and compare the domain to " +
      "the one on their official site.",
  };
};

const replyToMismatch: Rule = (input) => {
  const from = emailDomain(input.fromEmail);
  const reply = emailDomain(input.replyToEmail);
  if (!from || !reply || from === reply) return null;
  return {
    id: "replyto-mismatch",
    category: "sender-identity",
    severity: "medium",
    title: `Replies go to a different domain (${reply}, not ${from})`,
    detail:
      "The visible sender and the address that receives your reply don't " +
      "match, a common trick to catch replies at an attacker-controlled inbox.",
    evidence: [
      `From: ${input.fromEmail ?? from}`,
      `Reply-To: ${input.replyToEmail ?? reply}`,
    ],
    advice: "Don't reply directly. Contact the company through its own website.",
  };
};

const noExperiencePatterns = [
  /\bno (experience|skills?|qualifications?|degree|resume|cv)\s+(is\s+)?(needed|required|necessary)\b/i,
  /\b(anyone|everyone) can (do|apply)\b/i,
  /\bno interview (needed|required)\b/i,
];

const noExperienceHighPay: Rule = (input) => {
  const ev = evidenceFor(input.text, noExperiencePatterns);
  if (!ev.length) return null;
  const hasPayFigure = /\$\s?\d/.test(input.text) ||
    /\b(salary|pay|compensation|earn)\b/i.test(input.text);
  if (!hasPayFigure) return null;
  return {
    id: "no-experience-high-pay",
    category: "offer-content",
    severity: "medium",
    title: 'Promises pay while asking for "no experience"',
    detail:
      "Legitimate paid roles have requirements. Pairing a salary with " +
      '"no experience needed" is a hallmark of recruitment fraud.',
    evidence: ev,
    advice: "Look for the same title on real job boards and compare the ask.",
  };
};

const unsolicitedPatterns = [
  /\b(found|came across|come across|discovered|stumbled (up)?on|seen|saw|viewed|noticed|reviewed|looked at|looked through|impressed by|checked out) your (linkedin |online )?(profile|resume|cv|cover letter|background|experience)\b/i,
  /\byour (profile|resume|cv) (was )?(match(ed|es)?|selected|shortlisted) (for|to)\b/i,
  /\bwe (got|obtained|received|were given) your (contact|details|resume|information|number) from\b/i,
];

const unsolicitedContact: Rule = (input) => {
  const ev = evidenceFor(input.text, unsolicitedPatterns);
  if (!ev.length) return null;
  const applied = /\b(you (applied|submitted)|your application|the role you applied)\b/i.test(
    input.text,
  );
  if (applied) return null;
  return {
    id: "unsolicited-contact",
    category: "offer-content",
    severity: "low",
    title: "Unsolicited — you never applied",
    detail:
      "Not a problem by itself, but scam outreach almost always starts this " +
      "way, so weigh it with everything else here.",
    evidence: ev,
    advice: "Be extra careful verifying an opportunity that came to you cold.",
  };
};

const ROLE_WORDS =
  /\b(engineer|developer|programmer|manager|designer|analyst|specialist|coordinator|assistant|representative|consultant|administrator|director|technician|nurse|accountant|clerk|agent|associate|architect|scientist|writer|editor|marketer|bookkeeper|paralegal|controller|strategist|officer)\b/i;

const vagueRole: Rule = (input) => {
  const text = input.text;
  if (text.length < 200) return null; // too short to judge
  const talksAboutAJob =
    /\b(position|role|opportunity|vacancy|opening|job)\b/i.test(text);
  if (!talksAboutAJob) return null;
  if (ROLE_WORDS.test(text)) return null;
  return {
    id: "vague-role",
    category: "offer-content",
    severity: "low",
    title: "Never names an actual job title",
    detail:
      "A real posting says what the job is. A long message about an " +
      '"opportunity" that never names a role is a warning sign.',
    evidence: [],
    advice: "Ask for the exact job title and the team, then verify both.",
  };
};

const grammarArtifact = {
  doubleSpace: /\S {2,}\S/,
  kindly: /\bkindly\b/i,
  revert: /\brevert back\b/i,
  needful: /\bdo the needful\b/i,
  allCaps: /\b[A-Z]{4,}\b(?:.*\b[A-Z]{4,}\b)/s,
  lowerStart: /(?:[.!?]\s+[a-z].*){2,}/s,
};

const grammarArtifacts: Rule = (input) => {
  const hits = Object.entries(grammarArtifact)
    .filter(([, re]) => re.test(input.text))
    .map(([name]) => name);
  if (hits.length < 2) return null;
  return {
    id: "grammar-artifacts",
    category: "offer-content",
    severity: "low",
    title: "Writing style typical of scam templates",
    detail:
      'Odd phrasing ("kindly", "revert back"), inconsistent capitalization, ' +
      "and spacing errors are common in mass scam messages.",
    evidence: [],
    advice: "Minor on its own — treat as supporting evidence, not proof.",
  };
};

/* -------------------------------------------------------------------------- */
/* Process — recruitment-lure patterns                                        */
/* -------------------------------------------------------------------------- */

const phoneHarvestPatterns = [
  /\b(leave|drop|send|share|provide|give|text) (me |us )?(your )?(phone |cell |mobile |contact |best )?(number|phone number)\b/i,
  /\byour (best )?(contact|phone|cell|mobile) (number|no)\b/i,
  /\bwhat'?s your (number|phone|cell|mobile)\b/i,
];

const recruiterPhoneHarvest: Rule = (input) => {
  const ev = evidenceFor(input.text, phoneHarvestPatterns);
  if (!ev.length) return null;
  return {
    id: "recruiter-phone-harvest",
    category: "process",
    severity: "medium",
    title: "Asks for your phone number up front instead of scheduling",
    detail:
      "Rather than booking a call through the platform or a company email, the " +
      'sender wants your number so someone else can "reach out". It is a common ' +
      "way to move you onto an unmonitored channel and away from any record.",
    evidence: ev,
    advice:
      "Don't share your number until you have confirmed the company and role on " +
      "its official website.",
  };
};

const leaderHandoffPatterns = [
  /\bmy (leader|leadership)\b/i,
  /\b(forward|pass|send|give) (it|you|your (info|details|number|message|contact)) to my (leader|leadership|manager|supervisor|boss|senior|superior)\b/i,
  /\b(my|our|the) (leader|leadership|boss|manager|project manager|senior manager|supervisor|superior|colleague) will (contact|reach out to|get in touch with|call|add|inform|update|message|email) you\b/i,
  /\barrange for (a|an|our|my) [a-z ]{0,25}(manager|leader|colleague|representative|supervisor) to contact you\b/i,
];

const unnamedLeaderHandoff: Rule = (input) => {
  const ev = evidenceFor(input.text, leaderHandoffPatterns);
  if (!ev.length) return null;
  return {
    id: "unnamed-leader-handoff",
    category: "process",
    severity: "high",
    title: 'Hands you off to an unnamed "leader" or third party',
    detail:
      "A real recruiter names the interviewer and sets a concrete next step. " +
      'Being passed to "my leader" or a nameless "project manager" who will ' +
      "contact you separately — often by text — is a scripted-scam pattern.",
    evidence: ev,
    advice:
      "Ask for the person's full name, title, and company email address, then " +
      "verify them on the company's website before continuing.",
  };
};

const attachmentJdPatterns = [
  /\b(here is|here'?s|attached is|attached please find|find attached|see attached|please find|i have attached) [^.]{0,45}\bjob description\b/i,
  /\bjob description[^.]{0,45}\.(docx?|pdf|rtf)\b/i,
  /\.(docx?|pdf|rtf)\s*\d{1,4}\s*(kb|mb)\s*download\b/i,
];

const jobDescAttachment: Rule = (input) => {
  const ev = evidenceFor(input.text, attachmentJdPatterns);
  if (!ev.length) return null;
  return {
    id: "job-desc-attachment",
    category: "process",
    severity: "low",
    title: "Sends the job description as a file to download",
    detail:
      "Legitimate recruiters usually paste the description or link to the live " +
      "posting. An unsolicited .docx or .pdf can carry malware.",
    evidence: ev,
    advice:
      "Don't open the file. Ask for the role in plain text or a link to the " +
      "company careers page.",
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
  cvServiceReferral,
  piiBeforeOffer,
  accountCredentials,
  freemailSender,
  domainCompanyMismatch,
  lookalikeDomain,
  replyToMismatch,
  offPlatformPush,
  unnamedLeaderHandoff,
  recruiterPhoneHarvest,
  cvCriticismPressure,
  flatteryHook,
  unrealisticPay,
  noExperienceHighPay,
  hiredNoInterview,
  urgencyPressure,
  unsolicitedContact,
  vagueRole,
  jobDescAttachment,
  genericGreeting,
  grammarArtifacts,
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
