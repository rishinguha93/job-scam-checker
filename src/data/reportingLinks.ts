/**
 * Reference data for the "I think I've been scammed" flow. US-focused for now;
 * a future version can localize by country.
 */

export interface ReportingResource {
  label: string;
  url: string;
  /** When this resource is the right one. */
  when: string;
}

export interface RecoveryStep {
  /** Short imperative heading. */
  action: string;
  detail: string;
  resources?: ReportingResource[];
  /** Do this quickly — time-sensitive. */
  urgent?: boolean;
}

/** What the user may have handed over. Drives which steps we show. */
export type Exposure = "money" | "personal-data" | "credentials" | "nothing-yet";

const FTC_REPORT: ReportingResource = {
  label: "ReportFraud.ftc.gov",
  url: "https://reportfraud.ftc.gov",
  when: "Always — report the scam itself to the FTC.",
};

const IC3: ReportingResource = {
  label: "FBI IC3 (ic3.gov)",
  url: "https://www.ic3.gov",
  when: "Money sent by wire, crypto, or large amounts.",
};

const IDENTITY_THEFT: ReportingResource = {
  label: "IdentityTheft.gov",
  url: "https://www.identitytheft.gov",
  when: "You shared SSN, bank details, or ID documents. Gives a recovery plan.",
};

export const CREDIT_BUREAUS: ReportingResource[] = [
  { label: "Equifax freeze", url: "https://www.equifax.com/personal/credit-report-services/credit-freeze/", when: "Freeze your credit file." },
  { label: "Experian freeze", url: "https://www.experian.com/freeze/center.html", when: "Freeze your credit file." },
  { label: "TransUnion freeze", url: "https://www.transunion.com/credit-freeze", when: "Freeze your credit file." },
];

const STEP_REPORT_FTC: RecoveryStep = {
  action: "Report the scam to the FTC",
  detail:
    "File a report describing what happened. It helps investigators and gives " +
    "you a paper trail.",
  resources: [FTC_REPORT],
};

const STEP_CONTACT_BANK: RecoveryStep = {
  action: "Call your bank or payment provider now",
  detail:
    "Ask them to stop or reverse the transfer and to flag the account. Wires " +
    "and crypto can sometimes be recalled within the first 24–72 hours.",
  urgent: true,
};

const STEP_REPORT_IC3: RecoveryStep = {
  action: "Report the financial loss to the FBI",
  detail:
    "IC3 handles wire, crypto, and task-scam losses and can coordinate with " +
    "banks on recalls.",
  resources: [IC3],
  urgent: true,
};

const STEP_IDENTITY_THEFT: RecoveryStep = {
  action: "Start an identity-theft recovery plan",
  detail:
    "IdentityTheft.gov walks you through disputing fraudulent accounts opened " +
    "in your name and generates the letters you'll need.",
  resources: [IDENTITY_THEFT],
  urgent: true,
};

const STEP_FREEZE_CREDIT: RecoveryStep = {
  action: "Freeze your credit at all three bureaus",
  detail:
    "A freeze is free and stops new credit being opened in your name. You can " +
    "lift it later when you need to.",
  resources: CREDIT_BUREAUS,
};

const STEP_SECURE_ACCOUNTS: RecoveryStep = {
  action: "Change passwords and turn on two-factor authentication",
  detail:
    "Start with your email, then any account that shared the password. Use a " +
    "unique password for each.",
  urgent: true,
};

const STEP_KEEP_EVIDENCE: RecoveryStep = {
  action: "Save everything before you block",
  detail:
    "Screenshot the messages, profile, emails, and any receipts or wallet " +
    "addresses. You'll need them for the reports.",
};

const STEP_BLOCK: RecoveryStep = {
  action: "Stop contact and block",
  detail:
    "Do not reply, do not send a final message, and do not try to recover " +
    "losses by paying more — that is how the scam deepens.",
};

const STEP_REPORT_PLATFORM: RecoveryStep = {
  action: "Report the account to the platform",
  detail:
    "Report the profile or sender on LinkedIn, the job board, or your email " +
    "provider so it can be taken down.",
};

/** Build the ordered step list for a given exposure. */
export function recoveryPlan(exposure: Exposure): RecoveryStep[] {
  const steps: RecoveryStep[] = [STEP_KEEP_EVIDENCE];

  if (exposure === "money") {
    steps.push(STEP_CONTACT_BANK, STEP_REPORT_IC3);
  }
  if (exposure === "personal-data") {
    steps.push(STEP_IDENTITY_THEFT, STEP_FREEZE_CREDIT);
  }
  if (exposure === "credentials") {
    steps.push(STEP_SECURE_ACCOUNTS);
  }

  steps.push(STEP_REPORT_FTC, STEP_REPORT_PLATFORM, STEP_BLOCK);
  return steps;
}
