import { describe, expect, it } from "vitest";
import { analyze } from "./analyze";

describe("analyze", () => {
  it("returns no strong signal for an ordinary recruiter note", () => {
    const result = analyze({
      text:
        "Hi Alex, I'm a recruiter at Northwind Software. We saw your GitHub and " +
        "have a backend engineer opening. Would you be open to a 30-minute video " +
        "interview with our hiring panel next week?",
      fromEmail: "j.doe@northwind.com",
      claimedCompany: "Northwind Software",
    });
    expect(result.verdict).toBe("no-strong-signal");
    expect(result.findings).toHaveLength(0);
  });

  it("flags a task scam as very likely a scam", () => {
    const result = analyze({
      text:
        "Congratulations, you are hired! Start immediately. Complete 40 simple " +
        "tasks per set to earn $400 a day. If your balance goes negative you " +
        "just top up your USDT wallet to unlock withdrawals. Contact me on " +
        "Telegram @hrmanager.",
      channel: "whatsapp",
    });
    expect(result.verdict).toBe("very-likely-scam");
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("crypto-topup");
    expect(ids).toContain("offplatform-push");
    expect(ids).toContain("unrealistic-pay");
  });

  it("catches the fake-check / forward-funds pattern", () => {
    const result = analyze({
      text:
        "We will mail you a check to buy your home-office equipment from our " +
        "approved vendor. Deposit the check, then wire the remaining balance to " +
        "the supplier the same day.",
    });
    expect(result.verdict).toBe("very-likely-scam");
    expect(result.findings.map((f) => f.id)).toContain("wire-or-forward-funds");
  });

  it("treats a request for SSN / bank details as critical", () => {
    const result = analyze({
      text:
        "To set up payroll before we talk, reply with your Social Security " +
        "number, bank account and routing number, and a photo of your driver's " +
        "license.",
    });
    expect(result.verdict).toBe("very-likely-scam");
    const pii = result.findings.find((f) => f.id === "pii-before-offer");
    expect(pii).toBeDefined();
    expect(pii?.evidence.length).toBeGreaterThan(0);
  });

  it("raises caution (not scam) for softer signals only", () => {
    const result = analyze({
      text:
        "Dear Candidate, positions are filling fast — please confirm within 30 " +
        "minutes to keep your spot in the process.",
    });
    expect(result.verdict).toBe("caution");
    expect(result.findings.every((f) => f.severity !== "critical")).toBe(true);
  });

  it("flags a personal gmail address when a company is claimed", () => {
    const result = analyze({
      text: "I represent the recruiting team at Acme Corp.",
      fromEmail: "acme.recruiter2024@gmail.com",
      claimedCompany: "Acme Corp",
    });
    const f = result.findings.find((x) => x.id === "freemail-sender");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });

  it("flags the 'leave your number / my leader will contact you' recruitment lure", () => {
    const text = `Recruiter: Hello, I am a Recruiter in the Human Resources Department at CME Group and I have seen your profile on LinkedIn and you have a wealth of experience in your field. We are currently recruiting for senior management positions. If you are interested in learning more about our senior vacancies, please leave your phone number. We will arrange for a project manager to contact you.

Hi, thank you for reaching out. Can you clarify what sort of senior management positions you're recruiting for? Is there a job description I can review?

Recruiter: The position I have for you is Application Support Specialist. If you are interested you can leave your number and I will forward it to my leadership, remember to reply in time, thank you, here is your job description Application Support Specialist jobs.docx 11 KB Download

Recruiter: Of course, and my leader will keep you informed throughout the whole process, so keep an eye out for news from my leader.

Recruiter: My leader just added your text message so you can check it out and reply. Did you reply to my leader's message?`;

    const result = analyze({ text, channel: "linkedin", claimedCompany: "CME Group" });
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("unnamed-leader-handoff");
    expect(ids).toContain("recruiter-phone-harvest");
    expect(ids).toContain("offplatform-push");
    expect(["high-risk", "very-likely-scam"]).toContain(result.verdict);
  });

  it("flags the CV-rewrite upsell run by a fake recruiter", () => {
    const text = `Hi, I came across your profile and honestly you are a brilliant, exceptional candidate — truly impressed by your background. You are exactly what we are looking for.

Before I put you forward, could you send me your CV?

Thanks. To be blunt, your CV is weak and it won't get past the ATS in its current state. I can't submit this to my client as it is.

Good news — I know someone who can rewrite your CV properly. Go to Fiverr and look up the profile I've linked; the package starts at $90 and turnaround is 48 hours. Once that's done I'll submit you straight away.`;

    const result = analyze({ text, channel: "linkedin" });
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("cv-service-referral");
    expect(ids).toContain("cv-criticism-pressure");
    expect(ids).toContain("flattery-hook");
    expect(result.verdict).toBe("very-likely-scam");
  });

  it("flags the polished, no-obvious-money-ask lure", () => {
    // Generated as a "realistic scam recruiter message". Crosses no money or
    // PII red line, so it once scored 7 and returned "no strong signal".
    const text =
      "Hi , I came across your profile and I am very impressed by your " +
      "background. We are currently recruiting for a high-level, confidential " +
      "remote position with an incredible salary ($120k–$150k starting) that " +
      "fits your experience perfectly. The hiring manager wants to move forward " +
      "immediately without a standard screening call. Please message our lead " +
      "talent coordinator directly on WhatsApp at +1-555-0199 or click [this " +
      "secure link] to download the job specs and fill out our onboarding " +
      "questionnaire. Time is critical for the first review group!";

    const result = analyze({ text, channel: "linkedin" });
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("offplatform-push");
    expect(ids).toContain("interview-bypass");
    expect(ids).toContain("onboarding-paperwork-early");
    expect(ids).toContain("urgency-pressure");
    expect(result.verdict).toBe("very-likely-scam");
  });

  it("flags a short lure that leads with money and skips the interview", () => {
    const text =
      "Hello! I saw your profile and I am very impressed with your background. " +
      "I am a senior recruiter for a major global tech firm. We have an urgent " +
      "remote opening for a [Your Field] position. The pay is $95/hour with " +
      "flexible hours. No formal interview is needed with the hiring manager. " +
      "Please add our hiring coordinator on WhatsApp at +1-555-0199 immediately " +
      "to claim your spot in our first review group. Thanks";

    const result = analyze({ text, channel: "linkedin" });
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("offplatform-push");
    expect(ids).toContain("interview-bypass");
    expect(ids).toContain("unrealistic-pay");
    expect(ids).toContain("vague-role");
    expect(result.verdict).toBe("very-likely-scam");
  });

  it("does not claim nothing was found when a sub-threshold finding exists", () => {
    // One medium finding scores 15, below the caution threshold of 20 — but the
    // summary must not then read as an all-clear for something we did flag.
    const text =
      "Hi! Great to connect. Before our call I'd like to walk through the repo " +
      "with you. You'll just need to pull our public repository to your machine, " +
      "review the dependencies, and see how the modules fit together.";
    const result = analyze({ text });

    expect(result.verdict).toBe("no-strong-signal");
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary).not.toMatch(/no known scam patterns matched/i);
    expect(result.summary).toMatch(/nothing here is decisive/i);
  });

  it("keeps the plain all-clear wording when there are genuinely no findings", () => {
    const text =
      "Hi Rishin, I'm a recruiter at Northwind Software. We have an opening for " +
      "a backend engineer and thought you might be a fit. Would you be open to a " +
      "video interview with our hiring panel next week?";
    const result = analyze({ text });

    expect(result.findings).toHaveLength(0);
    expect(result.summary).toMatch(/no known scam patterns matched/i);
  });

  it("flags a malware attachment sent as interview instructions", () => {
    const text =
      "Hello we reviewed your profile for our open Data Analyst position and " +
      "believe you are an excellent fit. Our team has already selected you for " +
      "an initial online screening interview. Please download the company " +
      "introduction briefing and interview instructions from our secure portal " +
      "here: [micro-job-portal-secure-link.com] or use the attached " +
      "Job_Specs_PDF.scr. Please complete this review within 24 hours so we can " +
      "schedule your live panel call.";

    const result = analyze({ text, channel: "linkedin" });
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain("executable-file");
    expect(ids).toContain("suspicious-link-host");
    expect(ids).toContain("urgency-pressure");
    expect(result.verdict).toBe("very-likely-scam");
  });

  it("every finding carries evidence and advice", () => {
    const result = analyze({
      text:
        "You are hired! Pay a $150 refundable deposit for your training kit and " +
        "send it via gift card today only.",
    });
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(f.title).toBeTruthy();
      expect(f.advice).toBeTruthy();
      expect(Array.isArray(f.evidence)).toBe(true);
    }
  });
});
