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
