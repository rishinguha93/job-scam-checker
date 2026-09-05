import { describe, expect, it } from "vitest";
import { analyze } from "./analyze";
import { assessInput } from "./relevance";

describe("assessInput — junk", () => {
  it("flags a keysmash with a long repeated run", () => {
    expect(
      assessInput("jdojkSANLKSNCk\nsssssssssssssssssssssssssssssssssssssssss."),
    ).toBe("gibberish");
  });

  it("flags a short keysmash with no repeated run", () => {
    expect(assessInput("asdfgh qwertyu zxcvbnm hjklmn")).toBe("gibberish");
  });

  it("flags empty / whitespace-only input", () => {
    expect(assessInput("   \n  ")).toBe("gibberish");
  });

  it("flags readable-looking words with no function words at all", () => {
    expect(assessInput("banana table rocket purple engine window carpet melon")).toBe(
      "gibberish",
    );
  });
});

describe("assessInput — language", () => {
  it("flags non-Latin script rather than calling it junk", () => {
    const bengali =
      "আপনার প্রোফাইল দেখে আমরা একটি চাকরির সুযোগ সম্পর্কে জানাতে চাই। অনুগ্রহ করে উত্তর দিন।";
    expect(assessInput(bengali)).toBe("non-english");
  });

  it("does not flag English containing a few accented characters", () => {
    const text =
      "Hi José, I am a recruiter at Nortec and we have an opening for a backend " +
      "engineer. Would you be open to a short call with our hiring team next week?";
    expect(assessInput(text)).toBeNull();
  });
});

describe("assessInput — topic", () => {
  it("flags long readable text that has nothing to do with hiring", () => {
    const text =
      "I went to the shop this morning and bought some milk, bread and a bag of " +
      "apples. The weather was cold so I walked back quickly and made a cup of " +
      "tea when I got home. Later I might watch a film with my sister.";
    expect(assessInput(text)).toBe("off-topic");
  });

  it("gives short messages the benefit of the doubt", () => {
    expect(assessInput("Hey, are you free to chat tomorrow?")).toBeNull();
  });

  it("passes a normal recruiter message through", () => {
    const text =
      "Hi Rishin, I am a recruiter at Northwind Software. We have an opening for " +
      "a backend engineer and I thought your experience was a strong match. " +
      "Would you be open to a 30-minute interview with the hiring team?";
    expect(assessInput(text)).toBeNull();
  });
});

describe("analyze — not-checkable verdict", () => {
  it("returns not-checkable with no findings for a keysmash", () => {
    const r = analyze({ text: "jdojkSANLKSNCk sssssssssssssssssssssssssss." });
    expect(r.verdict).toBe("not-checkable");
    expect(r.issue).toBe("gibberish");
    expect(r.findings).toHaveLength(0);
    expect(r.score).toBe(0);
  });

  it("still reports real red flags in off-topic-looking text", () => {
    // No hiring vocabulary, but a critical money rule fires — the verdict must
    // win over the off-topic gate.
    const text =
      "Hello there, please send payment as an Apple gift card today so that we " +
      "can release the item to you. Kindly confirm once you have sent it over " +
      "and we will proceed with the next steps for you immediately.";
    const r = analyze({ text });
    expect(r.verdict).toBe("very-likely-scam");
    expect(r.findings.map((f) => f.id)).toContain("gift-cards");
  });

  it("does not mark a genuine recruiter message as not-checkable", () => {
    const text =
      "Hi Rishin, I am a recruiter at Northwind Software. We have an opening for " +
      "a backend engineer and thought you might be a fit. Open to a call?";
    expect(analyze({ text }).verdict).not.toBe("not-checkable");
  });
});
