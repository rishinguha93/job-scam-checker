import { describe, expect, it } from "vitest";
import {
  extractUrls,
  isFormHost,
  isIpHost,
  isKnownGoodHost,
  isShortenerHost,
  lookalikeReasons,
} from "./urls";

const hosts = (text: string) => extractUrls(text).map((u) => u.host);

describe("extractUrls", () => {
  it("finds links written with a scheme", () => {
    expect(hosts("Apply at https://Acme-Careers.online/apply now")).toContain(
      "acme-careers.online",
    );
  });

  it("finds links written with www", () => {
    expect(hosts("See www.example.com/jobs")).toContain("example.com");
  });

  it("finds bare domains", () => {
    expect(hosts("Apply at acmecareers.xyz today")).toContain("acmecareers.xyz");
  });

  it("does not treat a filename as a link", () => {
    expect(hosts("Attached: job description.docx and notes.pdf")).toEqual([]);
  });

  it("does not treat a missing space after a full stop as a link", () => {
    expect(hosts("Send it over.Please reply soon.Thanks")).toEqual([]);
  });

  it("de-duplicates the same link repeated", () => {
    const found = extractUrls("go to bit.ly/abc and again bit.ly/abc");
    expect(found).toHaveLength(1);
  });

  it("keeps the path for inspection", () => {
    const [url] = extractUrls("https://example.com/Onboarding/W4");
    expect(url.path).toBe("/onboarding/w4");
  });
});

describe("host classification", () => {
  it("recognises shorteners but not LinkedIn's own", () => {
    expect(isShortenerHost("bit.ly")).toBe(true);
    expect(isShortenerHost("cutt.ly")).toBe(true);
    expect(isShortenerHost("lnkd.in")).toBe(false);
  });

  it("recognises generic form builders", () => {
    expect(isFormHost("docs.google.com")).toBe(true);
    expect(isFormHost("forms.gle")).toBe(true);
    expect(isFormHost("acme.com")).toBe(false);
  });

  it("recognises bare IP addresses", () => {
    expect(isIpHost("192.168.1.10")).toBe(true);
    expect(isIpHost("acme.com")).toBe(false);
  });

  it("recognises hosts that belong in real recruiting mail", () => {
    for (const good of [
      "greenhouse.io",
      "boards.greenhouse.io",
      "acme.myworkdayjobs.com",
      "calendly.com",
      "docs.google.com",
    ]) {
      expect(isKnownGoodHost(good)).toBe(true);
    }
  });
});

describe("lookalikeReasons", () => {
  it("clears well-known hosts even when they contain a brand name", () => {
    expect(lookalikeReasons("docs.google.com")).toEqual([]);
    expect(lookalikeReasons("boards.greenhouse.io")).toEqual([]);
  });

  it("flags a bolt-on recruiting word", () => {
    expect(lookalikeReasons("initech-careers.com").length).toBeGreaterThan(0);
  });

  it("flags an unusual TLD", () => {
    expect(lookalikeReasons("initech.online").length).toBeGreaterThan(0);
  });

  it("flags a brand name inside someone else's domain", () => {
    expect(lookalikeReasons("google-hiring-team.com").join(" ")).toContain("google");
  });

  it("flags digits standing in for letters", () => {
    expect(lookalikeReasons("g00gle-jobs.com").length).toBeGreaterThan(0);
  });

  it("says nothing about an ordinary company domain", () => {
    expect(lookalikeReasons("northwindsoftware.com")).toEqual([]);
    expect(lookalikeReasons("northwind-software.com")).toEqual([]);
  });

  it("flags official-sounding words stitched together", () => {
    expect(lookalikeReasons("micro-job-portal-secure-link.com").join(" ")).toContain(
      "stitched together",
    );
  });

  it("flags an unusual number of hyphens", () => {
    expect(lookalikeReasons("a-b-c-d-e-f.com").length).toBeGreaterThan(0);
  });

  it("does not flag a single trust word in an ordinary domain", () => {
    // One such word is unremarkable; the bolt-on suffix check owns that case.
    expect(lookalikeReasons("acmesupport.com")).toEqual([]);
  });
});
