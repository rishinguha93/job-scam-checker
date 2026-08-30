# Research: Recruiting Scams Targeting Job Seekers

Background research that motivates this project and defines what the detection
engine must recognize. Compiled 2026-08-29.

## 1. Scale

- FTC job-scam reports **nearly tripled 2020 → 2024**; reported losses jumped
  **$90M → $501M**.
- 2025 PasswordManager.com survey: **1 in 4 job seekers** fell victim to a hiring
  scam; ~half of victims lost money or personal information.
- Fake-recruiter contact channels: **email 72%, text 62%, phone 38%,
  LinkedIn 29%**.
- Task / "gamified job" scams are the **fastest-growing** employment-fraud
  category heading into 2026.

## 2. Scam taxonomy

| Type | How money/data is extracted | Tell-tale mechanics |
|---|---|---|
| **Task / "gamified job"** | Paid to click "task sets"; balance goes negative; handler says deposit crypto to "unlock" withdrawal; each round doubles. Nothing is withdrawable. | WhatsApp/Telegram recruiting, "40 tasks per set", "commission", "combo tasks", crypto wallet top-up |
| **Advance-fee** | Upfront payment for equipment, training, certification, background check, or "access to listings" | Any request to pay in order to get hired |
| **Fake-check / overpayment** | Mails a check to "buy home-office equipment from our vendor"; check bounces after victim wires the difference | Check arrives before any work; asked to forward funds |
| **Identity theft / fake onboarding** | "Onboarding paperwork" harvests SSN, bank, ID scans, DOB before any real offer | PII / bank details requested at interview stage or before a verified offer |
| **Crypto "job"** | The role itself involves moving crypto, or pay requires opening/funding a wallet | FBI-flagged category |
| **Recruiter impersonation** | Clones a real recruiter/company to lend credibility to any of the above | Free-mail or lookalike domain; profile < 3 months old; < 50 connections; stock photo |
| **Deepfake interview** (emerging) | Live video call with an AI-generated "executive" | Lip-sync lag, unnatural movement, AI background |

## 3. Red-flag signal catalog

See `ruleset.md` for the implementable version. Summary groups:

- **Sender / identity** — free-mail or lookalike domain; reply-to ≠ from;
  new/thin LinkedIn profile; name absent from the company's real team page;
  pressure to move to WhatsApp/Telegram/Signal.
- **Offer / message content** — pay far above market for low skill; vague duties;
  "no experience needed"; unsolicited contact; urgency / limited-time; hired with
  no real interview; generic greeting; grammar errors; copy-pasted job text.
- **Process** — interview only by text chat; offer before any substantive
  interview; role not on the company's own careers page.
- **Money (hardest red line)** — any request for the applicant to pay
  (equipment, training, certs, background check, "starter kit"); send / forward /
  wire money; deposit or "top up" a crypto wallet; buy gift cards; receive a
  check and send part back.
- **Personal data** — SSN, bank/routing, ID/passport scan, DOB, or account
  logins requested before a signed, verified offer.

## 4. Legitimate-verification actions (the tool should coach these)

Confirm the company domain on the email; find the role on the company's **own**
careers site; search the recruiter's name + company on LinkedIn; reverse-image-
search the profile photo; contact the company through a number/email looked up
independently; never trust a single "good" signal alone.

## 5. Existing tools & the gap

- **Web checkers** (paste text → verdict): JobScamScore, VerifyJobs, VeriJob.
- **Browser extensions** (inline on job boards): ScamShield, Job Scam Alert Pro,
  ApplySafe.
- **Adjacent:** GhostCheck (ghost jobs, not scams).

Gaps this project targets:

1. Most tools score a **job posting**; weak on **1:1 recruiter emails / DMs**.
2. Verdicts are opaque — little "here's your next safe step" coaching.
3. Little support for **"I already engaged / already paid"** recovery.
4. No **conversation-level** analysis (paste a whole thread; detect escalation to
   a money ask).

## 6. "Already a victim" flow

- Money sent by wire/crypto → bank + IC3 (ic3.gov) within 24–72h.
- SSN / bank shared → IdentityTheft.gov; credit freeze at all three bureaus; new
  cards.
- Report the scam → ReportFraud.ftc.gov.

## Sources

- FTC job-scam rise: <https://www.wknofm.org/show/protecting-your-money/2026-07-14/ftc-warns-job-scams-are-on-the-rise>
- FTC "Job Scams" consumer page: <https://consumer.ftc.gov/all-scams/job-scams>
- PasswordManager.com survey: <https://finance.yahoo.com/news/passwordmanager-com-survey-finds-1-092000643.html>
- Contact-channel stats: <https://builtin.com/articles/avoid-fake-job-scams>
- Task scams (BBB / 2026): <https://scamwatchhq.com/task-scams-gamified-job-fraud-bbb-2026/>
- Task-scam mechanics: <https://www.cyberjustice.law/learn/what-are-task-scams>
- Pig-butchering meets gig economy: <https://www.proofpoint.com/us/blog/threat-insight/pig-butchers-join-gig-economy-cryptocurrency-scammers-target-job-seekers>
- FBI cryptocurrency job scams: <https://www.fbi.gov/how-we-can-help-you/victim-services/national-crimes-and-victim-resources/cryptocurrency-job-scams>
- Fake recruiters impersonating a company: <https://about.gitlab.com/blog/new-wave-of-fake-job-scams-impersonating-recruiters/>
- Recruiter red flags: <https://www.airswift.com/blog/recruitment-scam-red-flags>
- Verifying a recruiter email: <https://www.scamadviser.com/articles/how-to-verify-if-a-recruiter-email-is-legitimate>
- Verifying a recruiter (agency view): <https://www.goodwinrecruiting.com/blog/contacted-by-a-talent-recruiter-make-sure-theyre-legit>
- If you gave your SSN: <https://www.aura.com/learn/i-gave-my-social-security-number-to-a-scammer>
- Where to report: <https://antifraud.com/victims/where-to-report-a-scam/>
- Scamwise (product model): <https://scamwise.com/> · <https://scamwise.com/about>
