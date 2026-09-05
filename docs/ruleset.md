# Red-flag ruleset

The catalog the detection engine implements. Each rule is a pure function in
`src/engine/rules.ts` that inspects a normalized input and, on a match, returns a
`Finding`. Keep this document and that file in sync.

**Status:** all 34 rules below are implemented, each with a positive test (and,
where it matters, a negative test) in `src/engine/rules.test.ts`.

Link handling lives in `src/engine/urls.ts` (extraction + host classification,
tested in `urls.test.ts`); `lookalikeReasons()` there is shared by the sender
-domain rule and the link rules so both judge a domain the same way.

## Input shape

The engine normalizes user input into:

| Field | Source | Notes |
|---|---|---|
| `text` | the pasted message / thread body | required |
| `fromEmail` | optional "from" address the user supplies | enables sender-domain rules |
| `replyToEmail` | optional reply-to address | enables mismatch rule |
| `claimedCompany` | optional company name the recruiter claims | enables domain-vs-company checks |
| `channel` | where it arrived: `email` \| `linkedin` \| `text` \| `whatsapp` \| `other` | |

## Severity model

| Severity | Weight | Meaning |
|---|---|---|
| `critical` | — | Forces the verdict to **Very likely a scam** regardless of score. Reserved for the money/PII red lines that are almost never present in a legitimate hiring process. |
| `high` | 30 | Strong individual indicator. |
| `medium` | 15 | Meaningful in combination. |
| `low` | 7 | Weak; contributes only in aggregate. |

## Input relevance gate

Before any rule runs, `src/engine/relevance.ts` checks that the input is
actually a readable message. Without this, junk input falls through every rule
and reports "No strong signal found" — which reads as reassurance for something
that was never assessed.

| Issue | Detected by | Result |
|---|---|---|
| `gibberish` | 6+ repeated characters; <50% of alphabetic tokens look word-like (vowel present, no 5+ consonant run, ≤24 chars); or ≥8 tokens with zero English function words | Short-circuits before the rules |
| `non-english` | ≥20 letters and <40% of them Latin script | Short-circuits before the rules |
| `off-topic` | ≥25 tokens and no work/hiring vocabulary anywhere | **Only** applied when the rules also found nothing — a message that trips a real rule always gets a real verdict |

All three produce the `not-checkable` verdict with an `issue` field, rendered in
neutral grey: deliberately not the green "no strong signal" state.

## Verdict bands

1. Any `critical` finding → **Very likely a scam**
2. **Combination escalation** → **Very likely a scam**, even with no `critical`:
   - score ≥ 80 with ≥ 4 findings, or
   - ≥ 2 `high` findings with ≥ 5 findings total.
   Rationale: a stack of independent red flags is scam-level on its own; some
   lures (e.g. "leave your number, my leader will contact you") never cross a
   money/PII red line but are unmistakable in aggregate.
3. Score ≥ 45 → **High risk**
4. Score ≥ 20 → **Caution — verify before proceeding**
5. Otherwise → **No strong signal — still verify independently**

The verdict is never "safe". Absence of red flags is not proof of legitimacy, and
the UI must say so.

## Rules

### Money — critical

| id | Matches (case-insensitive) | Notes |
|---|---|---|
| `pay-to-start` | "pay for" + (equipment / training / certification / background check / starter kit / onboarding fee / registration fee) | Applicant being asked to pay anything. |
| `wire-or-forward-funds` | "wire", "send the remaining", "forward the funds", "transfer the balance", "send back" | Fake-check / money-mule pattern. |
| `crypto-topup` | "crypto", "usdt", "bitcoin", "wallet", "binance", "deposit to unlock", "recharge", "top up" + task/commission context | Task-scam withdrawal trap. |
| `gift-cards` | "gift card", "steam card", "apple card", "google play card" | Never a legitimate payroll instrument. |
| `cv-service-referral` | CV/resume mentioned **and** one of: a directive pointing at Fiverr/Upwork/etc., a named "CV writing service", "I know someone who can rewrite your CV", or CV work attached to a fee/price | The CV-rewrite upsell. Money is laundered through a third-party service the "recruiter" often owns. The directive-verb requirement stops a job spec that merely mentions Fiverr from matching. |
| `remote-access-tool` | install/use + AnyDesk, TeamViewer, UltraViewer, RustDesk, LogMeIn, Splashtop, Quick Assist | Hands over control of the candidate's machine. Never legitimate from an employer. Bare "remote desktop"/"RDP" deliberately excluded — they appear in real IT job specs. |
| `reshipping-role` | "receive packages at your home … and forward", "reship … overseas", "package/parcel inspector\|processor\|coordinator", "quality control inspector" + packages | Parcel-mule scheme. Goods bought with stolen cards; the victim's name is on the shipping records. |

### Personal data — critical

| id | Matches | Notes |
|---|---|---|
| `pii-before-offer` | "social security" / "ssn" / "bank account" / "routing number" / "date of birth" / "passport" / "driver's license" / "voided check" | Requested before a signed, verified offer. v1 flags any request; a later version can gate on whether an offer stage was reached. |
| `account-credentials` | "password", "login to", "verification code", "one-time code", "2fa code" | Credential harvest. |

### Personal data — high

| id | Matches | Notes |
|---|---|---|
| `onboarding-paperwork-early` | W-4 / W-9 / I-9 / 1099 / P45 / P60 / T4, "direct deposit", "payroll form", "tax form", "onboarding\|new-hire portal\|paperwork\|packet" | **High, not critical**: this paperwork is entirely normal *after* a signed offer, so it must not force a scam verdict on a genuine onboarding email. |
| `form-host-link` | a link to Google Forms / Typeform / JotForm / SurveyMonkey / Airtable / Formstack. Escalates from `medium` to `high` when the message also mentions onboarding, payroll, bank, SSN, tax, ID or verification | Real hiring and payroll run through the company's own system. Anyone can build one of these in minutes. |

### Sender / identity — high / medium

| id | Severity | Matches |
|---|---|---|
| `freemail-sender` | high | `fromEmail` domain in {gmail, outlook, hotmail, yahoo, aol, proton, gmx, mail.com, icloud} while a company is claimed |
| `domain-company-mismatch` | high | `fromEmail` domain does not contain / align with `claimedCompany` slug |
| `lookalike-domain` | high | domain contains a known brand with an inserted/!swapped char, extra word, or odd TLD (e.g. `-careers`, `.online`, `.info`, digits substituted for letters) |
| `replyto-mismatch` | medium | `replyToEmail` domain ≠ `fromEmail` domain |
| `offplatform-push` | high | "contact me on" + (whatsapp / telegram / signal / skype); also handoff to an SMS thread or a third party's chat ("reply to my leader's message", "added your text message", "continue by text") |
| `suspicious-link-host` | high | a link whose host is a bare IP address, or fails `lookalikeReasons()` — bolt-on word, odd TLD, brand name in someone else's domain, digit-for-letter swaps. Skips `KNOWN_GOOD_HOSTS` first, so Greenhouse / Lever / Workday / Calendly / `docs.google.com` never trip it. |
| `shortened-link` | medium | bit.ly, tinyurl, cutt.ly, rebrand.ly, t.co, is.gd, ow.ly … **`lnkd.in` deliberately excluded** — it is LinkedIn's own shortener and expected where these messages arrive. |

### Offer / content — medium / low

| id | Severity | Matches |
|---|---|---|
| `unrealistic-pay` | high | a parsed pay figure clears a market-rate threshold (≥$40/hr, ≥$200/day, ≥$1,200/wk) *and* the text nearby describes simple/low-skill work. The amount is parsed and compared numerically — not just detected — so an ordinary rate like $18/hr (e.g. a paid research study) does not fire. |
| `no-experience-high-pay` | medium | "no experience" / "no skills needed" / "anyone can do" near a pay figure |
| `hired-no-interview` | high | "you are hired" / "offer" / "start immediately" with no mention of interview, or "interview" only via chat app |
| `urgency-pressure` | medium | "limited slots", "respond within", "act now", "today only", "positions filling fast", "remember to reply in time" |
| `unsolicited-contact` | low | "found/seen/viewed/noticed your profile", "came across your resume", "your profile matched", "we got your contact from" + no application referenced |
| `generic-greeting` | low | "dear candidate", "dear applicant", "hello dear", "dear sir/madam" |
| `vague-role` | low | no concrete job title, team, or product named anywhere in the text |
| `grammar-artifacts` | low | multiple sentence-start lowercase, double spaces, ALL-CAPS runs, "kindly" + "revert back" |
| `flattery-hook` | low | **two or more** of: "brilliant/outstanding/exceptional", "rare talent / perfect candidate / exactly what we need", "truly impressed", "your profile stood out". One compliment is normal recruiter language; a stack of them is rapport-building before an ask. |

### Process — recruitment-lure patterns

| id | Severity | Matches |
|---|---|---|
| `recruiter-phone-harvest` | medium | "leave/drop/send your (phone) number", "your best contact number", "what's your number" — number requested up front instead of scheduling |
| `unnamed-leader-handoff` | high | "my leader" / "my leadership", "forward it to my leader/manager", "my leader/boss/manager will contact **or email** you", "arrange for a project manager to contact you" |
| `job-desc-attachment` | low | "here is your job description …", "job description … .docx/.pdf", ".docx NN KB Download" — JD delivered as a downloadable file |
| `cv-criticism-pressure` | medium | "your CV is weak / needs rewriting", "won't get past the ATS", "ATS-friendly", "before I can submit … your CV" — the manufactured problem that sets up a paid rewrite |
| `chat-only-interview` | high | "interview over Teams chat / instant messaging", "text-based interview", "no video required", "keep your camera off" — you never see or hear a person |
| `install-software-request` | high | "download/install our app\|client\|platform\|interview software", or a link to `.exe/.msi/.dmg/.apk/.scr/.bat/.pkg/.jar`. **Suppressed** when every hit names a platform in `TRUSTED_PLATFORMS` (Zoom, Teams, Meet, Webex, Skype, Slack, Whereby). |
| `run-code-request` | medium | `git clone`, `npm install`, "clone the repo", "run the project locally", "review the codebase before the interview". **Medium on purpose** — genuine take-home tasks look identical, so this contributes rather than decides. Advice tells the user to run it only in a throwaway VM. |

## Findings output

Each finding returned to the UI:

```js
/** @type {Finding} */
{
  id: 'crypto-topup',
  category: 'money',
  severity: 'critical',
  title: 'Asks you to deposit or "top up" funds to get paid',
  detail: 'Legitimate employers never require you to send money, crypto, or ' +
          'gift cards. This is the core mechanic of task scams.',
  evidence: ['...the exact matched substring from the user text...'],
  advice: 'Do not send anything. Stop contact.'
}
```

The UI groups findings by `category`, shows `evidence` as quoted snippets from
the user's own text, and renders the band-appropriate next step.
