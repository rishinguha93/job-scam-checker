# Red-flag ruleset

The catalog the detection engine implements. Each rule is a pure function in
`src/engine/rules.ts` that inspects a normalized input and, on a match, returns a
`Finding`. Keep this document and that file in sync.

**Status:** all 22 rules below are implemented, each with a positive test (and,
where it matters, a negative test) in `src/engine/rules.test.ts`.

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

### Personal data — critical

| id | Matches | Notes |
|---|---|---|
| `pii-before-offer` | "social security" / "ssn" / "bank account" / "routing number" / "date of birth" / "passport" / "driver's license" / "voided check" | Requested before a signed, verified offer. v1 flags any request; a later version can gate on whether an offer stage was reached. |
| `account-credentials` | "password", "login to", "verification code", "one-time code", "2fa code" | Credential harvest. |

### Sender / identity — high / medium

| id | Severity | Matches |
|---|---|---|
| `freemail-sender` | high | `fromEmail` domain in {gmail, outlook, hotmail, yahoo, aol, proton, gmx, mail.com, icloud} while a company is claimed |
| `domain-company-mismatch` | high | `fromEmail` domain does not contain / align with `claimedCompany` slug |
| `lookalike-domain` | high | domain contains a known brand with an inserted/!swapped char, extra word, or odd TLD (e.g. `-careers`, `.online`, `.info`, digits substituted for letters) |
| `replyto-mismatch` | medium | `replyToEmail` domain ≠ `fromEmail` domain |
| `offplatform-push` | high | "contact me on" + (whatsapp / telegram / signal / skype); also handoff to an SMS thread or a third party's chat ("reply to my leader's message", "added your text message", "continue by text") |

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

### Process — recruitment-lure patterns

| id | Severity | Matches |
|---|---|---|
| `recruiter-phone-harvest` | medium | "leave/drop/send your (phone) number", "your best contact number", "what's your number" — number requested up front instead of scheduling |
| `unnamed-leader-handoff` | high | "my leader" / "my leadership", "forward it to my leader/manager", "my leader will contact you", "arrange for a project manager to contact you" |
| `job-desc-attachment` | low | "here is your job description …", "job description … .docx/.pdf", ".docx NN KB Download" — JD delivered as a downloadable file |

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
