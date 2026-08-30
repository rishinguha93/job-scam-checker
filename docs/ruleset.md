# Red-flag ruleset

The catalog the detection engine implements. Each rule is a pure function in
`src/engine/rules.ts` that inspects a normalized input and, on a match, returns a
`Finding`. Keep this document and that file in sync.

**Status:** all 19 rules below are implemented, each with a positive test (and,
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

## Verdict bands

1. Any `critical` finding → **Very likely a scam**
2. Score ≥ 45 → **High risk**
3. Score ≥ 20 → **Caution — verify before proceeding**
4. Otherwise → **No strong signal — still verify independently**

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
| `offplatform-push` | high | "contact me on" / "message me on" / "add me on" + (whatsapp / telegram / signal / skype) |

### Offer / content — medium / low

| id | Severity | Matches |
|---|---|---|
| `unrealistic-pay` | high | pay figure parsed (`$NNN/day`, `$N,NNN/week`) that is implausibly high for described low-skill work, or phrases like "earn $500 a day" + "simple tasks" |
| `no-experience-high-pay` | medium | "no experience" / "no skills needed" / "anyone can do" near a pay figure |
| `hired-no-interview` | high | "you are hired" / "offer" / "start immediately" with no mention of interview, or "interview" only via chat app |
| `urgency-pressure` | medium | "limited slots", "respond within", "act now", "today only", "positions filling fast" |
| `unsolicited-contact` | low | "found your profile", "came across your resume", "your profile matched" + no application referenced |
| `generic-greeting` | low | "dear candidate", "dear applicant", "hello dear", "dear sir/madam" |
| `vague-role` | low | no concrete job title, team, or product named anywhere in the text |
| `grammar-artifacts` | low | multiple sentence-start lowercase, double spaces, ALL-CAPS runs, "kindly" + "revert back" |

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
