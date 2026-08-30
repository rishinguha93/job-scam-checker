# job-scam-checker

A privacy-first web tool that helps individual job seekers tell whether a
recruiter email, LinkedIn message, text, or job offer is a scam — and tells them
what to do next.

Modeled on general-purpose "is this a scam?" checkers (e.g. Scamwise), but
scoped to **recruiting fraud**: fake recruiters, task/"gamified job" scams,
advance-fee and fake-check schemes, and identity-theft "onboarding".

## Status

Early scaffold — a working skeleton, not a finished product. The detection
engine runs a transparent, rule-based analysis **entirely in the browser**;
nothing the user pastes is uploaded. See `docs/research.md` for the problem
research and `docs/ruleset.md` for the red-flag catalog the engine implements.

## Stack

- **Vite** + **React** + **TypeScript** for the UI
- **Vitest** for engine unit tests
- The detection engine (`src/engine/`) has **no DOM or React dependency** so it
  can be tested in isolation and later reused in a browser extension or a
  server-side check.

## Getting started

```bash
npm install
npm run dev      # start the dev server
npm test         # run engine tests
npm run build    # typecheck + production build to dist/
```

## Project structure

```
job-scam-checker/
├── index.html              Vite entry; loads src/main.tsx
├── src/
│   ├── main.tsx            React bootstrap
│   ├── App.tsx             Hash routing between the three views
│   ├── styles.css          All styles (light + dark)
│   ├── engine/             Detection logic — framework-agnostic, unit-tested
│   │   ├── types.ts        Shared types
│   │   ├── rules.ts        Individual red-flag rules (pure functions)
│   │   ├── analyze.ts      Orchestrator: run rules, aggregate a verdict
│   │   └── analyze.test.ts Engine tests
│   ├── views/
│   │   ├── CheckMessage.tsx    Paste a message/thread → verdict + red flags
│   │   ├── VerifyRecruiter.tsx Guided recruiter/company verification checklist
│   │   └── Scammed.tsx         "I think I've been scammed" triage + reporting
│   ├── components/         Shared UI helpers (empty for now)
│   └── data/
│       └── reportingLinks.ts   FTC / IC3 / IdentityTheft.gov references
├── docs/
│   ├── research.md         Problem research, scam taxonomy, sources
│   └── ruleset.md          Red-flag catalog + scoring model
└── tests/                  Reserved for integration/UI tests
```

## Design principles

- **Local-only analysis.** The core verdict never sends the user's message
  anywhere. Any future API-backed signal (domain reputation, OCR, LLM pass) is
  opt-in and clearly labeled.
- **Explainable.** Every verdict lists the specific red flags found, quoting the
  user's own text. No black-box score.
- **Actionable.** Every result ends in a concrete next step — a verification
  checklist, or reporting instructions if the user already engaged.
- **Never says "safe".** Absence of red flags is not proof of legitimacy, and
  the UI says so.

## Roadmap

- **v1 (client-side):** message checker, verification checklist, victim triage.
  Expand the ruleset; add engine tests per rule.
- **v2 (API-backed, opt-in):** domain age/reputation lookups, screenshot OCR,
  reverse image search, optional LLM "deeper analysis", crowd-reported scammer
  database.
