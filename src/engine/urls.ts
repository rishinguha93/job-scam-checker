/**
 * Link extraction and host classification.
 *
 * Most recruiting scams are delivered by a link — a fake application form, a
 * fake company login, a fake onboarding portal. The rules in `rules.ts` read
 * words; this module gives them the ability to look at the links too.
 */

/** Hosts that shorten a link and hide where it really goes. */
const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "cutt.ly",
  "rebrand.ly",
  "is.gd",
  "ow.ly",
  "buff.ly",
  "shorturl.at",
  "rb.gy",
  "tiny.cc",
  "s.id",
  "t.ly",
  "shorte.st",
  "adf.ly",
  // Deliberately NOT lnkd.in: that is LinkedIn's own shortener and is expected
  // on the platform where most of these messages arrive.
]);

/** Generic form/document builders — fine for a survey, wrong for onboarding. */
const FORM_HOSTS = [
  "docs.google.com",
  "forms.gle",
  "forms.office.com",
  "typeform.com",
  "jotform.com",
  "surveymonkey.com",
  "airtable.com",
  "formstack.com",
  "wufoo.com",
  "cognitoforms.com",
];

/** TLDs disproportionately used for throwaway impersonation domains. */
export const SUSPICIOUS_TLDS = new Set([
  "online", "info", "site", "xyz", "top", "click", "buzz", "work", "shop",
  "icu", "cyou", "sbs", "monster", "quest", "fit", "beauty", "autos",
]);

/** Well-known employer/brand tokens people try to impersonate. */
export const BRAND_TOKENS = [
  "google", "microsoft", "apple", "amazon", "meta", "linkedin", "netflix",
  "oracle", "deloitte", "accenture", "pwc", "kpmg", "cisco", "adobe",
  "salesforce", "fedex", "ups", "walmart", "tesla", "nvidia", "spotify",
];

/**
 * Hosts that legitimately appear in real recruiting messages — applicant
 * tracking systems, scheduling tools, payroll providers, the big platforms.
 * Checked before any look-alike test so `docs.google.com` isn't reported as a
 * Google impersonation.
 */
const KNOWN_GOOD_HOSTS = [
  "google.com", "gmail.com", "microsoft.com", "office.com", "live.com",
  "linkedin.com", "lnkd.in", "github.com", "gitlab.com", "apple.com",
  "amazon.com", "amazon.jobs", "zoom.us", "webex.com", "calendly.com",
  "greenhouse.io", "lever.co", "workday.com", "myworkdayjobs.com",
  "ashbyhq.com", "smartrecruiters.com", "icims.com", "taleo.net",
  "bamboohr.com", "adp.com", "gusto.com", "workable.com", "jobvite.com",
  "indeed.com", "glassdoor.com", "ziprecruiter.com", "prolific.com",
  "prolific.co", "dropbox.com", "notion.so", "docusign.net", "docusign.com",
];

/** File extensions that must not be mistaken for a domain ending. */
const FILE_EXTENSIONS = new Set([
  "doc", "docx", "pdf", "js", "ts", "jsx", "tsx", "py", "rb", "go", "rs",
  "java", "png", "jpg", "jpeg", "gif", "svg", "webp", "zip", "rar", "exe",
  "msi", "dmg", "apk", "csv", "xls", "xlsx", "ppt", "pptx", "txt", "md",
  "json", "xml", "html", "htm", "css", "sh", "bat", "mp4", "mov", "env",
]);

/**
 * TLDs accepted when a link is written without `http://` or `www.`. Without
 * this, a missing space after a full stop ("etc.Please note") reads as a
 * domain. A link written with a scheme is trusted to be a link regardless.
 */
const KNOWN_TLDS = new Set([
  // generic
  "com", "net", "org", "int", "edu", "gov", "mil", "biz", "info", "name",
  "io", "co", "ai", "dev", "app", "me", "tv", "cc", "xyz", "top", "click",
  "shop", "work", "buzz", "icu", "cyou", "sbs", "online", "site", "live",
  "life", "world", "tech", "store", "space", "website", "agency", "careers",
  "jobs", "email", "link", "page", "cloud", "digital", "group", "media",
  "network", "solutions", "systems", "consulting", "company", "global",
  "monster", "quest", "fit", "beauty", "autos", "pro", "plus", "team",
  // country
  "us", "uk", "ca", "de", "fr", "in", "au", "nl", "es", "it", "jp", "cn",
  "br", "ru", "eu", "asia", "ie", "nz", "za", "ng", "ke", "mx", "ar", "cl",
  "sg", "hk", "tw", "kr", "th", "my", "ph", "vn", "id", "pk", "bd", "lk",
  "se", "no", "fi", "dk", "pl", "cz", "at", "ch", "be", "pt", "gr", "tr",
  "ua", "ro", "hu", "il", "ae", "sa", "qa", "ly", "gl", "gg", "to", "sh",
  "is", "st", "im", "je",
]);

export interface ExtractedUrl {
  /** The link exactly as it appeared in the text. */
  raw: string;
  /** Lowercased hostname, no port. */
  host: string;
  /** Path plus query, lowercased. Empty when the link was a bare domain. */
  path: string;
}

// Explicit links, then bare domains (no scheme) which scammers often use.
const EXPLICIT_URL_RE = /(?:https?:\/\/|www\.)[^\s<>"'\])}]+/gi;
const BARE_DOMAIN_RE =
  /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(\/[^\s<>"'\])}]*)?/gi;

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/^www\./, "").replace(/:\d+$/, "");
}

/** Is `host` the given registrable domain, or a subdomain of it? */
function hostMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/** Pull every link out of the text, de-duplicated by host+path. */
export function extractUrls(text: string): ExtractedUrl[] {
  const found = new Map<string, ExtractedUrl>();

  const add = (
    raw: string,
    rawHost: string,
    rawPath: string,
    requireKnownTld: boolean,
  ) => {
    const host = normalizeHost(rawHost);
    if (!host.includes(".")) return;
    const tld = host.split(".").pop() ?? "";
    if (FILE_EXTENSIONS.has(tld)) return; // "notes.docx" is not a link
    if (requireKnownTld && !KNOWN_TLDS.has(tld)) return;
    const path = rawPath.toLowerCase();
    const key = `${host}${path}`;
    if (!found.has(key)) found.set(key, { raw, host, path });
  };

  for (const m of text.matchAll(EXPLICIT_URL_RE)) {
    const raw = m[0].replace(/[.,;:!?)]+$/, "");
    const withoutScheme = raw.replace(/^https?:\/\//i, "");
    const slash = withoutScheme.indexOf("/");
    const hostPart = slash === -1 ? withoutScheme : withoutScheme.slice(0, slash);
    const pathPart = slash === -1 ? "" : withoutScheme.slice(slash);
    add(raw, hostPart, pathPart, false);
  }

  // Bare domains, skipping anything already captured with a scheme.
  const alreadySeen = new Set([...found.values()].map((u) => u.host));
  for (const m of text.matchAll(BARE_DOMAIN_RE)) {
    const host = normalizeHost(m[1]);
    if (alreadySeen.has(host)) continue;
    add(m[0].replace(/[.,;:!?)]+$/, ""), m[1], m[2] ?? "", true);
  }

  return [...found.values()];
}

/** A host we expect to see in genuine recruiting mail. */
export function isKnownGoodHost(host: string): boolean {
  return KNOWN_GOOD_HOSTS.some((good) => hostMatches(host, good));
}

export function isShortenerHost(host: string): boolean {
  return SHORTENER_HOSTS.has(host);
}

export function isFormHost(host: string): boolean {
  return FORM_HOSTS.some((form) => hostMatches(host, form));
}

/** A bare IPv4 address used in place of a domain name. */
export function isIpHost(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/**
 * Plain-language reasons a hostname looks like an impersonation. Empty when
 * nothing is wrong with it. Shared by the sender-domain rule and the link rules
 * so both judge a domain the same way.
 */
export function lookalikeReasons(host: string): string[] {
  if (isKnownGoodHost(host)) return [];

  const parts = host.split(".");
  const tld = parts[parts.length - 1];
  const core = parts.slice(0, -1).join(".");
  const reasons: string[] = [];

  if (
    /[-.](careers?|hr|jobs?|recruit(ing|ment)?|talent|hiring|apply|portal)$/.test(core) ||
    /^(careers?|hr|jobs?|recruit(ing|ment)?|talent|hiring|apply|portal)[-.]/.test(core)
  ) {
    reasons.push('a bolt-on word like "-careers" or "hr-"');
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(`an unusual .${tld} ending`);
  }
  for (const brand of BRAND_TOKENS) {
    if (core.includes(brand) && core !== brand && !core.endsWith(`.${brand}`)) {
      reasons.push(`the name "${brand}" inside a domain that isn't theirs`);
      break;
    }
  }
  if (/[a-z]\d|\d[a-z]/.test(core.replace(/\d{4,}/g, ""))) {
    reasons.push("digits standing in for letters");
  }

  return reasons;
}
