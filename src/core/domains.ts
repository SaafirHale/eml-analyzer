/**
 * Domain helpers: organisational domain, punycode, confusable skeletons, edit distance and
 * the lookalike comparison built from them. No network and no public-suffix download, so the
 * organisational domain is an approximation (last two labels, three under common
 * second-level suffixes such as co.uk).
 */

import type { LookalikeTechnique } from "./types.js";

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "net.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp",
  "co.za", "org.za",
  "com.br", "net.br", "org.br",
  "com.mx", "com.ar", "com.co", "com.pe",
  "co.in", "net.in", "org.in", "firm.in",
  "com.cn", "net.cn", "org.cn",
  "com.sg", "com.my", "com.hk", "com.tw", "com.tr", "com.ua", "com.pl",
  "co.kr", "or.kr", "co.il", "co.id",
]);

/** Freemail and consumer mailbox providers. A sender here is an individual, never a company. */
export const FREEMAIL_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
  "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
  "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru",
  "mail.ru", "tutanota.com", "fastmail.com", "hey.com",
  // Reserved test names used by the bundled samples, so the demo behaves like real mail.
  "freemail.test",
]);

export function normaliseDomain(d: string): string {
  return d.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function domainOf(address: string | undefined): string | undefined {
  if (!address) return undefined;
  const clean = address.trim().replace(/^<|>$/g, "");
  const at = clean.lastIndexOf("@");
  if (at < 0) return undefined;
  const d = normaliseDomain(clean.slice(at + 1));
  return d || undefined;
}

export function isIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || (h.includes(":") && /^[0-9a-f:.]+$/i.test(h));
}

/** eTLD+1 approximation. */
export function orgDomain(domain: string): string {
  const d = normaliseDomain(domain);
  if (isIpLiteral(d)) return d;
  const labels = d.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

/** The public suffix part of a domain under the same approximation. */
export function suffixOf(domain: string): string {
  const org = orgDomain(domain);
  const dot = org.indexOf(".");
  return dot < 0 ? "" : org.slice(dot + 1);
}

/** The registrable label: "example" for mail.example.co.uk. */
export function registrableLabel(domain: string): string {
  const org = orgDomain(domain);
  const dot = org.indexOf(".");
  return dot < 0 ? org : org.slice(0, dot);
}

export function sameOrg(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false;
  return orgDomain(a) === orgDomain(b);
}

// --------------------------------------------------------------- punycode --
// RFC 3492 decoder. URL parsing gives us ASCII hosts; this turns xn-- labels back into
// the characters a reader would see.

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function basicToDigit(cp: number): number {
  if (cp >= 0x30 && cp < 0x3a) return cp - 22;
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
  return BASE;
}

export function punycodeDecodeLabel(input: string): string {
  const output: number[] = [];
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error("bad punycode");
      const digit = basicToDigit(input.charCodeAt(idx++));
      if (digit >= BASE) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function hasPunycode(domain: string): boolean {
  return domain.split(".").some((l) => l.toLowerCase().startsWith("xn--"));
}

/** xn--exmple-cua.test → exämple.test. Labels that fail to decode are left alone. */
export function toUnicode(domain: string): string {
  return domain
    .split(".")
    .map((label) => {
      if (!label.toLowerCase().startsWith("xn--")) return label;
      try {
        return punycodeDecodeLabel(label.slice(4).toLowerCase());
      } catch {
        return label;
      }
    })
    .join(".");
}

// ------------------------------------------------------------- confusables --

const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i",
  "ј": "j", "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "ԛ": "q", "г": "r",
  "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "ʏ": "y", "з": "3",
  // Greek
  "α": "a", "β": "b", "ϲ": "c", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
  "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
  // Latin lookalikes that NFKD does not fold
  "ı": "i", "ł": "l", "ɡ": "g", "ɑ": "a", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ß": "ss",
  // ASCII substitutions
  "0": "o", "1": "l", "|": "l", "5": "s", "$": "s", "@": "a",
};

/**
 * A comparison key in which characters that look alike collapse to one form. Two labels with
 * the same skeleton read the same to a person skimming a sender line.
 */
export function skeleton(label: string): string {
  const folded = label
    .normalize("NFKC")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "");
  let out = "";
  for (const ch of folded) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, "m").replace(/vv/g, "w");
}

export function scriptsIn(label: string): Set<string> {
  const scripts = new Set<string>();
  for (const ch of label) {
    if (/\p{Script=Latin}/u.test(ch)) scripts.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add("Greek");
    else if (/\p{Script=Armenian}/u.test(ch)) scripts.add("Armenian");
    else if (/[^\x00-\x7f]/.test(ch) && /\p{L}/u.test(ch)) scripts.add("Other");
  }
  return scripts;
}

export function isMixedScript(domain: string): boolean {
  return domain.split(".").some((l) => scriptsIn(l).size > 1);
}

/** Optimal string alignment distance (Levenshtein plus adjacent transposition). */
export function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array<number>(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = v;
    }
  }
  return d[m]![n]!;
}

export type LookalikeMatch = {
  techniques: LookalikeTechnique[];
  distance?: number;
  unicode?: string;
};

/**
 * Does `candidate` look like `reference` without belonging to the same organisation?
 * Returns null when it does not.
 */
export function compareDomains(candidate: string, reference: string): LookalikeMatch | null {
  const cand = normaliseDomain(candidate);
  const ref = normaliseDomain(reference);
  if (!cand || !ref || isIpLiteral(cand) || isIpLiteral(ref)) return null;
  if (orgDomain(cand) === orgDomain(ref)) return null;

  const unicode = toUnicode(cand);
  const candLabel = registrableLabel(unicode);
  const refLabel = registrableLabel(ref);
  if (refLabel.length < 4) return null;

  const techniques: LookalikeTechnique[] = [];
  const candSkel = skeleton(candLabel);
  const refSkel = skeleton(refLabel);
  let distance: number | undefined;

  if (candLabel === refLabel) {
    techniques.push("tld-swap");
  } else if (candSkel === refSkel) {
    techniques.push("homoglyph");
  } else {
    const dist = editDistance(candSkel, refSkel);
    const limit = refSkel.length >= 9 ? 2 : 1;
    if (dist <= limit) {
      techniques.push("edit-distance");
      distance = dist;
    }
  }

  if (!techniques.length) {
    // The real name used as a token somewhere else in the host: example.com.login.test,
    // example-sso.test, secure-example.test.
    // Tokens come from everything left of the public suffix, so a ".example" TLD never
    // counts as the brand name "example".
    const suffix = suffixOf(unicode);
    const namePart = suffix ? unicode.slice(0, unicode.length - suffix.length - 1) : unicode;
    const tokens = namePart.split(/[.\-_]/).filter(Boolean).map(skeleton);
    const host = unicode.slice(0, unicode.length - orgDomain(unicode).length);
    const refOrgSkel = skeleton(orgDomain(ref));
    if (
      tokens.includes(refSkel) ||
      skeleton(host).includes(refOrgSkel) ||
      (candSkel.length > refSkel.length && candSkel.includes(refSkel) && refSkel.length >= 5)
    ) {
      techniques.push("combosquat");
    }
  }

  if (!techniques.length) return null;
  if (hasPunycode(cand)) techniques.push("punycode");
  if (isMixedScript(unicode)) techniques.push("mixed-script");
  return { techniques, distance, unicode: unicode !== cand ? unicode : undefined };
}
