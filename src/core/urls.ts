import { hasPunycode, isIpLiteral, normaliseDomain, sameOrg } from "./domains.js";
import { extractHtmlLinks } from "./html.js";
import type { LinkFlag, LinkInfo, LinkSource } from "./types.js";

export const SHORTENERS = new Set([
  "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy",
  "cutt.ly", "shorturl.at", "rebrand.ly", "t.ly", "tiny.cc", "s.id", "v.gd", "lnkd.in", "qrco.de",
  "bl.ink", "short.io", "shorturl.gg", "x.gd", "urlz.fr", "clck.ru", "u.to", "trib.al",
]);

/** Hosts whose whole job is to bounce a visitor somewhere else. */
const KNOWN_REDIRECTORS = [
  /(^|\.)safelinks\.protection\.outlook\.com$/,
  /(^|\.)urldefense\.(com|proofpoint\.com)$/,
  /^l\.facebook\.com$/,
  /^www\.google\.[a-z.]+$/, // only with /url? — checked below
];

const REDIRECT_PARAMS = /^(url|u|redirect|redirect_uri|redirecturl|redir|r|target|dest|destination|next|continue|goto|link|out|to|q|returnurl|return_to)$/i;

const CREDENTIAL_PATH = /(log-?in|sign-?in|signon|sso|auth|verify|validation|password|passwd|account|secure|update|unlock|mfa|2fa|webmail|owa|wp-admin)/i;

export function defang(url: string): string {
  return url
    .replace(/^http(s?):\/\//i, (_, s: string) => `hxxp${s}://`)
    .replace(/^ftp:\/\//i, "fxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'`{}|\\^\[\]]+/gi;

export function extractTextUrls(text: string): string[] {
  const out: string[] = [];
  for (const m of text.match(URL_RE) ?? []) {
    let u = m.replace(/[.,;:!?)\]>'"]+$/, "");
    // Keep a closing paren that belongs to the URL itself.
    if (m.includes("(") && !u.includes("(")) u = m.replace(/[.,;:!?\]>'"]+$/, "");
    out.push(u);
  }
  return out;
}

function safeUrl(href: string): URL | undefined {
  try {
    return new URL(/^www\./i.test(href) ? `http://${href}` : href);
  } catch {
    return undefined;
  }
}

function hostOf(href: string): string | undefined {
  const u = safeUrl(href);
  return u?.hostname ? normaliseDomain(u.hostname) : undefined;
}

/** Does the visible text look like a URL or bare domain? Returns its host if so. */
function hostShownInText(text: string): string | undefined {
  const t = text.trim();
  const m = /^(?:https?:\/\/)?((?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?:[/:?#]\S*)?$/i.exec(t);
  return m?.[1] ? normaliseDomain(hostOf(`http://${m[1]}`) ?? m[1]) : undefined;
}

function redirectTargetOf(u: URL): string | undefined {
  for (const [k, v] of u.searchParams) {
    if (!REDIRECT_PARAMS.test(k)) continue;
    const val = v.trim();
    if (/^(https?:)?\/\//i.test(val) || /^www\./i.test(val)) return val;
    if (/^aHR0c/.test(val)) {
      // base64 of "http"
      try {
        const decoded = atob(val);
        if (/^https?:\/\//.test(decoded)) return decoded;
      } catch {
        /* not base64 */
      }
    }
  }
  return undefined;
}

export type RawLink = { href: string; text?: string; source: LinkSource; kind?: string };

export function collectLinks(html: string | undefined, text: string | undefined): RawLink[] {
  const out: RawLink[] = [];
  if (html) {
    for (const l of extractHtmlLinks(html)) {
      if (/^(mailto|tel|cid|#)/i.test(l.href) || l.href.startsWith("#")) continue;
      out.push({ href: l.href, text: l.text, source: "html", kind: l.kind });
    }
  }
  if (text) {
    // A text part that mirrors the HTML repeats its links; keep only the new ones.
    const inHtml = new Set(out.map((l) => l.href));
    for (const u of extractTextUrls(text)) if (!inHtml.has(u)) out.push({ href: u, source: "text" });
  }
  return out;
}

export function analyzeLink(
  raw: RawLink,
  ctx: { fromDomain?: string; recipients: string[] },
): LinkInfo {
  const flags: LinkFlag[] = [];
  const href = raw.href.trim();
  const u = safeUrl(href);
  const host = u?.hostname ? normaliseDomain(u.hostname) : undefined;
  let redirectTarget: string | undefined;

  if (/^javascript:/i.test(href)) flags.push("javascript-uri");
  if (/^data:/i.test(href)) flags.push("data-uri");
  if (raw.kind === "form") flags.push("form-action");

  if (u && host) {
    if (u.protocol === "http:") flags.push("non-https");
    if (isIpLiteral(host)) flags.push("ip-host");
    if (hasPunycode(host)) flags.push("punycode");
    if (SHORTENERS.has(host)) flags.push("shortener");
    redirectTarget = redirectTargetOf(u);
    const knownRedirector =
      KNOWN_REDIRECTORS.some((r) => r.test(host)) && (!/^www\.google\./.test(host) || u.pathname === "/url");
    if (redirectTarget || knownRedirector) flags.push("redirector");
    if (CREDENTIAL_PATH.test(u.pathname)) flags.push("credential-path");
    let decoded = href.toLowerCase();
    try {
      decoded = decodeURIComponent(href).toLowerCase();
    } catch {
      /* malformed escape: compare the raw string */
    }
    if (ctx.recipients.some((r) => r && decoded.includes(r.toLowerCase()))) flags.push("recipient-in-url");
  }

  if (raw.text && host) {
    const shown = hostShownInText(raw.text);
    if (shown && !sameOrg(shown, host)) flags.push("text-href-mismatch");
  }

  return {
    href,
    text: raw.text,
    host,
    source: raw.source,
    flags,
    redirectTarget,
    defanged: defang(href),
  };
}

/** Collapse exact duplicates (same href, text and source). */
export function dedupeLinks(links: LinkInfo[]): LinkInfo[] {
  const seen = new Set<string>();
  return links.filter((l) => {
    const k = `${l.source}\u0000${l.href}\u0000${l.text ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export { hostOf, safeUrl };
