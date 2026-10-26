import type { ReceivedHop, RouteResult } from "./types.js";

/** RFC 5322 dates with optional trailing comments such as "(UTC)". */
export function parseMailDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const clean = value.replace(/\([^)]*\)/g, " ").replace(/\s+/g, " ").trim();
  const t = Date.parse(clean);
  return Number.isFinite(t) ? new Date(t) : undefined;
}

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const IPV6 = /(?<![\w:])((?:[0-9a-f]{1,4})?(?::(?:[0-9a-f]{1,4})?){2,7})(?![\w:])/i;

function grab(re: RegExp, s: string): string | undefined {
  const m = re.exec(s);
  return m?.[1]?.replace(/[<>]/g, "").replace(/;$/, "");
}

export function parseReceived(raw: string): Omit<ReceivedHop, "index" | "delaySeconds"> {
  const value = raw.replace(/\s+/g, " ").trim();
  const semi = value.lastIndexOf(";");
  const body = semi >= 0 ? value.slice(0, semi) : value;
  const date = semi >= 0 ? parseMailDate(value.slice(semi + 1)) : undefined;

  const hop: Omit<ReceivedHop, "index" | "delaySeconds"> = { raw: value };
  const fromM = /^from\s+(\S+)(?:\s+\(([^)]*)\))?/i.exec(body);
  if (fromM) {
    hop.from = fromM[1];
    const comment = fromM[2] ?? "";
    const bracket = /\[([^\]]+)\]/.exec(comment);
    const v6 = grab(IPV6, comment);
    // A full address has seven colons; anything shorter must compress with "::" (rules out times).
    const ipv6 = v6 && (v6.includes("::") || v6.split(":").length === 8) ? v6 : undefined;
    const ip = bracket?.[1]?.replace(/^IPv6:/i, "") ?? grab(IPV4, comment) ?? ipv6;
    if (ip) hop.fromIp = ip;
    const rdns = comment.replace(/\[[^\]]*\]/g, "").replace(/helo=\S+/i, "").trim().split(/\s+/)[0];
    if (rdns && rdns !== ip && !/^unknown$/i.test(rdns) && /[a-z]/i.test(rdns)) hop.fromRdns = rdns;
  }
  if (!hop.fromIp) {
    // Some relays put the address in the from token itself: "from [192.0.2.4]".
    const ip = grab(/^from\s+\[([^\]]+)\]/i, body);
    if (ip) hop.fromIp = ip;
  }
  const by = grab(/\bby\s+(\S+)/i, body);
  if (by) hop.by = by;
  const withP = grab(/\bwith\s+([A-Za-z0-9_-]+)/i, body);
  if (withP) hop.with = withP;
  const id = grab(/\bid\s+(\S+)/i, body);
  if (id) hop.id = id;
  const forA = grab(/\bfor\s+(<[^>]+>|\S+@\S+)/i, body);
  if (forA) hop.for = forA;
  if (date) hop.date = date.toISOString();
  return hop;
}

/**
 * Received headers are prepended, so the list is newest first. The returned hops run in
 * delivery order: hop 1 is where the message entered the chain.
 */
export function analyzeRoute(receivedNewestFirst: string[], dateHeader?: string): RouteResult {
  const hops: ReceivedHop[] = receivedNewestFirst
    .slice()
    .reverse()
    .map((raw, i) => ({ index: i + 1, ...parseReceived(raw) }));

  let prev: number | undefined;
  for (const hop of hops) {
    if (!hop.date) continue;
    const t = Date.parse(hop.date);
    if (prev !== undefined) hop.delaySeconds = Math.round((t - prev) / 1000);
    prev = t;
  }

  const dated = hops.filter((h) => h.date);
  const result: RouteResult = { hops };
  if (dated.length >= 2) {
    result.totalSeconds = Math.round((Date.parse(dated.at(-1)!.date!) - Date.parse(dated[0]!.date!)) / 1000);
  }
  const sent = parseMailDate(dateHeader);
  if (sent && dated[0]) {
    result.dateToFirstHopSeconds = Math.round((Date.parse(dated[0].date!) - sent.getTime()) / 1000);
  }
  return result;
}

export function formatDuration(seconds: number): string {
  const sign = seconds < 0 ? "-" : "";
  let s = Math.abs(seconds);
  if (s < 60) return `${sign}${s}s`;
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const parts = [d && `${d}d`, h && `${h}h`, m && `${m}m`, s && `${s}s`].filter(Boolean);
  return sign + parts.slice(0, 2).join(" ");
}

const DOC_V4 = [/^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./];
const PRIVATE_V4 = [/^10\./, /^127\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./];

export function ipKind(ip: string): "documentation" | "private" | "public" | "ipv6" {
  if (ip.includes(":")) {
    if (/^2001:db8:/i.test(ip)) return "documentation";
    if (/^(fe80|fc|fd|::1)/i.test(ip)) return "private";
    return "ipv6";
  }
  if (DOC_V4.some((r) => r.test(ip))) return "documentation";
  if (PRIVATE_V4.some((r) => r.test(ip))) return "private";
  return "public";
}
