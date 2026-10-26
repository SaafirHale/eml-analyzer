/**
 * Authentication-Results (RFC 8601), ARC (RFC 8617), DKIM-Signature tags and Received-SPF,
 * turned into SPF / DKIM / DMARC / ARC verdicts with a plain-language explanation.
 *
 * Nothing is re-verified here: there is no DNS in a browser tab. The verdicts are the ones
 * the receiving server recorded, read from the topmost Authentication-Results headers, which
 * are the ones added by the mailbox's own gateway.
 */

import { domainOf, sameOrg } from "./domains.js";
import type {
  ArcSet,
  AuthMethodName,
  AuthMethodResult,
  AuthResult,
  AuthResultsHeader,
  AuthSummaryItem,
  DkimSignature,
  HeaderField,
  Verdict,
} from "./types.js";

/** Split on a delimiter that is not inside a (comment) or "quoted string". */
function splitTop(s: string, delim: string): string[] {
  const out: string[] = [];
  let depth = 0, quoted = false, cur = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === "\\" && i + 1 < s.length) {
      cur += ch + s[++i];
      continue;
    }
    if (ch === '"') quoted = !quoted;
    else if (!quoted && ch === "(") depth++;
    else if (!quoted && ch === ")") depth = Math.max(0, depth - 1);
    if (ch === delim && depth === 0 && !quoted) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

function methodName(raw: string): AuthMethodName {
  const m = raw.toLowerCase().split("/")[0]!;
  if (m === "spf" || m === "dmarc" || m === "arc" || m === "compauth" || m === "bimi") return m;
  if (m.startsWith("dkim")) return "dkim";
  return "other";
}

export function parseResinfo(resinfo: string): AuthMethodResult | null {
  const comments: string[] = [];
  const stripped = resinfo.replace(/\(([^()]*)\)/g, (_, c: string) => {
    comments.push(c.trim());
    return " ";
  });
  const tokens = stripped.match(/[^\s=]+\s*=\s*(?:"[^"]*"|[^\s]+)|\S+/g) ?? [];
  const first = tokens.shift();
  if (!first) return null;
  const eq = first.indexOf("=");
  if (eq < 0) return null;
  const rawMethod = first.slice(0, eq).trim();
  const result = first.slice(eq + 1).trim().toLowerCase();
  const props: Record<string, string> = {};
  let reason: string | undefined;
  for (const tok of tokens) {
    const i = tok.indexOf("=");
    if (i < 0) continue;
    const k = tok.slice(0, i).trim().toLowerCase();
    const v = tok.slice(i + 1).trim().replace(/^"|"$/g, "");
    if (k === "reason") reason = v;
    else props[k] = v;
  }
  return {
    method: methodName(rawMethod),
    rawMethod: rawMethod.toLowerCase(),
    result,
    reason,
    props,
    comment: comments.length ? comments.join("; ") : undefined,
  };
}

export function parseAuthResults(
  raw: string,
  source: AuthResultsHeader["source"] = "Authentication-Results",
): AuthResultsHeader {
  const parts = splitTop(raw.replace(/\s+/g, " "), ";");
  let instance: number | undefined;
  if (source === "ARC-Authentication-Results" && /^i\s*=\s*\d+$/i.test(parts[0] ?? "")) {
    instance = Number(parts.shift()!.split("=")[1]);
  }
  // Microsoft 365 omits the authserv-id and starts straight with "spf=…".
  let authservId = "";
  if (parts[0] && !/^[a-z0-9-]+(\/\d+)?\s*=/i.test(parts[0])) {
    authservId = parts.shift()!.replace(/\([^)]*\)/g, "").trim().split(/\s+/)[0] ?? "";
  }
  const results = parts
    .filter((p) => p.toLowerCase() !== "none")
    .map(parseResinfo)
    .filter((r): r is AuthMethodResult => r !== null);
  return { source, authservId, instance, results, raw };
}

/** DKIM-Signature, ARC-Seal and ARC-Message-Signature are tag=value; lists. */
export function parseTagList(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k) out[k] = part.slice(i + 1).replace(/\s+/g, "").trim();
  }
  return out;
}

function toVerdict(result: string | undefined): Verdict {
  switch ((result ?? "").toLowerCase()) {
    case "pass":
      return "pass";
    case "fail":
    case "hardfail":
      return "fail";
    case "softfail":
      return "softfail";
    case "neutral":
      return "neutral";
    case "none":
    case "bestguesspass":
      return "none";
    case "temperror":
      return "temperror";
    case "permerror":
      return "permerror";
    case "policy":
      return "policy";
    default:
      return "unknown";
  }
}

function policyFrom(r: AuthMethodResult): string | undefined {
  const p = /\bp=(\w+)/i.exec(r.comment ?? "")?.[1] ?? r.props["policy.published-domain-policy"];
  return p?.toLowerCase();
}

function explainSpf(v: Verdict, domain: string | undefined, aligned: boolean | undefined, fromDomain: string | undefined, ip?: string): string {
  const d = domain ?? "the envelope sender";
  const by = ip ? ` (${ip})` : "";
  switch (v) {
    case "pass":
      return `The server that handed this message over${by} is on the list of servers allowed to send for ${d}. ` +
        (aligned
          ? "That domain matches the From address, so the pass counts toward DMARC."
          : `${d} is not the From domain${fromDomain ? ` (${fromDomain})` : ""}, so the pass says nothing about the name on the From line.`);
    case "fail":
      return `${d} publishes a list of servers allowed to send for it, and the server that delivered this message${by} is not on it.`;
    case "softfail":
      return `The sending server${by} is not on ${d}'s list of allowed senders. The domain asks receivers to accept and mark such mail rather than reject it.`;
    case "neutral":
      return `${d} publishes SPF but makes no claim either way about the sending server.`;
    case "none":
      return `${d} publishes no SPF record, so there is no list of allowed senders to check against.`;
    case "temperror":
    case "permerror":
      return `The SPF check for ${d} errored (${v}). A permerror usually means a broken record; a temperror, a DNS timeout.`;
    default:
      return "The receiving server recorded no SPF result.";
  }
}

function explainDkim(v: Verdict, domain: string | undefined, aligned: boolean | undefined, fromDomain: string | undefined): string {
  const d = domain ?? "the signer";
  switch (v) {
    case "pass":
      return `A signature from ${d} verifies: the signed headers and body are unchanged since ${d} signed them. ` +
        (aligned
          ? "The signing domain matches the From address."
          : `${d} is not the From domain${fromDomain ? ` (${fromDomain})` : ""}, so the signature proves who relayed it, not who the From line names.`);
    case "fail":
      return `A signature claiming to come from ${d} does not verify. The message was altered after signing, or the signature is forged.`;
    case "none":
      return "The message carries no DKIM signature, so nothing ties its content to any domain.";
    case "neutral":
    case "policy":
      return `A DKIM signature from ${d} was present but not evaluated (${v}).`;
    case "temperror":
    case "permerror":
      return `The DKIM check for ${d} errored (${v}), usually a missing or malformed public key.`;
    default:
      return "The receiving server recorded no DKIM result.";
  }
}

function explainDmarc(v: Verdict, domain: string | undefined, policy: string | undefined): string {
  const d = domain ?? "the From domain";
  const p = policy ? ` (policy p=${policy})` : "";
  switch (v) {
    case "pass":
      return `${d} passed DMARC${p}: SPF or DKIM passed for a domain that matches the From address. The From domain is not spoofed.`;
    case "fail":
      return `${d} publishes a DMARC policy${p} and this message had neither an aligned SPF pass nor an aligned DKIM pass. By the domain owner's own rules, it did not come from them.`;
    case "none":
      return `${d} publishes no DMARC policy, so nothing ties the From address to the servers that sent it. Anyone can put this domain on a From line.`;
    case "temperror":
    case "permerror":
      return `The DMARC check for ${d} errored (${v}).`;
    default:
      return "The receiving server recorded no DMARC result.";
  }
}

function explainArc(v: Verdict, sets: ArcSet[]): string {
  const n = sets.length;
  const hops = n === 1 ? "one intermediary" : `${n} intermediaries`;
  switch (v) {
    case "pass":
      return `The message passed through ${hops} (a list or forwarding service) that recorded the authentication results it saw, and the receiver found the seal chain intact. Those earlier results are in the ARC table.`;
    case "fail":
      return `An ARC chain is present (${hops}) but the receiver found it broken. Results claimed by earlier hops cannot be relied on.`;
    case "none":
      return n
        ? `ARC headers are present (${hops}) but the receiver did not evaluate them.`
        : "No ARC chain: the message was not resealed by a forwarding service on the way in.";
    default:
      return n ? `ARC headers are present (${hops}); the receiver recorded no ARC verdict.` : "No ARC headers.";
  }
}

export function analyzeAuth(headers: HeaderField[], fromAddress: string | undefined): AuthResult {
  const fromDomain = domainOf(fromAddress);
  const get = (name: string) => headers.filter((h) => h.name.toLowerCase() === name).map((h) => h.value);

  const all = get("authentication-results").map((v) => parseAuthResults(v));
  // The topmost header was added last, by the gateway closest to the mailbox. Headers from
  // the same authserv-id belong to that gateway; anything further down may be forged.
  const primaryId = all[0]?.authservId;
  const primary = all.filter((h) => h.authservId === primaryId);
  const results = primary.flatMap((h) => h.results);

  const receivedSpf = get("received-spf");
  const dkimSignatures: DkimSignature[] = get("dkim-signature").map((v) => {
    const t = parseTagList(v);
    return {
      domain: t.d?.toLowerCase(),
      selector: t.s,
      algorithm: t.a,
      headers: t.h ? t.h.split(":").map((x) => x.trim().toLowerCase()) : undefined,
    };
  });

  const arcMap = new Map<number, ArcSet>();
  const arcSet = (i: number) => {
    let s = arcMap.get(i);
    if (!s) arcMap.set(i, (s = { instance: i }));
    return s;
  };
  for (const v of get("arc-seal")) {
    const t = parseTagList(v);
    const s = arcSet(Number(t.i ?? 0));
    s.cv = t.cv?.toLowerCase();
    s.sealDomain = t.d?.toLowerCase();
  }
  for (const v of get("arc-message-signature")) {
    const t = parseTagList(v);
    arcSet(Number(t.i ?? 0)).signatureDomain = t.d?.toLowerCase();
  }
  for (const v of get("arc-authentication-results")) {
    const parsed = parseAuthResults(v, "ARC-Authentication-Results");
    arcSet(parsed.instance ?? 0).authResults = parsed;
  }
  const arc = [...arcMap.values()].sort((a, b) => a.instance - b.instance);

  const summary: AuthSummaryItem[] = [];

  // SPF
  const spf = results.find((r) => r.method === "spf");
  if (spf) {
    const domain = domainOf(spf.props["smtp.mailfrom"]) ?? spf.props["smtp.mailfrom"]?.toLowerCase() ?? spf.props["smtp.helo"]?.toLowerCase();
    const v = toVerdict(spf.result);
    const aligned = domain && fromDomain ? sameOrg(domain, fromDomain) : undefined;
    const ip = /\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})\b/i.exec(spf.comment ?? "")?.[1];
    summary.push({ method: "spf", verdict: v, domain, aligned, explanation: explainSpf(v, domain, aligned, fromDomain, ip) });
  } else if (receivedSpf[0]) {
    const v = toVerdict(receivedSpf[0].trim().split(/[\s(;]/)[0]);
    const domain = domainOf(/envelope-from=["<]?([^\s;">]+)/i.exec(receivedSpf[0])?.[1]);
    const aligned = domain && fromDomain ? sameOrg(domain, fromDomain) : undefined;
    summary.push({ method: "spf", verdict: v, domain, aligned, explanation: explainSpf(v, domain, aligned, fromDomain) });
  } else {
    summary.push({ method: "spf", verdict: "unknown", explanation: explainSpf("unknown", undefined, undefined, fromDomain) });
  }

  // DKIM: prefer an aligned pass, then any pass, then the first result.
  const dkims = results.filter((r) => r.method === "dkim");
  const dkimDomain = (r: AuthMethodResult) => {
    const d = (r.props["header.d"] ?? domainOf(r.props["header.i"]))?.toLowerCase();
    return d && d !== "none" ? d : undefined;
  };
  const dkim =
    dkims.find((r) => toVerdict(r.result) === "pass" && fromDomain && dkimDomain(r) && sameOrg(dkimDomain(r)!, fromDomain)) ??
    dkims.find((r) => toVerdict(r.result) === "pass") ??
    dkims[0];
  if (dkim) {
    const domain = dkimDomain(dkim) ?? dkimSignatures[0]?.domain;
    const v = toVerdict(dkim.result);
    const aligned = domain && fromDomain ? sameOrg(domain, fromDomain) : undefined;
    summary.push({ method: "dkim", verdict: v, domain, aligned, explanation: explainDkim(v, domain, aligned, fromDomain) });
  } else {
    const v: Verdict = all.length && !dkimSignatures.length ? "none" : "unknown";
    summary.push({ method: "dkim", verdict: v, domain: dkimSignatures[0]?.domain, explanation: explainDkim(v, dkimSignatures[0]?.domain, undefined, fromDomain) });
  }

  // DMARC
  const dmarc = results.find((r) => r.method === "dmarc");
  if (dmarc) {
    const domain = dmarc.props["header.from"]?.toLowerCase() ?? fromDomain;
    const v = toVerdict(dmarc.result);
    summary.push({
      method: "dmarc",
      verdict: v,
      domain,
      explanation: explainDmarc(v, domain, policyFrom(dmarc)),
    });
  } else {
    summary.push({ method: "dmarc", verdict: "unknown", domain: fromDomain, explanation: explainDmarc("unknown", fromDomain, undefined) });
  }

  // ARC: the receiver's own arc= verdict, else the newest seal's cv=.
  const arcRes = results.find((r) => r.method === "arc");
  const newest = arc.at(-1);
  const arcVerdict: Verdict = arcRes ? toVerdict(arcRes.result) : newest?.cv ? toVerdict(newest.cv) : arc.length ? "unknown" : "none";
  summary.push({ method: "arc", verdict: arcVerdict, domain: newest?.sealDomain, explanation: explainArc(arcVerdict, arc) });

  if (!all.length) {
    for (const s of summary) {
      if (s.verdict === "unknown" && s.method !== "arc") {
        s.explanation += " There is no Authentication-Results header at all: the receiving server recorded no checks, or the headers were stripped.";
      }
    }
  }

  return { headers: [...all, ...arc.flatMap((a) => (a.authResults ? [a.authResults] : []))], receivedSpf, dkimSignatures, arc, summary };
}

export { policyFrom };
