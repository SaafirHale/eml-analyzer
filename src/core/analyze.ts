import PostalMime from "postal-mime";
import type { Address, Attachment, Email } from "postal-mime";
import { analyzeAuth } from "./auth.js";
import { attachmentFlags, extensionOf, hasCredentialForm, sha256Hex, smugglingIndicators, sniff } from "./attachments.js";
import { EXEC_TITLE, ROLE_TITLE, contentCues } from "./content.js";
import {
  FREEMAIL_DOMAINS,
  compareDomains,
  domainOf,
  hasPunycode,
  normaliseDomain,
  orgDomain,
  registrableLabel,
  sameOrg,
  toUnicode,
} from "./domains.js";
import { extractImages, htmlToText } from "./html.js";
import { QR_IMAGE_TYPES, browserImageDecoder, decodeQr } from "./qr.js";
import { analyzeRoute, formatDuration, parseMailDate } from "./received.js";
import type {
  AnalysisResult,
  AnalyzeOptions,
  AttachmentInfo,
  HeaderField,
  IdentityResult,
  IdentityRow,
  LinkInfo,
  LookalikeFinding,
  Mailbox,
  QrFinding,
  RiskBand,
  Severity,
  Signal,
  SignalCategory,
} from "./types.js";
import { analyzeLink, collectLinks, dedupeLinks, defang } from "./urls.js";

export const ANALYZER_VERSION = "eml-analyzer 0.1.0";

function mailboxes(list: Address[] | Address | undefined): Mailbox[] {
  if (!list) return [];
  const arr = Array.isArray(list) ? list : [list];
  return arr.flatMap((a) => (a.group ? a.group : [a])).map((m) => ({ name: m.name ?? "", address: (m.address ?? "").toLowerCase() }));
}

function toBytes(content: Attachment["content"]): Uint8Array {
  if (typeof content === "string") return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

function severityFor(weight: number): Severity {
  if (weight <= 0) return "info";
  if (weight < 10) return "low";
  if (weight < 20) return "medium";
  if (weight < 35) return "high";
  return "critical";
}

export function bandFor(score: number): RiskBand {
  if (score >= 50) return "high";
  if (score >= 20) return "suspicious";
  return "low";
}

export const BAND_LABEL: Record<RiskBand, string> = {
  low: "Low risk",
  suspicious: "Suspicious",
  high: "Likely phishing",
};

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Parse and analyse one message. Accepts the raw .eml as a string, bytes or a Blob/File. */
export async function analyzeEml(
  input: string | ArrayBuffer | Uint8Array | Blob,
  options: AnalyzeOptions = {},
): Promise<AnalysisResult> {
  const email: Email = await PostalMime.parse(input as never, { attachmentEncoding: "arraybuffer" });
  const signals: Signal[] = [];
  const notes: string[] = [];
  const add = (id: string, category: SignalCategory, weight: number, title: string, detail: string) => {
    if (signals.some((s) => s.id === id)) return;
    signals.push({ id, category, weight, severity: severityFor(weight), title, detail });
  };

  const headers: HeaderField[] = email.headers.map((h) => ({ name: h.originalKey, value: h.value }));
  const headerValues = (name: string) => email.headers.filter((h) => h.key === name).map((h) => h.value);

  // ------------------------------------------------------------ message --
  const fromList = mailboxes(email.from);
  const from = fromList[0];
  const to = mailboxes(email.to);
  const cc = mailboxes(email.cc);
  const text = email.text ?? "";
  const html = email.html ?? "";
  const bodyText = text || htmlToText(html);
  const fromDomain = domainOf(from?.address);

  const recipientDomains = [
    ...new Set(
      [...to, ...cc].map((m) => domainOf(m.address)).concat(domainOf(email.deliveredTo))
        .filter((d): d is string => !!d)
        .map(orgDomain),
    ),
  ];
  const protectedDomains = [...new Set([...(options.protectedDomains ?? []).map((d) => orgDomain(normaliseDomain(d))), ...recipientDomains])];
  const isInternal = !!fromDomain && protectedDomains.some((d) => sameOrg(d, fromDomain));
  const isFreemail = !!fromDomain && FREEMAIL_DOMAINS.has(orgDomain(fromDomain));

  // ---------------------------------------------------------- identity --
  const replyTo = mailboxes(email.replyTo);
  const sender = mailboxes(email.sender)[0];
  const returnPath = email.returnPath?.replace(/^<|>$/g, "").toLowerCase();
  const msgIdDomain = domainOf(email.messageId?.replace(/^<|>$/g, ""));
  const rows: IdentityRow[] = [];
  const row = (field: IdentityRow["field"], value: string, domain: string | undefined) => {
    rows.push({
      field,
      value,
      domain,
      orgDomain: domain ? orgDomain(domain) : undefined,
      differsFromFrom: domain && fromDomain && field !== "From" && field !== "To" && field !== "Delivered-To" ? !sameOrg(domain, fromDomain) : undefined,
    });
  };
  for (const m of fromList) row("From", m.name ? `${m.name} <${m.address}>` : m.address, domainOf(m.address));
  if (sender) row("Sender", sender.name ? `${sender.name} <${sender.address}>` : sender.address, domainOf(sender.address));
  for (const m of replyTo) row("Reply-To", m.name ? `${m.name} <${m.address}>` : m.address, domainOf(m.address));
  if (returnPath) row("Return-Path", returnPath, domainOf(returnPath));
  if (email.messageId) row("Message-ID", email.messageId, msgIdDomain);
  for (const m of to) row("To", m.name ? `${m.name} <${m.address}>` : m.address, domainOf(m.address));
  if (email.deliveredTo) row("Delivered-To", email.deliveredTo, domainOf(email.deliveredTo));
  const identity: IdentityResult = { from, fromCount: fromList.length, rows };

  // -------------------------------------------------------------- auth --
  const auth = analyzeAuth(headers, from?.address);
  const verdictOf = (m: string) => auth.summary.find((s) => s.method === m);
  const spf = verdictOf("spf")!;
  const dkim = verdictOf("dkim")!;
  const dmarc = verdictOf("dmarc")!;
  const arcV = verdictOf("arc")!;

  if (!auth.headers.some((h) => h.source === "Authentication-Results")) {
    add("auth.missing", "authentication", 5, "No Authentication-Results", "The receiving server recorded no SPF, DKIM or DMARC results, so the sender cannot be confirmed.");
  }
  if (dmarc.verdict === "fail") {
    add("auth.dmarc.fail", "authentication", 30, "DMARC failed", dmarc.explanation);
  } else if (dmarc.verdict === "none") {
    add("auth.dmarc.none", "authentication", 8, "No DMARC policy for the From domain", dmarc.explanation);
  } else if (dmarc.verdict === "pass") {
    if (isFreemail) {
      add("auth.dmarc.pass-freemail", "authentication", 0, "DMARC passed for a freemail domain", `${fromDomain} is a consumer mailbox provider. The pass proves the provider sent it; anyone can open an account there.`);
    } else {
      add("auth.dmarc.pass", "authentication", -15, "DMARC passed", dmarc.explanation);
    }
  }
  if (spf.verdict === "fail") add("auth.spf.fail", "authentication", 15, "SPF failed", spf.explanation);
  else if (spf.verdict === "softfail") add("auth.spf.softfail", "authentication", 8, "SPF soft-failed", spf.explanation);
  else if (spf.verdict === "permerror" || spf.verdict === "temperror") add("auth.spf.error", "authentication", 4, `SPF ${spf.verdict}`, spf.explanation);
  if (dkim.verdict === "fail") add("auth.dkim.fail", "authentication", 12, "DKIM signature failed", dkim.explanation);
  else if (dkim.verdict === "none") add("auth.dkim.none", "authentication", 4, "No DKIM signature", dkim.explanation);
  if (arcV.verdict === "fail") add("auth.arc.fail", "authentication", 5, "ARC chain broken", arcV.explanation);
  const compauth = auth.headers.flatMap((h) => (h.source === "Authentication-Results" ? h.results : [])).find((r) => r.method === "compauth");
  if (compauth && compauth.result === "fail") {
    add("auth.compauth.fail", "authentication", 10, "Microsoft composite authentication failed", `compauth=fail${compauth.reason ? ` reason=${compauth.reason}` : ""}: Microsoft 365 judged the From address unverified.`);
  }

  // ------------------------------------------------------ identity signals --
  if (fromList.length > 1) add("identity.multiple-from", "identity", 15, "More than one From address", `The From header lists ${fromList.length} mailboxes; clients show only one.`);
  if (!from) add("identity.no-from", "identity", 10, "No From address", "The message has no parseable From address.");

  const rtDiff = replyTo.filter((m) => fromDomain && domainOf(m.address) && !sameOrg(domainOf(m.address), fromDomain));
  if (rtDiff.length) {
    const rt = rtDiff[0]!.address;
    const free = FREEMAIL_DOMAINS.has(orgDomain(domainOf(rt)!));
    add(
      "identity.replyto-mismatch",
      "identity",
      free ? 20 : 15,
      "Reply-To goes to a different domain",
      `Replies go to ${rt}, not to ${fromDomain}${free ? " — a consumer mailbox" : ""}. A reply would bypass the claimed sender entirely.`,
    );
  }
  if (returnPath && fromDomain && domainOf(returnPath) && !sameOrg(domainOf(returnPath), fromDomain)) {
    const ok = dmarc.verdict === "pass";
    add(
      "identity.returnpath-mismatch",
      "identity",
      ok ? 0 : 5,
      "Envelope sender differs from From",
      `Return-Path is ${returnPath}, From is ${fromDomain}. ` +
        (ok ? "Common for newsletters sent through a mailing service, and DMARC passed." : "Without a DMARC pass, nothing links the two."),
    );
  }
  if (sender && fromDomain && domainOf(sender.address) && !sameOrg(domainOf(sender.address), fromDomain)) {
    add("identity.sender-mismatch", "identity", 5, "Sender header differs from From", `Sender is ${sender.address}; some clients show "on behalf of".`);
  }
  if (msgIdDomain && fromDomain && !sameOrg(msgIdDomain, fromDomain) && !isFreemail) {
    add("identity.messageid-mismatch", "identity", 0, "Message-ID from another domain", `Message-ID was generated at ${msgIdDomain}. Normal for mailing services; worth noting alongside other signals.`);
  }
  if (!email.messageId) add("structure.no-message-id", "structure", 3, "No Message-ID", "Every mail server adds one; its absence suggests a hand-built message.");
  if (!email.date) add("structure.no-date", "structure", 3, "No Date header", "The message carries no Date header.");

  if (from?.name) {
    const name = from.name;
    const emailInName = /[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i.exec(name);
    if (emailInName && emailInName[0].toLowerCase() !== from.address) {
      const claimed = emailInName[1]!.toLowerCase();
      const internal = protectedDomains.some((d) => sameOrg(d, claimed));
      add(
        "identity.displayname-email",
        "identity",
        internal ? 30 : 20,
        "Display name shows a different address",
        `The display name reads "${name}" but the message came from ${from.address}. Most mail apps show only the name, so the reader sees ${emailInName[0]}.`,
      );
    } else {
      const brand = recipientDomains.map(registrableLabel).find((l) => l.length >= 4 && new RegExp(`\\b${l}\\b`, "i").test(name));
      if (brand && !isInternal) {
        add("identity.displayname-brand", "identity", 15, "Display name uses your organisation's name", `"${name}" names ${brand}, but the address is ${from.address}, outside ${recipientDomains.join(", ")}.`);
      }
    }
    if (!isInternal && EXEC_TITLE.test(name)) {
      add("identity.exec-title", "identity", 10, "Executive title from outside the organisation", `"${name}" claims a senior title from ${fromDomain}.`);
    } else if (!isInternal && ROLE_TITLE.test(name)) {
      add("identity.role-title", "identity", 8, "Internal department name from outside", `"${name}" reads like an internal team, sent from ${fromDomain}.`);
    }
  }
  if (isFreemail && !signals.some((s) => s.id === "identity.displayname-email")) {
    add("identity.freemail", "identity", 3, "Sent from a consumer mailbox", `${fromDomain} is a freemail provider.`);
  }

  // ---------------------------------------------------------- lookalikes --
  const lookalikes: LookalikeFinding[] = [];
  const noteLookalike = (domain: string | undefined, where: string, refs: string[]) => {
    if (!domain) return;
    for (const ref of refs) {
      const m = compareDomains(domain, ref);
      if (!m) continue;
      const existing = lookalikes.find((l) => l.domain === domain && l.resembles === ref);
      if (existing) {
        if (!existing.where.includes(where)) existing.where.push(where);
      } else {
        lookalikes.push({ domain, unicode: m.unicode, resembles: ref, techniques: m.techniques, distance: m.distance, where: [where] });
      }
      return;
    }
  };
  noteLookalike(fromDomain, "From", protectedDomains);
  for (const m of replyTo) noteLookalike(domainOf(m.address), "Reply-To", protectedDomains);
  noteLookalike(domainOf(returnPath), "Return-Path", protectedDomains);
  const linkRefs = [...new Set([...protectedDomains, ...(fromDomain && !isFreemail ? [orgDomain(fromDomain)] : [])])];

  if (fromDomain && hasPunycode(fromDomain)) {
    add("lookalike.from-punycode", "lookalike", 15, "From domain is internationalised (punycode)", `${fromDomain} displays as ${toUnicode(fromDomain)}.`);
  }

  // ---------------------------------------------------------------- links --
  const recipientsForUrl = [...to, ...cc].map((m) => m.address).filter(Boolean);
  let links: LinkInfo[] = dedupeLinks(collectLinks(html, text).map((l) => analyzeLink(l, { fromDomain, recipients: recipientsForUrl })));

  // --------------------------------------------------------- attachments --
  const attachments: AttachmentInfo[] = [];
  const qrCandidates: { label: string; bytes: Uint8Array; mime: string }[] = [];
  for (const [i, a] of email.attachments.entries()) {
    const bytes = toBytes(a.content);
    const filename = a.filename ?? `attachment-${i + 1}${a.mimeType.startsWith("image/") ? "." + a.mimeType.split("/")[1] : ""}`;
    const sniffed = sniff(bytes);
    const flags = attachmentFlags(filename, sniffed, a.mimeType);
    let indicators: string[] | undefined;
    const fam = sniffed?.family;
    if (fam === "html" || fam === "svg" || ["html", "htm", "shtml", "svg", "xhtml"].includes(extensionOf(filename))) {
      const body = new TextDecoder().decode(bytes);
      indicators = smugglingIndicators(body);
      if (indicators.length >= 3) flags.push("html-smuggling");
      if (hasCredentialForm(body)) flags.push("credential-form");
      // Links inside an HTML attachment matter as much as links in the body.
      for (const l of collectLinks(body, undefined)) links.push(analyzeLink({ ...l, source: "attachment" }, { fromDomain, recipients: recipientsForUrl }));
    }
    const sha256 = await sha256Hex(bytes);
    attachments.push({
      filename,
      declaredType: a.mimeType,
      sniffedType: sniffed?.type,
      sniffedLabel: sniffed?.label,
      size: bytes.length,
      sha256,
      disposition: a.disposition,
      contentId: a.contentId,
      inline: a.disposition === "inline" || !!a.related,
      flags,
      smugglingIndicators: indicators?.length ? indicators : undefined,
      virusTotalUrl: `https://www.virustotal.com/gui/file/${sha256}`,
    });
    const imageType = sniffed?.family === "image" ? sniffed.type : a.mimeType;
    if (QR_IMAGE_TYPES.test(imageType)) qrCandidates.push({ label: filename, bytes, mime: imageType });
  }
  // Images embedded straight into the HTML as data: URIs.
  extractImages(html)
    .filter((img) => /^data:image\/[a-z+]+;base64,/i.test(img.src))
    .forEach((img, n) => {
      const [, mime, b64] = /^data:(image\/[a-z+]+);base64,(.*)$/is.exec(img.src) ?? [];
      if (!mime || !b64 || !QR_IMAGE_TYPES.test(mime)) return;
      try {
        qrCandidates.push({ label: `data: URI image #${n + 1}`, bytes: base64ToBytes(b64), mime });
      } catch {
        notes.push(`data: URI image #${n + 1} is not valid base64.`);
      }
    });

  // ------------------------------------------------------------------- QR --
  const qr: QrFinding[] = [];
  if (!options.skipQr && qrCandidates.length) {
    const decoder = options.decodeImage ?? browserImageDecoder;
    for (const c of qrCandidates) {
      try {
        const img = await decoder(c.bytes, c.mime);
        if (!img) {
          notes.push(`QR decoding is unavailable in this environment; ${c.label} was not scanned.`);
          continue;
        }
        const data = decodeQr(img);
        if (data) qr.push({ image: c.label, data, isUrl: /^(https?:\/\/|www\.)/i.test(data.trim()) });
      } catch {
        notes.push(`${c.label} could not be decoded as an image.`);
      }
    }
  }
  for (const q of qr) {
    if (q.isUrl) links.push(analyzeLink({ href: q.data.trim(), source: "qr" }, { fromDomain, recipients: recipientsForUrl }));
  }
  links = dedupeLinks(links);

  // Lookalikes in link and QR destinations.
  for (const l of links) {
    if (!l.host) continue;
    noteLookalike(l.host, l.source === "qr" ? "QR code" : "link", linkRefs);
    if (lookalikes.some((x) => x.domain === l.host) && !l.flags.includes("lookalike")) l.flags.push("lookalike");
    if (l.redirectTarget) {
      const target = (() => {
        try {
          return normaliseDomain(new URL(/^\/\//.test(l.redirectTarget!) ? `https:${l.redirectTarget}` : l.redirectTarget!).hostname);
        } catch {
          return undefined;
        }
      })();
      noteLookalike(target, "redirect target", linkRefs);
    }
  }

  // --------------------------------------------------------- link signals --
  const withFlag = (f: LinkInfo["flags"][number]) => links.filter((l) => l.flags.includes(f));
  const list = (ls: LinkInfo[], n = 3) => ls.slice(0, n).map((l) => defang(l.href)).join(", ") + (ls.length > n ? ` and ${ls.length - n} more` : "");

  const mismatch = withFlag("text-href-mismatch");
  if (mismatch.length) {
    const l = mismatch[0]!;
    add("links.text-href-mismatch", "links", 25, "Link text shows one address, the link goes to another", `Text "${l.text}" points to ${defang(l.href)}${mismatch.length > 1 ? ` (${mismatch.length} links like this)` : ""}.`);
  }
  if (withFlag("shortener").length) add("links.shortener", "links", 8, "URL shortener", `The real destination is hidden behind ${list(withFlag("shortener"))}.`);
  if (withFlag("redirector").length) {
    const r = withFlag("redirector");
    add("links.redirector", "links", 8, "Redirecting link", `${list(r, 2)}${r[0]?.redirectTarget ? ` forwards to ${defang(r[0].redirectTarget)}` : ""}.`);
  }
  if (withFlag("ip-host").length) add("links.ip-host", "links", 15, "Link to a bare IP address", list(withFlag("ip-host")));
  if (withFlag("punycode").length) add("links.punycode", "links", 10, "Internationalised (punycode) link domain", withFlag("punycode").map((l) => `${l.host} shows as ${toUnicode(l.host!)}`).join("; "));
  if (withFlag("recipient-in-url").length) add("links.recipient-in-url", "links", 8, "Your address is baked into a link", `Pre-filled login pages are a phishing-kit habit: ${list(withFlag("recipient-in-url"), 2)}.`);
  const credExternal = withFlag("credential-path").filter((l) => l.host && !(fromDomain && sameOrg(l.host, fromDomain)) && !protectedDomains.some((d) => sameOrg(d, l.host)));
  if (credExternal.length) add("links.credential-path", "links", 6, "Login-style link to an outside domain", list(credExternal, 2));
  if (withFlag("form-action").length) add("links.form", "links", 15, "Form that submits somewhere", `A form posts to ${list(withFlag("form-action"), 2)}.`);
  if (withFlag("javascript-uri").length || withFlag("data-uri").length) add("links.script-uri", "links", 15, "javascript: or data: link", "Links that run code or carry an inline document instead of opening a page.");
  if (withFlag("non-https").length) add("links.non-https", "links", 0, "Unencrypted http:// links", list(withFlag("non-https"), 2));

  for (const lk of lookalikes) {
    const how = lk.techniques.join(", ");
    const shown = lk.unicode ? ` (displays as ${lk.unicode})` : "";
    for (const where of lk.where) {
      const id = `lookalike.${where.toLowerCase().replace(/[^a-z]+/g, "-")}`;
      const weight = where === "From" ? 35 : where === "link" || where === "QR code" || where === "redirect target" ? 25 : 20;
      add(id, "lookalike", weight, `${where} domain imitates ${lk.resembles}`, `${lk.domain}${shown} resembles ${lk.resembles}: ${how}${lk.distance ? `, ${lk.distance} edit${lk.distance > 1 ? "s" : ""} away` : ""}.`);
    }
  }

  // --------------------------------------------------- attachment signals --
  const byFlag = (f: AttachmentInfo["flags"][number]) => attachments.filter((a) => a.flags.includes(f));
  const names = (as: AttachmentInfo[]) => as.map((a) => a.filename).join(", ");
  if (byFlag("html-smuggling").length) {
    const a = byFlag("html-smuggling")[0]!;
    add("attachments.html-smuggling", "attachments", 40, "HTML smuggling pattern", `${a.filename} assembles a file inside the browser: ${a.smugglingIndicators!.join("; ")}.`);
  }
  if (byFlag("type-mismatch").length) {
    add("attachments.type-mismatch", "attachments", 25, "File is not what its name says", byFlag("type-mismatch").map((a) => `${a.filename} is declared ${a.declaredType} but the bytes are ${a.sniffedLabel ?? "something else"}`).join("; ") + ".");
  }
  if (byFlag("rtlo").length) add("attachments.rtlo", "attachments", 30, "Right-to-left override in a filename", `${names(byFlag("rtlo"))} uses a Unicode control character to reverse how the extension reads.`);
  if (byFlag("double-extension").length) add("attachments.double-extension", "attachments", 20, "Double file extension", `${names(byFlag("double-extension"))} hides its real type behind a familiar one.`);
  if (byFlag("executable").length) add("attachments.executable", "attachments", 30, "Executable or script attachment", names(byFlag("executable")));
  if (byFlag("disk-image").length) add("attachments.disk-image", "attachments", 20, "Disk image attachment", `${names(byFlag("disk-image"))}: disk images unpack files without Mark-of-the-Web on older Windows.`);
  if (byFlag("macro-container").length) add("attachments.macro", "attachments", 20, "Macro-enabled Office file", names(byFlag("macro-container")));
  if (byFlag("credential-form").length) add("attachments.credential-form", "attachments", 25, "Attachment contains a password form", `${names(byFlag("credential-form"))} renders a login form offline.`);
  const risky = byFlag("risky-extension").filter((a) => !a.flags.includes("executable"));
  if (risky.length) add("attachments.risky-extension", "attachments", 15, "Attachment type often used in phishing", names(risky));

  // ------------------------------------------------------------ QR signals --
  const qrUrls = qr.filter((q) => q.isUrl);
  if (qrUrls.length) {
    add("qr.url", "qr", 25, "QR code with a link", `${qrUrls[0]!.image} decodes to ${defang(qrUrls[0]!.data)}. A phone camera opens it outside the mail filter and off the managed device.`);
  } else if (qr.length) {
    add("qr.data", "qr", 5, "QR code in an image", `${qr[0]!.image} decodes to "${qr[0]!.data.slice(0, 120)}".`);
  }

  // ------------------------------------------------------------- content --
  const cues = contentCues(`${email.subject ?? ""}\n${bodyText}`);
  for (const c of cues) add(`content.${c.id}`, "content", 6, c.label, `Phrases: ${c.matches.map((m) => `"${m}"`).join(", ")}.`);
  if (headerValues("list-unsubscribe").length && dmarc.verdict === "pass" && !isFreemail) {
    add("content.list-unsubscribe", "content", -5, "Authenticated bulk mail", "Carries a List-Unsubscribe header and passed DMARC, the shape of a legitimate mailing.");
  }

  // ---------------------------------------------------------------- route --
  const route = analyzeRoute(headerValues("received"), email.date ? headerValues("date")[0] : undefined);
  const slow = route.hops.filter((h) => (h.delaySeconds ?? 0) > 3600);
  if (slow.length) {
    add("route.delay", "route", 0, "Long delay between hops", slow.map((h) => `hop ${h.index} (${h.by ?? "?"}) after ${formatDuration(h.delaySeconds!)}`).join("; ") + ". Queued, greylisted or held for scanning.");
  }
  const skew = route.hops.filter((h) => (h.delaySeconds ?? 0) < -60);
  if (skew.length) add("route.clock-skew", "route", 0, "Hop timestamps run backwards", `Hop ${skew.map((h) => h.index).join(", ")}: a relay clock is wrong or a header was inserted.`);
  if (route.dateToFirstHopSeconds !== undefined && Math.abs(route.dateToFirstHopSeconds) > 86400) {
    add("route.date-mismatch", "route", 3, "Date header far from delivery", `The Date header is ${formatDuration(route.dateToFirstHopSeconds)} away from the first Received timestamp.`);
  }
  if (!route.hops.length) add("route.none", "route", 0, "No Received headers", "Pasted headers only, or the message never crossed a mail server.");

  // ---------------------------------------------------------------- score --
  const raw = signals.reduce((sum, s) => sum + s.weight, 0);
  const score = Math.max(0, Math.min(100, raw));
  signals.sort((a, b) => b.weight - a.weight);

  return {
    analyzer: ANALYZER_VERSION,
    analyzedAt: (options.now ?? new Date()).toISOString(),
    message: {
      subject: email.subject,
      date: parseMailDate(headerValues("date")[0])?.toISOString() ?? email.date,
      messageId: email.messageId,
      from,
      to,
      cc,
      hasHtml: !!html,
      hasText: !!text,
      textPreview: bodyText.slice(0, 600),
    },
    headers,
    route,
    auth,
    identity,
    lookalikes,
    links,
    attachments,
    qr,
    notes,
    signals,
    score,
    band: bandFor(score),
  };
}
