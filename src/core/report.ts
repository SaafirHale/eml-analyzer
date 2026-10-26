import { BAND_LABEL } from "./analyze.js";
import { formatDuration } from "./received.js";
import type { AnalysisResult } from "./types.js";
import { defang } from "./urls.js";

export function toJSON(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

const cell = (s: string | number | undefined) => String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

function table(head: string[], rows: (string | number | undefined)[][]): string {
  if (!rows.length) return "_None._\n";
  return [
    `| ${head.join(" | ")} |`,
    `| ${head.map(() => "---").join(" | ")} |`,
    ...rows.map((r) => `| ${r.map(cell).join(" | ")} |`),
  ].join("\n") + "\n";
}

/**
 * A Markdown report for a ticket or case note. Every URL is defanged so the report can be
 * pasted anywhere without creating live links.
 */
export function toMarkdown(result: AnalysisResult): string {
  const m = result.message;
  const out: string[] = [];
  out.push(`# Email analysis: ${m.subject ? cell(m.subject) : "(no subject)"}`);
  out.push("");
  out.push(`**Verdict:** ${BAND_LABEL[result.band]} — score ${result.score}/100`);
  out.push("");
  out.push(`- From: ${m.from ? `${m.from.name ? `${m.from.name} ` : ""}<${m.from.address}>` : "(none)"}`);
  out.push(`- To: ${m.to.map((t) => t.address).join(", ") || "(none)"}`);
  out.push(`- Date: ${m.date ?? "(none)"}`);
  out.push(`- Message-ID: ${m.messageId ?? "(none)"}`);
  out.push(`- Analysed: ${result.analyzedAt} by ${result.analyzer}, locally in the browser`);
  out.push("");

  out.push("## Signals");
  out.push("");
  out.push(table(["Weight", "Severity", "Signal", "Detail"], result.signals.map((s) => [s.weight > 0 ? `+${s.weight}` : s.weight, s.severity, s.title, defangText(s.detail)])));

  out.push("## Authentication");
  out.push("");
  out.push(table(["Check", "Result", "Domain", "Aligned", "Meaning"], result.auth.summary.map((a) => [a.method.toUpperCase(), a.verdict, a.domain, a.aligned === undefined ? "" : a.aligned ? "yes" : "no", a.explanation])));

  out.push("## Identity");
  out.push("");
  out.push(table(["Field", "Value", "Org domain", "Differs from From"], result.identity.rows.map((r) => [r.field, r.value, r.orgDomain, r.differsFromFrom === undefined ? "" : r.differsFromFrom ? "yes" : "no"])));

  out.push("## Route");
  out.push("");
  out.push(table(["#", "From", "IP", "By", "With", "Time (UTC)", "Delay"], result.route.hops.map((h) => [h.index, h.fromRdns ?? h.from, h.fromIp, h.by, h.with, h.date, h.delaySeconds === undefined ? "" : formatDuration(h.delaySeconds)])));

  if (result.lookalikes.length) {
    out.push("## Lookalike domains");
    out.push("");
    out.push(table(["Domain", "Displays as", "Resembles", "Technique", "Seen in"], result.lookalikes.map((l) => [defang(l.domain), l.unicode, l.resembles, l.techniques.join(", "), l.where.join(", ")])));
  }

  out.push("## Links");
  out.push("");
  out.push(table(["Destination (defanged)", "Shown text", "Source", "Flags"], result.links.map((l) => [l.defanged, l.text ? defangText(l.text) : "", l.source, l.flags.join(", ")])));

  out.push("## Attachments");
  out.push("");
  out.push(table(["File", "Declared", "Actual", "Size", "SHA-256", "Flags"], result.attachments.map((a) => [a.filename, a.declaredType, a.sniffedLabel, a.size, a.sha256, a.flags.join(", ")])));
  if (result.attachments.length) {
    out.push("Look up a hash on VirusTotal at `virustotal[.]com/gui/file/<sha256>`.");
    out.push("");
  }

  if (result.qr.length) {
    out.push("## QR codes");
    out.push("");
    out.push(table(["Image", "Decoded"], result.qr.map((q) => [q.image, q.isUrl ? defang(q.data) : q.data])));
  }

  if (result.notes.length) {
    out.push("## Notes");
    out.push("");
    for (const n of result.notes) out.push(`- ${n}`);
    out.push("");
  }
  return out.join("\n");
}

/** Defang URLs that appear inside free text (signal details). */
function defangText(s: string): string {
  if (/^www\./i.test(s.trim())) return defang(s);
  return s.replace(/\bhttps?:\/\/[^\s"')]+/gi, (u) => defang(u));
}
