/**
 * Small, DOM-free HTML readers. The analyzer never renders message HTML; it only reads
 * attributes and text out of it, so a tolerant regex pass is enough and works the same in
 * the browser, in a worker and under Node.
 */

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—",
  hellip: "…", copy: "©", reg: "®", trade: "™", rsquo: "’", lsquo: "‘", rdquo: "”",
  ldquo: "“", bull: "•", middot: "·", zwnj: "‌", zwj: "‍", shy: "­",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, body: string) => {
    if (body[0] === "#") {
      const cp = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? m;
  });
}

/** Visible text of an HTML fragment, whitespace collapsed. */
export function htmlToText(html: string): string {
  return decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|head|title)\b[\s\S]*?<\/\1\s*>/gi, " ")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/(p|div|tr|li|h[1-6]|table)\s*>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t ]+/g, " ")
    .replace(/\s*\n\s*/g, "\n")
    .trim();
}

function attr(tag: string, name: string): string | undefined {
  const re = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const m = re.exec(tag);
  if (!m) return undefined;
  return decodeEntities((m[1] ?? m[2] ?? m[3] ?? "").trim());
}

export type HtmlLink = {
  href: string;
  text?: string;
  kind: "a" | "area" | "form" | "meta-refresh" | "img";
};

export function extractHtmlLinks(html: string): HtmlLink[] {
  const out: HtmlLink[] = [];
  const clean = html.replace(/<!--[\s\S]*?-->/g, " ");

  const anchor = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  for (let m; (m = anchor.exec(clean)); ) {
    const href = attr(m[1] ?? "", "href");
    if (!href) continue;
    const text = htmlToText(m[2] ?? "").replace(/\s+/g, " ").trim();
    out.push({ href, text: text || undefined, kind: "a" });
  }

  for (const [re, name, kind] of [
    [/<area\b([^>]*)>/gi, "href", "area"],
    [/<form\b([^>]*)>/gi, "action", "form"],
  ] as const) {
    for (let m; (m = re.exec(clean)); ) {
      const href = attr(m[1] ?? "", name);
      if (href) out.push({ href, kind });
    }
  }

  const meta = /<meta\b([^>]*)>/gi;
  for (let m; (m = meta.exec(clean)); ) {
    const tag = m[1] ?? "";
    if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
    const content = attr(tag, "content") ?? "";
    const u = /url\s*=\s*['"]?([^'";]+)/i.exec(content);
    if (u?.[1]) out.push({ href: u[1].trim(), kind: "meta-refresh" });
  }
  return out;
}

export type HtmlImage = { src: string; alt?: string };

export function extractImages(html: string): HtmlImage[] {
  const out: HtmlImage[] = [];
  const re = /<img\b([^>]*)>/gi;
  for (let m; (m = re.exec(html)); ) {
    const src = attr(m[1] ?? "", "src");
    if (src) out.push({ src, alt: attr(m[1] ?? "", "alt") });
  }
  return out;
}
