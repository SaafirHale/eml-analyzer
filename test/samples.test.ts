import { describe, expect, it } from "vitest";
import { toJSON, toMarkdown } from "../src/core/index.js";
import { analyzeSample, ids } from "./helpers.js";

describe("01 clean newsletter", async () => {
  const r = await analyzeSample("01-clean-newsletter.eml");

  it("scores low", () => {
    expect(r.band).toBe("low");
    expect(r.score).toBeLessThan(20);
  });

  it("reads SPF, DKIM, DMARC and ARC as passing", () => {
    const v = Object.fromEntries(r.auth.summary.map((s) => [s.method, s.verdict]));
    expect(v).toEqual({ spf: "pass", dkim: "pass", dmarc: "pass", arc: "pass" });
    const dkim = r.auth.summary.find((s) => s.method === "dkim")!;
    expect(dkim.domain).toBe("fieldnotes.example");
    expect(dkim.aligned).toBe(true);
    const spf = r.auth.summary.find((s) => s.method === "spf")!;
    expect(spf.aligned).toBe(false);
    expect(spf.explanation).toMatch(/not the From domain/);
  });

  it("parses the ARC set", () => {
    expect(r.auth.arc).toHaveLength(1);
    expect(r.auth.arc[0]).toMatchObject({ instance: 1, cv: "none", sealDomain: "example.com" });
    expect(r.auth.arc[0]!.authResults?.authservId).toBe("relay.example.com");
  });

  it("orders hops oldest first with delays", () => {
    expect(r.route.hops.map((h) => h.by)).toEqual(["mta7.esp-mailer.example", "relay.example.com", "mbx01.example.com"]);
    expect(r.route.hops[0]).toMatchObject({ fromIp: "10.20.4.14" });
    expect(r.route.hops[1]).toMatchObject({ fromIp: "198.51.100.27", fromRdns: "mta7.esp-mailer.example", delaySeconds: 7 });
    expect(r.route.totalSeconds).toBe(9);
  });

  it("treats the ESP envelope sender as informational", () => {
    const rp = r.signals.find((s) => s.id === "identity.returnpath-mismatch");
    expect(rp?.weight).toBe(0);
  });

  it("finds the links without flagging them", () => {
    expect(r.links.length).toBeGreaterThanOrEqual(4);
    expect(r.links.every((l) => !l.flags.includes("text-href-mismatch") && !l.flags.includes("lookalike"))).toBe(true);
    expect(r.lookalikes).toEqual([]);
  });

  it("hashes the inline logo and finds no QR code in it", () => {
    expect(r.attachments).toHaveLength(1);
    expect(r.attachments[0]).toMatchObject({ filename: "logo.png", sniffedType: "image/png", inline: true, flags: [] });
    expect(r.attachments[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.qr).toEqual([]);
  });
});

describe("02 spoofed CEO BEC", async () => {
  const r = await analyzeSample("02-ceo-bec.eml");

  it("scores as likely phishing", () => {
    expect(r.band).toBe("high");
  });

  it("catches the address hidden in the display name", () => {
    const s = r.signals.find((x) => x.id === "identity.displayname-email")!;
    expect(s.weight).toBe(30);
    expect(s.detail).toContain("dana.whitfield@example.com");
  });

  it("flags the Reply-To that leaves the sender's domain", () => {
    expect(ids(r)).toContain("identity.replyto-mismatch");
    const rt = r.identity.rows.find((x) => x.field === "Reply-To")!;
    expect(rt.differsFromFrom).toBe(true);
  });

  it("does not give credit for DMARC passing at a freemail provider", () => {
    expect(ids(r)).toContain("auth.dmarc.pass-freemail");
    expect(ids(r)).not.toContain("auth.dmarc.pass");
  });

  it("notes the payment and pressure language", () => {
    expect(ids(r)).toEqual(expect.arrayContaining(["content.payment", "content.urgency"]));
  });

  it("converts the -0400 Date header to UTC and lines it up with the first hop", () => {
    expect(r.message.date).toBe("2026-10-20T12:41:12.000Z");
    expect(r.route.dateToFirstHopSeconds).toBe(2);
  });
});

describe("03 credential phish with lookalike domain", async () => {
  const r = await analyzeSample("03-credential-phish-lookalike.eml");

  it("scores as likely phishing", () => {
    expect(r.band).toBe("high");
    expect(r.score).toBe(100);
  });

  it("parses the Microsoft-style Authentication-Results with no authserv-id", () => {
    const v = Object.fromEntries(r.auth.summary.map((s) => [s.method, s.verdict]));
    expect(v.spf).toBe("softfail");
    expect(v.dkim).toBe("none");
    expect(v.dmarc).toBe("none");
    expect(ids(r)).toContain("auth.compauth.fail");
  });

  it("identifies the From domain as a homoglyph of the recipient's domain", () => {
    const f = r.lookalikes.find((l) => l.domain === "examp1e.test")!;
    expect(f.resembles).toBe("example.com");
    expect(f.techniques).toContain("homoglyph");
    expect(f.where).toEqual(expect.arrayContaining(["From", "link"]));
    expect(ids(r)).toContain("lookalike.from");
  });

  it("decodes the punycode link domain", () => {
    const p = r.lookalikes.find((l) => l.domain.startsWith("xn--"))!;
    expect(p.unicode).toBe("exämple.test");
    expect(p.techniques).toEqual(expect.arrayContaining(["homoglyph", "punycode"]));
  });

  it("catches link text that shows a different URL", () => {
    const l = r.links.find((x) => x.flags.includes("text-href-mismatch"))!;
    expect(l.text).toBe("https://login.example.com/password/keep");
    expect(l.host).toBe("examp1e.test");
    expect(l.flags).toEqual(expect.arrayContaining(["recipient-in-url", "credential-path", "lookalike"]));
    expect(l.defanged).toMatch(/^hxxps:\/\/examp1e\[\.\]test\//);
  });

  it("unwraps the redirector and checks where it goes", () => {
    const l = r.links.find((x) => x.flags.includes("redirector"))!;
    expect(l.redirectTarget).toBe("https://example.com.account-verify.test/reset");
    const t = r.lookalikes.find((x) => x.domain === "example.com.account-verify.test")!;
    expect(t.techniques).toContain("combosquat");
    expect(t.where).toContain("redirect target");
  });

  it("flags the hour-and-a-half hold between relays as information", () => {
    const d = r.signals.find((s) => s.id === "route.delay")!;
    expect(d.weight).toBe(0);
    expect(r.route.hops[1]!.delaySeconds).toBe(5381);
  });
});

describe("04 HTML smuggling attachment", async () => {
  const r = await analyzeSample("04-html-smuggling.eml");

  it("scores as likely phishing despite passing authentication", () => {
    expect(r.auth.summary.find((s) => s.method === "dmarc")!.verdict).toBe("pass");
    expect(r.band).toBe("high");
  });

  it("detects the smuggling script", () => {
    const a = r.attachments.find((x) => x.filename.endsWith(".html"))!;
    expect(a.sniffedType).toBe("text/html");
    expect(a.flags).toEqual(expect.arrayContaining(["html-smuggling", "risky-extension"]));
    expect(a.smugglingIndicators).toEqual(expect.arrayContaining(["atob() base64 decoding", "new Blob() built in the page", "URL.createObjectURL()"]));
    expect(ids(r)).toContain("attachments.html-smuggling");
  });

  it("sniffs the .pdf that is really a ZIP", () => {
    const a = r.attachments.find((x) => x.filename === "Statement_Oct2026.pdf")!;
    expect(a.declaredType).toBe("application/pdf");
    expect(a.sniffedType).toBe("application/zip");
    expect(a.flags).toContain("type-mismatch");
  });

  it("produces SHA-256 hashes and VirusTotal links", () => {
    for (const a of r.attachments) {
      expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(a.virusTotalUrl).toBe(`https://www.virustotal.com/gui/file/${a.sha256}`);
    }
  });
});

describe("05 QR phish", async () => {
  const r = await analyzeSample("05-qr-phish.eml");

  it("decodes the QR code in the inline image", () => {
    expect(r.qr).toEqual([
      { image: "mfa-enroll.png", data: "https://example-benefits.test/mfa/enroll?uid=jordan.lee%40example.com&t=8f31c2", isUrl: true },
    ]);
  });

  it("analyses the QR destination like any other link", () => {
    const l = r.links.find((x) => x.source === "qr")!;
    expect(l.host).toBe("example-benefits.test");
    expect(l.flags).toEqual(expect.arrayContaining(["lookalike", "recipient-in-url", "credential-path"]));
    expect(ids(r)).toEqual(expect.arrayContaining(["qr.url", "lookalike.qr-code"]));
  });

  it("scores as likely phishing", () => {
    expect(r.band).toBe("high");
  });

  it("notes that the body itself has no clickable links", () => {
    expect(r.links.filter((l) => l.source !== "qr")).toEqual([]);
  });
});

describe("reports", async () => {
  const r = await analyzeSample("03-credential-phish-lookalike.eml");

  it("round-trips JSON", () => {
    expect(JSON.parse(toJSON(r))).toEqual(JSON.parse(JSON.stringify(r)));
  });

  it("writes Markdown with every URL defanged", () => {
    const md = toMarkdown(r);
    expect(md).toContain("# Email analysis: Action required: your password expires today");
    expect(md).toContain("**Verdict:** Likely phishing");
    expect(md).toContain("hxxps://examp1e[.]test");
    expect(md).not.toMatch(/\bhttps?:\/\/(?!www\.virustotal)/);
  });
});
