import { describe, expect, it } from "vitest";
import {
  analyzeLink,
  attachmentFlags,
  compareDomains,
  defang,
  editDistance,
  extractTextUrls,
  formatDuration,
  orgDomain,
  parseAuthResults,
  parseReceived,
  punycodeDecodeLabel,
  skeleton,
  sniff,
  sha256Hex,
  smugglingIndicators,
  toUnicode,
} from "../src/core/index.js";
import { decodeEntities, extractHtmlLinks, htmlToText } from "../src/core/html.js";

describe("domains", () => {
  it("approximates the organisational domain", () => {
    expect(orgDomain("mail.news.example.com")).toBe("example.com");
    expect(orgDomain("shop.example.co.uk")).toBe("example.co.uk");
    expect(orgDomain("example.com")).toBe("example.com");
  });

  it("decodes punycode", () => {
    expect(punycodeDecodeLabel("exmple-cua")).toBe("exämple");
    expect(toUnicode("xn--exmple-cua.test")).toBe("exämple.test");
    expect(toUnicode("plain.example")).toBe("plain.example");
  });

  it("collapses confusable characters", () => {
    expect(skeleton("examp1e")).toBe("example");
    expect(skeleton("еxample")).toBe("example"); // Cyrillic е
    expect(skeleton("rnicrosoft")).toBe("microsoft");
    expect(skeleton("ExÄmple")).toBe("example");
  });

  it("measures edit distance with transpositions", () => {
    expect(editDistance("example", "exmaple")).toBe(1);
    expect(editDistance("example", "examples")).toBe(1);
    expect(editDistance("kitten", "sitting")).toBe(3);
  });

  it("classifies lookalike techniques", () => {
    expect(compareDomains("examp1e.com", "example.com")?.techniques).toEqual(["homoglyph"]);
    expect(compareDomains("exmaple.com", "example.com")?.techniques).toEqual(["edit-distance"]);
    expect(compareDomains("example.co", "example.com")?.techniques).toEqual(["tld-swap"]);
    expect(compareDomains("example-sso.test", "example.com")?.techniques).toEqual(["combosquat"]);
    expect(compareDomains("example.com.login.test", "example.com")?.techniques).toEqual(["combosquat"]);
    const cyr = compareDomains("xn--xample-2of.com", "example.com"); // еxample with Cyrillic е
    expect(cyr?.techniques).toEqual(expect.arrayContaining(["homoglyph", "punycode"]));
    expect(cyr?.unicode).toBe("еxample.com");
  });

  it("does not flag the same organisation or unrelated names", () => {
    expect(compareDomains("mail.example.com", "example.com")).toBeNull();
    expect(compareDomains("fieldnotes.example", "example.com")).toBeNull();
    expect(compareDomains("northwind-supply.test", "example.com")).toBeNull();
    expect(compareDomains("sample.com", "example.com")).toBeNull();
  });

  it("flags mixed-script labels", () => {
    const m = compareDomains("pаypal-example.test", "example.com"); // Cyrillic а in "paypal"
    expect(m?.techniques).toEqual(expect.arrayContaining(["combosquat", "mixed-script"]));
  });
});

describe("Authentication-Results", () => {
  it("parses a standard header with comments and properties", () => {
    const h = parseAuthResults(
      "mx.example.com; spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=a@example.net; dkim=fail reason=\"bad signature\" header.d=example.net header.s=s1; dmarc=fail (p=REJECT) header.from=example.net",
    );
    expect(h.authservId).toBe("mx.example.com");
    expect(h.results.map((r) => [r.method, r.result])).toEqual([["spf", "pass"], ["dkim", "fail"], ["dmarc", "fail"]]);
    expect(h.results[0]!.props["smtp.mailfrom"]).toBe("a@example.net");
    expect(h.results[0]!.comment).toBe("sender IP is 192.0.2.1");
    expect(h.results[1]!.reason).toBe("bad signature");
  });

  it("parses the Microsoft form with no authserv-id", () => {
    const h = parseAuthResults("spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.net; dkim=pass header.d=example.net;dmarc=pass action=none header.from=example.net;compauth=pass reason=100");
    expect(h.authservId).toBe("");
    expect(h.results.map((r) => r.method)).toEqual(["spf", "dkim", "dmarc", "compauth"]);
    expect(h.results[2]!.props.action).toBe("none");
    expect(h.results[3]!.reason).toBe("100");
  });

  it("reads the ARC instance", () => {
    const h = parseAuthResults("i=2; lists.example.org; dkim=pass header.d=example.net", "ARC-Authentication-Results");
    expect(h.instance).toBe(2);
    expect(h.authservId).toBe("lists.example.org");
  });
});

describe("Received", () => {
  it("pulls apart a Postfix-style hop", () => {
    const h = parseReceived("from mail.example.net (mail.example.net [203.0.113.5]) by mx.example.com (Postfix) with ESMTPS id 4XYZ for <a@example.com>; Mon, 26 Oct 2026 09:14:03 +0000 (UTC)");
    expect(h).toMatchObject({
      from: "mail.example.net",
      fromRdns: "mail.example.net",
      fromIp: "203.0.113.5",
      by: "mx.example.com",
      with: "ESMTPS",
      id: "4XYZ",
      for: "a@example.com",
      date: "2026-10-26T09:14:03.000Z",
    });
  });

  it("reads IPv6 and bare-paren addresses", () => {
    expect(parseReceived("from host.example (2001:db8::25) by mx.example.com with ESMTP; Mon, 26 Oct 2026 09:14:03 +0000").fromIp).toBe("2001:db8::25");
    expect(parseReceived("from [198.51.100.9] by mx.example.com; Mon, 26 Oct 2026 09:14:03 +0000").fromIp).toBe("198.51.100.9");
  });

  it("formats durations", () => {
    expect(formatDuration(7)).toBe("7s");
    expect(formatDuration(5381)).toBe("1h 29m");
    expect(formatDuration(-90)).toBe("-1m 30s");
  });
});

describe("links", () => {
  const ctx = { fromDomain: "example.net", recipients: ["a@example.com"] };

  it("defangs", () => {
    expect(defang("https://evil.example/a?b=c@d")).toBe("hxxps://evil[.]example/a?b=c[@]d");
  });

  it("extracts URLs from text without trailing punctuation", () => {
    expect(extractTextUrls("Go to https://example.com/a. Or (https://example.org/b), or www.example.net!")).toEqual([
      "https://example.com/a",
      "https://example.org/b",
      "www.example.net",
    ]);
  });

  it("flags shorteners, IP hosts and redirectors", () => {
    expect(analyzeLink({ href: "https://bit.ly/3xYz", source: "text" }, ctx).flags).toContain("shortener");
    expect(analyzeLink({ href: "http://192.0.2.44/login", source: "text" }, ctx).flags).toEqual(expect.arrayContaining(["ip-host", "non-https", "credential-path"]));
    const r = analyzeLink({ href: "https://www.google.com/url?q=https://example.org/x", source: "html" }, ctx);
    expect(r.flags).toContain("redirector");
    expect(r.redirectTarget).toBe("https://example.org/x");
    const b = analyzeLink({ href: "https://t.example/r?target=aHR0cHM6Ly9leGFtcGxlLm9yZy9w", source: "html" }, ctx);
    expect(b.redirectTarget).toBe("https://example.org/p");
  });

  it("compares displayed text with the real destination", () => {
    expect(analyzeLink({ href: "https://evil.test/x", text: "www.example.com", source: "html" }, ctx).flags).toContain("text-href-mismatch");
    expect(analyzeLink({ href: "https://www.example.com/x", text: "example.com", source: "html" }, ctx).flags).not.toContain("text-href-mismatch");
    expect(analyzeLink({ href: "https://evil.test/x", text: "Click here", source: "html" }, ctx).flags).not.toContain("text-href-mismatch");
  });
});

describe("HTML reading", () => {
  it("decodes entities", () => {
    expect(decodeEntities("a&amp;b &#x41;&#66; &lt;x&gt;")).toBe("a&b AB <x>");
  });

  it("extracts anchors, forms and meta refresh", () => {
    const links = extractHtmlLinks(
      `<a href="https://a.example/?x=1&amp;y=2"><b>Open</b> it</a><form action='https://b.example/post'></form><meta http-equiv="refresh" content="0; url=https://c.example/">`,
    );
    expect(links).toEqual([
      { href: "https://a.example/?x=1&y=2", text: "Open it", kind: "a" },
      { href: "https://b.example/post", kind: "form" },
      { href: "https://c.example/", kind: "meta-refresh" },
    ]);
  });

  it("drops script and style from visible text", () => {
    expect(htmlToText("<style>p{}</style><p>Hello</p><script>x()</script><p>there</p>")).toBe("Hello\nthere");
  });
});

describe("attachments", () => {
  const bytes = (s: string) => new TextEncoder().encode(s);

  it("sniffs by magic bytes", () => {
    expect(sniff(bytes("%PDF-1.7\n"))?.type).toBe("application/pdf");
    expect(sniff(new Uint8Array([0x4d, 0x5a, 0x90, 0x00]))?.family).toBe("exe");
    expect(sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0]))?.family).toBe("zip");
    expect(sniff(bytes("<!DOCTYPE html><html>"))?.type).toBe("text/html");
    expect(sniff(bytes('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'))?.family).toBe("svg");
  });

  it("finds ISO images at their offset", () => {
    const iso = new Uint8Array(0x8010);
    iso.set([0x43, 0x44, 0x30, 0x30, 0x31], 0x8001);
    expect(sniff(iso)?.family).toBe("disk");
  });

  it("flags double extensions, RTLO and mismatches", () => {
    expect(attachmentFlags("invoice.pdf.html", sniff(bytes("<html>")), "text/html")).toEqual(expect.arrayContaining(["double-extension", "risky-extension"]));
    expect(attachmentFlags("report‮fdp.exe", sniff(new Uint8Array([0x4d, 0x5a])), "application/octet-stream")).toEqual(expect.arrayContaining(["rtlo", "executable"]));
    expect(attachmentFlags("scan.jpg", sniff(new Uint8Array([0x4d, 0x5a])), "image/jpeg")).toContain("type-mismatch");
    expect(attachmentFlags("report.docx", sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04])), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")).toEqual([]);
  });

  it("hashes with Web Crypto", async () => {
    expect(await sha256Hex(bytes("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("does not call ordinary HTML smuggling", () => {
    expect(smugglingIndicators("<html><body><p>Hi</p></body></html>")).toEqual([]);
  });
});
