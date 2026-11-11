# Portfolio entry (draft)

Draft for `src/content/projects.ts` in the saafirhale.com repo, in the shape of its `Project` type.
Every claim below can be checked against this repository. The repo is public, so `status` is
`"live"`; add a second link once the tool is mounted at `/tools/eml`.

```ts
{
  slug: "eml-analyzer",
  category: "security",
  title: "Phishing Email Analyzer",
  blurb:
    "Drop in a .eml and get the route, SPF/DKIM/DMARC/ARC verdicts, lookalike domains, real link destinations, attachment types and QR codes, all inside the browser.",
  body: [
    "A phishing triage tool that runs entirely in the browser tab. Drop in a .eml file or paste the raw source and it parses the full header chain into a hop-by-hop Received timeline with the delay at each relay, lines up From, Reply-To, Return-Path, Sender and Message-ID to show where replies and bounces really go, and turns Authentication-Results and the ARC chain into SPF, DKIM, DMARC and ARC verdicts with a plain-language explanation of each, including whether the passing domain actually matches the From address.",
    "Every domain the message names, from the sender to link destinations, redirect targets and decoded QR codes, is checked against the recipient's own domains for homoglyphs, punycode, mixed scripts, edit distance, combosquats and TLD swaps. Links show the real destination beside the visible text, with redirectors unwrapped and a defanged copy button. Attachments are typed from their bytes rather than their names, hashed with SHA-256 through Web Crypto, linked to a VirusTotal lookup, and HTML attachments are scanned for HTML-smuggling script patterns. QR codes in images are decoded client-side, so a quishing lure with no clickable link still surfaces its URL.",
    "Every finding becomes a weighted signal, and the sum gives a verdict from low risk to likely phishing. The report exports as Markdown for a ticket, with every URL defanged, or as JSON. Nothing is uploaded and the message HTML is never rendered. It is a framework-agnostic TypeScript core with a React component, tested with Vitest against a corpus of five synthetic messages: a clean newsletter, a display-name CEO spoof, a credential phish on a lookalike domain, an HTML-smuggling attachment and a QR-code phish.",
  ],
  stack: ["TypeScript", "React", "postal-mime", "jsQR", "Web Crypto", "Vitest", "Vite"],
  links: [{ label: "GitHub", href: "https://github.com/SaafirHale/eml-analyzer" }],
  status: "live",
}
```

## Facts behind the copy

| Claim | Where to check |
| --- | --- |
| Runs in the browser, no upload, HTML never rendered | `src/core/` has no network calls; `src/core/html.ts` reads HTML with regular expressions only; the UI prints body text in a `<pre>` |
| Received timeline with per-hop delay | `src/core/received.ts`, `Route` section |
| SPF / DKIM / DMARC / ARC verdicts with explanation and alignment | `src/core/auth.ts` |
| Lookalike techniques listed | `src/core/domains.ts` (`compareDomains`), `test/units.test.ts` |
| Redirectors unwrapped, defanged copy | `src/core/urls.ts` |
| Type from bytes, SHA-256 via Web Crypto, VirusTotal link | `src/core/attachments.ts`, `src/core/analyze.ts` |
| HTML-smuggling scan | `smugglingIndicators` in `src/core/attachments.ts`; sample 04 |
| QR decoding client-side | `src/core/qr.ts` (jsQR, createImageBitmap); sample 05; verified in the browser preview |
| Markdown and JSON export, URLs defanged | `src/core/report.ts`, test "writes Markdown with every URL defanged" |
| Five synthetic samples, Vitest | `samples/`, `test/samples.test.ts` (55 tests in total at the time of writing) |
