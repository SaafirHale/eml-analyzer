import { useMemo, useState } from "react";
import { BAND_LABEL } from "../core/analyze.js";
import { ipKind, formatDuration } from "../core/received.js";
import { toJSON, toMarkdown } from "../core/report.js";
import { defang } from "../core/urls.js";
import type { AnalysisResult, AttachmentFlag, LinkFlag, Mailbox, Verdict } from "../core/types.js";
import { CopyButton, Section, SeverityMark, Tag, download, formatBytes, formatDate } from "./ui.js";

const LINK_FLAG_LABEL: Record<LinkFlag, string> = {
  "text-href-mismatch": "text ≠ destination",
  shortener: "shortener",
  redirector: "redirector",
  "ip-host": "IP address",
  punycode: "punycode",
  lookalike: "lookalike",
  "recipient-in-url": "your address in URL",
  "non-https": "http",
  "data-uri": "data: URI",
  "javascript-uri": "javascript:",
  "form-action": "form",
  "credential-path": "login path",
};

const ATTACHMENT_FLAG_LABEL: Record<AttachmentFlag, string> = {
  "type-mismatch": "type mismatch",
  "risky-extension": "risky type",
  "double-extension": "double extension",
  rtlo: "RTL override",
  "html-smuggling": "HTML smuggling",
  "credential-form": "password form",
  executable: "executable",
  "macro-container": "macros",
  "disk-image": "disk image",
};

const QUIET_LINK_FLAGS = new Set<LinkFlag>(["non-https", "credential-path"]);

function verdictTone(v: Verdict): "ok" | "warn" | "muted" {
  if (v === "pass") return "ok";
  if (v === "fail" || v === "softfail" || v === "permerror") return "warn";
  return "muted";
}

function mailbox(m: Mailbox | undefined) {
  if (!m) return "—";
  if (!m.name) return m.address;
  return /[<>@,"]/.test(m.name) ? `"${m.name.replace(/"/g, "\\\"")}" <${m.address}>` : `${m.name} <${m.address}>`;
}

function slug(s: string | undefined) {
  return (s ?? "message").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "message";
}

export function Results({ result, fileName }: { result: AnalysisResult; fileName?: string }) {
  const r = result;
  const md = useMemo(() => toMarkdown(r), [r]);
  const base = `eml-report-${slug(r.message.subject)}`;
  const [showHeaders, setShowHeaders] = useState(false);
  const scored = r.signals.filter((s) => s.weight !== 0);
  const info = r.signals.filter((s) => s.weight === 0);
  const maxDelay = Math.max(1, ...r.route.hops.map((h) => Math.abs(h.delaySeconds ?? 0)));
  let n = 0;

  return (
    <div className="eml-results">
      {/* ------------------------------------------------------- verdict */}
      <section className="eml-sec eml-verdict" data-band={r.band}>
        <div className="eml-split">
          <div className="eml-label">
            <div className="eml-label-idx">Verdict</div>
            <div className="eml-score">
              <span className="eml-score-n">{r.score}</span>
              <span className="eml-score-of">/100</span>
            </div>
            <div className="eml-band">{BAND_LABEL[r.band]}</div>
          </div>
          <div className="eml-body">
            <h2 className="eml-h2">{r.message.subject || "(no subject)"}</h2>
            <dl className="eml-kv">
              <dt>From</dt>
              <dd>{mailbox(r.message.from)}</dd>
              <dt>To</dt>
              <dd>{r.message.to.map(mailbox).join(", ") || "—"}</dd>
              <dt>Date</dt>
              <dd>{formatDate(r.message.date)}</dd>
              {fileName ? (
                <>
                  <dt>File</dt>
                  <dd>{fileName}</dd>
                </>
              ) : null}
            </dl>
            <div className="eml-actions">
              <button type="button" className="eml-btn" onClick={() => download(`${base}.md`, md, "text/markdown")}>
                Export Markdown
              </button>
              <button type="button" className="eml-btn eml-btn-ghost" onClick={() => download(`${base}.json`, toJSON(r), "application/json")}>
                Export JSON
              </button>
              <CopyButton text={md} label="Copy Markdown" />
            </div>
            <p className="eml-fine">
              Score is the sum of the weights below, held between 0 and 100. Under 20 reads as low risk, 50 and over as likely phishing. URLs in
              the exports are defanged.
            </p>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------- signals */}
      <Section index={++n} label="Signals" note={`${scored.length} scored · ${info.length} noted`}>
        <div className="eml-list">
          {r.signals.map((s) => (
            <div className="eml-row eml-signal" key={s.id} data-sev={s.severity}>
              <span className="eml-weight">{s.weight > 0 ? `+${s.weight}` : s.weight === 0 ? "0" : `−${Math.abs(s.weight)}`}</span>
              <div className="eml-signal-body">
                <div className="eml-signal-title">
                  {s.title} <SeverityMark severity={s.severity} />
                </div>
                <div className="eml-signal-detail">{s.detail}</div>
              </div>
              <span className="eml-cat">{s.category}</span>
            </div>
          ))}
          {!r.signals.length ? <div className="eml-row eml-muted">Nothing to report.</div> : null}
        </div>
      </Section>

      {/* ------------------------------------------------------ identity */}
      <Section index={++n} label="Identity" note="Who the message says it is from, and where replies and bounces go.">
        <div className="eml-table-wrap">
          <table className="eml-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Value</th>
                <th>Org domain</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {r.identity.rows.map((row, i) => (
                <tr key={i} data-diff={row.differsFromFrom ? "true" : undefined}>
                  <td className="eml-nowrap">{row.field}</td>
                  <td className="eml-break">{row.value}</td>
                  <td className="eml-nowrap">{row.orgDomain ?? "—"}</td>
                  <td className="eml-nowrap">{row.differsFromFrom ? <Tag tone="warn">≠ From</Tag> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {r.lookalikes.length ? (
          <>
            <h4 className="eml-h4">Lookalike domains</h4>
            <div className="eml-list">
              {r.lookalikes.map((l, i) => (
                <div className="eml-row" key={i}>
                  <span className="eml-mono-strong">{l.domain}</span>
                  {l.unicode ? <span>displays as <strong className="eml-accent">{l.unicode}</strong></span> : null}
                  <span className="eml-muted">resembles</span>
                  <span>{l.resembles}</span>
                  <span className="eml-tags">
                    {l.techniques.map((t) => (
                      <Tag key={t} tone="warn">
                        {t}
                        {t === "edit-distance" && l.distance ? ` ${l.distance}` : ""}
                      </Tag>
                    ))}
                  </span>
                  <span className="eml-muted">in {l.where.join(", ")}</span>
                </div>
              ))}
            </div>
          </>
        ) : null}
      </Section>

      {/* -------------------------------------------------------- auth */}
      <Section
        index={++n}
        label="Authentication"
        note={
          r.auth.headers[0]
            ? `As recorded by ${r.auth.headers[0].authservId || "the receiving server"}. Nothing is re-verified: a browser tab has no DNS.`
            : "No Authentication-Results header."
        }
      >
        <div className="eml-list">
          {r.auth.summary.map((a) => (
            <div className="eml-row eml-auth" key={a.method}>
              <span className="eml-auth-m">{a.method.toUpperCase()}</span>
              <span className="eml-auth-v">
                <Tag tone={verdictTone(a.verdict)}>{a.verdict}</Tag>
              </span>
              <div className="eml-auth-body">
                <div className="eml-auth-meta">
                  {a.domain ? <span>{a.domain}</span> : null}
                  {a.aligned !== undefined ? <span className="eml-muted">{a.aligned ? "aligned with From" : "not aligned with From"}</span> : null}
                </div>
                <div className="eml-auth-x">{a.explanation}</div>
              </div>
            </div>
          ))}
        </div>
        {r.auth.arc.length ? (
          <>
            <h4 className="eml-h4">ARC chain</h4>
            <div className="eml-table-wrap">
              <table className="eml-table">
                <thead>
                  <tr>
                    <th>i=</th>
                    <th>Sealed by</th>
                    <th>cv=</th>
                    <th>Results that hop recorded</th>
                  </tr>
                </thead>
                <tbody>
                  {r.auth.arc.map((s) => (
                    <tr key={s.instance}>
                      <td>{s.instance}</td>
                      <td>{s.sealDomain ?? s.signatureDomain ?? "—"}</td>
                      <td>{s.cv ?? "—"}</td>
                      <td className="eml-break">
                        {s.authResults
                          ? `${s.authResults.authservId}: ${s.authResults.results.map((x) => `${x.rawMethod}=${x.result}`).join(", ")}`
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
        {r.auth.dkimSignatures.length ? (
          <p className="eml-fine">
            DKIM-Signature headers:{" "}
            {r.auth.dkimSignatures.map((d, i) => (
              <span key={i}>
                {i ? ", " : ""}d={d.domain} s={d.selector}
              </span>
            ))}
          </p>
        ) : null}
      </Section>

      {/* ------------------------------------------------------- route */}
      <Section
        index={++n}
        label="Route"
        note={
          r.route.hops.length
            ? `${r.route.hops.length} hop${r.route.hops.length > 1 ? "s" : ""}${r.route.totalSeconds !== undefined ? `, ${formatDuration(r.route.totalSeconds)} end to end` : ""}. Oldest first.`
            : "No Received headers."
        }
      >
        <ol className="eml-route">
          {r.route.hops.map((h) => {
            const d = h.delaySeconds;
            const slow = d !== undefined && d > 3600;
            const width = d === undefined ? 0 : Math.max(2, (Math.log10(Math.abs(d) + 1) / Math.log10(maxDelay + 1)) * 100);
            return (
              <li className="eml-hop" key={h.index} data-slow={slow ? "true" : undefined}>
                <div className="eml-hop-idx">{h.index}</div>
                <div className="eml-hop-main">
                  <div className="eml-hop-path">
                    <span className="eml-break">{h.fromRdns ?? h.from ?? "?"}</span>
                    <span className="eml-muted"> → </span>
                    <span className="eml-break">{h.by ?? "?"}</span>
                  </div>
                  <div className="eml-hop-meta">
                    {h.fromIp ? (
                      <span>
                        {h.fromIp} <span className="eml-muted">({ipKind(h.fromIp)})</span>
                      </span>
                    ) : null}
                    {h.with ? <span>{h.with}</span> : null}
                    <span>{formatDate(h.date)}</span>
                  </div>
                </div>
                <div className="eml-hop-delay">
                  <span className="eml-hop-bar">
                    <span style={{ width: `${width}%` }} />
                  </span>
                  <span className="eml-hop-dt">{d === undefined ? (h.index === 1 ? "start" : "—") : `+${formatDuration(d)}`}</span>
                </div>
              </li>
            );
          })}
        </ol>
        {r.route.dateToFirstHopSeconds !== undefined ? (
          <p className="eml-fine">Date header to first hop: {formatDuration(r.route.dateToFirstHopSeconds)}.</p>
        ) : null}
      </Section>

      {/* ------------------------------------------------------- links */}
      <Section
        index={++n}
        label="Links"
        note={r.links.length ? `${r.links.length} unique, from text, HTML, attachments and QR codes.` : "No links."}
      >
        {r.links.length ? (
          <>
            <div className="eml-actions eml-actions-tight">
              <CopyButton text={r.links.map((l) => l.defanged).join("\n")} label="Copy all, defanged" />
            </div>
            <div className="eml-list">
              {r.links.map((l, i) => {
                const loud = l.flags.filter((f) => !QUIET_LINK_FLAGS.has(f));
                return (
                  <div className="eml-row eml-link" key={i} data-flagged={loud.length ? "true" : undefined}>
                    <div className="eml-link-main">
                      <div className="eml-link-href eml-break">{l.defanged}</div>
                      {l.text ? (
                        <div className="eml-link-text">
                          <span className="eml-muted">shown as </span>
                          <span className="eml-break">“{l.text}”</span>
                        </div>
                      ) : null}
                      {l.redirectTarget ? (
                        <div className="eml-link-text">
                          <span className="eml-muted">forwards to </span>
                          <span className="eml-break eml-accent">{defang(l.redirectTarget)}</span>
                        </div>
                      ) : null}
                      <div className="eml-tags">
                        <Tag tone="muted">{l.source}</Tag>
                        {l.flags.map((f) => (
                          <Tag key={f} tone={QUIET_LINK_FLAGS.has(f) ? "muted" : "warn"}>
                            {LINK_FLAG_LABEL[f]}
                          </Tag>
                        ))}
                      </div>
                    </div>
                    <CopyButton text={l.defanged} />
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <p className="eml-muted">No links in the text, HTML, attachments or QR codes.</p>
        )}
      </Section>

      {/* -------------------------------------------------- attachments */}
      <Section index={++n} label="Attachments" note="Type from the bytes, not the name. Hashes are SHA-256, computed here.">
        {r.attachments.length ? (
          <div className="eml-list">
            {r.attachments.map((a, i) => (
              <div className="eml-row eml-att" key={i} data-flagged={a.flags.length ? "true" : undefined}>
                <div className="eml-att-main">
                  <div className="eml-att-name eml-break">{a.filename}</div>
                  <div className="eml-att-meta">
                    <span>
                      declared <strong>{a.declaredType}</strong>
                    </span>
                    <span>
                      actual{" "}
                      <strong className={a.flags.includes("type-mismatch") ? "eml-accent" : undefined}>{a.sniffedLabel ?? "unknown"}</strong>
                    </span>
                    <span>{formatBytes(a.size)}</span>
                    {a.inline ? <span className="eml-muted">inline</span> : null}
                  </div>
                  <div className="eml-hash eml-break">{a.sha256}</div>
                  {a.smugglingIndicators ? <div className="eml-fine">Script indicators: {a.smugglingIndicators.join("; ")}</div> : null}
                  {a.flags.length ? (
                    <div className="eml-tags">
                      {a.flags.map((f) => (
                        <Tag key={f} tone="warn">
                          {ATTACHMENT_FLAG_LABEL[f]}
                        </Tag>
                      ))}
                    </div>
                  ) : null}
                </div>
                <div className="eml-att-actions">
                  <CopyButton text={a.sha256} label="Copy hash" />
                  <a className="eml-mini" href={a.virusTotalUrl} target="_blank" rel="noopener noreferrer">
                    VirusTotal ↗
                  </a>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="eml-muted">No attachments.</p>
        )}
        {r.attachments.length ? (
          <p className="eml-fine">The VirusTotal link opens a hash lookup in a new tab. Nothing is sent from here, and the file itself never leaves this browser.</p>
        ) : null}
      </Section>

      {/* ---------------------------------------------------------- QR */}
      <Section index={++n} label="QR codes" note="Every image attachment and data: URI image is scanned here.">
        {r.qr.length ? (
          <div className="eml-list">
            {r.qr.map((q, i) => (
              <div className="eml-row" key={i}>
                <span className="eml-muted">{q.image}</span>
                <span className="eml-break eml-mono-strong">{q.isUrl ? defang(q.data) : q.data}</span>
                {q.isUrl ? <Tag tone="warn">link</Tag> : null}
              </div>
            ))}
          </div>
        ) : (
          <p className="eml-muted">
            {r.attachments.some((a) => a.declaredType.startsWith("image/")) ? "Images scanned; no QR codes found." : "No images to scan."}
          </p>
        )}
        {r.notes.map((note, i) => (
          <p className="eml-fine" key={i}>
            {note}
          </p>
        ))}
      </Section>

      {/* ----------------------------------------------------- headers */}
      <Section index={++n} label="Headers" note={`${r.headers.length} fields, in the order they appear.`}>
        <button type="button" className="eml-toggle" data-on={showHeaders} onClick={() => setShowHeaders((v) => !v)}>
          {showHeaders ? "Hide raw headers" : "Show raw headers"}
        </button>
        {showHeaders ? (
          <div className="eml-headers">
            {r.headers.map((h, i) => (
              <div className="eml-header" key={i}>
                <span className="eml-header-k">{h.name}</span>
                <span className="eml-header-v">{h.value}</span>
              </div>
            ))}
          </div>
        ) : null}
        {r.message.textPreview ? (
          <>
            <h4 className="eml-h4">Body text (as plain text, never rendered)</h4>
            <pre className="eml-pre">{r.message.textPreview}</pre>
          </>
        ) : null}
      </Section>
    </div>
  );
}
