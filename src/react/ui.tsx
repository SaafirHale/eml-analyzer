import { useState, type ReactNode } from "react";
import type { Severity } from "../core/types.js";

export function Section({ index, label, note, children }: { index: number; label: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section className="eml-sec">
      <div className="eml-split">
        <div className="eml-label">
          <div className="eml-label-idx">{String(index).padStart(2, "0")}</div>
          <h3 className="eml-h3">{label}</h3>
          {note ? <div className="eml-label-note">{note}</div> : null}
        </div>
        <div className="eml-body">{children}</div>
      </div>
    </section>
  );
}

export function Tag({ children, tone = "neutral", title }: { children: ReactNode; tone?: "neutral" | "warn" | "ok" | "muted"; title?: string }) {
  return (
    <span className="eml-tag" data-tone={tone} title={title}>
      {children}
    </span>
  );
}

export function SeverityMark({ severity }: { severity: Severity }) {
  return (
    <span className="eml-sev" data-sev={severity}>
      {severity}
    </span>
  );
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for contexts without the async clipboard (file://, older browsers).
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

export function CopyButton({ text, label = "Copy", done = "Copied" }: { text: string; label?: string; done?: string }) {
  const [state, setState] = useState<"idle" | "done" | "fail">("idle");
  return (
    <button
      type="button"
      className="eml-mini"
      onClick={async () => {
        setState((await writeClipboard(text)) ? "done" : "fail");
        setTimeout(() => setState("idle"), 1400);
      }}
    >
      {state === "done" ? done : state === "fail" ? "Blocked" : label}
    </button>
  );
}

export function download(filename: string, body: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function formatDate(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}
