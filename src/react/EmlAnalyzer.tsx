"use client";

import { useCallback, useRef, useState, type DragEvent } from "react";
import { analyzeEml } from "../core/analyze.js";
import type { AnalysisResult, ImageDecoder } from "../core/types.js";
import { Results } from "./Results.js";

export type EmlSample = {
  id: string;
  label: string;
  /** Returns the raw .eml. Called only when the sample is picked. */
  load: () => Promise<string | ArrayBuffer>;
};

export type EmlAnalyzerProps = {
  /** Optional sample messages shown as one-click buttons. */
  samples?: EmlSample[];
  /** Domains to protect from lookalikes, in addition to the recipient's. */
  protectedDomains?: string[];
  /** Override image decoding for QR scanning (defaults to createImageBitmap + canvas). */
  decodeImage?: ImageDecoder;
  className?: string;
};

const MAX_BYTES = 30 * 1024 * 1024;

type State =
  | { kind: "idle" }
  | { kind: "busy"; label: string }
  | { kind: "done"; result: AnalysisResult; label: string }
  | { kind: "error"; message: string };

export function EmlAnalyzer({ samples, protectedDomains, decodeImage, className }: EmlAnalyzerProps) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [dragging, setDragging] = useState(false);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [paste, setPaste] = useState("");
  const [domains, setDomains] = useState((protectedDomains ?? []).join(", "));
  const [activeSample, setActiveSample] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const run = useCallback(
    async (input: string | ArrayBuffer | Blob, label: string) => {
      setState({ kind: "busy", label });
      try {
        const result = await analyzeEml(input, {
          protectedDomains: domains.split(/[\s,;]+/).map((d) => d.trim()).filter(Boolean),
          decodeImage,
        });
        setState({ kind: "done", result, label });
        requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
      } catch (e) {
        setState({ kind: "error", message: `Could not parse ${label}: ${e instanceof Error ? e.message : String(e)}` });
      }
    },
    [domains, decodeImage],
  );

  const openFile = (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setState({ kind: "error", message: `${file.name} is ${(file.size / 1024 / 1024).toFixed(1)} MB. The limit is 30 MB.` });
      return;
    }
    setActiveSample(null);
    void run(file, file.name);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    openFile(e.dataTransfer.files?.[0]);
  };

  return (
    <div className={`eml${className ? ` ${className}` : ""}`}>
      <section className="eml-sec eml-intake">
        <div className="eml-split">
          <div className="eml-label">
            <div className="eml-label-idx">Input</div>
            <p className="eml-label-note">
              Parsed in this tab. Nothing is uploaded, nothing is fetched, and the message HTML is never rendered.
            </p>
          </div>
          <div className="eml-body">
            <div
              className="eml-drop"
              data-dragging={dragging ? "true" : undefined}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
            >
              <div className="eml-drop-title">Drop a .eml file here</div>
              <div className="eml-actions">
                <button type="button" className="eml-btn" onClick={() => fileInput.current?.click()}>
                  Choose file
                </button>
                <button type="button" className="eml-btn eml-btn-ghost" data-on={pasteOpen} onClick={() => setPasteOpen((v) => !v)}>
                  Paste source
                </button>
              </div>
              <input
                ref={fileInput}
                type="file"
                accept=".eml,message/rfc822,.txt"
                hidden
                onChange={(e) => {
                  openFile(e.target.files?.[0]);
                  e.target.value = "";
                }}
              />
            </div>

            {pasteOpen ? (
              <div className="eml-paste">
                <label className="eml-field-label" htmlFor="eml-paste">
                  Raw message source, headers included
                </label>
                <textarea
                  id="eml-paste"
                  className="eml-textarea"
                  spellCheck={false}
                  value={paste}
                  placeholder={"Received: from …\nFrom: …\nSubject: …\n\nBody"}
                  onChange={(e) => setPaste(e.target.value)}
                />
                <div className="eml-actions">
                  <button
                    type="button"
                    className="eml-btn"
                    disabled={!paste.trim()}
                    onClick={() => {
                      setActiveSample(null);
                      void run(paste.replace(/\r?\n/g, "\r\n"), "pasted source");
                    }}
                  >
                    Analyse
                  </button>
                </div>
              </div>
            ) : null}

            <div className="eml-options">
              <label className="eml-field-label" htmlFor="eml-domains">
                Your domains (optional, for lookalike checks)
              </label>
              <input
                id="eml-domains"
                className="eml-input"
                value={domains}
                placeholder="example.com, example.net"
                onChange={(e) => setDomains(e.target.value)}
              />
            </div>

            {samples?.length ? (
              <div className="eml-samples">
                <span className="eml-field-label">Synthetic samples</span>
                <div className="eml-sample-list">
                  {samples.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      className="eml-toggle"
                      data-on={activeSample === s.id}
                      onClick={async () => {
                        setActiveSample(s.id);
                        try {
                          void run(await s.load(), s.label);
                        } catch (e) {
                          setState({ kind: "error", message: `Could not load ${s.label}: ${String(e)}` });
                        }
                      }}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="eml-status" role="status" aria-live="polite">
              {state.kind === "busy" ? `Analysing ${state.label}…` : null}
              {state.kind === "error" ? <span className="eml-accent">{state.message}</span> : null}
            </div>
          </div>
        </div>
      </section>

      <div ref={resultsRef}>{state.kind === "done" ? <Results result={state.result} fileName={state.label} /> : null}</div>
    </div>
  );
}
