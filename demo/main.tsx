import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { EmlAnalyzer, type EmlSample } from "../src/react/index.js";
import "../src/react/styles.css";
import "./demo.css";

import newsletter from "../samples/01-clean-newsletter.eml?raw";
import bec from "../samples/02-ceo-bec.eml?raw";
import credential from "../samples/03-credential-phish-lookalike.eml?raw";
import smuggling from "../samples/04-html-smuggling.eml?raw";
import qr from "../samples/05-qr-phish.eml?raw";

const samples: EmlSample[] = [
  { id: "newsletter", label: "Clean newsletter", load: async () => newsletter },
  { id: "bec", label: "Spoofed CEO (BEC)", load: async () => bec },
  { id: "credential", label: "Credential phish, lookalike domain", load: async () => credential },
  { id: "smuggling", label: "HTML smuggling attachment", load: async () => smuggling },
  { id: "qr", label: "QR code phish", load: async () => qr },
];

function ThemeToggle() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? "dark");
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      className="demo-theme"
      onClick={() => {
        document.documentElement.dataset.theme = next;
        try {
          localStorage.setItem("sh-theme", next);
        } catch {
          /* private mode */
        }
        setTheme(next);
      }}
    >
      {next} theme
    </button>
  );
}

function App() {
  return (
    <div className="demo-wrap">
      <header className="demo-top">
        <span className="demo-mark">Saafir Hale / tools / eml</span>
        <ThemeToggle />
      </header>
      <section className="demo-hero">
        <h1 className="demo-h1">Phishing email analyzer</h1>
        <p className="demo-lede">
          Drop in a .eml and read it the way an analyst would: the hop-by-hop route, what SPF, DKIM and DMARC actually said, who the sender
          claims to be, where every link really goes, and what each attachment really is.
        </p>
      </section>
      <EmlAnalyzer samples={samples} />
      <footer className="demo-foot">
        <span>Runs in the browser. No upload, no tracking.</span>
        <span>Samples are synthetic: reserved domains and documentation IP ranges.</span>
      </footer>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
