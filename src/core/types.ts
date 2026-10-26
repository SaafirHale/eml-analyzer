/** Shared result types. Everything here is plain data so it serialises straight to JSON. */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type SignalCategory =
  | "authentication"
  | "identity"
  | "lookalike"
  | "links"
  | "attachments"
  | "qr"
  | "content"
  | "route"
  | "structure";

/** One finding. Positive weight raises the risk score, negative weight lowers it. */
export type Signal = {
  id: string;
  category: SignalCategory;
  severity: Severity;
  weight: number;
  title: string;
  detail: string;
};

export type Mailbox = { name: string; address: string };

export type HeaderField = { name: string; value: string };

// ------------------------------------------------------------------ route --

export type ReceivedHop = {
  /** 1 = first hop (closest to the sender). */
  index: number;
  raw: string;
  from?: string;
  fromRdns?: string;
  fromIp?: string;
  by?: string;
  with?: string;
  id?: string;
  for?: string;
  /** ISO timestamp, when the date after the semicolon parsed. */
  date?: string;
  /** Seconds since the previous hop. Negative means the clocks disagree. */
  delaySeconds?: number;
};

export type RouteResult = {
  hops: ReceivedHop[];
  /** Seconds from the first hop to the last. */
  totalSeconds?: number;
  /** Seconds between the Date header and the first hop. */
  dateToFirstHopSeconds?: number;
};

// --------------------------------------------------------- authentication --

export type AuthMethodName = "spf" | "dkim" | "dmarc" | "arc" | "compauth" | "bimi" | "other";

export type AuthMethodResult = {
  method: AuthMethodName;
  /** Method as written, e.g. "spf" or "dkim-atps". */
  rawMethod: string;
  result: string;
  reason?: string;
  /** ptype.property=value pairs, e.g. { "smtp.mailfrom": "a@b", "header.d": "b" }. */
  props: Record<string, string>;
  /** Free-text comment in parentheses, if any. */
  comment?: string;
};

export type AuthResultsHeader = {
  source: "Authentication-Results" | "ARC-Authentication-Results";
  authservId: string;
  /** ARC instance (i=) for ARC-Authentication-Results. */
  instance?: number;
  results: AuthMethodResult[];
  raw: string;
};

export type DkimSignature = {
  domain?: string;
  selector?: string;
  algorithm?: string;
  headers?: string[];
};

export type ArcSet = {
  instance: number;
  /** cv= from ARC-Seal: none | pass | fail. */
  cv?: string;
  sealDomain?: string;
  signatureDomain?: string;
  authResults?: AuthResultsHeader;
};

export type Verdict = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "policy" | "unknown";

export type AuthSummaryItem = {
  method: "spf" | "dkim" | "dmarc" | "arc";
  verdict: Verdict;
  /** Domain the check was about (envelope domain for SPF, d= for DKIM, header.from for DMARC). */
  domain?: string;
  /** Whether that domain aligns with the From domain (relaxed, organisational domain). */
  aligned?: boolean;
  /** One or two sentences in plain language. */
  explanation: string;
};

export type AuthResult = {
  headers: AuthResultsHeader[];
  receivedSpf: string[];
  dkimSignatures: DkimSignature[];
  arc: ArcSet[];
  summary: AuthSummaryItem[];
};

// --------------------------------------------------------------- identity --

export type IdentityRow = {
  field: "From" | "Sender" | "Reply-To" | "Return-Path" | "Message-ID" | "To" | "Delivered-To";
  value: string;
  domain?: string;
  /** Organisational domain (eTLD+1 approximation). */
  orgDomain?: string;
  /** True when the org domain differs from the From org domain. */
  differsFromFrom?: boolean;
};

export type IdentityResult = {
  from?: Mailbox;
  fromCount: number;
  rows: IdentityRow[];
};

// ---------------------------------------------------------------- lookalike --

export type LookalikeTechnique =
  | "homoglyph"
  | "punycode"
  | "mixed-script"
  | "edit-distance"
  | "combosquat"
  | "tld-swap";

export type LookalikeFinding = {
  /** The suspicious domain as seen in the message. */
  domain: string;
  /** Unicode form, when the domain was punycode. */
  unicode?: string;
  /** Legitimate domain it resembles. */
  resembles: string;
  techniques: LookalikeTechnique[];
  distance?: number;
  /** Where it appeared: "From", "Reply-To", "link", "QR code" … */
  where: string[];
};

// ------------------------------------------------------------------- links --

export type LinkSource = "html" | "text" | "qr" | "attachment";

export type LinkFlag =
  | "text-href-mismatch"
  | "shortener"
  | "redirector"
  | "ip-host"
  | "punycode"
  | "lookalike"
  | "recipient-in-url"
  | "non-https"
  | "data-uri"
  | "javascript-uri"
  | "form-action"
  | "credential-path";

export type LinkInfo = {
  href: string;
  /** Visible anchor text (HTML only). */
  text?: string;
  host?: string;
  source: LinkSource;
  flags: LinkFlag[];
  /** Destination pulled out of a redirector's query string. */
  redirectTarget?: string;
  defanged: string;
};

// ------------------------------------------------------------- attachments --

export type AttachmentFlag =
  | "type-mismatch"
  | "risky-extension"
  | "double-extension"
  | "rtlo"
  | "html-smuggling"
  | "credential-form"
  | "executable"
  | "macro-container"
  | "disk-image";

export type AttachmentInfo = {
  filename: string;
  declaredType: string;
  /** What the bytes say the file is. */
  sniffedType?: string;
  sniffedLabel?: string;
  size: number;
  sha256: string;
  disposition: string | null;
  contentId?: string;
  inline: boolean;
  flags: AttachmentFlag[];
  /** Matched HTML-smuggling indicators, for the report. */
  smugglingIndicators?: string[];
  virusTotalUrl: string;
};

// ---------------------------------------------------------------------- QR --

export type QrFinding = {
  /** Attachment filename or "data: URI #n". */
  image: string;
  data: string;
  isUrl: boolean;
};

// ------------------------------------------------------------------ result --

export type MessageSummary = {
  subject?: string;
  date?: string;
  messageId?: string;
  from?: Mailbox;
  to: Mailbox[];
  cc: Mailbox[];
  hasHtml: boolean;
  hasText: boolean;
  textPreview: string;
};

export type RiskBand = "low" | "suspicious" | "high";

export type AnalysisResult = {
  /** Version of the analyzer that produced this result. */
  analyzer: string;
  analyzedAt: string;
  message: MessageSummary;
  headers: HeaderField[];
  route: RouteResult;
  auth: AuthResult;
  identity: IdentityResult;
  lookalikes: LookalikeFinding[];
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  qr: QrFinding[];
  /** Notes about things that could not be checked (e.g. an image that would not decode). */
  notes: string[];
  signals: Signal[];
  score: number;
  band: RiskBand;
};

/** RGBA pixels, as returned by ImageData. */
export type DecodedImage = { data: Uint8ClampedArray; width: number; height: number };

export type ImageDecoder = (bytes: Uint8Array, mimeType: string) => Promise<DecodedImage | null>;

export type AnalyzeOptions = {
  /**
   * Domains that belong to you. Lookalike checks compare against these as well as the
   * recipient and From domains.
   */
  protectedDomains?: string[];
  /** Turns image bytes into pixels for QR decoding. Defaults to createImageBitmap + canvas. */
  decodeImage?: ImageDecoder;
  /** Skip QR decoding entirely. */
  skipQr?: boolean;
  /** Fixed timestamp for analyzedAt, for reproducible output. */
  now?: Date;
};
