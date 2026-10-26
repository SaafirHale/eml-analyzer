/** Language cues. Each category counts once, however many phrases match. */

export type ContentCue = { id: string; label: string; matches: string[] };

const CUES: { id: string; label: string; patterns: RegExp[] }[] = [
  {
    id: "payment",
    label: "Payment or banking request",
    patterns: [
      /gift ?cards?/i, /wire (transfer|the funds|payment)/i, /\bbank(ing)? (details|information|account)\b/i,
      /\bupdated? (payment|remittance|banking) (details|information|instructions)\b/i,
      /\binvoice\b.*\b(overdue|attached|payment)\b/i, /\bremittance\b/i, /\bACH\b/, /\bpayment (is )?(due|pending|overdue)\b/i,
    ],
  },
  {
    id: "credential",
    label: "Credential or account lure",
    patterns: [
      /verify (your )?(account|identity|email|mailbox)/i, /password (will )?(expire|expires|expired|expiry|reset)/i,
      /\b(re-?validate|re-?activate|re-?confirm|re-?enroll)\b/i, /mailbox (is )?(full|over quota|suspended)/i,
      /\baccount (will be |has been )?(suspended|locked|disabled|deactivated|closed)\b/i,
      /\b(MFA|multi-factor|two-factor|2FA) (enrollment|re-?enrollment|update|verification|required)\b/i,
      /sign in to (keep|continue|retain)/i, /scan (the|this) (QR|code)/i,
    ],
  },
  {
    id: "urgency",
    label: "Urgency or secrecy pressure",
    patterns: [
      /\burgent(ly)?\b/i, /\bimmediately\b/i, /within (24|48|twenty-four) hours/i, /\bASAP\b/,
      /are you (at|on) your desk/i, /\bquick (favou?r|task|request)\b/i, /\b(keep this|strictly) confidential\b/i,
      /\bdon'?t (tell|mention|share)\b/i, /\bin a meeting\b/i, /\bfinal (notice|warning|reminder)\b/i,
      /\btoday (by|before)\b/i, /\bexpires? today\b/i,
    ],
  },
];

export function contentCues(text: string): ContentCue[] {
  const out: ContentCue[] = [];
  for (const cue of CUES) {
    const matches = cue.patterns.map((re) => re.exec(text)?.[0]).filter((m): m is string => !!m);
    if (matches.length) out.push({ id: cue.id, label: cue.label, matches: [...new Set(matches)] });
  }
  return out;
}

export const EXEC_TITLE = /\b(CEO|CFO|COO|CTO|CIO|president|chair(man|woman|person)?|chief [a-z]+ officer|managing director|founder|owner|general counsel)\b/i;
export const ROLE_TITLE = /\b(payroll|human resources|HR|IT (support|help ?desk|service ?desk|department|team)|help ?desk|service ?desk|accounts? (payable|receivable)|billing|finance (team|department)|security (team|alert|notice)|administrator|admin team|mail(box)? (admin|support)|benefits)\b/i;
