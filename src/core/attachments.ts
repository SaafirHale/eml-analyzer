import type { AttachmentFlag } from "./types.js";

export type Sniffed = { type: string; label: string; family: string };

type Magic = { bytes: (number | null)[]; offset?: number; type: string; label: string; family: string };

const MAGIC: Magic[] = [
  { bytes: [0x25, 0x50, 0x44, 0x46, 0x2d], type: "application/pdf", label: "PDF", family: "pdf" },
  { bytes: [0x50, 0x4b, 0x03, 0x04], type: "application/zip", label: "ZIP container", family: "zip" },
  { bytes: [0x50, 0x4b, 0x05, 0x06], type: "application/zip", label: "ZIP container (empty)", family: "zip" },
  { bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], type: "application/x-ole-storage", label: "OLE compound file (legacy Office / .msg)", family: "ole" },
  { bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], type: "image/png", label: "PNG image", family: "image" },
  { bytes: [0xff, 0xd8, 0xff], type: "image/jpeg", label: "JPEG image", family: "image" },
  { bytes: [0x47, 0x49, 0x46, 0x38], type: "image/gif", label: "GIF image", family: "image" },
  { bytes: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50], type: "image/webp", label: "WebP image", family: "image" },
  { bytes: [0x42, 0x4d], type: "image/bmp", label: "BMP image", family: "image" },
  { bytes: [0x4d, 0x5a], type: "application/x-msdownload", label: "Windows executable (MZ)", family: "exe" },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], type: "application/x-elf", label: "ELF executable", family: "exe" },
  { bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], type: "application/vnd.rar", label: "RAR archive", family: "archive" },
  { bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], type: "application/x-7z-compressed", label: "7-Zip archive", family: "archive" },
  { bytes: [0x1f, 0x8b], type: "application/gzip", label: "gzip archive", family: "archive" },
  { bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], type: "application/x-ms-shortcut", label: "Windows shortcut (LNK)", family: "lnk" },
  { bytes: [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d], type: "application/onenote", label: "OneNote section", family: "onenote" },
  { bytes: [0x43, 0x44, 0x30, 0x30, 0x31], offset: 0x8001, type: "application/x-iso9660-image", label: "ISO 9660 disk image", family: "disk" },
  { bytes: [0x7b, 0x5c, 0x72, 0x74, 0x66], type: "application/rtf", label: "RTF document", family: "rtf" },
  { bytes: [0x4d, 0x53, 0x43, 0x46], type: "application/vnd.ms-cab-compressed", label: "CAB archive", family: "archive" },
];

function matches(buf: Uint8Array, m: Magic): boolean {
  const off = m.offset ?? 0;
  if (buf.length < off + m.bytes.length) return false;
  return m.bytes.every((b, i) => b === null || buf[off + i] === b);
}

export function sniff(buf: Uint8Array): Sniffed | undefined {
  for (const m of MAGIC) if (matches(buf, m)) return { type: m.type, label: m.label, family: m.family };
  // Text formats: look at the first couple of KB.
  const head = new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, 2048)).replace(/^﻿/, "").trimStart().toLowerCase();
  if (/^<svg\b|^<\?xml[^>]*>\s*(<!--[\s\S]*?-->\s*)*<svg\b/.test(head)) return { type: "image/svg+xml", label: "SVG image (can carry script)", family: "svg" };
  if (/^(<!doctype html|<html\b|<head\b|<body\b|<script\b|<meta\b|<iframe\b)/.test(head) || /<script\b/.test(head)) {
    return { type: "text/html", label: "HTML document", family: "html" };
  }
  if (/^begin:vcalendar/.test(head)) return { type: "text/calendar", label: "Calendar invite", family: "text" };
  if (/^(@echo off|powershell|cmd \/c)/.test(head)) return { type: "text/x-script", label: "Shell script", family: "script" };
  const printable = [...buf.subarray(0, 512)].filter((b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0x80).length;
  if (buf.length && printable / Math.min(buf.length, 512) > 0.95) return { type: "text/plain", label: "Plain text", family: "text" };
  return undefined;
}

/** Which file families each extension is allowed to be. */
const EXT_FAMILY: Record<string, string[]> = {
  pdf: ["pdf"],
  zip: ["zip"], docx: ["zip"], xlsx: ["zip"], pptx: ["zip"], docm: ["zip"], xlsm: ["zip"], pptm: ["zip"],
  odt: ["zip"], ods: ["zip"], jar: ["zip"], apk: ["zip"], epub: ["zip"],
  doc: ["ole", "rtf"], xls: ["ole"], ppt: ["ole"], msg: ["ole"], msi: ["ole"],
  png: ["image"], jpg: ["image"], jpeg: ["image"], gif: ["image"], webp: ["image"], bmp: ["image"],
  svg: ["svg"],
  exe: ["exe"], dll: ["exe"], scr: ["exe"], com: ["exe"], cpl: ["exe"], sys: ["exe"],
  rar: ["archive"], "7z": ["archive"], gz: ["archive"], tgz: ["archive"], cab: ["archive"],
  lnk: ["lnk"], one: ["onenote"], iso: ["disk"], img: ["disk"],
  rtf: ["rtf"],
  htm: ["html"], html: ["html"], shtml: ["html"], xhtml: ["html"], mht: ["html", "text"],
  txt: ["text"], csv: ["text"], ics: ["text"], eml: ["text"], log: ["text"], json: ["text"], xml: ["text", "svg"],
};

export const RISKY_EXTENSIONS = new Set([
  "html", "htm", "shtml", "xhtml", "mht", "svg", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
  "ps1", "bat", "cmd", "lnk", "url", "iso", "img", "vhd", "vhdx", "exe", "scr", "com", "pif",
  "cpl", "msi", "dll", "jar", "one", "xll", "docm", "xlsm", "pptm", "xlam", "chm", "reg",
]);

const MACRO_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "xlam", "dotm", "xll"]);
const DISK_EXTENSIONS = new Set(["iso", "img", "vhd", "vhdx"]);
const EXECUTABLE_EXTENSIONS = new Set(["exe", "scr", "com", "pif", "cpl", "msi", "dll", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk"]);
const DECOY_EXTENSIONS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "csv", "zip"]);

export function extensionOf(filename: string): string {
  const clean = filename.replace(/[‎‏‪-‮⁦-⁩]/g, "").trim().toLowerCase();
  const dot = clean.lastIndexOf(".");
  return dot < 0 ? "" : clean.slice(dot + 1);
}

export async function sha256Hex(buf: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buf as Uint8Array<ArrayBuffer>);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const SMUGGLING_PATTERNS: [RegExp, string][] = [
  [/\batob\s*\(/, "atob() base64 decoding"],
  [/new\s+Blob\s*\(/, "new Blob() built in the page"],
  [/URL\.createObjectURL\s*\(/, "URL.createObjectURL()"],
  [/msSaveOrOpenBlob|msSaveBlob/, "msSaveOrOpenBlob() (legacy IE/Edge save)"],
  [/\.download\s*=|\sdownload\s*=\s*["']/, "download attribute set on a link"],
  [/\.click\s*\(\s*\)/, "scripted click()"],
  [/Uint8Array\s*\(|charCodeAt\s*\(/, "byte-array construction"],
  [/String\.fromCharCode|unescape\s*\(|eval\s*\(|Function\s*\(/, "obfuscated script (fromCharCode / unescape / eval)"],
  [/[A-Za-z0-9+/]{2000,}={0,2}/, "long embedded base64 blob"],
];

export function smugglingIndicators(text: string): string[] {
  return SMUGGLING_PATTERNS.filter(([re]) => re.test(text)).map(([, label]) => label);
}

export function hasCredentialForm(text: string): boolean {
  return /<input\b[^>]*type\s*=\s*["']?password/i.test(text) || (/<form\b/i.test(text) && /(password|passwd|pwd)/i.test(text));
}

export function attachmentFlags(filename: string, sniffed: Sniffed | undefined, declaredType: string): AttachmentFlag[] {
  const flags: AttachmentFlag[] = [];
  const ext = extensionOf(filename);
  if (/[‮‭⁦-⁩]/.test(filename)) flags.push("rtlo");

  const parts = filename.toLowerCase().split(".").slice(1);
  if (parts.length >= 2 && DECOY_EXTENSIONS.has(parts.at(-2)!) && ext !== parts.at(-2)) flags.push("double-extension");

  if (RISKY_EXTENSIONS.has(ext)) flags.push("risky-extension");
  if (MACRO_EXTENSIONS.has(ext)) flags.push("macro-container");
  if (DISK_EXTENSIONS.has(ext) || sniffed?.family === "disk") flags.push("disk-image");
  if (EXECUTABLE_EXTENSIONS.has(ext) || sniffed?.family === "exe" || sniffed?.family === "lnk") flags.push("executable");

  if (sniffed) {
    const allowed = EXT_FAMILY[ext];
    const extMismatch = allowed ? !allowed.includes(sniffed.family) && !(sniffed.family === "text" && allowed.includes("html")) : false;
    const declared = declaredType.toLowerCase();
    const declaredFamily =
      declared === "application/pdf" ? "pdf" :
      declared.startsWith("image/") && declared !== "image/svg+xml" ? "image" :
      declared === "text/html" ? "html" : undefined;
    const typeMismatch = declaredFamily !== undefined && declaredFamily !== sniffed.family;
    if (extMismatch || typeMismatch) flags.push("type-mismatch");
  }
  return [...new Set(flags)];
}
