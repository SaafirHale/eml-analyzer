// Builds the synthetic sample corpus in samples/. Everything is invented: domains are
// reserved names (example.com, *.example, *.test — RFC 2606 / RFC 6761), IP addresses are
// documentation ranges (RFC 5737) or private space, and the "payloads" are harmless text.
//
//   node scripts/make-samples.mjs

import { writeFileSync, mkdirSync } from "node:fs";
import { domainToASCII } from "node:url";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import QRCode from "qrcode";
import { PNG } from "pngjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "samples");
mkdirSync(outDir, { recursive: true });

const CRLF = "\r\n";
const b64 = (buf) => Buffer.from(buf).toString("base64").replace(/.{1,76}/g, (l) => l + CRLF).trimEnd();
const write = (name, lines) => {
  const text = lines.join(CRLF) + CRLF;
  writeFileSync(join(outDir, name), text);
  console.log(`samples/${name}  ${text.length} bytes`);
};

// ---------------------------------------------------------------- helpers --

/** Minimal stored (uncompressed) ZIP with one file. */
function zipOne(name, content) {
  const data = Buffer.from(content);
  const nameBuf = Buffer.from(name);
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  let crc = 0xffffffff;
  for (const b of data) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8);
  crc = (crc ^ 0xffffffff) >>> 0;

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);

  const localPart = Buffer.concat([local, nameBuf, data]);
  const centralPart = Buffer.concat([central, nameBuf]);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralPart.length, 12);
  end.writeUInt32LE(localPart.length, 16);
  return Buffer.concat([localPart, centralPart, end]);
}

/** Flat-colour PNG, used as a newsletter logo that holds no QR code. */
function solidPng(w, h, [r, g, b]) {
  const png = new PNG({ width: w, height: h });
  for (let i = 0; i < w * h; i++) {
    png.data[i * 4] = r;
    png.data[i * 4 + 1] = g;
    png.data[i * 4 + 2] = b;
    png.data[i * 4 + 3] = 255;
  }
  return PNG.sync.write(png);
}

const RECIPIENT = "Jordan Lee <jordan.lee@example.com>";

// ------------------------------------------------------------ 1. newsletter --
{
  const boundary = "fn-alt-7731";
  const related = "fn-rel-7731";
  const logo = solidPng(48, 48, [32, 96, 64]);
  const text = [
    "Field Notes Weekly - Issue 42",
    "",
    "This week: trail maps for the autumn season, a gear checklist, and reader photos.",
    "",
    "Read the issue: https://fieldnotes.example/issues/42",
    "Manage your subscription: https://fieldnotes.example/account/preferences",
    "",
    "You are receiving this because you subscribed at fieldnotes.example.",
    "Unsubscribe: https://fieldnotes.example/unsubscribe?id=7731",
  ];
  const html = [
    "<!doctype html><html><body style=\"font-family:Arial,sans-serif\">",
    "<img src=\"cid:logo-7731@news.fieldnotes.example\" alt=\"Field Notes\" width=\"48\" height=\"48\">",
    "<h1>Field Notes Weekly &mdash; Issue 42</h1>",
    "<p>This week: trail maps for the autumn season, a gear checklist, and reader photos.</p>",
    "<p><a href=\"https://fieldnotes.example/issues/42?utm_source=newsletter&amp;utm_medium=email\">Read issue 42</a></p>",
    "<p><a href=\"https://fieldnotes.example/issues/42/gear-checklist\">The gear checklist</a></p>",
    "<p style=\"font-size:11px;color:#666\">You are receiving this because you subscribed at fieldnotes.example.",
    "<a href=\"https://fieldnotes.example/account/preferences\">Manage preferences</a> &middot;",
    "<a href=\"https://fieldnotes.example/unsubscribe?id=7731\">Unsubscribe</a></p>",
    "</body></html>",
  ];
  write("01-clean-newsletter.eml", [
    "Received: from relay.example.com (relay.example.com [192.0.2.10])",
    "\tby mbx01.example.com with ESMTPS id 7Hq2Lm for <jordan.lee@example.com>;",
    "\tMon, 19 Oct 2026 14:02:07 +0000",
    "Authentication-Results: mbx01.example.com;",
    "\tspf=pass (sender IP is 198.51.100.27) smtp.mailfrom=bounces.esp-mailer.example;",
    "\tdkim=pass (2048-bit key) header.d=fieldnotes.example header.s=fn1;",
    "\tdmarc=pass (p=QUARANTINE sp=QUARANTINE pct=100) header.from=fieldnotes.example;",
    "\tarc=pass (i=1)",
    "ARC-Seal: i=1; a=rsa-sha256; t=1792418525; cv=none; d=example.com; s=arc2026;",
    "\tb=SYNTHETICARCSEALVALUE0000000000000000000000000000000000000000000000",
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc2026;",
    "\th=from:to:subject:date:message-id; bh=SYNTHETICBODYHASH000000000000000000000=;",
    "\tb=SYNTHETICARCSIGNATURE00000000000000000000000000000000000000000000000",
    "ARC-Authentication-Results: i=1; relay.example.com;",
    "\tspf=pass smtp.mailfrom=bounces.esp-mailer.example;",
    "\tdkim=pass header.d=fieldnotes.example header.s=fn1;",
    "\tdmarc=pass header.from=fieldnotes.example",
    "Received: from mta7.esp-mailer.example (mta7.esp-mailer.example [198.51.100.27])",
    "\tby relay.example.com with ESMTPS id 3kQx9P for <jordan.lee@example.com>;",
    "\tMon, 19 Oct 2026 14:02:05 +0000",
    "Received: from app-04.internal.esp-mailer.example (unknown [10.20.4.14])",
    "\tby mta7.esp-mailer.example with ESMTP id 9aa1c4;",
    "\tMon, 19 Oct 2026 14:01:58 +0000",
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=fieldnotes.example; s=fn1;",
    "\th=from:to:subject:date:message-id:list-unsubscribe;",
    "\tbh=SYNTHETICBODYHASH000000000000000000000=; b=SYNTHETICDKIMSIGNATURE000000000000000000",
    "Return-Path: <bounce-7731-jordan.lee=example.com@bounces.esp-mailer.example>",
    "From: Field Notes Weekly <digest@news.fieldnotes.example>",
    `To: ${RECIPIENT}`,
    "Subject: Field Notes Weekly - Issue 42: autumn trail maps",
    "Date: Mon, 19 Oct 2026 14:01:57 +0000",
    "Message-ID: <20261019140157.7731.42@news.fieldnotes.example>",
    "List-Unsubscribe: <https://fieldnotes.example/unsubscribe?id=7731>, <mailto:unsubscribe@fieldnotes.example>",
    "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    ...text,
    "",
    `--${boundary}`,
    `Content-Type: multipart/related; boundary="${related}"`,
    "",
    `--${related}`,
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    ...html,
    "",
    `--${related}`,
    "Content-Type: image/png; name=\"logo.png\"",
    "Content-Transfer-Encoding: base64",
    "Content-ID: <logo-7731@news.fieldnotes.example>",
    "Content-Disposition: inline; filename=\"logo.png\"",
    "",
    b64(logo),
    `--${related}--`,
    "",
    `--${boundary}--`,
  ]);
}

// ---------------------------------------------------------------- 2. CEO BEC --
{
  write("02-ceo-bec.eml", [
    "Received: from mx1.example.com (mx1.example.com [192.0.2.25])",
    "\tby mbx01.example.com with ESMTPS id 1aB77c for <jordan.lee@example.com>;",
    "\tTue, 20 Oct 2026 12:41:20 +0000",
    "Authentication-Results: mbx01.example.com;",
    "\tspf=pass (sender IP is 203.0.113.80) smtp.mailfrom=exec.dwhitfield@freemail.test;",
    "\tdkim=pass (2048-bit key) header.d=freemail.test header.s=fm2026;",
    "\tdmarc=pass (p=NONE sp=NONE) header.from=freemail.test",
    "Received: from smtp-out.freemail.test (smtp-out.freemail.test [203.0.113.80])",
    "\tby mx1.example.com with ESMTPS id 9Zt41q for <jordan.lee@example.com>;",
    "\tTue, 20 Oct 2026 12:41:17 +0000",
    "Received: from [198.51.100.203] (unknown [198.51.100.203])",
    "\tby smtp-out.freemail.test with ESMTPSA id fm-55a0;",
    "\tTue, 20 Oct 2026 12:41:14 +0000",
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=freemail.test; s=fm2026;",
    "\th=from:reply-to:to:subject:date:message-id; bh=SYNTHETICBODYHASH000000000000000000000=;",
    "\tb=SYNTHETICDKIMSIGNATURE000000000000000000",
    "Return-Path: <exec.dwhitfield@freemail.test>",
    "From: \"Dana Whitfield <dana.whitfield@example.com>\" <exec.dwhitfield@freemail.test>",
    "Reply-To: <d.whitfield.office@private-inbox.test>",
    `To: ${RECIPIENT}`,
    "Subject: Quick favour - are you at your desk?",
    "Date: Tue, 20 Oct 2026 08:41:12 -0400",
    "Message-ID: <CAF3xq9Pz8-synthetic-41a@mail.freemail.test>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 7bit",
    "",
    "Jordan,",
    "",
    "Are you at your desk? I need you to handle a quick task for me today.",
    "I'm in a meeting with the board until 3 and can't take calls.",
    "",
    "We need to send gift cards to a client team this afternoon - 8 x $200.",
    "Keep this confidential for now, it's meant to be a surprise.",
    "",
    "Reply to this email and I will send the details.",
    "",
    "Dana",
    "Sent from my phone",
  ]);
}

// ------------------------------------------------------- 3. credential phish --
{
  const boundary = "cp-alt-30f1";
  const punyHost = domainToASCII("exämple.test"); // exämple.test
  const loginHref = "https://examp1e.test/sso/login?user=jordan.lee%40example.com&amp;next=%2Fmail";
  const html = [
    "<html><body style=\"font-family:Segoe UI,Arial,sans-serif\">",
    "<p>Dear user,</p>",
    "<p>Your Example account password expires today at 17:00. To keep your current password",
    "and avoid losing access to email, verify your account below.</p>",
    `<p><a href="${loginHref}">https://login.example.com/password/keep</a></p>`,
    "<p><a href=\"https://redirect.partner-ads.test/out?url=https%3A%2F%2Fexample.com.account-verify.test%2Freset\">Keep my current password</a></p>",
    `<p>Questions? Visit the <a href="https://${punyHost}/help">IT help portal</a>.</p>`,
    "<p>Example IT Service Desk</p>",
    "</body></html>",
  ];
  write("03-credential-phish-lookalike.eml", [
    "Received: from mx1.example.com (mx1.example.com [192.0.2.25])",
    "\tby mbx01.example.com with ESMTPS id 5Fe0aa for <jordan.lee@example.com>;",
    "\tWed, 21 Oct 2026 10:31:55 +0000",
    "Authentication-Results: spf=softfail (sender IP is 203.0.113.145)",
    "\tsmtp.mailfrom=mailer.bulk-relay.test; dkim=none (message not signed)",
    "\theader.d=none;dmarc=none action=none header.from=examp1e.test;compauth=fail",
    "\treason=001",
    "Received-SPF: SoftFail (mx1.example.com: domain of transitioning",
    "\tmailer.bulk-relay.test discourages use of 203.0.113.145 as permitted sender)",
    "Received: from relay-04.bulk-relay.test (203.0.113.145) by mx1.example.com",
    "\twith ESMTP id 2Kd91x for <jordan.lee@example.com>; Wed, 21 Oct 2026 10:31:52 +0000",
    "Received: from ws-217.bulk-relay.test (ws-217.bulk-relay.test [198.51.100.77])",
    "\tby relay-04.bulk-relay.test with ESMTP id 8812ff; Wed, 21 Oct 2026 09:02:11 +0000",
    "Return-Path: <bounce@mailer.bulk-relay.test>",
    "From: Example IT Service Desk <it-servicedesk@examp1e.test>",
    `To: ${RECIPIENT}`,
    "Subject: Action required: your password expires today",
    "Date: Wed, 21 Oct 2026 09:01:58 +0000",
    "Message-ID: <a81f2c0e.5d1@relay-04.bulk-relay.test>",
    "X-Priority: 1",
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Your Example account password expires today at 17:00.",
    "Keep your current password: https://examp1e.test/sso/login?user=jordan.lee@example.com",
    "",
    `--${boundary}`,
    "Content-Type: text/html; charset=utf-8",
    "",
    ...html,
    "",
    `--${boundary}--`,
  ]);
}

// --------------------------------------------------------- 4. HTML smuggling --
{
  const boundary = "hs-mix-30418";
  const payload = Buffer.from("SYNTHETIC TEST PAYLOAD. Not malware. Generated for eml-analyzer tests.\n".repeat(40)).toString("base64");
  const smuggler = [
    "<!DOCTYPE html>",
    "<html><head><meta charset=\"utf-8\"><title>Remittance Advice</title></head>",
    "<body>",
    "<p>Loading your document&hellip;</p>",
    "<script>",
    `var d = "${payload}";`,
    "var bin = atob(d);",
    "var bytes = new Uint8Array(bin.length);",
    "for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }",
    "var blob = new Blob([bytes], { type: \"application/octet-stream\" });",
    "var a = document.createElement(\"a\");",
    "a.href = URL.createObjectURL(blob);",
    "a.download = \"Remittance_INV-30418.iso\";",
    "document.body.appendChild(a);",
    "a.click();",
    "</script>",
    "</body></html>",
  ].join("\n");
  const fakePdf = zipOne("statement.txt", "SYNTHETIC TEST FILE. A ZIP container named .pdf for type-sniffing tests.\n");
  write("04-html-smuggling.eml", [
    "Received: from mx1.example.com (mx1.example.com [192.0.2.25])",
    "\tby mbx01.example.com with ESMTPS id 0Qe8ru for <jordan.lee@example.com>;",
    "\tThu, 22 Oct 2026 15:12:41 +0000",
    "Authentication-Results: mbx01.example.com;",
    "\tspf=pass (sender IP is 203.0.113.9) smtp.mailfrom=ap@northwind-supply.test;",
    "\tdkim=pass (2048-bit key) header.d=northwind-supply.test header.s=sel1;",
    "\tdmarc=pass (p=NONE) header.from=northwind-supply.test",
    "Received: from mail.northwind-supply.test (mail.northwind-supply.test [203.0.113.9])",
    "\tby mx1.example.com with ESMTPS id 6Tt2pn for <jordan.lee@example.com>;",
    "\tThu, 22 Oct 2026 15:12:38 +0000",
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=northwind-supply.test; s=sel1;",
    "\th=from:to:subject:date:message-id; bh=SYNTHETICBODYHASH000000000000000000000=;",
    "\tb=SYNTHETICDKIMSIGNATURE000000000000000000",
    "Return-Path: <ap@northwind-supply.test>",
    "From: Accounts Payable <ap@northwind-supply.test>",
    `To: ${RECIPIENT}`,
    "Subject: Remittance advice 10/22 - payment confirmation INV-30418",
    "Date: Thu, 22 Oct 2026 15:12:30 +0000",
    "Message-ID: <inv30418.1022@northwind-supply.test>",
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Hello,",
    "",
    "Please find the remittance advice attached for invoice payment INV-30418.",
    "Open the attached document in your browser to view it.",
    "",
    "Regards,",
    "Accounts Payable",
    "",
    `--${boundary}`,
    "Content-Type: text/html; name=\"Remittance_Advice_INV-30418.html\"",
    "Content-Transfer-Encoding: base64",
    "Content-Disposition: attachment; filename=\"Remittance_Advice_INV-30418.html\"",
    "",
    b64(smuggler),
    "",
    `--${boundary}`,
    "Content-Type: application/pdf; name=\"Statement_Oct2026.pdf\"",
    "Content-Transfer-Encoding: base64",
    "Content-Disposition: attachment; filename=\"Statement_Oct2026.pdf\"",
    "",
    b64(fakePdf),
    "",
    `--${boundary}--`,
  ]);
}

// ---------------------------------------------------------------- 5. QR phish --
{
  const boundary = "qr-rel-8f31";
  const qrUrl = "https://example-benefits.test/mfa/enroll?uid=jordan.lee%40example.com&t=8f31c2";
  const qrPng = await QRCode.toBuffer(qrUrl, { type: "png", errorCorrectionLevel: "M", margin: 4, scale: 6 });
  write("05-qr-phish.eml", [
    "Received: from mx1.example.com (mx1.example.com [192.0.2.25])",
    "\tby mbx01.example.com with ESMTPS id 3Pq0zz for <jordan.lee@example.com>;",
    "\tFri, 23 Oct 2026 07:55:03 +0000",
    "Authentication-Results: mbx01.example.com;",
    "\tspf=pass (sender IP is 198.51.100.140) smtp.mailfrom=notifications@benefits-portal.test;",
    "\tdkim=none (no signature);",
    "\tdmarc=none header.from=benefits-portal.test",
    "Received: from out-3.benefits-portal.test (out-3.benefits-portal.test [198.51.100.140])",
    "\tby mx1.example.com with ESMTP id 7Lm2qq for <jordan.lee@example.com>;",
    "\tFri, 23 Oct 2026 07:55:01 +0000",
    "Return-Path: <notifications@benefits-portal.test>",
    "From: HR Benefits Team <notifications@benefits-portal.test>",
    `To: ${RECIPIENT}`,
    "Subject: MFA re-enrollment required for your benefits account",
    "Date: Fri, 23 Oct 2026 07:54:58 +0000",
    "Message-ID: <mfa-8f31c2@benefits-portal.test>",
    "MIME-Version: 1.0",
    `Content-Type: multipart/related; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/html; charset=utf-8",
    "",
    "<html><body style=\"font-family:Arial,sans-serif\">",
    "<p>Your multi-factor authentication for the benefits portal must be re-enrolled before Friday.</p>",
    "<p>Scan the QR code below with your phone camera to continue.</p>",
    "<p><img src=\"cid:mfa-qr@benefits-portal.test\" alt=\"QR code\" width=\"174\" height=\"174\"></p>",
    "<p>HR Benefits Team</p>",
    "</body></html>",
    "",
    `--${boundary}`,
    "Content-Type: image/png; name=\"mfa-enroll.png\"",
    "Content-Transfer-Encoding: base64",
    "Content-ID: <mfa-qr@benefits-portal.test>",
    "Content-Disposition: inline; filename=\"mfa-enroll.png\"",
    "",
    b64(qrPng),
    "",
    `--${boundary}--`,
  ]);
}

