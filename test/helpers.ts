import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PNG } from "pngjs";
import { analyzeEml } from "../src/core/index.js";
import type { AnalysisResult, ImageDecoder } from "../src/core/index.js";

/** Node has no createImageBitmap; decode PNGs with pngjs so the QR path runs under test. */
export const pngDecoder: ImageDecoder = async (bytes, mime) => {
  if (mime !== "image/png") return null;
  const png = PNG.sync.read(Buffer.from(bytes));
  return { data: new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.length), width: png.width, height: png.height };
};

export function sample(name: string): Buffer {
  return readFileSync(join(import.meta.dirname, "..", "samples", name));
}

export function analyzeSample(name: string): Promise<AnalysisResult> {
  return analyzeEml(sample(name), { decodeImage: pngDecoder, now: new Date("2026-10-26T00:00:00Z") });
}

export const ids = (r: AnalysisResult) => r.signals.map((s) => s.id);
