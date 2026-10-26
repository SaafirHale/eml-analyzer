import jsQR from "jsqr";
import type { DecodedImage, ImageDecoder } from "./types.js";

/**
 * Browser image decoder: createImageBitmap + (Offscreen)Canvas. Returns null where neither
 * exists (Node without a decoder injected), so the caller can note that QR decoding was skipped.
 */
export const browserImageDecoder: ImageDecoder = async (bytes, mimeType) => {
  if (typeof createImageBitmap !== "function") return null;
  const blob = new Blob([bytes as Uint8Array<ArrayBuffer>], { type: mimeType || "application/octet-stream" });
  const bitmap = await createImageBitmap(blob);
  try {
    // Large photos are scaled down; QR codes survive that and jsQR gets much faster.
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    let ctx: OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D | null = null;
    if (typeof OffscreenCanvas === "function") {
      ctx = new OffscreenCanvas(w, h).getContext("2d");
    } else if (typeof document !== "undefined") {
      const c = document.createElement("canvas");
      c.width = w;
      c.height = h;
      ctx = c.getContext("2d");
    }
    if (!ctx) return null;
    // White background so transparent PNG codes read as dark-on-light.
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(bitmap, 0, 0, w, h);
    const img = ctx.getImageData(0, 0, w, h);
    return { data: img.data, width: w, height: h };
  } finally {
    bitmap.close?.();
  }
};

export function decodeQr(img: DecodedImage): string | undefined {
  const res = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
  return res?.data || undefined;
}

export const QR_IMAGE_TYPES = /^image\/(png|jpe?g|gif|webp|bmp)$/i;
