import { closeSync, openSync, readSync } from "node:fs";
import { windowsFiles } from "./resolve-security-md";
import { decodePosixBytes, encodePosixPath } from "./posix-path";

export const PREVIEW_BYTES = 1024;
export const PREVIEW_READ_BYTES = 64 * 1024;

const bomEncoding = (data: Buffer) =>
  data[0] === 0xff && data[1] === 0xfe
    ? "utf-16le"
    : data[0] === 0xfe && data[1] === 0xff
      ? "utf-16be"
      : "utf-8";

function decodeSource(data: Buffer): string {
  // Preview decoding historically ignores malformed or incomplete source units.
  if (bomEncoding(data) === "utf-8")
    return decodePosixBytes(data)
      .replace(/^[\ufeff]/u, "")
      .replace(/[\udc80-\udcff]/gu, "");
  const units = Buffer.from(data.subarray(2, data.length - (data.length % 2)));
  if (bomEncoding(data) === "utf-16be") units.swap16();
  return units.toString("utf16le").replace(/[\ud800-\udfff]/gu, "");
}

export function isBinarySample(data: Buffer): boolean {
  return bomEncoding(data) === "utf-8"
    ? data.includes(0)
    : decodeSource(data).includes("\0");
}

export function truncateUtf8(text: string, budget: number): string {
  if (budget <= 0) return "";
  const bytes = Buffer.from(text);
  if (bytes.length <= budget) return text;
  let end = Math.min(budget, bytes.length);
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return bytes.subarray(0, end).toString("utf8");
}

export function previewForBytes(
  data: Buffer,
  budget = PREVIEW_BYTES,
): [string, boolean] {
  if (isBinarySample(data)) return ["", true];
  if (budget <= 0) return ["", false];
  let lines = decodeSource(data).replace(/\r\n?/gu, "\n").split("\n");
  let first = 0,
    last = lines.length;
  while (first < last && !lines[first]!.trim()) first++;
  while (last > first && !lines[last - 1]!.trim()) last--;
  lines = lines.slice(first, last);
  const complete = lines.join("\n");
  if (Buffer.byteLength(complete) <= budget) return [complete, false];
  const nonblank = lines.filter((line) => line.trim());
  const remainder = nonblank.slice(12);
  lines =
    remainder.length <= 10
      ? nonblank
      : [
          ...nonblank.slice(0, 12),
          "...",
          ...Array.from(
            { length: 10 },
            (_, index) =>
              remainder[Math.floor((index * (remainder.length - 1)) / 9)]!,
          ),
        ];
  if (!lines.length) return ["", false];
  const sampled = lines.join("\n");
  if (Buffer.byteLength(sampled) <= budget) return [sampled, false];
  const render = (size: number) =>
    lines
      .map((line) => (line === "..." ? line : truncateUtf8(line, size)))
      .join("\n");
  let low = 0,
    high = Math.max(...lines.map((line) => Buffer.byteLength(line))),
    best = "";
  while (low <= high) {
    const middle = Math.floor((low + high) / 2),
      candidate = render(middle);
    if (Buffer.byteLength(candidate) <= budget) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
  }
  return [
    best.trim() && best.trim() !== "..." ? best : truncateUtf8(sampled, budget),
    false,
  ];
}

export function* fileChunks(path: string): Iterable<Buffer> {
  const descriptor = openSync(encodePosixPath(path), "r");
  try {
    while (true) {
      const buffer = Buffer.allocUnsafe(PREVIEW_READ_BYTES);
      const length = readSync(descriptor, buffer, 0, buffer.length, null);
      if (!length) return;
      yield buffer.subarray(0, length);
    }
  } finally {
    closeSync(descriptor);
  }
}

/** Retain a bounded preview while checking every byte for binary content. */
export function sampleFile(path: string): [Buffer, boolean] {
  try {
    let sample: Buffer = Buffer.alloc(0),
      first = true,
      binary = false;
    const consume = (chunk: Buffer) => {
      if (first) {
        sample = chunk;
        first = false;
      }
      binary =
        bomEncoding(sample) === "utf-8"
          ? chunk.includes(0)
          : isBinarySample(Buffer.concat([sample.subarray(0, 2), chunk]));
      return !binary;
    };
    if (process.platform === "win32")
      windowsFiles().readChunks(Buffer.from(path, "utf16le"), consume);
    else for (const chunk of fileChunks(path)) if (!consume(chunk)) break;
    return [binary ? Buffer.alloc(0) : sample, binary];
  } catch {
    return [Buffer.alloc(0), true];
  }
}
