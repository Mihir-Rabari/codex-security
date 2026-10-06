import type { TriageResult } from "../types.ts";

export function outputText(output: unknown) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

export function hasTriageJson(text: string) {
  return (
    /```(?:json)?\s*[\s\S]*?```/i.test(text) ||
    /schema_version\s*["']?\s*:\s*["']?triage-finding\/v0/i.test(text) ||
    /["']findings["']\s*:/i.test(text) ||
    /["']verdict["']\s*:/i.test(text)
  );
}

export function parseExpected(
  value: unknown,
  trim = typeof value === "string",
) {
  if (typeof value === "string") {
    value = value.split(",");
  }
  const terms = Array.isArray(value) ? value.map(String) : [];
  return trim ? terms.flatMap((term) => term.trim() || []) : terms;
}

export function extractJson(
  output: unknown,
  schemaVersion: string,
  {
    requireSingle = false,
    failureMessage = `Could not find a parseable ${schemaVersion} JSON block.`,
  }: { requireSingle?: boolean; failureMessage?: string } = {},
) {
  const text = outputText(output);
  const fencedBlocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map(
    (match) => match[1].trim(),
  );
  const candidates =
    fencedBlocks.length > 0
      ? fencedBlocks
      : [text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)];
  if (requireSingle) {
    candidates.length = 0;
    let depth = 0;
    let start = 0;
    for (const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]]/gs)) {
      if (match[0] === "{" || match[0] === "[") {
        if (depth++ === 0) start = match.index;
      } else if (
        (match[0] === "}" || match[0] === "]") &&
        depth > 0 &&
        --depth === 0
      ) {
        candidates.push(text.slice(start, match.index + 1));
      }
    }
  }
  const matches: Record<string, unknown>[] = [];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as Record<string, unknown>;
      if (requireSingle) matches.push(parsed);
      else if (parsed && parsed.schema_version === schemaVersion) return parsed;
    } catch {
      // The response may contain more than one fenced block. Try the next one.
    }
  }
  if (
    matches.length === 1 &&
    !Array.isArray(matches[0]) &&
    matches[0].schema_version === schemaVersion
  )
    return matches[0];
  throw new Error(failureMessage);
}

export function extractTriageResult(
  output: unknown,
  failureMessage = "Could not find a parseable triage-finding/v0 JSON result",
) {
  return extractJson(output, "triage-finding/v0", {
    failureMessage,
  }) as unknown as TriageResult;
}
