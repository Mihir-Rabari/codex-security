/** Recognize policy blocks and explicit refusal responses, not ordinary review failures. */
export function isReviewRefusal(
  message: string,
  codexErrorInfo?: unknown,
): boolean {
  if (
    codexErrorInfo === "cyberPolicy" ||
    codexErrorInfo === "misalignmentPolicyViolation"
  )
    return true;
  return [
    /\bflagged for possible cybersecurity risk\b/iu,
    /\bflagged for potentially high-risk cyber activity\b/iu,
    /\bcyber[_\s-]?policy\b/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy[ _-]*(?::\s*(?:request\s+)?)?(?:violation|refusal|refused)\b/iu,
    /\b(?:refusal|refused|blocked)(?:\s+(?:under|by|due to|because of)\s+|\s*:\s*)(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy\b/iu,
    /^(?:I(?:['’]m| am) sorry[,.:]?\s*(?:but\s+)?|Sorry[,.:]?\s*)?I(?:\s+(?:cannot|can['’]t|won['’]t|am (?:unable|not able) to)|['’]m (?:unable|not able) to)\s+(?:help|assist|comply)\b/iu,
  ].some((pattern) => pattern.test(message.trim()));
}
