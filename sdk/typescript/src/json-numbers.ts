import { ContractValidationError } from "./errors.js";

export function parseJsonNumbers(source: string, context: string): unknown {
  return JSON.parse(source, (_key, value: unknown) => {
    if (typeof value === "number") validateJsonNumber(value, context);
    return value;
  });
}

export function validateJsonNumbers(value: unknown, context: string): void {
  if (typeof value === "number") validateJsonNumber(value, context);
  else if (value !== null && typeof value === "object")
    for (const item of Object.values(value)) validateJsonNumbers(item, context);
}

export function validateJsonNumber(value: number, context: string): void {
  if (!Number.isFinite(value)) {
    throw new ContractValidationError(
      `${context}: non-finite JSON numbers are not supported.`,
    );
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new ContractValidationError(
      `${context}: unsafe integer-valued JSON numbers are not supported.`,
    );
  }
}
