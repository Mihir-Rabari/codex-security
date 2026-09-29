import type { ScanCost } from "./cost.js";

/** Cumulative receipts replace their prior value; absent and unavailable are distinct. */
export class ScanAccounting {
  readonly #receipts = new Map<string, Readonly<ScanCost> | null>();
  completed: Readonly<ScanCost> | null = null;

  record(key: string, cost: Readonly<ScanCost> | null): void {
    this.#receipts.set(key, cost);
  }
  has(key: string): boolean {
    return this.#receipts.has(key);
  }
  get hasChildren(): boolean {
    return [...this.#receipts.keys()].some((key) => key !== "merge");
  }
  get hasUnknown(): boolean {
    return [...this.#receipts.values()].includes(null);
  }
  get known(): ScanCost | null {
    return [...this.#receipts.values()].reduce<ScanCost | null>(
      (total, cost) => (cost === null ? total : addScanCosts(total, cost)),
      null,
    );
  }
  get complete(): ScanCost | null {
    return this.hasUnknown ? null : this.known;
  }

  /** An already persisted total may include receipts that are no longer locally available. */
  acceptTotal(cost: Readonly<ScanCost> | null): void {
    if (
      cost &&
      (!this.completed || cost.estimatedUsd > this.completed.estimatedUsd)
    )
      this.completed = cost;
  }

  restoreTerminal(
    saved: Readonly<ScanCost> | null,
    costs: ReadonlyArray<Readonly<ScanCost> | null> | null,
  ): void {
    this.completed = saved;
    if (costs !== null) {
      costs.forEach((cost, index) => this.record(`terminal-${index}`, cost));
      this.acceptTotal(this.complete);
    }
  }
}

export function addScanCosts(
  previous: Readonly<ScanCost> | null,
  current: Readonly<ScanCost>,
): ScanCost {
  if (previous === null) return { ...current };
  const { estimatedUsdRange: currentRange, ...currentCost } = current;
  const previousRange = previous.estimatedUsdRange;
  return {
    ...currentCost,
    inputTokens: previous.inputTokens + current.inputTokens,
    cachedInputTokens: previous.cachedInputTokens + current.cachedInputTokens,
    cacheWriteInputTokens:
      previous.cacheWriteInputTokens + current.cacheWriteInputTokens,
    outputTokens: previous.outputTokens + current.outputTokens,
    estimatedUsd: previous.estimatedUsd + current.estimatedUsd,
    ...(previous.cacheWriteInputTokensReported === false ||
    current.cacheWriteInputTokensReported === false
      ? { cacheWriteInputTokensReported: false }
      : {}),
    ...(previousRange === undefined || currentRange === undefined
      ? {}
      : {
          estimatedUsdRange: {
            context: "unknown" as const,
            min: previousRange.min + currentRange.min,
            max:
              previousRange.max === null || currentRange.max === null
                ? null
                : previousRange.max + currentRange.max,
          },
        }),
  };
}

export function scanCostUsage(
  cost: Readonly<ScanCost>,
): Record<string, number | boolean> {
  return {
    input_tokens: cost.inputTokens,
    cached_input_tokens: cost.cachedInputTokens,
    cache_write_input_tokens: cost.cacheWriteInputTokens,
    output_tokens: cost.outputTokens,
    ...(cost.cacheWriteInputTokensReported === false
      ? { cache_write_input_tokens_reported: false }
      : {}),
  };
}
