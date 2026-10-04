"use strict";

import type { AssertionContext } from "../../types.js";

const { parseCaseOutcome } =
  require("../scripts/sastbench-result") as typeof import("../scripts/sastbench-result.js");

export = (output: unknown, context: AssertionContext) => {
  const expectedInputId = String(context.vars.case_id || "");
  const expectedGroundTruth = String(
    context.test?.metadata?.ground_truth || "",
  );
  try {
    const { verdict } = parseCaseOutcome(output, expectedInputId);
    if (verdict === "needs_review") {
      return {
        pass: false,
        score: 0,
        reason: "SastBench case abstained with needs_review.",
      };
    }
    const prediction =
      verdict === "confirmed" ? "true_positive" : "false_positive";
    const pass = prediction === expectedGroundTruth;
    return {
      pass,
      score: pass ? 1 : 0,
      reason: pass
        ? `SastBench verdict matched ${expectedGroundTruth}.`
        : `SastBench verdict predicted ${prediction}; expected ${expectedGroundTruth}.`,
    };
  } catch (error) {
    return {
      pass: false,
      score: 0,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
};
