#!/usr/bin/env node
"use strict";

const assert = require("assert");
const triageIo = require("../assertions/triage-io.js");

assert.throws(() => triageIo("no json", {}), {
  message: "Could not find a parseable triage-finding/v0 JSON block.",
});

function outputFor({ inputId, sourceType, verdict }) {
  const stackRank = {
    rank_queue: verdict === "not_actionable" ? null : verdict,
    rank: verdict === "not_actionable" ? null : 1,
    rationale: verdict === "not_actionable" ? "not actionable" : "Example ranking",
    drivers: [],
  };
  return `\`\`\`json
{
  "schema_version": "triage-finding/v0",
  "repository": {
    "path": "/tmp/repo",
    "revision": "abc123"
  },
  "findings": [
    {
      "triage_item_id": "triage-001",
      "input_id": "${inputId}",
      "source_type": "${sourceType}",
      "title": "Example finding",
      "normalized_input": {},
      "verdict": "${verdict}",
      "confidence": "high",
      "exploitability_stack_rank": ${JSON.stringify(stackRank)},
      "affected_locations": [],
      "reachable_path": [],
      "evidence": [],
      "counterevidence": [],
      "proof_gaps": [],
      "recommended_next_step": "No action",
      "fix_finding_handoff": ${verdict === "confirmed" ? JSON.stringify("Fix handoff") : "null"}
    }
  ]
}
\`\`\``;
}

function baseContext({ caseId, inputId, sourceType, expectedVerdict, expectedBinaryLabel }) {
  return {
    vars: {
      case_id: caseId,
      expected_ids: inputId,
      expected_source_types: sourceType,
      expected_verdicts: expectedVerdict,
      expected_binary_label: expectedBinaryLabel,
    },
  };
}

function assertPasses(name, output, context) {
  const result = triageIo(output, context);
  assert.equal(result.pass, true, `${name}: ${result.reason}`);
}

function assertFails(name, output, context, expectedReason) {
  const result = triageIo(output, context);
  assert.equal(result.pass, false, `${name}: expected assertion to fail`);
  assert.match(result.reason, expectedReason, `${name}: unexpected failure reason`);
}

const sourceType = "cve";

assertPasses(
  "vulnerable scanbench cases map to confirmed/positive",
  outputFor({ inputId: "input-001", sourceType, verdict: "confirmed" }),
  baseContext({
    caseId: "case-001",
    inputId: "input-001",
    sourceType,
    expectedVerdict: "confirmed",
    expectedBinaryLabel: "positive",
  }),
);

assertPasses(
  "fixed scanbench cases map to not_actionable/negative",
  outputFor({ inputId: "input-002", sourceType, verdict: "not_actionable" }),
  baseContext({
    caseId: "case-002",
    inputId: "input-002",
    sourceType,
    expectedVerdict: "not_actionable",
    expectedBinaryLabel: "negative",
  }),
);

assertFails(
  "negative calibration labels cannot expect confirmed",
  outputFor({ inputId: "input-002", sourceType, verdict: "confirmed" }),
  baseContext({
    caseId: "case-002",
    inputId: "input-002",
    sourceType,
    expectedVerdict: "confirmed",
    expectedBinaryLabel: "negative",
  }),
  /fixed.*not_actionable|negative/,
);

assertFails(
  "rank queue must match the verdict",
  outputFor({ inputId: "input-001", sourceType, verdict: "confirmed" }).replace('"rank_queue":"confirmed"', '"rank_queue":"needs_review"'),
  baseContext({ caseId: "case-001", inputId: "input-001", sourceType, expectedVerdict: "confirmed", expectedBinaryLabel: "positive" }),
  /rank_queue must match verdict/,
);
console.log("triage-io assertion tests passed");
