"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  CORPUS,
  EXPECTED,
  FIXTURE_ROOT,
  parseOutcome,
  normalizePromptfooResult,
  summarize,
  summarizeExport,
  matchRetention,
} = require("./sca-result.js");
const { generateTests } = require("./generate-tests.js");
const { stageRuntime } = require("./run-promptfoo.js");
const assertion = require("../assertions/sca-evidence.js");
const { afterEach } = require("../assertions/sca-metrics.js");
const { buildBaselines } = require("./baselines.js");

function resultFor(testCase, verdict = EXPECTED[testCase.gold_label]) {
  const component = testCase.input.component;
  return {
    schema_version: "triage-finding/v0",
    repository: { path: `/synthetic/${testCase.case_id}`, revision: null },
    findings: [
      {
        triage_item_id: `triage-${testCase.case_id}`,
        input_id: testCase.input.input_id,
        source_type: "advisory",
        title: "Synthetic application assessment",
        normalized_input: {
          vulnerable_component: `${component.name} ${component.version}`,
          claimed_source:
            "Request fields from the synthetic application contract",
          claimed_sink: "Fictional dependency API",
          claimed_control: "The literal option or missing deployment setting",
          affected_version_or_path: `${component.version} in ${component.source}`,
          preconditions: testCase.input.preconditions,
          impact: "Fictional advisory impact",
          references: testCase.input.advisory_ids,
        },
        verdict,
        confidence: verdict === "needs_review" ? "low" : "high",
        affected_locations: [
          {
            label: "Application option",
            path: "src/application.mjs",
            lines: "4",
            detail: "The source option controls advisory applicability.",
          },
        ],
        reachable_path: ["User-controlled request enters handle"],
        boundary_assessment: {
          product_surface: "Fictional fixture endpoint",
          source_trust: "untrusted",
          boundary_crossed:
            verdict === "needs_review" ? null : verdict === "confirmed",
          policy_basis: "APPLICATION.md",
        },
        exploitability_stack_rank: {
          rank_queue: verdict === "not_actionable" ? null : verdict,
          rank: verdict === "not_actionable" ? null : 1,
          rationale: "Synthetic case only",
          drivers: [],
        },
        evidence: testCase.required_evidence.map(
          (entry) =>
            `${entry.path}:${entry.line} selects \`${entry.fragment}\`.`,
        ),
        counterevidence: [],
        proof_gaps:
          verdict === "needs_review" ? ["Deployed setting is missing."] : [],
        recommended_next_step: "Review the static dependency assessment.",
        fix_finding_handoff:
          verdict === "confirmed"
            ? "Review a dependency update and ordinary project checks."
            : null,
      },
    ],
  };
}

function rowFor(testCase, verdict) {
  return {
    vars: { case_id: testCase.case_id },
    response: { output: JSON.stringify(resultFor(testCase, verdict)) },
  };
}

test("corpus contains four fictional families and all three labels without claiming human outcomes", () => {
  assert.equal(CORPUS.kind, "synthetic_smoke");
  assert.equal(CORPUS.human_adjudicated_cases, 0);
  assert.equal(CORPUS.cases.length, 12);
  assert.equal(new Set(CORPUS.cases.map((item) => item.case_id)).size, 12);
  assert.equal(
    new Set(CORPUS.cases.map((item) => item.advisory_family)).size,
    4,
  );
  for (const label of ["affected", "not_affected", "unresolved"])
    assert.equal(
      CORPUS.cases.filter((item) => item.gold_label === label).length,
      4,
    );
});

test("scanner and inspectable-usage baselines preserve all matches without inventing applicability labels", () => {
  const baselines = buildBaselines();
  assert.equal(baselines.cases.length, 12);
  for (const entry of baselines.cases) {
    assert.equal(entry.scanner_only.application_assessment, null);
    assert.equal(
      entry.scanner_with_usage_evidence.application_assessment,
      null,
    );
    assert.deepEqual(
      entry.scanner_only.advisory_ids,
      entry.scanner_with_usage_evidence.advisory_ids,
    );
    assert.equal(entry.scanner_with_usage_evidence.source_evidence[0].line, 1);
    assert.equal(JSON.stringify(entry).includes("gold_label"), false);
  }
});

for (const fixture of CORPUS.cases) {
  test(`${fixture.case_id}: frozen source/advisory digests and schema-valid expected assessment`, () => {
    for (const [relative, expected] of Object.entries(fixture.sha256)) {
      const bytes = fs.readFileSync(
        path.join(FIXTURE_ROOT, fixture.case_id, relative),
      );
      assert.equal(
        crypto.createHash("sha256").update(bytes).digest("hex"),
        expected,
        relative,
      );
    }
    const output = resultFor(fixture);
    assert.deepEqual(parseOutcome(output, fixture).evidenceFailures, []);
    assert.equal(
      assertion(output, { vars: { case_id: fixture.case_id } }).pass,
      true,
    );
    const captured = JSON.parse(
      fs.readFileSync(
        path.join(FIXTURE_ROOT, fixture.case_id, "osv.json"),
        "utf8",
      ),
    );
    assert.equal(
      captured.results[0].packages[0].package.name,
      fixture.input.component.name,
    );
    assert.equal(
      captured.results[0].packages[0].package.version,
      fixture.input.component.version,
    );
    assert.deepEqual(
      captured.results[0].packages[0].vulnerabilities[0],
      fixture.input.advisories[0],
    );
  });
}

test("wrong source, package, resolved version and advisory cannot pass evidence checks", () => {
  const fixture = CORPUS.cases[0];
  const result = resultFor(fixture);
  result.findings[0].normalized_input = {
    ...result.findings[0].normalized_input,
    vulnerable_component: `${fixture.input.component.name}-extra 11.4.0`,
    affected_version_or_path: "11.4.0 in nested/package-lock.json",
    references: ["SCA-FIXTURE-001-extra"],
  };
  assert.equal(parseOutcome(result, fixture).evidenceFailures.length, 4);
});

test("a citation must quote the correct source span, not merely mention a filename", () => {
  const fixture = CORPUS.cases[0];
  for (const text of [
    "src/application.mjs says maxDepth: null",
    "src/application.mjs:1 selects `maxDepth: null`",
    "src/application.mjs:4 selects `maxDepth: true`",
    "src/application.mjs:1-900 selects `maxDepth: null`",
    "other/application.mjs:4 selects `maxDepth: null`",
  ]) {
    const result = resultFor(fixture);
    result.findings[0].evidence = [text];
    assert.match(
      parseOutcome(result, fixture).evidenceFailures.join(" "),
      /supported citation/,
    );
  }
});

test("needs_review must identify a proof gap", () => {
  const fixture = CORPUS.cases[2];
  const result = resultFor(fixture);
  result.findings[0].proof_gaps = [];
  assert.match(
    parseOutcome(result, fixture).evidenceFailures.join(" "),
    /proof gap/,
  );
});

test("missing, duplicate, or changed match IDs and malformed schema become invalid output", () => {
  const fixture = CORPUS.cases[0];
  for (const mutate of [
    (result) => {
      result.findings = [];
    },
    (result) => {
      result.findings.push(result.findings[0]);
    },
    (result) => {
      result.findings[0].input_id = "wrong-match";
    },
    (result) => {
      result.findings[0].source_type = "freeform";
    },
    (result) => {
      delete result.findings[0].evidence;
    },
    (result) => {
      result.findings[0].unexpected = true;
    },
  ]) {
    const result = resultFor(fixture);
    mutate(result);
    const outcome = normalizePromptfooResult({
      vars: { case_id: fixture.case_id },
      response: { output: result },
    });
    assert.equal(outcome.status, "invalid_output");
    assert.equal(outcome.verdict, null);
  }
});

test("provider errors remain model errors rather than unresolved or negative labels", () => {
  const outcome = normalizePromptfooResult({
    vars: { case_id: CORPUS.cases[0].case_id },
    response: { error: "Synthetic provider failure" },
  });
  assert.equal(outcome.status, "model_error");
  assert.equal(outcome.verdict, null);
  assert.equal(outcome.error, "Synthetic provider failure");
  assert.equal(summarize([outcome]).affectedConfirmationRecall, 0);
});

test("three-class confusion, recall, dismissals, coverage and uncertainty use all attempted cases", () => {
  const row = (caseIndex, verdict) =>
    normalizePromptfooResult(rowFor(CORPUS.cases[caseIndex], verdict));
  const outcomes = [
    row(0, "confirmed"),
    row(0, "needs_review"),
    { ...row(0), status: "invalid_output", verdict: null },
    row(0, "not_actionable"),
    row(1, "not_actionable"),
    row(2, "confirmed"),
    row(2, "needs_review"),
    { ...row(1), status: "model_error", verdict: null },
  ];
  const report = summarize(outcomes);
  assert.equal(report.attempted, 8);
  assert.equal(report.uniqueCases, 3);
  assert.equal(report.confirmationPrecision, 0.5);
  assert.equal(report.affectedConfirmationRecall, 0.25);
  assert.equal(report.incorrectDismissalRate, 0.25);
  assert.equal(report.dismissalPrecision, 0.5);
  assert.equal(report.uncertaintyHandling, 0.5);
  assert.equal(report.decisionCoverage, 0.5);
  assert.equal(report.decisionAccuracy, 0.5);
  assert.equal(report.unjustifiedDecisionsOnUnresolved, 1);
  assert.equal(report.confusionMatrix.affected.invalid_output, 1);
  assert.equal(report.confusionMatrix.not_affected.model_error, 1);
});

test("undefined metrics and unreviewed evidence are null, not invented perfect scores", () => {
  const report = summarize([]);
  assert.equal(report.confirmationPrecision, null);
  assert.equal(report.decisionCoverage, null);
  assert.equal(report.reviewerSupportedEvidenceRate, null);
  const one = summarize([normalizePromptfooResult(rowFor(CORPUS.cases[0]))]);
  assert.equal(one.mechanicalCitationPassRate, 1);
  assert.equal(one.reviewerSupportedEvidenceRate, null);
  assert.equal(one.costCoverage, 0);
});

test("cost and latency report actual available measurements", () => {
  const rows = [10, 30, 50, null].map((latency, index) =>
    normalizePromptfooResult({
      ...rowFor(CORPUS.cases[0]),
      latencyMs: latency,
      cost: index < 2 ? 0.1 : null,
    }),
  );
  const report = summarize(rows);
  assert.equal(report.medianLatencyMs, 30);
  assert.equal(report.reportedCostUsd, 0.2);
  assert.equal(report.costCoverage, 0.5);
});

test("scanner retention tracks source, resolved version and every original alias independently of assessments", () => {
  const first = CORPUS.cases[0].input;
  const second = {
    ...first,
    component: { ...first.component, source: "nested/package-lock.json" },
  };
  const third = {
    ...first,
    component: { ...first.component, version: "1.3.0" },
  };
  assert.equal(
    matchRetention([first, second, third], [first, second, third]).rate,
    1,
  );
  assert.equal(matchRetention([first, second, third], [first]).rate, 1 / 3);
  assert.equal(
    matchRetention(
      [first],
      [{ ...first, advisory_ids: [first.advisory_ids[0]] }],
    ).rate,
    0.5,
  );
  assert.equal(matchRetention([], []).rate, null);
  assert.equal(
    matchRetention(
      [second],
      [
        {
          ...second,
          component: {
            ...second.component,
            source: "nested\\package-lock.json",
          },
        },
      ],
    ).rate,
    1,
  );
});

test("exports retain separate arms and errors; unrecognized cases do not silently disappear", () => {
  const rows = ["baseline", "wrapper"].map((label) => ({
    ...rowFor(CORPUS.cases[0]),
    prompt: { label },
    provider: { id: "synthetic-provider" },
  }));
  const report = summarizeExport({ results: { results: rows } });
  assert.equal(Object.keys(report.arms).length, 2);
  assert.equal(report.human_adjudicated_cases, 0);
  assert.throws(
    () => summarizeExport({ results: [{ vars: { case_id: "unknown" } }] }),
    /Unknown SCA case/,
  );
});

test("Promptfoo metrics include execution failures even when normal assertions do not run", () => {
  const updated = afterEach({
    test: { vars: { case_id: CORPUS.cases[0].case_id } },
    result: { response: { error: "Synthetic failure" } },
  });
  assert.equal(updated.result.namedScores.attempted, 1);
  assert.equal(updated.result.namedScores.execution_errors, 1);
  assert.equal(updated.result.namedScores.affected_cases, 1);
  assert.equal(updated.result.namedScores.correctly_confirmed, 0);
});

test("model staging contains source and skill runtime without the gold corpus or scoring scripts", () => {
  const runtime = stageRuntime();
  const previous = process.env.SCA_EVAL_RUNTIME_ROOT;
  try {
    process.env.SCA_EVAL_RUNTIME_ROOT = runtime;
    const tests = generateTests();
    assert.equal(tests.length, 12);
    assert.equal(
      fs.existsSync(
        path.join(
          runtime,
          "plugins/codex-security/skills/triage-finding/SKILL.md",
        ),
      ),
      true,
    );
    assert.equal(fs.existsSync(path.join(runtime, "evals")), false);
    assert.equal(fs.existsSync(path.join(runtime, "cases/corpus.json")), false);
    for (const item of tests) {
      assert.deepEqual(Object.keys(item.vars).sort(), [
        "case_id",
        "input_id",
        "target_repo",
      ]);
      const staged = fs.readdirSync(item.vars.target_repo);
      assert.equal(staged.includes("corpus.json"), false);
      assert.equal(staged.includes("input.json"), true);
    }
  } finally {
    if (previous === undefined) delete process.env.SCA_EVAL_RUNTIME_ROOT;
    else process.env.SCA_EVAL_RUNTIME_ROOT = previous;
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

module.exports = { resultFor };
