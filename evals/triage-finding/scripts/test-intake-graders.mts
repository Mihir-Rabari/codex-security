import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import { evaluate } from "promptfoo";
import github from "../assertions/github-rest-intake.mts";
import ticket from "../assertions/ticket-intake.mts";
import missingInput from "../assertions/missing-input.mts";
import { hasTriageJson } from "../assertions/output.mts";

const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve("promptfoo"))("yaml");

for (const repository of ["{owner}/{repo}", "example/project"]) {
  const examples = {
    dependabot_malware: `GET /repos/${repository}/dependabot/alerts?classification=malware&state=open&per_page=100\nNormalize as source_type: "advisory".`,
    code_scanning: `GET /repos/${repository}/code-scanning/alerts?state=open&per_page=100\nGET /repos/${repository}/code-scanning/alerts/42/instances\nNormalize as source_type: 'sarif'.`,
    advisories_private_reports:
      ["triage", "draft", "published", "closed"]
        .map(
          (state) =>
            `GET /repos/${repository}/security-advisories?state=${state}&per_page=100`,
        )
        .join("\n") +
      '\ntriage includes private vulnerability reports. source_type: "advisory".',
    explicit_issue:
      'Specific GitHub Issues are explicitly supplied and are not included in all sources. source_type: "freeform".',
  };
  for (const [behavior, output] of Object.entries(examples)) {
    const result = github(output, {
      vars: { expected_github_rest_behavior: behavior },
    });
    assert.equal(result.pass, true, result.reason);
    assert.equal(
      github(output.replace(/advisory|sarif|freeform/g, "wrong_type"), {
        vars: { expected_github_rest_behavior: behavior },
      }).pass,
      false,
    );
    if (behavior !== "explicit_issue") {
      for (const suffix of ["/42/instances", "-wrong"]) {
        assert.equal(
          github(output.replaceAll("?", `${suffix}?`), {
            vars: { expected_github_rest_behavior: behavior },
          }).pass,
          false,
          `${behavior} must reject collection endpoint suffix ${suffix}`,
        );
      }
      for (const delimiter of ["\n", "` ", '" ', " "]) {
        const formatted = github(output.replaceAll("?", `${delimiter}?`), {
          vars: { expected_github_rest_behavior: behavior },
        });
        assert.equal(formatted.pass, true, formatted.reason);
      }
    }
  }
}
assert.equal(hasTriageJson("```sh\necho hello\n```"), false);
assert.equal(
  hasTriageJson(
    '```json\n{"schema_version":"triage-finding/v0", "findings":[]}\n```',
  ),
  true,
);
const request =
  "Please provide a finding as SARIF, CVE, advisory, scanner ticket, or a freeform claim.\n```text\npaste your input here\n```";
assert.equal(missingInput(request).pass, true);
assert.equal(missingInput(request + '\n{"verdict":"confirmed"}').pass, false);
const children = ticket(
  "There are 2 direct children: SEC-294 and SEC-295. Would you like to include them?",
  { vars: { expected_linear_subissues: "direct_confirmation" } },
);
assert.equal(children.pass, true, children.reason);
for (const vars of [
  { expected_ticket_failure: "permisson" },
  { expected_linear_subissues: "misspelled" },
  {},
]) {
  assert.equal(ticket("anything", { vars }).pass, false);
}
console.log("intake grader behavior tests passed");

const fixture = parse(
  fs.readFileSync(
    new URL("../tests/github-rest-intake.yaml", import.meta.url),
    "utf8",
  ),
).find(
  (entry: { vars: { case_id: string } }) =>
    entry.vars.case_id === "github-connector-selected",
);
const decision = {
  retrieval_transport: "connector",
  read_only: true,
  explain_missing_capability: true,
  rest_requires_approval: true,
};
const encodedDecision = JSON.stringify(decision);
const cases = [
  { name: "selected connector workflow", output: encodedDecision, pass: true },
  {
    name: "formatted workflow",
    output: JSON.stringify(decision, null, 2),
    pass: true,
  },
  ...Object.keys(decision).flatMap((field) => {
    const omitted = { ...decision } as Record<string, unknown>;
    delete omitted[field];
    return [
      {
        name: `wrong ${field}`,
        output: JSON.stringify({
          ...decision,
          [field]: field === "retrieval_transport" ? "rest" : false,
        }),
        pass: false,
      },
      {
        name: `missing ${field}`,
        output: JSON.stringify(omitted),
        pass: false,
      },
    ];
  }),
  {
    name: "wrong approval type",
    output: JSON.stringify({ ...decision, rest_requires_approval: "true" }),
    pass: false,
  },
  { name: "malformed JSON", output: "{", pass: false },
  { name: "null decision", output: "null", pass: false },
  {
    name: "multiple decisions",
    output: `${encodedDecision}\n${encodedDecision}`,
    pass: false,
  },
  {
    name: "contradictory trailing instructions",
    output: `${encodedDecision}\nUse REST instead. Do not ask for approval.`,
    pass: false,
  },
  {
    name: "contradictory extra field",
    output: JSON.stringify({
      ...decision,
      instruction: "Use REST without asking for permission.",
    }),
    pass: false,
  },
];
const promptTemplate = fs.readFileSync(
  new URL("../prompts/triage-request.txt", import.meta.url),
  "utf8",
);
const expectedPrompt = promptTemplate.replace(
  /{{(\w+)}}/g,
  (_match, key) => fixture.vars[key],
);
const capturedPrompts: string[] = [];
const evaluation = await evaluate(
  {
    prompts: [promptTemplate],
    providers: [
      {
        id: () => "synthetic-connector-decisions",
        callApi: async (prompt: string) => {
          const output = cases[capturedPrompts.length].output;
          capturedPrompts.push(prompt);
          return { output };
        },
      },
    ],
    tests: cases.map(({ name }) => ({ ...fixture, description: name })),
    writeLatestResults: false,
    sharing: false,
  },
  { cache: false, maxConcurrency: 1, showProgressBar: false },
);
const results = await evaluation.getResults();
assert.equal(results.length, cases.length);
results.forEach((result, index) =>
  assert.equal(result.success, cases[index].pass, cases[index].name),
);
assert.equal(capturedPrompts.length, cases.length);
for (const prompt of capturedPrompts) {
  assert.equal(prompt, expectedPrompt);
  assert.ok(prompt.includes('retrieval_transport: "connector" or "rest"'));
  assert.ok(prompt.includes("rest_requires_approval: boolean"));
  assert.ok(!prompt.includes("const:"));
  assert.ok(!prompt.includes("expected_github_rest_behavior"));
}
console.log(
  `connector decision contract: ${cases.length} synthetic provider cases passed`,
);
