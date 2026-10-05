import assert from "node:assert/strict";
import github from "../assertions/github-rest-intake.mts";
import ticket from "../assertions/ticket-intake.mts";
import missingInput from "../assertions/missing-input.mts";
import { hasTriageJson } from "../assertions/output.mts";

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
  }
}
const connectorContext = {
  vars: { expected_github_rest_behavior: "connector_selected" },
};
assert.equal(
  github(
    "Use the selected GitHub Connector's read-only tools. If its retrieval capability is unavailable, explain the limitation and ask before switching to REST.",
    connectorContext,
  ).pass,
  true,
);
assert.equal(
  github(
    "Use GitHub Connector only as an auth token source. Do not use the GitHub Connector to retrieve findings; use REST.",
    connectorContext,
  ).pass,
  false,
);

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

for (const response of [
  "Use the GitHub Connector read-only tools. It has no limitation. Do not ask before switching to REST.",
  "Use the GitHub Connector read-only tools. If its capability is unavailable, do not ask before switching to REST.",
  "Use the GitHub Connector read-only tools. If its capability is unavailable, switch to REST without permission.",
])
  assert.equal(github(response, connectorContext).pass, false);

for (const prohibition of [
  "Never switch to REST without permission.",
  "Do not fall back to REST without approval.",
  "Don't use REST without permission.",
]) {
  const response = `Use the GitHub Connector read-only tools. Its retrieval capability is unavailable. ${prohibition}`;
  assert.equal(github(response, connectorContext).pass, true);
  assert.equal(
    github(`${response} Do not ask before switching to REST.`, connectorContext)
      .pass,
    false,
  );
}
