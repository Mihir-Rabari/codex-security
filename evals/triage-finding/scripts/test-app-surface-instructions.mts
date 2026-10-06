import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const pluginRoot = path.resolve(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "plugins",
  "codex-security",
);
const skillRoot = path.join(pluginRoot, "skills", "triage-finding");
const skillPath = path.join(skillRoot, "SKILL.md");
const skill = fs.readFileSync(skillPath, "utf8");
const ticketIntakePath = path.join(skillRoot, "references", "ticket-intake.md");
const ticketIntake = fs.readFileSync(ticketIntakePath, "utf8");
const agentPath = path.join(skillRoot, "agents", "openai.yaml");
const agent = fs.readFileSync(agentPath, "utf8");
const pluginPath = path.join(pluginRoot, ".codex-plugin", "plugin.json");
const plugin = JSON.parse(fs.readFileSync(pluginPath, "utf8"));

assert.match(skill, /### Jira and Linear intake/);
assert.match(skill, /references\/ticket-intake\.md/);
assert.match(ticketIntake, /Atlassian[\s\S]*JQL/);
assert.match(ticketIntake, /natural-language search[\s\S]*discover[\s\S]*JQL/);
assert.match(skill, /security or vulnerability Jira\/Linear tickets/);
assert.match(skill, /Atlassian and Linear mentions are connector hints/);
assert.match(skill, /generic ticket or duplicate triage/);
assert.match(
  ticketIntake,
  /Normalize Jira and Linear vulnerability tickets as `source_type: "scanner_ticket"`/,
);
assert.match(
  ticketIntake,
  /issue key[\s\S]*URL[\s\S]*project[\s\S]*status[\s\S]*labels[\s\S]*components[\s\S]*priority/,
);
assert.match(
  ticketIntake,
  /Default to read-only import and triage[\s\S]*Do not add comments, transition or close issues, assign owners, or change labels/,
);
assert.match(agent, /default_prompt:.*Use \$triage-finding/);
assert.match(ticketIntake, /missing connector|connector.*unavailable/i);
assert.match(ticketIntake, /authentication|reauthorize/i);
assert.match(ticketIntake, /insufficient permission|request access/i);
assert.match(ticketIntake, /not found|inaccessible/i);
assert.match(ticketIntake, /transient/i);
assert.match(ticketIntake, /retry the identical read once/i);
assert.match(ticketIntake, /do not inspect the repository/i);
assert.match(ticketIntake, /do not[\s\S]*emit[\s\S]*triage-finding\/v0/i);
assert.match(ticketIntake, /list[\s\S]*direct children[\s\S]*parent/i);
assert.match(ticketIntake, /exhaust[\s\S]*pag(?:es|ination)/i);
assert.match(ticketIntake, /identifiers?[\s\S]*titles?[\s\S]*count/i);
assert.match(ticketIntake, /ask[\s\S]*before[\s\S]*full[\s\S]*content/i);
assert.match(ticketIntake, /repeat[\s\S]*next depth/i);
assert.match(ticketIntake, /independent vulnerability claim/i);
assert.match(ticketIntake, /ambiguous[\s\S]*ask/i);
assert.match(ticketIntake, /deterministic[\s\S]*tree order/i);
assert.equal(plugin.interface.defaultPrompt.length, 3);
assert(
  plugin.interface.defaultPrompt.every(
    (prompt: string) => [...prompt].length <= 128,
  ),
);
assert(
  plugin.interface.defaultPrompt.includes(
    "Triage existing security findings against this repository.",
  ),
);

import githubIntake from "../assertions/github-rest-intake.mts";
const connectorContext = {
  vars: {
    expected_github_rest_behavior: "explicit_connector",
    target_repo: "https://github.com/promptfoo/promptfoo",
  },
};
const connectorDecision = {
  transport: "github_connector_read_only",
  fallback: "explain_and_request_rest_approval",
  scope: {
    account: "user_specified_or_approved",
    repository: "promptfoo/promptfoo",
  },
};
for (const answer of [
  JSON.stringify(connectorDecision),
  `Decision for /repos/{owner}/{repo}/code-scanning/alerts:\n\`\`\`json\n${JSON.stringify(connectorDecision, null, 2)}\n\`\`\``,
  `Use the connector [1](references/github-rest-intake.md).\n${JSON.stringify(connectorDecision)}`,
  `Use the connector [1](references/github-rest-intake.md).\n\`\`\`json\n${JSON.stringify(connectorDecision)}\n\`\`\``,
  `Use the connector [1][transport].\n${JSON.stringify(connectorDecision)}`,
  `Use the connector [1][1].\n${JSON.stringify(connectorDecision)}`,
  `Use the connector [1][].\n${JSON.stringify(connectorDecision)}`,
  `Use the connector.\n[1]: references/github-rest-intake.md\n${JSON.stringify(connectorDecision)}`,
  `Use the connector [1].\n[1]: references/github-rest-intake.md\n${JSON.stringify(connectorDecision)}`,
  `Use the connector [1].\n[1]:\n  references/github-rest-intake.md\n${JSON.stringify(connectorDecision)}`,
]) {
  const result = githubIntake(answer, connectorContext);
  assert.equal(result.pass, true, result.reason);
}
for (const wrongDecision of [
  { transport: "rest" },
  { transport: "other" },
  { fallback: "automatic_rest" },
  { fallback: "stop" },
  { fallback: undefined },
  { scope: { ...connectorDecision.scope, account: "any" } },
  { scope: { ...connectorDecision.scope, repository: "example/other-repo" } },
]) {
  const answer = JSON.stringify({ ...connectorDecision, ...wrongDecision });
  assert.equal(githubIntake(answer, connectorContext).pass, false, answer);
}
assert.equal(githubIntake("{invalid JSON}", connectorContext).pass, false);

const defaultContext = {
  vars: { expected_github_rest_behavior: "default_rest" },
};
for (const transport of ["rest", "github_connector_read_only", "other"]) {
  assert.equal(
    githubIntake(JSON.stringify({ transport }), defaultContext).pass,
    transport === "rest",
  );
}
assert.equal(
  githubIntake('{"transport":"rest"}\n{"transport":"other"}', defaultContext).pass,
  false,
);

for (const answer of [
  JSON.stringify({
    ...connectorDecision,
    triage_result: { schema_version: "triage-finding/v0", findings: [] },
  }),
  JSON.stringify({
    ...connectorDecision,
    extra: [{ result: { schema_version: "triage-finding/v0", findings: [] } }],
  }),
  JSON.stringify([connectorDecision]),
  `\`\`\`json\n${JSON.stringify([connectorDecision])}\n\`\`\``,
  `${JSON.stringify(connectorDecision)}\n${JSON.stringify({ schema_version: "triage-finding/v0", findings: [] })}`,
  `${JSON.stringify(connectorDecision)}\n[1]`,
  `${JSON.stringify(connectorDecision)}\n[1]\n\`\`\`text\n[1]: references/github-rest-intake.md\n\`\`\``,
  `${JSON.stringify(connectorDecision)}\n[1]: references/github-rest-intake.md\n~~~json\n[1]\n~~~`,
  `${JSON.stringify(connectorDecision)}\n\`\`\`json\n[1][]\n\`\`\``,
  `${JSON.stringify(connectorDecision)}\n\`\`\`json\n[1][{"transport":"rest"}]\n\`\`\``,
  `Use the connector [1].\n[1]: references/github-rest-intake.md\n${JSON.stringify(connectorDecision)}\n\`\`\`json\n[1]\n\`\`\``,
  `\`\`\`json\n${JSON.stringify(connectorDecision)}\n\`\`\`\n\`\`\`json\n${JSON.stringify({ schema_version: "triage-finding/v0", findings: [] })}\n\`\`\``,
]) {
  assert.equal(githubIntake(answer, connectorContext).pass, false, answer);
}

for (const fenced of [
  [true, true],
  [true, false],
  [false, true],
]) {
  const conflictingDecisions = [
    connectorDecision,
    { ...connectorDecision, transport: "rest" },
  ]
    .map((decision, index) =>
      fenced[index]
        ? `\`\`\`json\n${JSON.stringify(decision)}\n\`\`\``
        : JSON.stringify(decision),
    )
    .join("\n");
  assert.equal(
    githubIntake(
      `Endpoint: /repos/{owner}/{repo}/code-scanning/alerts\n${conflictingDecisions}`,
      connectorContext,
    ).pass,
    false,
  );
}

const intakeCases = fs.readFileSync(
  path.join(import.meta.dirname, "../tests/github-rest-intake.yaml"),
  "utf8",
);
const connectorMatch = intakeCases.match(
  /case_id: github-explicit-connector[\s\S]*?(?=\n- description:|$)/,
);
assert(connectorMatch);
const connectorCase = connectorMatch[0];
assert.match(connectorCase, /finding_input:.*code scanning/i);
