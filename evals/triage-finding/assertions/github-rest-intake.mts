import { outputText as textFor, hasTriageJson } from "./output.mts";
import type { AssertionContext } from "../types.ts";
function containsAll(text: string, patterns: RegExp[]) {
  return patterns.every((pattern) => pattern.test(text));
}

function endpointPattern(path: string, queryParts: string[] = []) {
  const escapedPath = path
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\\\{(?:owner|repo)\\\}/g, "[^/\\s?`]+");
  const queryPatterns = queryParts.map((part) => new RegExp(part, "i"));
  return (text: string) =>
    new RegExp(escapedPath, "i").test(text) && containsAll(text, queryPatterns);
}

function escapedLiteralPattern(value: unknown) {
  return new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
}

const checks = {
  choose_source: (text: string) => {
    const failures = [];
    if (!/choose|specify|which|select/i.test(text)) {
      failures.push("must ask the user to choose or specify a GitHub source");
    }
    for (const pattern of [
      /code scanning/i,
      /Dependabot/i,
      /malware/i,
      /security advisories|advisories/i,
      /private (vulnerability )?reports?|private reports?/i,
      /\ball\b/i,
    ]) {
      if (!pattern.test(text)) {
        failures.push(`missing source option matching ${pattern}`);
      }
    }
    if (hasTriageJson(text)) {
      failures.push(
        "must not emit triage JSON before a GitHub source is selected",
      );
    }
    return failures;
  },

  project_repo_inference: (text: string, context: AssertionContext) => {
    const failures = checks.choose_source(text);
    const expectedRepo = String(context.vars.expected_inferred_repo || "");

    if (
      !/Codex project.*(attached|GitHub)|attached.*Codex project|project.*attached.*GitHub/is.test(
        text,
      )
    ) {
      failures.push(
        "must say the GitHub repository is inferred from the attached Codex project",
      );
    }
    if (expectedRepo && !escapedLiteralPattern(expectedRepo).test(text)) {
      failures.push(`must include inferred GitHub repository ${expectedRepo}`);
    }
    if (
      /provide.*(owner\/repo|GitHub repository|repository URL)|ask.*(owner\/repo|GitHub repository|repository URL)/is.test(
        text,
      )
    ) {
      failures.push(
        "must not ask for a GitHub repository when the Codex project attached repo is available",
      );
    }
    return failures;
  },

  dependabot_malware: (text: string) => {
    const hasEndpoint = endpointPattern(
      "/repos/{owner}/{repo}/dependabot/alerts",
      ["classification=malware", "state=open", "per_page=100"],
    )(text);
    return [
      ...(!hasEndpoint
        ? [
            "must use Dependabot alerts endpoint with classification=malware, state=open, and per_page=100",
          ]
        : []),
      ...(!/source_type["']?\s*:\s*[`"']?advisory\b|normalize as [`"']?advisory\b/i.test(
        text,
      )
        ? ["must say Dependabot malware normalizes as advisory"]
        : []),
    ];
  },

  code_scanning: (text: string) => {
    const hasAlerts = endpointPattern(
      "/repos/{owner}/{repo}/code-scanning/alerts",
      ["state=open", "per_page=100"],
    )(text);
    const hasInstances =
      /code-scanning\/alerts\/(?:\{alert_number\}|[0-9]+)\/instances/i.test(
        text,
      );
    return [
      ...(!hasAlerts
        ? [
            "must use code scanning alerts endpoint with state=open and per_page=100",
          ]
        : []),
      ...(!hasInstances
        ? ["must fetch code scanning alert instances per alert"]
        : []),
      ...(!/source_type["']?\s*:\s*[`"']?sarif\b|normalize as [`"']?sarif\b/i.test(
        text,
      )
        ? ["must say code scanning normalizes as sarif"]
        : []),
    ];
  },

  advisories_private_reports: (text: string) => {
    const hasEndpoint = endpointPattern(
      "/repos/{owner}/{repo}/security-advisories",
      ["per_page=100"],
    )(text);
    const hasEachState = ["triage", "draft", "published", "closed"].every(
      (state) => new RegExp(`state=${state}`, "i").test(text),
    );
    return [
      ...(!hasEndpoint
        ? ["must use repository security advisories endpoint with per_page=100"]
        : []),
      ...(!hasEachState
        ? [
            "must include separate triage, draft, published, and closed advisory state requests",
          ]
        : []),
      ...(/state=\{triage\|draft\|published\|closed\}/i.test(text)
        ? [
            "must not combine advisory states in one state={triage|draft|published|closed} request",
          ]
        : []),
      ...(!/triage.*private vulnerability reports?|private vulnerability reports?.*triage/is.test(
        text,
      )
        ? ["must identify state=triage as private vulnerability reports"]
        : []),
      ...(!/source_type["']?\s*:\s*[`"']?advisory\b|normalize as [`"']?advisory\b/i.test(
        text,
      )
        ? ["must say advisories/private reports normalize as advisory"]
        : []),
    ];
  },

  connector_selected: (text: string) => {
    const fallbackInstructions = text.replace(
      /\b(?:never|not|cannot|[a-z]+n['’]t)\s+(?:\w+\s+)*(?:switch to|fall back to|use)\s+REST\s+without\s+(?:approval|permission)\b/gi,
      "",
    );
    return [
      ...(/(?:do not|don't|no need to|need not)\s+(?:ask|seek|request)[^.\n]*REST|REST[^.\n]*(?:do not|don't|no need to|need not)\s+(?:ask|seek|request)/i.test(
        text,
      ) ||
      /REST[^.\n]*without (?:approval|permission)/i.test(fallbackInstructions)
        ? ["must ask before switching to REST"]
        : []),
      ...(!/GitHub Connector|connector/i.test(text) || !/read.only/i.test(text)
        ? ["must use the selected connector's read-only tools"]
        : []),
      ...(!/cannot|unavailable|not (?:expose|support|retrieve)/i.test(text)
        ? ["must explain unavailable connector capabilities"]
        : []),
      ...(!/(?:ask|approval|permission|confirm)[\s\S]*REST|REST[\s\S]*(?:ask|approval|permission|confirm)/i.test(
        text,
      )
        ? ["must ask before switching to REST"]
        : []),
      ...(/only as an? (?:auth )?token source|do not use.*GitHub Connector.*(?:fetch|retrieve|findings)/i.test(
        text,
      )
        ? ["must honor the explicitly selected connector for retrieval"]
        : []),
    ];
  },

  explicit_issue: (text: string) => {
    return [
      ...(!/GitHub Issues?.*(explicit|specific)|specific.*GitHub Issues?/is.test(
        text,
      )
        ? [
            "must say GitHub Issues are only used when explicitly/specially provided",
          ]
        : []),
      ...(!/not.*\ball\b|exclude.*\ball\b|do not include.*\ball\b/is.test(text)
        ? [
            "must say GitHub Issues are not included in all/default source selection",
          ]
        : []),
      ...(!/source_type["']?\s*:\s*[`"']?freeform\b|normalize as [`"']?freeform\b/i.test(
        text,
      )
        ? ["must say explicit GitHub Issues normalize as freeform"]
        : []),
    ];
  },
};

export default (output: unknown, context: AssertionContext) => {
  const text = textFor(output);
  const behavior = String(context.vars.expected_github_rest_behavior || "");
  const check = checks[behavior as keyof typeof checks];
  const failures = check
    ? check(text, context)
    : [`unknown expected_github_rest_behavior: ${behavior}`];

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason:
      failures.length === 0
        ? "GitHub REST intake behavior matched."
        : failures.join("; "),
  };
};
