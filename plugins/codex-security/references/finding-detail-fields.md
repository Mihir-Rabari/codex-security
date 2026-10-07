# Rich Finding Detail Fields

For every reportable finding in `findings.json`, preserve the validated reasoning and the exact source snippets that prove it. The Codex Security workspace renders these fields directly; it does not recover missing analysis from `report.md` or read source files after the scan.

## Writing Rules

- Lead the title and `summary` with the user action and product impact.
- Use `attackPath.summary` to briefly explain how to reproduce the issue.
- Explain how the code causes that product behavior in `rootCause.summary`. Use plain language and avoid repetition.
- Wrap RPC names, functions, types, fields, parameters, configuration keys, literal identifiers, and short expressions in single backticks. For example: `route/set`, `routeName`, `destination`, and `RouteTable::set_route()`.
- Keep code out of prose. Put source snippets in `codeEvidence[].code`, then reference them from the section that explains why the snippet matters. The workspace consolidates those referenced snippets under **Root cause** so the violated invariant and its source proof stay together.
- Root cause must be a source-backed walkthrough, not a verdict paragraph. Start with the code where user-controlled data is declared, decoded, or read; follow each meaningful call, transformation, or state transition; then show the missing control, dangerous operation, and later consumer when it affects impact.
- Give each code-evidence item a stable `id`, a concise `label`, an exact source location, the smallest useful snippet, a `role`, and an `explanation`. Supported roles include `user_input`, `entrypoint`, `propagation`, `root_control`, `sink`, `outcome`, and `expected_control`.
- Write each `explanation` as connective reasoning: identify the attacker-controlled value at this step, say which callee or state receives it next, and explain why the shown lines preserve or violate the expected invariant.
- Order `rootCause.evidenceRefs` from user input to outcome. Put an `expected_control` comparison after the vulnerable call-stack refs; it is supporting context, not a step in the vulnerable stack. Omit incidental helpers that do not carry the value or enforce the relevant boundary.
- Do not use location-only filler such as "the root cause is tied to the broken control at path:line." The source table already records locations. Explain the violated invariant and show the code that violates it.
- Validation must connect attacker-controlled input, the missing or bypassed control, and the security-relevant state change or sink. Do not replace that proof with a list of file names and line numbers.
- Attack-path analysis must be concise. Record the realistic attacker boundary, the minimum trigger sequence, and the concrete outcome. Use code evidence for the important transitions instead of repeating the full validation narrative.
- Populate only evidence-backed fields. Omit unknown values instead of adding placeholders.

## Concise Workspace Projection

The finding detail view is a decision-focused projection of the canonical finding, not a copy of the full `vulnerability-writeup` report. Preserve the parts of that report that a reviewer needs to understand and act on the issue:

- the validation method, direct observations, confidence rationale, and remaining uncertainty;
- dataflow source, meaningful transformations, dangerous sink, and concrete outcome;
- realistic attacker, entry point, access requirements, preconditions, and attacker outcome;
- severity rationale plus the specific evidence that would raise or lower the rating;
- the minimal remediation invariant (`remediation`, a single string), plus `remediationTests` and `preventiveControls`, each an array of short strings with one regression test or preventive control per entry.

Keep background exposition, alternate exploit research, full PoC instructions, representative command output, and long source walkthroughs in the detailed write-up. Do not copy them into canonical fields merely to make the workspace report longer. The workspace should stay self-contained enough to support triage while avoiding duplicated or speculative prose.

The workspace **Evidence** section is an artifact navigator, not another source-proof section. When `writeup.reportPath` is present, the workbench lists that verified scan-local report plus regular files below its sibling `poc/` directory. Each row opens the exact file in the editor through a host-mediated Codex navigation request. Do not place artifact paths in root-cause prose or add an unvalidated artifact list to the canonical finding merely for display.

## Structured Example

This explicitly synthetic example describes an invented notification-routing service. All names, paths, line numbers, and snippets below are invented to illustrate the field structure and evidence ordering; they do not describe an assessed repository:

```json
{
  "summary": "The illustrative `route/set` method forwards caller-controlled `routeName` and `destination` to `RouteTable::set_route()`. Startup rejects the reserved `owner` identifier, but the runtime mutation path accepts it and replaces the destination used for owner notifications.",
  "codeEvidence": [
    {
      "id": "rpc-input",
      "label": "Caller-controlled route fields",
      "path": "src/routes/request.rs",
      "startLine": 6,
      "endLine": 10,
      "language": "rust",
      "role": "user_input",
      "code": "#[serde(rename_all = \"camelCase\")]\npub struct RouteSetParams {\n    pub route_name: String,\n    pub destination: String,\n}",
      "explanation": "`routeName` and `destination` are accepted as caller-controlled strings."
    },
    {
      "id": "rpc-forward",
      "label": "RPC forwards both fields without validation",
      "path": "src/routes/handler.rs",
      "startLine": 15,
      "endLine": 15,
      "language": "rust",
      "role": "entrypoint",
      "code": "self.routes.set_route(params.route_name, params.destination)?;",
      "explanation": "The handler passes both values directly to `set_route()` and performs no reserved-ID check."
    },
    {
      "id": "startup-reserved-check",
      "label": "Startup protects the reserved owner route",
      "path": "src/routes/table.rs",
      "startLine": 12,
      "endLine": 14,
      "language": "rust",
      "role": "expected_control",
      "code": "if route_name == \"owner\" {\n    return Err(\"route name is reserved\");\n}",
      "explanation": "Initial route construction prevents custom routes from replacing the owner notification destination."
    },
    {
      "id": "runtime-upsert",
      "label": "Runtime upsert omits the reserved-ID check",
      "path": "src/routes/table.rs",
      "startLine": 25,
      "endLine": 29,
      "language": "rust",
      "role": "root_control",
      "code": "if route_name.is_empty() {\n    return Err(\"route name cannot be empty\");\n}\nself.routes.insert(route_name, destination);\nOk(())",
      "explanation": "`set_route()` rejects only an empty ID before inserting into the shared map. Passing `owner` replaces the protected entry."
    },
    {
      "id": "default-lookup",
      "label": "Owner notifications read the overwritten map entry",
      "path": "src/routes/table.rs",
      "startLine": 35,
      "endLine": 37,
      "language": "rust",
      "role": "outcome",
      "code": "pub fn owner_destination(&self) -> Option<&String> {\n    self.routes.get(\"owner\")\n}",
      "explanation": "Notification delivery resolves the reserved `owner` ID through the mutable route map, so the replacement affects later notifications."
    }
  ],
  "rootCause": {
    "summary": "The violated invariant is that custom routes must not replace the owner notification destination. Startup enforces that invariant, but `RouteTable::set_route()` does not reuse the reserved-ID check and inserts a destination under the caller-supplied key.",
    "evidenceRefs": [
      "rpc-input",
      "rpc-forward",
      "runtime-upsert",
      "default-lookup",
      "startup-reserved-check"
    ]
  },
  "validation": {
    "method": "illustrative source trace",
    "summary": "The invented snippets show that a `route/set` caller controls both inputs, the RPC forwards them unchanged, and runtime insertion accepts `owner`.",
    "evidenceRefs": ["rpc-input", "rpc-forward", "runtime-upsert"],
    "assertions": [
      "The runtime path lacks the reserved-ID check present during startup.",
      "Inserting `owner` replaces the existing `HashMap` entry."
    ],
    "limitations": [
      "This is a synthetic teaching example; no running service or real repository was assessed."
    ]
  },
  "attackPath": {
    "summary": "In the toy service, a client permitted to configure custom routes calls `route/set` with `routeName: \"owner\"` and a destination it controls. Later owner notifications resolve the replaced map entry.",
    "dataflow": {
      "summary": "`route/set` parameters -> request handler -> `set_route()` -> shared route map -> `owner_destination()`",
      "source": "caller-controlled `routeName` and `destination`",
      "sink": "the shared route map",
      "outcome": "owner notifications use the caller-controlled destination",
      "evidenceRefs": [
        "rpc-input",
        "rpc-forward",
        "runtime-upsert",
        "default-lookup"
      ]
    },
    "reachability": {
      "summary": "The toy service permits clients to configure custom routes, while reserving owner notifications for the service owner. The client must have access to the route configuration RPC.",
      "attacker": "client permitted to configure custom routes",
      "entrypoint": "`route/set` RPC",
      "outcome": "future owner notifications are routed to the caller-controlled destination"
    },
    "evidenceRefs": ["rpc-forward", "runtime-upsert", "default-lookup"],
    "impact": {
      "level": "medium",
      "why": "Private owner notifications can be delivered to the client-controlled destination."
    },
    "likelihood": {
      "level": "medium",
      "why": "The toy service exposes route configuration to clients, but the attack requires access to that RPC."
    },
    "limitations": [
      "The example demonstrates notification redirection, not code execution."
    ]
  },
  "remediation": "Reuse the startup reserved-ID check inside `RouteTable::set_route()` so the runtime mutation path rejects the reserved `owner` identifier.",
  "remediationTests": [
    "Assert that `route/set` with `routeName: \"owner\"` returns an error.",
    "Assert that `owner_destination()` still resolves the original destination after a rejected upsert."
  ],
  "preventiveControls": [
    "Centralize reserved-identifier validation so every route mutation path shares one guard."
  ]
}
```

`rootCause.code` and `rootCause.language` remain supported for older producers that can provide only one snippet. New producers should use the shared `codeEvidence` catalog, assign call-stack roles, and order `rootCause.evidenceRefs` from input to outcome so the same exact source can support Root Cause, Validation, and Attack-path analysis without copying it into several fields.
