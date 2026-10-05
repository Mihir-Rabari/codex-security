import { stripVTControlCharacters } from "node:util";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError, OutputDirectoryError } from "../src/errors.js";
import {
  warningResult,
  dependencies,
  fakeResult,
  fakeSecurity,
} from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";

import { createCliTest } from "./support/cli-run.js";

describe("CLI diagnostics", () => {
  test.each([{ flags: [] }, { flags: ["--json"] }])(
    "reports rerun history failures once: $flags",
    async ({ flags }) => {
      for (const lookupFails of [false, true]) {
        const message = lookupFails
          ? "Synthetic history failure."
          : "No completed scans found for the current repository.";
        const calls: string[] = [];
        const deps = dependencies({
          onWorkbench: (args) => {
            calls.push(args[0]!);
            if (lookupFails) throw new Error(message);
            return { scans: [] };
          },
        });
        const { stderr, runCli } = createCliTest(main);
        expect(await runCli(["scans", "rerun", ...flags], deps)).toBe(2);
        expect(stderr.text()).toBe(`codex-security: ${message}\n`);
        expect(calls).toEqual(["list-scans"]);
      }
    },
  );

  test("retains local filesystem errors through artifact failure wrappers", async () => {
    // Reading a directory produces a real local errno on the supported platforms.
    const cause = await readFile(import.meta.dir).then(
      () => {
        throw new Error("Expected a filesystem failure");
      },
      (error: unknown) => error,
    );
    const wrapped = new CodexSecurityError(
      "Could not read artifact: permission denied",
      {
        cause: new Error("Required artifact could not be read", { cause }),
      },
    );
    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async () => {
        throw wrapped;
      });
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(await runCli(["scan", ".", "--json"], deps)).toBe(2);
    expect(JSON.parse(stdout.text()).message).toBe(wrapped.message);
    expect(stderr.text()).toContain(wrapped.message);
    expect(stderr.text()).not.toContain("model access");
  });

  test.each([
    {
      command: "policy",
      args: ["policy", "--json", "--full-output"],
      structured: true,
    },
    {
      command: "suggest-owners",
      args: ["suggest-owners", "findings.json"],
      structured: false,
    },
    {
      command: "classify-severity",
      args: ["classify-severity", "--scan", "latest"],
      structured: false,
    },
    {
      command: "dedupe",
      args: [
        "dedupe",
        "--scan",
        "latest",
        "--findings-url",
        "https://example.test/findings",
      ],
      structured: false,
    },
    {
      command: "verify-fix",
      args: ["verify-fix", "Synthetic finding"],
      structured: false,
    },
    {
      command: "patch",
      args: ["patch", "Synthetic finding", "--json"],
      structured: true,
    },
    {
      command: "scan import",
      args: ["--json", "scan", "import", "--csv", "findings.csv"],
      structured: false,
    },
    {
      command: "GitHub import",
      args: ["import", "github", "example/repository"],
      structured: false,
    },
  ])(
    "escapes terminal controls in $command failures while preserving details",
    async ({ command, args, structured }) => {
      const message =
        "Operation failed: token=SYNTHETIC_VALUE\u001b[2J\ncontinued\r\ttail\u009b2J\u009d0;title\u009c";
      const fail = throwing(message);
      const deps = dependencies({ onCodex: fail, onRepositoryCommand: fail });
      deps.classifyScanSeverity = fail;
      deps.deduplicateScan = fail;
      deps.importScan = fail;
      deps.importGitHubAlerts = fail;
      if (command === "policy" || command === "suggest-owners")
        deps.currentDirectory = fail;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(args, deps)).toBe(2);
      expect(stderr.text()).toContain(
        "codex-security: Operation failed: token=SYNTHETIC_VALUE [2J continued  tail 2J 0;title \n",
      );
      expect(stderr.text()).not.toContain("\u001b");
      if (structured) {
        const result = JSON.parse(stdout.text());
        expect(result.error?.message ?? result.message).toBe(message);
      }
    },
  );

  for (const failure of [
    new CodexSecurityError("token budget exceeded"),
    new CodexSecurityError("basic validation failed"),
    new OutputDirectoryError(
      "Could not write results: token=SYNTHETIC_LOCAL_VALUE",
    ),
    new CodexSecurityError("request timed out token=SYNTHETIC_TIMEOUT_VALUE"),
  ]) {
    test(`preserves scan failure details for ${failure.message}`, async () => {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity((Promise.reject<never>).bind(Promise, failure));

      expect(await runCli(["scan", ".", "--json", "--verbose"], deps)).toBe(2);
      expect(JSON.parse(stdout.text()).message).toBe(failure.message);
      expect(stderr.text()).toContain(failure.message);
    });
  }

  test.each([
    { name: "dashboard", args: [], environment: {}, tty: true, verbose: false },
    { name: "plain", args: [], environment: {}, tty: false, verbose: false },
    {
      name: "headless",
      args: ["--headless"],
      environment: {},
      tty: true,
      verbose: false,
    },
    {
      name: "verbose flag",
      args: ["--verbose"],
      environment: {},
      tty: true,
      verbose: true,
    },
    {
      name: "debug environment",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: "  DeBuG  " },
      tty: true,
      verbose: true,
    },
    {
      name: "shared debug fallback",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: " ", LOG_LEVEL: " DEBUG " },
      tty: false,
      verbose: true,
    },
    {
      name: "dedicated level precedence",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: "info", LOG_LEVEL: "debug" },
      tty: false,
      verbose: false,
    },
    {
      name: "verbose flag precedence",
      args: ["--verbose"],
      environment: { CODEX_SECURITY_LOG_LEVEL: "error", LOG_LEVEL: "warn" },
      tty: false,
      verbose: true,
    },
  ])("preserves warning details and verbosity for $name", async (mode) => {
    const warning = "recoverable warning: token=SYNTHETIC_WARNING_VALUE";
    const observer = "observer failure: token=SYNTHETIC_OBSERVER_VALUE";
    const { stderr, runCli } = createCliTest(main, {
      stderr: mode.tty,
    });

    const result = fakeResult([], "complete", {
      input_tokens: 200,
      cached_input_tokens: 20,
      output_tokens: 10,
    });
    const deps = dependencies({
      environment: { ...mode.environment, NO_COLOR: "1" },
    });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onScanStarted?.();
        options?.onCost?.(result.cost!);
        options?.onWarning?.(warning);
        options?.onObserverError?.("onWorkerStatus", new Error(observer));
        return result;
      });

    expect(await runCli(["scan", ".", ...mode.args], deps)).toBe(0);
    const output = stripVTControlCharacters(stderr.text()).replace(
      /\s+/gu,
      " ",
    );
    expect(output).toContain(`codex-security: warning: ${warning}`);
    expect(output).toContain(`onWorkerStatus observer failed: ${observer}`);
    expect(output.includes("codex-security: debug:")).toBe(mode.verbose);
    if (mode.verbose) {
      expect(output).toContain(
        `codex-security: debug: scan.warning message=${JSON.stringify(warning)}`,
      );
      expect(output).toContain(
        'authentication.selected requested="auto" method="api_key" source="OPENAI_API_KEY" verified=false',
      );
      expect(output).toContain("input_tokens=200 cached_input_tokens=20");
      expect(output).toContain(
        'scan.observer_failed observer="onWorkerStatus" classification="unknown"',
      );
    }
  });

  test("preserves target warning details in diagnostics and result data", async () => {
    const warning = "Source changed: token=SYNTHETIC_TARGET_VALUE";
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () => fakeSecurity(warningResult(warning, true));
    expect(await runCli(["scan", ".", "--json", "--verbose"], deps)).toBe(2);
    expect(JSON.parse(stdout.text()).warnings).toEqual([warning]);
    expect(stderr.text()).toContain(`codex-security: warning: ${warning}`);
  });

  test("preserves live activity and observer messages", async () => {
    const activity = "command result: token=SYNTHETIC_ACTIVITY_VALUE";
    const observer = "observer result: token=SYNTHETIC_OBSERVER_VALUE";
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const deps = dependencies({ environment: { NO_COLOR: "1" } });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onScanStarted?.();
        options?.onActivity?.({
          id: "synthetic-command",
          kind: "command",
          status: "completed",
          description: activity,
          paths: [],
        });
        options?.onObserverError?.("onWorkerStatus", new Error(observer));
        return fakeResult();
      });

    expect(await runCli(["scan", "."], deps)).toBe(0);
    const output = stripVTControlCharacters(stderr.text()).replace(
      /\s+/gu,
      " ",
    );
    expect(output).toContain(activity);
    expect(output).toContain(observer);
    expect(stderr.text()).toContain("\u001B[?1049h");
    expect(stderr.text()).toContain("\u001B[?1049l");
  });
});

test.each([
  { args: ["scans", "resume", "saved"] },
  { args: ["scans", "rerun", "saved"] },
  { args: ["scans", "rerun"] },
])("$args emits structured lookup failures", async ({ args }) => {
  for (const flags of [
    ["--json"],
    ["--format", "jsonl"],
    ["--json", "--full-output"],
  ]) {
    const { stdout, stderr, runCli } = createCliTest(main);
    const code = await runCli(
      [...args, ...flags],
      dependencies({
        onWorkbench: throwing("Synthetic saved scan lookup failure"),
      }),
    );
    expect(code).toBe(2);
    const output = JSON.parse(stdout.text());
    expect(output.error?.message ?? output.message).toBe(
      "Synthetic saved scan lookup failure",
    );
    expect(stderr.text()).toContain("Synthetic saved scan lookup failure");
  }
});

test("saved resume rejects Markdown before loading state", async () => {
  const { stderr, runCli } = createCliTest(main);
  const code = await runCli(
    ["scans", "resume", "saved", "--format", "md"],
    dependencies({
      onWorkbench: throwing("Must not load state"),
    }),
  );
  expect(code).toBe(2);
  expect(stderr.text()).toContain("Markdown output is not supported");
});

test.each([
  { args: ["classify-severity", "--scan", "--rubric", "rules.md"] },
  {
    args: [
      "dedupe",
      "--scan",
      "--findings-url",
      "https://example.test/findings",
    ],
  },
])("requires values for saved scan selectors in $args", async ({ args }) => {
  const { stderr, runCli } = createCliTest(main);
  expect(await runCli(args, dependencies())).toBe(2);
  expect(stderr.text()).toContain("Missing value for flag: --scan");
});

test.each(["authentication", "patch review"])(
  "treats dismissed %s prompts as cancellation",
  async (stage) => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
    const error = new Error("User dismissed the prompt");
    error.name = "ExitPromptError";
    const deps = dependencies({
      environment: { OPENAI_API_KEY: "synthetic-key" },
    });
    if (stage === "authentication") {
      deps.hasStoredChatGPTSignIn = async () => true;
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: async () => {
          throw error;
        },
      };
    } else {
      deps.createSecurity = () =>
        fakeSecurity(async () => fakeResult(["high"]));
      deps.confirmPatchReview = async () => {
        throw error;
      };
      deps.patchEditor = async () => null;
    }
    expect(await runCli(["scan", "--format", "toon"], deps)).toBe(130);
    expect(stderr.text()).toContain("canceled");
    if (stage === "patch review") expect(stdout.text()).toContain("manifest:");
  },
);

test("uses stored API-key advice for a forbidden model request", async () => {
  const { stderr, runCli } = createCliTest(main);
  const deps = dependencies();
  deps.createSecurity = () =>
    fakeSecurity(async (_repository, options) => {
      options?.onAuthentication?.({
        method: "stored_credentials",
        credentialType: "api_key",
        verified: false,
      });
      throw new Error("403 model access denied");
    });
  expect(await runCli(["scan", "--json"], deps)).toBe(2);
  expect(stderr.text()).toContain("stored API key");
  expect(stderr.text()).not.toContain("stored ChatGPT credentials");
});

test.each(["resume", "rerun"])(
  "saved %s honors structured output on a terminal",
  async (command) => {
    for (const flags of [["--json"], ["--format", "jsonl"], []]) {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
      const code = await runCli(
        ["scans", command, "saved", ...flags],
        dependencies({
          onWorkbench: () => ({
            scanId: "saved-canonical",
            scanDir: "/synthetic/scan-output",
            recipe: {
              repository: "/synthetic/repository",
              target: { kind: "repository", paths: [] },
              mode: "deep",
              config: {},
            },
          }),
        }),
      );
      expect(code, stderr.text()).toBe(0);
      if (flags.length > 0) {
        expect(JSON.parse(stdout.text())).toHaveProperty("manifest");
        expect(stderr.text()).not.toContain("\u001b[?1049h");
      } else expect(stdout.text()).toBe("");
    }
  },
);
