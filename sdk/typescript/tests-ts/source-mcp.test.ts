import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { stringify } from "smol-toml";
import type { JsonObject, JsonValue } from "../src/config.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "../src/deduplication/checkpointed-review.js";
import { checkpointWorkbench } from "./support/workbench-fakes.js";
import {
  CodexReviewRunner,
  type CodexReview,
} from "../src/deduplication/codex-review.js";
import { resolveSourceMcp } from "../src/deduplication/source-mcp.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

async function sourceForTest(
  config: JsonObject,
  environment: NodeJS.ProcessEnv,
  repository = process.cwd(),
) {
  await writeFile(
    join(environment["CODEX_HOME"]!, "config.toml"),
    stringify(config),
  );
  return resolveSourceMcp(
    "source",
    {
      CODEX_SECURITY_STATE_DIR: join(environment["CODEX_HOME"]!, "state"),
      ...environment,
    },
    undefined,
    repository,
  );
}

async function sourceCheckout() {
  const repository = await temporaryDirectory();
  execFileSync("git", ["init", "-q", repository]);
  execFileSync("git", [
    "-C",
    repository,
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.com",
    "commit",
    "--allow-empty",
    "-qm",
    "source fixture",
  ]);
  execFileSync("git", [
    "-C",
    repository,
    "remote",
    "add",
    "origin",
    "https://git.example.com/team/repo.git",
  ]);
  return repository;
}

for (const transport of [
  "http",
  "http-static",
  "stdio",
  "stdio-relative",
  "stdio-absolute",
  "stdio-credentials",
] as const) {
  test(`native dedupe keeps ${transport} source configuration at its process boundary`, async () => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    const captured = join(home, "mcp-environment.json");
    let modelRequests = 0;
    const authorizations: (string | undefined)[] = [];
    const server = createServer((request, response) => {
      if (request.url?.startsWith("/mcp")) {
        authorizations.push(request.headers.authorization);
        response.writeHead(503).end("Synthetic source server unavailable");
      } else {
        if (request.url?.includes("responses")) modelRequests++;
        response
          .writeHead(200, { "Content-Type": "application/json" })
          .end('{"data":[]}');
      }
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address() as { port: number };
    const url = `http://127.0.0.1:${address.port}`;
    try {
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
        ...(transport === "stdio-credentials"
          ? {}
          : { OPENAI_API_KEY: "synthetic-review-key" }),
        ...(transport === "http-static"
          ? {}
          : { SOURCE_AUTH: "token synthetic-env-auth" }),
        INHERITED_SOURCE: "synthetic-inherited",
        OBJECT_SOURCE: "synthetic-object",
        IMPLICIT_SOURCE: "synthetic-implicit",
        OVERRIDDEN_SOURCE: "synthetic-ambient",
      };
      const inheritedSource: JsonValue[] = [
        "OPTIONAL_SOURCE",
        "MISSING_SOURCE",
        "CODEX_SQLITE_HOME",
        "INHERITED_SOURCE",
        "OVERRIDDEN_SOURCE",
        { name: "OBJECT_SOURCE", source: "local" },
        { name: "IMPLICIT_SOURCE" },
      ];
      const provider = {
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      };
      const configuration: JsonObject = {
        mcp_servers: {
          source: {
            startup_timeout_sec: 2,
            ...(["stdio-absolute", "stdio-credentials"].includes(transport)
              ? { tool_timeout_sec: 12.5 }
              : {}),
            ...(!transport.startsWith("stdio")
              ? {
                  url: `${url}/mcp`,
                  http_headers: {
                    Authorization: "token synthetic-static-auth",
                  },
                  env_http_headers: { Authorization: "SOURCE_AUTH" },
                }
              : {
                  command: process.execPath,
                  args: [
                    relative(
                      repository,
                      fileURLToPath(
                        new URL("fixtures/source-mcp.mjs", import.meta.url),
                      ),
                    ),
                    captured,
                  ],
                  ...(transport === "stdio-relative"
                    ? { cwd: relative(process.cwd(), repository) }
                    : transport === "stdio-absolute"
                      ? { cwd: repository }
                      : {}),
                  env: {
                    OPENAI_API_KEY: "synthetic-source-key",
                    CODEX_HOME: "synthetic-source-home",
                    OPTIONAL_SOURCE: "synthetic-fallback",
                    [process.platform === "win32"
                      ? "overridden_source"
                      : "OVERRIDDEN_SOURCE"]: "synthetic-explicit",
                  },
                  env_vars: inheritedSource,
                }),
          },
        },
        ...provider,
      };
      if (transport === "stdio-credentials") {
        const credentialHome = join(home, "state", "codex-home");
        await mkdir(credentialHome, { recursive: true, mode: 0o700 });
        await writeFile(
          join(credentialHome, "auth.json"),
          JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
          { mode: 0o600 },
        );
        await writeFile(
          join(credentialHome, "config.toml"),
          stringify(configuration),
          { mode: 0o600 },
        );
      }
      const source = await sourceForTest(
        configuration,
        environment,
        repository,
      );
      expect(source.server["tool_timeout_sec"]).toBe(
        ["stdio-absolute", "stdio-credentials"].includes(transport)
          ? 12.5
          : undefined,
      );
      const runner = new CodexReviewRunner(
        environment,
        undefined,
        AbortSignal.timeout(15_000),
        repository,
        undefined,
        source,
      );
      await expect(
        runner.run({
          stage: "pair-review",
          model: "gpt-5.6-sol",
          effort: "low",
          prompt: "Read source using the required MCP server.",
          schema: { type: "object" },
          validate: (value) => value,
        }),
      ).rejects.toThrow(/required.*source|source.*required/i);
      expect(modelRequests).toBe(0);
      if (!transport.startsWith("stdio")) {
        expect(authorizations.length).toBeGreaterThan(0);
        expect(new Set(authorizations)).toEqual(
          new Set([
            transport === "http-static"
              ? "token synthetic-static-auth"
              : "token synthetic-env-auth",
          ]),
        );
      } else {
        const child = JSON.parse(await readFile(captured, "utf8"));
        expect(await realpath(child.cwd)).toBe(await realpath(repository));
        expect(source.server["env"]).toEqual(child.environment);
        expect(child.environment).toEqual({
          OPENAI_API_KEY: "synthetic-source-key",
          CODEX_HOME: "synthetic-source-home",
          OPTIONAL_SOURCE: "synthetic-fallback",
          INHERITED_SOURCE: "synthetic-inherited",
          OBJECT_SOURCE: "synthetic-object",
          IMPLICIT_SOURCE: "synthetic-implicit",
          OVERRIDDEN_SOURCE: "synthetic-explicit",
        });
      }
    } finally {
      const closed = new Promise<void>((resolve) =>
        server.close(() => resolve()),
      );
      server.closeAllConnections();
      await closed;
    }
  });
}

test("source MCP preserves native settings and requires an enabled configured server", async () => {
  const home = await temporaryDirectory();
  const source = await sourceForTest(
    {
      mcp_servers: {
        source: {
          url: "https://source.example.com/.api/mcp",
          http_headers: { Authorization: "token synthetic-static-auth" },
          env_http_headers: { Authorization: "SOURCE_AUTH" },
          default_tools_approval_mode: "approve",
          tools: {
            read_source: { approval_mode: "approve", output_token_limit: 321 },
          },
        },
        unrelated: { command: "unrelated-command" },
      },
    },
    { CODEX_HOME: home, SOURCE_AUTH: "token synthetic-env-auth" },
  );
  expect(source.server).toMatchObject({
    url: "https://source.example.com/.api/mcp",
    http_headers: { Authorization: "token synthetic-static-auth" },
    env_http_headers: { Authorization: "SOURCE_AUTH" },
    enabled: true,
    required: true,
    default_tools_approval_mode: "prompt",
    tools: {
      read_source: { approval_mode: "prompt", output_token_limit: 321 },
    },
  });
  expect(source.environment).toEqual({
    SOURCE_AUTH: "token synthetic-env-auth",
  });
  await expect(
    resolveSourceMcp("missing", { CODEX_HOME: home }),
  ).rejects.toThrow("not configured");
  await expect(
    sourceForTest(
      {
        mcp_servers: {
          source: { command: "synthetic-command", enabled: false },
        },
      },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("disabled");
  const optional = await sourceForTest(
    {
      mcp_servers: {
        source: {
          url: "https://source.example.com/mcp",
          env_http_headers: { Authorization: "MISSING_SOURCE_AUTH" },
        },
      },
    },
    { CODEX_HOME: home },
  );
  expect(optional.environment).toEqual({});
  expect(optional.server["env_http_headers"]).toEqual({
    Authorization: "MISSING_SOURCE_AUTH",
  });
});

test.skipIf(process.platform !== "win32")(
  "source credentials preserve inherited Windows environment aliases",
  async () => {
    const home = await temporaryDirectory();
    const source = await sourceForTest(
      {
        mcp_servers: {
          source: {
            url: "https://source.example.com/mcp",
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, source_auth: "token synthetic-source-auth" },
    );
    expect(source.environment).toEqual({
      SOURCE_AUTH: "token synthetic-source-auth",
      source_auth: "token synthetic-source-auth",
    });
  },
);

test("source MCP leaves remote environment resolution to Codex", async () => {
  const home = await temporaryDirectory();
  const env_vars = [{ name: "REMOTE_SOURCE", source: "remote" }];
  const source = await sourceForTest(
    { mcp_servers: { source: { command: "synthetic-command", env_vars } } },
    { CODEX_HOME: home, REMOTE_SOURCE: "synthetic-local-value" },
  );
  expect(source.server["env_vars"]).toEqual(env_vars);
  expect(source.server["env"]).toBeUndefined();
  expect(source.environment).toEqual({});
});

test.each([
  "environment",
  "project-environment",
  "credential-environment",
  "origin",
])("rechecks resumed reviews after source MCP %s changes", async (changed) => {
  const home = await temporaryDirectory();
  const repository = await sourceCheckout();
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: join(home, "state"),
    SOURCE_ROOT: "synthetic-source-root",
  };
  if (changed === "project-environment") {
    await mkdir(join(repository, ".codex"));
    await writeFile(
      join(repository, ".codex", "config.toml"),
      stringify({
        mcp_servers: { source: { env_vars: ["SOURCE_ROOT"] } },
      }),
    );
  }
  if (changed === "credential-environment") {
    const credentialHome = join(home, "state", "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    await writeFile(
      join(credentialHome, "auth.json"),
      JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
      { mode: 0o600 },
    );
    await writeFile(
      join(credentialHome, "config.toml"),
      stringify({
        mcp_servers: {
          source: {
            command: "synthetic-source-command",
            env_vars: ["SOURCE_ROOT"],
          },
        },
      }),
      { mode: 0o600 },
    );
  }
  await sourceForTest(
    {
      projects: { [repository]: { trust_level: "trusted" } },
      mcp_servers: {
        source: {
          command: "synthetic-source-command",
          ...(changed === "project-environment"
            ? {}
            : { env_vars: ["SOURCE_ROOT"] }),
        },
      },
    },
    environment,
    repository,
  );
  const store = checkpointWorkbench("source-context", { repository });
  const workflow = new FindingWorkflow(
    "source-context",
    environment,
    store.run,
  );
  let calls = 0;
  const runner = {
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls++;
      return review.validate({ decision: "SAME" });
    },
  };
  const review: CodexReview<{ decision: string }> = {
    stage: "pair-review",
    model: "gpt-5.6-sol",
    effort: "low",
    prompt: "Review the synthetic findings.",
    schema: { type: "object" },
    validate: () => ({ decision: "SAME" }),
  };
  const checkpoint = async () =>
    new CheckpointedReviewRunner(
      workflow,
      runner,
      await workflow.sourceSnapshot(repository),
      { allRepositories: true },
      await reviewSettingsDigest(environment, {
        mcp: await resolveSourceMcp(
          "source",
          environment,
          undefined,
          repository,
        ),
        repository,
      }),
    );
  await (await checkpoint()).run(review);
  await (await checkpoint()).run(review);
  expect(calls).toBe(1);
  if (changed !== "origin") environment.SOURCE_ROOT = "changed-source-root";
  else
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "set-url",
      "origin",
      "https://git.example.com/team/other.git",
    ]);
  await (await checkpoint()).run(review);
  expect(calls).toBe(2);
});

test.each(["cancel", "configuration-error"])(
  "source configuration %s preserves diagnostics and closes the native child",
  async (scenario) => {
    const home = await temporaryDirectory();
    const repository = await sourceCheckout();
    await writeFile(
      join(home, "config.toml"),
      stringify({
        projects: { [repository]: { trust_level: "trusted" } },
        mcp_servers: { source: { command: "synthetic-source-command" } },
      }),
    );
    if (scenario === "configuration-error") {
      await mkdir(join(repository, ".codex"));
      await writeFile(
        join(repository, ".codex", "config.toml"),
        stringify({
          mcp_servers: {
            source: { default_tools_approval_mode: "synthetic-invalid-mode" },
          },
        }),
      );
    }
    const controller = new AbortController();
    const cancellation = new Error(
      "synthetic source configuration cancellation",
    );
    let child: ChildProcessWithoutNullStreams | undefined;
    let directory: string | undefined;
    const result = resolveSourceMcp(
      "source",
      {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: relative(process.cwd(), home),
        CODEX_SECURITY_STATE_DIR: join(home, "state"),
      },
      controller.signal,
      repository,
      (command, args, options) => {
        directory = String(options.cwd);
        expect(options.env!["CODEX_HOME"]).toBe(home);
        child = spawn(command, args, options);
        if (scenario === "cancel")
          child.once("spawn", () => controller.abort(cancellation));
        return child;
      },
    );
    if (scenario === "cancel") await expect(result).rejects.toBe(cancellation);
    else await expect(result).rejects.toThrow("synthetic-invalid-mode");
    expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
    expect(existsSync(directory!)).toBe(false);
  },
);

test("source configuration preserves caller-relative auth helper context", async () => {
  const home = await temporaryDirectory();
  const tools = join(home, "auth-tools");
  await mkdir(tools);
  const captured = join(home, "auth.json.capture");
  await writeFile(
    join(tools, "auth.mjs"),
    `
    import {writeFileSync} from "node:fs";
    writeFileSync(process.argv[2], JSON.stringify({cwd: process.cwd(), home: process.env.CODEX_HOME, value: process.env.SYNTHETIC_AUTH_VALUE}));
    console.log("synthetic-provider-token");
  `,
  );
  const config = {
    model_provider: "fixture",
    model_providers: {
      fixture: {
        name: "Fixture",
        wire_api: "responses",
        base_url: "http://127.0.0.1:9/v1",
        request_max_retries: 0,
        auth: {
          command: process.execPath,
          args: ["auth.mjs", captured],
          cwd: "auth-tools",
        },
      },
    },
    mcp_servers: { source: { command: "synthetic-source-command" } },
  };
  await writeFile(join(home, "config.toml"), stringify(config));
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: relative(process.cwd(), home),
    SYNTHETIC_AUTH_VALUE: "synthetic-caller-value",
  };
  await resolveSourceMcp("source", environment);
  const actual = JSON.parse(await readFile(captured, "utf8"));
  expect(await realpath(actual.cwd)).toBe(await realpath(tools));
  expect(await realpath(actual.home)).toBe(await realpath(home));
  expect(actual.value).toBe("synthetic-caller-value");
  expect(environment.CODEX_HOME).toBe(relative(process.cwd(), home));
});

test.each(["http", "stdio"])(
  "source MCP rejects conflicting %s connections across credential homes before startup",
  async (transport) => {
    const home = await temporaryDirectory();
    const credentialHome = join(home, "state", "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    await writeFile(
      join(credentialHome, "auth.json"),
      JSON.stringify({ OPENAI_API_KEY: "synthetic-stored-key" }),
      { mode: 0o600 },
    );
    let sourceRequests = 0;
    const endpoint = createServer((request, response) => {
      if (request.url?.startsWith("/mcp")) sourceRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    });
    await new Promise<void>((resolve) =>
      endpoint.listen(0, "127.0.0.1", resolve),
    );
    const url = `http://127.0.0.1:${(endpoint.address() as { port: number }).port}`;
    try {
      const provider = {
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      };
      const storedConfig = stringify({
        ...provider,
        mcp_servers: {
          source: {
            url: `${url}/mcp/stored`,
            http_headers: { Authorization: "synthetic-stored-source-auth" },
          },
        },
      });
      await writeFile(join(credentialHome, "config.toml"), storedConfig, {
        mode: 0o600,
      });
      await expect(
        sourceForTest(
          {
            ...provider,
            mcp_servers: {
              source:
                transport === "http"
                  ? { url: `${url}/mcp/selected` }
                  : { command: "synthetic-source-command" },
            },
          },
          {
            PATH: process.env["PATH"],
            SystemRoot: process.env["SystemRoot"],
            CODEX_HOME: home,
            CODEX_SECURITY_STATE_DIR: join(home, "state"),
          },
        ),
      ).rejects.toThrow("conflicting definitions");
      expect(sourceRequests).toBe(0);
      expect(await readFile(join(credentialHome, "config.toml"), "utf8")).toBe(
        storedConfig,
      );
    } finally {
      const closed = new Promise<void>((resolve) =>
        endpoint.close(() => resolve()),
      );
      endpoint.closeAllConnections();
      await closed;
    }
  },
);

test.each(["C:\\source", "/srv/source"])(
  "source MCP preserves executor-owned cwd %s",
  async (cwd) => {
    const home = await temporaryDirectory();
    const source = await sourceForTest(
      {
        mcp_servers: {
          source: {
            command: "synthetic-source-command",
            environment_id: "synthetic-executor",
            cwd,
          },
        },
      },
      { CODEX_HOME: home },
    );
    expect(source.server["cwd"]).toBe(cwd);
    expect(source.server["environment_id"]).toBe("synthetic-executor");
  },
);
