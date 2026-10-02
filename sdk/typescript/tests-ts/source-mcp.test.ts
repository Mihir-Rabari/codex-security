import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { stringify } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { resolveSourceMcp } from "../src/deduplication/source-mcp.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

async function sourceForTest(
  config: JsonObject,
  environment: NodeJS.ProcessEnv,
) {
  await writeFile(
    join(environment["CODEX_HOME"]!, "config.toml"),
    stringify(config),
  );
  return resolveSourceMcp("source", environment);
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

for (const transport of ["http", "stdio"] as const) {
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
        OPENAI_API_KEY: "synthetic-review-key",
        SOURCE_AUTH: "token synthetic-env-auth",
        INHERITED_SOURCE: "synthetic-inherited",
        OVERRIDDEN_SOURCE: "synthetic-ambient",
      };
      const source = await sourceForTest(
        {
          mcp_servers: {
            source: {
              startup_timeout_sec: 2,
              ...(transport === "http"
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
                      fileURLToPath(
                        new URL("fixtures/source-mcp.mjs", import.meta.url),
                      ),
                      captured,
                    ],
                    env: {
                      OPENAI_API_KEY: "synthetic-source-key",
                      CODEX_HOME: "synthetic-source-home",
                      OPTIONAL_SOURCE: "synthetic-fallback",
                      OVERRIDDEN_SOURCE: "synthetic-explicit",
                    },
                    env_vars: [
                      "OPTIONAL_SOURCE",
                      "MISSING_SOURCE",
                      "INHERITED_SOURCE",
                      "OVERRIDDEN_SOURCE",
                    ],
                  }),
            },
          },
          model_provider: "fixture",
          model_providers: {
            fixture: {
              name: "Fixture",
              wire_api: "responses",
              base_url: `${url}/v1`,
              request_max_retries: 0,
            },
          },
        },
        environment,
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
      if (transport === "http") {
        expect(authorizations.length).toBeGreaterThan(0);
        expect(new Set(authorizations)).toEqual(
          new Set(["token synthetic-env-auth"]),
        );
      } else {
        expect(JSON.parse(await readFile(captured, "utf8"))).toEqual({
          OPENAI_API_KEY: "synthetic-source-key",
          CODEX_HOME: "synthetic-source-home",
          OPTIONAL_SOURCE: "synthetic-fallback",
          INHERITED_SOURCE: "synthetic-inherited",
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
          tools: { read_source: { approval_mode: "approve" } },
        },
        unrelated: { command: "unrelated-command" },
      },
    },
    { CODEX_HOME: home, SOURCE_AUTH: "token synthetic-env-auth" },
  );
  expect(source.server).toEqual({
    url: "https://source.example.com/.api/mcp",
    http_headers: { Authorization: "token synthetic-static-auth" },
    env_http_headers: { Authorization: "SOURCE_AUTH" },
    enabled: true,
    required: true,
    default_tools_approval_mode: "prompt",
    tools: { read_source: { approval_mode: "prompt" } },
  });
  expect(source.environment).toEqual({
    SOURCE_AUTH: "token synthetic-env-auth",
  });
  await expect(
    resolveSourceMcp("missing", { CODEX_HOME: home }),
  ).rejects.toThrow("not configured");
  await expect(
    sourceForTest(
      { mcp_servers: { source: { enabled: false } } },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("disabled");
  await expect(
    sourceForTest(
      {
        mcp_servers: {
          source: {
            url: "https://source.example.com/mcp",
            env_http_headers: { Authorization: "MISSING_SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("MISSING_SOURCE_AUTH");
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
