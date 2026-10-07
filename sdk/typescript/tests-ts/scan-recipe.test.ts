import { createCliTest } from "./support/cli-run.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { runWorkbench } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import {
  EXTERNAL_CODEX_PROVIDERS,
  mergedCodexConfig,
  type JsonObject,
} from "../src/config.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(
  (["openrouter", "fireworks"] as const).flatMap((provider) =>
    (["standard", "deep"] as const).flatMap((mode) =>
      ["partial", "different-key"].map((profileKind) => ({
        provider,
        mode,
        profileKind,
      })),
    ),
  ),
)(
  "saved launches retain explicit standard provider refinements: %j",
  async ({ provider, mode, profileKind }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "profile-home");
    const runtimeHome = join(root, "runtime-home");
    await Promise.all([mkdir(repository), mkdir(home), mkdir(runtimeHome)]);
    await writeFile(join(repository, "fixture.py"), "value = 1\n");
    await writeFile(
      join(home, "review.config.toml"),
      `model="synthetic-model"\nmodel_provider="${provider}"\n[model_providers.${provider}]\n` +
        (profileKind === "partial"
          ? "request_max_retries=4\n"
          : 'env_key="SYNTHETIC_OLD_PROVIDER_KEY"\n'),
    );
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const standard = EXTERNAL_CODEX_PROVIDERS[provider];
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      [standard.env_key]: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const overrides = {
      profile: "review",
      model_provider: provider,
      model_providers: { [provider]: standard },
    };
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, codexOverrides: overrides },
      {
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(runtimeHome),
          deepScanConfigPath: join(runtimeHome, "deep-scan-config.toml"),
        }),
        resolvePluginPython: async () => python,
        runWorkbench: async (_runtime, args, input) => command(args, input),
        createCodex: throwing("Synthetic stop after registration"),
      },
    );
    try {
      await expect(
        client.run(repository, { mode, outputDir: join(root, "scan") }),
      ).rejects.toThrow("Synthetic stop after registration");
      const scans = (await command(["list-scans", "--repository", repository]))[
        "scans"
      ] as Array<{ scanId: string }>;
      expect(scans).toHaveLength(1);
      const recipe = (
        await command(["get-scan-recipe", "--scan-id", scans[0]!.scanId])
      )["recipe"] as { config: JsonObject };
      expect(recipe.config).toMatchObject({
        profile: "review",
        model_providers: { [provider]: standard },
      });
      const initial = await mergedCodexConfig(
        { codexOverrides: overrides },
        home,
      );
      const replay = await mergedCodexConfig(
        { codexOverrides: recipe.config },
        home,
      );
      expect(replay["model_providers"]).toEqual(initial["model_providers"]);
      expect(JSON.stringify(recipe)).not.toContain("synthetic-launch-key");
      expect(JSON.stringify(recipe)).not.toContain(
        "SYNTHETIC_OLD_PROVIDER_KEY",
      );
    } finally {
      await client.close();
    }
  },
);

test.each(["standard", "deep"])(
  "%s scans save large post-scan prompts before starting Codex",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "state", "codex-home");
    await mkdir(repository);
    await mkdir(codexHome, { recursive: true });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const promptFile = join(root, "post-scan.md");
    const postScanPrompt =
      "Review the completed scan and its evidence.\n".repeat(10_000);
    expect(Buffer.byteLength(postScanPrompt)).toBeGreaterThan(256 * 1024);
    await writeFile(promptFile, postScanPrompt);
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      [
        "scan",
        repository,
        "--mode",
        mode,
        "--output-dir",
        join(root, "scan"),
        "--post-scan-prompt-file",
        promptFile,
        "--json",
      ],
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: throwing("Synthetic stop after registration"),
          }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic stop after registration");
    await rm(promptFile);
    const scans = (await command(["list-scans", "--repository", repository]))[
      "scans"
    ] as Array<{ scanId: string }>;
    expect(scans).toHaveLength(1);
    const saved = await command([
      "get-scan-recipe",
      "--scan-id",
      scans[0]!.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({ mode, postScanPrompt });
    expect(JSON.stringify(saved)).not.toContain(promptFile);
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
  },
);
