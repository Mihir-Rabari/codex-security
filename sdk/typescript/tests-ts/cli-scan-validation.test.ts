import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { TestClient } from "./support/api-client.js";
import { createCliTest } from "./support/cli-run.js";
import { throwing } from "./support/errors.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

describe("CLI scan validation preflight", () => {
  test.each([
    ["other head", false],
    ["local changes", false],
    ["other head", true],
    ["local changes", true],
  ] as const)(
    "rejects committed diffs with %s before scanning (workflow: %s)",
    async (checkout, workflow) => {
      const root = await temporaryDirectory("scan-validation-preflight-");
      try {
        const repository = join(root, "repository");
        await mkdir(repository);
        git(repository, "init", "-q", "-b", "main");
        const source = join(repository, "source.ts");
        await writeFile(source, "export const value = 'base';\n");
        git(repository, "add", ".");
        git(repository, "commit", "-qm", "base");
        const base = git(repository, "rev-parse", "HEAD");
        await writeFile(source, "export const value = 'head';\n");
        git(repository, "commit", "-qam", "head");
        const head = git(repository, "rev-parse", "HEAD");
        if (checkout === "other head") {
          git(repository, "checkout", "-q", "--detach", base);
        } else {
          await writeFile(source, "export const value = 'local';\n");
        }
        const prepareRuntime = mock(throwing("Unexpected runtime setup"));
        const createCodex = mock(throwing("Unexpected model invocation"));
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(
            [
              "scan",
              repository,
              "--diff",
              base,
              "--head",
              head,
              "--validate",
              ...(workflow ? ["--workflow-id", "diff-validation"] : []),
              "--json",
            ],
            {
              ...dependencies({ currentDirectory: root }),
              createSecurity: (config) =>
                new TestClient(config, { prepareRuntime, createCodex }),
            },
          ),
        ).toBe(2);
        expect(JSON.parse(stdout.text())).toMatchObject({ status: "failed" });
        expect(stderr.text()).toContain(
          checkout === "other head"
            ? "checkout to match the requested head revision"
            : "clean repository checkout",
        );
        expect(prepareRuntime).not.toHaveBeenCalled();
        expect(createCodex).not.toHaveBeenCalled();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
