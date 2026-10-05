import {
  mkdir,
  mkdtemp,
  readFile,
  stat,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { exportArtifact } from "../src/index.js";
import {
  resolveArtifactExportOutput,
  readThreatModelPath,
  writeThreatModel,
} from "../src/artifact-export.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { PYTHON } from "./support/security-policy.js";

const caseProbe = await mkdtemp(join(tmpdir(), "codex-security-case-probe-"));
await mkdir(join(caseProbe, "reports"));
const caseInsensitiveVolume = await stat(join(caseProbe, "REPORTS")).then(
  () => true,
  () => false,
);
await rm(caseProbe, { recursive: true, force: true });

describe("offline artifact export", () => {
  test("resolves the current directory without traversing outside it", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cwd-output-"));
    try {
      const currentDirectory = join(root, "repository");
      const scanDir = join(root, "scan");
      await mkdir(currentDirectory);
      await mkdir(scanDir);
      const result = await resolveArtifactExportOutput(
        { scanDir, output: currentDirectory, format: "json" },
        currentDirectory,
      );
      expect(result.output).toBe(currentDirectory);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("resolves a scan-local export before its exports directory exists", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-new-export-"));
    try {
      const scanDir = join(root, "scan");
      await mkdir(scanDir);
      const output = join(scanDir, "exports", "findings.json");
      expect(
        (
          await resolveArtifactExportOutput(
            { scanDir, output, format: "json" },
            root,
          )
        ).output,
      ).toBe(output);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(!caseInsensitiveVolume)(
    "accepts an export parent accessed through a case alias",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-case-output-"));
      await mkdir(join(root, "reports"));
      try {
        const result = await resolveArtifactExportOutput(
          {
            scanDir: join(root, "scan"),
            format: "json",
            output: join(root, "REPORTS", "result.json"),
          },
          root,
        );
        await writeFile(result.output, "synthetic export");
        expect(
          await readFile(join(root, "reports", "result.json"), "utf8"),
        ).toBe("synthetic export");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("resolves real export directories while refusing linked repository parents", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-output-path-"));
    const reports = join(root, "reports");
    await mkdir(reports);
    const link = join(root, "linked");
    await symlink(reports, link, "junction");
    try {
      const options = {
        scanDir: join(root, "scan"),
        format: "json" as const,
        output: join(reports, "result.json"),
      };
      expect((await resolveArtifactExportOutput(options, root)).output).toBe(
        options.output,
      );
      await expect(
        resolveArtifactExportOutput(
          { ...options, output: join(link, "result.json") },
          root,
        ),
      ).rejects.toThrow("cannot traverse a repository symlink");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("only exposes a document matching the current canonical model", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-current-model-"));
    const modelPath = join(root, "threatmodel.md");
    const options = { pythonPath: PYTHON, pluginRoot: PLUGIN_ROOT };
    const manifest = {
      documentType: "codex-security.policy-draft",
      status: "completed",
      threatModel: { format: "markdown", content: "# Original model\n" },
    };
    try {
      await writeFile(
        join(root, "policy-draft.json"),
        JSON.stringify(manifest),
      );
      await writeThreatModel(root, options);
      expect(await readThreatModelPath(root, options)).toBe(modelPath);
      manifest.threatModel.content = "# Updated model\n";
      await writeFile(
        join(root, "policy-draft.json"),
        JSON.stringify(manifest),
      );
      expect(await readThreatModelPath(root, options)).toBeNull();
      expect(await readFile(modelPath, "utf8")).toContain("Original model");
      await writeThreatModel(root, options);
      expect(await readThreatModelPath(root, options)).toBe(modelPath);
      expect(
        await readThreatModelPath(root, {
          ...options,
          pythonPath: join(root, "missing-python"),
        }),
      ).toBeNull();
      const controller = new AbortController();
      controller.abort(new Error("Synthetic path lookup cancellation"));
      await expect(
        readThreatModelPath(root, {
          ...options,
          signal: controller.signal,
        }),
      ).rejects.toThrow("Synthetic path lookup cancellation");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports canonical policy Markdown before completion without its convenience file", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-offline-model-"));
    const source = join(root, "policy");
    const output = join(root, "threatmodel.md");
    const content =
      "# Component model\n\n| Asset | Boundary |\n| --- | --- |\n| Café | Caller → service |\n\n```text\nline one\n  line two\n```\n";
    const manifest = {
      documentType: "codex-security.policy-draft",
      schemaVersion: "1.0",
      repository: "/synthetic/repository",
      scope: "services/api",
      revision: "synthetic-revision",
      status: "threat_model_ready",
      threatModel: {
        format: "markdown",
        content,
        scope: { includePaths: ["services/api"], excludePaths: [] },
        origin: "generated",
      },
    };
    await mkdir(source);
    const original = JSON.stringify(manifest);
    await writeFile(join(source, "policy-draft.json"), original);
    try {
      const result = await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output,
      });
      expect(result.path).toBe(output);
      expect(result.provenance).toMatchObject({
        status: "threat_model_ready",
        provisional: true,
      });
      const exported = await readFile(output, "utf8");
      expect(exported).toStartWith(content);
      expect(exported).toContain("services/api");
      expect(await readFile(join(source, "policy-draft.json"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("exports historical Markdown and rejects missing models or overwriting source artifacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-legacy-model-"));
    const source = join(root, "policy");
    await mkdir(source);
    try {
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(root, "missing.md"),
        }),
      ).rejects.toThrow("No saved threat model");
      const original = "# Historical model\n\nSource-backed details.\n";
      await writeFile(join(source, "THREAT_MODEL.md"), original);
      expect(await readThreatModelPath(source)).toBe(
        join(source, "THREAT_MODEL.md"),
      );
      await exportArtifact({
        source: { directory: source },
        artifact: "threat-model",
        output: join(root, "threatmodel.md"),
      });
      expect(await readFile(join(root, "threatmodel.md"), "utf8")).toBe(
        original,
      );
      await expect(
        exportArtifact({
          source: { directory: source },
          artifact: "threat-model",
          output: join(source, "THREAT_MODEL.md"),
        }),
      ).rejects.toThrow("cannot overwrite a scan artifact");
      expect(await readFile(join(source, "THREAT_MODEL.md"), "utf8")).toBe(
        original,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not expose a historical model through a linked parent directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-linked-model-"));
    const source = join(root, "scan");
    const outside = join(root, "outside");
    await mkdir(source);
    await mkdir(join(outside, "01_context"), { recursive: true });
    await writeFile(
      join(outside, "01_context", "threat_model.md"),
      "# Unrelated model\n",
    );
    try {
      await symlink(
        outside,
        join(source, "artifacts"),
        process.platform === "win32" ? "junction" : "dir",
      );
      expect(await readThreatModelPath(source)).toBeNull();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
