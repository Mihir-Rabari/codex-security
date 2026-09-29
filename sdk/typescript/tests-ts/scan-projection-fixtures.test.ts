import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import fixtureTemplate from "../../../plugins/codex-security/tests/fixtures/scan-projection/canonical-child.json";
import type { Finding } from "../src/models.js";
import {
  prepareScanArtifactRestorer,
  runCodexCommand,
} from "../src/runtime.js";
import { combineScanCoverage, validateScanMerge } from "../src/scan-merge.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python =
  process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const fixture = JSON.parse(
  JSON.stringify(fixtureTemplate).replaceAll(
    "@CHILD@",
    fixtureTemplate.sourceScanId,
  ),
) as typeof fixtureTemplate;
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function canonicalChild() {
  if (python === null)
    throw new Error("Python is required for projection fixtures.");
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "projection-fixture-")),
  );
  roots.push(root);
  const parent = join(root, "parent");
  const source = join(parent, fixture.relativeDirectory);
  await mkdir(source, { recursive: true, mode: 0o700 });
  const prepared = await runCodexCommand(
    { command: python },
    [
      "-I",
      "-X",
      "utf8",
      "-B",
      "-c",
      `
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "tests"))
sys.path.insert(0, str(Path(sys.argv[2]) / "scripts"))
from workbench_test_support import write_completed_contract
from finalize_scan_contract import finalize_scan
source, target = Path(sys.argv[3]), Path(sys.argv[4])
fixture = json.load(sys.stdin)
for name in ("src/extract.py", "shared/control.py", "outside.py"):
    path = target / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("print('synthetic fixture')\\n" * 2)
write_completed_contract(source, fixture["sourceScanId"], target, include_paths=["src"], coverage_mode="scoped_path", inventory_strategy="scoped_path")
for name, values in (("findings", {"findings": fixture["findings"]}), ("coverage", fixture["coverage"])):
    path = source / (name + ".json")
    path.write_text(json.dumps({**json.loads(path.read_text()), **values}))
for name, contents in fixture["files"].items():
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
finalize_scan(source)
`,
      sourcePlugin,
      PLUGIN_ROOT,
      source,
      join(root, "target"),
    ],
    process.env,
    JSON.stringify(fixture),
  );
  expect(prepared.success, prepared.stderr).toBe(true);
  const original = JSON.parse(
    await readFile(join(source, "findings.json"), "utf8"),
  ) as { findings: Finding[] };
  const options = {
    python,
    pluginRoot: PLUGIN_ROOT,
    environment: { ...process.env },
  };
  return { root, parent, source, original, options };
}

test("completed projection follows the shared canonical child fixture", async () => {
  const h = await canonicalChild();
  const writer = await prepareScanArtifactRestorer(h.options, h.parent);
  const projected = await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(projected.sourceFindings).toEqual(
    fixture.expected.sourceFindingIndexes.map(
      (index) => h.original.findings[index]!,
    ),
  );
  for (const [index, expected] of fixture.expected.findings.entries()) {
    expect(projected.draft.findings[index]).toMatchObject({
      identity: expected.identity,
      locations: expected.locations,
      provenance: {
        sourceFindingIds: expected.sourceFindingIds,
        extensions: { fixture: "preserve-source-provenance" },
      },
      ...("writeup" in expected ? { writeup: expected.writeup } : {}),
    });
  }
  expect<unknown>(combineScanCoverage([projected])).toEqual(
    fixture.expected.coverage,
  );
  expect(
    await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    ),
  ).toEqual(projected);
  for (const [destination, original] of Object.entries(
    fixture.expected.fileProjections,
  )) {
    expect(await readFile(join(h.parent, destination))).toEqual(
      await readFile(join(h.source, original)),
    );
  }
  expect(
    JSON.parse(await readFile(join(h.source, "findings.json"), "utf8")),
  ).toEqual(h.original);
  // Supporting evidence is read again on the next projection; there is no cross-call cache.
  const evidence = Object.entries(fixture.expected.fileProjections).find(
    ([, path]) => path.endsWith("trace.txt"),
  )!;
  const replacement = Buffer.from([0, 128, 255, 3]);
  await writeFile(join(h.source, evidence[1]), replacement);
  await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(await readFile(join(h.parent, evidence[0]))).toEqual(replacement);
});

test("normalizes sealed legacy findings for merging while retaining exact source evidence", async () => {
  const h = await canonicalChild();
  const first = fixture.expected.sourceFindingIndexes[0]!;
  const legacy = {
    ...h.original,
    findings: h.original.findings.map((finding, index) =>
      index === first
        ? {
            ...finding,
            attackPath: {
              steps: { first: "upload" },
              preconditions: "An attacker can submit an archive.",
            },
          }
        : finding,
    ),
  };
  const sourceBytes = JSON.stringify(legacy);
  const findingsPath = join(h.source, "findings.json");
  await writeFile(findingsPath, sourceBytes);
  const manifestPath = join(h.source, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  manifest.scan.artifacts.find(
    (artifact) => artifact.path === "findings.json",
  )!.sha256 = createHash("sha256").update(sourceBytes).digest("hex");
  await writeFile(manifestPath, JSON.stringify(manifest));

  const writer = await prepareScanArtifactRestorer(h.options, h.parent);
  const projected = await writer.projectChild(
    fixture.parentScanId,
    fixture.sourceScanId,
    h.source,
  );
  expect(projected.draft.findings[0]!.attackPath).toEqual({
    preconditions: ["An attacker can submit an archive."],
  });
  expect(projected.sourceFindings).toEqual(
    fixture.expected.sourceFindingIndexes.map(
      (index) => legacy.findings[index]!,
    ),
  );
  const result = validateScanMerge(
    {
      scanId: fixture.parentScanId,
      groups: projected.draft.findings.map((finding) => ({
        sourceFindingIds: finding.provenance.sourceFindingIds!,
        canonicalSourceFindingId: finding.provenance.sourceFindingIds![0]!,
      })),
    },
    [projected],
    null,
  );
  expect(result.aggregate.findings[0]!.provenance.sourceFindings).toEqual([
    { id: `${fixture.sourceScanId}:0`, finding: legacy.findings[first]! },
  ]);
  expect(await readFile(findingsPath, "utf8")).toBe(sourceBytes);
});

test.each(["source ID", "seal", "parent directory"])(
  "rejects changed %s at the projection boundary",
  async (change) => {
    const h = await canonicalChild();
    const writer = await prepareScanArtifactRestorer(h.options, h.parent);
    let source = h.source;
    let scanId = fixture.sourceScanId;
    if (change === "source ID") scanId = "different-child";
    if (change === "seal")
      await writeFile(join(source, "findings.json"), "{}\n");
    if (change === "parent directory") {
      const moved = join(h.root, "moved-parent");
      await rename(h.parent, moved);
      await mkdir(h.parent, { mode: 0o700 });
      source = join(moved, fixture.relativeDirectory);
    }
    await expect(
      writer.projectChild(fixture.parentScanId, scanId, source),
    ).rejects.toThrow();
    expect(existsSync(join(h.parent, "findings"))).toBe(false);
  },
);

test.skipIf(process.platform === "win32")(
  "rejects unsafe evidence without copying outside bytes",
  async () => {
    const h = await canonicalChild();
    const outside = join(h.root, "outside.txt");
    await writeFile(outside, "Synthetic outside evidence");
    await symlink(outside, join(h.source, "findings/check/unsafe.txt"));
    const writer = await prepareScanArtifactRestorer(h.options, h.parent);
    await expect(
      writer.projectChild(fixture.parentScanId, fixture.sourceScanId, h.source),
    ).rejects.toThrow("inside the scan directory");
    expect(
      existsSync(
        join(h.parent, `findings/${fixture.sourceScanId}-check-4/unsafe.txt`),
      ),
    ).toBe(false);
  },
);

async function pythonWrapper(root: string, block = false) {
  const wrapper = join(root, "selected-python");
  const trace = join(root, "projection-processes.jsonl");
  const ready = join(root, "projection-ready");
  const closed = join(root, "projection-closed");
  await writeFile(
    wrapper,
    `#!${python}
import json, os, signal, sys, time
with open(${JSON.stringify(trace)}, "a") as trace:
    trace.write(json.dumps(sys.argv[1:]) + "\\n")
if ${block ? "True" : "False"} and sys.argv[-1].endswith("project_scan_artifacts.py"):
    def finish(signum, frame):
        time.sleep(0.1)
        with open(${JSON.stringify(closed)}, "w") as closed:
            closed.write("completed child cleanup")
        sys.exit(0)
    signal.signal(signal.SIGTERM, finish)
    with open(${JSON.stringify(ready)}, "w") as ready:
        ready.write("ready")
    while True:
        signal.pause()
os.execv(${JSON.stringify(python)}, [${JSON.stringify(python)}, *sys.argv[1:]])
`,
  );
  await chmod(wrapper, 0o700);
  return { wrapper, trace, ready, closed };
}

test.skipIf(process.platform === "win32")(
  "projects many evidence files with one selected Python process",
  async () => {
    const h = await canonicalChild();
    const many = join(h.source, "findings/check/many");
    await mkdir(many);
    const files = Array.from({ length: 64 }, (_, index) => ({
      name: `${index}.bin`,
      bytes: Buffer.alloc(32 * 1024, index),
    }));
    await Promise.all(
      files.map(({ name, bytes }) => writeFile(join(many, name), bytes)),
    );
    const wrapper = await pythonWrapper(h.root);
    const writer = await prepareScanArtifactRestorer(
      { ...h.options, python: wrapper.wrapper },
      h.parent,
    );
    await writeFile(wrapper.trace, "");
    await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    );
    const invocations = (await readFile(wrapper.trace, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as string[]);
    expect(invocations).toHaveLength(1);
    expect(invocations[0]!.at(-1)).toBe(
      join(PLUGIN_ROOT, "scripts/project_scan_artifacts.py"),
    );
    for (const { name, bytes } of files) {
      expect(
        await readFile(
          join(h.parent, `findings/${fixture.sourceScanId}-check-4/many`, name),
        ),
      ).toEqual(bytes);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "cancellation waits for the admitted projection process to close",
  async () => {
    const h = await canonicalChild();
    const wrapper = await pythonWrapper(h.root, true);
    const controller = new AbortController();
    const writer = await prepareScanArtifactRestorer(
      { ...h.options, python: wrapper.wrapper },
      h.parent,
    );
    const pending = writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
      controller.signal,
    );
    const settled = pending.then(
      () => undefined,
      (error: unknown) => error,
    );
    try {
      const deadline = Date.now() + 3000;
      while (!existsSync(wrapper.ready) && Date.now() < deadline)
        await new Promise((resolve) => setTimeout(resolve, 10));
      expect(existsSync(wrapper.ready)).toBe(true);
      const reason = new Error("Synthetic projection cancellation");
      controller.abort(reason);
      expect(await settled).toBe(reason);
      expect(await readFile(wrapper.closed, "utf8")).toBe(
        "completed child cleanup",
      );
    } finally {
      controller.abort();
      await settled;
    }
  },
);

test.each([false, true])(
  "does not overwrite a projected report with colliding evidence (uppercase: %p)",
  async (uppercase) => {
    const h = await canonicalChild();
    const base = `${fixture.sourceScanId}-check-3`;
    const name = uppercase ? `${base}.md`.toUpperCase() : `${base}.md`;
    await writeFile(
      join(h.source, "findings/check-3", name),
      "Supporting evidence",
    );
    const writer = await prepareScanArtifactRestorer(h.options, h.parent);
    const projected = await writer.projectChild(
      fixture.parentScanId,
      fixture.sourceScanId,
      h.source,
    );
    const reportPath = `findings/${base}-2/${base}-2.md`;
    expect(
      projected.draft.findings.some(
        (finding) => finding.writeup?.reportPath === reportPath,
      ),
    ).toBe(true);
    expect(await readFile(join(h.parent, reportPath))).toEqual(
      await readFile(join(h.source, "findings/check-3/check-3.md")),
    );
    expect(
      await readFile(join(h.parent, `findings/${base}-2/${name}`), "utf8"),
    ).toBe("Supporting evidence");
    expect(
      await readFile(join(h.source, "findings/check-3", name), "utf8"),
    ).toBe("Supporting evidence");
  },
);
