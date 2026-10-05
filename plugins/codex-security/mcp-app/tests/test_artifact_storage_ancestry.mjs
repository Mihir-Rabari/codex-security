import assert from "node:assert/strict";
import {
  access,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { importSource } from "./import-module.mjs";

const { standaloneArtifactContext } = await importSource(
  fileURLToPath(new URL("../src/artifact-storage.ts", import.meta.url)),
);

test("standalone storage checks existing ancestors before creating a collection", async (t) => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "artifact-ancestry-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const repository = path.join(root, "repository");
  const alias = path.join(root, "alias");
  await mkdir(repository);
  await symlink(
    repository,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  await assert.rejects(
    standaloneArtifactContext(
      repository,
      async () => ({ targetPath: repository }),
      true,
      path.join(alias, "new", "scans"),
      "persistent",
    ),
    /outside the target repository/,
  );
  await assert.rejects(access(path.join(repository, "new")), {
    code: "ENOENT",
  });
});
