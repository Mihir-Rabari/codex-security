import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { copyCompletedScanFixture } from "../plugin-root.js";

export function createTemporaryDirectories(canonical = true) {
  const directories: string[] = [];

  return {
    track(path: string): void {
      directories.push(path);
    },

    async create(prefix: string): Promise<string> {
      const path = await temporaryDirectory(prefix, canonical);
      directories.push(path);
      return path;
    },

    async cleanup(): Promise<void> {
      await Promise.all(
        directories
          .splice(0)
          .map((path) => rm(path, { recursive: true, force: true })),
      );
    },
  };
}

export function createApiTestFixtures(
  prefix = "codex-security-api-",
  canonicalize = true,
) {
  const temporaryDirectories = createTemporaryDirectories(canonicalize);
  return {
    temporaryDirectories,
    cleanup: temporaryDirectories.cleanup,
    async copyCompletedScan(root: string): Promise<string> {
      const scanDir = join(root, "scan");
      await copyCompletedScanFixture(scanDir);
      await chmod(scanDir, 0o700);
      await writeFile(join(scanDir, "report.md"), "# Scan report\n");
      return scanDir;
    },
    temporaryDirectory(directoryPrefix = prefix): Promise<string> {
      return temporaryDirectories.create(directoryPrefix);
    },
  };
}

export async function temporaryDirectory(
  prefix: string,
  canonicalize = true,
): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  return canonicalize ? realpath(path) : path;
}
