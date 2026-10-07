import { mkdir, realpath, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies, capture } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { pythonExecutable } from "./support/python.js";
import { runPython } from "./support/python-probe.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { workbenchCommand } from "./support/workbench-command.js";

const savedAliasFindings = String.raw`
import sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_db as workbench
state, repository, alias = map(Path, sys.argv[2:5])
state.mkdir(exist_ok=True)
with sqlite3.connect(state / "workbench.sqlite3") as connection:
    connection.row_factory = sqlite3.Row
    workbench.apply_migrations(connection)
    def insert(table, **values):
        connection.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
    timestamp = "2026-08-01T00:00:00Z"
    for name, target in (("canonical", repository), ("alias", alias)):
        metadata = target.stat()
        insert("security_targets", id=name, current_path=str(target), display_name=name, created_at=timestamp, updated_at=timestamp)
        insert("workspaces", id=name, target_id=name, created_at=timestamp, updated_at=timestamp)
        insert("scans", id=name, workspace_id=name, target_id=name, target_path=str(target), target_revision="unversioned", target_device=str(metadata.st_dev), target_inode=str(metadata.st_ino), scope=".", mode="standard", scan_dir=str(state / name), status="complete", phase="reporting", started_at=timestamp, completed_at=timestamp, created_at=timestamp, updated_at=timestamp)
        insert("scan_progress", scan_id=name, updated_at=timestamp)
        insert("findings", id=name, fingerprint=name, rule_id="synthetic-rule", identity_anchor=name, created_at=timestamp, updated_at=timestamp)
        insert("finding_occurrences", id=name, finding_id=name, scan_id=name, title=name, summary="Synthetic finding", severity="high", confidence="high", remediation="Constrain the path", details_json="{}", created_at=timestamp)
    if sys.argv[5] == "stale":
        connection.execute("UPDATE scans SET target_inode = ? WHERE id = 'alias'", (str(alias.stat().st_ino + 1),))
`;

test("findings list preserves exact saved aliases and rejects their stale ownership", async () => {
  const root = await temporaryDirectory("findings-alias-boundary-");
  try {
    const repository = join(root, "repository");
    const alias = join(root, "saved-alias");
    const unsavedAlias = join(root, "unsaved-alias");
    await mkdir(repository);
    for (const path of [alias, unsavedAlias]) {
      await symlink(
        repository,
        path,
        process.platform === "win32" ? "junction" : "dir",
      );
    }
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    for (const stale of [false, true]) {
      const state = join(root, stale ? "stale-state" : "current-state");
      const initialized = runPython(python!, [
        "-c",
        savedAliasFindings,
        join(PLUGIN_ROOT, "scripts"),
        state,
        repository,
        alias,
        stale ? "stale" : "current",
      ]);
      expect(new TextDecoder().decode(initialized.stderr)).toBe("");
      expect(initialized.exitCode).toBe(0);
      for (const requested of [alias, repository, unsavedAlias]) {
        const stdout = capture();
        const stderr = capture();
        const result = await main(
          ["findings", "list", requested, "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({ onWorkbench: workbenchCommand(python!, state) }),
        );
        if (stale && requested === alias) {
          expect(result).toBe(2);
          expect(stderr.text()).toContain(
            "Repository findings are unavailable",
          );
        } else {
          expect(result).toBe(0);
          const output = JSON.parse(stdout.text());
          expect(output.repository).toBe(await realpath(repository));
          expect(
            output.findings.map(
              (finding: { scanId: string }) => finding.scanId,
            ),
          ).toEqual([requested === alias ? "alias" : "canonical"]);
        }
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
