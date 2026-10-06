import { chmodSync, mkdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import { applyMigrations } from "./migrations";

export async function openWorkbenchDatabase(
  databasePath: string,
  { deferred = false }: { deferred?: boolean } = {},
): Promise<DatabaseSync> {
  mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
  for (let attempt = 0; ; attempt++) {
    const database = new DatabaseSync(databasePath);
    try {
      database.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
      applyMigrations(database, undefined, !deferred || attempt > 0);
      database.exec("PRAGMA journal_mode = WAL");
      chmodSync(databasePath, 0o600);
      return database;
    } catch (error) {
      database.close();
      const busy =
        error instanceof Error &&
        "errcode" in error &&
        [5, 6].includes(Number(error.errcode) & 0xff);
      if (attempt === 4 || !busy) throw error;
      await setTimeout(50 * 2 ** attempt);
    }
  }
}

export async function databaseInfo(
  environment: NodeJS.ProcessEnv = process.env,
): Promise<{ databasePath: string }> {
  const home =
    (process.platform === "win32"
      ? environment.USERPROFILE
      : environment.HOME) || homedir();
  const expandHome = (path: string) =>
    path === "~" ? home : /^~[/\\]/u.test(path) ? home + path.slice(1) : path;
  const state = environment.CODEX_SECURITY_STATE_DIR
    ? expandHome(environment.CODEX_SECURITY_STATE_DIR)
    : [
        expandHome(environment.CODEX_HOME ?? "~/.codex") || ".",
        "state",
        "plugins",
        "codex-security",
      ].join(sep);
  mkdirSync(state, { recursive: true, mode: 0o700 });
  const databasePath = join(realpathSync.native(state), "workbench.sqlite3");
  const database = await openWorkbenchDatabase(databasePath, {
    deferred: true,
  });
  database.close();
  return { databasePath };
}
