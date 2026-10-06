import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import { applyMigrations } from "./migrations";
import { decodePosixBytes, encodePosixPath } from "../helpers/posix-path";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";

function createStateDirectory(path: string): void {
  if (process.platform !== "win32") path = path.replace(/\/+$/u, "") || "/";
  const nativePath =
    process.platform === "win32" ? path : encodePosixPath(path);
  const create = () => {
    if (process.platform === "win32")
      windowsFileSystem(windowsBinding()).mkdir(widePath(path), true);
    else mkdirSync(nativePath, { recursive: true, mode: 0o700 });
  };
  try {
    create();
  } catch (error) {
    if (
      !["ENOENT", "EEXIST"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      ) &&
      (error as { winerror?: number }).winerror !== 183
    )
      throw error;
    const entry = lstatSync(nativePath, { throwIfNoEntry: false });
    if (entry?.isSymbolicLink()) {
      const target =
        process.platform === "win32"
          ? readlinkSync(nativePath)
          : decodePosixBytes(readlinkSync(nativePath, { encoding: "buffer" }));
      createStateDirectory(
        isAbsolute(target) ? target : `${dirname(path)}${sep}${target}`,
      );
      return;
    }
    const parent = dirname(path);
    if (entry || parent === path) throw error;
    createStateDirectory(parent);
    create();
  }
}

export async function openWorkbenchDatabase(
  databasePath: string,
  { deferred = false }: { deferred?: boolean } = {},
): Promise<DatabaseSync> {
  createStateDirectory(dirname(databasePath));
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
  state: string,
): Promise<{ databasePath: string }> {
  if (
    typeof state !== "string" ||
    !isAbsolute(state) ||
    !state.isWellFormed()
  ) {
    throw new Error(
      "database-info requires an absolute Unicode state-directory string.",
    );
  }
  // Keep an ASCII alias usable even when its destination has raw POSIX bytes.
  const database = await openWorkbenchDatabase(
    `${state}${sep}workbench.sqlite3`,
    { deferred: true },
  );
  database.close();
  const canonicalState =
    process.platform === "win32"
      ? realpathSync.native(state)
      : decodePosixBytes(
          realpathSync.native(encodePosixPath(state), { encoding: "buffer" }),
        );
  const databasePath = join(canonicalState, "workbench.sqlite3");
  return { databasePath };
}
