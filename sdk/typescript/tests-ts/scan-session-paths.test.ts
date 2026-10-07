import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { resolveScanSessionPaths } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { nodeCommand, pythonExecutable } from "./support/shell.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "scan-session-paths-",
);
afterEach(cleanup);

async function fixture(label: string, response = "selected") {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const sqliteHome = join(root, "selected-state");
  const directory = join(root, "scan");
  const state = join(root, "workbench");
  await Promise.all(
    [home, sqliteHome, directory, state].map((path) => mkdir(path)),
  );
  const ids = [
    "root",
    "discovery",
    "resumed-discovery",
    "reducer",
    "resumed-reducer",
  ].map((id) => `${label}-${id}`);
  const paths = ids.map((id) => join(home, `${id}.jsonl`));
  await Promise.all(
    paths.map((path, index) =>
      writeFile(
        path,
        JSON.stringify({ type: "session_meta", payload: { id: ids[index] } }) +
          "\n",
      ),
    ),
  );
  const python = pythonExecutable()!;
  execFileSync(python, [
    "-I",
    "-B",
    "-c",
    [
      "import json,sqlite3,sys",
      "from pathlib import Path",
      "sqlite_home,state,ids,paths=json.loads(sys.argv[1])",
      "c=sqlite3.connect(Path(sqlite_home)/'state_7.sqlite')",
      "c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)')",
      "c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)')",
      "c.executemany('INSERT INTO threads VALUES (?,?)',zip(ids,paths))",
      "c.commit();c.close()",
      "c=sqlite3.connect(Path(state)/'workbench.sqlite3')",
      "c.execute('CREATE TABLE scans(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,mode TEXT NOT NULL)')",
      "c.execute('CREATE TABLE workspaces(id TEXT PRIMARY KEY,thread_id TEXT)')",
      "c.execute('CREATE TABLE deep_scan_workers(scan_id TEXT NOT NULL,sdk_thread_id TEXT)')",
      "c.execute(\"INSERT INTO scans VALUES ('scan','workspace','deep')\")",
      "c.execute(\"INSERT INTO workspaces VALUES ('workspace',?)\",(ids[0],))",
      "c.executemany(\"INSERT INTO deep_scan_workers VALUES ('scan',?)\",[(id,)for id in ids[1:]])",
      "c.commit();c.close()",
    ].join("\n"),
    JSON.stringify([sqliteHome, state, ids, paths]),
  ]);
  const transcript = join(root, "requests.jsonl");
  const preload = join(root, "native-config.mjs");
  await writeFile(
    preload,
    [
      'import { createInterface } from "node:readline";',
      'import { appendFileSync } from "node:fs";',
      `const transcript = ${JSON.stringify(transcript)};`,
      "for await (const line of createInterface({input:process.stdin})) {",
      "const request=JSON.parse(line);",
      'appendFileSync(transcript, JSON.stringify({request,cwd:process.cwd(),home:process.env.CODEX_HOME,argv:process.argv.slice(1)})+"\\n");',
      'if(request.method==="initialize") process.stdout.write(JSON.stringify({id:request.id,result:{}})+"\\n");',
      response === "blocked"
        ? ""
        : response === "error"
          ? 'if(request.method==="config/read") process.stdout.write(JSON.stringify({id:request.id,error:{message:"Synthetic native configuration failure"}})+"\\n");'
          : `if(request.method==="config/read") process.stdout.write(JSON.stringify({id:request.id,result:{config:{sqlite_home:${JSON.stringify(sqliteHome)}}}})+"\\n");`,
      "}",
    ].join("\n"),
  );
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: state,
    NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
  };
  delete environment["CODEX_STATE_DB"];
  delete environment["CODEX_SQLITE_HOME"];
  const options = { python, pluginRoot: PLUGIN_ROOT, environment };
  const native = { command: nodeCommand(), workingDirectory: directory };
  return {
    root,
    home,
    sqliteHome,
    directory,
    ids,
    paths,
    transcript,
    options,
    native,
  };
}

test("resolves native SQLite ownership for concurrent fresh and resumed Deep workers", async () => {
  const fixtures = await Promise.all([fixture("first"), fixture("second")]);
  const completed = await Promise.allSettled(
    fixtures.map(async (f) => {
      for (const id of f.ids)
        expect(
          [
            ...(await resolveScanSessionPaths(f.options, "scan", id, f.native)),
          ].sort(),
        ).toEqual([...f.paths].sort());
      const requests = (await readFile(f.transcript, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(
        requests.filter((x) => x.request.method === "config/read"),
      ).toHaveLength(1);
      expect(requests.map((x) => x.request.method)).toEqual([
        "initialize",
        "initialized",
        "config/read",
      ]);
      for (const row of requests) {
        expect(row.cwd).toBe(f.directory);
        expect(row.home).toBe(f.home);
        expect(row.argv).toHaveLength(2);
        expect(basename(row.argv[0])).toBe("app-server");
        expect(row.argv[1]).toBe("--stdio");
      }
      expect(requests[2].request.params).toEqual({
        cwd: f.directory,
        includeLayers: false,
      });
    }),
  );
  for (const row of completed) if (row.status === "rejected") throw row.reason;
});

test.each(["CODEX_SQLITE_HOME", "CODEX_STATE_DB"] as const)(
  "preserves explicit %s ownership without querying native configuration",
  async (key) => {
    const f = await fixture("explicit", "error");
    f.options.environment[key] =
      key === "CODEX_STATE_DB"
        ? join(f.sqliteHome, "state_7.sqlite")
        : f.sqliteHome;
    expect(
      [
        ...(await resolveScanSessionPaths(
          f.options,
          "scan",
          f.ids[0]!,
          f.native,
        )),
      ].sort(),
    ).toEqual([...f.paths].sort());
    await expect(readFile(f.transcript, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

test("retains native configuration errors and incomplete ownership rejection", async () => {
  const f = await fixture("failure", "error");
  await expect(
    resolveScanSessionPaths(f.options, "scan", f.ids[0]!, f.native),
  ).rejects.toThrow("scan session ownership");
  await expect(
    resolveScanSessionPaths(
      {
        ...f.options,
        environment: {
          ...f.options.environment,
          CODEX_SQLITE_HOME: f.sqliteHome,
        },
      },
      null,
      "unowned-thread",
      f.native,
    ),
  ).rejects.toThrow("scan session ownership");
});

test("aborts a pending native SQLite query and drains its child", async () => {
  const f = await fixture("abort", "blocked");
  const controller = new AbortController();
  const pending = resolveScanSessionPaths(
    { ...f.options, signal: controller.signal },
    "scan",
    f.ids[0]!,
    f.native,
  );
  let requests = "";
  while (!requests.includes("config/read")) {
    try {
      requests = await readFile(f.transcript, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await Bun.sleep(5);
  }
  controller.abort(new Error("Synthetic caller cancellation"));
  await expect(pending).rejects.toBeDefined();
});

test.each(["unrelated", "schema"])(
  "resolves native SQLite ownership when the default database is %s",
  async (stale) => {
    const f = await fixture("stale-" + stale);
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      stale === "schema"
        ? "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE legacy(value TEXT)');c.close()"
        : "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)');c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)');c.close()",
      join(f.home, "state_7.sqlite"),
    ]);
    expect(
      [
        ...(await resolveScanSessionPaths(
          f.options,
          "scan",
          f.ids[0]!,
          f.native,
        )),
      ].sort(),
    ).toEqual([...f.paths].sort());
    expect(await readFile(f.transcript, "utf8")).toContain(
      '"method":"config/read"',
    );
  },
);

test.each(["CODEX_SQLITE_HOME", "CODEX_STATE_DB"] as const)(
  "does not replace an incomplete explicit %s with native fallback",
  async (key) => {
    const f = await fixture("explicit-incomplete");
    const database = join(f.home, "state_7.sqlite");
    execFileSync(f.options.python, [
      "-I",
      "-B",
      "-c",
      "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)');c.execute('CREATE TABLE thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)');c.close()",
      database,
    ]);
    f.options.environment[key] = key === "CODEX_STATE_DB" ? database : f.home;
    await expect(
      resolveScanSessionPaths(f.options, "scan", f.ids[0]!, f.native),
    ).rejects.toThrow("scan session ownership");
    await expect(readFile(f.transcript, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);
