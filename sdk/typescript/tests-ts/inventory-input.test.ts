import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, parse, relative, sep } from "node:path";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
import { nodeCommand } from "./support/shell.js";
import { git } from "./git-fixture.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporary = createTemporaryDirectoriesSync(true);
const node = nodeCommand().command;
afterEach(temporary.cleanup);

function fixture() {
  const root = temporary.create("codex-security-inventory-"),
    repo = join(root, "repository"),
    out = join(root, "output");
  mkdirSync(repo);
  git(repo, "init", "-q");
  const write = (path: string, data: string | Buffer = "value = 1\n") => {
    const file = join(repo, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, data);
    return file;
  };
  const run = (command: string, args: string[] = [], env = process.env) =>
    spawnSync(
      node,
      [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        command,
        "--repo",
        repo,
        "--out",
        out,
        ...args,
      ],
      { env, encoding: "utf8" },
    );
  const success = (command: string, args: string[] = []) => {
    const result = run(command, args);
    expect(result.status, result.stderr).toBe(0);
    return readFileSync(out, "utf8");
  };
  const rows = (command = "make-repo-rank-input", args: string[] = []) =>
    success(command, args)
      .split(/\r?\n/u)
      .filter(Boolean)
      .map(
        (line) =>
          JSON.parse(line) as { path: string; area?: string; preview?: string },
      );
  const commit = () => {
    git(repo, "add", ".");
    git(repo, "commit", "-qm", "Fixture revision");
    return git(repo, "rev-parse", "HEAD");
  };
  return { root, repo, out, write, run, success, rows, commit };
}

for (const scope of [".", "src", "./src", "src/résumé.py"]) {
  test(`path inventory preserves ripgrep spelling and byte order for ${scope}`, () => {
    const f = fixture();
    f.write("src/résumé.py");
    f.write("src/alpha.py");
    f.write("src/binary", Buffer.from([0]));
    f.write(".hidden/source.py");
    f.write(".gitignore", "ignored/\n");
    f.write("ignored/untracked.py");
    f.write("ignored/tracked.py");
    git(f.repo, "add", "--force", "ignored/tracked.py");
    const args = [
      "--files",
      "--null",
      "--hidden",
      "--path-separator",
      "/",
      "--glob",
      "!**/.git",
      "--glob",
      "!**/.git/**",
      "--",
      scope,
    ];
    const rg = spawnSync("rg", args, { cwd: f.repo });
    const expected = rg.stdout.toString().split("\0").filter(Boolean);
    if (scope === ".") expected.push("./ignored/tracked.py");
    expect(f.success("generate-in-scope-files", ["--scope", scope])).toBe(
      expected
        .map((path) => Buffer.from(path + "\n"))
        .sort(Buffer.compare)
        .map(String)
        .join(""),
    );
    expect(readdirSync(f.root).filter((name) => name.endsWith(".tmp"))).toEqual(
      [],
    );
  });
}

for (const command of ["make-repo-rank-input", "make-repo-scope-input"]) {
  test(`${command} retains explicit and ignored tracked files without widening directory scope`, () => {
    const f = fixture();
    f.write("src/source.py");
    f.write("src/entrypoint", "run\n");
    f.write("outside.py");
    f.write(".gitignore", "src/ignored*\n");
    f.write("src/ignored-tracked.py");
    f.write("src/ignored-untracked.py");
    f.write("src/binary", Buffer.from([0]));
    f.write("direct.bin", Buffer.from([0]));
    git(f.repo, "add", "--force", "src/ignored-tracked.py");
    const scopes = join(f.root, "scopes.json");
    writeFileSync(
      scopes,
      JSON.stringify(["src", "direct.bin", "src/source.py"]),
    );
    const rows = f.rows(command, ["--scopes-file", scopes]);
    expect(rows.map((row) => row.path)).toEqual([
      "direct.bin",
      ...(command === "make-repo-scope-input" ? ["src/binary"] : []),
      "src/entrypoint",
      "src/ignored-tracked.py",
      "src/source.py",
    ]);
    if (command === "make-repo-rank-input") expect(rows[0]!.preview).toBe("");
  });
}

for (const encoding of ["utf8", "utf16le", "utf16be"] as const) {
  for (const mode of ["repo", "revisions", "local-patch"]) {
    test(`${mode} previews decode ${encoding} and detect binary bytes beyond the prefix`, () => {
      const f = fixture();
      f.write("existing.py");
      const base = f.commit();
      const source = "    value = 'café 😀  literal'  \n\n    return value  \n";
      const bytes =
        encoding === "utf8"
          ? Buffer.from(source)
          : Buffer.concat([
              Buffer.from([0xff, 0xfe]),
              Buffer.from(source, "utf16le"),
            ]);
      if (encoding === "utf16be") bytes.swap16();
      f.write("text", bytes);
      const lateBinary =
        encoding === "utf8"
          ? Buffer.concat([Buffer.alloc(96 * 1024, 120), Buffer.from([0])])
          : Buffer.concat([
              Buffer.from([0xff, 0xfe]),
              Buffer.from("x".repeat(96 * 1024) + "\0", "utf16le"),
            ]);
      if (encoding === "utf16be") lateBinary.swap16();
      f.write("encoded-binary", lateBinary);
      f.write(
        "late-binary",
        Buffer.concat([Buffer.alloc(96 * 1024, 120), Buffer.from([0])]),
      );
      for (const bom of [
        [0xff, 0xfe],
        [0xfe, 0xff],
      ])
        f.write(
          `late-bom-${bom[0]}`,
          Buffer.concat([
            Buffer.alloc(64 * 1024, 120),
            Buffer.from([...bom, 104, 0, 105, 0]),
          ]),
        );
      if (mode === "revisions") f.commit();
      const rows =
        mode === "repo"
          ? f.rows()
          : f.rows("make-diff-rank-input", ["--base", base, "--mode", mode]);
      expect(rows.find((row) => row.path === "text")?.preview).toBe(
        source.slice(0, -1),
      );
      expect(
        rows.some(
          (row) =>
            row.path === "late-binary" ||
            row.path === "encoded-binary" ||
            row.path.startsWith("late-bom-"),
        ),
      ).toBe(false);
    });
  }
}

for (const budget of [0, -1, 2, 30, 220, 1024]) {
  test(`preview budget ${budget} preserves source and complete UTF-8 units`, () => {
    const f = fixture(),
      source = Array.from(
        { length: 40 },
        (_, index) =>
          `line_${String(index).padStart(2, "0")} ${"😀".repeat(20)}`,
      ).join("\n");
    f.write("source", source);
    const preview = f.rows("make-repo-rank-input", [
      "--preview-bytes",
      String(budget),
    ])[0]!.preview!;
    expect(Buffer.byteLength(preview)).toBeLessThanOrEqual(Math.max(0, budget));
    expect(preview).not.toContain("\ufffd");
    if (budget <= 0) expect(preview).toBe("");
    else if (budget <= 30) expect(source.startsWith(preview)).toBe(true);
    else {
      expect(preview).toContain("line_39");
      expect(preview).toContain("...");
    }
  });
}

test("small previews retain complete bodies, literal replacement characters, and line whitespace", () => {
  const f = fixture();
  f.write(
    "source",
    "\n \t\n    text = 'two  spaces\tand\u0085a separator �'  \r\n    return text  \r\n\n",
  );
  expect(f.rows()[0]!.preview).toBe(
    "    text = 'two  spaces\tand\u0085a separator �'  \n    return text  ",
  );
});

test("explicit scope names are literal and JSONL escapes Unicode separators", () => {
  const f = fixture(),
    name = "audit\u0085line\u2028paragraph\u2029.py";
  f.write(name);
  f.write("~literal/file");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify([name, "~literal"]));
  const text = f.success("make-repo-rank-input", ["--scopes-file", scopes]);
  expect(text).not.toMatch(/[\u0085\u2028\u2029]/u);
  expect(
    text
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((line) => JSON.parse(line).path),
  ).toEqual([name, "~literal/file"]);
});

for (const mode of ["revisions", "local-patch"]) {
  test(`${mode} selects added, changed, deleted, and renamed regular files`, () => {
    const f = fixture();
    f.write("changed.py", "old\n");
    f.write("deleted.py", "delete\n");
    f.write("renamed.py", "rename\n");
    const base = f.commit();
    f.write("changed.py", "new\n");
    rmSync(join(f.repo, "deleted.py"));
    git(f.repo, "mv", "renamed.py", "moved.py");
    f.write("new-file", "added\n");
    git(f.repo, "add", ".");
    f.write("unstaged.py", "unstaged\n");
    if (mode === "revisions") {
      f.commit();
      f.write("changed.py", "worktree must not leak\n");
    }
    const args = ["--base", base, "--mode", mode];
    const rows = f.rows("make-diff-rank-input", args);
    expect(rows.find((row) => row.path === "changed.py")?.preview).toBe("new");
    expect(rows.find((row) => row.path === "deleted.py")?.preview).toBe("");
    expect(rows.map((row) => row.path)).toEqual([
      "changed.py",
      "deleted.py",
      "moved.py",
      "new-file",
      "unstaged.py",
    ]);
    expect(
      f.success("generate-in-scope-files", [
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-mode",
        mode,
      ]),
    ).toBe(rows.map((row) => row.path + "\n").join(""));
  });
}

test("failed inventory generation preserves the existing file", () => {
  const f = fixture();
  f.write("source");
  writeFileSync(f.out, "previous\n");
  for (const args of [
    ["--scope", "missing"],
    ["--scope", ".."],
    ["--scope", ".", "--diff-base", "missing-revision"],
  ]) {
    expect(f.run("generate-in-scope-files", args).status).toBe(2);
    expect(readFileSync(f.out, "utf8")).toBe("previous\n");
  }
  const absent = f.run("generate-in-scope-files", ["--scope", "."], {
    ...process.env,
    PATH: f.root,
  });
  expect(absent.status).toBe(2);
  expect(readFileSync(f.out, "utf8")).toBe("previous\n");
});

for (const command of ["make-repo-scope-input", "make-repo-rank-input"]) {
  test(`${command} ignores tracked descendants replaced by symlinks`, () => {
    const f = fixture();
    f.write("src/nested/source");
    f.commit();
    rmSync(join(f.repo, "src", "nested"), { recursive: true });
    const outside = join(f.root, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "source"), "external\n");
    symlinkSync(outside, join(f.repo, "src", "nested"), "junction");
    const scopes = join(f.root, "scopes.json");
    writeFileSync(scopes, JSON.stringify(["src"]));
    expect(f.rows(command, ["--scopes-file", scopes])).toEqual([]);
    if (command === "make-repo-scope-input") {
      writeFileSync(scopes, JSON.stringify(["src/nested/../source"]));
      expect(f.run(command, ["--scopes-file", scopes]).status).not.toBe(0);
    }
  });
}

test.skipIf(process.platform === "win32")(
  "line-breaking and non-UTF8 diff paths fail without replacing inventory",
  () => {
    const f = fixture();
    f.write("source");
    const base = f.commit();
    for (const name of ["line\nname", "line\rname"]) {
      f.write(name);
      writeFileSync(f.out, "previous\n");
      expect(f.run("generate-in-scope-files", ["--scope", "."]).status).toBe(2);
      expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      rmSync(join(f.repo, name));
    }
    const path = Buffer.concat([
      Buffer.from(f.repo + "/"),
      Buffer.from([0xff]),
    ]);
    writeFileSync(path, "text");
    expect(
      f.run("generate-in-scope-files", [
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-mode",
        "local-patch",
      ]).status,
    ).toBe(2);
    expect(readFileSync(f.out, "utf8")).toBe("previous\n");
  },
);

test("inventory excludes nested Git metadata and handles long destination names", () => {
  const f = fixture();
  f.write("nested/source");
  git(join(f.repo, "nested"), "init", "-q");
  const out = join(f.root, "a".repeat(251) + ".txt");
  const result = f.run("generate-in-scope-files", [
    "--scope",
    ".",
    "--out",
    out,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(out, "utf8")).toBe("./nested/source\n");
});

test("scope inventory rejects symbolic-link components before lexical parent traversal", () => {
  const f = fixture();
  f.write("src/source");
  symlinkSync(join(f.repo, "src"), join(f.repo, "alias"), "junction");
  const scopes = join(f.root, "scopes.json");
  for (const scope of [
    "alias/source",
    "alias/../src/source",
    `${f.root}${sep}.${sep}repository${sep}alias${sep}..${sep}src${sep}source`,
  ]) {
    writeFileSync(scopes, JSON.stringify([scope]));
    const result = f.run("make-repo-scope-input", ["--scopes-file", scopes]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("symbolic links");
  }
});

test.skipIf(process.platform === "win32")(
  "path inventory refuses output symlinks and creates private replacement files",
  () => {
    const f = fixture();
    f.write("source");
    const target = join(f.root, "existing");
    writeFileSync(target, "untouched\n");
    symlinkSync(target, f.out);
    const rejected = f.run("generate-in-scope-files", ["--scope", "."]);
    expect(rejected.status).toBe(2);
    expect(rejected.stderr).toContain("symbolic link");
    expect(readFileSync(target, "utf8")).toBe("untouched\n");
    rmSync(f.out);
    f.success("generate-in-scope-files", ["--scope", "."]);
    expect(statSync(f.out).mode & 0o777).toBe(0o600);
  },
);

for (const ending of ["\n", "\r"])
  test.skipIf(process.platform === "win32")(
    `launchers preserve undecodable POSIX roots ending ${JSON.stringify(ending)} and scoped names through Git and ripgrep`,
    () => {
      const f = fixture();
      f.write("source", "selected revision\n");
      const base = f.commit();
      f.write("source", "current revision\n");
      f.commit();
      const rawRoot = Buffer.concat([
        Buffer.from(f.root + "/raw-"),
        Buffer.from([0xff]),
        Buffer.from("'`$" + ending),
      ]);
      renameSync(f.repo, rawRoot);
      const rawScope = Buffer.concat([
        Buffer.from("scope-"),
        Buffer.from([0xfe]),
        Buffer.from("'`$"),
      ]);
      mkdirSync(Buffer.concat([rawRoot, Buffer.from("/"), rawScope]));
      writeFileSync(
        Buffer.concat([
          rawRoot,
          Buffer.from("/"),
          rawScope,
          Buffer.from("/entry"),
        ]),
        "scoped source\n",
      );
      const literal = (bytes: Buffer) =>
        [...bytes]
          .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
          .join("");
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp",
      );
      const run = (command: string, scoped: boolean) =>
        spawnSync(
          "/bin/sh",
          [
            "-c",
            [
              `repository=$(printf '%b.' '${literal(rawRoot)}'); repository=\${repository%.}`,
              `scope=$(printf '%b.' '${literal(rawScope)}'); scope=\${scope%.}`,
              `exec "$1" --helper "$2" --repo "$repository" --out "$3" ${scoped ? '--scope "$scope"' : '--base "$4" --head HEAD'}`,
            ].join("\n"),
            "inventory-fixture",
            launcher,
            command,
            f.out,
            base,
          ],
          { encoding: "utf8" },
        );
      const diff = run("make-diff-rank-input", false);
      expect(diff.status, diff.stderr).toBe(0);
      expect(JSON.parse(readFileSync(f.out, "utf8")).preview).toBe(
        "current revision",
      );
      const inventory = run("generate-in-scope-files", true);
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(f.out)).toEqual(
        Buffer.concat([rawScope, Buffer.from("/entry\n")]),
      );
    },
  );

test("Git inventory clears inherited repository selection and keeps forced tracked files", () => {
  const f = fixture();
  f.write(".gitignore", "tracked.py\n");
  f.write("tracked.py");
  git(f.repo, "add", "--force", "tracked.py");
  const env = {
    ...process.env,
    [process.platform === "win32" ? "gIt_DiR" : "GIT_DIR"]: join(
      f.root,
      "missing-git",
    ),
    [process.platform === "win32" ? "gIt_WoRk_TrEe" : "GIT_WORK_TREE"]: f.root,
  };
  const result = f.run("make-repo-rank-input", [], env);
  expect(result.status, result.stderr).toBe(0);
  expect(
    readFileSync(f.out, "utf8")
      .trim()
      .split(/\r?\n/u)
      .map((line) => JSON.parse(line).path),
  ).toEqual([".gitignore", "tracked.py"]);
});

test.skipIf(process.platform === "win32")(
  "path inventories exceed the default execFile output buffer",
  () => {
    const f = fixture(),
      bin = join(f.root, "bin");
    mkdirSync(bin);
    const command = join(bin, "rg"),
      count = 20_000,
      prefix = "source-".repeat(15);
    writeFileSync(
      command,
      `#!${node}\nfor(let index=0;index<${count};index++) process.stdout.write(${JSON.stringify(prefix)}+String(index).padStart(5,'0')+'\\0');\n`,
      { mode: 0o700 },
    );
    const result = f.run("generate-in-scope-files", ["--scope", "."], {
      ...process.env,
      PATH: bin,
      CODEX_SECURITY_GIT: "",
    });
    expect(result.status, result.stderr).toBe(0);
    const rows = readFileSync(f.out, "utf8").trimEnd().split("\n");
    expect(rows.length).toBe(count);
    expect(rows[0]).toBe(prefix + "00000");
    expect(rows.at(-1)).toBe(prefix + "19999");
  },
);

test("explicit scopes preserve literal glob, tilde and colon filenames", () => {
  const f = fixture();
  const files =
    process.platform === "win32"
      ? ["src/[slug]/page.tsx", "~/example.ts"]
      : [
          "src/[slug]/page.tsx",
          "src/star*file.ts",
          "src/question?file.ts",
          "~/example.ts",
          "module:handler.ts",
        ];
  for (const path of [
    ...files,
    "src/s/page.tsx",
    "src/l/page.tsx",
    "src/starOtherfile.ts",
    "src/questionXfile.ts",
  ])
    f.write(path);
  f.commit();
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify(["src/[slug]", ...files.slice(1)]));
  expect(
    f
      .rows("make-repo-scope-input", ["--scopes-file", scopes])
      .map((row) => row.path),
  ).toEqual([...files].sort());
});

for (const rawExecutable of [false, true])
  test.skipIf(process.platform === "win32")(
    `Git children retain raw HOME/PATH and explicit Git filters (raw executable: ${rawExecutable})`,
    () => {
      const f = fixture();
      f.write("visible.py");
      f.write("hidden.py");
      const home = Buffer.concat([
        Buffer.from(f.root + "/home-"),
        Buffer.from([0xff]),
      ]);
      const bin = Buffer.concat([
        Buffer.from(f.root + "/bin-"),
        Buffer.from([0xfe]),
      ]);
      mkdirSync(home);
      mkdirSync(bin);
      writeFileSync(
        Buffer.concat([home, Buffer.from("/.gitconfig")]),
        "[core]\nexcludesFile = ~/.gitignore_global\n",
      );
      writeFileSync(
        Buffer.concat([home, Buffer.from("/.gitignore_global")]),
        "hidden.py\n",
      );
      writeFileSync(
        Buffer.concat([bin, Buffer.from("/inventory-child-tool")]),
        '#!/bin/sh\nprintf executed > "$INVENTORY_CHILD_MARKER"\n',
        { mode: 0o700 },
      );
      const gitPath = Buffer.concat([
        Buffer.from(f.root + "/git-"),
        rawExecutable ? Buffer.from([0xfd]) : Buffer.from("wrapper"),
      ]);
      const hostGit = Bun.which("git")!;
      const quote = (value: string) =>
        "'" + value.replaceAll("'", "'\\''") + "'";
      writeFileSync(
        gitPath,
        `#!/bin/sh\nset -e\ntest "$GIT_LITERAL_PATHSPECS" = 1\ntest -z "\${GIT_DIR+x}"\ninventory-child-tool\nexec ${quote(hostGit)} "$@"\n`,
        { mode: 0o700 },
      );
      const octal = (bytes: Buffer) =>
        [...bytes]
          .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
          .join("");
      const marker = join(f.root, "child-ran");
      const script = [
        `HOME=$(printf '%b' '${octal(home)}'); export HOME`,
        `raw_bin=$(printf '%b' '${octal(bin)}'); PATH="$raw_bin"; export PATH`,
        `CODEX_SECURITY_GIT=$(printf '%b' '${octal(gitPath)}'); export CODEX_SECURITY_GIT`,
        'exec "$1" "$2" make-repo-rank-input --repo "$3" --out "$4"',
      ].join("\n");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          script,
          "inventory-env",
          node,
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          f.repo,
          f.out,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            GIT_CONFIG_GLOBAL: undefined,
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_DIR: join(f.root, "wrong-git"),
            GIT_LITERAL_PATHSPECS: "0",
            INVENTORY_CHILD_MARKER: marker,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(
        readFileSync(f.out, "utf8")
          .trim()
          .split(/\r?\n/u)
          .map((line) => JSON.parse(line).path),
      ).toEqual(["visible.py"]);
      expect(readFileSync(marker, "utf8")).toBe("executed");
    },
  );

test.skipIf(process.platform === "win32")(
  "ripgrep children retain raw HOME and PATH",
  () => {
    const f = fixture();
    f.write("visible.py");
    const home = Buffer.concat([
      Buffer.from(f.root + "/home-"),
      Buffer.from([0xff]),
    ]);
    const bin = Buffer.concat([
      Buffer.from(f.root + "/bin-"),
      Buffer.from([0xfe]),
    ]);
    mkdirSync(home);
    mkdirSync(bin);
    writeFileSync(Buffer.concat([home, Buffer.from("/marker")]), "raw-home\n");
    writeFileSync(
      Buffer.concat([bin, Buffer.from("/rg")]),
      '#!/bin/sh\nset -e\nIFS= read -r value < "$HOME/marker"\ntest "$value" = raw-home\nprintf "./visible.py\\0"\n',
      { mode: 0o700 },
    );
    const octal = (bytes: Buffer) =>
      [...bytes]
        .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
        .join("");
    const script = [
      `HOME=$(printf '%b' '${octal(home)}'); export HOME`,
      `PATH=$(printf '%b' '${octal(bin)}'); export PATH`,
      'exec "$1" "$2" generate-in-scope-files --repo "$3" --scope . --out "$4"',
    ].join("\n");
    const result = spawnSync(
      "/bin/sh",
      [
        "-c",
        script,
        "inventory-env",
        node,
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        f.repo,
        f.out,
      ],
      { encoding: "utf8", env: { ...process.env, CODEX_SECURITY_GIT: "" } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.out, "utf8")).toBe("./visible.py\n");
  },
);

test.skipIf(process.platform === "win32")(
  "Git discovery distinguishes absent and empty PATH",
  () => {
    const f = fixture();
    f.write(".gitignore", "retained.txt\n");
    f.write("retained.txt");
    git(f.repo, "add", "--force", "retained.txt");
    const env = {
      ...process.env,
      CODEX_SECURITY_GIT: undefined,
      PATH: undefined,
    };
    const result = f.run("make-repo-rank-input", [], env);
    expect(result.status, result.stderr).toBe(0);
    expect(
      readFileSync(f.out, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line).path),
    ).toContain("retained.txt");
    expect(
      f.run("make-repo-rank-input", [], { ...env, PATH: "" }).status,
    ).not.toBe(0);
  },
);

for (const setting of [
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "XDG_CONFIG_HOME",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_VALUE_0",
  "RIPGREP_CONFIG_PATH",
])
  test.skipIf(process.platform === "win32")(
    `inventory tools retain raw ${setting} configuration`,
    () => {
      const f = fixture();
      f.write("visible.py");
      f.write("hidden.py");
      const rawPath = Buffer.concat([
        Buffer.from(f.root + "/configuration-"),
        Buffer.from([0xff]),
      ]);
      const ignore = join(f.root, "ignore");
      writeFileSync(ignore, "hidden.py\n");
      let value = rawPath;
      if (
        setting === "GIT_CONFIG_PARAMETERS" ||
        setting === "GIT_CONFIG_VALUE_0"
      ) {
        writeFileSync(rawPath, "hidden.py\n");
        if (setting === "GIT_CONFIG_PARAMETERS")
          value = Buffer.concat([
            Buffer.from("'core.excludesFile="),
            rawPath,
            Buffer.from("'"),
          ]);
      } else {
        let config = rawPath;
        if (setting === "XDG_CONFIG_HOME") {
          mkdirSync(Buffer.concat([rawPath, Buffer.from("/git")]), {
            recursive: true,
          });
          config = Buffer.concat([rawPath, Buffer.from("/git/config")]);
        }
        writeFileSync(
          config,
          setting === "RIPGREP_CONFIG_PATH"
            ? "--glob\n!hidden.py\n"
            : `[core]\nexcludesFile = ${JSON.stringify(ignore)}\n`,
        );
      }
      const octal = [...value]
        .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
        .join("");
      const command =
        setting === "RIPGREP_CONFIG_PATH"
          ? "generate-in-scope-files"
          : "make-repo-rank-input";
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          `${setting}=$(printf '%b' '${octal}'); export ${setting}\nexec "$1" "$2" "$3" --repo "$4" --out "$5" --scope .`,
          "inventory-config",
          node,
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          command,
          f.repo,
          f.out,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            ...(setting === "RIPGREP_CONFIG_PATH" ? {} : { HOME: f.root }),
            CODEX_SECURITY_GIT: Bun.which("git")!,
            GIT_CONFIG_GLOBAL:
              setting === "XDG_CONFIG_HOME" ? undefined : "/dev/null",
            GIT_CONFIG_SYSTEM: "/dev/null",
            GIT_CONFIG_PARAMETERS: undefined,
            GIT_CONFIG_COUNT:
              setting === "GIT_CONFIG_VALUE_0" ? "1" : undefined,
            GIT_CONFIG_KEY_0: "core.excludesFile",
            GIT_CONFIG_VALUE_0: undefined,
            GIT_CONFIG_NOSYSTEM: undefined,
            XDG_CONFIG_HOME: undefined,
            RIPGREP_CONFIG_PATH: undefined,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      const lines = readFileSync(f.out, "utf8").trim().split("\n");
      expect(
        setting === "RIPGREP_CONFIG_PATH"
          ? lines
          : lines.map((line) => JSON.parse(line).path),
      ).toEqual([
        setting === "RIPGREP_CONFIG_PATH" ? "./visible.py" : "visible.py",
      ]);
    },
  );

test("absolute file scopes work when the repository is a filesystem root", () => {
  const f = fixture();
  const source = f.write("source.py");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify([source]));
  const root = parse(f.repo).root;
  const result = f.run("make-repo-scope-input", [
    "--repo",
    root,
    "--scopes-file",
    scopes,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(readFileSync(f.out, "utf8")).path).toBe(
    relative(root, source).split(sep).join("/"),
  );
});

test.skipIf(process.platform !== "win32")(
  "drive-relative scopes stay anchored to the repository",
  () => {
    const f = fixture();
    f.write("src/source.py");
    const scope = `${parse(f.repo).root.slice(0, 2)}src`;
    expect(
      f.rows("make-repo-rank-input", ["--scope", scope]).map((row) => row.path),
    ).toEqual(["src/source.py"]);
    const scopes = join(f.root, "scopes.json");
    writeFileSync(scopes, JSON.stringify([scope]));
    expect(
      f
        .rows("make-repo-scope-input", ["--scopes-file", scopes])
        .map((row) => row.path),
    ).toEqual(["src/source.py"]);
  },
);

test("preview trimming handles a full sample of leading blank lines", () => {
  const f = fixture();
  f.write("source.py", "\n".repeat(64_000) + "kept\n");
  expect(f.rows()[0]!.preview).toBe("kept");
});

for (const command of ["make-repo-rank-input", "make-repo-scope-input"])
  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    `${command} reports unreadable tracked directories without replacing output`,
    () => {
      const f = fixture();
      f.write("private/source.py");
      git(f.repo, "add", ".");
      const scopes = join(f.root, "scopes.json");
      writeFileSync(scopes, JSON.stringify(["."]));
      writeFileSync(f.out, "previous\n");
      const directory = join(f.repo, "private");
      chmodSync(directory, 0);
      try {
        const result = f.run(command, ["--scopes-file", scopes]);
        expect(result.status).toBe(1);
        expect(result.stderr).toMatch(/EACCES|permission denied/iu);
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      } finally {
        chmodSync(directory, 0o700);
      }
    },
  );

test("inventory skips stale tracked entries after deletion and directory replacement", () => {
  const f = fixture();
  f.write("deleted.py");
  f.write("replaced/source.py");
  git(f.repo, "add", ".");
  rmSync(join(f.repo, "deleted.py"));
  rmSync(join(f.repo, "replaced"), { recursive: true });
  f.write("replaced");
  expect(f.rows().map((row) => row.path)).toEqual(["replaced"]);
});

test("absolute explicit scopes ignore dot and empty components before the repo", () => {
  const f = fixture();
  f.write("src/source.py");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(
    scopes,
    JSON.stringify([
      `${f.root}${sep}.${sep}repository${sep}src${sep}source.py`,
      `${f.root}${sep}${sep}repository${sep}src${sep}source.py`,
    ]),
  );
  expect(
    f
      .rows("make-repo-scope-input", ["--scopes-file", scopes])
      .map((row) => row.path),
  ).toEqual(["src/source.py"]);
});

test("diff inventory expands a home-relative repository scope", () => {
  const f = fixture();
  f.write("source.py", "before\n");
  const base = f.commit();
  f.write("source.py", "after\n");
  const result = f.run(
    "generate-in-scope-files",
    [
      "--scope",
      "~/repository",
      "--diff-base",
      base,
      "--diff-mode",
      "local-patch",
    ],
    { ...process.env, HOME: f.root, USERPROFILE: f.root },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.out, "utf8")).toBe("source.py\n");
});

test.skipIf(process.platform === "win32")(
  "inventory falls back to ripgrep when selected Git's interpreter is missing",
  () => {
    const f = fixture();
    f.write("source.py");
    const selectedGit = join(f.root, "git");
    writeFileSync(selectedGit, `#!${join(f.root, "missing-interpreter")}\n`, {
      mode: 0o700,
    });
    const result = f.run("make-repo-rank-input", [], {
      ...process.env,
      CODEX_SECURITY_GIT: selectedGit,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(f.out, "utf8")).path).toBe("source.py");
  },
);

test("inventory preserves scoped names beneath dotted-I repository names", () => {
  const f = fixture();
  f.write("scope/source.py", "kept\n");
  const repository = join(f.root, "İrepository");
  renameSync(f.repo, repository);
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify(["scope"]));
  for (const command of ["make-repo-scope-input", "make-repo-rank-input"]) {
    const rows = f.rows(command, [
      "--repo",
      repository,
      "--scopes-file",
      scopes,
    ]);
    expect(rows.map((row) => row.path)).toEqual(["scope/source.py"]);
    if (command === "make-repo-rank-input")
      expect(rows[0]).toMatchObject({ area: "scope", preview: "kept" });
  }
});
