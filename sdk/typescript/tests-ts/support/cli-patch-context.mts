import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { main } from "../../src/cli.js";
import { capture, dependencies } from "../cli-fixtures.js";

const root = process.argv[2]!;
const outcomes = [];
for (const kind of ["absolute Git alias", "relative Git alias", "gh", "glab"]) {
  const directory = join(root, kind);
  const repository = join(directory, "repository");
  const remote = join(directory, "remote.git");
  const alias = join(directory, "alias");
  await mkdir(repository, { recursive: true });
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    HOME: directory,
    USERPROFILE: directory,
    GIT_CONFIG_GLOBAL: join(directory, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const git = (args: string[], cwd = repository, env = environment) =>
    execFileSync("git", args, {
      cwd,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  git(["init", "--initial-branch=main"]);
  git(["config", "user.name", "Synthetic User"]);
  git(["config", "user.email", "synthetic@example.test"]);
  git(["config", "user.useConfigOnly", "true"]);
  await writeFile(join(repository, "app.ts"), "original\n");
  git(["add", "."]);
  git(["commit", "-m", "Synthetic initial checkout"]);
  git(["init", "--bare", remote]);
  git(["remote", "add", "origin", remote]);
  if (kind.includes("Git alias")) {
    await symlink(
      repository,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    environment["GIT_DIR"] = (
      kind.startsWith("relative")
        ? relative(repository, join(alias, ".git"))
        : join(alias, ".git")
    ).replaceAll(sep, "/");
    await writeFile(
      environment["GIT_CONFIG_GLOBAL"]!,
      `[includeIf "gitdir:${kind.startsWith("relative") ? `${repository.replaceAll(sep, "/")}/${environment["GIT_DIR"]}` : "**/alias/.git"}"]\npath = identity\n`,
    );
    await writeFile(
      join(directory, "identity"),
      "[user]\nname = Synthetic Alias\nemail = alias@example.test\n",
    );
    git(["config", "--local", "--unset", "user.name"]);
    git(["config", "--local", "--unset", "user.email"]);
    assert.ok(
      git(["var", "GIT_AUTHOR_IDENT"]).startsWith(
        "Synthetic Alias <alias@example.test> ",
      ),
    );
  } else {
    await mkdir(join(directory, "elsewhere", "target"), { recursive: true });
    await symlink(
      join(directory, "elsewhere", "target"),
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    for (const parent of [directory, join(directory, "elsewhere")]) {
      await mkdir(join(parent, "config"));
      await writeFile(
        join(parent, "config", "config.yml"),
        parent === directory
          ? "selected configuration\n"
          : "different configuration\n",
      );
    }
    environment[kind === "gh" ? "GH_CONFIG_DIR" : "GLAB_CONFIG_DIR"] =
      `${relative(repository, alias)}/../config`;
  }
  const output = capture();
  const error = capture();
  const exitCode = await main(
    ["patch", "Synthetic issue", "--create-pr", "--json"],
    output.stream,
    error.stream,
    dependencies({
      currentDirectory: repository,
      environment,
      onCodex: async (_args, output) => {
        await writeFile(join(repository, "app.ts"), "fixed\n");
        output?.stdout.write("Patch complete.");
        return 0;
      },
      onRepositoryCommand: async (command, args, cwd, options) => {
        const selectedEnvironment = { ...environment, ...options?.environment };
        if (command === "git") {
          if (kind === "glab" && args[0] === "remote")
            return "https://gitlab.com/example/repository.git";
          if (kind === "glab" && args[0] === "ls-remote")
            args = [...args.slice(0, 3), remote, ...args.slice(4)];
          const result = git(
            args,
            options?.directory ?? cwd,
            selectedEnvironment,
          );
          return options?.trim === false ? result : result.trim();
        }
        if (!kind.includes("Git alias")) {
          const selected =
            selectedEnvironment[
              kind === "gh" ? "GH_CONFIG_DIR" : "GLAB_CONFIG_DIR"
            ]!;
          const contents = await readFile(
            resolve(options?.directory ?? cwd, selected, "config.yml"),
            "utf8",
          );
          if (contents !== "selected configuration\n")
            throw new Error("Provider configuration changed after patching");
        }
        return args[1] === "create"
          ? "https://github.example.test/example/repository/pull/17"
          : "";
      },
    }),
  );
  outcomes.push({
    kind,
    exitCode,
    error: error.text(),
    applied: JSON.parse(output.text()).applied,
  });
  await rm(directory, { recursive: true });
}
console.log(JSON.stringify(outcomes));
