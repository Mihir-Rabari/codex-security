import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [
    fileURLToPath(new URL("../src/native-executable.ts", import.meta.url)),
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { resolveCodexPath, resolveTrustedCodex, snapshotNativeEnvironment } =
  await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
const temporaryRoots = [];
try {
  await testWindowsNpmPackageResolution();
  await testWindowsNpmPackageResolution("managed");
  await testCodexHomePathsStayBoundToOriginalDirectory();
  if (process.platform === "win32") {
    await testWindowsWorkerEnvironmentPreservesMixedCaseKeys();
    await testWindowsLauncherSkipsExtensionlessNpmShim();
  }
  assert.equal(
    resolveCodexPath({ CODEX_CLI_PATH: "C:\\Tools\\codex.exe" }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  assert.equal(
    resolveCodexPath({ codex_cli_path: "C:\\Tools\\codex.exe" }, "win32"),
    "C:\\Tools\\codex.exe",
  );
  const originalCwd = path.join(process.cwd(), "fixture-root");
  assert.equal(
    resolveCodexPath(
      { CODEX_CLI_PATH: "fixture/codex" },
      "linux",
      process.arch,
      originalCwd,
    ),
    path.join(originalCwd, "fixture/codex"),
  );
} finally {
  await Promise.all(
    temporaryRoots.map((root) => rm(root, { recursive: true, force: true })),
  );
}

async function testCodexHomePathsStayBoundToOriginalDirectory() {
  if (process.platform === "win32") {
    assert.equal(
      resolveCodexPath(
        { CODEX_CLI_PATH: "\\Tools\\codex.exe" },
        "win32",
        process.arch,
        "C:\\original\\cwd",
      ),
      "C:\\Tools\\codex.exe",
    );
    assert.equal(
      resolveCodexPath(
        { CODEX_CLI_PATH: "/Tools/codex.exe" },
        "win32",
        process.arch,
        "D:\\original\\cwd",
      ),
      "D:\\Tools\\codex.exe",
    );
  }

  // Root-relative Windows paths use the cwd drive, which can differ from TEMP.
  const root = await mkdtemp(
    path.join(
      process.platform === "win32" ? process.cwd() : tmpdir(),
      "codex-security-native-home-",
    ),
  );
  temporaryRoots.push(root);
  const target = path.join(root, "target", "nested");
  await Promise.all([
    mkdir(target, { recursive: true }),
    mkdir(path.join(root, "target", "home"), { recursive: true }),
    mkdir(path.join(root, "home")),
  ]);
  await symlink(target, path.join(root, "link"), "junction");

  const previousCodexHome = process.env.CODEX_HOME;
  try {
    const homes = [
      `${root}${path.sep}link${path.sep}..${path.sep}home`,
      `  ${root}${path.sep}home  `,
      `${path.relative(process.cwd(), root)}${path.sep}link${path.sep}..${path.sep}home`,
      ...(process.platform === "win32"
        ? [`\\${path.relative(path.parse(root).root, root)}\\link\\..\\home`]
        : []),
    ];
    for (const home of homes) {
      process.env.CODEX_HOME = home;
      const expectedHome = await realpath(path.resolve(home.trim()));
      const environment = await snapshotNativeEnvironment();
      assert.equal(environment.CODEX_HOME, expectedHome);
      assert.equal(process.env.CODEX_HOME, home);
      const childCwd = await realpath(target);
      const child = spawnSync(
        process.execPath,
        [
          "-e",
          [
            "const { realpathSync } = require('node:fs');",
            "process.stdout.write(JSON.stringify({ cwd: process.cwd(), codexHome: process.env.CODEX_HOME, resolvedHome: realpathSync(process.env.CODEX_HOME) }));",
          ].join("\n"),
        ],
        { encoding: "utf8", env: environment, cwd: childCwd },
      );
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0);
      assert.deepEqual(JSON.parse(child.stdout), {
        cwd: childCwd,
        codexHome: expectedHome,
        resolvedHome: expectedHome,
      });
    }
  } finally {
    restoreEnv("CODEX_HOME", previousCodexHome);
  }
}

async function testWindowsWorkerEnvironmentPreservesMixedCaseKeys() {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-windows-env-")),
  );
  temporaryRoots.push(root);
  const names = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_MANAGED_PACKAGE_ROOT",
    "LOCALAPPDATA",
  ];
  const previousEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      names.includes(key.toUpperCase()),
    ),
  );
  const values = {
    CODEX_CLI_PATH: path.join(root, "custom-codex.exe"),
    CODEX_HOME: root,
    CODEX_MANAGED_PACKAGE_ROOT: path.join(root, "managed-package"),
    LOCALAPPDATA: path.join(root, "local-app-data"),
  };
  try {
    for (const name of names) delete process.env[name];
    for (const [name, value] of Object.entries(values))
      process.env[name.toLowerCase()] = value;

    const environment = await snapshotNativeEnvironment();
    for (const [name, value] of Object.entries(values)) {
      assert.equal(environment[name], value);
      assert.deepEqual(
        Object.keys(environment).filter((key) => key.toUpperCase() === name),
        [name],
      );
      assert.equal(process.env[name.toLowerCase()], value);
    }
    assert.equal(resolveCodexPath(environment, "win32"), values.CODEX_CLI_PATH);
  } finally {
    for (const name of names) delete process.env[name];
    Object.assign(process.env, previousEnvironment);
  }
}

async function testWindowsLauncherSkipsExtensionlessNpmShim() {
  const root = await mkdtemp(
    path.join(tmpdir(), "codex-security-windows-launcher-"),
  );
  temporaryRoots.push(root);
  const shimDirectory = path.join(root, "npm-shims");
  const binaryDirectory = path.join(root, "native-bin");
  await Promise.all([mkdir(shimDirectory), mkdir(binaryDirectory)]);
  await writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n");
  await copyFile(process.execPath, path.join(binaryDirectory, "codex.exe"));

  const brokenEnvironment = windowsLauncherEnvironment(shimDirectory);
  const broken = spawnSync("codex", ["--version"], {
    encoding: "utf8",
    env: brokenEnvironment,
  });
  assert.equal(["ENOENT", "EPERM"].includes(broken.error?.code), true);

  const environment = windowsLauncherEnvironment(
    shimDirectory,
    binaryDirectory,
  );
  const fixed = spawnSync(
    resolveCodexPath(environment, "win32"),
    ["--version"],
    {
      encoding: "utf8",
      env: environment,
    },
  );
  assert.equal(fixed.error, undefined);
  assert.equal(fixed.status, 0);
  assert.equal(fixed.stdout.trim(), process.version);
}

async function testWindowsNpmPackageResolution(installation = "global") {
  const root = await mkdtemp(
    path.join(tmpdir(), "codex-security windows-npm-"),
  );
  temporaryRoots.push(root);
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetTriple =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : "x86_64-pc-windows-msvc";
  const packageDirectory =
    installation === "managed"
      ? path.join(root, "node_modules")
      : path.join(root, "npm", "node_modules");
  const shimDirectory =
    installation === "managed"
      ? path.join(packageDirectory, ".bin")
      : path.join(root, "npm");
  const codexPackage = path.join(packageDirectory, "@openai", "codex");
  const platformPackage = path.join(
    codexPackage,
    "node_modules",
    "@openai",
    `codex-win32-${architecture}`,
  );
  const nativeBinary = path.join(
    platformPackage,
    "vendor",
    targetTriple,
    "bin",
    "codex.exe",
  );
  await Promise.all([
    mkdir(path.dirname(nativeBinary), { recursive: true }),
    mkdir(shimDirectory, { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(shimDirectory, "codex"), "#!/bin/sh\nexit 1\n"),
    writeFile(
      path.join(codexPackage, "package.json"),
      JSON.stringify({ name: "@openai/codex" }),
    ),
    writeFile(
      path.join(platformPackage, "package.json"),
      JSON.stringify({ name: `@openai/codex-win32-${architecture}` }),
    ),
    copyFile(process.execPath, nativeBinary),
  ]);

  const environment = windowsLauncherEnvironment(shimDirectory);
  if (installation === "managed") {
    environment.CODEX_MANAGED_PACKAGE_ROOT = codexPackage;
  }
  assert.equal(
    await realpath(resolveCodexPath(environment, "win32", architecture)),
    await realpath(nativeBinary),
  );
  const repository = path.join(root, "repository");
  await mkdir(repository);
  const selected = await resolveTrustedCodex(
    environment,
    repository,
    "win32",
    architecture,
  );
  assert.ok(selected);
  assert.equal(
    await realpath(selected.executable),
    await realpath(nativeBinary),
  );
  if (installation === "global") {
    const repositoryBin = path.join(repository, "bin");
    const alias = path.join(root, "repository-bin-alias");
    await mkdir(repositoryBin, { recursive: true });
    await copyFile(process.execPath, path.join(repositoryBin, "codex.exe"));
    await symlink(repositoryBin, alias, "junction");
    for (const configured of [undefined, "codex", "codex.exe"]) {
      for (const quoted of [false, true]) {
        const directories = [repositoryBin, alias, shimDirectory].map(
          (directory) => (quoted ? `"${directory}"` : directory),
        );
        const search = windowsLauncherEnvironment(...directories);
        if (configured !== undefined) search.CODEX_CLI_PATH = configured;
        const trusted = await resolveTrustedCodex(
          search,
          repository,
          "win32",
          architecture,
        );
        assert.ok(
          trusted,
          "a later trusted npm installation must remain discoverable",
        );
        assert.equal(
          await realpath(trusted.executable),
          await realpath(nativeBinary),
        );
        if (!quoted || process.platform === "win32") {
          assert.equal(trusted.environment.PATH, await realpath(shimDirectory));
        }
        assert.equal(search.Path, directories.join(path.delimiter));
      }
    }
    const explicit = windowsLauncherEnvironment(repositoryBin, shimDirectory);
    explicit.CODEX_CLI_PATH = path.join(repositoryBin, "codex.exe");
    assert.equal(
      await resolveTrustedCodex(explicit, repository, "win32", architecture),
      null,
    );
  }
  if (installation === "managed") {
    const mixedCaseEnvironment = {
      ...environment,
      codex_managed_package_root: codexPackage,
    };
    delete mixedCaseEnvironment.CODEX_MANAGED_PACKAGE_ROOT;
    assert.equal(
      await realpath(
        resolveCodexPath(mixedCaseEnvironment, "win32", architecture),
      ),
      await realpath(nativeBinary),
    );
  }
  if (process.platform === "win32") {
    assert.equal(
      spawnSync("codex.exe", ["--version"], {
        encoding: "utf8",
        env: environment,
      }).error?.code,
      "ENOENT",
    );

    const fixed = spawnSync(
      resolveCodexPath(environment, "win32", architecture),
      ["--version"],
      {
        encoding: "utf8",
        env: environment,
      },
    );
    assert.equal(fixed.error, undefined);
    assert.equal(fixed.status, 0);
    assert.equal(fixed.stdout.trim(), process.version);
  }
}

function windowsLauncherEnvironment(...directories) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.toLowerCase() === "path") {
      delete environment[key];
    }
  }
  delete environment.CODEX_CLI_PATH;
  delete environment.CODEX_MANAGED_PACKAGE_ROOT;
  environment.Path = directories.join(path.delimiter);
  return environment;
}

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
