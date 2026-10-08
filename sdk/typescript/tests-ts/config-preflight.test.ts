import { cp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { windowsHelperFixture } from "./windows-helper-command.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const { temporaryDirectory, cleanup } =
  createApiTestFixtures("config-preflight-");
afterEach(cleanup);
const v1 = [
  "--multi-agent-runtime-owner",
  "native",
  "--multi-agent-runtime-version",
  "v1",
  "--multi-agent-runtime-provenance",
  "app-server",
];
const bridge = [
  "--multi-agent-runtime-owner",
  "codex-bridge",
  "--multi-agent-runtime-version",
  "v2",
  "--multi-agent-runtime-provenance",
  "verified-bridge",
];
const available = [
  "--runtime-check",
  "delegation_available=true",
  "--runtime-check",
  "goal_tools_available=true",
];
interface Result {
  capability: string;
  status: string;
  actual?: unknown;
  configured_value?: unknown;
  source?: string;
  severity?: string;
}
interface Payload {
  status: string;
  error?: string;
  profile: string;
  config_paths: string[];
  user_config_path: string | null;
  config_profile: string | null;
  config_profile_path: string | null;
  config_resolution: string;
  config_discovery: Record<string, unknown> | null;
  multi_agent_mode: string;
  multi_agent_context: Record<string, unknown>;
  remediation: Record<string, unknown>;
  results: Result[];
  failed: Result[];
  unknown: Result[];
}

async function run(args: string[], env?: NodeJS.ProcessEnv, cwd?: string) {
  const result = await runCommand(node, [helper, "config-preflight", ...args], {
    env: { ...process.env, ...env },
    cwd,
  });
  return {
    ...result,
    payload: result.stdout.startsWith("{")
      ? (JSON.parse(result.stdout) as Payload)
      : undefined,
  };
}

async function configured(
  config: string,
  args: string[] = [],
  profile = "security_scan",
) {
  const root = await temporaryDirectory();
  const file = join(root, "config.toml");
  await writeFile(file, config);
  return {
    ...(await run(["--profile", profile, "--config", file, ...args])),
    file,
  };
}

const capacity = (payload: Payload) =>
  payload.results.find((item) => item.capability === "usable_worker_slots_6")!;
const goals = (payload: Payload) =>
  payload.results.find((item) => item.capability === "goals_enabled")!;

test("bundled profiles route scans and keep optional capabilities advisory", async () => {
  const registry = parseToml(
    await readFile(
      join(PLUGIN_ROOT, "preflight/capability-profiles.toml"),
      "utf8",
    ),
  );
  expect(registry["version"]).toBe(1);
  for (const [skill, profile] of [
    ["security-scan", "security_scan"],
    ["security-diff-scan", "security_diff_scan"],
    ["deep-security-scan", "deep_security_scan"],
  ]) {
    const result = await run([
      "--skill",
      skill!,
      "--config",
      join(await temporaryDirectory(), "missing.toml"),
    ]);
    expect(result.status).toBe(0);
    expect(result.payload!.profile).toBe(profile!);
    expect(result.payload!.status).toBe("ready");
    expect(result.payload!.failed).toEqual([]);
    if (profile === "deep_security_scan")
      expect(result.payload!.results).toEqual([]);
    else
      expect(
        result.payload!.unknown.some(
          (item) => item.capability === "delegated_workers",
        ),
      ).toBe(true);
    if (profile === "security_diff_scan")
      expect(goals(result.payload!).actual).toBe(true);
    else
      expect(
        result.payload!.results.some(
          (item) =>
            item.capability === "goal_tools" ||
            item.capability === "goals_enabled",
        ),
      ).toBe(false);
    expect(JSON.stringify(result.payload)).not.toContain("csv_fanout");
  }
});

test.each([
  ["v1 default", "", v1, "v1", 6, "pass"],
  ["v1 configured", "[agents]\nmax_threads=8\n", v1, "v1", 8, "pass"],
  ["v1 insufficient", "[agents]\nmax_threads=4\n", v1, "v1", 4, "fail"],
  [
    "unknown mode",
    "[agents]\nmax_threads=8\n",
    [],
    "unknown",
    undefined,
    "unknown",
  ],
  [
    "native v2",
    "[features.multi_agent_v2]\nenabled=true\nmax_concurrent_threads_per_session=9\n",
    [],
    "v2",
    8,
    "pass",
  ],
  [
    "native v2 default",
    "[features]\nmulti_agent_v2=true\n",
    [],
    "v2",
    3,
    "fail",
  ],
  [
    "native v1 feature",
    "[features]\nmulti_agent_v2=false\n",
    [],
    "v1",
    6,
    "pass",
  ],
  [
    "verified bridge",
    "[multiagent_config]\nmax_concurrency=9\n",
    bridge,
    "bridge-v2",
    8,
    "pass",
  ],
  [
    "bridge runtime cap",
    "",
    [...bridge, "--multi-agent-session-cap", "7"],
    "bridge-v2",
    6,
    "pass",
  ],
  ["bridge missing cap", "", bridge, "bridge-v2", undefined, "unknown"],
  [
    "native model-selected v2",
    "[agents]\nmax_threads=9\n",
    [
      "--multi-agent-runtime-owner",
      "native",
      "--multi-agent-runtime-version",
      "v2",
      "--multi-agent-runtime-provenance",
      "tool-surface",
    ],
    "v2",
    undefined,
    "unknown",
  ],
  ["TOML float", "[agents]\nmax_threads=8.0\n", v1, "v1", 8, "fail"],
  ["TOML boolean", "[agents]\nmax_threads=true\n", v1, "v1", true, "fail"],
  [
    "effective override",
    "[agents]\nmax_threads=4\n",
    [...v1, "--effective-config", "agents.max_threads=9"],
    "v1",
    9,
    "pass",
  ],
  [
    "effective float",
    "",
    [...v1, "--effective-config", "agents.max_threads=9.0"],
    "v1",
    9,
    "fail",
  ],
] as const)(
  "reports worker capacity: %s",
  async (_name, config, args, mode, actual, status) => {
    const result = await configured(config, [
      ...args,
      "--runtime-check",
      "delegation_available=false",
    ]);
    expect(result.status).toBe(0);
    expect(result.payload!.multi_agent_mode).toBe(mode);
    expect(capacity(result.payload!).status).toBe(status);
    expect(capacity(result.payload!).actual).toBe(actual);
    expect(
      result.payload!.failed.find(
        (item) => item.capability === "delegated_workers",
      )?.severity,
    ).toBe("warn");
  },
);

test.each(
  (
    [
      ["", v1],
      [
        "[agents]\nmax_threads=9\n",
        [
          "--multi-agent-runtime-owner",
          "native",
          "--multi-agent-runtime-version",
          "v2",
          "--multi-agent-runtime-provenance",
          "tool-surface",
        ],
      ],
      ["[features]\nmulti_agent_v2=true\n", []],
      ["[multiagent_config]\nmax_concurrency=9\n", []],
      ["", bridge],
    ] as const
  ).map(([config, args], index) => [String(index + 1), config, args] as const),
)(
  "deep compatibility profile adds no requirements (case %s)",
  async (_case, config, args) => {
    const result = await configured(
      config,
      [...args, "--available-plugin-skill", "validation"],
      "deep_security_scan",
    );
    expect(result.status).toBe(0);
    expect(result.payload!.results).toEqual([]);
    expect(result.payload!.remediation["patches"]).toBeUndefined();
  },
);

test("disabled goals remain a suggestion with actionable remediation", async () => {
  const result = await configured(
    "[features]\ngoals=false\n",
    [...available, ...v1],
    "security_diff_scan",
  );
  expect(result.status).toBe(0);
  expect(goals(result.payload!)).toMatchObject({
    status: "fail",
    severity: "suggest",
    actual: false,
  });
  expect(result.payload!.remediation["patches"]).toContainEqual({
    path: "features.goals",
    value: true,
  });
});

test.each([
  [
    "",
    'profile="scan.fast"\n[profiles."scan.fast".features]\ngoals=true\n',
    true,
  ],
  [
    'profile="scan"\n[profiles.scan.features]\ngoals=true\n',
    "[features]\ngoals=false\n",
    false,
  ],
  [
    "[features]\nmulti_agent_v2=true\n",
    "[features.multi_agent_v2]\nmax_concurrent_threads_per_session=9\n",
    8,
  ],
  [
    "[features.multi_agent_v2]\nenabled=true\nmax_concurrent_threads_per_session=9\n",
    "[features]\nmulti_agent_v2=false\n",
    6,
  ],
  [
    "[features.multi_agent_v2]\nenabled=false\nmax_concurrent_threads_per_session=9\n",
    "[features]\nmulti_agent_v2=true\n",
    8,
  ],
] as const)(
  "resolves config layers and partial feature tables (%s)",
  async (lower, higher, expected) => {
    const root = await temporaryDirectory();
    const a = join(root, "a.toml"),
      b = join(root, "b.toml");
    await writeFile(a, lower);
    await writeFile(b, higher);
    const result = await run([
      "--profile",
      typeof expected === "boolean" ? "security_diff_scan" : "security_scan",
      "--config",
      a,
      "--config",
      b,
    ]);
    expect(result.status).toBe(0);
    expect(result.payload!.config_resolution).toBe("manual-layers");
    expect(result.payload!.config_paths).toEqual([a, b]);
    expect(result.payload!.user_config_path).toBeNull();
    expect(
      typeof expected === "boolean"
        ? goals(result.payload!).actual
        : capacity(result.payload!).actual,
    ).toBe(expected);
  },
);

test("legacy profiles merge supported features and ignore profile agents", async () => {
  const result = await configured(
    'profile="scan"\n[agents]\nmax_threads=6\n[features.multi_agent_v2]\nenabled=true\n[profiles.scan.features.multi_agent_v2]\nmax_concurrent_threads_per_session=9\n[profiles.scan.agents]\nmax_threads=100\n',
    [],
    "deep_security_scan",
  );
  expect(result.status).toBe(2);
  expect(result.payload!.error).toContain("agents.max_threads cannot be set");
  const legacy = await configured(
    'profile="scan"\n[agents]\nmax_threads=6\n[profiles.scan.agents]\nmax_threads=100\n',
    v1,
  );
  expect(capacity(legacy.payload!).actual).toBe(6);
  const partial = await configured(
    'profile="scan"\n[features.multi_agent_v2]\nenabled=true\n[profiles.scan.features.multi_agent_v2]\nmax_concurrent_threads_per_session=9\n',
  );
  expect(capacity(partial.payload!).actual).toBe(8);
  expect(capacity(partial.payload!).source).toBe(
    `${partial.file} [profiles.scan]`,
  );
});

test.each(["trusted", "untrusted"])(
  "discovers %s project config and ignores project profile selection",
  async (trust) => {
    const root = await temporaryDirectory();
    const home = join(root, "codex-home"),
      repo = join(root, "repo"),
      cwd = join(repo, "package");
    await mkdir(home);
    await mkdir(join(repo, ".git"), { recursive: true });
    await mkdir(join(repo, ".codex"));
    await mkdir(join(cwd, ".codex"), { recursive: true });
    await writeFile(
      join(home, "config.toml"),
      stringifyToml({
        projects: { [repo]: { trust_level: trust } },
        agents: { max_threads: 8 },
      }),
    );
    await writeFile(
      join(repo, ".codex/config.toml"),
      "[agents]\nmax_threads=4\n",
    );
    await writeFile(
      join(cwd, ".codex/config.toml"),
      'profile="project"\n[profiles.project.features]\ngoals=false\n[agents]\nmax_threads=9\n',
    );
    const result = await run(
      ["--profile", "security_scan", "--cwd", cwd, ...v1],
      { CODEX_HOME: home },
    );
    expect(result.status).toBe(0);
    expect(result.payload!.config_profile).toBeNull();
    expect(result.payload!.config_discovery).toEqual({
      cwd,
      project_root: repo,
      project_trust_level: trust,
      project_layers_loaded: trust === "trusted",
    });
    expect(capacity(result.payload!).actual).toBe(trust === "trusted" ? 9 : 8);
    expect(result.payload!.config_paths.slice(1)).toEqual([
      join(home, "config.toml"),
      ...(trust === "trusted"
        ? [join(repo, ".codex/config.toml"), join(cwd, ".codex/config.toml")]
        : []),
    ]);
  },
);

test.each([true, false].map((present) => [String(present), present] as const))(
  "CLI profile files override embedded selection (present=%s)",
  async (_name, present) => {
    const root = await temporaryDirectory(),
      home = join(root, "home"),
      repo = join(root, "repo");
    await mkdir(home);
    await mkdir(repo);
    await writeFile(
      join(home, "config.toml"),
      'profile="default"\n[features]\ngoals=false\n[profiles.default.features]\ngoals=false\n',
    );
    if (present)
      await writeFile(
        join(home, "work.config.toml"),
        "[features]\ngoals=true\n",
      );
    const result = await run(
      [
        "--profile",
        "security_diff_scan",
        "--codex-config-profile",
        "work",
        "--cwd",
        repo,
      ],
      { CODEX_HOME: home },
    );
    expect(result.status).toBe(0);
    expect(result.payload!.config_profile).toBe("work");
    expect(result.payload!.config_profile_path).toBe(
      present ? join(home, "work.config.toml") : null,
    );
    expect(goals(result.payload!).actual).toBe(present);
  },
);

test("trusted project settings override a CLI profile without selecting a new profile", async () => {
  const root = await temporaryDirectory(),
    home = join(root, "home"),
    repo = join(root, "repo");
  await mkdir(home);
  await mkdir(join(repo, ".git"), { recursive: true });
  await mkdir(join(repo, ".codex"));
  await writeFile(
    join(home, "config.toml"),
    stringifyToml({ projects: { [repo]: { trust_level: "trusted" } } }),
  );
  await writeFile(join(home, "work.config.toml"), "[features]\ngoals=true\n");
  await writeFile(
    join(repo, ".codex/config.toml"),
    'profile="untrusted-selection"\n[features]\ngoals=false\n',
  );
  const result = await run(
    [
      "--profile",
      "security_diff_scan",
      "--cwd",
      repo,
      "--codex-config-profile",
      "work",
    ],
    { CODEX_HOME: home },
  );
  expect(result.status).toBe(0);
  expect(result.payload!.config_profile).toBe("work");
  expect(goals(result.payload!).actual).toBe(false);
});

test.each(
  [undefined, "", "  ", "~/.codex", "literal"].map(
    (value) => [JSON.stringify(value) ?? "unset", value] as const,
  ),
)(
  "resolves home without trimming literal paths (%s)",
  async (_name, configuredHome) => {
    const root = await temporaryDirectory(),
      home = join(root, "home");
    const codexHome =
      configuredHome === "literal"
        ? join(
            root,
            process.platform === "win32" ? " selected home" : " selected home ",
          )
        : join(home, ".codex");
    await mkdir(codexHome, { recursive: true });
    await writeFile(
      join(codexHome, "config.toml"),
      "[agents]\nmax_threads=8\n",
    );
    const result = await run(
      ["--profile", "security_scan", "--cwd", root, ...v1],
      {
        HOME: home,
        USERPROFILE: home,
        CODEX_HOME: configuredHome === "literal" ? codexHome : configuredHome,
      },
    );
    expect(result.status).toBe(0);
    expect(result.payload!.user_config_path).toBe(
      join(codexHome, "config.toml"),
    );
    expect(capacity(result.payload!).actual).toBe(8);
  },
);

test("discovery canonicalizes aliases before checking project trust", async () => {
  const root = await temporaryDirectory(),
    home = join(root, "home"),
    repo = join(root, "repo"),
    alias = join(root, "alias");
  await mkdir(home);
  await mkdir(join(repo, ".git"), { recursive: true });
  await mkdir(join(repo, ".codex"));
  await symlink(repo, alias, process.platform === "win32" ? "junction" : "dir");
  await writeFile(
    join(home, "config.toml"),
    stringifyToml({
      projects: {
        [process.platform === "win32" ? repo.toUpperCase() : repo]: {
          trust_level: "trusted",
        },
      },
    }),
  );
  await writeFile(
    join(repo, ".codex/config.toml"),
    "[agents]\nmax_threads=9\n",
  );
  const result = await run(
    ["--profile", "security_scan", "--cwd", alias, ...v1],
    { CODEX_HOME: home },
  );
  expect(result.status).toBe(0);
  expect(result.payload!.config_discovery?.["project_root"]).toBe(repo);
  expect(capacity(result.payload!).actual).toBe(9);
});

test.skipIf(process.platform !== "win32")(
  "unresolved saved project aliases do not block a trusted local project",
  async () => {
    const root = await temporaryDirectory(),
      home = join(root, "home"),
      repo = join(root, "repo"),
      removed = join(root, "removed"),
      stale = join(root, "stale");
    await mkdir(home);
    await mkdir(join(repo, ".git"), { recursive: true });
    await mkdir(join(repo, ".codex"));
    await mkdir(removed);
    await symlink(removed, stale, "junction");
    await rm(removed, { recursive: true });
    await writeFile(
      join(home, "config.toml"),
      stringifyToml({
        projects: {
          [stale]: { trust_level: "trusted" },
          [repo.toUpperCase()]: { trust_level: "trusted" },
        },
      }),
    );
    await writeFile(
      join(repo, ".codex/config.toml"),
      "[agents]\nmax_threads=9\n",
    );
    const args = ["--profile", "security_scan", ...v1];
    const invalid = await run([...args, "--cwd", stale], { CODEX_HOME: home });
    expect(invalid.status).toBe(2);
    expect(invalid.payload!.status).toBe("error");
    const result = await run([...args, "--cwd", repo], { CODEX_HOME: home });
    expect(result.status).toBe(0);
    expect(result.payload!.config_discovery?.["project_trust_level"]).toBe(
      "trusted",
    );
    expect(capacity(result.payload!).actual).toBe(9);
  },
);

test("relative CODEX_HOME keeps its literal spelling and resolves from the helper cwd", async () => {
  const root = await temporaryDirectory();
  const home =
    process.platform === "win32" ? " relative home" : " relative home ";
  await mkdir(join(root, home));
  await writeFile(join(root, home, "config.toml"), "[agents]\nmax_threads=8\n");
  const result = await run(
    ["--profile", "security_scan", "--cwd", root, ...v1],
    { CODEX_HOME: home },
    root,
  );
  expect(result.status).toBe(0);
  expect(result.payload!.user_config_path).toBe(join(home, "config.toml"));
  expect(capacity(result.payload!).actual).toBe(8);
});

test.skipIf(process.platform === "win32")(
  "CODEX_HOME keeps symlink-parent resolution for base and profile files",
  async () => {
    const root = await temporaryDirectory();
    const actual = join(root, "actual");
    const alias = join(root, "alias");
    const selected = join(actual, "selected");
    const decoy = join(root, "selected");
    await mkdir(join(actual, "child"), { recursive: true });
    await mkdir(selected);
    await mkdir(decoy);
    await symlink(join(actual, "child"), alias, "dir");
    for (const [directory, count] of [
      [selected, 8],
      [decoy, 2],
    ] as const) {
      await writeFile(
        join(directory, "config.toml"),
        `[agents]\nmax_threads=${count}\n`,
      );
      await writeFile(
        join(directory, "work.config.toml"),
        `[agents]\nmax_threads=${count + 1}\n`,
      );
    }
    const home = `${alias}/../selected`;
    for (const profile of [undefined, "work"]) {
      const result = await run(
        [
          "--profile",
          "security_scan",
          "--cwd",
          root,
          ...v1,
          ...(profile ? ["--codex-config-profile", profile] : []),
        ],
        { CODEX_HOME: home },
      );
      expect(result.status).toBe(0);
      expect(capacity(result.payload!).actual).toBe(profile ? 9 : 8);
      expect(result.payload!.user_config_path).toBe(
        `${home}/${profile ? "work.config" : "config"}.toml`,
      );
    }
  },
);

test.each(
  (
    [
      ['profile="missing"\n', [], "config profile 'missing' not found"],
      ["profile=1\n", [], "profile must be a string"],
      [
        'profile="bad"\n[profiles]\nbad=1\n',
        [],
        "config profile 'bad' must be a table",
      ],
      [
        '[features]\nmulti_agent_v2="yes"\n',
        [],
        "features.multi_agent_v2 must be a boolean or table",
      ],
      [
        '[features.multi_agent_v2]\nenabled="yes"\n',
        [],
        "features.multi_agent_v2.enabled must be a boolean",
      ],
      [
        "[features.multi_agent_v2]\nenabled=true\n[agents]\nmax_threads=9\n",
        [],
        "agents.max_threads cannot be set",
      ],
      [
        "",
        ["--multi-agent-runtime-owner", "native"],
        "require --multi-agent-runtime-provenance",
      ],
      [
        "",
        ["--multi-agent-runtime-provenance", "tool-surface"],
        "requires an explicit runtime owner",
      ],
      [
        "",
        [
          "--multi-agent-runtime-owner",
          "codex-bridge",
          "--multi-agent-runtime-provenance",
          "thread-context",
        ],
        "requires --multi-agent-runtime-provenance verified-bridge",
      ],
      [
        "",
        [
          "--multi-agent-runtime-owner",
          "native",
          "--multi-agent-runtime-provenance",
          "verified-bridge",
        ],
        "native ownership cannot use",
      ],
      [
        "",
        [...v1, "--multi-agent-session-cap", "4"],
        "valid only for a V2 runtime",
      ],
      [
        "[multiagent_config]\nmax_concurrency=9\n",
        [],
        "does not prove bridge ownership",
      ],
      [
        "[multiagent_config]\nmax_concurrency=9\n",
        [...bridge, "--multi-agent-session-cap", "8"],
        "conflicting bridge concurrency facts",
      ],
      [
        "",
        ["--available-plugin-skill", "codex-security:validation"],
        "expected plugin-local skill name",
      ],
      [
        "",
        ["--effective-config", "features.goals=invalid"],
        "expected JSON value",
      ],
      [
        "",
        ["--runtime-check", "delegation_available=yes"],
        "expected true or false",
      ],
    ] as const
  ).map(([config, args, message]) => [message, config, args] as const),
)("reports configuration errors: %s", async (message, config, args) => {
  const result = await configured(config, [...args]);
  expect(result.status).toBe(2);
  expect(result.payload!.status).toBe("error");
  expect(result.payload!.error).toContain(message);
});

test.each(
  [
    [],
    ["--profile", "security_scan", "--skill", "security-scan"],
    ["--profile", "security_scan", "--multi-agent-mode", "v1"],
    ["--profile", "security_scan", "--multi-agent-session-cap", "0"],
    ["--profile", "security_scan", "--multi-agent-runtime-owner", "other"],
  ].map((args) => [args.join(" ") || "missing selector", args] as const),
)("rejects invalid arguments: %s", async (_name, args) => {
  const result = await run(args);
  expect(result.status).toBe(2);
  expect(result.stderr.length).toBeGreaterThan(0);
  expect(result.stdout).toBe("");
});

test("help and real helper execution need no Python runtime", async () => {
  const root = await temporaryDirectory();
  const env = {
    PATH: "",
    PYTHON: join(root, "missing-python"),
    CODEX_HOME: root,
  };
  const help = await run(["--help"], env);
  expect(help.status).toBe(0);
  expect(help.stdout).toContain("--effective-config");
  const result = await run(
    [
      "--profile",
      "security_scan",
      "--config",
      join(root, "missing.toml"),
      ...v1,
    ],
    env,
  );
  expect(result.status).toBe(0);
  expect(capacity(result.payload!).actual).toBe(6);
});

test("JSON output preserves Unicode paths while escaping terminal controls", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config-é-\u202e.toml");
  await writeFile(config, "");
  const result = await run(["--profile", "security_scan", "--config", config]);
  expect(result.status).toBe(0);
  expect(result.payload!.config_paths).toEqual([config]);
  expect(result.stdout).not.toMatch(/[^\x00-\x7f]/u);
  expect(result.stdout).toContain("\\u202e");
});

test.skipIf(process.platform !== "win32")(
  "documented PowerShell launcher preserves literal plugin and config paths",
  async () => {
    const root = await temporaryDirectory();
    const directory = join(root, "config %USERNAME% !EXPAND! 雪's");
    const expanded = directory.replace("%USERNAME%", "expanded-user");
    await mkdir(directory);
    await mkdir(expanded);
    const config = join(directory, "config.toml");
    await writeFile(config, "[agents]\nmax_threads=19\n");
    await writeFile(join(expanded, "config.toml"), "[agents]\nmax_threads=3\n");
    const launcher = windowsHelperFixture(root, {
      CODEX_SECURITY_CONFIG_PATH: config,
    });
    await cp(
      join(PLUGIN_ROOT, "preflight"),
      join(launcher.plugin, "preflight"),
      {
        recursive: true,
      },
    );
    for (const powershell of launcher.powershells) {
      const result = await launcher.run(
        powershell,
        "references/config-preflight.md",
        {
          "<plugin_dir>": launcher.plugin,
          "<scan-working-directory>": root,
          "<capability-profile>": "security_scan",
          "<active-config-argument>": '--config "%CODEX_SECURITY_CONFIG_PATH%"',
          "<true|false>": "true",
          "<verified-multi-agent-runtime-arguments>": v1.join(" "),
        },
      );
      expect(result.status, result.diagnostics).toBe(0);
      expect(result.stdout, result.diagnostics).not.toContain(
        "expanded-plugin-used",
      );
      const payload = JSON.parse(result.stdout) as Payload;
      expect(payload.config_paths, result.diagnostics).toEqual([config]);
      expect(capacity(payload).actual, result.diagnostics).toBe(19);
    }
  },
);

test.each([[], ["ROOT.marker"]])(
  "discovers configured project-root markers: %j",
  async (...markers) => {
    const root = await temporaryDirectory(),
      home = join(root, "home"),
      repo = join(root, "repo"),
      cwd = join(repo, "child");
    await mkdir(home);
    await mkdir(cwd, { recursive: true });
    await writeFile(join(repo, "ROOT.marker"), "");
    await writeFile(
      join(home, "config.toml"),
      stringifyToml({ project_root_markers: markers }),
    );
    const result = await run(["--profile", "security_scan", "--cwd", cwd], {
      CODEX_HOME: home,
    });
    expect(result.status).toBe(0);
    expect(result.payload!.config_discovery?.["project_root"]).toBe(
      markers.length ? repo : cwd,
    );
  },
);

test("absolute project-root markers retain trusted cwd configuration", async () => {
  const root = await temporaryDirectory(),
    home = join(root, "home"),
    cwd = join(root, "repo", "child"),
    marker = join(root, "ROOT.marker");
  await mkdir(home);
  await mkdir(join(cwd, ".codex"), { recursive: true });
  await writeFile(marker, "");
  await writeFile(
    join(home, "config.toml"),
    stringifyToml({
      project_root_markers: [marker],
      agents: { max_threads: 3 },
      projects: { [cwd]: { trust_level: "trusted" } },
    }),
  );
  await writeFile(
    join(cwd, ".codex/config.toml"),
    "[agents]\nmax_threads=19\n",
  );
  const result = await run(
    ["--profile", "security_scan", "--cwd", cwd, ...v1],
    { CODEX_HOME: home },
  );
  expect(result.status).toBe(0);
  expect(result.payload!.config_discovery?.["project_root"]).toBe(cwd);
  expect(capacity(result.payload!).actual).toBe(19);
});

test("malformed TOML reports a structured error without changing the file", async () => {
  const result = await configured("[features\ngoals=true\n");
  expect(result.status).toBe(2);
  expect(result.payload!.status).toBe("error");
  expect(result.payload!.error).toBeTruthy();
  expect(await readFile(result.file, "utf8")).toBe("[features\ngoals=true\n");
});

test("TOML dates are not feature or profile tables", async () => {
  for (const [config, error] of [
    [
      "[features]\nmulti_agent_v2=2026-10-08\n",
      "features.multi_agent_v2 must be a boolean or table",
    ],
    [
      'profile="scan"\n[profiles]\nscan=2026-10-08\n',
      "config profile 'scan' must be a table",
    ],
  ] as const) {
    const result = await configured(config);
    expect(result.status).toBe(2);
    expect(result.payload!.error).toBe(error);
  }
});

test.skipIf(process.platform === "win32")(
  "preserves raw CODEX_HOME and the default working directory",
  async () => {
    const root = await temporaryDirectory();
    const prefix = join(root, "raw-");
    const raw = Buffer.concat([Buffer.from(prefix), Buffer.from([255])]);
    const ordinary = join(root, "ordinary");
    const decoy = `${prefix}\ufffd`;
    for (const directory of [raw, ordinary, decoy]) {
      const bytes =
        typeof directory === "string" ? Buffer.from(directory) : directory;
      await mkdir(directory);
      await mkdir(Buffer.concat([bytes, Buffer.from("/.codex")]));
      const config = `[agents]\nmax_threads=${directory === decoy ? 2 : 8}\n`;
      await writeFile(
        Buffer.concat([bytes, Buffer.from("/config.toml")]),
        config,
      );
      await writeFile(
        Buffer.concat([bytes, Buffer.from("/.codex/config.toml")]),
        config,
      );
    }
    for (const mode of ["home", "cwd", "home-default"]) {
      const result = await runCommand(
        "/bin/sh",
        [
          "-c",
          String.raw`
raw="$1$(printf '\377')"
if [ "$3" = home ]; then
  CODEX_HOME="$raw"; export CODEX_HOME; cd "$2"; set -- "$4" --helper
elif [ "$3" = cwd ]; then
  CODEX_HOME="$2"; export CODEX_HOME; cd "$raw"; set -- "$4" --helper
else
  unset CODEX_HOME; HOME="$raw"; export HOME; cd "$2"; set -- "$5" "$6"
fi
exec "$@" config-preflight --profile security_scan --multi-agent-runtime-owner native --multi-agent-runtime-version v1 --multi-agent-runtime-provenance app-server
`,
          "preflight-raw-path",
          prefix,
          ordinary,
          mode,
          join(PLUGIN_ROOT, "scripts/launch_codex_security_mcp"),
          node,
          helper,
        ],
        { env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
      );
      expect(result.status, result.stderr).toBe(0);
      const payload = JSON.parse(result.stdout) as Payload;
      expect(capacity(payload).actual).toBe(8);
      expect(
        mode === "cwd"
          ? payload.config_discovery?.["cwd"]
          : payload.user_config_path,
      ).toBe(
        `${prefix}\udcff${mode === "cwd" ? "" : mode === "home" ? "/config.toml" : "/.codex/config.toml"}`,
      );
    }
  },
);

test("custom registries preserve blocking, incomplete, and ready exit statuses", async () => {
  const root = await temporaryDirectory(),
    registry = join(root, "registry.toml"),
    config = join(root, "config.toml");
  await writeFile(config, "");
  await writeFile(
    registry,
    stringifyToml({
      version: 1,
      capabilities: { check: { kind: "runtime", check: "synthetic" } },
      profiles: {
        custom: {
          description: "Synthetic profile",
          requirements: [
            {
              capability: "check",
              severity: "block",
              reason: "Synthetic requirement",
            },
          ],
        },
      },
      routes: [{ skill: "synthetic", profile: "custom" }],
    }),
  );
  for (const [checks, status, code] of [
    [[], "incomplete", 2],
    [["--runtime-check", "synthetic=false"], "blocked", 1],
    [["--runtime-check", "synthetic=true"], "ready", 0],
  ] as const) {
    const result = await run([
      "--skill",
      "synthetic",
      "--registry",
      registry,
      "--config",
      config,
      ...checks,
    ]);
    expect(result.status).toBe(code);
    expect(result.payload!.status).toBe(status);
  }
});

test("effective JSON tables and arrays compare by value with TOML requirements", async () => {
  const root = await temporaryDirectory(),
    registry = join(root, "registry.toml"),
    config = join(root, "config.toml");
  await writeFile(config, "");
  const table = { enabled: true, nested: { capacity: 9007199254740993n } };
  for (const [expected, matching, different] of [
    [
      table,
      '{"enabled":true,"nested":{"capacity":9007199254740993}}',
      '{"enabled":true,"nested":{"capacity":9007199254740992}}',
    ],
    [
      [table],
      '[{"enabled":true,"nested":{"capacity":9007199254740993}}]',
      '[{"enabled":false,"nested":{"capacity":9007199254740993}}]',
    ],
  ] as const) {
    await writeFile(
      registry,
      stringifyToml({
        version: 1,
        capabilities: {
          check: {
            kind: "config",
            path: "synthetic",
            op: "==",
            value: expected,
          },
        },
        profiles: {
          custom: {
            description: "Synthetic structured configuration",
            requirements: [
              {
                capability: "check",
                severity: "block",
                reason: "Synthetic requirement",
              },
            ],
          },
        },
      }),
    );
    for (const [value, code] of [
      [matching, 0],
      [different, 1],
    ] as const) {
      const result = await run([
        "--profile",
        "custom",
        "--registry",
        registry,
        "--config",
        config,
        "--effective-config",
        `synthetic=${value}`,
      ]);
      expect(result.status).toBe(code);
      expect(result.payload!.results[0]!.status).toBe(code ? "fail" : "pass");
    }
  }
});
