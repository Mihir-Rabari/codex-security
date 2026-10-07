import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runWorkflowScript } from "./support/workflow-script.js";

type Step = { name: string; run?: string };
const workflow = Bun.YAML.parse(
  readFileSync(
    new URL(
      "../../../.github/workflows/node-github-release.yml",
      import.meta.url,
    ),
    "utf8",
  ),
) as { jobs: Record<string, { steps: Step[] }> };

function script(job: string, name: string) {
  const step = workflow.jobs[job]?.steps.find((step) => step.name === name);
  if (!step?.run) throw new Error(`Missing workflow script: ${job}/${name}`);
  return step.run;
}

const reuse = script(
  "action",
  "Reuse an existing immutable Action distribution",
);
const detect = script("release", "Detect Action release source");
const complete = script("complete", "Require completed release channels");
const publish = script("action", "Publish immutable Action tag and metadata");
const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(includeAction = true) {
  const directory = mkdtempSync(join(tmpdir(), "action release workflow "));
  directories.push(directory);
  const repository = join(directory, "release source");
  const output = join(directory, "outputs");
  mkdirSync(repository);
  function git(...args: string[]) {
    return execFileSync(
      "git",
      [
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release@example.invalid",
        "-c",
        "commit.gpgsign=false",
        ...args,
      ],
      { cwd: repository, encoding: "utf8", stdio: "pipe" },
    ).trim();
  }
  function write(path: string, value: string) {
    const destination = join(repository, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, value);
  }
  function commit(message: string) {
    git("add", "--all");
    git("commit", "-m", message);
    return git("rev-parse", "HEAD");
  }
  function run(script: string, environment: Record<string, string> = {}) {
    writeFileSync(output, "");
    const result = runWorkflowScript(
      repository,
      script,
      {
        GITHUB_OUTPUT: output.replaceAll("\\", "/"),
        RELEASE_VERSION: "99.1.2",
        RELEASE_SHA: source,
        ...environment,
      },
      ["-e", "-o", "pipefail"],
    );
    return { ...result, output: readFileSync(output, "utf8") };
  }
  git("init");
  write("README.md", "Synthetic CLI source\n");
  if (includeAction) write("action.yml", "name: Synthetic Action\n");
  const source = commit("Create release source");
  function distribution(extraSourcePath?: string) {
    for (const path of [
      "github-action/package.json",
      "github-action/package-lock.json",
      "github-action/runtime/package.json",
      "github-action/runtime/package-lock.json",
      "github-action/dist/index.cjs",
      "github-action/dist/post.cjs",
    ]) {
      write(path, "Synthetic generated release content\n");
    }
    if (extraSourcePath) write(extraSourcePath, "Unrelated source change\n");
    const sha = commit("Package Action release");
    git("tag", "action-v99.1.2", sha);
    git("checkout", "--detach", source);
    return sha;
  }
  return { directory, git, write, commit, run, source, distribution };
}

test("reuses a generated Action commit derived from the exact CLI release", () => {
  const release = fixture();
  const distribution = release.distribution();
  const result = release.run(reuse);
  expect(result.status).toBe(0);
  expect(result.output).toBe("existing=true\n");
  expect(release.git("rev-parse", "HEAD")).toBe(distribution);
});

test("leaves the CLI source ready for first Action publication", () => {
  const release = fixture();
  const result = release.run(reuse);
  expect(result.status).toBe(0);
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("rejects an Action distribution derived from a different source commit", () => {
  const release = fixture();
  release.write("README.md", "Another CLI source commit\n");
  release.commit("Advance source");
  release.distribution();
  const result = release.run(reuse);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("exact CLI source");
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("rejects unrelated source edits in an existing Action distribution", () => {
  const release = fixture();
  release.distribution("github-action/src/index.ts");
  const result = release.run(reuse);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("outside release packaging");
  expect(result.output).toBe("");
  expect(release.git("rev-parse", "HEAD")).toBe(release.source);
});

test("detects Action support from the release commit during historical recovery", () => {
  const release = fixture(false);
  release.write("action.yml", "name: Synthetic Action\n");
  const newerSource = release.commit("Add Action after earlier CLI release");
  const historical = release.run(detect);
  expect(historical.status).toBe(0);
  expect(historical.output).toBe("");
  const current = release.run(detect, { RELEASE_SHA: newerSource });
  expect(current.status).toBe(0);
  expect(current.output).toBe("present=true\n");
});

function publicationFixture(existingManifest: string) {
  const release = fixture();
  const runner = join(release.directory, "runner");
  const remote = join(release.directory, "published assets");
  const uploads = join(release.directory, "uploads");
  mkdirSync(runner);
  mkdirSync(remote);
  writeFileSync(uploads, "");
  release.write(
    "github-action/build/release-manifest.json",
    "verified manifest\n",
  );
  release.write("github-action/build/sbom.cdx.json", "verified SBOM\n");
  writeFileSync(join(remote, "action-release-manifest.json"), existingManifest);
  const fakeGitHub = `gh() {
  case "$1 $2" in
    'release view')
      for asset in "$REMOTE_ASSETS/"*; do basename "$asset"; done
      ;;
    'release download')
      local asset destination
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --pattern) asset="$2"; shift ;;
          --dir) destination="$2"; shift ;;
        esac
        shift
      done
      cp "$REMOTE_ASSETS/$asset" "$destination/$asset"
      ;;
    'release upload')
      local asset="$(basename "\${!#}")"
      cp "\${!#}" "$REMOTE_ASSETS/$asset"
      printf '%s\\n' "$asset" >> "$UPLOADS"
      ;;
    *) return 1 ;;
  esac
}
`;
  return {
    remote,
    uploads,
    run() {
      return release.run(`${fakeGitHub}${publish}`, {
        EXISTING: "true",
        RUNNER_TEMP: runner.replaceAll("\\", "/"),
        REMOTE_ASSETS: remote.replaceAll("\\", "/"),
        UPLOADS: uploads.replaceAll("\\", "/"),
        GITHUB_REPOSITORY: "example/security-tool",
        GITHUB_STEP_SUMMARY: join(release.directory, "summary.md").replaceAll(
          "\\",
          "/",
        ),
      });
    },
  };
}

test("completes partial Action metadata publication and reuses matching assets", () => {
  const publication = publicationFixture("verified manifest\n");
  expect(publication.run().status).toBe(0);
  expect(readFileSync(publication.uploads, "utf8")).toBe(
    "action-sbom.cdx.json\n",
  );
  expect(
    readFileSync(join(publication.remote, "action-sbom.cdx.json"), "utf8"),
  ).toBe("verified SBOM\n");
  expect(publication.run().status).toBe(0);
  expect(readFileSync(publication.uploads, "utf8")).toBe(
    "action-sbom.cdx.json\n",
  );
});

test("rejects mismatched published Action metadata without replacing it", () => {
  const publication = publicationFixture("different published manifest\n");
  const result = publication.run();
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("Published Action metadata differs");
  expect(readFileSync(publication.uploads, "utf8")).toBe("");
  expect(
    readFileSync(
      join(publication.remote, "action-release-manifest.json"),
      "utf8",
    ),
  ).toBe("different published manifest\n");
});

test.each([
  ["success", "success", "success", "true", true],
  ["success", "success", "skipped", "", true],
  ["failure", "skipped", "skipped", "", false],
  ["success", "failure", "skipped", "true", false],
  ["success", "success", "failure", "true", false],
  ["success", "success", "skipped", "true", false],
  ["success", "cancelled", "skipped", "", false],
] as const)(
  "requires completed release channels: release=%s install=%s action=%s present=%s",
  (releaseResult, installResult, actionResult, hasAction, succeeds) => {
    const release = fixture();
    const result = release.run(complete, {
      RELEASE_RESULT: releaseResult,
      INSTALL_RESULT: installResult,
      ACTION_RESULT: actionResult,
      HAS_ACTION: hasAction,
    });
    expect(result.status === 0).toBe(succeeds);
  },
);
