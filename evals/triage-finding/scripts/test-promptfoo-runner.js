const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { stageSkillRuntime } = require("./run-promptfoo");

test("runtime contains checkout skill and fixtures without calibration labels", () => {
  const root = stageSkillRuntime();
  try {
    const skill = "plugins/codex-security/skills/triage-finding/SKILL.md";
    assert.equal(
      fs.readFileSync(path.join(root, skill), "utf8"),
      fs.readFileSync(path.resolve(__dirname, "../../..", skill), "utf8"),
    );
    assert.ok(
      fs.existsSync(
        path.join(root, "evals/triage-finding/fixtures/repo/src/server.js"),
      ),
    );
    for (const name of ["datasets", "tests", "artifacts"])
      assert.equal(
        fs.existsSync(path.join(root, "evals/triage-finding", name)),
        false,
      );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const [signal, exitCode] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  for (const delivery of ["pid", "group"]) {
    test(
      `runner forwards ${signal} once (${delivery}) and removes its runtime after the child exits`,
      { skip: process.platform === "win32", timeout: 15000 },
      async (t) => {
        const target = `
        let received = 0;
        process.on(${JSON.stringify(signal)}, () => {
          received++;
          if (received > 1) process.exit(99);
          setTimeout(() => { console.log("graceful:" + received); process.exit(0); }, 150);
        });
        console.log(JSON.stringify({ root: process.env.TRIAGE_RUNTIME_ROOT }));
        setInterval(() => {}, 1000);
      `;
        const driver = `
      const cp = require('node:child_process');
      const spawn = cp.spawn;
      cp.spawn = (command, args, options) => spawn(process.execPath, ['--eval', command === process.execPath ? "" : ${JSON.stringify(target)}], options);
      require(${JSON.stringify(require.resolve("./run-promptfoo"))}).runPromptfoo([]).then(code => { process.exitCode = code; });
    `;
        const child = spawn(process.execPath, ["--eval", driver], {
          stdio: ["ignore", "pipe", "pipe"],
          detached: true,
        });
        t.after(() => {
          if (child.exitCode === null) child.kill("SIGKILL");
        });
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        const exited = new Promise((resolve, reject) => {
          child.once("error", reject);
          child.once("exit", (code, signal) => resolve({ code, signal }));
        });
        let text = "";
        const ready = new Promise((resolve) => {
          child.stdout.on("data", (chunk) => {
            text += chunk;
            if (text.includes("\n")) resolve(JSON.parse(text.split("\n")[0]));
          });
        });
        const { root } = await Promise.race([
          ready,
          exited.then(() => {
            throw new Error(`runner exited early: ${stderr}`);
          }),
        ]);
        t.after(() => fs.rmSync(root, { recursive: true, force: true }));
        assert.ok(fs.existsSync(root));
        if (delivery === "group") process.kill(-child.pid, signal);
        else child.kill(signal);
        assert.deepEqual(
          await exited,
          { code: exitCode, signal: null },
          stderr,
        );
        assert.match(text, /graceful:1/);
        assert.equal(fs.existsSync(root), false);
      },
    );
  }
}
