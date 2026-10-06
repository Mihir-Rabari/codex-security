import { afterEach, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ScanCostTracker } from "../src/cost.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "scan-receipt-window-",
);
afterEach(cleanup);
function tokens(input: number) {
  return { input_tokens: input, output_tokens: 0, total_tokens: input };
}
test.each([
  "reset-gap",
  "no-reset",
  "legacy-baseline",
  "receipt-baseline",
] as const)(
  "preserves SDK and Python receipt completeness across windows: %s",
  async (scenario) => {
    const home = await temporaryDirectory();
    await mkdir(join(home, "sessions"));
    const path = join(home, "sessions", "owner.jsonl");
    const before = "2026-09-01T00:00:00Z",
      at = "2026-09-01T00:00:02Z",
      start = "2026-09-01T00:00:01Z";
    const receipt = (
      usage: number,
      cumulative: number,
      id: string,
      timestamp = at,
    ) => ({
      type: "token_usage_record",
      timestamp,
      payload: {
        thread_id: "owner",
        turn_id: "owned-turn",
        response_id: id,
        model: "gpt-5.6-sol",
        usage: tokens(usage),
        thread_token_usage: tokens(cumulative),
      },
    });
    const baseline = scenario.endsWith("baseline");
    const records = [
      {
        type: "session_meta",
        timestamp: before,
        payload: { id: "owner", model: "gpt-5.6-sol", timestamp: before },
      },
      ...(scenario === "legacy-baseline"
        ? [
            {
              type: "event_msg",
              timestamp: before,
              payload: {
                type: "token_count",
                info: { total_token_usage: tokens(900) },
              },
            },
          ]
        : []),
      ...(scenario === "receipt-baseline"
        ? [receipt(900, 900, "before", before)]
        : []),
      {
        type: "turn_context",
        timestamp: at,
        payload: { turn_id: "owned-turn", model: "gpt-5.6-sol" },
      },
      ...(baseline
        ? [receipt(20, 920, "new")]
        : [
            receipt(100, 100, "first"),
            receipt(20, scenario === "reset-gap" ? 40 : 120, "second"),
          ]),
    ];
    await writeFile(
      path,
      records.map((x) => JSON.stringify(x) + "\n").join(""),
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.003,
    });
    tracker.setAttributionReader(async () => ({
      formatVersion: 1,
      executionThreadIds: [],
      owner: { threadId: "owner", turnId: "owned-turn", startedAt: start },
      startedAt: start,
      completedAt: null,
    }));
    tracker.start("owner");
    const code = [
      "import json,sys",
      "from pathlib import Path",
      "from datetime import datetime,timezone",
      "sys.path.insert(0,sys.argv[1])",
      "import workbench_scan_usage as w",
      "models={}",
      "usage,warnings=w._read_rollout_usage(w.RolloutSession('owner',None,Path(sys.argv[2])),started_at=datetime(2026,9,1,0,0,1,tzinfo=timezone.utc),completed_at=None,owner_turn_id='owned-turn',model_usage=models)",
      "print(json.dumps({'usage':usage,'warnings':sorted(warnings),'models':[{'model':m,**v} for m,v in models.items()]}))",
    ].join("\n");
    const executable = Bun.which("python3") ?? Bun.which("python");
    expect(executable).not.toBeNull();
    const python = spawnSync(
      executable!,
      [
        "-I",
        "-B",
        "-c",
        code,
        join(import.meta.dir, "../../../plugins/codex-security/scripts"),
        path,
      ],
      { encoding: "utf8" },
    );
    expect(python.status, python.stderr).toBe(0);
    const py = JSON.parse(python.stdout);
    try {
      const sdk = await tracker.stop();
      expect((sdk.usage as { input_tokens: number }).input_tokens).toBe(
        baseline ? 20 : 120,
      );
      expect(py.usage.inputTokens).toBe(baseline ? 20 : 120);
      if (scenario === "reset-gap") {
        expect(sdk.usage).toHaveProperty("coverage", "partial");
        expect(py.warnings).toContain("token_receipts_incomplete");
      } else {
        expect(sdk.usage).not.toHaveProperty("coverage", "partial");
        expect(py.warnings).not.toContain("token_receipts_incomplete");
      }
    } finally {
      await tracker.stop();
    }
  },
);
