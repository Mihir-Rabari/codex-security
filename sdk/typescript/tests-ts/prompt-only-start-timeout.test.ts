import { expect, test } from "bun:test";
import { workbenchTimeout } from "../../../plugins/codex-security/mcp-app/src/workbench-timeout.js";

test("gives prompt-only and ordinary scan startup the five-minute scan timeout", () => {
  expect(workbenchTimeout("start-prompt-only-scan")).toBe(300_000);
  expect(workbenchTimeout("start-scan")).toBe(300_000);
  expect(workbenchTimeout("other-operation")).toBe(30_000);
});
