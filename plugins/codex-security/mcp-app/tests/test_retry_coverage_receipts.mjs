import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const stopAfterDraft of [false, true]) {
    test(`archived receipt survives ${resume ? "reconstruction" : "live retry"} and ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          stopAfterDraft,
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const completeness of ["complete", "partial"]) {
  for (const stopAfterDraft of [false, true]) {
    test(`streamed discovery retry retains origin through ${completeness} ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-origin-stream-"));
      try {
        await publishCoverageFixture(root, completeness, {
          streamRetry: true,
          stopAfterDraft,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const failClosedResult of [false, true]) {
  test(`generic closing checkpoint replaces retained host surface after failed result=${failClosedResult}`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-generic-closure-"));
    try {
      await publishCoverageFixture(root, "complete", {
        closeGeneric: true,
        failClosedResult,
        stopAfterDraft: true,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
