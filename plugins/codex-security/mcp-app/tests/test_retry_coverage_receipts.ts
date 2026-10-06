import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.ts";

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const retryPending of [false, true]) {
      test(`archived receipt and pending records survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${retryPending ? "an updated gap" : "a clean retry"}`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            retryPending,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of ["scan", "equivalent scan"] as const) {
      test(`receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "receipt-namespace-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const activeReceiptSpelling of [
      "worker",
      "scan",
      "equivalent scan",
    ] as const) {
      test(`active receipt namespace survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${activeReceiptSpelling} spelling`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "active-receipt-namespace-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            activeReceiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "active scan",
      "equivalent active scan",
    ] as const) {
      test(`linked archived receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(path.join(tmpdir(), "receipt-namespace-"));
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    test(`shared scan receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "shared-scan-receipts-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          sharedReceipt: true,
          stopAfterDraft: outcome === "recovery",
          stopBeforeDraft: outcome === "no parent",
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`archived shared receipts survive ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${receiptSpelling} spelling`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "archived-shared-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}

for (const resume of [false, true]) {
  for (const outcome of ["completion", "recovery", "no parent"]) {
    for (const sharedReceipt of [false, true]) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with ${sharedReceipt ? "shared" : "worker"} current evidence`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "empty-current-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            sharedReceipt,
            emptyReceipt: true,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
    for (const receiptSpelling of [
      "shared scan",
      "equivalent shared scan",
    ] as const) {
      test(`empty receipt survives ${resume ? "reconstruction" : "live retry"} and ${outcome} with archived ${receiptSpelling} evidence`, async () => {
        const root = await mkdtemp(
          path.join(tmpdir(), "empty-archived-receipts-"),
        );
        try {
          await publishCoverageFixture(root, "complete", {
            receiptRetry: true,
            receiptSpelling,
            emptyReceipt: true,
            stopAfterDraft: outcome === "recovery",
            stopBeforeDraft: outcome === "no parent",
            resume,
          });
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  }
}
