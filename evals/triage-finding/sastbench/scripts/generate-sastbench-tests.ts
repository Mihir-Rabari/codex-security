#!/usr/bin/env node

import type { SastBenchRecord, SampleSpec } from "../../types.js";

const {
  DEFAULT_DATASET_PATH,
  DEFAULT_TARGET_ROOT,
  generatePromptfooTests,
  generateRepresentativeSampleTests,
  loadDataset,
} = require("./sastbench-lib") as typeof import("./sastbench-lib.js");

interface GenerateOptions {
  dataset?: SastBenchRecord[];
  datasetPath?: string;
  targetRoot?: string;
  sampleSpec?: SampleSpec;
}

function loadRecords(options: GenerateOptions) {
  return Array.isArray(options.dataset)
    ? options.dataset
    : loadDataset(options.datasetPath || DEFAULT_DATASET_PATH);
}

function generateTests(options: GenerateOptions = {}) {
  const records = loadRecords(options);
  return generatePromptfooTests(
    records,
    options.targetRoot || DEFAULT_TARGET_ROOT,
  );
}

function generateSampleTests(options: GenerateOptions = {}) {
  const records = loadRecords(options);
  return generateRepresentativeSampleTests(
    records,
    options.targetRoot || DEFAULT_TARGET_ROOT,
    options.sampleSpec,
  );
}

export = { generateSampleTests, generateTests };
