"use strict";

// Resolve the throwaway runtime when the provider runs, not when Promptfoo
// persists its configuration for --resume or --retry-errors.
module.exports = class TriageProvider {
  constructor(options) {
    this.options = options;
    this.config = options.config;
  }

  id() {
    return `file://${__filename}`;
  }

  async callApi(...args) {
    this.provider ??= import("promptfoo").then(({ loadApiProvider }) => {
      if (!process.env.TRIAGE_RUNTIME_ROOT) {
        throw new Error(
          "Run this evaluation through scripts/run-promptfoo.js.",
        );
      }
      return loadApiProvider("openai:codex-sdk:gpt-5.5", {
        basePath: this.config.basePath,
        options: {
          ...this.options,
          config: {
            ...this.config,
            working_dir: process.env.TRIAGE_RUNTIME_ROOT,
          },
        },
      });
    });
    return (await this.provider).callApi(...args);
  }

  async cleanup() {
    if (this.provider) await (await this.provider).cleanup?.();
  }
};
