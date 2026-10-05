import type { ApiProvider, ProviderOptions } from "promptfoo";

// Resolve the throwaway runtime when the provider runs, not when Promptfoo
// persists its configuration for --resume or --retry-errors.
export default class TriageProvider implements ApiProvider {
  declare private readonly options: ProviderOptions;
  declare config: ProviderOptions["config"];
  declare private provider: Promise<ApiProvider> | undefined;
  constructor(options: ProviderOptions) {
    this.options = options;
    this.config = options.config;
  }

  id() {
    return `file://${import.meta.filename}`;
  }

  async callApi(...args: Parameters<ApiProvider["callApi"]>) {
    this.provider ??= import("promptfoo").then(({ loadApiProvider }) => {
      if (!process.env.TRIAGE_RUNTIME_ROOT) {
        throw new Error(
          "Run this evaluation through scripts/run-promptfoo.mts.",
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
}
