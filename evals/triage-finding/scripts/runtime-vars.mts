import path from "node:path";

const evalRoot = path.resolve(import.meta.dirname, "..");

// Resolve target paths for each execution, including persisted retries.
// The provider binds runtime and executable settings after case overrides.
export default (vars: Record<string, unknown>) => ({
  ...vars,
  target_repo: vars.calibration_repo
    ? path.join(
        (vars.calibration_repo_root ||
          path.join(evalRoot, "artifacts", "calibration-repos")) as string,
        vars.calibration_repo as string,
      )
    : vars.target_repo,
});
