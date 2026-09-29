/** Workbench operations that can finish a scan retain the scan startup timeout. */
export function workbenchTimeout(command: string): number {
  return [
    "begin-deep-scan",
    "complete-scan",
    "export-findings",
    "get-scan",
    "get-workspace",
    "inspect-setup",
    "list-findings",
    "preserve-scan-results",
    "recover-scan-results",
    "request-finding-remediation",
    "request-finding-remediation-action",
    "save-workspace",
    "set-finding-triage",
    "set-finding-remediation",
    "start-headless-standard-scan",
    "start-prompt-only-scan",
    "start-scan",
  ].includes(command)
    ? 300_000
    : 30_000;
}
