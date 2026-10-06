import {
  App,
  applyDocumentTheme,
  applyHostStyleVariables,
} from "@modelcontextprotocol/ext-apps";
import * as z from "zod/v4";
import { version } from "../../package.json";
import {
  conversationMessage,
  findingMessage,
  findingsPageSchema,
  scanSchema,
  scansPageSchema,
  type Finding,
  type Scan,
} from "./model.js";

const app = new App({ name: "Codex Security Local", version }, {});
const root = document.querySelector<HTMLElement>("main")!;
const notice = document.querySelector<HTMLElement>("#notice")!;
const search = document.querySelector<HTMLInputElement>("#search")!;
const actions = document.querySelector<HTMLElement>("#actions")!;
let view: "scans" | "findings" = "scans";
let offset = 0;
let selected: { scanId: string; occurrenceId?: string } | null = null;
let generation = 0;

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  text?: string,
  className?: string,
) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function button(label: string, action: () => void | Promise<void>) {
  const node = element("button", label);
  node.type = "button";
  node.onclick = async () => {
    node.disabled = true;
    notice.textContent = "";
    try {
      await action();
    } catch (error) {
      notice.textContent =
        error instanceof Error ? error.message : String(error);
    } finally {
      node.disabled = false;
    }
  };
  return node;
}

async function read<T>(
  name: string,
  args: Record<string, unknown>,
  schema: z.ZodType<T>,
): Promise<T> {
  const result = await app.callServerTool({ name, arguments: args });
  if (result.isError) {
    throw new Error(
      result.content
        ?.filter((item) => item.type === "text")
        .map((item) => item.text)
        .join("\n") || "Could not load local results.",
    );
  }
  return schema.parse(result.structuredContent);
}

function field(label: string, value: unknown) {
  const section = element("section");
  section.append(
    element("h3", label),
    element(
      "pre",
      typeof value === "string" ? value : JSON.stringify(value, null, 2),
    ),
  );
  return section;
}

function table(headings: string[], rows: (string | HTMLElement)[][]) {
  const result = element("table");
  const head = element("thead");
  const labels = element("tr");
  for (const heading of headings) {
    const cell = element("th", heading);
    cell.scope = "col";
    labels.append(cell);
  }
  head.append(labels);
  const body = element("tbody");
  for (const values of rows) {
    const row = element("tr");
    for (const value of values) {
      const cell = element("td");
      cell.append(value);
      row.append(cell);
    }
    body.append(row);
  }
  result.append(head, body);
  return result;
}

function pagination(nextOffset: number | null | undefined) {
  const navigation = element("nav", undefined, "pagination");
  navigation.ariaLabel = "Results pages";
  const previous = button("Previous", () => {
    offset = Math.max(0, offset - 20);
    return refresh();
  });
  previous.disabled = offset === 0;
  const next = button("Next", () => {
    offset = nextOffset!;
    return refresh();
  });
  next.disabled = nextOffset == null;
  navigation.append(
    previous,
    element("span", `Page ${Math.floor(offset / 20) + 1}`),
    next,
  );
  return navigation;
}

function showFinding(scan: Scan, finding: Finding) {
  const detail = element("article");
  detail.append(
    element("h2", finding.title),
    element(
      "p",
      `${finding.severity.level} · ${finding.triage?.status ?? finding.status ?? "untriaged"}`,
    ),
  );
  const buttons = element("div", undefined, "actions");
  for (const action of ["Investigate", "Fix", "Verify"] as const) {
    const actionButton = button(action, async () => {
      await app.sendMessage(findingMessage(action, scan, finding));
      notice.textContent = "Conversation request sent to Codex.";
    });
    actionButton.disabled =
      action !== "Investigate" &&
      (scan.remediationAvailable !== true ||
        finding.remediationState?.state === "requested" ||
        finding.remediationState?.state === "verifying" ||
        finding.remediationState?.pendingAction != null);
    buttons.append(actionButton);
  }
  detail.append(
    buttons,
    field("Summary", finding.summary ?? "No summary recorded"),
  );
  if (scan.remediationUnavailableReason)
    detail.append(element("p", scan.remediationUnavailableReason));
  for (const [key, label] of [
    ["locations", "Locations"],
    ["writeup", "Writeup"],
    ["codeEvidence", "Code evidence"],
    ["attackPath", "Attack path"],
    ["validation", "Validation"],
    ["remediation", "Remediation"],
    ["remediationState", "Remediation status"],
  ]) {
    if (finding[key] != null) detail.append(field(label, finding[key]));
  }
  detail.append(
    field("Local identities", {
      scanId: scan.scanId,
      findingId: finding.findingId,
      occurrenceId: finding.occurrenceId,
    }),
  );
  return detail;
}

async function refresh() {
  const current = ++generation;
  root.setAttribute("aria-busy", "true");
  root.replaceChildren(element("p", "Loading local results…"));
  actions.replaceChildren();
  notice.textContent = "";
  for (const tab of document.querySelectorAll<HTMLButtonElement>(
    "[data-view]",
  )) {
    tab.setAttribute("aria-pressed", String(tab.dataset.view === view));
  }
  try {
    if (selected) {
      const { scan } = await read(
        "get_codex_security_scan",
        selected,
        z.object({ scan: scanSchema }),
      );
      if (current !== generation) return;
      const selection = selected;
      actions.append(
        button("Back", () => {
          selected = selection.occurrenceId
            ? { scanId: selection.scanId }
            : null;
          return refresh();
        }),
      );
      const heading = element("div", undefined, "page-heading");
      heading.append(
        element("h1", "Scan details"),
        element("p", scan.targetPath),
      );
      const content = element("div");
      content.append(
        heading,
        element(
          "p",
          `${scan.progress.status} · ${scan.progress.phase} · ${scan.mode}`,
        ),
      );
      if (scan.continuationThreadId) {
        const threadId = scan.continuationThreadId;
        content.append(
          button("Open scan conversation", () =>
            app
              .openLink({
                url: `codex://threads/${encodeURIComponent(threadId)}`,
              })
              .then(() => {}),
          ),
        );
      }
      if (scan.failureMessage)
        content.append(field("Scan failure", scan.failureMessage));
      content.append(field("Progress", scan.progress));
      if (selection.occurrenceId) {
        const finding = scan.findings.find(
          (item) => item.occurrenceId === selection.occurrenceId,
        );
        if (!finding)
          throw new Error(
            "This finding occurrence is no longer available in this scan.",
          );
        content.append(showFinding(scan, finding));
      } else {
        content.append(element("h2", `${scan.findingCount} findings`));
        content.append(
          table(
            ["Finding", "Severity", "Status"],
            scan.findings.map((finding) => [
              button(finding.title, () => {
                selected = {
                  scanId: scan.scanId,
                  occurrenceId: finding.occurrenceId,
                };
                return refresh();
              }),
              finding.severity.level,
              finding.triage?.status ?? finding.status ?? "untriaged",
            ]),
          ),
        );
        if (scan.findingsTruncated) {
          content.append(
            button("Browse all findings in this scan", () =>
              loadScanFindings(scan.scanId, 0),
            ),
          );
        }
      }
      root.replaceChildren(content);
      return;
    }
    const args = {
      limit: 20,
      offset,
      ...(search.value.trim() ? { query: search.value.trim() } : {}),
    };
    if (view === "scans") {
      const page = await read(
        "list_codex_security_scans",
        args,
        scansPageSchema,
      );
      if (current !== generation) return;
      root.replaceChildren(element("h1", "Scans"));
      if (!page.scans.length)
        root.append(
          element(
            "p",
            "No local scans match. Start a scan in Codex to create one.",
          ),
        );
      else
        root.append(
          table(
            ["Repository", "Status", "Mode", "Findings"],
            page.scans.map((scan) => [
              button(scan.targetPath, () => {
                selected = { scanId: scan.scanId };
                return refresh();
              }),
              `${scan.progress.status} · ${scan.progress.phase}`,
              scan.mode,
              String(scan.findingCount),
            ]),
          ),
        );
      root.append(pagination(page.nextOffset));
    } else {
      const page = await read(
        "list_codex_security_global_findings",
        args,
        findingsPageSchema,
      );
      if (current !== generation) return;
      root.replaceChildren(element("h1", "Findings"));
      if (!page.findings.length)
        root.append(element("p", "No local findings match."));
      else
        root.append(
          table(
            ["Finding", "Repository", "Severity", "Status"],
            page.findings.map((finding) => [
              button(finding.title, () => {
                selected = {
                  scanId: finding.scanId,
                  occurrenceId: finding.occurrenceId,
                };
                return refresh();
              }),
              finding.targetPath,
              finding.severity.level,
              finding.status ?? "untriaged",
            ]),
          ),
        );
      root.append(pagination(page.nextOffset));
    }
  } catch (error) {
    if (current === generation) {
      root.replaceChildren(
        element(
          "p",
          "Local results could not be loaded. Refresh to try again.",
        ),
      );
      notice.textContent =
        error instanceof Error ? error.message : String(error);
    }
  } finally {
    if (current === generation) root.removeAttribute("aria-busy");
  }
}

async function loadScanFindings(scanId: string, pageOffset: number) {
  const current = ++generation;
  const { findingsPage } = await read(
    "list_codex_security_findings",
    { scanId, offset: pageOffset, limit: 20 },
    z.object({
      findingsPage: z.object({
        findings: z.array(scanSchema.shape.findings.element),
        nextOffset: z.number().nullable(),
      }),
    }),
  );
  if (current !== generation) return;
  root.replaceChildren(
    element("h1", "Scan findings"),
    table(
      ["Finding", "Severity"],
      findingsPage.findings.map((finding) => [
        button(finding.title, () => {
          selected = { scanId, occurrenceId: finding.occurrenceId };
          return refresh();
        }),
        finding.severity.level,
      ]),
    ),
  );
  if (pageOffset > 0)
    root.append(
      button("Previous", () => loadScanFindings(scanId, pageOffset - 20)),
    );
  if (findingsPage.nextOffset != null)
    root.append(
      button("Next", () => loadScanFindings(scanId, findingsPage.nextOffset!)),
    );
}

async function start() {
  app.onhostcontextchanged = (context) => {
    if (context.theme) applyDocumentTheme(context.theme);
    if (context.styles?.variables)
      applyHostStyleVariables(context.styles.variables);
  };
  await app.connect();
  const context = app.getHostContext();
  if (context?.theme) applyDocumentTheme(context.theme);
  if (context?.styles?.variables)
    applyHostStyleVariables(context.styles.variables);
  for (const tab of document.querySelectorAll<HTMLButtonElement>(
    "[data-view]",
  )) {
    tab.onclick = () => {
      view = tab.dataset.view === "findings" ? "findings" : "scans";
      offset = 0;
      selected = null;
      void refresh();
    };
  }
  document
    .querySelector("#search-form")!
    .addEventListener("submit", (event) => {
      event.preventDefault();
      offset = 0;
      selected = null;
      void refresh();
    });
  document.querySelector("#refresh")!.replaceWith(button("Refresh", refresh));
  document.querySelector("#new-scan")!.replaceWith(
    button("New scan", async () => {
      await app.sendMessage(
        conversationMessage(
          "Use the codex-security security-scan skill to start a Local security scan. Confirm the repository and scope with me before starting. Keep results in the existing local Security store on this computer.",
        ),
      );
    }),
  );
  await refresh();
}

void start().catch((error) => {
  notice.textContent = `Could not connect to Codex: ${error instanceof Error ? error.message : String(error)}`;
});
