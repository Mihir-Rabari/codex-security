import { parseArgs } from "node:util";
import { parseJson } from "../helpers/json";
import { openWorkbenchDatabase, workbenchDatabasePath } from "./database";
import {
  listStoredFindings,
  storeFindings,
  type EmbeddedFinding,
} from "./findings";

export async function findingsCommand(
  command: string,
  args: string[],
  input: string,
): Promise<unknown> {
  const request = parseJson(input) as {
    stateDirectory: string;
    args?: string[];
    payload: { entries: EmbeddedFinding[]; repositoryId?: string };
  };
  const { values } = parseArgs({
    args: request.args ?? args,
    options:
      command === "list-stored-findings"
        ? { limit: { type: "string" }, offset: { type: "string" } }
        : {},
  });
  const { stateDirectory, payload } = request;
  const limit = Number(values.limit);
  const offset = Number(values.offset);
  if (
    command === "list-stored-findings" &&
    (!Number.isSafeInteger(limit) ||
      limit <= 0 ||
      !Number.isSafeInteger(offset) ||
      offset < 0)
  )
    throw new Error(
      "--limit must be a positive integer and --offset a non-negative integer.",
    );
  const database = await openWorkbenchDatabase(
    workbenchDatabasePath(stateDirectory),
    { deferred: command === "list-stored-findings" },
  );
  try {
    if (command === "store-findings")
      return storeFindings(
        database,
        payload.entries,
        new Date().toISOString(),
        payload.repositoryId,
      );
    return listStoredFindings(database, { limit, offset });
  } finally {
    database.close();
  }
}
