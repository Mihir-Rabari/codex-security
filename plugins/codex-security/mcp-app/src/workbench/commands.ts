import { parseJson } from "../helpers/json";
import { openWorkbenchDatabase, workbenchDatabasePath } from "./database";
import {
  listStoredFindings,
  storeFindings,
  type EmbeddedFinding,
} from "./findings";

export async function findingsCommand(
  command: string,
  input: string,
): Promise<unknown> {
  const request = parseJson(input) as {
    stateDirectory: string;
    payload: unknown;
  };
  const { stateDirectory, payload } = request;
  const page = payload as { limit: number; offset: number };
  if (
    command === "list-stored-findings" &&
    (!Number.isSafeInteger(page.limit) ||
      page.limit <= 0 ||
      !Number.isSafeInteger(page.offset) ||
      page.offset < 0)
  )
    throw new Error(
      "limit must be a positive integer and offset a non-negative integer.",
    );
  const database = await openWorkbenchDatabase(
    workbenchDatabasePath(stateDirectory),
    { deferred: command === "list-stored-findings" },
  );
  try {
    if (command === "store-findings") {
      const { entries, repositoryId } = payload as {
        entries: EmbeddedFinding[];
        repositoryId?: string;
      };
      return storeFindings(
        database,
        entries,
        new Date().toISOString(),
        repositoryId,
      );
    }
    return listStoredFindings(database, page);
  } finally {
    database.close();
  }
}
