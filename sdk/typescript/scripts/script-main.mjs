import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function isMain(moduleUrl) {
  return (
    process.argv[1] !== undefined &&
    pathToFileURL(realpathSync(process.argv[1])).href === moduleUrl
  );
}
