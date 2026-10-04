import { mkdir, writeFile } from "node:fs/promises";
import { junit, tap, type TestEvent } from "node:test/reporters";

export default async function* report(source: AsyncIterable<TestEvent>) {
  const events: TestEvent[] = [];
  async function* record() {
    for await (const event of source) {
      events.push(event);
      yield event;
    }
  }

  yield* tap(record());

  try {
    await mkdir("reports", { recursive: true });
    await writeFile(
      "reports/junit.xml",
      junit(events as unknown as AsyncIterable<TestEvent>),
    );
  } catch (error) {
    console.warn(
      `Could not write the optional MCP test report: ${(error as Error).message}`,
    );
  }
}
