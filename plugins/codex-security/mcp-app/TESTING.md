# MCP tests

From `sdk/typescript`, install both packages' dependencies, prepare the [universal native payload](../native/README.md#package-inputs), and run `pnpm run test:mcp`. That command builds the bundled plugin before testing it. To rerun only the tests after a build, run `pnpm run test:mcp` from this directory.

`pnpm run build:tests` type-checks the TypeScript tests and tooling and uses esbuild to emit ignored `.js` files beside their `.ts` sources, plus `.mjs` files for the `.mts` reporter and host-build test. This preserves relative fixture paths and supports Node 22.13 without a TypeScript loader. `pnpm run test:mcp` runs that build first; `pnpm run typecheck` also checks the tests.

Node's test runner discovers `tests/test_*.js`, covering the compiled TypeScript tests, and runs at most two files at once, each in a separate process. Assertions within a file remain sequential. Write new tests in TypeScript and keep shared helpers outside that filename pattern. A failing script fails the command. The reporter streams Node's TAP output and then tries to write Node's JUnit report to `reports/junit.xml`; an unavailable report path warns without changing the test result. CI uploads that file with the Node 22 reports.

For a serial comparison, run:

```sh
pnpm run build:tests
node --test --test-concurrency=1 "tests/test_*.js"
```

Use the existing injected clocks for retry policy tests. Keep real timers, subprocesses, SQLite files, and isolated temporary directories in the lifecycle, locking, permissions, and stdio tests. Do not share writable fixtures between test files or rebuild the bundled plugin while another test is reading it.
