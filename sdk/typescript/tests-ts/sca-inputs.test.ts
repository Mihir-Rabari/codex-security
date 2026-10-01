import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  additionalScaInput,
  inspectAdditionalScaInput,
  type AdditionalScaFormat,
} from "../src/sca-inputs.js";

function inspect(content: string, format: AdditionalScaFormat) {
  return inspectAdditionalScaInput(content, format, "app/dependencies");
}

describe("additional SCA input contracts", () => {
  test.each([
    ["uv.lock", "uv", "PyPI"],
    ["poetry.lock", "poetry", "PyPI"],
    ["Pipfile.lock", "pipenv", "PyPI"],
    ["requirements-dev.txt", "requirements", "PyPI"],
    ["my-requirements.txt", "requirements", "PyPI"],
    ["go.mod", "go", "Go"],
    ["Cargo.lock", "cargo", "crates.io"],
    ["pom.xml", "maven", "Maven"],
    ["synthetic.pom", "maven", "Maven"],
    ["gradle.lockfile", "gradle", "Maven"],
    ["buildscript-gradle.lockfile", "gradle", "Maven"],
    ["Gemfile.lock", "bundler", "RubyGems"],
    ["gems.locked", "bundler", "RubyGems"],
    ["composer.lock", "composer", "Packagist"],
    ["packages.lock.json", "nuget", "NuGet"],
  ] as const)(
    "discovers the pinned extractor input %s",
    (name, format, ecosystem) => {
      expect(additionalScaInput(join("nested", name))).toEqual({
        format,
        ecosystem,
      });
    },
  );

  test.each([
    "go.sum",
    "Cargo.toml",
    "pyproject.toml",
    "Pipfile",
    "build.gradle",
    "other.lockfile",
    "requirements.in",
    "__proto__",
  ])("does not treat %s as a supported resolved input", (name) =>
    expect(additionalScaInput(name)).toBeNull(),
  );

  test.each(["uv", "poetry"] as const)(
    "preserves %s direct origins and normalizes PyPI names",
    (format) => {
      const source =
        format === "uv"
          ? 'source = { editable = "../local" }'
          : 'source = { type = "directory", url = "../local" }';
      const result = inspect(
        `[[package]]\nname="Synthetic_Package.Name"\nversion="1!2.0.post1"\n${source}\n`,
        format,
      );
      expect(result.status).toBe("scanned");
      expect(result.references).toEqual([
        expect.objectContaining({
          ecosystem: "PyPI",
          name: "synthetic-package-name",
          version: "1!2.0.post1",
        }),
      ]);
    },
  );

  test("does not mistake registry URLs for direct Python archives", () => {
    expect(
      inspect(
        '[[package]]\nname="synthetic"\nversion="2.0rc1"\nsource={registry="https://example.invalid/simple"}',
        "uv",
      ).references,
    ).toEqual([]);
    expect(
      inspect(
        '[[package]]\nname="synthetic"\nversion="2.0rc1"\nsource={type="legacy",url="https://example.invalid/simple"}',
        "poetry",
      ).references,
    ).toEqual([]);
  });

  test("distinguishes uv virtual root from omitted local identities", () => {
    const root =
      '[[package]]\nname="application"\nversion="1.0.0"\nsource={virtual="."}\n';
    const local =
      '[[package]]\nname="synthetic-local"\nversion="1.0.0"\nsource={path="../local"}\n';
    expect(
      inspect(root + local, "uv").references.map((reference) => reference.name),
    ).toEqual(["synthetic-local"]);
  });

  test("counts Pipenv omitted local, unpinned, and custom-category entries", () => {
    const result = inspect(
      JSON.stringify({
        _meta: { version: 6 },
        default: {
          registry: { version: "==1.2.3" },
          local: { path: "./local", editable: true },
          range: { version: ">=2" },
        },
        develop: { dev: { version: "==1.2.3" } },
        custom: { extra: { version: "==1.0.0" } },
      }),
      "pipenv",
    );
    expect(result.status).toBe("scanned");
    expect(result.references.map((reference) => reference.name)).toEqual([
      "local",
      "range",
      "extra",
    ]);
  });

  test("keeps Cargo nonregistry origins unresolved without losing registry inventory", () => {
    const result = inspect(
      [
        "version=4",
        '[[package]]\nname="registry"\nversion="1.2.3"\nsource="registry+https://example.invalid/index"',
        '[[package]]\nname="workspace"\nversion="1.0.0"',
        '[[package]]\nname="git"\nversion="1.2.3"\nsource="git+https://example.invalid/source#synthetic"',
      ].join("\n"),
      "cargo",
    );
    expect(result.status).toBe("scanned");
    expect(result.references.map((reference) => reference.name)).toEqual([
      "workspace",
      "git",
    ]);
  });

  test("accepts pinned requirements with hashes and markers but reports manifest coverage", () => {
    const result = inspect(
      'Synthetic_Package[extra]==1!2.0.post1 ; python_version >= "3.10"\nsynthetic-two==1.2.3 \\\n --hash=sha256:synthetic\n# comment\n',
      "requirements",
    );
    expect(result.status).toBe("scanned");
    expect(result.limitations.length).toBeGreaterThan(0);
    expect(result.diagnostics.length).toBeGreaterThan(0);
  });

  test.each([
    "synthetic>=1.0",
    "synthetic==1.*",
    "synthetic>=1,<2",
    "synthetic",
    "-r pins.txt",
    "--requirement pins.txt",
    "-c constraints.txt",
    "-e ./local",
    "synthetic @ https://example.invalid/package.whl",
    "synthetic==${VERSION}",
  ])(
    "does not invoke the requirements extractor for unresolved declaration %s",
    (content) =>
      expect(inspect(content, "requirements").status).toBe("unsupported"),
  );

  test.each(["1.16", "1.17rc1", "", "unknown"])(
    "does not pass Go %s to a scanner that might read additional go.sum inventory",
    (version) =>
      expect(
        inspect(
          `module example.test/app\n${version ? `go ${version}` : ""}`,
          "go",
        ).status,
      ).toBe("unsupported"),
  );

  test("supports current Go pins and mirrors upstream toolchain precedence", () => {
    expect(
      inspect(
        "module example.test/app\ngo 1.17\nrequire example.test/pkg v1.2.3",
        "go",
      ).status,
    ).toBe("scanned");
    expect(
      inspect("module example.test/app\ngo 1.16\ntoolchain go1.20.3", "go")
        .status,
    ).toBe("scanned");
    expect(
      inspect("module example.test/app\ngo 1.20\ntoolchain default", "go")
        .status,
    ).toBe("unsupported");
    expect(
      inspect(
        "module example.test/app\ngo 1.20\nexclude example.test/pkg v1.2.3",
        "go",
      ).limitations.length,
    ).toBeGreaterThan(0);
    expect(
      inspect(
        "module example.test/app\ngo 1.20\nexclude example.test/pkg v1.2.3",
        "go",
      ).diagnostics.length,
    ).toBeGreaterThan(0);
  });

  test.each([
    ["uv", '[[package]\nname="broken"'],
    ["poetry", "package=1"],
    ["pipenv", '{"default":'],
    ["cargo", '[[package]]\nversion="1.0.0"'],
  ] as const)(
    "reports malformed %s metadata instead of empty clean inventory",
    (format, content) => {
      expect(inspect(content, format).status).toBe("unsupported");
    },
  );

  test("accepts namespaced Maven direct pins and preserves manifest limitations", () => {
    const result = inspect(
      `<?xml version="1.0"?>
      <m:project xmlns:m="http://maven.apache.org/POM/4.0.0">
        <!-- parent-free synthetic fixture -->
        <m:modelVersion>4.0.0</m:modelVersion>
        <m:properties><m:compiler.version>17</m:compiler.version></m:properties>
        <m:build><m:plugins><m:plugin><m:artifactId>synthetic-plugin</m:artifactId><m:version>1.0.0</m:version><m:configuration><m:parent>ordinary configuration</m:parent></m:configuration></m:plugin></m:plugins></m:build>
        <m:dependencies><m:dependency>
          <m:groupId>example.test</m:groupId><m:artifactId>synthetic</m:artifactId>
          <m:version><![CDATA[1.0.Final+build]]></m:version>
        </m:dependency></m:dependencies>
      </m:project>`,
      "maven",
    );
    expect(result.status).toBe("scanned");
    expect(result.references).toEqual([]);
    expect(result.limitations.length).toBeGreaterThan(0);
    expect(result.diagnostics.length).toBeGreaterThan(0);
  });

  test.each([
    "<project><parent><relativePath>parent/pom.xml</relativePath></parent></project>",
    '<m:project xmlns:m="http://maven.apache.org/POM/4.0.0"><m:parent/></m:project>',
    "<project><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic</artifactId><version>[1,2)</version></dependency></dependencies></project>",
    "<project><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic</artifactId><version>${dependency.version}</version></dependency></dependencies></project>",
    "<project><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic</artifactId></dependency></dependencies></project>",
    "<project><dependencies>",
  ])("does not pass unresolved Maven manifest syntax to OSV", (content) => {
    expect(inspect(content, "maven").status).toBe("unsupported");
  });

  test("retains Maven local system artifacts as unresolved references", () => {
    const result = inspect(
      "<project><dependencies><dependency><groupId>example.test</groupId><artifactId>synthetic</artifactId><version>1.0.0</version><scope>system</scope><systemPath>lib/synthetic.jar</systemPath></dependency></dependencies></project>",
      "maven",
    );
    expect(result.status).toBe("scanned");
    expect(result.references).toEqual([
      expect.objectContaining({
        ecosystem: "Maven",
        name: "example.test:synthetic",
        version: "1.0.0",
      }),
    ]);
  });

  test("keeps Gradle locked versions and detects rows OSV silently omits", () => {
    expect(
      inspect(
        "# lockfile\r\n example.test:synthetic:1.0.Final=runtimeClasspath \r\nempty=testRuntimeClasspath\r\n",
        "gradle",
      ).status,
    ).toBe("scanned");
    expect(
      inspect(
        "example.test:synthetic:1.0.0=runtimeClasspath\nnot-a-package",
        "gradle",
      ).status,
    ).toBe("unsupported");
  });

  test("retains Bundler PATH provenance with upstream platform-version normalization", () => {
    const result = inspect(
      "GEM\n  remote: https://example.invalid/registry\n  specs:\n    registry (1.2.3)\nPATH\n  specs:\n    local (1.2.3-x64-mingw)\n  remote: local/source\nPLATFORMS\n  x64-mingw\n",
      "bundler",
    );
    expect(result.status).toBe("scanned");
    expect(result.references).toEqual([
      expect.objectContaining({
        ecosystem: "RubyGems",
        name: "local",
        version: "1.2.3",
        resolution: "path:local/source",
      }),
    ]);
  });

  test("detects the Bundler extractor's actual line token ceiling", () => {
    const prefix = "  remote: https://example.invalid/";
    const below = prefix + "a".repeat(65_535 - prefix.length);
    expect(
      inspect(`GEM\n${below}\n  specs:\n    synthetic (1.2.3)\n`, "bundler")
        .status,
    ).toBe("scanned");
    expect(
      inspect(`GEM\n${below}a\n  specs:\n    synthetic (1.2.3)\n`, "bundler")
        .status,
    ).toBe("unsupported");
  });

  test("distinguishes Composer registry distribution metadata from local origin", () => {
    const result = inspect(
      JSON.stringify({
        packages: [
          {
            name: "synthetic/registry",
            version: "v1.2.3",
            dist: { type: "zip", url: "https://example.invalid/registry.zip" },
            source: { type: "git", url: "https://example.invalid/source.git" },
          },
          {
            name: "synthetic/local",
            version: "v1.2.3",
            dist: { type: "path", url: "./local" },
            source: { type: "path", url: "./local" },
          },
        ],
        "packages-dev": [],
      }),
      "composer",
    );
    expect(result.status).toBe("scanned");
    expect(result.references).toEqual([
      expect.objectContaining({
        ecosystem: "Packagist",
        name: "synthetic/local",
        version: "v1.2.3",
      }),
    ]);
  });

  test("counts NuGet project identities once across frameworks and ignores requested ranges", () => {
    const dependencies = {
      "Synthetic.Registry": {
        type: "Direct",
        requested: "[1.0,)",
        resolved: "1.2.3-beta.2",
      },
      "Synthetic.Local": { type: "Project" },
    };
    const result = inspect(
      JSON.stringify({
        version: 1,
        dependencies: { net8: dependencies, net9: dependencies },
      }),
      "nuget",
    );
    expect(result.status).toBe("scanned");
    expect(result.references).toEqual([
      expect.objectContaining({
        ecosystem: "NuGet",
        name: "Synthetic.Local",
        version: null,
      }),
    ]);
  });
});
