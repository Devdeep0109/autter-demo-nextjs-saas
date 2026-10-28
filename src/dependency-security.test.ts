import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Guards the dependency security pins for the CVEs addressed by the
 * dependency bump (GHSA-p3m5-59mp-jv5r et al.). The packages were
 * bumped to fixed versions in package-lock.json; this test ensures the
 * lockfile keeps shipping those fixed versions and does not regress.
 */
const LOCK_PATH = fileURLToPath(new URL("../package-lock.json", import.meta.url));

function lockedVersion(entryPath: string): string | undefined {
  const lock = JSON.parse(readFileSync(LOCK_PATH, "utf8")) as {
    packages: Record<string, { version?: string }>;
  };
  return lock.packages[entryPath]?.version;
}

describe("dependency security pins", () => {
  const cases: Array<{ entry: string; expected: string }> = [
    { entry: "node_modules/next", expected: "15.5.24" },
    { entry: "node_modules/tinypool", expected: "2.1.2" },
    { entry: "node_modules/vite/node_modules/postcss", expected: "8.5.18" },
    { entry: "node_modules/sharp", expected: "0.35.4" },
    { entry: "node_modules/source-map-js", expected: "1.2.2" },
    { entry: "node_modules/vite", expected: "8.3.3" },
    { entry: "node_modules/zod", expected: "4.6.6" },
  ];

  test.each(cases)("$entry is pinned to $expected", ({ entry, expected }) => {
    expect(lockedVersion(entry)).toBe(expected);
  });
});
