import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The interface is translated by rewriting the text of the page. An <option> without a value takes its text as its
// value, so in a translated interface a menu would send "baixo" to the server instead of "low".
function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return name.endsWith(".jsx") && !name.includes(".test.") ? [path] : [];
  });
}

describe("menus in a translated interface", () => {
  it("never leave an option's value to its text", () => {
    const offenders = sources(join(process.cwd(), "src")).flatMap((file) =>
      readFileSync(file, "utf8").split("\n").flatMap((line, i) =>
        /<option(?![^>]*\bvalue=)[^>]*>\s*\{/.test(line) ? [`${file}:${i + 1}`] : []));
    expect(offenders).toEqual([]);
  });
});
