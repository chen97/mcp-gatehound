// The form previews the name a downstream will be stored under; the Rust decides it. Both
// read tests_fixtures/derived_names.json, and this asserts the TypeScript half still agrees.
// A preview that drifted would be wrong in the one place an operator looks to check.
import { readFileSync } from "node:fs";

const table = JSON.parse(readFileSync("../../../tests_fixtures/derived_names.json", "utf8"));
const src = readFileSync("src/main.ts", "utf8");

// Lift the two functions straight out of the source rather than restating them here, so this
// tests what ships instead of a copy that could itself drift.
const grab = (name) => {
  const at = src.indexOf(`function ${name}(`);
  if (at < 0) throw new Error(`${name} is gone from main.ts`);
  let depth = 0;
  for (let i = src.indexOf("{", at); i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(at, i + 1);
  }
  throw new Error(`could not read ${name}`);
};

const strip = (js) => js.replace(/:\s*(string|Draft|ConnKind)\b/g, "").replace(/\bd: Draft\b/g, "d");
const fns = new Function(
  `${strip(grab("slug"))}\n${strip(grab("derivedName"))}\nreturn { slug, derivedName };`,
)();

let failed = 0;
const check = (got, want, label) => {
  if (got !== want) {
    console.error(`  ${label}\n    expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
    failed++;
  }
};

for (const [url, want] of table.url) {
  check(fns.derivedName({ kind: "mcp", url, base_url: "", tools: [] }), want, url);
  check(fns.derivedName({ kind: "http", url: "", base_url: url, tools: [] }), want, `${url} (http)`);
}
for (const [cmd, want] of table.command) {
  check(fns.derivedName({ kind: "exec", url: "", base_url: "", tools: [{ cmd }] }), want, cmd);
}

if (failed) {
  console.error(`\nthe form's preview disagrees with the stored name in ${failed} case(s)`);
  process.exit(1);
}
console.log(`derived names agree with the Rust in ${table.url.length * 2 + table.command.length} cases`);
