// Two things about the window that a type checker cannot see:
//
//  1. The form previews the name a downstream will be stored under; the Rust decides it. Both
//     read tests_fixtures/derived_names.json, and a preview that drifted would be wrong in the
//     one place an operator looks to check.
//  2. The screens must not redraw themselves on a timer. Every five seconds the window re-reads
//     the core, and a screen that rewrites its DOM regardless throws away scroll position,
//     focus and anything expanded. Two habits cause it, and both are easy to reintroduce.
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

// --- the screens must not redraw themselves ---------------------------------

const lines = src.split("\n");
const problems = [];

lines.forEach((line, i) => {
  const at = `src/main.ts:${i + 1}`;
  // Writing innerHTML directly skips the "has anything actually changed?" check, so the
  // screen rebuilds on every read whether or not it needed to.
  // One exemption, and it has to say so on the line: an element built once and thrown away —
  // a modal, say — is not a screen, has nothing to diff against, and cannot redraw on a timer
  // because nothing re-renders it. Requiring the marker keeps every such case visible here
  // rather than letting the rule quietly rot.
  if (
    /\.innerHTML\s*=/.test(line) &&
    !/^\s*el\.innerHTML = html;/.test(line) &&
    !/built once, never repainted/.test(`${lines[i - 1] ?? ""}\n${line}`)
  ) {
    problems.push(`${at}  writes innerHTML directly — go through paint(el, html)`);
  }
  // A relative time inside markup changes the markup, so any list holding one repaints on a
  // timer however little else moved. ago() emits the instant and tickTimes fills in the words.
  // The one legitimate use is inside ago() itself, seeding the text it will later refresh.
  if (/\$\{(esc\()?when\(/.test(line) && !/^\s*return `<time class="ago"/.test(line)) {
    problems.push(`${at}  puts a relative time in the markup — use ago(...) instead`);
  }
});

if (problems.length) {
  console.error("\nthese would make a screen redraw itself on a timer:");
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("no screen redraws itself on a timer");
