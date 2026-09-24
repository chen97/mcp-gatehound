// What does the board cost while nobody is looking?
//
// This window lives in a menubar, and closing it hides it rather than quitting, so hidden is
// where it spends most of its life. The idle drift is the one thing on the page that costs a
// style recalculation and a repaint every frame — `stroke-dashoffset` is not a composited
// property — and `body.unwatched` is what is supposed to stop it.
//
// The numbers here are software-rendered, so they are an upper bound rather than the number a
// user would see. Read them as A against B: watched versus unwatched, and each candidate turned
// off one at a time, which is how you find out which technique is the expensive one rather than
// guessing.
//
//   node idle.mjs
import { openBoard, reporter } from "./board-harness.mjs";

const r = reporter();
const { page, errors, close } = await openBoard({ port: 5204 });

const cdp = await page.context().newCDPSession(page);
await cdp.send("Performance.enable");

const metrics = async () => Object.fromEntries((await cdp.send("Performance.getMetrics")).metrics.map((m) => [m.name, m.value]));

/// Percentage of one core, plus how much of it was per-frame style work.
///
/// `TaskDuration` over wall clock is the share of a core; `RecalcStyleDuration` alongside it says
/// whether the main thread is restyling every frame or just compositing.
const sample = async (label, ms) => {
  const a = await metrics();
  const t0 = Date.now();
  await page.waitForTimeout(ms);
  const b = await metrics();
  const wall = (Date.now() - t0) / 1000;
  const of = (k) => ((b[k] ?? 0) - (a[k] ?? 0)) / wall * 100;
  const row = { label, cpu: of("TaskDuration"), style: of("RecalcStyleDuration"), layout: of("LayoutDuration") };
  console.log(`  ${label.padEnd(26)} ${row.cpu.toFixed(1).padStart(5)}% of a core` +
              `   restyle ${row.style.toFixed(1)}%   layout ${row.layout.toFixed(1)}%`);
  return row;
};

const WINDOW = 6000;
r.say(`\nsampled over ${WINDOW / 1000}s each, software-rendered — compare them, do not quote them`);

const watched = await sample("watched, everything on", WINDOW);

// The shell hiding the window is the real path, but a webview that reports `visibilitychange`
// when hidden is a per-platform accident — and headless Chromium never reports it at all, so
// the property is redefined and the event dispatched by hand.
await page.evaluate(() => {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
  document.dispatchEvent(new Event("visibilitychange"));
});
const flagged = await page.evaluate(() => document.body.classList.contains("unwatched"));
r.check(flagged, "hiding the window sets body.unwatched", "hiding the window did not set body.unwatched");

const unwatched = await sample("unwatched", WINDOW);

// Back to watched, then turn the candidates off one at a time in the same run.
await page.evaluate(() => {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
  document.dispatchEvent(new Event("visibilitychange"));
});
await page.waitForTimeout(500);

await page.addStyleTag({ content: ".trace-drift { animation: none !important; }" });
const noDrift = await sample("watched, drift off", WINDOW);

await page.addStyleTag({ content: ".chip .dot.green::after, .chip .pill.hot { animation: none !important; }" });
const nothing = await sample("watched, nothing moving", WINDOW);

// ---- what the numbers say ----------------------------------------------------------------

r.say("");
const driftCost = watched.cpu - noDrift.cpu;
const pulseCost = noDrift.cpu - nothing.cpu;
r.say(`  the drift costs about ${driftCost.toFixed(1)}% of a core; the halo and the waiting pulse together about ${pulseCost.toFixed(1)}%`);
r.say(`  the drift accounts for ${(watched.style - noDrift.style).toFixed(1)}% of the ${watched.style.toFixed(1)}% spent restyling`);

r.check(unwatched.cpu < watched.cpu * 0.5 || unwatched.cpu < 1.5,
  `the pause holds — ${watched.cpu.toFixed(1)}% watched falls to ${unwatched.cpu.toFixed(1)}% unwatched`,
  `the pause has stopped working — ${watched.cpu.toFixed(1)}% watched, ${unwatched.cpu.toFixed(1)}% unwatched`);

r.check(unwatched.style < 1.0,
  `nothing is restyling per frame while nobody is looking (${unwatched.style.toFixed(1)}%)`,
  `something still restyles every frame while hidden (${unwatched.style.toFixed(1)}%)`);

await close();
r.done(errors, "the board pauses when nobody is looking");
