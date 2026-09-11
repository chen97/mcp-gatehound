---
name: verify-by-driving
description: Verify UI changes by driving the running app and measuring, not by reading the code or eyeballing a screenshot. Use whenever a change affects layout, scrolling, focus, animation, hover, or anything whose correctness depends on real geometry — and whenever asked whether something is smooth, leaking, or costing CPU. Covers the headless-browser harness for webview apps, what to assert, and the failures this catches that code review does not.
---

# Verify by driving

Reading the code tells you what you wrote. Driving the app tells you what it does. For anything
positional, animated, or timed, those are different, and the gap is where the bugs live.

## The rule

**If a change touches geometry, focus, motion, or cost, do not report it as working until you
have driven it and read numbers back.** A screenshot is evidence; a measurement is proof. A
screenshot scaled to fit a chat window is neither — position is exactly what it loses.

## What this catches that reading does not

Every one of these was invisible in review and obvious in a measurement:

| Symptom | What the code looked like | What the measurement said |
|---|---|---|
| Node expand/collapse flickering on hover | Correct | Expanded 153px inside a 176px slot — the tile shrank out from under the cursor and oscillated |
| Animation "not following the line" | Correct | The path ran end-to-start; the dot was travelling backwards |
| Idle animation looked dead | Correct | One dash per line, lit 22% of the time, one every 1.3s |
| Expanded card overflowed | Correct at the width I tested | Only reproduced at 820–900px; the report was from a Retina screen at ~830 logical px |
| Focus landed on the right element | Correct | The element was 70px above the viewport — focused, and off screen |
| "Feels fine" ambient motion | Correct | 4.4% of a core, continuously, forever |

Twice I also chased a bug that did not exist, because I judged a scaled screenshot by eye.
Dumping the geometry settled it in one run both times.

## The harness (webview / Electron / Tauri UI)

Serve the built assets, stub the native bridge, drive with Playwright. Nothing about this needs
the real backend — the point is the UI's own behaviour.

```js
import { chromium } from "playwright";
import http from "node:http"; import fs from "node:fs"; import path from "node:path";

// 1. Serve the built frontend.
const server = http.createServer((req, res) => { /* static from dist/ */ });
await new Promise((r) => server.listen(PORT, r));

// 2. Stub the native bridge with a fixture, and count what the UI asks for.
await page.addInitScript((data) => {
  window.__calls = [];
  window.__NATIVE__ = { invoke: (cmd, args) => { window.__calls.push([cmd, args]);
                                                 return Promise.resolve(data[cmd] ?? null); } };
}, FIXTURE);

// 3. Fail loudly on anything thrown.
const errors = []; page.on("pageerror", (e) => errors.push(String(e)));
```

Two things the harness must always do: **stub the bridge so the fixture is the input**, and
**collect `pageerror`** — a silent exception in a handler looks exactly like "the feature does
nothing".

### Headless lies about some things

- **Scrollbars do not exist in headless Chromium.** `offsetWidth - clientWidth` is 0 however you
  style them. Run `xvfb-run -a node probe.mjs` with `headless: false` to see them at all.
- **`visibilityState` is always `visible`**, and bringing another tab to the front does not
  change it. To exercise a visibility path, redefine the property and dispatch the event.
- **CPU numbers are software-rendered**, so they are an upper bound, not the user's number. Use
  them to compare A against B, not to quote an absolute.

## What to assert

Prefer a number you can compare over a boolean you have to trust.

- **Position**: element rect relative to the scrollport — `inView`, `topOff`, `botOff`. Assert
  *both* that the thing is visible and that the focused element is visible; they are different
  claims and the second is the one that breaks.
- **Stability**: probe the edges. Twelve hover positions across a node's boundary, asserting the
  width never changes, is what proves the oscillation is gone.
- **Direction**: for a path animation, sample `getPointAtLength(0)` and
  `getPointAtLength(getTotalLength())` and check which end is which.
- **Idempotence**: do the thing twice. A second click, a second paint, a second publish —
  handlers that stack and listeners that double up only show up on the second pass.
- **Cost**: CDP `Performance.getMetrics`, sampled across a window. `TaskDuration` over wall
  clock is your percentage of a core; `RecalcStyleDuration` says whether the main thread is
  doing per-frame style work it should not be.
- **Retention**: hold a `WeakRef` to each element you replace, run `--js-flags=--expose-gc`,
  force GC, count survivors. A leak keeps all of them; healthy keeps one or two.

## Isolate the cause, do not guess it

When something costs more than it should, turn the candidates off one at a time in the same run:

```js
const all      = await sample("everything", 8000);
await page.addStyleTag({ content: ".drift { animation: none !important; }" });
const noDrift  = await sample("drift off", 8000);
```

That is what turned "the board animation is expensive" into "the drift is 4.4%, the halo is
0.0%" — and 0.0% is the interesting half, because it says which technique to reach for next.

## Keep the harness

Probes are cheap to write and expensive to re-derive. Keep them next to the UI in the repo, not
in a scratch directory, and name them after the question they answer (`hoversize.mjs`,
`lines.mjs`, `idle.mjs`). Re-running the whole set after an unrelated change is how you find out
you broke something you were not thinking about.

## Not only webviews

The harness is webview-specific; the discipline is not. For a native UI the equivalents are UI
tests that read frames back (`XCUIElement.frame`, view hierarchy dumps), Instruments for the
cost questions, and the same rule: assert a number, probe the edges, do it twice.
