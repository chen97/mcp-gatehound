// Does a call's spark travel along the wire?
//
// The spark is meant to be a dash swept along the measured path — `stroke-dasharray: 34
// (len - 34)` with the offset animating from `--len` to 0, which is how you move 34px of light
// from one end of a bent path to the other. What `.trace-spark.run` actually animates is
// `@keyframes drift`, a `translateX`, which moves the whole path sideways across the container
// and leaves the dash exactly where it started.
//
// Reading the stylesheet makes that an argument. This makes it a number: sample the path's two
// ends, then sample where the lit dash actually is at t=0.25/0.5/0.75 and how far it is from the
// wire it is supposed to be following.
//
//   node spark.mjs
import { openBoard, reporter } from "./board-harness.mjs";

const r = reporter();
const { page, errors, close } = await openBoard();

/// Everything about one spark, read at one instant.
///
/// Two positions are computed, both in screen pixels:
///
///   wire(t)  — the point a fraction t along the path, mapped through the *sibling* `.trace`'s
///              screen matrix. That is the wire, and it never moves.
///   dash(t)  — the midpoint of the lit 34px dash, derived from the computed `stroke-dashoffset`
///              and mapped through the *spark's* own screen matrix, which carries the animation's
///              transform. That is where the light actually is.
///
/// If the spark swept the path those two would coincide at every t. The distance between them is
/// the bug, in pixels.
const sample = (t) =>
  page.evaluate((t) => {
    const spark = document.querySelector(".board-wires .trace-spark.run");
    if (!spark) return null;
    // The `.trace` painted from the same `d` in the same group — the wire itself, untransformed.
    const wire = spark.parentElement.querySelectorAll(".trace")[
      [...spark.parentElement.querySelectorAll(".trace-spark")].indexOf(spark)
    ];
    const cs = getComputedStyle(spark);
    const len = spark.getTotalLength();

    const at = (el, l) => {
      const p = el.getPointAtLength(l);
      const m = el.getScreenCTM();
      return { x: +(p.x * m.a + p.y * m.c + m.e).toFixed(1), y: +(p.x * m.b + p.y * m.d + m.f).toFixed(1) };
    };

    // Where the dash sits *along the path*, in path-length units.
    //
    // dasharray is `34 len`, so the pattern's period is 34 + len — a dash, then a full
    // path-length of gap — not len. That distinction is the whole measurement: there is exactly
    // one dash in flight and it travels 34 + len to cross, because it starts wholly before the
    // path (offset 34, occupying [-34, 0]) and finishes wholly past it (offset -len, occupying
    // [len, len + 34]). Reducing that modulo len wraps a dash that has not wrapped and reports it
    // back at the near end — which reads exactly like a spark that never moved.
    const off = parseFloat(cs.strokeDashoffset) || 0;
    const mid = -off + 17;                 // centre of the dash, in path units

    // Only ask where the light is while the dash actually overlaps the path. Off either end it is
    // not drawn, so the question has no answer and a clamped one would be a fiction.
    const onPath = mid >= 0 && mid <= len;
    const dash = onPath ? at(spark, mid) : null;
    const want = onPath ? at(wire, mid) : null;

    return {
      len: Math.round(len),
      period: Math.round(34 + len),
      // `strokeDasharray`, lowercase a — `strokeDashArray` is not a property and reads undefined,
      // which printed as "dasharray undefined" and looked like the dash geometry was missing.
      dashArray: cs.strokeDasharray,
      dashOffset: +off.toFixed(1),
      alongPath: +mid.toFixed(1),          // where the light is on the wire, 0 = the caller's end
      onPath,
      transform: cs.transform,
      dash, want,
      // Whether the lit dash is on its wire or somewhere else in the window — i.e. whether the
      // element is being translated across the container instead of swept along the path.
      off: onPath ? Math.round(Math.hypot(dash.x - want.x, dash.y - want.y)) : null,
    };
  }, t);

// The two ends, before anything runs. Which end is which is the other half of the question the
// repo's own skill learned the hard way — "the path ran end-to-start; the dot was travelling
// backwards" — so it gets measured rather than assumed.
const ends = await page.evaluate(() => {
  const s = document.querySelector('.board-wires .trace-spark[data-service="notes"]')
    ?? document.querySelector(".board-wires .trace-spark");
  const m = s.getScreenCTM();
  const map = (p) => ({ x: Math.round(p.x * m.a + p.y * m.c + m.e), y: Math.round(p.x * m.b + p.y * m.d + m.f) });
  const hub = document.querySelector("#flow-hub").getBoundingClientRect();
  return {
    which: s.dataset.service ? `service ${s.dataset.service}` : `caller ${s.dataset.caller}`,
    len: Math.round(s.getTotalLength()),
    p0: map(s.getPointAtLength(0)),
    p1: map(s.getPointAtLength(s.getTotalLength())),
    hub: { x: Math.round(hub.x + hub.width / 2), y: Math.round(hub.y + hub.height / 2) },
  };
});

r.say(`\npath geometry — ${ends.which}, ${ends.len}px long`);
r.say(`  getPointAtLength(0)    (${ends.p0.x}, ${ends.p0.y})`);
r.say(`  getPointAtLength(len)  (${ends.p1.x}, ${ends.p1.y})`);
r.say(`  the chip's centre      (${ends.hub.x}, ${ends.hub.y})`);
const d0 = Math.hypot(ends.p0.x - ends.hub.x, ends.p0.y - ends.hub.y);
const d1 = Math.hypot(ends.p1.x - ends.hub.x, ends.p1.y - ends.hub.y);
r.say(`  start is ${Math.round(d0)}px from the chip, end is ${Math.round(d1)}px — the path runs ` +
      (d0 < d1 ? "chip → tile" : "tile → chip"));

// Fire one, exactly the way `pulse()` does: a duration from the measured length, then the
// classes. Slowed 6× so the samples land in the middle of it rather than racing it.
const DUR = 4200;
await page.evaluate((dur) => {
  const s = document.querySelector('.board-wires .trace-spark[data-service="notes"]')
    ?? document.querySelector(".board-wires .trace-spark");
  s.classList.remove("run", "ok", "err", "held");
  void s.getBoundingClientRect();
  s.style.animationDuration = `${dur}ms`;
  s.classList.add("run", "ok");
}, DUR);

r.say(`\nwhere the light actually is, across one ${DUR}ms spark`);
const rows = [];
for (const t of [0.05, 0.25, 0.5, 0.75, 0.95]) {
  await page.waitForTimeout(t === 0.05 ? DUR * 0.05 : DUR * 0.2);
  const s = await sample(t);
  if (!s) { r.fail("the spark stopped running before it could be sampled"); break; }
  rows.push({ t, ...s });
  r.say(`  t=${t.toFixed(2)}  along the path ${String(s.alongPath).padStart(6)}px of ${s.len}` +
        (s.onPath
          ? `   light at (${s.dash.x}, ${s.dash.y})   wire wants (${s.want.x}, ${s.want.y})   off by ${s.off}px`
          : `   (off the end — the dash is ${s.alongPath < 0 ? "still approaching" : "past"} the path, not drawn)`));
}

if (rows.length) {
  const first = rows[0];
  r.say(`\n  dasharray    ${first.dashArray}`);
  r.say(`  dashoffset   ${rows.map((x) => x.dashOffset).join(" → ")}`);
  r.say(`  transform    ${rows.map((x) => (x.transform.match(/matrix\([^)]*?([-\d.]+),\s*[-\d.]+\)$/)?.[1] ?? x.transform)).join(" → ")}  (translateX)`);

  // Monotonic and forward. Sampling is wall-clock so the exact figures drift a little between
  // runs, which is why this asks the shape of the travel rather than pinning each position:
  // strictly increasing, covering most of the path, in the direction the path runs.
  const moved = rows.at(-1).alongPath - rows[0].alongPath;
  const travel = Math.round(moved / first.len * 100);
  const monotonic = rows.every((x, i) => i === 0 || x.alongPath > rows[i - 1].alongPath);
  r.say("");
  r.check(monotonic && moved > first.len * 0.5,
    `the light travels the wire, forwards and without doubling back — ${travel}% of its length`,
    monotonic
      ? `the light barely moves: ${Math.round(moved)}px of ${first.len} across the whole ${DUR}ms`
      : `the light does not travel steadily — it goes ${rows.map((x) => x.alongPath).join(" → ")}, ` +
        `which doubles back. A discrete animation looks like this.`);

  // Only the samples where the dash is actually over the path can answer this.
  const onWire = rows.filter((x) => x.onPath);
  const worst = onWire.length ? Math.max(...onWire.map((x) => x.off)) : null;
  r.check(onWire.length >= 2 && worst <= 4,
    `the light stays on the wire — never more than ${worst}px off, across ${onWire.length} samples on the path`,
    onWire.length < 2
      ? `the dash was over the path for only ${onWire.length} of ${rows.length} samples — too few to tell`
      : `the light leaves the wire — up to ${worst}px away from the path it is meant to be following`);

  // The offset must interpolate, not flip. Chrome degrades an animation to discrete when an
  // endpoint is an unresolved calc(), and the giveaway is that every sample reads one of exactly
  // two values — which is how `calc(-1 * var(--len))` hid in this stylesheet.
  const distinct = new Set(rows.map((x) => x.dashOffset)).size;
  r.check(distinct > 2,
    `stroke-dashoffset interpolates — ${distinct} distinct values across the sweep`,
    `stroke-dashoffset takes only ${distinct} value(s) across the sweep — the animation is ` +
    `discrete, not interpolated, so the spark jumps rather than travels`);

  const xs = new Set(rows.map((x) => x.transform));
  r.check(xs.size === 1,
    "the path itself is not transformed",
    `the path is being translated instead (${xs.size} distinct transforms) — @keyframes drift moves ` +
    `the element across the container, not the dash along the wire`);
}

await close();
r.done(errors, "a call's spark sweeps the wire it belongs to");
