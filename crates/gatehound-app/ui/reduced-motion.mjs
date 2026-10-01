// What actually stops when motion is unwelcome?
//
// `prefers-reduced-motion: reduce` is a different design, not a disabled one — the fade stays,
// the travel goes, and the ambient loops go entirely. The stylesheet says all of that. Whether
// the rules reach the elements they name is a separate question, and the only way to answer it
// is to turn the preference on and read the computed styles back.
//
// Three of the things this checks are the same shape of mistake: a rule that names an element
// which is not the one carrying the animation. That is invisible in review — the rule looks
// right, it is just pointed at nothing.
//
//   node reduced-motion.mjs
import { openBoard, reporter } from "./board-harness.mjs";

const r = reporter();

// ---- 1. Is there a rule in the stylesheet with nothing in it? ----------------------------

{
  const { page, close } = await openBoard({ settle: false, port: 5202 });
  const blocks = await page.evaluate(() => {
    const out = [];
    for (const sheet of document.styleSheets) {
      let rules; try { rules = sheet.cssRules; } catch { continue; }
      const walk = (list) => {
        for (const rule of list) {
          if (rule.media?.mediaText?.includes("prefers-reduced-motion")) {
            out.push({ text: rule.media.mediaText, count: rule.cssRules.length,
                       selectors: [...rule.cssRules].map((x) => x.selectorText ?? `@${x.name ?? "?"}`) });
          }
          if (rule.cssRules) walk(rule.cssRules);
        }
      };
      walk(rules);
    }
    return out;
  });

  r.say(`\nreduced-motion blocks in the shipped stylesheet: ${blocks.length}`);
  blocks.forEach((b, i) => r.say(`  [${i}] ${b.count} rule(s)  ${b.selectors.join(", ") || "— empty —"}`));
  const empty = blocks.filter((b) => b.count === 0);
  r.check(empty.length === 0,
    "every reduced-motion block does something",
    `${empty.length} reduced-motion block(s) are empty — they read as "this was considered" when nothing was`);

  // The rule the stylesheet writes as `.node.lit`. If there is no `.node`, it cannot be applying.
  const nodes = await page.evaluate(() => ({
    node: document.querySelectorAll(".node").length,
    tile: document.querySelectorAll(".tile").length,
    slot: document.querySelectorAll(".tile-slot").length,
  }));
  r.say(`\nelements on the board: .node ${nodes.node}, .tile ${nodes.tile}, .tile-slot ${nodes.slot}`);
  r.check(nodes.node > 0 || !blocks.some((b) => b.selectors.some((s) => s?.includes(".node"))),
    "no rule names an element that does not exist",
    `the stylesheet styles .node.lit and there are 0 .node elements — the class is .tile, the state is .tile-slot.lit`);
  await close();
}

// ---- 2. Does the board's entrance actually stop travelling? -------------------------------
//
// `.tile-slot` is what carries `tile-in-left` / `tile-in-right`, both of which are a translateX.
// The reduce block swaps `animation-name` on `.tile` and `.chip`. `.tile` is the button *inside*
// the slot, so the swap lands on an element that has no animation to swap.

{
  const { page, errors, close } = await openBoard({ reducedMotion: "reduce", settle: false, port: 5203 });

  const read = () =>
    page.evaluate(() => {
      const pick = (sel) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        const cs = getComputedStyle(el);
        const m = cs.transform;
        const tx = m === "none" ? 0 : +(m.match(/matrix\(([^)]*)\)/)?.[1].split(",")[4] ?? 0);
        return { name: cs.animationName, dur: cs.animationDuration, tx: +(+tx).toFixed(1), opacity: +cs.opacity.slice(0, 4) };
      };
      return {
        slot: pick(".rail.left .tile-slot"),
        tile: pick(".rail.left .tile-slot .tile"),
        chip: pick(".chip"),
        drift: pick(".trace-drift"),
        halo: (() => { const el = document.querySelector(".chip .dot.green"); if (!el) return null;
          const cs = getComputedStyle(el, "::after"); return { name: cs.animationName, opacity: +cs.opacity.slice(0, 4) }; })(),
        hot: pick(".chip .pill.hot"),
      };
    });

  r.say(`\nwith reduce-motion on, sampled across the board's entrance`);
  const frames = [];
  for (let i = 0; i < 5; i++) { frames.push(await read()); await page.waitForTimeout(70); }

  const f = frames[0];
  r.say(`  .tile-slot   animation ${f.slot.name} ${f.slot.dur}   translateX ${frames.map((x) => x.slot.tx).join(" → ")}`);
  r.say(`  .tile        animation ${f.tile.name} ${f.tile.dur}`);
  r.say(`  .chip        animation ${f.chip.name} ${f.chip.dur}`);

  const travel = Math.max(...frames.map((x) => Math.abs(x.slot.tx)));
  r.check(travel < 0.5,
    "the board's tiles arrive without travelling",
    `the tiles still slide ${travel}px under reduce-motion — the reduce block renames the animation on ` +
    `.tile, but the animation is on .tile-slot, so "${f.slot.name}" keeps running`);

  r.check(f.chip.name === "fade-in",
    "the chip fades in rather than scaling",
    `the chip still runs "${f.chip.name}" under reduce-motion`);

  // The ambient loops. These the stylesheet does target correctly — worth proving, because the
  // point of the section is that reduce is a design, not a switch, and these are the half of it
  // that works.
  r.say(`\n  ambient loops under reduce`);
  r.say(`    .trace-drift          animation ${f.drift.name}  opacity ${f.drift.opacity}`);
  r.say(`    .chip .dot.green::after  animation ${f.halo.name}  opacity ${f.halo.opacity}`);
  r.say(`    .chip .pill.hot       animation ${f.hot?.name ?? "—"}`);
  r.check(f.drift.name === "none" && f.drift.opacity === 0, "the idle drift is gone", `the idle drift still runs (${f.drift.name})`);
  r.check(f.halo.name === "none", "the status halo is gone", `the status halo still runs (${f.halo.name})`);
  r.check(!f.hot || f.hot.name === "none", "the waiting pulse is gone", `the waiting pulse still runs (${f.hot.name})`);

  // A call still has to say it happened — by lighting the whole wire and fading, not by travelling.
  await page.waitForTimeout(600);
  const spark = await page.evaluate(() => {
    const s = document.querySelector(".board-wires .trace-spark");
    s.classList.add("run", "ok");
    const cs = getComputedStyle(s);
    return { name: cs.animationName, dash: cs.strokeDasharray, off: cs.strokeDashoffset };
  });
  r.say(`\n  a call under reduce: animation ${spark.name}  dasharray ${spark.dash}  dashoffset ${spark.off}`);
  r.check(spark.name === "flash", "a call flashes the wire instead of sending a dot", `a call still runs "${spark.name}"`);

  await close();
  r.done(errors, "reduced motion is a different design, and every rule in it reaches something");
}
