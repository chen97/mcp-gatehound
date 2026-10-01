// Does the coloured text in this app actually clear its floor, in both schemes?
//
// `accessibility.md` quotes a table of token-against-surface ratios. Those are arithmetic on the
// token block and they hold by construction once the block is adopted verbatim. This asks the
// question the table cannot: whether the *rendered* pairs on real elements clear the floor —
// which is a different question, because a pill's background is a `color-mix` at 10% over
// whatever card it happens to sit on, and no table can know what that composited to.
//
// Floors, from `accessibility.md`: 4.5:1 for text at every size — the large-text relaxation is
// declined deliberately — and 3:1 for non-text that carries meaning. Disabled text is formally
// exempt from 1.4.3; this repo holds it to 3:1 anyway.
//
//   node contrast.mjs
import { openBoard, reporter } from "./board-harness.mjs";

const r = reporter();

/// Every probe is a real element on a real screen, named by what a reader would call it.
///
/// `floor` is 4.5 unless the thing is not text. Where an element does not exist on the board the
/// probe reports it as missing rather than passing — a selector that matches nothing is the
/// failure mode this whole file exists to catch.
const PROBES = [
  { what: "body text", sel: ".card p, .card", text: true },
  { what: "meta / hint", sel: ".meta", text: true },
  { what: "window title", sel: "h1", text: true },
  { what: "card heading", sel: ".card h3", text: true },
  { what: "table header", sel: "th", text: true },
  { what: "pill — ok", sel: ".pill.ok", text: true },
  { what: "pill — bad", sel: ".pill.bad", text: true },
  { what: "pill — waiting", sel: ".pill.waiting", text: true },
  { what: "pill — hot (filled amber)", sel: ".pill.hot", text: true },
  // `:not(nav button)` on every one of these. Without it the plain-button and ghost probes both
  // matched the first `button` in the document, which is a tab in the nav — `querySelector` is
  // DOM order, and the nav is above the content. Both reported 6.27:1, the same number as the
  // "nav, inactive" row two lines down, and neither had measured a content button at all.
  { what: "primary button", sel: "button.primary:not(nav button)", text: true },
  { what: "default button", sel: "button:not(.primary):not(.ghost):not(.danger):not(nav button)", text: true },
  { what: "ghost button", sel: "button.ghost:not(nav button)", text: true },
  { what: "danger button", sel: "button.danger:not(nav button)", text: true },
  { what: "input text", sel: "input", text: true },
  { what: "nav, inactive", sel: "nav button:not(.active)", text: true },
  { what: "nav, active", sel: "nav button.active", text: true },
  { what: "code", sel: "code", text: true },
];

/// Pseudo-elements and states that no selector reaches, driven into place first.
/// Disabled text is formally exempt from WCAG 1.4.3. This repo holds it to 3:1 anyway, on the
/// grounds that "is this greyed out or is my eye going" is not a question a UI should raise —
/// and both button kinds are checked, because they reach their grey by different routes.
const SPECIALS = [
  { what: "input placeholder", sel: "input", pseudo: "::placeholder", text: true },
  { what: "disabled primary button", sel: "button.primary:not(nav button)", disable: true, text: true, floor: 3 },
  { what: "disabled default button", sel: "button:not(.primary):not(.ghost):not(.danger):not(nav button)",
    disable: true, text: true, floor: 3 },
  // The ghost and danger variants reach their ink by a different route to the plain button —
  // `--mut` and `--bad-tx`, both already quietened — so `opacity: 0.5` quietens them a second
  // time. That is the trap the primary fell into, and it is only caught here by measuring each
  // variant rather than assuming the shared rule covers them.
  { what: "disabled ghost button", sel: "button.ghost:not(nav button)", disable: true, text: true, floor: 3 },
  { what: "disabled danger button", sel: "button.danger:not(nav button)", disable: true, text: true, floor: 3 },
];

const L = ([r8, g8, b8]) => {
  const f = (c) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * f(r8) + 0.7152 * f(g8) + 0.0722 * f(b8);
};
const ratio = (a, b) => {
  const [x, y] = [L(a), L(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

/// Read colour and *composited* background for one element, in the page.
///
/// The background is the crux. A pill's own background is `color-mix(… 10%, transparent)`, so
/// taking it at face value would compare the text against something 90% see-through. Walking up
/// and compositing each translucent layer onto the one behind it is what the eye actually does.
const read = (page, sel, pseudo, disable) =>
  page.evaluate(([sel, pseudo, disable]) => {
    const el = document.querySelector(sel);
    if (!el) return null;
    // `button` transitions `opacity`, and `:disabled` is what changes it. Setting the property and
    // reading the computed style in the same block races that transition: the read can land at
    // t=0 and report opacity 1, which is how the disabled ghost button measured 15.29:1 — the
    // undimmed ink, a number it never renders. It read as comfortably passing, and a false pass on
    // an accessibility floor is worse than a false fail. Suppressing the transition for the
    // measurement makes the disabled state land instantly and the number repeatable.
    const savedTransition = el.style.transition;
    if (disable) {
      el.style.transition = "none";
      el.disabled = true;
      void el.offsetWidth; // force the style recalc before anything is read back
    }

    // Chromium does not serialize every colour as `rgb()`. A `color-mix(… , transparent)` comes
    // back as `color(srgb 0.12 0.57 0.33 / 0.1)` — channels 0–1, not 0–255. Reading those floats
    // as bytes makes every translucent tint collapse to near-black at 10% alpha, which composites
    // to a neutral grey: 0.9 x 255 = 229.5 in all three channels, or #e6e6e6, whatever the colour
    // actually was. That is not a rounding error, it is a different background, and it was quietly
    // failing the pills against a grey they never render on.
    const parse = (s) => {
      const m = (s || "").match(/[\d.]+/g);
      if (!m) return null;
      const k = /^color\(/.test(s || "") ? 255 : 1;
      return [+m[0] * k, +m[1] * k, +m[2] * k, m[3] === undefined ? 1 : +m[3]];
    };
    const over = (fg, bg) => fg.slice(0, 3).map((c, i) => c * fg[3] + bg[i] * (1 - fg[3]));

    const cs = getComputedStyle(el, pseudo || undefined);
    const colour = parse(cs.color);
    const opacity = parseFloat(getComputedStyle(el).opacity);

    // Composite every background from the root forward, so each translucent layer lands on what
    // is genuinely behind it rather than on white.
    const chain = [];
    for (let n = el; n; n = n.parentElement) chain.unshift(n);
    let bg = [255, 255, 255];
    for (const n of chain) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c[3] > 0) bg = over(c, bg);
    }
    // The element's own opacity fades its text toward its backdrop — which is how a disabled
    // control gets quieter, and it has to be in the number or the number is not what is on screen.
    const fg = opacity < 1 ? over([...colour.slice(0, 3), colour[3] * opacity], bg) : over(colour, bg);

    if (disable) { el.disabled = false; el.style.transition = savedTransition; }
    return { fg: fg.map(Math.round), bg: bg.map(Math.round) };
  }, [sel, pseudo ?? null, !!disable]);

const hex = (c) => "#" + c.map((x) => x.toString(16).padStart(2, "0")).join("");

/// Enough rows that every coloured thing this file asks about actually renders.
///
/// One request per pill meaning — `allow` is green, `ask→denied` red, `ask` amber — plus a held
/// call, which is what puts the approval card on screen with its primary, ghost and danger
/// buttons. Without these the probe skips two thirds of its cases and reports a clean run.
const POPULATED = {
  requests: [
    { id: 1, ts: new Date(Date.now() - 4000).toISOString(), identity: "paperclip", client_name: "paperclip",
      method: "tools/call", tool: "echo", args_json: '{"text":"hi"}', decision: "allow", action_type: "proxy",
      upstream: "notes", status: "ok", error: null, duration_ms: 12, response_json: '{"ok":true}', token_id: "t1" },
    { id: 2, ts: new Date(Date.now() - 9000).toISOString(), identity: "claude", client_name: "claude",
      method: "tools/call", tool: "fetch", args_json: '{"url":"https://example.com"}', decision: "ask→denied",
      action_type: "proxy", upstream: "web", status: "error", error: "refused by the operator",
      duration_ms: 4100, response_json: null, token_id: "t2" },
    { id: 3, ts: new Date(Date.now() - 14000).toISOString(), identity: "claude", client_name: "claude",
      method: "tools/call", tool: "search", args_json: "{}", decision: "ask", action_type: "proxy",
      upstream: "notes", status: "pending", error: null, duration_ms: null, response_json: null, token_id: "t2" },
  ],
  pending: [
    { id: "p1", ts: new Date().toISOString(), identity: "claude", tool: "echo", args_preview: '{"text":"hi"}' },
  ],
};

for (const scheme of ["dark", "light"]) {
  const { page, errors, close } = await openBoard({ colorScheme: scheme, fixture: POPULATED });
  // The board alone has no pills and no table. The log screen carries both; visiting it is what
  // makes those probes real rather than skipped.
  await page.click('nav button:has-text("Log")').catch(() => {});
  await page.waitForTimeout(500);

  r.say(`\n${scheme}`);
  let worst = { ratio: Infinity };

  const run = async (probes) => {
    for (const p of probes) {
      const got = await read(page, p.sel, p.pseudo, p.disable);
      // A probe whose element is absent is a failure, not a skip. A selector that matches nothing
      // reports a clean run, which is the exact shape of the bug this file is here to catch.
      if (!got) { r.fail(`${scheme}: no element matched "${p.sel}" for ${p.what} — nothing was measured`); continue; }
      const cr = ratio(got.fg, got.bg);
      const floor = p.floor ?? (p.text ? 4.5 : 3);
      r.say(`  ${cr >= floor ? " " : "✗"} ${p.what.padEnd(30)} ${cr.toFixed(2).padStart(5)}:1  ` +
            `(floor ${floor})  ${hex(got.fg)} on ${hex(got.bg)}`);
      if (cr < floor) r.fail(`${scheme}: ${p.what} measures ${cr.toFixed(2)}:1, below its ${floor}:1 floor`);
      if (cr < worst.ratio) worst = { ratio: cr, what: p.what };
    }
  };

  await run([...PROBES, ...SPECIALS]);

  // The empty state only exists when nothing matches, so it is driven into place rather than
  // waited for. Filtering to nothing also puts its primary "Clear filters" button on screen.
  await page.fill("#logq", "nothing-matches-this");
  await page.waitForTimeout(300);
  await run([
    { what: "empty-state heading", sel: ".empty h4", text: true },
    { what: "empty-state body", sel: ".empty p", text: true },
    { what: "empty-state action", sel: ".empty button.primary", text: true },
  ]);

  r.say(`  worst on screen: ${worst.what} at ${worst.ratio.toFixed(2)}:1`);
  if (errors.length) errors.forEach((e) => r.fail(`page error: ${e}`));
  await close();
}

r.done([], "every coloured pair on screen clears its floor, in both schemes");
