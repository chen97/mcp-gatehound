// Does the window's title read as a title?
//
// `h1` was the last literal font size in the stylesheet, and the one change in the design-system
// migration a person would actually see. The argument for moving it was that at 14px it sat a
// pixel from a card's `h3`, so the window had no size that read as a title. That claim is a
// measurement, not an opinion, and this is the measurement — it reads the *rendered* size of
// every heading the window can show, including the one inside a modal, which only exists once a
// modal has actually been opened.
//
// `--h1=15px` overrides the stylesheet's value at run time so candidate sizes can be compared
// against the same board without editing the file three times. With no flag it measures what the
// stylesheet says today, which is the check worth keeping.
//
//   node title-size.mjs
//   node title-size.mjs --h1=17px
import { openBoard, reporter, FIXTURE } from "./board-harness.mjs";

const override = process.argv.find((a) => a.startsWith("--h1="))?.slice(5) ?? null;

/// One pending request, so the approval card exists. It carries the largest `h3` in the window
/// (`--t-lg`, where an ordinary card's is `--t-md`), which makes it the real thing `h1` is
/// competing with — comparing against an ordinary card's `h3` flatters the title by 2.5px.
const PENDING = [
  { id: "p1", ts: new Date().toISOString(), identity: "claude", tool: "echo",
    args_preview: '{"text":"hello"}' },
];

const r = reporter();
const { page, errors, close } = await openBoard({ fixture: { pending: PENDING } });

if (override) await page.addStyleTag({ content: `h1 { font-size: ${override} !important; }` });

r.say(`Rendered heading sizes${override ? `  (h1 forced to ${override})` : ""}`);

/// Every heading the window can show, with what it is *for* — the ladder is only wrong if two
/// rungs that mean different things measure the same.
const sizeOf = (sel) =>
  page.$eval(sel, (el) => parseFloat(getComputedStyle(el).fontSize)).catch(() => null);

const h1 = await sizeOf("h1");
const approval = await sizeOf(".card.approval h3");
const card = await sizeOf(".card:not(.approval) h3");

// The modal heading is the one that cannot be read off a static page: nothing renders a `.modal`
// until something opens one, so this walks to Downstream and opens the add flow the way a person
// would. "Add a downstream…" is used because it is the one modal trigger on a board this fixture
// draws that is visible without first expanding a disclosure.
await page.click('[data-screen="actions"]');
await page.waitForSelector("#actions button.primary", { state: "visible" });
await page.click("#actions button.primary");
await page.waitForSelector(".modal h3", { state: "visible" });
const modal = await sizeOf(".modal h3");

const rows = [
  ["h1               window title", h1],
  [".modal h3        dialog heading", modal],
  [".card.approval h3  approval heading", approval],
  [".card h3         card heading", card],
];
for (const [label, px] of rows) r.say(`  ${label.padEnd(38)} ${px === null ? "absent" : `${px}px`}`);

const others = [modal, approval, card].filter((v) => v !== null);
const biggestOther = Math.max(...others);

r.say("");
r.check(
  h1 > biggestOther,
  `the title is the largest heading in the window — ${h1}px against ${biggestOther}px`,
  `the title is not the largest heading — h1 ${h1}px, largest other heading ${biggestOther}px`,
);
r.check(
  h1 - biggestOther >= 2,
  `and it is clear of the next heading by ${h1 - biggestOther}px`,
  `and it is only ${h1 - biggestOther}px from the next heading, which does not read as a step`,
);

// Named separately because it is the specific collision the size decision turned on: a dialog
// heading and a window title are different things and should not measure the same.
r.check(
  modal === null || h1 !== modal,
  "the title and a dialog heading are different sizes",
  `the title and a dialog heading are both ${h1}px — the same size for two different things`,
);

// The other half of the argument, and the half that is easy to assume rather than measure: that a
// larger title costs vertical room in a window that has little to spare. It does not. The header
// is a flex row whose height is set by the tallest thing in it — the `Pause gateway` button at
// `--ctl-h` — so the title grows inside a row that was already that tall. Asserted by shrinking
// the title to a size nothing would ship and checking the chrome does not move.
const chrome = () => page.$eval(".top", (el) => el.getBoundingClientRect().height);
const chromeNow = await chrome();
await page.addStyleTag({ content: "h1 { font-size: 10px !important; }" });
const chromeTiny = await chrome();
r.say("");
r.check(
  chromeNow === chromeTiny,
  `the title costs the board no vertical room — chrome is ${chromeNow}px whether the title is ` +
    `${h1}px or 10px, because the row is as tall as its button either way`,
  `the title drives the chrome's height: ${chromeNow}px at ${h1}px, ${chromeTiny}px at 10px — ` +
    `a larger title costs ${chromeNow - chromeTiny}px of board`,
);

await close();
r.done(errors, "the window has a size that reads as a title");
