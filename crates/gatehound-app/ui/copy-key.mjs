// What does the super token's Copy button actually put on the clipboard?
//
// It has to be the token and nothing else — not the dots the card shows, not a shortened form,
// no prefix, no newline — because a client pastes it straight into its own config and a
// near-miss authenticates as nobody. It once wrote nothing at all (CHE-349): the clipboard kept
// whatever was on it before, the button still said "Copied", and the first anyone knew was a
// client that never got in. So this clicks the real button and reads what landed.
//
//   node copy-key.mjs
import { openBoard, reporter } from "./board-harness.mjs";

// A stand-in the same shape as a real one: 64 hex characters.
const TOKEN = "0123456789abcdef".repeat(4);

const r = reporter();
const { page, errors, close } = await openBoard({
  port: 5206,
  settle: false,
  fixture: { access: { super_token: TOKEN, owner: "you", endpoint: "http://127.0.0.1:8790/mcp", tokens: [] } },
});

// Whatever was on the clipboard before, so "left it alone" cannot pass for "copied".
await page.evaluate(() => {
  window.__clipboard = "stale text";
  navigator.clipboard.writeText = async (t) => { window.__clipboard = t; };
});

await page.click('nav button[data-screen="upstream"]');
await page.waitForSelector("#copy-super");
await page.click("#copy-super");
await page.waitForFunction(() => window.__clipboard !== "stale text", null, { timeout: 2000 }).catch(() => {});
const got = await page.evaluate(() => window.__clipboard);

r.say("the super token's Copy button");
r.check(got !== "stale text", "writes to the clipboard", "leaves the clipboard as it was");
r.check(got === TOKEN, "writes the token exactly", `writes ${got.length} characters that are not the token`);
r.check(got.length === 64 && !/\s/.test(got), "64 characters, no whitespace", `${got.length} characters`);

await close();
r.done(errors, "Copy hands over the super token, whole");
