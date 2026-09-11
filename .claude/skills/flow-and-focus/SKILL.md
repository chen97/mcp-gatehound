---
name: flow-and-focus
description: Interaction rules for desktop app UIs — where the reader lands after a click, what a control is allowed to do, and how a multi-step flow finishes the job it started. Use when building or reviewing forms, wizards, expandable lists, modals, tabs, or any screen where clicking something makes something else appear. Covers reveal-scroll-focus, choosing before filling, and the failure modes that make a screen feel confusing rather than broken.
---

# Flow and focus

Most "the UX is confusing" reports are not about looks. They are about one of three things: the
reader does not know where the thing they asked for went, a control did something other than
what its shape promised, or a flow stopped before the job was done.

## 1. Anything a click reveals, the click must also deliver you to

**Revealing a component and leaving the reader to find it is a bug**, whether what appeared is a
folded row, a form, or a panel further down the page.

Make it one rule rather than a line in every handler. A declarative attribute on the control,
read by a single listener, applied after the repaint:

```html
<button data-reveals="#pack-panel">Import a pack…</button>
```

```js
// Capture phase: the button's own handler repaints synchronously, so a listener running
// after it would be asking for a paint that has already happened.
document.addEventListener("click", (e) => {
  const b = e.target?.closest("[data-reveals]");
  if (b) pendingReveal = b.dataset.reveals;
}, true);
```

Act on it **after** the paint, not in the handler: the element you clicked was thrown away and
rebuilt, so scrolling to it would scroll something already detached. A selector that matches
nothing after the paint costs nothing — it clears itself and the screen does not move, which is
what makes it safe to set from a control that might not reveal anything after all.

### Where to scroll to

- **Scroll the thing named, not its card.** For something revealed three-quarters of the way
  down a long form, scrolling the card lands you at the top of the form with what appeared still
  off screen. The exception is a row header: the body it just opened is underneath it, so the
  card is the unit there.
- **`block: "nearest"` when it fits.** Already on screen means do not move; half off means rise
  by exactly the half that was missing. Centring everything you touch turns a page you are
  reading into one that jumps.
- **`block: "start"` when it does not fit.** `nearest` on something taller than the window
  settles on whichever edge is closer, which puts a long form's top above the fold.
- **`scroll-margin-block` on the targets.** The declarative half; `nearest` is the other half,
  and neither works without the other.

### Where to put the keyboard

- A **field** if there is one — inside what was revealed first, then anywhere in its card.
- **Never a button.** The first focusable thing in a card is sometimes "Delete", and arriving on
  it makes Enter dangerous.
- **Never something off screen.** If starting at the top would leave the first field below the
  fold, focus the region instead (`tabIndex = -1`, so it is reachable programmatically without
  joining the tab order). A consent checkbox focused unseen makes Space agree to something the
  reader cannot read.
- **`focus({ preventScroll: true })`, then scroll deliberately.** Focusing scrolls by itself, to
  wherever the browser likes; without this you get two competing moves.

### Only on the way in

Opening scrolls. **Closing scrolls nothing** — you are looking at the row; it stays put.

## 2. A control may only do what its shape promises

A `<select>` changes a value. It does not navigate. A dropdown whose options replace the form
you are filling in is navigation wearing a select's clothes, and the reader loses their work
with no way back.

**When a choice decides which form you fill in, it is a step before the form, not a control
inside it.** Ask first — a modal with the options and what each one means — then open the right
form, and leave a way back to the question.

**And keep the surface.** Answering the question and having the thing that asked it disappear is
the same failure as rule 1, one level up: you acted, and now you have to go and find what your
answer did. The panel that asked should become the form — and become the next form after that.
Mechanically this means the dialog owns a body it can re-render, not a fixed one:

```js
// `render` returns the body for the current state; `wire` re-attaches after every render and is
// handed a `redraw`, so a control that changes the form's shape — listing what a server offers,
// adding a row — asks for a new body instead of closing anything.
stepModal({ title, render: () => formFor(draft), wire: (redraw, done) => wireForm(redraw, done) })
```

Two things make this work rather than merely render: put the redraw through the same diffing
write the screens use, so an unchanged body is left alone and half-typed input survives; and read
the fields back into your draft *before* redrawing, or the redraw is what loses them.

The same principle in its other common form: **a row that opens must be reachable by keyboard.**
If it is a `div` because it carries pills and a status dot (legitimate — those do not belong
inside a `button`), then it owes `role="button"`, `tabindex="0"`, `aria-expanded`, and an
Enter/Space handler. A role is a promise; the handler is keeping it.

## 3. A flow ends when the job is done, not when a step succeeds

The worst version of this is quiet: the flow reports success and leaves the reader with
something that does not work yet.

> "Add a downstream → a script you write" saved a file to disk and returned to the list. Nothing
> could call it. The step that made it callable lived in a different card, discoverable only by
> expanding the script — so the flow ended, successfully, having not done what it was for.

If a job needs two steps, **say so and walk both**: "Step 1 of 2", carry the values across, and
if the reader cancels the second, tell them what they have and where to finish it.

## 4. Arriving from elsewhere

When a click on one screen navigates to a component on another:

- **Arrive collapsed.** You clicked a node to find out where it lives, not to read everything
  inside it. Opening it is the next thing the reader chooses.
- **Mark the arrival** briefly, so the eye lands on the right row.
- **Set the intent before navigating**, not after. Changing it from inside the render that was
  meant to show it means asking for another render from within one — the refresh guard queues
  it, and the mark lands on an element the queued repaint throws away.

## 5. Repainting without losing the reader

If the screen re-reads on a timer or on events, rewriting the DOM each time throws away scroll
position, focus, text selection, and anything expanded.

- **Diff before you write.** Compare against the string you intended to write, not
  `el.innerHTML` — that comes back re-serialised, so the comparison never matches and every
  repaint happens anyway.
- **Re-attach handlers only when the elements are new.** Otherwise you stack a second listener
  on every surviving button.
- **Hold "what is expanded" outside the DOM**, so it survives the repaint.
- **Do not repaint over half-typed input.** A text field is being edited; a checkbox is not — a
  tick is a finished decision, and treating it as "still being edited" leaves consent boxes
  tickable but inert, which is the worst possible shape for a security gate.

## Native equivalents

Rules 2, 3 and 4 are about what you ask and when, and carry over unchanged. Rule 1 carries as
intent — `scrollRectToVisible` / `UIAccessibility.post(notification: .layoutChanged)` and moving
first responder — with the same two constraints: never move first responder to something
off screen, and never to a destructive control. Rule 5 is a webview problem; a native view tree
keeps its own state and does not need it.
