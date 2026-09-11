---
name: motion-and-idle-cost
description: What may move in a desktop app UI, how it moves, and what must stop when nobody is looking. Use when adding or reviewing animation, transitions, ambient motion, loading states, or a menubar/tray app's background behaviour — and whenever asked why an app is warm, draining battery, or spinning a fan while idle. Covers duration and easing, which properties are free and which cost a frame, rationing motion by how often it is seen, and the idle-cost audit.
---

# Motion and idle cost

Two questions, and they are the same question. Motion that earns its place is motion somebody is
watching; motion nobody is watching is a cost with no benefit.

## Part 1 — what may move

### Ration motion by how often it is seen

The more often a thing happens, the less it may move.

| Seen | Budget |
|---|---|
| Dozens of times a day (tab switch, row open) | 160–200ms, or nothing |
| Once per real change (a panel arriving) | 250–320ms, may be the thing that catches the eye |
| Permanently on screen | faint or still — and see Part 2 |
| A real event (a call, a failure) | outranks all of the above |

### Duration and easing

- **Entrances 250ms; things you do constantly 160–200ms.** Nothing over ~400ms.
- **Use a real easing curve.** The built-in CSS easings are too weak to read as intentional.
  `cubic-bezier(0.23, 1, 0.32, 1)` for entrances; a symmetric curve for something moving between
  two places it already occupies.
- **Transitions, not keyframes, for anything interruptible.** Transitions retarget: a dialog
  raised while another is still leaving turns around from wherever it got to. Keyframes restart
  from zero. This is also what lets the queue between two dialogs be 60ms instead of 200.
- **Remove on `transitionend`, not on a guessed timeout.** Otherwise changing a duration later
  leaves a panel yanked out mid-flight or a dead backdrop over the page.
- **Never scale from zero.** A panel arrives from `scale(0.96)`, not `scale(0)`.
- **Animate a backdrop and its panel on the same duration**, or they read as two things moving
  rather than one surface arriving.

### Motion that indicates something must be driven by that something

An idle loop looks identical whether or not anything is happening, which makes it an indicator
that indicates nothing. Fire on the real event — a logged request, a state change — and let an
idle app be a still picture. That stillness is information.

### Reduced motion is a different design, not a disabled one

`prefers-reduced-motion` should keep the fade and drop the movement, not remove the feedback. A
dash travelling a wire becomes a flash in place; the wire still says what happened.

## Part 2 — what it costs

### Some properties are free and some cost a frame

The compositor can animate `transform` and `opacity` without the main thread. **Everything else
costs a style recalculation and a repaint every frame**, and in an SVG that means repainting the
whole drawing.

Measured on one real diagram, same page, same run:

| | Cost |
|---|---|
| Marching dots along traces (`stroke-dashoffset`, infinite) | **4.4% of a core** at 16 paths, **5.9%** at 44 |
| A pulsing halo (`transform` + `opacity`, infinite) | **0.0%** |
| The same board with no motion | 0.1% |

Same visual weight, same "always on", a hundredfold difference in cost. Before animating a
property that is not `transform` or `opacity`, check whether the effect can be expressed as one
that is — and if it cannot, accept that it is a per-frame cost and apply Part 3.

### Numbers, not adjectives

`Performance.getMetrics` over a sampling window: `TaskDuration` ÷ wall clock is your percentage
of a core, and a non-zero `RecalcStyleDuration` says the main thread is doing per-frame style
work. Turn candidates off one at a time in the same run rather than guessing which one is the
cost — the 0.0% result above is the useful half of that experiment.

## Part 3 — the idle-cost audit

For a menubar or tray app, **closing the window hides it; the app keeps running.** Hidden is
where the window spends most of its life. Audit it as its own state.

Three questions:

1. **What runs on a timer?** A "safety net" re-read is a net nobody is standing under when the
   window is hidden. Gate it, and refresh immediately on the way back so nothing returns stale.
   Events should still arrive and still redraw while hidden — that is what makes the poll
   *only* the net, and safe to pause.
2. **What moves?** Every infinite animation, paused.
3. **What touches the disk or the network per tick?** A screen that hashes every file on disk to
   notice "changed on disk" is right to do that on arrival and after a change, and wrong to do
   it twelve times a minute for a screen sitting still. Read on the events that matter, plus a
   slow floor.

### Know when you are hidden — do not infer it

Whether a hidden webview reports `visibilitychange` is a per-platform accident. **The shell
knows**: it is the thing that called `hide()`. Emit from there, let the page's own
`visibilitychange` override it when the browser does notice (more current news), and prefer the
explicit signal to a guess.

```js
function watched() { return shellSaysWatched ?? document.visibilityState !== "hidden"; }
```

```css
body.unwatched .drift,
body.unwatched .halo { animation-play-state: paused; }
```

Result on the app this came from: 10 IPC round-trips and 4.0% of a core per 12 seconds while
hidden, down to **0 and 0.0%**.

## What else to check while you are there

Cheap, and it is the same sitting:

- **Retention**: `WeakRef` the elements you replace, force GC, count survivors. One or two is
  healthy; all of them is a leak.
- **Listener stacking**: one delegated listener on `document` beats one per paint. Count them.
- **Background probes**: a health check on a loop must have a *probe* timeout, not the call
  timeout it inherits. A 60-second call timeout on a 30-second loop means one silent upstream
  holds up every upstream behind it and the status reports minutes-old news.
- **Queues without a ceiling**: anything that parks a task waiting for a permit or a rate-limit
  window is an in-memory queue. Know what bounds it.

## Native equivalents

Part 1 carries over whole — the durations, the easing, the ration, reduced motion
(`UIAccessibility.isReduceMotionEnabled` / `NSWorkspace.accessibilityDisplayShouldReduceMotion`).
Part 2's property table is webview-specific, but the principle is not: know which of your
animations are handled off the main thread. Part 3 is the same audit with different hooks —
`applicationDidHide` / `occlusionState`, and `Timer` invalidation instead of a class on `body`.
