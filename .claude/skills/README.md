# Skills

Three skills written out of what actually worked while building this app's window. They are
plain files — copy the folders into `~/.claude/skills/` (available everywhere) or into
`<project>/.claude/skills/` (that project only), and they load on the next session.

```
cp -r .claude/skills/{verify-by-driving,flow-and-focus,motion-and-idle-cost} ~/.claude/skills/
```

| Skill | Answers |
|---|---|
| `verify-by-driving` | How do I know this works? Drive the app and read numbers back; here is the harness and what to assert. |
| `flow-and-focus` | Where does the reader land after a click, what is a control allowed to do, and when is a flow finished? |
| `motion-and-idle-cost` | What may move, how, what it costs per frame, and what must stop when nobody is looking. |

Each one marks which of its rules are webview-specific and which carry over to a native UI, so
they are usable on an AppKit or SwiftUI app with the mechanics swapped and the reasoning intact.

## Where they came from

They are not a summary of general advice. Every rule in them is one that was earned here —
usually by getting it wrong first, measuring, and finding out why. The tables of "what the code
looked like" versus "what the measurement said" are real cases from this repository's history,
and the cost figures are real readings from its own diagram.

## Related third-party skills

These are separate and publicly available; install them alongside rather than expecting the
three above to cover them.

- **[cathrynlavery/diagram-design](https://github.com/cathrynlavery/diagram-design)** — the
  editorial diagram system used for [`docs/tech-stack.html`](../../docs/tech-stack.html):
  39 visual types, a skinnable token set, and six non-negotiable connector rules.
- **Emil Kowalski's animation recipes** — the source of the entrance/exit contract in
  `motion-and-idle-cost` (transitions over keyframes, one surface, never scale from zero) and of
  the `cubic-bezier(0.23, 1, 0.32, 1)` easing this app uses throughout.
