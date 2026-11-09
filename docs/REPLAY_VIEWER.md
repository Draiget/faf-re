# Replay viewer

How the timeline bar moves through a replay, and why a click sometimes loads a saved position and sometimes plays through the game. The code is in `src/moho/sim/ReplayTimeline.cpp` and `data/fafengine/modules/lua/ui/game/replay_timeline.lua`.

## The bar

The bar sits at the bottom of the screen and appears when the mouse reaches that edge. `Ctrl-T` keeps it shown. Click or drag to choose a time. A move keeps the session, the camera and the UI.

Thin lines on the bar are keyframes: full saves of the game state, every 30 seconds of game time by default. A click within 3 pixels of a line goes to that keyframe.

While a move is under way, a strip above the bar shows the target. `Esc` or Cancel stops a fast forward where it is. A load can't be stopped, and `Esc` waits for it.

## Jump or fast forward

Hovering or dragging shows what a click at that time would do, next to the time:

| Label | Colour | What the click does |
|---|---|---|
| **Jump** | blue | Loads a keyframe at or before the target into a new sim, holds the picture, plays any ticks left to the target, then shows the result |
| **Fast forward** | amber | Plays every tick from where the replay is now to the target, as fast as the sim can |
| none | | Nothing to decide: the time is the current one, or a load is under way and the replay's position isn't known until it ends |

The label and the click use the same function, so they agree, unless the numbers below change between the hover and the click.

### The rule

- **Going back always jumps.** A sim can't run backward. With no keyframe before the target, the new sim starts from the replay's beginning.
- **Going forward jumps only when that saves time:**

  `ticks skipped > load time × ticks per second`

  Ticks skipped runs from the current tick to the newest keyframe at or before the target. With no keyframe there yet, the click fast forwards.

Both numbers are measured on the machine running the game. They start at 5 seconds and 100 ticks per second. The load time updates after every load. The speed updates after any run of at least 50 ticks, whether it followed a load or was a fast forward.

### Why two keyframes ahead can fast forward

Every keyframe is a full save and could be loaded. A short forward move just doesn't gain anything from it, because loading replaces the whole sim. One run early in a game:

| Move | Ticks | Took | Done by |
|---|---|---|---|
| 156 to 921 | 765 | 3.9 s | Jump, with the limit at about 310 ticks (3.3 s × 94 ticks per second) |
| 1248 to 1521 | 273 | 1.2 s | Fast forward, measuring about 228 ticks per second |
| 1552 to 2121 | 569 | 3.2 s | Fast forward, with the limit now at about 750 ticks (3.3 s × 228) |

The last move crosses two keyframes (600 ticks apart at most), and a load would have taken about as long. A game gets slower to simulate as it grows, so the limit should drop and the same distance should start to jump.

The limit also moves with each measurement: a slow run after a load lowers it, and a quick fast forward raises it. That is why the same distance can jump at one time and fast forward at another.

## Where keyframes come from

A hidden copy of the game's exe (no window, below normal priority) writes a replay's keyframes ahead of the viewer, so a first move forward can load one. They are compressed with zstd and kept in `replay_keyframes\<process id>` next to the exe (in the temporary folder's `faf_replay_keyframes` when the exe's folder can't be written), and removed when the replay ends or the next one starts. A keyframe only loads in the exe that wrote it.

While the hidden process hasn't reached a time yet, there is no keyframe to load there, and a forward click plays through. New lines appear on the bar as keyframes get written.

## Options

Under Options > Gameplay:

| Option | What it changes |
|---|---|
| Replay keyframe spacing | Game time between keyframes. Closer ones make moves shorter and use more disk. The hidden process takes a new value from the next replay |
| Replay keyframe cache | Disk space one replay's keyframes may use. Past it, older ones are thinned out and moving far back takes longer |
| Replay background preparation | Turns the hidden process off. Forward moves then only load keyframes the viewer already saved as it played past them |

The matching console variables are in [SWITCHES.md](SWITCHES.md): `replay_KeyframeEvery`, `replay_KeyframeMaxMB`, `replay_PrepareKeyframes`, `replay_KeyframeQuietDisk`. Saved options win over `/con` for the first three.

## Reading the log

The game's log says what each move did, on lines starting `Replay timeline:`:

| Line | Means |
|---|---|
| `restoring the keyframe of beat N` | A jump started, from this keyframe |
| `a keyframe loads in S s, and ticks play at T a second` | A jump ended, and these are the numbers the rule uses next. A later fast forward can change T without a new line |
| `from tick A to B in S s` | A move arrived. With no `restoring` line since the previous arrival, it was a fast forward |

## Replays stay exact

The viewer only ever plays recorded beats, from a state that headless tests prove identical to playing the replay from the start, so a move can't change what happens in the game. [RETAIL_REPLAY_PARITY.md](RETAIL_REPLAY_PARITY.md) explains how parity is measured.
