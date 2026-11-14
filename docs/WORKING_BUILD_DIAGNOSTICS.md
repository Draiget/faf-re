# Working-build network diagnostics

This diagnostic branch is based on the working x64 upstream `e4cc5d8b` engine,
with the existing Microchip lobby/F11 fixes. It does not adopt newer upstream
simulation code or enable the experimental frame-clock/skew options.

## Collect a test

The engine hook is off by default. Set the top-level Game.prefs preference
`microchip_network_diagnostics = true`, then launch a new multiplayer game.
Leave the Microchip F11 UI mod disabled for the comparison. F11 does not need
to be open. The recorder samples every two seconds and sends no packets.
Two seconds is the target: the UI scheduler can wait longer at low frame rates.
The recorded wall-clock interval is used when calculating tick progress.

Logs go to the normal FAF match log:
`%APPDATA%/Forged Alliance Forever/logs/game_<id>.log`.
Find `MicrochipNetDiag START`, `SAMPLE`, and `PEER` lines. Samples begin once
the session clients are available and stop when the session ends. Replays and
single-player sessions are skipped. To disable collection for subsequent games,
set `microchip_network_diagnostics = false` in Game.prefs while the game is closed.

## What the records mean

- `elapsed` is real time between UI samples. Large gaps show that this UI-side
  recorder wasn't scheduled promptly. They do not by themselves distinguish
  rendering, a UI mod, Windows scheduling, loading, or background CPU load.
- `ticks_per_second` is observed game-tick progress over that real-time window.
  Normal speed targets ten ticks/second. Loading, intentional pauses, and
  intentionally changed game speed must be excluded when interpreting it.
- Every `PEER` lists the reported `maxsp` (simulation capacity), local RTT and
  quiet time, remote dispatched beat, and incoming command-buffer matrix.
  Remote RTTs are not inferred. These fields are read from the existing F11 data.
- Your local row additionally contains the negotiated `actual_rate`, the
  requested rate and the engine's native `bottleneck` label. Negative local
  capacity relative to the requested speed is evidence of a local sim limit.
  `data` means missing command data; `ack` means waiting for acknowledgements;
  `readiness` is startup readiness. `nothing` is no bottleneck of those kinds
  at that particular instant, not proof that the whole match is healthy.
- Native bottleneck member numbers use zero-based `engine_index`. The buffer
  table uses the one-based `id`. Both are included to avoid mixing the indexes.

The recorder copies data without altering the source snapshot. Its buffers,
rows and text fields are bounded, but reading and writing diagnostics still
has a small cost. A successful synthetic test is not a live performance
measurement. The trace can narrow the cause; a controlled classic/x64 comparison
and other players' observations remain necessary for attribution.

The engine update adds only read-only fields to `GetSessionClients`; it does
not change the command stream, peer protocol, simulation calculations, CPU
allocation, renderer or game-clock behavior. The UI hook fails closed if it
cannot collect a sample. Existing files and Game.prefs should be backed up
before deployment. Match logs remain local and may include player nicknames.
