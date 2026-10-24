## What changed

<!-- What the PR does and why. Link the issue or replay that shows the problem, if there is one. -->

## Sim impact

<!-- The most important part of the review. Tick exactly one. A replay plays back bit for bit like retail only if the sim does exactly what the original ForgedAlliance.exe did, so anything that can change sim state is checked against replays (docs/RETAIL_REPLAY_PARITY.md). If you are not sure, tick the last box and say why. -->

- [ ] **None.** UI, rendering, audio, movies, tooling, docs or build only; nothing the sim reads or writes.
- [ ] **Replay or network only.** Replay reading/writing, playback controls, lobby, connections; the sim gets the same commands on the same beats.
- [ ] **Sim code touched, behaviour should stay identical.** Refactor, recovered function, crash fix, or a performance change behind a switch.
- [ ] **Sim behaviour changes on purpose.** Gameplay fix, ported FA-Binary-Patches change, new Lua sim function. Say below how it is gated.
- [ ] **Not sure.**

<!-- Code under src/moho/sim, unit, ai, entity, command, collision, path, projectile, vision, script, math, src/lua and src/legacy/math runs in the sim, and so do fixes to shared containers it uses. A CI check fails the PR if it ticks "None" and changes files there; tick "Not sure" if you think the change is still safe. -->

**If the sim behaviour changes:** <!-- Game version it is gated on (sim_FafGameVersion), or the switch that turns it off, and what retail replays do with it. A change that is always on breaks every retail replay and every multiplayer game against a retail client. -->

**If it is a performance change:** <!-- Switch name (console variable and startup flag), its row in docs/SWITCHES.md, and confirmation that both settings give the same checksums. -->

## Build

- Arch: <!-- x64 / x86 / both -->
- Compiler and config: <!-- e.g. clang-cl Release via build.ps1 -->

## Testing

<!-- Required for "Replay or network only", "Sim code touched" and "Sim behaviour changes"; a CI check fails the PR without at least one row. Play the core set from docs/PR_REPLAY_CHECK.md (the extended set too for pathfinding, formations, x87 math, AI-facing engine functions or sim threading) and list every replay you played, including the ones that failed. -->

| Replay ID | Arch | `sim_Workers` | Renderer | Result |
|---|---|---|---|---|
| | | | | <!-- all checksums match / first mismatch at beat N / crash --> |

- [ ] Played in a live lobby (which clients: ours, retail, both)
- [ ] Checked in game by hand (what you looked at)

## Notes for the reviewer

<!-- Anything you could not test, known side effects, follow-ups. -->
