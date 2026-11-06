# Contributing

Thanks for helping. This engine has one job above all others: play every game exactly like the retail `ForgedAlliance.exe`, so our players can share games and replays with retail players and with each other. Most review comments come back to that, so please read [Sim parity](#sim-parity-the-rule-that-decides-most-reviews) before you start.

## Before you start

- For anything bigger than a small fix, open an issue first (or comment on one) and say what you plan to do. A short plan saves a rewrite.
- Say when you start, so nobody else does the same work: comment "working on this" on the issue, or open a draft PR early. Check open issues and draft PRs before you begin. If you stop, say so, so someone else can take it over.
- One topic per pull request. A bug fix, a refactor and a new switch are three PRs.
- Build and run it yourself: [Build](README.md#build). `.\build.ps1` builds x64 Release; `.\build.ps1 -Arch both` builds x86 too.

## Sim parity: the rule that decides most reviews

Supreme Commander runs in lockstep. Every player's machine runs the whole simulation and only the players' commands travel over the network. If one machine computes anything differently, even one bit, that game desyncs. A replay is the same thing: the recorded commands are played into the sim again, and it must reach the same checksums.

Code under `src/moho/{sim,unit,ai,entity,command,collision,path,projectile,vision,script,math}/`, `src/lua/` and `src/legacy/math/` runs in the sim, and so do fixes to shared containers it uses. For that code:

1. **Same behaviour as retail, unless it is gated.** A refactor, a crash fix or a performance change must leave every checksum identical. A deliberate gameplay change must be off for retail games and replays, gated on `sim_FafGameVersion`, and the PR says how.
2. **A switch never changes what the sim computes.** Every performance switch gives the same checksums whether it is on or off ([docs/SWITCHES.md](docs/SWITCHES.md)). A setting that changes the result is a gameplay change, not a switch: rule 1 applies.
3. **No new sim setting that changes the result.** A sim console variable or sim command (`TSimConVar`, `CSimConFunc`, a `DoSimCommand` alias) goes to every player through the command stream and into the replay. Debug tools that only draw or print are fine, as long as they are registered cheat-only (`allowWithoutCheats = false`). Anything that changes sim state through one needs the maintainer's agreement before you write it.
4. **Nothing local reaches the sim.** Thread count, frame rate, wall-clock time, hardware, file timestamps, UI state and local console variables must not change what the sim computes.
5. **Prove it with replays.** Play the core set from [docs/PR_REPLAY_CHECK.md](docs/PR_REPLAY_CHECK.md) (the extended set too for pathfinding, formations, x87 math, AI-facing engine functions or sim threading) and list every replay in the PR, failures included. How parity is measured: [docs/RETAIL_REPLAY_PARITY.md](docs/RETAIL_REPLAY_PARITY.md).

A PR that ticks "Sim behaviour changes" or "Not sure", or that adds a sim console variable or sim command, gets the **`parity: at risk`** label automatically. It is not merged until the maintainer has signed off on why it cannot desync a game or a replay; they remove the label when it is settled.

UI, rendering, audio and movies are not in the sim and can change freely, but a change to what the original game did should say so (the reviewer adds `retail divergence`).

## Features that need other players on our engine

A feature that only works when other players run our engine asks one shared announcement. Don't add another way to detect our builds, or a new message type: [docs/PEER_FEATURES.md](docs/PEER_FEATURES.md) says how to add it.

## Working on recovered code

Every engine function in `src/` was rebuilt from the original binary, and its behaviour is the reference.

- Keep the `Address: 0x...` comment block above a recovered function, in the header and the `.cpp`. It is how anyone checks the code against the binary.
- When you fix a function to match the binary, cite the instructions you read (`0x008581BB: ...`) in the comment or the PR.
- Recovered layouts stay on the legacy types (`fa::vector`, `fa::string`, `gpg::` containers). The game's builds drop the unused word the binary keeps at the start of each container, so the `static_assert(sizeof(...))` checks and `+0x..` comments describe the binary, and the `clang-x86-retail-layout` preset is what checks them (the `Layout check` workflow compiles it on every change to the engine). Keep them, and build that preset when you change a layout.
- Use named fields and real virtual calls, not pointer arithmetic or offsets (`*(int*)(p + 0x78)`).
- No stub or placeholder functions.

## Writing tests

Use **GoogleTest (GTest)** for all unit and integration tests. Do not roll custom or ad-hoc test harnesses (such as custom `Check` loops, hand-rolled `gFailures` counters, or manual `main()` runners).

- **Standard assertions and fixtures**: Use standard GTest macros (`TEST`, `TEST_F`, `EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_TRUE`, etc.). They provide structured output, accurate failure source locations, and automatic failure propagation.
- **Entry point**: Link against `gtest_main` whenever the test executable does not require special command-line handling. If custom CLI arguments are required (e.g. data file paths or flags), call `::testing::InitGoogleTest(&argc, argv)` and return `RUN_ALL_TESTS()` from `main()`.
- **CMake & CTest integration**:
  - Link test executables against `gtest` or `gtest_main` (`target_link_libraries(<target> PRIVATE ... gtest_main)`).
  - Register the executable with `add_test(NAME <name> COMMAND <target>)`.
  - Set IDE grouping: `set_target_properties(<target> PROPERTIES FOLDER "Tests/<Subgroup>")`.
  - Label tests for CTest selection: `set_tests_properties(<name> PROPERTIES LABELS "<Label>")`.
- **Existing tests group**: All existing test suites converted from custom harnesses belong to the `Existing` group (suite names prefixed with `Existing_`, CTest label `Existing`, CMake folder `Tests/Existing`, and grouped under the `existing_tests` custom build target). New tests should define clear suite names for their module without the `Existing_` prefix.
- **Running tests**:
  ```powershell
  # Run all existing tests via CTest
  ctest --test-dir build/clang-x64-release -L Existing --output-on-failure

  # Run a specific test executable with filter
  .\build\clang-x64-release\tests\faf_net_tests.exe --gtest_filter=Existing_NetRobustness.LuaValidValues
  ```

## Commits and pull request titles

Commit titles and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). PRs are squash-merged and the PR's title becomes the commit title, so a CI check (`Commit titles`) checks that title and leaves the titles of a PR's commits free. A PR with one commit is the exception: the merge uses that commit's title, so it is checked too. Every commit on `master` is checked, and no commit in a PR may carry an AI or bot attribution line, because a squash copies commit messages into the merged one.

```
<type>(<scope>): <what is true after this change>
```

| Type | For |
|---|---|
| `feat` | new behaviour or feature |
| `fix` | bug fix, including code brought back in line with the original binary |
| `perf` | performance change (behind a switch, see rule 2 above) |
| `refactor` | restructuring with no behaviour change |
| `test` | tests, scenarios, replay tooling |
| `docs` | documentation only |
| `build` | CMake, dependencies, build and release scripts |
| `ci` | GitHub workflows and their scripts |
| `chore` | anything else that does not change the engine |
| `revert` | reverts an earlier commit |

Rules the check enforces:

- The type is one of those above, in lowercase.
- `feat`, `fix`, `perf`, `refactor` and `test` need a scope: the area the change touches, in lowercase (`ui`, `sim`, `render`, `d3d12`, `audio`, `lua`, `net`, `replay`, `range-rings`, ...). Several are separated by commas: `perf(d3d12,vulkan)`. The scope is optional for the other types.
- One space after the colon; the title does not end with a full stop; at most 150 characters.
- A `!` after the scope marks a breaking change, e.g. a changed save or replay format: `feat(replay)!: ...`.
- In a commit message, a blank line separates the title from the body.
- No AI or bot `Co-authored-by:` lines and no "Generated with ..." lines. Commits are authored by the people who submit them.
- A `fixup!` or `squash!` title is refused wherever a title is checked. Merge commits and git's own `Revert "..."` titles are accepted as they are.

Write the title as what is now true, not as an instruction, and put the issue number at the end:

```
fix(ui): command feedback blips show when the camera is zoomed out (#25)
perf(sim): recon blips refresh per army on sim workers
feat(lua): GetDepositsAroundPoint in the UI state
docs(switches): sim_Workers takes effect on the next dispatch
```

The body says why, and for a fix to match the binary, which instructions show it. Check your titles before pushing (Node 18 or later):

```powershell
node .github/scripts/commit-lint.js --range origin/master..HEAD
node .github/scripts/commit-lint.js "fix(ui): my title"
```

To check every commit as you make it, call `node .github/scripts/commit-lint.js --file "$1"` from a `commit-msg` hook.

Commits made before this rule use an older `Area: sentence` style; they stay as they are.

## Pull requests

- Fill in the template ([.github/pull_request_template.md](.github/pull_request_template.md)), especially **Sim impact** (tick exactly one box) and **Testing** (the replays you played). The `PR sim impact` check fails without them.
- Most labels are set automatically from the template, the changed files and the diff: `sim: ...`, `area: ...`, `parity: at risk`, `recovery`, `needs template`, `needs replay check`, `merge conflict`. A label a maintainer sets or removes by hand is left alone.
- Say what you could not test. "Not tested on x86" is useful; silence is not.
- Keep the PR up to date with `master` and resolve conflicts yourself.

## Reporting bugs

Open an issue with what you did, what happened, what retail does instead, the build (x86/x64, renderer) and, if you can, a replay ID or a short video. For a desync, the replay ID and the beat it desyncs at are the most useful things you can give.
