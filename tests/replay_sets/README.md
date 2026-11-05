# Stored call hashes

For each replay in `replays.tsv`, `<replay>.sets` holds the original game's per-function call hashes, and `<replay>.tsv` says what they cover: for each function its name, its parameter and result kinds, which parameters are hashed, and its result kind. Every stored hash must appear when our build plays that replay, so the check needs no original game.

The eight replays of the core set cover 1,006 functions. A function is stored only if it matched the original game on every one of these replays where the original called it, apart from the original's own bugs listed in `retail_bugs.tsv`, and repeated between two runs of our build on each. Both games record up to the same beat, listed in `replays.tsv`, ten beats before the replay's end: the original usually plays a few beats further than our headless, and those calls would read as differences.

A hash cannot be turned back into a function call: it holds no inputs, and most of these functions read game objects. So this needs a replay, and is not a direct-call test like `tests/math_dump`.

## Running it (Windows, x86)

```
cmake --preset clang-x86-release -B build/call-hash -DFAF_CALL_HASH_BUILD=ON
cmake --build build/call-hash --target headless
tools\retail-recorder\build.bat
tools\retail-recorder\check_replay_sets.ps1 -BuildDir build\call-hash
```

The script plays every replay in `replays.tsv`; `-Replay <id>` plays one. The replays come from the parity pool (`tmp/parity/pool`) and need game data 3835 and the listed init file, which holds the M28AI version where one is needed. Exit code 0 means every stored hash was found and every recorded checksum matched. The report names each function that differs, is no longer called, or changed its signature.

- **DIFFERS:** the same inputs now give another result, or those inputs no longer occur. This is the finding the test exists for.
- **NOT CALLED:** nothing reaches that function on this replay any more.
- **CHANGED:** the function's name or kinds changed, so its stored hashes no longer cover the same words. A rename or signature change lands here, and needs the data regenerated. A struct's size does not count: it follows the container layout a build picks, and no stored hash covers a struct.

The whole list goes to `<spec>.report`. One bug spreads through the game, so the function at fault is often not the one with the most missing hashes: a deliberate bug in `MaxInt` gave 100 differing functions, with `MaxInt` itself at line 82 of the report.

## What it does not catch

It only sees inputs these replays produce. A bug in a branch no replay runs passes: a deliberate bug in `MaxInt`'s `lhs < rhs` branch changed nothing on the first replay, because all 35 calls there are `(1, 1)`. About half of the stored functions (541) have one distinct hash, so they are checked thinly, and more replays barely change that: going from three replays to eight doubled the stored hashes but moved this from 546 to 541, and added 3 functions. A function with no plain argument or result is not checked at all, and neither is a function the original game cannot hook.

## Bugs of the original game

We don't copy the original's bugs, so a call that only gives its result because of one is not a test. `retail_bugs.tsv` lists those calls by function and hash, each with its cause, and the comparison and `make` both leave them out, so the rest of the function stays checked. List a call only when its cause has been read in the binary.

## Regenerating

It takes the original game: `tools/retail-recorder/README.md`, "Comparing with our build", then `replay_sets.py make`. Only functions that compare the same and repeat between two runs of our build are stored, at most 4,096 hashes each (a fixed sample, so a rare difference in a very hot function can go unseen).
