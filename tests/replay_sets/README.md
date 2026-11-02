# Stored call hashes

For each replay, `<replay>.sets` holds the original game's per-function call hashes, and `<replay>.tsv` says what they cover: for each function its name, its parameter and result kinds, which parameters are hashed, and its result kind. Every stored hash must appear when our build plays that replay, so the check needs no original game.

A hash cannot be turned back into a function call: it holds no inputs, and most of these functions read game objects. So this needs a replay, and is not a direct-call test like `tests/math_dump`.

## Running it (Windows, x86)

```
cmake --preset clang-x86-release -B build/call-hash -DFAF_CALL_HASH_BUILD=ON
cmake --build build/call-hash --target headless
tools\retail-recorder\build.bat
tools\retail-recorder\check_replay_sets.ps1 -BuildDir build\call-hash
```

The replay comes from the parity pool (`tmp/parity/pool`) and needs game data 3835. Exit code 0 means every stored hash was found and every recorded checksum matched. The report names each function that differs, is no longer called, or changed its signature.

- **DIFFERS:** the same inputs now give another result, or those inputs no longer occur. This is the finding the test exists for.
- **NOT CALLED:** nothing reaches that function on this replay any more.
- **CHANGED:** the function's name or kinds changed, so its stored hashes no longer cover the same words. A rename or signature change lands here, and needs the data regenerated.

The whole list goes to `<spec>.report`. One bug spreads through the game, so the function at fault is often not the one with the most missing hashes: a deliberate bug in `MaxInt` gave 100 differing functions, with `MaxInt` itself at line 82 of the report.

## What it does not catch

It only sees inputs this replay produces. A bug in a branch the replay never runs passes: a deliberate bug in `MaxInt`'s `lhs < rhs` branch changed nothing here, because all 35 calls on this replay are `(1, 1)`. About half of the stored functions have one distinct hash, so they are checked thinly. More replays widen this. A function with no plain argument or result is not checked at all, and neither is a function the original game cannot hook.

## Regenerating

It takes the original game: `tools/retail-recorder/README.md`, "Comparing with our build", then `replay_sets.py make`. Only functions that compare the same and repeat between two runs of our build are stored, at most 4,096 hashes each (a fixed sample, so a rare difference in a very hot function can go unseen).
