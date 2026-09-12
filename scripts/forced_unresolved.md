# Forced-unresolved symbol allowlist

Symbols this recovery does not define yet. `main.vcxproj` links with `/FORCE`,
so each is a warning rather than an error - but the linker still needs an
address for the call site and uses RVA 0, which the loader relocates to the
module base. Calling one jumps to `imagebase + 0`.

`scripts/linkcheck.py` reads this list and fails a build that produces any
unresolved symbol not in it. Remove an entry when it is recovered; never add
one to silence a build.

The list is currently **empty**: every symbol the tree references is
defined. Keep it that way - a new entry here is a latent jump to the image
base, not a build fix.

## The list

```
```
