# Forced-unresolved symbol allowlist

Symbols this recovery does not define yet. The list is currently **empty**: every symbol the tree references is defined. Keep it that way.

- **Why it matters**: `main.vcxproj` links with `/FORCE`, so an unresolved symbol is only a warning. The linker still needs an address for the call site and uses RVA 0, which the loader relocates to the module base, so calling one jumps to `imagebase + 0`.
- **How it is enforced**: `scripts/linkcheck.py` reads this list and fails a build that produces any unresolved symbol not in it.
- **Rule**: remove an entry when it is recovered; never add one to silence a build. A new entry here is a latent jump to the image base, not a build fix.

## The list

```
```
