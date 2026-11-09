# FAF FreeType 2.15.0 patch

Baseline: the FreeType 2.15.0 release archive (`dependencies/freetype`, pinned by SHA256 in `cmake/FafDependencies.cmake`). `cmake/FafDependencies.cmake` applies the patch at configure time; a tree given through `FAF_FREETYPE_DIR` has to carry it already, and `cmake/deps/freetype` stops the configure when it doesn't.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `src/base/fthash.c` | `hash_init` leaves `size` at 0 when its table can't be allocated; `hash_rehash` keeps the old table, size and limit when the larger table can't be allocated; `ft_hash_str_free`, the lookups and both iterators treat a null hash or table as an empty one | **Yes**: without it, an allocation that fails inside the autohinter crashes the game |

## Why

A mod's font cooks in the game's process with FreeType's memory capped (issue #305, `MSDF_MakeModCookOptions`). Past the cap an allocation fails, and FreeType is meant to treat that as running out of memory. Two paths in its hash table didn't: both set the table's size before allocating it, so a failed allocation left a null table with a size, and the free function then read through it. The autohinter builds such a table for each style (`af_reverse_character_map_new` in `src/autofit/afadjust.c`), so a font that makes it run short at that moment crashed the game, as `faf_msdf_safety_tests` did when it lowered FreeType's memory step by step:

```
faf_msdf_safety_tests!ft_hash_str_free+0x40
faf_msdf_safety_tests!af_reverse_character_map_new+0x8d
faf_msdf_safety_tests!af_latin_metrics_init+0x138f
faf_msdf_safety_tests!af_autofitter_load_glyph+0x20b
faf_msdf_safety_tests!FT_Load_Glyph+0x265
```

With that fixed, the same test crashed one step later: when the map fails to build, `af_reverse_character_map_new` logs "Using blank map" but leaves the map null, and `af_latin_hints_apply` then looks up in it (`ft_hash_num_lookup` read a null table). A lookup in a table that was never built now finds nothing, which is the blank map that message means.

Not reported upstream yet.
