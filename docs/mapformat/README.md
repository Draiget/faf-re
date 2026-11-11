# Map formats

Status: **revision 1, byte layouts of containers 3 and 4**. Two independent implementations (the C++ reader and the Python reference) agree on every golden map in `tests/mapformat/golden/`. The engine side is staged (FULL3D.md section 4); the first stage, the Classic bridge, is what the engine does today. A change to a byte layout from here on is a chunk version or revision bump.

The engine knows four map formats. It works out which one a file is before it parses any payload, logs it, and refuses
what it cannot load with a reason instead of guessing.

| Id | Name | Container | What it is |
|---|---|---|---|
| 1 | **Classic** | 2 | The stock `.scmap`: heightfield, strata masks, one water plane. Loader unchanged. |
| 2 | **Legacy25D** | 2 | A Classic file plus a mesh-terrain manifest (`TerrainSystem = 'mesh'`, `terrain/terrain.lua`, SCM meshes). The format FA-MeshTerrain and the SC2 campaign port use today. Kept as it is. |
| 3 | **Extended** | 3 | New chunked format on the heightfield model: everything modern a ground-based RTS map needs. [EXTENDED.md](EXTENDED.md) |
| 4 | **Full3D** | 4 | The ultimate version: Extended plus a streamed 3D world (meshes, volumes, collision, multi-level navigation, lightmaps, large-world coordinates). [FULL3D.md](FULL3D.md) |

Ids 3 and 4 equal the container version on purpose. Classic and Legacy25D share container 2 and are told apart by the
scenario / manifest, as today. Container framing, hashing, limits and the text dump used by the tests are in
[CONTAINER.md](CONTAINER.md).

Design decisions: the formats are separate; container 2 behaviour does not change at all; Legacy25D stays as it is and is not container 4; Full3D is the "can do anything" format, designed after industry practice and aligned with Extended.

## Detection (`MapFormat.cpp`)

1. Read the first 8 bytes: magic `0x1A70614D` ('Map\x1A') and the container version. Anything else: `NotAMap`.
2. Container 2: Classic. If the map's scenario says `TerrainSystem = 'mesh'` (or the manifest named by `TerrainMesh`
   exists with a known `version`): Legacy25D. (The scenario is read by the code that already reads it; detection only
   asks.)
3. Container 3: Extended. Container 4: Full3D. Any other value: `UnsupportedContainer` (message names the value).
4. For 3 and 4 the header is validated next (see CONTAINER.md): spec revision, required-feature mask, directory
   checksum. A required feature the exe does not implement refuses the map and names the feature.

The result is `SMapFormatInfo { id, container, revision, requiredFeatures, optionalFeatures, simHash }`. It is logged
(`MapFormat: Extended rev 1 features req=0x3 opt=0x1fa simhash=ab12...`), returned to Lua by `GetMapFormat()`, reported by the
`previewOnly` pass (map list, lobby), and part of the lobby map check.

## Principles (the best practices this design follows)

**Structure and evolution**
1. *Chunked and versioned.* PNG-style: each chunk has an id, a version and a required/optional flag. Unknown optional
   chunks are skipped, unknown required chunks refuse the map. A new feature is a new chunk, not a new container.
2. *Container version = breaking change; revision = additive.* Old exes refuse container 3 and 4 at the first 8 bytes
   (they already do: the magic matches, the version does not).
3. *Sim data and render data never share a chunk.* Sim chunks are deterministic, integer/fixed-point where it matters,
   identical on every client and hashed into `simHash` (lobby check, replay header). Render chunks are never read by the
   sim; a headless server skips them. Derived caches are a third class and are always optional and verifiable.
4. *One source of truth.* Anything computable (normals, nav meshes, mip pyramids, shadow cascades) is derived data in an
   optional chunk with a fingerprint of its inputs; a mismatch means the cache is ignored and rebuilt.
5. *Authoring metadata is not gameplay.* Names, authors, localisation, generator recipe, tool stamps, timestamps live in
   non-sim chunks, so re-saving a map in the editor never changes its `simHash`.

**Safety (maps are untrusted downloads)**
6. Every offset and size is bounds- and overflow-checked before use; no allocation is sized from the file without a
   limit (CONTAINER.md section 6); decompressed size is declared and enforced; the directory has its own checksum, every chunk
   its own CRC32.
7. Embedded assets can only be data (textures, meshes, sounds), only under the map's own namespace, never code or
   blueprints, and cannot shadow game files.
8. A fuzz corpus (truncation, bit flips, size lies) is part of the test suite.

**Data**
9. *Explicit units and conventions:* world units as FA (1 cell = 1 unit by default), Y up, little endian, IEEE-754 f32,
   colour spaces declared per texture, normals RG with reconstructed Z, quaternions smallest-three when stored.
10. *Exact height quantisation:* `h = min + v * 2^k` (exact in f32), not a free float scale; erosion-quality terraces vanish
    with a finer `k`, and every client computes the same height.
11. *Block-compressed GPU textures stored ready to upload* (BC1/3/4/5/6H/7) with mips, or "generate at load" flags;
    heights, masks and ids stored losslessly with predictors + deflate.
12. *Indexed splatting* (top-4 material indices + weights per texel) instead of one mask channel per layer: cost does not
    grow with the layer count. Dense masks stay available for lossless Classic conversion.
13. *Materials by reference* (PBR metallic-roughness, glTF-aligned, height-blended, triplanar option, stochastic /
    hex tiling, parallax); a map points at materials rather than copying textures. An optional embedded asset bundle makes a
    map self-contained.
14. *Seeded, specified procedures:* scatter placement and any generated detail use a specified integer PRNG (PCG32) and
    hash, so an editor, a server and every client draw the same picture.
15. *Time of day, weather and sublevels are keyed data* that scripts switch by name; the render side reads the sim clock, never
    the wall clock.
16. *Min/max height pyramid* (derived) for culling, line-of-sight and ray queries.
17. *Large worlds:* cell-relative quantised coordinates and an f64 world origin (Full3D) so precision does not degrade away
    from the origin; streamed cells with HLOD proxies.
18. *Provenance and trust:* generator id + seed, tool stamp, optional Ed25519 signature over `simHash` and metadata hash.
19. *Strategic hints for AI and scripts* (regions, chokepoints, expansion candidates, island ids) as optional data, so AIs
    stop re-deriving the same facts per game.
20. *Conformance:* golden maps for every chunk, a text dump (`DumpText`) both the reader and the Python reference
    implementation must produce identically, and a validator tool with strict and lenient modes.

## Compatibility

- Classic to Extended is lossless (`tools/mapformat/classic_to_extended.py` does it).
- Extended to Classic is possible when the map only uses what Classic can say (the writer has a "classic-compatible" check);
  render chunks are dropped, sim chunks must fit.
- Full3D contains Extended's heightfield as its base layer, so an Extended-only consumer (a tool, a minimap renderer) can read the
  base chunks of a Full3D file by ignoring the optional ones; a Full3D map that needs 3D features marks them required.
- Legacy25D maps keep working through the existing renderer; when Full3D lands, a converter lifts them to container 4.

## Where things are

| Path | What |
|---|---|
| `docs/mapformat/` | this spec |
| `src/moho/sim/mapformat/` | engine-independent reader (std only): detection, container, hashing, inflate, chunk decoders, text dump |
| `src/moho/sim/CWldMap.cpp` | `MapLoad` dispatch (container 3 and 4), `GetMapFormat` |
| `tests/mapformat/` | unit, golden, fuzz tests (standalone executable, no engine link) |
| `tools/mapformat/` | Python reference reader / writer, validator, golden generator, Classic converter |

## For writers (map editors, tools)

- Reference implementation: `tools/mapformat/mapfmt/` (Python, standard library only): `container.py` writer/reader, one `encode_xxx / decode_xxx / dump_xxx` per chunk, `builder.py`, `loadmap.py`. Naming of every dumped field: `tools/mapformat/DUMP_NAMES.md`.
- Check a file: `python tools/mapformat/mapinfo.py map.fmap --validate [--dump]`. Golden maps for every chunk and every failure class: `tests/mapformat/golden/` (README there). Regenerate/verify: `python tools/mapformat/make_golden.py [--check]`.
- Rules a writer must follow: CONTAINER.md (sorting, alignment, CRCs, `simHash`, limits), EXTENDED.md Appendix A (clarifications), feature bits declared in `requiredFeatures` for every sim feature the data uses, markers still written to `_save.lua` (Appendix B), heights as `min + v * 2^k` (stock = `0`, `-7`).
- Down-conversion to a Classic `.scmap` is `ExportClassic` (C++, `src/moho/sim/mapformat/ClassicExport.*`); the same function is how the engine loads container 3 / 4 maps today.
