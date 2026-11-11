# Container framing (containers 3 and 4)

Common to Extended (3) and Full3D (4). Revision 1. All integers little endian, floats IEEE-754 binary32 unless `f64`.
`u8 u16 u32 u64 i8 i16 i32 i64 f32 f64`. Offsets are absolute from the start of the file.

## 1. File layout

```
[ file header, 128 bytes ]
[ chunk data, each chunk starts on a 16-byte boundary, any order ]
[ chunk directory, at header.dirOffset ]
```

The directory is at the end so a writer can stream chunks out and write the directory last; a reader finds it through the header.

### 1.1 File header (128 bytes)

| Off | Type | Field | Notes |
|---|---|---|---|
| 0 | u32 | magic | `0x1A70614D` ('Map\x1A'), same as Classic |
| 4 | u32 | container | 3 or 4. Classic's reader sees a version it does not know and refuses |
| 8 | u16 | revision | additive revision of this container (1). A reader accepts `revision <= its own`; a higher one is accepted only if `requiredFeatures` is fully supported (unknown optional chunks are skipped) |
| 10 | u16 | headerSize | 128 |
| 12 | u32 | flags | bit0 = has signature chunk; others 0 |
| 16 | u64 | fileSize | exact; a mismatch refuses the file (truncation check) |
| 24 | u64 | dirOffset | |
| 32 | u32 | dirCount | at most 4096 |
| 36 | u32 | dirCrc32 | CRC32 of the directory bytes |
| 40 | u64 | requiredFeatures | bit set the reader must implement (section 4) |
| 48 | u64 | optionalFeatures | informational |
| 56 | u8[16] | mapGuid | stable identity of the map across saves |
| 72 | u8[32] | simHash | SHA-256 of the sim chunks (section 5) |
| 104 | u8[16] | reserved | 0 |
| 120 | u32 | reserved2 | 0 |
| 124 | u32 | headerCrc32 | CRC32 of bytes 0..123 |

### 1.2 Directory entry (48 bytes)

| Off | Type | Field | Notes |
|---|---|---|---|
| 0 | u8[4] | id | four ASCII characters, e.g. `GRID` |
| 4 | u16 | version | chunk version; a reader knows a maximum per id |
| 6 | u16 | flags | bit0 REQUIRED, bit1 SIM, bit2 DERIVED, bit3 DEFLATE (payload is a zlib-less raw deflate stream), others 0. SIM and DERIVED are exclusive; neither = render / metadata |
| 8 | u32 | instance | 0 for singleton chunks; index for repeated chunks (cells, lightmaps, textures) |
| 12 | u32 | crc32 | CRC32 of the **stored** bytes |
| 16 | u64 | offset | multiple of 16 |
| 24 | u64 | storedSize | bytes in the file |
| 32 | u64 | rawSize | bytes after inflate (equals storedSize when not compressed) |
| 40 | u64 | reserved | 0 |

`(id, instance)` pairs are unique. Entries are sorted by `(id, instance)` bytewise; the sort order is also the order used for `simHash`.
Chunk ranges must lie inside `[headerSize, dirOffset)` and must not overlap each other.

## 2. Codecs

Only raw DEFLATE (RFC 1951, no zlib/gzip wrapper). A tiny inflate lives in the reader so it needs no dependency and behaves identically in
tools and engine. The writer may choose per chunk whether to compress; the reader never assumes. Zstd is **not** used in revision 1; a
future revision can add flag bit4 and the reader refuses it when the feature bit is not supported.

Pre-compression predictors for arrays of integers (`PREDICT_*`) are defined per chunk (height, surface ids, splat planes).

## 3. Encoding conventions inside chunks

- `str` = `u16 length` + UTF-8 bytes, no terminator, length at most 4096. `path` = `str`, lower case VFS path starting with `/`.
- `array<T>` = `u32 count` + elements. Counts are limited per chunk (stated); a count that does not fit in the remaining bytes refuses the chunk.
- `vec2/vec3/vec4/quat` = consecutive f32. `color3` = linear RGB f32 (sRGB colours are named `srgb8` = 3 bytes). `guid` = 16 bytes.
- `enum8/enum16`: unknown values in a required chunk refuse the chunk, in an optional chunk the element is skipped where stated.
- `fx8 / fx16 / fx32` fixed point: value / 256, / 256, / 256 (signed) used in sim chunks where floats could differ between builds.
- Chunks are consumed exactly: unread trailing bytes make the chunk invalid (strict). Growth is by chunk version.
- `bitmask(W,H)` = rows of `ceil(W/8)` bytes, LSB first, row 0 = z 0.
- Planes of integers use `PREDICT`: 0 none, 1 delta along x, 2 delta along z, 3 Paeth. A plane has `rows`, `cols` and `channels` (interleaved
  components, 1 unless stated); a row holds `cols * channels` elements of `elemBytes` bytes (little-endian unsigned integers). Arithmetic is modulo
  2^(8*elemBytes). The left neighbour of element `i` in a row is element `i - channels` (absent = 0), the upper neighbour is the same element of the previous row
  (absent = 0), upper-left is both. Encoded value = value - prediction; decoding adds it back in reading order. Predictions: 1 = left, 2 = upper,
  3 = Paeth selector over (a = left, b = upper, c = upper-left) with `p = a + b - c` in signed 64 bit, `pa = |p-a|`, `pb = |p-b|`, `pc = |p-c|`, choose `a` if
  `pa <= pb && pa <= pc`, else `b` if `pb <= pc`, else `c`.
- World space: +X east, +Z south, +Y up, as FA. Cell (cx, cz) covers `[cx, cx+1) x [cz, cz+1)` times `cellSize`. Heights live on the `(cellsX+1) x (cellsZ+1)` sample grid.

## 4. Feature bits

| Bit | Name | Meaning (reader must implement when in `requiredFeatures`) |
|---|---|---|
| 0 | `GRID_NONSQUARE` | `cellsX != cellsZ` |
| 1 | `GRID_LARGE` | either axis above 4096 cells |
| 2 | `HEIGHT_FINE` | `stepLog2 < -7` |
| 3 | `SURFACE_LAYERS` | GPLY named masks used by the sim |
| 4 | `WATER_BODIES` | more than one water body or non-global extent in WBOD |
| 5 | `LEVELS` | LEVL decks affect movement |
| 6 | `PLAYABLE_POLYGON` | PLAY polygon |
| 7 | `MARKERS_BINARY` | MRKR / AREA are authoritative (save.lua markers absent) |
| 8 | `PROPS_BINARY` | PROP chunk is authoritative |
| 9 | `HINTS` | HINT chunk read by the AI |
| 16 | `RENDER_INDEXED_SPLAT` | SPLT mode 0 required to draw the map correctly |
| 17 | `RENDER_PBR_MATERIALS` | MATL needs PBR |
| 18 | `RENDER_VOLUMETRICS` | ATMO volumetric clouds / fog |
| 19 | `RENDER_TOD` | TODK |
| 32 | `WORLD_CELLS` | Full3D streamed cells |
| 33 | `WORLD_COLLISION` | Full3D COLL |
| 34 | `WORLD_NAV3D` | Full3D NAVS multi-layer surfaces / links |
| 35 | `WORLD_LARGE_COORDS` | Full3D `f64` origin used |
| 36 | `WORLD_LIGHTMAPS` | baked lightmaps needed |
| 37 | `WORLD_VOLUMES_SIM` | sim trigger volumes |
| 63 | `EXTENDED_FEATURES` | reserved: a second feature word follows in a later revision |

A map whose `requiredFeatures` has a bit the exe does not implement is refused with the feature names. Render-only features are normally
**optional** (the map still plays, drawn with the fallback); the writer sets them required only when the map is meaningless without them.

## 5. simHash

`simHash = SHA-256( for each directory entry with flag SIM in directory order: id(4) | version(u16) | instance(u32) | rawSize(u64) | rawBytes )`

The hash covers the **decompressed** bytes, so recompressing a map does not change it. Metadata, render and derived chunks never enter it.
It goes into the lobby map check (all players must have the same `simHash`) and may be recorded in the replay header.

## 6. Limits (reader hard caps, configurable by the engine, defaults)

| Limit | Default |
|---|---|
| file size | 4 GiB |
| directory entries | 4096 |
| single chunk raw size | 1 GiB |
| sum of raw sizes of all chunks decoded in one load | 3 GiB |
| inflate expansion ratio per chunk | 1:1032 (deflate's own maximum), beyond is refused |
| grid cells per axis | 65536; total sample count 2^30 |
| array counts | per chunk (stated in each chunk), never more than `remainingBytes / minElementSize` |
| string length | 4096 |
| nesting | chunks are flat; no recursion anywhere |

Checks happen in this order: header magic/version/size/CRC, directory bounds + CRC, per-chunk range + overlap, then per chunk: CRC of stored bytes,
inflate with declared `rawSize`, decode with bounds-checked reader. A chunk that fails is an error for required chunks and a warning (chunk dropped)
for optional ones when the reader runs in lenient mode; the engine runs strict for SIM chunks always.

## 7. Embedded assets (ASST) policy

Allowed entry types: DDS, PNG, TGA, SCM, SCA, XSB/XWB audio banks are **not** allowed (code-like parsers are riskier). Entries are mounted
read-only under `/maps/<mapname>/embedded/`; a path outside that prefix, `..`, an absolute override of `/units`, `/lua`, `/env`, `/projectiles`,
`/effects` is refused. Lua, `.bp`, `.scd` are refused. Total embedded size at most 1 GiB.

## 8. Text dump (conformance)

`DumpText(container) -> string` and the Python reference's `dump_text()` must produce **identical** output for a golden file. Format, one line each,
`\n` line endings, ASCII:

```
file.container = 3
file.revision = 1
file.required = 0x0000000000000003
chunk GRID inst=0 ver=1 flags=0x0003 raw=36
GRID.cellsX = 1024
GRID.cellSize = f32:3f800000
GRID.origin = [f32:00000000, f32:00000000]
GRID.something[0].name = "x"
```

Rules: integers decimal, u64 as decimal; flags hex 4 digits; floats `f32:` + 8 hex digits of the bit pattern; doubles `f64:` + 16 hex digits;
strings JSON-escaped in double quotes; byte blobs as `bytes[n] sha256:<64 hex>`; arrays `name.count = n` then `name[i].field`; fixed-size vectors inline
`[a, b, c]`; enums as integers. Large planes are dumped as `plane[WxH] sha256:<hex>` of the **decoded raw samples** (after predictor reversal),
never element by element. Chunks in directory order; fields in spec order. Unknown optional chunks are listed as `chunk XXXX inst=.. skipped`.

## 9. Versioning policy

- Adding a chunk id, a feature bit, an enum value that old readers may ignore: revision +1 (container unchanged).
- Changing a chunk's layout: that chunk's version +1; readers keep decoders for older versions.
- Anything that makes an old container-N reader misread the file: container +1.
- Chunk ids are never reused; deprecated ids stay reserved.
