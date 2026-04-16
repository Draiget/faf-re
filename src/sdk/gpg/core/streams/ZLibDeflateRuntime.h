#pragma once

#include <cstddef>
#include <cstdint>

struct DeflateCtDataRuntime
{
  union
  {
    std::uint16_t freq;
    std::uint16_t code;
  } fc{};
  union
  {
    std::uint16_t dad;
    std::uint16_t len;
  } dl{};
};

static_assert(sizeof(DeflateCtDataRuntime) == 0x04, "DeflateCtDataRuntime size must be 0x04");

struct DeflateZStreamRuntime
{
  std::uint8_t reserved00_2B[0x2C]{};
  std::int32_t data_type = 0; // +0x2C
};

static_assert(offsetof(DeflateZStreamRuntime, data_type) == 0x2C, "DeflateZStreamRuntime::data_type offset must be 0x2C");

struct DeflateStaticTreeDescriptorRuntime
{
  const DeflateCtDataRuntime* staticTree = nullptr; // +0x00
  const std::int32_t* extraBits = nullptr;          // +0x04
  std::int32_t extraBase = 0;                       // +0x08
  std::int32_t elems = 0;                           // +0x0C
  std::int32_t maxLength = 0;                       // +0x10
};

static_assert(
  offsetof(DeflateStaticTreeDescriptorRuntime, staticTree) == 0x00,
  "DeflateStaticTreeDescriptorRuntime::staticTree offset must be 0x00"
);
static_assert(
  offsetof(DeflateStaticTreeDescriptorRuntime, extraBits) == 0x04,
  "DeflateStaticTreeDescriptorRuntime::extraBits offset must be 0x04"
);
static_assert(
  offsetof(DeflateStaticTreeDescriptorRuntime, extraBase) == 0x08,
  "DeflateStaticTreeDescriptorRuntime::extraBase offset must be 0x08"
);
static_assert(
  offsetof(DeflateStaticTreeDescriptorRuntime, elems) == 0x0C,
  "DeflateStaticTreeDescriptorRuntime::elems offset must be 0x0C"
);
static_assert(
  offsetof(DeflateStaticTreeDescriptorRuntime, maxLength) == 0x10,
  "DeflateStaticTreeDescriptorRuntime::maxLength offset must be 0x10"
);
static_assert(sizeof(DeflateStaticTreeDescriptorRuntime) == 0x14, "DeflateStaticTreeDescriptorRuntime size must be 0x14");

struct DeflateTreeDescriptorRuntime
{
  DeflateCtDataRuntime* dynTree = nullptr;                        // +0x00
  std::int32_t maxCode = 0;                                       // +0x04
  const DeflateStaticTreeDescriptorRuntime* statDesc = nullptr;   // +0x08
};

static_assert(offsetof(DeflateTreeDescriptorRuntime, dynTree) == 0x00, "DeflateTreeDescriptorRuntime::dynTree offset must be 0x00");
static_assert(offsetof(DeflateTreeDescriptorRuntime, maxCode) == 0x04, "DeflateTreeDescriptorRuntime::maxCode offset must be 0x04");
static_assert(offsetof(DeflateTreeDescriptorRuntime, statDesc) == 0x08, "DeflateTreeDescriptorRuntime::statDesc offset must be 0x08");
static_assert(sizeof(DeflateTreeDescriptorRuntime) == 0x0C, "DeflateTreeDescriptorRuntime size must be 0x0C");

struct DeflateStateRuntime
{
  DeflateZStreamRuntime* strm = nullptr;       // +0x00
  std::uint8_t reserved04_07[0x04]{};
  std::uint8_t* pending_buf = nullptr;         // +0x08
  std::uint8_t reserved0C_13[0x08]{};
  std::int32_t pending = 0;                    // +0x14
  std::uint8_t reserved18_2B[0x14]{};
  std::uint32_t w_size = 0;                    // +0x2C
  std::uint8_t reserved30_33[0x04]{};
  std::uint32_t w_mask = 0;                    // +0x34
  std::uint8_t* window = nullptr;              // +0x38
  std::uint8_t reserved3C_3F[0x04]{};
  std::uint16_t* prev = nullptr;               // +0x40
  std::uint8_t reserved44_6B[0x28]{};
  std::uint32_t strstart = 0;                  // +0x6C
  std::uint32_t match_start = 0;               // +0x70
  std::uint32_t lookahead = 0;                 // +0x74
  std::uint32_t prev_length = 0;               // +0x78
  std::uint32_t max_chain_length = 0;          // +0x7C
  std::uint8_t reserved80_8B[0x0C]{};
  std::uint32_t good_match = 0;                // +0x8C
  std::uint32_t nice_match = 0;                // +0x90
  DeflateCtDataRuntime dyn_ltree[286]{};       // +0x94
  std::uint8_t reserved50C_987[0x47C]{};
  DeflateCtDataRuntime dyn_dtree[30]{};        // +0x988
  std::uint8_t reservedA00_A7B[0x7C]{};
  DeflateCtDataRuntime bl_tree[19]{};          // +0xA7C
  std::uint8_t reservedAC8_B3B[0x74]{};
  std::uint16_t bl_count[16]{};                // +0xB3C
  std::int32_t heap[573]{};                    // +0xB5C
  std::int32_t heap_len = 0;                   // +0x1450
  std::int32_t heap_max = 0;                   // +0x1454
  std::uint8_t depth[573]{};                   // +0x1458
  std::uint8_t reserved1695_1697[0x03]{};
  std::uint8_t* l_buf = nullptr;               // +0x1698
  std::uint32_t lit_bufsize = 0;               // +0x169C
  std::uint32_t last_lit = 0;                  // +0x16A0
  std::uint16_t* d_buf = nullptr;              // +0x16A4
  std::uint32_t opt_len = 0;                   // +0x16A8
  std::uint32_t static_len = 0;                // +0x16AC
  std::uint32_t matches = 0;                   // +0x16B0
  std::int32_t last_eob_len = 0;               // +0x16B4
  std::uint16_t bi_buf = 0;                    // +0x16B8
  std::uint16_t reserved16BA = 0;              // +0x16BA
  std::int32_t bi_valid = 0;                   // +0x16BC
};

using DeflateStateRuntimePrefix = DeflateStateRuntime;

static_assert(offsetof(DeflateStateRuntime, pending_buf) == 0x08, "DeflateStateRuntime::pending_buf offset must be 0x08");
static_assert(offsetof(DeflateStateRuntime, pending) == 0x14, "DeflateStateRuntime::pending offset must be 0x14");
static_assert(offsetof(DeflateStateRuntime, w_size) == 0x2C, "DeflateStateRuntime::w_size offset must be 0x2C");
static_assert(offsetof(DeflateStateRuntime, w_mask) == 0x34, "DeflateStateRuntime::w_mask offset must be 0x34");
static_assert(offsetof(DeflateStateRuntime, window) == 0x38, "DeflateStateRuntime::window offset must be 0x38");
static_assert(offsetof(DeflateStateRuntime, prev) == 0x40, "DeflateStateRuntime::prev offset must be 0x40");
static_assert(offsetof(DeflateStateRuntime, strstart) == 0x6C, "DeflateStateRuntime::strstart offset must be 0x6C");
static_assert(offsetof(DeflateStateRuntime, match_start) == 0x70, "DeflateStateRuntime::match_start offset must be 0x70");
static_assert(offsetof(DeflateStateRuntime, lookahead) == 0x74, "DeflateStateRuntime::lookahead offset must be 0x74");
static_assert(offsetof(DeflateStateRuntime, prev_length) == 0x78, "DeflateStateRuntime::prev_length offset must be 0x78");
static_assert(
  offsetof(DeflateStateRuntime, max_chain_length) == 0x7C, "DeflateStateRuntime::max_chain_length offset must be 0x7C"
);
static_assert(offsetof(DeflateStateRuntime, good_match) == 0x8C, "DeflateStateRuntime::good_match offset must be 0x8C");
static_assert(offsetof(DeflateStateRuntime, nice_match) == 0x90, "DeflateStateRuntime::nice_match offset must be 0x90");
static_assert(offsetof(DeflateStateRuntime, dyn_ltree) == 0x94, "DeflateStateRuntime::dyn_ltree offset must be 0x94");
static_assert(offsetof(DeflateStateRuntime, dyn_dtree) == 0x988, "DeflateStateRuntime::dyn_dtree offset must be 0x988");
static_assert(offsetof(DeflateStateRuntime, bl_tree) == 0xA7C, "DeflateStateRuntime::bl_tree offset must be 0xA7C");
static_assert(offsetof(DeflateStateRuntime, bl_count) == 0xB3C, "DeflateStateRuntime::bl_count offset must be 0xB3C");
static_assert(offsetof(DeflateStateRuntime, heap) == 0xB5C, "DeflateStateRuntime::heap offset must be 0xB5C");
static_assert(offsetof(DeflateStateRuntime, heap_len) == 0x1450, "DeflateStateRuntime::heap_len offset must be 0x1450");
static_assert(offsetof(DeflateStateRuntime, heap_max) == 0x1454, "DeflateStateRuntime::heap_max offset must be 0x1454");
static_assert(offsetof(DeflateStateRuntime, depth) == 0x1458, "DeflateStateRuntime::depth offset must be 0x1458");
static_assert(offsetof(DeflateStateRuntime, l_buf) == 0x1698, "DeflateStateRuntime::l_buf offset must be 0x1698");
static_assert(offsetof(DeflateStateRuntime, lit_bufsize) == 0x169C, "DeflateStateRuntime::lit_bufsize offset must be 0x169C");
static_assert(offsetof(DeflateStateRuntime, last_lit) == 0x16A0, "DeflateStateRuntime::last_lit offset must be 0x16A0");
static_assert(offsetof(DeflateStateRuntime, d_buf) == 0x16A4, "DeflateStateRuntime::d_buf offset must be 0x16A4");
static_assert(offsetof(DeflateStateRuntime, opt_len) == 0x16A8, "DeflateStateRuntime::opt_len offset must be 0x16A8");
static_assert(offsetof(DeflateStateRuntime, static_len) == 0x16AC, "DeflateStateRuntime::static_len offset must be 0x16AC");
static_assert(offsetof(DeflateStateRuntime, matches) == 0x16B0, "DeflateStateRuntime::matches offset must be 0x16B0");
static_assert(
  offsetof(DeflateStateRuntime, last_eob_len) == 0x16B4, "DeflateStateRuntime::last_eob_len offset must be 0x16B4"
);
static_assert(offsetof(DeflateStateRuntime, bi_buf) == 0x16B8, "DeflateStateRuntime::bi_buf offset must be 0x16B8");
static_assert(offsetof(DeflateStateRuntime, bi_valid) == 0x16BC, "DeflateStateRuntime::bi_valid offset must be 0x16BC");
static_assert(sizeof(DeflateStateRuntime) == 0x16C0, "DeflateStateRuntime size must be 0x16C0");

struct z_stream_s;
using z_stream = z_stream_s;

extern "C"
{
  /**
   * Address: 0x0095A830 (FUN_0095A830)
   *
   * What it does:
   * Scans the input stream for the inflate sync marker sequence and transitions
   * back to block decoding when the marker is found.
   */
  int __cdecl inflateSync(z_stream* stream);

  /**
   * Address: 0x0095AA90 (FUN_0095AA90)
   *
   * What it does:
   * Seeds the deflate history window with one preset dictionary and rebuilds
   * the hash chains used by the match finder.
   */
  int __cdecl deflateSetDictionary(
    z_stream* stream,
    const std::uint8_t* dictionary,
    unsigned int dictionaryLength
  );

  /**
   * Address: 0x0095B5C0 (FUN_0095B5C0)
   *
   * What it does:
   * Clones one active deflate stream state, including hash/window/pending
   * buffers, so compression can continue from an identical state.
   */
  int __cdecl deflateCopy(z_stream* destination, z_stream* source);

  /**
   * Address: 0x0095C990 (FUN_0095C990)
   *
   * What it does:
   * Returns the zlib build version literal used by runtime init entry points.
   */
  const char* __cdecl zlibVersion();

  /**
   * Address: 0x0095EB20 (FUN_0095EB20, _tr_tally)
   *
   * What it does:
   * Appends one literal or match token into `l_buf`/`d_buf`, updates dynamic
   * Huffman frequencies, and reports whether the literal buffer is full.
   */
  int __cdecl _tr_tally(DeflateStateRuntime* state, int distance, int literalOrLengthCode);

  /**
   * Address: 0x0095F140 (FUN_0095F140, bi_windup)
   *
   * What it does:
   * Flushes any pending bit-accumulator bytes into `pending_buf`, then clears
   * the bit-buffer validity lanes.
   */
  DeflateStateRuntime* __cdecl bi_windup(DeflateStateRuntime* state);

  /**
   * Address: 0x0095F1C0 (FUN_0095F1C0, copy_block)
   *
   * What it does:
   * Finalizes the bitstream byte boundary, optionally writes the stored-block
   * header, then appends `len` payload bytes into the pending output buffer.
   */
  void __cdecl copy_block(DeflateStateRuntime* state, int len, const std::uint8_t* buffer, int header);

  /**
   * Address: 0x0095AC80 (FUN_0095AC80, putShortMSB)
   *
   * What it does:
   * Writes one 16-bit value to `pending_buf` in big-endian byte order and
   * advances the pending cursor by two bytes.
   */
  DeflateStateRuntime* __cdecl putShortMSB(DeflateStateRuntime* state, std::int16_t value);

  /**
   * Address: 0x0095B860 (FUN_0095B860, longest_match)
   *
   * What it does:
   * Walks one hash-chain lane from `cur_match`, scans the window for the best
   * match, and updates `match_start` when a longer sequence is found.
   */
  unsigned int __cdecl longest_match(unsigned int cur_match, DeflateStateRuntime* state);

  /**
   * Address: 0x0095B9E0 (FUN_0095B9E0, longest_match_fast)
   *
   * What it does:
   * Runs one bounded fast-path compare for the current candidate and records
   * `match_start` when it reaches a 3-byte-or-better match.
   */
  int __cdecl longest_match_fast(DeflateStateRuntime* state, int cur_match);

  /**
   * Address: 0x0095DF50 (FUN_0095DF50, init_block)
   *
   * What it does:
   * Clears dynamic Huffman frequency lanes for a new block and seeds the
   * end-of-block literal frequency.
   */
  void __cdecl init_block(int dead, DeflateStateRuntime* state);

  /**
   * Address: 0x0095E090 (FUN_0095E090, gen_bitlen)
   *
   * What it does:
   * Computes Huffman code lengths for one dynamic tree, updates bit-length
   * histogram lanes, and accumulates opt/static bit-cost totals.
   */
  DeflateStateRuntime* __cdecl gen_bitlen(DeflateStateRuntime* state, DeflateTreeDescriptorRuntime* descriptor);

  /**
   * Address: 0x0095DFC0 (FUN_0095DFC0, pqdownheap)
   *
   * What it does:
   * Restores min-heap ordering in `state->heap` from one index using
   * dynamic-tree frequency/depth tie-break rules.
   */
  DeflateStateRuntime* __cdecl pqdownheap(
    DeflateStateRuntime* state,
    DeflateTreeDescriptorRuntime* descriptor,
    int heapIndex
  );

  /**
   * Address: 0x0095E3A0 (FUN_0095E3A0, send_tree)
   *
   * What it does:
   * Emits one code-length tree using repeat/run-length symbols into the
   * pending bitstream lanes.
   */
  void __cdecl send_tree(DeflateStateRuntime* state, DeflateCtDataRuntime* tree, int maxCode);

  /**
   * Address: 0x0095E2B0 (FUN_0095E2B0, scan_tree)
   *
   * What it does:
   * Scans one code-length tree lane and accumulates repeat symbol frequencies
   * into `bl_tree` for dynamic Huffman header construction.
   */
  void __cdecl scan_tree(DeflateCtDataRuntime* tree, int maxCode, DeflateStateRuntime* state);

  /**
   * Address: 0x0095EFD0 (FUN_0095EFD0, set_data_type)
   *
   * What it does:
   * Classifies stream data as binary/text from literal frequency lanes and
   * stores the result into `strm->data_type`.
   */
  void __cdecl set_data_type(int dead, DeflateStateRuntime* state);
}
