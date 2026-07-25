#pragma once

// zlib 1.2.x deflate types, recovered from ForgedAlliance.exe's statically
// linked zlib. Field offsets verified from the deflate leaf bodies' .asm
// displacements (the IDA decompiler mislabels this struct). Every field named
// here is touched by a recovered deflate function, and every offset is pinned
// by an offsetof static_assert against the address the .asm actually reads.
//
// The anchor is deflateInit2_ (FUN_0095C740): it ZALLOCs a 0x16C0-byte
// deflate_state and writes w_bits@0x30, w_mask@0x34, w_size@0x2C,
// hash_size@0x4C, hash_bits@0x50, hash_mask@0x54, hash_shift@0x58,
// window@0x38, prev@0x40, head@0x44, lit_bufsize@0x169C, l_buf@0x1698,
// d_buf@0x16A4, level@0x84, strategy@0x88, method@0x24, pending_buf@0x08,
// pending_buf_size@0x0C. The tree arrays and their descriptors are pinned by
// tr_init (FUN_0095F250): dyn_ltree@0x94, dyn_dtree@0x988, bl_tree@0xA7C,
// l_desc@0xB18, d_desc@0xB24, bl_desc@0xB30, bi_buf@0x16B8, bi_valid@0x16BC,
// last_eob_len@0x16B4. build_tree (FUN_0095F350) pins bl_count@0xB3C,
// heap@0xB5C, heap_len@0x1450, heap_max@0x1454, depth@0x1458, opt_len@0x16A8,
// static_len@0x16AC.

#include <cstddef>
#include <cstdint>

#include "zlib/ZLibCommon.h"

namespace zlib {

// -----------------------------------------------------------------------------
// deflate constants (zlib deflate.h / trees.c)
// -----------------------------------------------------------------------------

// deflate status values (deflate_state.status). Verified from the deflateEnd
// validity check in FUN_0095B4E0.asm and the deflate() driver FUN_0095AD00.asm.
constexpr int kDeflateInitState    = 42;   // INIT_STATE
constexpr int kDeflateExtraState   = 69;   // EXTRA_STATE
constexpr int kDeflateNameState    = 73;   // NAME_STATE
constexpr int kDeflateCommentState = 91;   // COMMENT_STATE
constexpr int kDeflateHcrcState    = 103;  // HCRC_STATE
constexpr int kDeflateBusyState    = 113;  // BUSY_STATE
constexpr int kDeflateFinishState  = 666;  // FINISH_STATE

// LZ77 / Huffman geometry (trees.c). These fix the sizes of the in-struct
// arrays; the offsets above already depend on these exact counts.
constexpr int kZDeflated     = 8;    // the only supported method
constexpr int kMinMatch      = 3;
constexpr int kMaxMatch      = 258;
constexpr int kMinLookahead  = kMaxMatch + kMinMatch + 1;  // 262 (0x106)

constexpr int kLengthCodes = 29;   // number of length codes, excl. END_BLOCK
constexpr int kLiterals    = 256;  // literal bytes 0..255
constexpr int kLCodes      = kLiterals + 1 + kLengthCodes;  // 286
constexpr int kDCodes      = 30;   // distance codes
constexpr int kBlCodes     = 19;   // bit-length transfer codes
constexpr int kHeapSize    = 2 * kLCodes + 1;   // 573
constexpr int kMaxBitsDeflate = 15;

constexpr int kEndBlock    = 256;  // end-of-block code in the literal tree
constexpr int kRep_3_6     = 16;   // repeat previous bit length 3..6 times
constexpr int kRepz_3_10   = 17;   // repeat a zero length 3..10 times
constexpr int kRepz_11_138 = 18;   // repeat a zero length 11..138 times

// deflate strategies (zlib.h). The engine only ever uses Z_DEFAULT_STRATEGY;
// the others are modelled because the match loops branch on them.
constexpr int kZDefaultStrategy = 0;
constexpr int kZFiltered        = 1;
constexpr int kZHuffmanOnly     = 2;
constexpr int kZRle             = 3;
constexpr int kZFixed           = 4;

// deflate flush values (zlib.h). deflate()/the match loops compare against
// these literals in FUN_0095AD00.asm.
constexpr int kDeflateNoFlush      = 0;
constexpr int kDeflatePartialFlush = 1;
constexpr int kDeflateSyncFlush    = 2;
constexpr int kDeflateFullFlush    = 3;
constexpr int kDeflateFinish       = 4;

constexpr int kZDefaultCompression = -1;
constexpr int kZBestCompression    = 9;

constexpr unsigned int kPresetDict = 0x20;  // preset dictionary flag in zlib hdr

// block_state returned by deflate_stored/deflate_fast/deflate_slow
// (FUN_0095BC00/0095BDE0/0095C150). The integer values are load-bearing: the
// driver compares `bstate == finish_started`/`finish_done` etc.
enum BlockState : int
{
  kBlockNeedMore     = 0,  // block not completed, need more input or more output
  kBlockDone         = 1,  // block flush performed
  kBlockFinishStarted = 2, // finish started, need only more output at next call
  kBlockFinishDone   = 3,  // finish done, accept no more input or output
};

// -----------------------------------------------------------------------------
// Huffman tree node + descriptors (zlib trees.c ct_data / tree_desc /
// static_tree_desc). ct_data is a 4-byte {freq|code, dad|len} pair.
// -----------------------------------------------------------------------------

// One symbol's frequency/code and father/length, a union pair in the original.
// Modelled as named accessors over the two 16-bit slots so behaviour code reads
// s.dyn_ltree[n].Freq() rather than raw halves.
struct CtData
{
  std::uint16_t fc;  // frequency count (building) or bit-string code (emitting)
  std::uint16_t dl;  // father node in the tree (building) or bit length (emit)

  [[nodiscard]] std::uint16_t Freq() const { return fc; }
  [[nodiscard]] std::uint16_t Code() const { return fc; }
  [[nodiscard]] std::uint16_t Dad()  const { return dl; }
  [[nodiscard]] std::uint16_t Len()  const { return dl; }
};
static_assert(sizeof(CtData) == 4, "zlib::CtData must be 4 bytes");

// Description of a static tree (static_l_desc/static_d_desc/static_bl_desc).
// 20 bytes on Win32: {const CtData*, const int*, int, int, int}. Byte-verified
// against ForgedAlliance.exe .rodata at 0xF32D78/0xF32D8C/0xF32DA0.
struct StaticTreeDesc
{
  const CtData* static_tree;   // +0x00 static tree or nullptr
  const int*    extra_bits;    // +0x04 extra bits for each code or nullptr
  int           extra_base;    // +0x08 base index for extra_bits
  int           elems;         // +0x0C max number of elements in the tree
  int           max_length;    // +0x10 max bit length for the codes
};
static_assert(sizeof(StaticTreeDesc) == 20, "zlib::StaticTreeDesc must be 20 bytes");

// Per-stream dynamic tree descriptor (tree_desc). 12 bytes:
// {CtData* dyn_tree, int max_code, StaticTreeDesc* stat_desc}. tr_init sets
// dyn_tree/stat_desc; build_tree fills max_code.
struct TreeDesc
{
  CtData*               dyn_tree;   // +0x00 the dynamic tree
  int                   max_code;   // +0x04 largest code with non-zero freq
  const StaticTreeDesc* stat_desc;  // +0x08 the corresponding static tree
};
static_assert(sizeof(TreeDesc) == 12, "zlib::TreeDesc must be 12 bytes");

// zlib gz_header (only the fields the gzip header emit in deflate() reads).
// wrap==2 (gzip) is present in this build even though the engine only uses the
// zlib wrapper; deflate() reads gzhead->text/extra/name/hcrc/comment/time/os.
struct GzHeaderW
{
  std::int32_t   text;       // +0x00
  std::uint32_t  time;       // +0x04
  std::int32_t   xflags;     // +0x08
  std::int32_t   os;         // +0x0C
  std::uint8_t*  extra;      // +0x10
  std::uint32_t  extra_len;  // +0x14
  std::uint32_t  extra_max;  // +0x18
  std::uint8_t*  name;       // +0x1C
  std::uint32_t  name_max;   // +0x20
  std::uint8_t*  comment;    // +0x24
  std::uint32_t  comm_max;   // +0x28
  std::int32_t   hcrc;       // +0x2C
  std::int32_t   done;       // +0x30
};

// -----------------------------------------------------------------------------
// deflate_state (internal_state for the deflate direction). Complete 0x16C0-byte
// layout; the ZALLOC size in deflateInit2_ (FUN_0095C740.asm 0x0095C810,
// push 16C0h) fixes sizeof.
// -----------------------------------------------------------------------------
struct DeflateState
{
  void*          strm;             // +0x00  back-pointer to the owning z_stream
  std::int32_t   status;           // +0x04  low-level state machine status
  std::uint8_t*  pending_buf;      // +0x08  output still pending
  std::uint32_t  pending_buf_size; // +0x0C  size of pending_buf (== 4*lit_bufsize)
  std::uint8_t*  pending_out;      // +0x10  next pending byte to output
  std::uint32_t  pending;          // +0x14  bytes in pending_buf
  std::int32_t   wrap;             // +0x18  0 raw, 1 zlib, 2 gzip
  GzHeaderW*     gzhead;           // +0x1C  gzip header sink or nullptr
  std::uint32_t  gzindex;          // +0x20  gzip header write index
  std::uint8_t   method;           // +0x24  STORED/DEFLATED
  std::uint8_t   pad_25[3];        // +0x25  alignment
  std::int32_t   last_flush;       // +0x28  flush of previous deflate call

  std::uint32_t  w_size;           // +0x2C  LZ77 window size
  std::uint32_t  w_bits;           // +0x30  log2(w_size)
  std::uint32_t  w_mask;           // +0x34  w_size - 1
  std::uint8_t*  window;           // +0x38  sliding window (2*w_size bytes)
  std::uint32_t  window_size;      // +0x3C  actual size of window (2*w_size)
  std::uint16_t* prev;             // +0x40  older-string links, w_size entries
  std::uint16_t* head;             // +0x44  heads of the hash chains

  std::uint32_t  ins_h;            // +0x48  hash index of string to insert
  std::uint32_t  hash_size;        // +0x4C  number of hash-table entries
  std::uint32_t  hash_bits;        // +0x50  log2(hash_size)
  std::uint32_t  hash_mask;        // +0x54  hash_size - 1
  std::uint32_t  hash_shift;       // +0x58  bits to shift ins_h per step
  std::int32_t   block_start;      // +0x5C  window pos of current block start
  std::uint32_t  match_length;     // +0x60  length of best match
  std::uint32_t  prev_match;       // +0x64  previous match
  std::int32_t   match_available;  // +0x68  set if previous match exists
  std::uint32_t  strstart;         // +0x6C  start of string to insert
  std::uint32_t  match_start;      // +0x70  start of matching string
  std::uint32_t  lookahead;        // +0x74  valid bytes ahead in window
  std::uint32_t  prev_length;      // +0x78  length of best match at prev step
  std::uint32_t  max_chain_length; // +0x7C  hash-chain search cap
  std::uint32_t  max_lazy_match;   // +0x80  lazy-match threshold (max_insert_length)
  std::int32_t   level;            // +0x84  compression level 0..9
  std::int32_t   strategy;         // +0x88  Z_DEFAULT_STRATEGY etc.
  std::uint32_t  good_match;       // +0x8C  faster search when prev match longer
  std::int32_t   nice_match;       // +0x90  stop when match exceeds this

  CtData         dyn_ltree[kHeapSize];       // +0x94   literal and length tree (573)
  CtData         dyn_dtree[2 * kDCodes + 1]; // +0x988  distance tree (61)
  CtData         bl_tree[2 * kBlCodes + 1];  // +0xA7C  bit-length tree (39)

  TreeDesc       l_desc;   // +0xB18  desc. for literal tree
  TreeDesc       d_desc;   // +0xB24  desc. for distance tree
  TreeDesc       bl_desc;  // +0xB30  desc. for bit-length tree

  std::uint16_t  bl_count[kMaxBitsDeflate + 1];  // +0xB3C  codes per bit length (16)

  int            heap[2 * kLCodes + 1];  // +0xB5C  heap for tree building (573)
  int            heap_len;               // +0x1450 elements in the heap
  int            heap_max;               // +0x1454 element of largest frequency

  std::uint8_t   depth[2 * kLCodes + 1]; // +0x1458 subtree depth tie-breaker (573)
  std::uint8_t   pad_1695[3];            // +0x1695 alignment to l_buf

  std::uint8_t*  l_buf;        // +0x1698 buffer for literals/lengths
  std::uint32_t  lit_bufsize;  // +0x169C match buffer size for lit/length
  std::uint32_t  last_lit;     // +0x16A0 running index in l_buf (sym_next)
  std::uint16_t* d_buf;        // +0x16A4 buffer for distances
  std::uint32_t  opt_len;      // +0x16A8 bit length of block, optimal trees
  std::uint32_t  static_len;   // +0x16AC bit length of block, static trees
  std::uint32_t  matches;      // +0x16B0 number of string matches in block
  std::int32_t   last_eob_len; // +0x16B4 bit length of EOB code for last block

  std::uint16_t  bi_buf;       // +0x16B8 bit accumulator (LSB first)
  std::uint16_t  pad_16BA;     // +0x16BA alignment
  std::int32_t   bi_valid;     // +0x16BC number of valid bits in bi_buf
};

static_assert(offsetof(DeflateState, status)           == 0x04);
static_assert(offsetof(DeflateState, pending_buf)      == 0x08);
static_assert(offsetof(DeflateState, pending_buf_size) == 0x0C);
static_assert(offsetof(DeflateState, pending_out)      == 0x10);
static_assert(offsetof(DeflateState, pending)          == 0x14);
static_assert(offsetof(DeflateState, wrap)             == 0x18);
static_assert(offsetof(DeflateState, gzhead)           == 0x1C);
static_assert(offsetof(DeflateState, gzindex)          == 0x20);
static_assert(offsetof(DeflateState, method)           == 0x24);
static_assert(offsetof(DeflateState, last_flush)       == 0x28);
static_assert(offsetof(DeflateState, w_size)           == 0x2C);
static_assert(offsetof(DeflateState, w_bits)           == 0x30);
static_assert(offsetof(DeflateState, w_mask)           == 0x34);
static_assert(offsetof(DeflateState, window)           == 0x38);
static_assert(offsetof(DeflateState, window_size)      == 0x3C);
static_assert(offsetof(DeflateState, prev)             == 0x40);
static_assert(offsetof(DeflateState, head)             == 0x44);
static_assert(offsetof(DeflateState, ins_h)            == 0x48);
static_assert(offsetof(DeflateState, hash_size)        == 0x4C);
static_assert(offsetof(DeflateState, hash_bits)        == 0x50);
static_assert(offsetof(DeflateState, hash_mask)        == 0x54);
static_assert(offsetof(DeflateState, hash_shift)       == 0x58);
static_assert(offsetof(DeflateState, block_start)      == 0x5C);
static_assert(offsetof(DeflateState, match_length)     == 0x60);
static_assert(offsetof(DeflateState, prev_match)       == 0x64);
static_assert(offsetof(DeflateState, match_available)  == 0x68);
static_assert(offsetof(DeflateState, strstart)         == 0x6C);
static_assert(offsetof(DeflateState, match_start)      == 0x70);
static_assert(offsetof(DeflateState, lookahead)        == 0x74);
static_assert(offsetof(DeflateState, prev_length)      == 0x78);
static_assert(offsetof(DeflateState, max_chain_length) == 0x7C);
static_assert(offsetof(DeflateState, max_lazy_match)   == 0x80);
static_assert(offsetof(DeflateState, level)            == 0x84);
static_assert(offsetof(DeflateState, strategy)         == 0x88);
static_assert(offsetof(DeflateState, good_match)       == 0x8C);
static_assert(offsetof(DeflateState, nice_match)       == 0x90);
static_assert(offsetof(DeflateState, dyn_ltree)        == 0x94);
static_assert(offsetof(DeflateState, dyn_dtree)        == 0x988);
static_assert(offsetof(DeflateState, bl_tree)          == 0xA7C);
static_assert(offsetof(DeflateState, l_desc)           == 0xB18);
static_assert(offsetof(DeflateState, d_desc)           == 0xB24);
static_assert(offsetof(DeflateState, bl_desc)          == 0xB30);
static_assert(offsetof(DeflateState, bl_count)         == 0xB3C);
static_assert(offsetof(DeflateState, heap)             == 0xB5C);
static_assert(offsetof(DeflateState, heap_len)         == 0x1450);
static_assert(offsetof(DeflateState, heap_max)         == 0x1454);
static_assert(offsetof(DeflateState, depth)            == 0x1458);
static_assert(offsetof(DeflateState, l_buf)            == 0x1698);
static_assert(offsetof(DeflateState, lit_bufsize)      == 0x169C);
static_assert(offsetof(DeflateState, last_lit)         == 0x16A0);
static_assert(offsetof(DeflateState, d_buf)            == 0x16A4);
static_assert(offsetof(DeflateState, opt_len)          == 0x16A8);
static_assert(offsetof(DeflateState, static_len)       == 0x16AC);
static_assert(offsetof(DeflateState, matches)          == 0x16B0);
static_assert(offsetof(DeflateState, last_eob_len)     == 0x16B4);
static_assert(offsetof(DeflateState, bi_buf)           == 0x16B8);
static_assert(offsetof(DeflateState, bi_valid)         == 0x16BC);
static_assert(sizeof(DeflateState) == 0x16C0, "zlib::DeflateState must be 0x16C0 bytes");

// -----------------------------------------------------------------------------
// deflate compression configuration table (trees.c config_table[10]).
// Each entry {good_length, max_lazy, nice_length, max_chain, func}. Byte-verified
// against ForgedAlliance.exe .rodata at VA 0xD4A440 (12-byte stride; lm_init
// FUN_0095B7D0.asm indexes it with imul-by-12). The func pointers in the binary
// are deflate_stored(L0), deflate_fast(L1..3), deflate_slow(L4..9); we carry the
// numeric fields and dispatch on level in the driver.
// -----------------------------------------------------------------------------
struct DeflateConfig
{
  std::uint16_t good_length;  // reduce lazy search above this match length
  std::uint16_t max_lazy;     // do not perform lazy search above this length
  std::uint16_t nice_length;  // quit search above this match length
  std::uint16_t max_chain;    // max hash-chain probes
};

inline constexpr DeflateConfig kConfigurationTable[10] = {
    /* 0 */ {0, 0, 0, 0},           // store only
    /* 1 */ {4, 4, 8, 4},           // max speed, no lazy matches
    /* 2 */ {4, 5, 16, 8},
    /* 3 */ {4, 6, 32, 32},
    /* 4 */ {4, 4, 16, 16},         // lazy matches
    /* 5 */ {8, 16, 32, 32},
    /* 6 */ {8, 16, 128, 128},
    /* 7 */ {8, 32, 128, 256},
    /* 8 */ {32, 128, 258, 1024},
    /* 9 */ {32, 258, 258, 4096},   // max compression
};

// -----------------------------------------------------------------------------
// Static Huffman trees + code tables (trees.c). All byte-verified against
// ForgedAlliance.exe .rodata at the addresses the recovered bodies reference
// via `mov ...,offset`.
//   static_ltree @0xD4C7E8  static_dtree @0xD4CC68
//   extra_lbits  @0xD4C698  extra_dbits  @0xD4C720  extra_blbits @0xD4C798
//   base_length  @0xD4CFE0  base_dist    @0xD4D058  bl_order     @0xD4C70C
//   _length_code @0xD4CEE0  _dist_code   @0xD4CCE0
// -----------------------------------------------------------------------------

inline constexpr int kExtraLBits[kLengthCodes] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
inline constexpr int kExtraDBits[kDCodes] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
inline constexpr int kExtraBlBits[kBlCodes] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7};

inline constexpr int kBaseLength[kLengthCodes] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28,
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 0};
inline constexpr int kBaseDist[kDCodes] = {
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192,
    256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288,
    16384, 24576};

// Permutation of the bit-length code lengths (trees.c bl_order[19]).
inline constexpr std::uint8_t kBlOrder[kBlCodes] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// Distance -> distance-code map (_dist_code[512]; only [0..255] direct, the
// rest indexed as _dist_code[256 + (dist>>7)]). Byte-verified @0xD4CCE0.
inline constexpr std::uint8_t kDistCode[512] = {
     0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
     8,  8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
     0,  0, 16, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29};

// Length (0..255 of match-3) -> length-code map (_length_code[256]).
// Byte-verified @0xD4CEE0.
inline constexpr std::uint8_t kLengthCode[kMaxMatch - kMinMatch + 1] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9, 10, 10, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17,
    18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19,
    20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28};

// static_ltree[288] {code, bit-length}. Byte-verified @0xD4C7E8.
inline constexpr CtData kStaticLTree[kLCodes + 2] = {
    { 12,8},{140,8},{ 76,8},{204,8},{ 44,8},{172,8},{108,8},{236,8},
    { 28,8},{156,8},{ 92,8},{220,8},{ 60,8},{188,8},{124,8},{252,8},
    {  2,8},{130,8},{ 66,8},{194,8},{ 34,8},{162,8},{ 98,8},{226,8},
    { 18,8},{146,8},{ 82,8},{210,8},{ 50,8},{178,8},{114,8},{242,8},
    { 10,8},{138,8},{ 74,8},{202,8},{ 42,8},{170,8},{106,8},{234,8},
    { 26,8},{154,8},{ 90,8},{218,8},{ 58,8},{186,8},{122,8},{250,8},
    {  6,8},{134,8},{ 70,8},{198,8},{ 38,8},{166,8},{102,8},{230,8},
    { 22,8},{150,8},{ 86,8},{214,8},{ 54,8},{182,8},{118,8},{246,8},
    { 14,8},{142,8},{ 78,8},{206,8},{ 46,8},{174,8},{110,8},{238,8},
    { 30,8},{158,8},{ 94,8},{222,8},{ 62,8},{190,8},{126,8},{254,8},
    {  1,8},{129,8},{ 65,8},{193,8},{ 33,8},{161,8},{ 97,8},{225,8},
    { 17,8},{145,8},{ 81,8},{209,8},{ 49,8},{177,8},{113,8},{241,8},
    {  9,8},{137,8},{ 73,8},{201,8},{ 41,8},{169,8},{105,8},{233,8},
    { 25,8},{153,8},{ 89,8},{217,8},{ 57,8},{185,8},{121,8},{249,8},
    {  5,8},{133,8},{ 69,8},{197,8},{ 37,8},{165,8},{101,8},{229,8},
    { 21,8},{149,8},{ 85,8},{213,8},{ 53,8},{181,8},{117,8},{245,8},
    { 13,8},{141,8},{ 77,8},{205,8},{ 45,8},{173,8},{109,8},{237,8},
    { 29,8},{157,8},{ 93,8},{221,8},{ 61,8},{189,8},{125,8},{253,8},
    { 19,9},{275,9},{147,9},{403,9},{ 83,9},{339,9},{211,9},{467,9},
    { 51,9},{307,9},{179,9},{435,9},{115,9},{371,9},{243,9},{499,9},
    { 11,9},{267,9},{139,9},{395,9},{ 75,9},{331,9},{203,9},{459,9},
    { 43,9},{299,9},{171,9},{427,9},{107,9},{363,9},{235,9},{491,9},
    { 27,9},{283,9},{155,9},{411,9},{ 91,9},{347,9},{219,9},{475,9},
    { 59,9},{315,9},{187,9},{443,9},{123,9},{379,9},{251,9},{507,9},
    {  7,9},{263,9},{135,9},{391,9},{ 71,9},{327,9},{199,9},{455,9},
    { 39,9},{295,9},{167,9},{423,9},{103,9},{359,9},{231,9},{487,9},
    { 23,9},{279,9},{151,9},{407,9},{ 87,9},{343,9},{215,9},{471,9},
    { 55,9},{311,9},{183,9},{439,9},{119,9},{375,9},{247,9},{503,9},
    { 15,9},{271,9},{143,9},{399,9},{ 79,9},{335,9},{207,9},{463,9},
    { 47,9},{303,9},{175,9},{431,9},{111,9},{367,9},{239,9},{495,9},
    { 31,9},{287,9},{159,9},{415,9},{ 95,9},{351,9},{223,9},{479,9},
    { 63,9},{319,9},{191,9},{447,9},{127,9},{383,9},{255,9},{511,9},
    {  0,7},{ 64,7},{ 32,7},{ 96,7},{ 16,7},{ 80,7},{ 48,7},{112,7},
    {  8,7},{ 72,7},{ 40,7},{104,7},{ 24,7},{ 88,7},{ 56,7},{120,7},
    {  4,7},{ 68,7},{ 36,7},{100,7},{ 20,7},{ 84,7},{ 52,7},{116,7},
    {  3,8},{131,8},{ 67,8},{195,8},{ 35,8},{163,8},{ 99,8},{227,8}};

// static_dtree[30] {code, bit-length}. Byte-verified @0xD4CC68.
inline constexpr CtData kStaticDTree[kDCodes] = {
    { 0,5},{16,5},{ 8,5},{24,5},{ 4,5},{20,5},{12,5},{28,5},
    { 2,5},{18,5},{10,5},{26,5},{ 6,5},{22,5},{14,5},{30,5},
    { 1,5},{17,5},{ 9,5},{25,5},{ 5,5},{21,5},{13,5},{29,5},
    { 3,5},{19,5},{11,5},{27,5},{ 7,5},{23,5}};

// Static tree descriptors. Byte-verified @0xF32D78/0xF32D8C/0xF32DA0.
inline constexpr StaticTreeDesc kStaticLDesc = {
    kStaticLTree, kExtraLBits, kLiterals + 1, kLCodes, kMaxBitsDeflate};
inline constexpr StaticTreeDesc kStaticDDesc = {
    kStaticDTree, kExtraDBits, 0, kDCodes, kMaxBitsDeflate};
inline constexpr StaticTreeDesc kStaticBlDesc = {
    nullptr, kExtraBlBits, 0, kBlCodes, 7};

} // namespace zlib
