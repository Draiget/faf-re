#pragma once

// zlib 1.2.x inflate types, recovered from ForgedAlliance.exe's statically
// linked zlib. Field offsets verified from the inflate leaf bodies
// (inflateReset FUN_00958DC0, etc.) — the .asm displacement of each write is
// the ground truth (the IDA decompiler mislabels this struct with deflate_state
// field names).
//
// This build predates the HEAD=16180 magic-base cookie (zlib 1.2.4+), so the
// inflate_mode enum is plain zero-based: HEAD == 0.

#include <cstddef>
#include <cstdint>

namespace zlib {

// One entry of a Huffman decoding table (zlib `code`, 4 bytes).
struct Code
{
  std::uint8_t  op;    // operation, extra bits, table bits
  std::uint8_t  bits;  // bits in this part of the code
  std::uint16_t val;   // offset in table or code value
};
static_assert(sizeof(Code) == 4, "zlib::Code must be 4 bytes");

// zlib inflate_mode (this build): zero-based, HEAD first. This build predates
// the HEAD=16180 magic-base cookie (zlib 1.2.4+), so the enum is plain
// zero-based. The exact integer of each mode is fixed by the HEAD=0 base and
// confirmed against inflate's main dispatch jump table (jpt_959104, 29 entries
// for modes 0..28) in FUN_00959070.asm — e.g. the reset ``if (mode == TYPE)
// mode = TYPEDO`` at the top pins TYPE=11/TYPEDO=12, and every ``mov [state],N``
// state transition in the .asm matches the ordering below. SYNC=29 and any
// larger value fall through the table's default arm.
enum InflateMode : std::int32_t
{
  kModeHead     = 0,   // i: waiting for magic header
  kModeFlags    = 1,   // i: waiting for method and flags (gzip)
  kModeTime     = 2,   // i: waiting for modification time (gzip)
  kModeOs       = 3,   // i: waiting for extra flags and operating system (gzip)
  kModeExlen    = 4,   // i: waiting for extra length (gzip)
  kModeExtra    = 5,   // i: waiting for extra bytes (gzip)
  kModeName     = 6,   // i: waiting for end of file name (gzip)
  kModeComment  = 7,   // i: waiting for end of comment (gzip)
  kModeHcrc     = 8,   // i: waiting for header crc (gzip)
  kModeDictid   = 9,   // i: waiting for dictionary check value
  kModeDict     = 10,  // waiting for inflateSetDictionary() call
  kModeType     = 11,  // i: waiting for type bits, including last-flag bit
  kModeTypedo   = 12,  // i: same, but skip check to exit inflate on new block
  kModeStored   = 13,  // i: waiting for stored size (length and complement)
  kModeCopy     = 14,  // i/o: waiting for input or output to copy stored block
  kModeTable    = 15,  // i: waiting for dynamic block table lengths
  kModeLenlens  = 16,  // i: waiting for code length code lengths
  kModeCodelens = 17,  // i: waiting for length/lit and distance code lengths
  kModeLen      = 18,  // i: waiting for length/lit code
  kModeLenext   = 19,  // i: waiting for length extra bits
  kModeDist     = 20,  // i: waiting for distance code
  kModeDistext  = 21,  // i: waiting for distance extra bits
  kModeMatch    = 22,  // o: waiting for output space to copy string
  kModeLit      = 23,  // o: waiting for output space to write literal
  kModeCheck    = 24,  // i: waiting for 32-bit check value
  kModeLength   = 25,  // i: waiting for 32-bit length (gzip)
  kModeDone     = 26,  // finished check, done -- remain here until reset
  kModeBad      = 27,  // got a data error -- remain here until reset
  kModeMem      = 28,  // got an inflate() memory error -- remain here until reset
  kModeSync     = 29,  // looking for synchronization bytes to restart inflate()
};

// Back-compatibility alias for the pre-extension name.
constexpr InflateMode kInflateModeHead = kModeHead;

// zlib inftrees.c code-table selector (the `type` argument of inflate_table).
// Confirmed from inflate's three call sites: inflate_table(CODES,...) for the
// code-length code, then (LENS,...) for literal/length, then (DISTS,...) for
// distance codes (FUN_00959070.asm at 0x009599xx..0x00959A2x).
enum CodeType : std::int32_t
{
  kCodeTypeCodes = 0,
  kCodeTypeLens  = 1,
  kCodeTypeDists = 2,
};

// zlib gz_header (zlib.h): the optional gzip header a caller can request via
// inflateGetHeader. inflate's HEAD..HCRC gzip modes fill these fields; every
// offset here is confirmed against the gzip-header stores in FUN_00959070.asm
// (head at state+0x20; e.g. +0x10 extra ptr, +0x14 extra_len, +0x18 extra_max,
// +0x1C name ptr, +0x20 name_max, +0x24 comment ptr, +0x28 comm_max, +0x2C
// hcrc, +0x30 done).
struct GzHeader
{
  std::int32_t   text;       // +0x00 true if compressed data believed to be text
  std::uint32_t  time;       // +0x04 modification time
  std::int32_t   xflags;     // +0x08 extra flags (not used when writing)
  std::int32_t   os;         // +0x0C operating system
  std::uint8_t*  extra;      // +0x10 pointer to extra field or nullptr
  std::uint32_t  extra_len;  // +0x14 extra field length (valid if extra != null)
  std::uint32_t  extra_max;  // +0x18 space at extra (only when reading)
  std::uint8_t*  name;       // +0x1C pointer to zero-terminated file name or null
  std::uint32_t  name_max;   // +0x20 space at name (only when reading)
  std::uint8_t*  comment;    // +0x24 pointer to zero-terminated comment or null
  std::uint32_t  comm_max;   // +0x28 space at comment (only when reading)
  std::int32_t   hcrc;       // +0x2C true if there was or will be a header crc
  std::int32_t   done;       // +0x30 true when done reading gzip header
};

static_assert(offsetof(GzHeader, extra)     == 0x10);
static_assert(offsetof(GzHeader, extra_len) == 0x14);
static_assert(offsetof(GzHeader, name)      == 0x1C);
static_assert(offsetof(GzHeader, comment)   == 0x24);
static_assert(offsetof(GzHeader, done)      == 0x30);

// zlib inflate_state (internal_state for the inflate direction). Only the fields
// touched by recovered code are named; the rest are covered by the trailing
// lens/work/codes arrays. Offsets verified against inflateReset FUN_00958DC0.asm
// and every state displacement in FUN_00959070.asm (all fall inside 0x00..0x70
// plus the arrays — this build has no separate sane/back/was fields).
struct InflateState
{
  std::int32_t   mode;        // +0x00  current inflate mode (HEAD=0 at reset)
  std::int32_t   last;        // +0x04  true if processing last block
  std::int32_t   wrap;        // +0x08  bit0 zlib, bit1 gzip
  std::int32_t   havedict;    // +0x0C  true if dictionary provided
  std::int32_t   flags;       // +0x10  gzip header method/flags
  std::uint32_t  dmax;        // +0x14  zlib header max distance (32768 at reset)
  std::uint32_t  check;       // +0x18  protected copy of check value
  std::uint32_t  total;       // +0x1C  protected copy of output count
  GzHeader*      head;        // +0x20  gz_headerp (optional gzip header sink)
  std::uint32_t  wbits;       // +0x24  log2 window size
  std::uint32_t  wsize;       // +0x28  window size (0 if unused)
  std::uint32_t  whave;       // +0x2C  valid bytes in window
  std::uint32_t  wnext;       // +0x30  window write index
  std::uint8_t*  window;      // +0x34  allocated sliding window
  std::uint32_t  hold;        // +0x38  input bit accumulator
  std::uint32_t  bits;        // +0x3C  number of bits in hold
  std::uint32_t  length;      // +0x40  literal or copy length
  std::uint32_t  offset;      // +0x44  distance back to copy from
  std::uint32_t  extra;       // +0x48  extra bits needed
  const Code*    lencode;     // +0x4C  starting table for length/literal codes
  const Code*    distcode;    // +0x50  starting table for distance codes
  std::uint32_t  lenbits;     // +0x54  index bits for lencode
  std::uint32_t  distbits;    // +0x58  index bits for distcode
  std::uint32_t  ncode;       // +0x5C  number of code-length code lengths
  std::uint32_t  nlen;        // +0x60  number of length code lengths
  std::uint32_t  ndist;       // +0x64  number of distance code lengths
  std::uint32_t  have;        // +0x68  number of code lengths in lens[]
  Code*          next;        // +0x6C  next available space in codes[]
  std::uint16_t  lens[320];   // +0x70  temporary code-length storage
  std::uint16_t  work[288];   // +0x2F0 work area for table building
  Code           codes[2048]; // +0x530 space for code tables (ENOUGH = 2048)
};

static_assert(offsetof(InflateState, mode)     == 0x00);
static_assert(offsetof(InflateState, last)     == 0x04);
static_assert(offsetof(InflateState, wrap)     == 0x08);
static_assert(offsetof(InflateState, havedict) == 0x0C);
static_assert(offsetof(InflateState, flags)    == 0x10);
static_assert(offsetof(InflateState, dmax)     == 0x14);
static_assert(offsetof(InflateState, check)    == 0x18);
static_assert(offsetof(InflateState, total)    == 0x1C);
static_assert(offsetof(InflateState, head)     == 0x20);
static_assert(offsetof(InflateState, wbits)    == 0x24);
static_assert(offsetof(InflateState, wsize)    == 0x28);
static_assert(offsetof(InflateState, whave)    == 0x2C);
static_assert(offsetof(InflateState, wnext)    == 0x30);
static_assert(offsetof(InflateState, window)   == 0x34);
static_assert(offsetof(InflateState, hold)     == 0x38);
static_assert(offsetof(InflateState, bits)     == 0x3C);
static_assert(offsetof(InflateState, length)   == 0x40);
static_assert(offsetof(InflateState, offset)   == 0x44);
static_assert(offsetof(InflateState, extra)    == 0x48);
static_assert(offsetof(InflateState, lencode)  == 0x4C);
static_assert(offsetof(InflateState, distcode) == 0x50);
static_assert(offsetof(InflateState, lenbits)  == 0x54);
static_assert(offsetof(InflateState, distbits) == 0x58);
static_assert(offsetof(InflateState, ncode)    == 0x5C);
static_assert(offsetof(InflateState, nlen)     == 0x60);
static_assert(offsetof(InflateState, ndist)    == 0x64);
static_assert(offsetof(InflateState, have)     == 0x68);
static_assert(offsetof(InflateState, next)     == 0x6C);
static_assert(offsetof(InflateState, lens)     == 0x70);
static_assert(offsetof(InflateState, work)     == 0x2F0);
static_assert(offsetof(InflateState, codes)    == 0x530);
static_assert(sizeof(InflateState) == 0x2530, "zlib::InflateState must be 0x2530 bytes");

// zlib z_stream_s (public stream head, 56 bytes). state is the opaque
// internal_state* (points at an InflateState for the inflate direction).
struct ZStream
{
  std::uint8_t*  next_in;    // +0x00
  std::uint32_t  avail_in;   // +0x04
  std::uint32_t  total_in;   // +0x08
  std::uint8_t*  next_out;   // +0x0C
  std::uint32_t  avail_out;  // +0x10
  std::uint32_t  total_out;  // +0x14
  char*          msg;        // +0x18
  void*          state;      // +0x1C  internal_state*
  void*          zalloc;     // +0x20  alloc_func
  void*          zfree;      // +0x24  free_func
  void*          opaque;     // +0x28
  std::int32_t   data_type;  // +0x2C
  std::uint32_t  adler;      // +0x30
  std::uint32_t  reserved;   // +0x34
};

static_assert(offsetof(ZStream, total_in)  == 0x08);
static_assert(offsetof(ZStream, total_out) == 0x14);
static_assert(offsetof(ZStream, msg)       == 0x18);
static_assert(offsetof(ZStream, state)     == 0x1C);
static_assert(offsetof(ZStream, adler)     == 0x30);
static_assert(sizeof(ZStream) == 0x38, "zlib::ZStream must be 56 bytes");

// zlib allocator callback ABI (z_stream zalloc/zfree).
using AllocFunc = void* (*)(void* opaque, unsigned int items, unsigned int size);
using FreeFunc  = void  (*)(void* opaque, void* address);

// zlib return codes (zlib.h). Values confirmed from the literal returns in
// FUN_00959070.asm (e.g. mov eax,1 = Z_STREAM_END, mov eax,0FFFFFFFBh = -5).
constexpr int kZOk           = 0;
constexpr int kZStreamEnd    = 1;
constexpr int kZNeedDict     = 2;
constexpr int kZErrno        = -1;
constexpr int kZStreamError  = -2;
constexpr int kZDataError    = -3;
constexpr int kZMemError     = -4;
constexpr int kZBufError     = -5;
constexpr int kZVersionError = -6;

// zlib flush values (zlib.h). inflate only distinguishes Z_FINISH (==4) and
// Z_BLOCK (==5) from the rest; those two literals appear in FUN_00959070.asm
// (cmp flush,4 / cmp flush,5).
constexpr int kZNoFlush      = 0;
constexpr int kZPartialFlush = 1;
constexpr int kZSyncFlush    = 2;
constexpr int kZFullFlush    = 3;
constexpr int kZFinish       = 4;
constexpr int kZBlock        = 5;
constexpr int kZTrees        = 6;

// libpng passes DEF_WBITS (15) through inflateInit_.
constexpr int kZDefaultWindowBits = 15;

// zlib inftrees.c limits. This (pre-1.2.3) build carries a single ENOUGH bound
// that only the LENS table build is checked against: inflate_table returns 1
// (over-subscribed) when a LENS build would use >= 1456 (0x5B0) code slots
// (FUN_0095CEC0.asm at 0x0095D135 and 0x0095D2C7, both gated on type == LENS).
// The state's codes[] array is oversized to 2048 entries (matches the 0x2000-
// byte codes region of the 0x2530-byte inflate_state).
constexpr unsigned int kEnoughCodes  = 1456;  // ENOUGH bound checked for LENS
constexpr unsigned int kMaxBits      = 15;    // maximum code length in bits

// inftrees.c static base/extra tables (zlib 1.2.x). Byte-verified against
// ForgedAlliance.exe .rodata: lbase @VA 0xD4A598, lext @0xD4A5D8, dbase
// @0xD4A618, dext @0xD4A658 (inflate_table loads these via `mov ...,offset`
// at FUN_0095CEC0.asm 0x0095D0B8..0x0095D0DC). lbase/lext are indexed from 257
// (length codes 257..285); dbase/dext from 0. The trailing two lext slots
// (28,29,30 -> 16,201,196) are the binary's exact padding bytes — only indices
// 0..28 are ever read, so 201/196 differ harmlessly from stock zlib's 77/68.
inline constexpr std::uint16_t kLenBase[31] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
inline constexpr std::uint16_t kLenExt[31] = {
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
    19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 201, 196};
inline constexpr std::uint16_t kDistBase[32] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
    16385, 24577, 0, 0};
inline constexpr std::uint16_t kDistExt[32] = {
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
    23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 64, 64};

// Permutation of code-length code lengths (zlib inflate.c `order[19]`).
// Byte-verified against ForgedAlliance.exe .rodata at VA 0xD4A220
// (FUN_00959070.asm reads it as word_D4A220 while filling lens[] in TABLE mode).
inline constexpr std::uint16_t kCodeLengthOrder[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// Precomputed fixed Huffman decode tables (zlib inffixed.h). For a fixed block
// inflate points lencode -> kLenFix (lenbits 9) and distcode -> kDistFix
// (distbits 5). Byte-verified against ForgedAlliance.exe .rodata: lenfix @VA
// 0xD499A0 (512 Code entries) and distfix @0xD4A1A0 (32 Code entries), the two
// addresses FUN_00959070.asm stores at 0x0095988F/0x0095989D.
inline constexpr Code kLenFix[512] = {
    {96,7,0}, {0,8,80}, {0,8,16}, {20,8,115}, {18,7,31}, {0,8,112},
    {0,8,48}, {0,9,192}, {16,7,10}, {0,8,96}, {0,8,32}, {0,9,160},
    {0,8,0}, {0,8,128}, {0,8,64}, {0,9,224}, {16,7,6}, {0,8,88},
    {0,8,24}, {0,9,144}, {19,7,59}, {0,8,120}, {0,8,56}, {0,9,208},
    {17,7,17}, {0,8,104}, {0,8,40}, {0,9,176}, {0,8,8}, {0,8,136},
    {0,8,72}, {0,9,240}, {16,7,4}, {0,8,84}, {0,8,20}, {21,8,227},
    {19,7,43}, {0,8,116}, {0,8,52}, {0,9,200}, {17,7,13}, {0,8,100},
    {0,8,36}, {0,9,168}, {0,8,4}, {0,8,132}, {0,8,68}, {0,9,232},
    {16,7,8}, {0,8,92}, {0,8,28}, {0,9,152}, {20,7,83}, {0,8,124},
    {0,8,60}, {0,9,216}, {18,7,23}, {0,8,108}, {0,8,44}, {0,9,184},
    {0,8,12}, {0,8,140}, {0,8,76}, {0,9,248}, {16,7,3}, {0,8,82},
    {0,8,18}, {21,8,163}, {19,7,35}, {0,8,114}, {0,8,50}, {0,9,196},
    {17,7,11}, {0,8,98}, {0,8,34}, {0,9,164}, {0,8,2}, {0,8,130},
    {0,8,66}, {0,9,228}, {16,7,7}, {0,8,90}, {0,8,26}, {0,9,148},
    {20,7,67}, {0,8,122}, {0,8,58}, {0,9,212}, {18,7,19}, {0,8,106},
    {0,8,42}, {0,9,180}, {0,8,10}, {0,8,138}, {0,8,74}, {0,9,244},
    {16,7,5}, {0,8,86}, {0,8,22}, {64,8,0}, {19,7,51}, {0,8,118},
    {0,8,54}, {0,9,204}, {17,7,15}, {0,8,102}, {0,8,38}, {0,9,172},
    {0,8,6}, {0,8,134}, {0,8,70}, {0,9,236}, {16,7,9}, {0,8,94},
    {0,8,30}, {0,9,156}, {20,7,99}, {0,8,126}, {0,8,62}, {0,9,220},
    {18,7,27}, {0,8,110}, {0,8,46}, {0,9,188}, {0,8,14}, {0,8,142},
    {0,8,78}, {0,9,252}, {96,7,0}, {0,8,81}, {0,8,17}, {21,8,131},
    {18,7,31}, {0,8,113}, {0,8,49}, {0,9,194}, {16,7,10}, {0,8,97},
    {0,8,33}, {0,9,162}, {0,8,1}, {0,8,129}, {0,8,65}, {0,9,226},
    {16,7,6}, {0,8,89}, {0,8,25}, {0,9,146}, {19,7,59}, {0,8,121},
    {0,8,57}, {0,9,210}, {17,7,17}, {0,8,105}, {0,8,41}, {0,9,178},
    {0,8,9}, {0,8,137}, {0,8,73}, {0,9,242}, {16,7,4}, {0,8,85},
    {0,8,21}, {16,8,258}, {19,7,43}, {0,8,117}, {0,8,53}, {0,9,202},
    {17,7,13}, {0,8,101}, {0,8,37}, {0,9,170}, {0,8,5}, {0,8,133},
    {0,8,69}, {0,9,234}, {16,7,8}, {0,8,93}, {0,8,29}, {0,9,154},
    {20,7,83}, {0,8,125}, {0,8,61}, {0,9,218}, {18,7,23}, {0,8,109},
    {0,8,45}, {0,9,186}, {0,8,13}, {0,8,141}, {0,8,77}, {0,9,250},
    {16,7,3}, {0,8,83}, {0,8,19}, {21,8,195}, {19,7,35}, {0,8,115},
    {0,8,51}, {0,9,198}, {17,7,11}, {0,8,99}, {0,8,35}, {0,9,166},
    {0,8,3}, {0,8,131}, {0,8,67}, {0,9,230}, {16,7,7}, {0,8,91},
    {0,8,27}, {0,9,150}, {20,7,67}, {0,8,123}, {0,8,59}, {0,9,214},
    {18,7,19}, {0,8,107}, {0,8,43}, {0,9,182}, {0,8,11}, {0,8,139},
    {0,8,75}, {0,9,246}, {16,7,5}, {0,8,87}, {0,8,23}, {64,8,0},
    {19,7,51}, {0,8,119}, {0,8,55}, {0,9,206}, {17,7,15}, {0,8,103},
    {0,8,39}, {0,9,174}, {0,8,7}, {0,8,135}, {0,8,71}, {0,9,238},
    {16,7,9}, {0,8,95}, {0,8,31}, {0,9,158}, {20,7,99}, {0,8,127},
    {0,8,63}, {0,9,222}, {18,7,27}, {0,8,111}, {0,8,47}, {0,9,190},
    {0,8,15}, {0,8,143}, {0,8,79}, {0,9,254}, {96,7,0}, {0,8,80},
    {0,8,16}, {20,8,115}, {18,7,31}, {0,8,112}, {0,8,48}, {0,9,193},
    {16,7,10}, {0,8,96}, {0,8,32}, {0,9,161}, {0,8,0}, {0,8,128},
    {0,8,64}, {0,9,225}, {16,7,6}, {0,8,88}, {0,8,24}, {0,9,145},
    {19,7,59}, {0,8,120}, {0,8,56}, {0,9,209}, {17,7,17}, {0,8,104},
    {0,8,40}, {0,9,177}, {0,8,8}, {0,8,136}, {0,8,72}, {0,9,241},
    {16,7,4}, {0,8,84}, {0,8,20}, {21,8,227}, {19,7,43}, {0,8,116},
    {0,8,52}, {0,9,201}, {17,7,13}, {0,8,100}, {0,8,36}, {0,9,169},
    {0,8,4}, {0,8,132}, {0,8,68}, {0,9,233}, {16,7,8}, {0,8,92},
    {0,8,28}, {0,9,153}, {20,7,83}, {0,8,124}, {0,8,60}, {0,9,217},
    {18,7,23}, {0,8,108}, {0,8,44}, {0,9,185}, {0,8,12}, {0,8,140},
    {0,8,76}, {0,9,249}, {16,7,3}, {0,8,82}, {0,8,18}, {21,8,163},
    {19,7,35}, {0,8,114}, {0,8,50}, {0,9,197}, {17,7,11}, {0,8,98},
    {0,8,34}, {0,9,165}, {0,8,2}, {0,8,130}, {0,8,66}, {0,9,229},
    {16,7,7}, {0,8,90}, {0,8,26}, {0,9,149}, {20,7,67}, {0,8,122},
    {0,8,58}, {0,9,213}, {18,7,19}, {0,8,106}, {0,8,42}, {0,9,181},
    {0,8,10}, {0,8,138}, {0,8,74}, {0,9,245}, {16,7,5}, {0,8,86},
    {0,8,22}, {64,8,0}, {19,7,51}, {0,8,118}, {0,8,54}, {0,9,205},
    {17,7,15}, {0,8,102}, {0,8,38}, {0,9,173}, {0,8,6}, {0,8,134},
    {0,8,70}, {0,9,237}, {16,7,9}, {0,8,94}, {0,8,30}, {0,9,157},
    {20,7,99}, {0,8,126}, {0,8,62}, {0,9,221}, {18,7,27}, {0,8,110},
    {0,8,46}, {0,9,189}, {0,8,14}, {0,8,142}, {0,8,78}, {0,9,253},
    {96,7,0}, {0,8,81}, {0,8,17}, {21,8,131}, {18,7,31}, {0,8,113},
    {0,8,49}, {0,9,195}, {16,7,10}, {0,8,97}, {0,8,33}, {0,9,163},
    {0,8,1}, {0,8,129}, {0,8,65}, {0,9,227}, {16,7,6}, {0,8,89},
    {0,8,25}, {0,9,147}, {19,7,59}, {0,8,121}, {0,8,57}, {0,9,211},
    {17,7,17}, {0,8,105}, {0,8,41}, {0,9,179}, {0,8,9}, {0,8,137},
    {0,8,73}, {0,9,243}, {16,7,4}, {0,8,85}, {0,8,21}, {16,8,258},
    {19,7,43}, {0,8,117}, {0,8,53}, {0,9,203}, {17,7,13}, {0,8,101},
    {0,8,37}, {0,9,171}, {0,8,5}, {0,8,133}, {0,8,69}, {0,9,235},
    {16,7,8}, {0,8,93}, {0,8,29}, {0,9,155}, {20,7,83}, {0,8,125},
    {0,8,61}, {0,9,219}, {18,7,23}, {0,8,109}, {0,8,45}, {0,9,187},
    {0,8,13}, {0,8,141}, {0,8,77}, {0,9,251}, {16,7,3}, {0,8,83},
    {0,8,19}, {21,8,195}, {19,7,35}, {0,8,115}, {0,8,51}, {0,9,199},
    {17,7,11}, {0,8,99}, {0,8,35}, {0,9,167}, {0,8,3}, {0,8,131},
    {0,8,67}, {0,9,231}, {16,7,7}, {0,8,91}, {0,8,27}, {0,9,151},
    {20,7,67}, {0,8,123}, {0,8,59}, {0,9,215}, {18,7,19}, {0,8,107},
    {0,8,43}, {0,9,183}, {0,8,11}, {0,8,139}, {0,8,75}, {0,9,247},
    {16,7,5}, {0,8,87}, {0,8,23}, {64,8,0}, {19,7,51}, {0,8,119},
    {0,8,55}, {0,9,207}, {17,7,15}, {0,8,103}, {0,8,39}, {0,9,175},
    {0,8,7}, {0,8,135}, {0,8,71}, {0,9,239}, {16,7,9}, {0,8,95},
    {0,8,31}, {0,9,159}, {20,7,99}, {0,8,127}, {0,8,63}, {0,9,223},
    {18,7,27}, {0,8,111}, {0,8,47}, {0,9,191}, {0,8,15}, {0,8,143},
    {0,8,79}, {0,9,255}};
inline constexpr Code kDistFix[32] = {
    {16,5,1}, {23,5,257}, {19,5,17}, {27,5,4097}, {17,5,5}, {25,5,1025},
    {21,5,65}, {29,5,16385}, {16,5,3}, {24,5,513}, {20,5,33}, {28,5,8193},
    {18,5,9}, {26,5,2049}, {22,5,129}, {64,5,0}, {16,5,2}, {23,5,385},
    {19,5,25}, {27,5,6145}, {17,5,7}, {25,5,1537}, {21,5,97}, {29,5,24577},
    {16,5,4}, {24,5,769}, {20,5,49}, {28,5,12289}, {18,5,13}, {26,5,3073},
    {22,5,193}, {64,5,0}};

} // namespace zlib
