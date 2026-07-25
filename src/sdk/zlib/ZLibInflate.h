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

// zlib inflate_mode (this build): zero-based, HEAD first.
enum InflateMode : std::int32_t { kInflateModeHead = 0 };

// zlib inflate_state (internal_state for the inflate direction). Only the fields
// touched by recovered code are named; the rest are covered by the trailing
// lens/work/codes arrays. Offsets verified against inflateReset FUN_00958DC0.asm.
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
  void*          head;        // +0x20  gz_headerp
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
static_assert(offsetof(InflateState, havedict) == 0x0C);
static_assert(offsetof(InflateState, dmax)     == 0x14);
static_assert(offsetof(InflateState, total)    == 0x1C);
static_assert(offsetof(InflateState, head)     == 0x20);
static_assert(offsetof(InflateState, wsize)    == 0x28);
static_assert(offsetof(InflateState, whave)    == 0x2C);
static_assert(offsetof(InflateState, wnext)    == 0x30);
static_assert(offsetof(InflateState, hold)     == 0x38);
static_assert(offsetof(InflateState, bits)     == 0x3C);
static_assert(offsetof(InflateState, lencode)  == 0x4C);
static_assert(offsetof(InflateState, distcode) == 0x50);
static_assert(offsetof(InflateState, next)     == 0x6C);
static_assert(offsetof(InflateState, lens)     == 0x70);
static_assert(offsetof(InflateState, work)     == 0x2F0);
static_assert(offsetof(InflateState, codes)    == 0x530);

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

// zlib return codes used by the recovered inflate leaves.
constexpr int kZOk           = 0;
constexpr int kZStreamError  = -2;

} // namespace zlib
