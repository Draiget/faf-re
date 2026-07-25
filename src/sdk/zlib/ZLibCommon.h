#pragma once

// Shared zlib 1.2.x public/stream types recovered from ForgedAlliance.exe's
// statically linked zlib. Field offsets verified from the zlib leaf bodies'
// .asm displacements (the IDA decompiler mislabels the internal_state structs).
//
// NOTE: src/sdk/zlib/ZLibInflate.h currently carries its own copy of ZStream
// from an earlier pass; it will be reduced to include this header so ZStream has
// a single owning definition (duplicate-layout reconciliation).

#include <cstddef>
#include <cstdint>

namespace zlib {

// zlib z_stream_s (public stream head, 56 bytes). state is the opaque
// internal_state* (an InflateState or DeflateState depending on direction).
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
static_assert(offsetof(ZStream, zfree)     == 0x24);
static_assert(offsetof(ZStream, opaque)    == 0x28);
static_assert(offsetof(ZStream, adler)     == 0x30);
static_assert(sizeof(ZStream) == 0x38, "zlib::ZStream must be 56 bytes");

// zlib allocator callback ABI (z_stream zalloc/zfree).
using AllocFunc = void* (*)(void* opaque, unsigned int items, unsigned int size);
using FreeFunc  = void  (*)(void* opaque, void* address);

// zlib return codes.
constexpr int kZOk           = 0;
constexpr int kZStreamEnd    = 1;
constexpr int kZNeedDict     = 2;
constexpr int kZStreamError  = -2;
constexpr int kZDataError    = -3;
constexpr int kZMemError     = -4;
constexpr int kZBufError     = -5;
constexpr int kZVersionError = -6;

} // namespace zlib
