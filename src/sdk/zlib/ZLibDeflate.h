#pragma once

// zlib 1.2.x deflate types, recovered from ForgedAlliance.exe's statically
// linked zlib. Field offsets verified from the deflate leaf bodies' .asm
// displacements (the IDA decompiler mislabels this struct). Only the fields
// touched by recovered code are named so far; the deflate family will extend
// this as more of the direction is recovered.

#include <cstddef>
#include <cstdint>

#include "zlib/ZLibCommon.h"

namespace zlib {

// deflate status values (deflate_state.status). Verified from the deflateEnd
// validity check in FUN_0095B4E0.asm.
constexpr int kDeflateInitState    = 42;   // INIT_STATE
constexpr int kDeflateExtraState   = 69;   // EXTRA_STATE
constexpr int kDeflateNameState    = 73;   // NAME_STATE
constexpr int kDeflateCommentState = 91;   // COMMENT_STATE
constexpr int kDeflateHcrcState    = 103;  // HCRC_STATE
constexpr int kDeflateBusyState    = 113;  // BUSY_STATE
constexpr int kDeflateFinishState  = 666;  // FINISH_STATE

// zlib deflate_state (internal_state for the deflate direction). Partial: only
// the leading control fields and the four heap buffers that deflateEnd frees are
// named; offsets verified from FUN_0095B4E0.asm ([state+4]=status,
// [state+8]=pending_buf, [state+0x38]=window, [state+0x40]=prev, [state+0x44]=head).
struct DeflateState
{
  void*          strm;        // +0x00  back-pointer to the owning z_stream
  std::int32_t   status;      // +0x04  as the low-level state machine sees it
  std::uint8_t*  pending_buf; // +0x08  output still to be emitted
  std::uint8_t   pad_0C_to_38[0x38 - 0x0C];  // +0x0C  (pending_buf_size, wrap, w_size, ...)
  std::uint8_t*  window;      // +0x38  the sliding window
  std::uint8_t   pad_3C_to_40[0x04];         // +0x3C  (window_size)
  std::uint16_t* prev;        // +0x40  linked list of previous string positions
  std::uint16_t* head;        // +0x44  head of the hash chains
};

static_assert(offsetof(DeflateState, status)      == 0x04);
static_assert(offsetof(DeflateState, pending_buf) == 0x08);
static_assert(offsetof(DeflateState, window)      == 0x38);
static_assert(offsetof(DeflateState, prev)        == 0x40);
static_assert(offsetof(DeflateState, head)        == 0x44);

} // namespace zlib
