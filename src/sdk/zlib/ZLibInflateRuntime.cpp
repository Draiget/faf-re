// zlib inflate runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). These recovered bodies match the binary at their given
// addresses and override the library copies via .obj-before-.lib resolution;
// the recovered TU is ExcludedFromBuild (a source-faithful record verified
// per-TU) so it never conflicts with the shipping zlib.lib.

#include "zlib/ZLibInflate.h"

#include <cstdlib>

/**
 * Address: 0x00958DC0 (FUN_00958DC0)
 * Mangled: inflateReset
 *
 * IDA signature:
 * int __cdecl inflateReset(z_streamp strm);
 *
 * Resets an inflate stream to the start of a new inflate operation without
 * reallocating: clears the running counts and message, sets adler to 1, and
 * reinitialises the inflate_state (mode = HEAD, dmax = 32768, cleared window /
 * bit-accumulator / dictionary flags) and points lencode/distcode/next at the
 * state's own codes[] table. Returns Z_STREAM_ERROR for a null stream or state,
 * otherwise Z_OK. Verified 1:1 against FUN_00958DC0.asm (this build predates the
 * HEAD magic-base cookie, so HEAD == 0, and state->check is intentionally not
 * reset here).
 */
extern "C" int inflateReset(zlib::ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<InflateState*>(strm->state);

  strm->total_in  = 0;
  strm->total_out = 0;
  state->total    = 0;
  strm->msg       = nullptr;
  strm->adler     = 1;  // to support ill-conceived Java test suite

  state->mode     = kInflateModeHead;
  state->last     = 0;
  state->havedict = 0;
  state->dmax     = 32768u;
  state->head     = nullptr;
  state->wsize    = 0;
  state->whave    = 0;
  state->wnext    = 0;
  state->hold     = 0;
  state->bits     = 0;
  state->lencode  = state->codes;
  state->distcode = state->codes;
  state->next     = state->codes;

  return kZOk;
}

/**
 * Address: 0x0095A670 (FUN_0095A670)
 * Mangled: inflateEnd
 *
 * IDA signature:
 * int __cdecl inflateEnd(z_streamp strm);
 *
 * Releases an inflate stream: frees the sliding window (if allocated) and the
 * inflate_state itself through the stream's zfree callback, then nulls
 * strm->state. Returns Z_STREAM_ERROR for a null stream, a null state, or a
 * missing zfree callback; otherwise Z_OK. Verified 1:1 against FUN_0095A670.asm
 * (all three guards precede any free; the freed pointer the IDA decompiler calls
 * `state->w_mask` is state->window at +0x34).
 */
extern "C" int inflateEnd(zlib::ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr || strm->zfree == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<InflateState*>(strm->state);
  const auto zfree = reinterpret_cast<FreeFunc>(strm->zfree);

  if (state->window != nullptr)
  {
    zfree(strm->opaque, state->window);
  }
  zfree(strm->opaque, strm->state);
  strm->state = nullptr;

  return kZOk;
}

/**
 * Address: 0x0095C9D0 (FUN_0095C9D0)
 * Mangled: zcalloc
 *
 * zlib's default allocator (zutil.c): ignores the opaque handle and returns
 * malloc(items * size). Matches FUN_0095C9D0.asm (imul items,size then malloc).
 */
extern "C" void* zcalloc([[maybe_unused]] void* opaque, unsigned int items, unsigned int size)
{
  return std::malloc(items * size);
}

/**
 * Address: 0x0095C9F0 (FUN_0095C9F0)
 * Mangled: zcfree
 *
 * zlib's default deallocator (zutil.c): ignores the opaque handle and frees the
 * address with the CRT free.
 */
extern "C" void zcfree([[maybe_unused]] void* opaque, void* address)
{
  std::free(address);
}

/**
 * Address: 0x00958E70 (FUN_00958E70)
 * Mangled: inflateInit2_
 *
 * IDA signature:
 * int __cdecl inflateInit2_(z_streamp strm, int windowBits, const char* version, int stream_size);
 *
 * Allocates and initialises an inflate stream. Rejects a version whose first
 * char isn't '1' or a stream_size other than sizeof(z_stream) (Z_VERSION_ERROR),
 * and a null stream (Z_STREAM_ERROR). Installs the default zcalloc/zcfree when
 * the caller left them null, allocates the inflate_state through zalloc
 * (Z_MEM_ERROR on failure), then derives wrap and the window size from
 * windowBits: for windowBits >= 0, wrap = (windowBits >> 4) + 1 and (when
 * < 48) windowBits &= 15; for windowBits < 0, wrap = 0 and windowBits negated.
 * A resulting window size outside 8..15 frees the state and returns
 * Z_STREAM_ERROR; otherwise it records wbits, clears the window pointer, and
 * tail-calls inflateReset. Verified 1:1 against FUN_00958E70.asm.
 */
extern "C" int inflateInit2_(zlib::ZStream* strm, int windowBits,
                             const char* version, int stream_size)
{
  using namespace zlib;

  if (version == nullptr || *version != '1' || stream_size != static_cast<int>(sizeof(ZStream)))
  {
    return kZVersionError;
  }
  if (strm == nullptr)
  {
    return kZStreamError;
  }

  strm->msg = nullptr;
  if (strm->zalloc == nullptr)
  {
    strm->zalloc = reinterpret_cast<void*>(&zcalloc);
    strm->opaque = nullptr;
  }
  if (strm->zfree == nullptr)
  {
    strm->zfree = reinterpret_cast<void*>(&zcfree);
  }

  auto* const state = static_cast<InflateState*>(
      reinterpret_cast<AllocFunc>(strm->zalloc)(strm->opaque, 1, sizeof(InflateState)));
  if (state == nullptr)
  {
    return kZMemError;
  }
  strm->state = state;

  if (windowBits >= 0)
  {
    state->wrap = (windowBits >> 4) + 1;
    if (windowBits < 48)
    {
      windowBits &= 15;
    }
  }
  else
  {
    state->wrap = 0;
    windowBits = -windowBits;
  }

  if (windowBits < 8 || windowBits > 15)
  {
    reinterpret_cast<FreeFunc>(strm->zfree)(strm->opaque, state);
    strm->state = nullptr;
    return kZStreamError;
  }

  state->wbits  = static_cast<std::uint32_t>(windowBits);
  state->window = nullptr;
  return inflateReset(strm);
}

/**
 * Address: 0x00958F40 (FUN_00958F40)
 * Mangled: inflateInit_
 *
 * IDA signature:
 * int __cdecl inflateInit_(z_streamp strm, const char* version, int stream_size);
 *
 * Thin wrapper: initialises an inflate stream with the default window size
 * (DEF_WBITS = 15) via inflateInit2_.
 */
extern "C" int inflateInit_(zlib::ZStream* strm, const char* version, int stream_size)
{
  return inflateInit2_(strm, zlib::kZDefaultWindowBits, version, stream_size);
}
