// zlib inflate runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). These recovered bodies match the binary at their given
// addresses and override the library copies via .obj-before-.lib resolution;
// the recovered TU is ExcludedFromBuild (a source-faithful record verified
// per-TU) so it never conflicts with the shipping zlib.lib.

#include "zlib/ZLibInflate.h"

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
