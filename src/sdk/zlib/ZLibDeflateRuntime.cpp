// zlib deflate runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). These recovered bodies match the binary at their given addresses
// and override the library copies via .obj-before-.lib resolution; the TU is
// ExcludedFromBuild (a source-faithful record verified per-TU + standalone).

#include "zlib/ZLibDeflate.h"

/**
 * Address: 0x0095B4E0 (FUN_0095B4E0)
 * Mangled: deflateEnd
 *
 * IDA signature:
 * int __cdecl deflateEnd(z_streamp strm);
 *
 * Releases a deflate stream. Guards a null stream / state and a deflate_state
 * whose status is not one of the recognised init/gzip-header/busy/finish values
 * (Z_STREAM_ERROR). Otherwise it frees the four heap buffers the deflate_state
 * owns — pending_buf, head, prev and window — plus the state itself through the
 * stream's zfree callback, nulls strm->state, and returns Z_DATA_ERROR if the
 * stream was mid-operation (BUSY_STATE) or Z_OK otherwise. Verified 1:1 against
 * FUN_0095B4E0.asm (the free order is pending_buf -> head -> prev -> window ->
 * state; the IDA decompiler's state->w_mask etc. names are the real
 * window/prev/head at +0x38/+0x40/+0x44).
 */
extern "C" int deflateEnd(zlib::ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<DeflateState*>(strm->state);
  const int status = state->status;
  if (status != kDeflateInitState && status != kDeflateExtraState &&
      status != kDeflateNameState && status != kDeflateCommentState &&
      status != kDeflateHcrcState && status != kDeflateBusyState &&
      status != kDeflateFinishState)
  {
    return kZStreamError;
  }

  const auto zfree = reinterpret_cast<FreeFunc>(strm->zfree);
  if (state->pending_buf != nullptr)
  {
    zfree(strm->opaque, state->pending_buf);
  }
  if (state->head != nullptr)
  {
    zfree(strm->opaque, state->head);
  }
  if (state->prev != nullptr)
  {
    zfree(strm->opaque, state->prev);
  }
  if (state->window != nullptr)
  {
    zfree(strm->opaque, state->window);
  }
  zfree(strm->opaque, strm->state);
  strm->state = nullptr;

  return (status == kDeflateBusyState) ? kZDataError : kZOk;
}
