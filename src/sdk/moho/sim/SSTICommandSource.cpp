#include "moho/sim/SSTICommandSource.h"

#include <cstring>
#include <new>
#include <string_view>

namespace moho
{
/**
 * Address: 0x007BF390 (FUN_007BF390, ??0SSTICommandSource@Moho@@QAE@@Z)
 * Mangled: ??0SSTICommandSource@Moho@@QAE@IHPBD@Z
 *
 * What it does:
 * Stores command-source scalar lanes, rewrites the legacy string lane into
 * empty SSO state, then deep-copies `playerName` bytes before committing
 * `mTimeouts`.
 */
SSTICommandSource::SSTICommandSource(
  const std::uint32_t index,
  const char* const playerName,
  const std::int32_t timeouts
)
  : mIndex(index)
  , mName()
{
  mName.myRes = 15U;
  mName.mySize = 0U;
  mName.bx.buf[0] = '\0';

  const std::size_t nameLength = std::strlen(playerName);
  mName.assign_owned(std::string_view(playerName, nameLength));
  mTimeouts = timeouts;
}

/**
 * Address: 0x005452B0 (FUN_005452B0, ??1SSTICommandSource@Moho@@QAE@@Z)
 * Mangled: ??1SSTICommandSource@Moho@@QAE@@Z
 *
 * What it does:
 * Releases heap-backed string storage (when present) and restores empty
 * SSO lanes.
 */
SSTICommandSource::~SSTICommandSource()
{
  mName.tidy(true, 0U);
}

/**
 * Address: 0x00756B60 (FUN_00756B60, ??4SSTICommandSource@Moho@@QAE@@Z)
 * Mangled: ??4SSTICommandSource@Moho@@QAE@@Z
 *
 * What it does:
 * Copies scalar/index lanes and rebuilds the string lane from source text.
 * Self-assignment follows binary semantics and leaves `mName` reset/recopied.
 */
SSTICommandSource& SSTICommandSource::operator=(const SSTICommandSource& other)
{
  mIndex = other.mIndex;
  mName.reset_and_assign(other.mName);
  mTimeouts = other.mTimeouts;
  return *this;
}


/**
 * Address: 0x007C84D0 (FUN_007C84D0, func_vec_SSTICommandSource_Append)
 *
 * What it does:
 * Appends one source entry into the command-source vector lane.
 */
void AppendSSTICommandSource(
  msvc8::vector<SSTICommandSource>& commandSources,
  const SSTICommandSource& entry
)
{
  commandSources.push_back(entry);
}

/**
 * Address: 0x00755810 (FUN_00755810, sub_755810)
 *
 * IDA signature:
 * void __cdecl sub_755810(Moho::SSTICommandSource *srcBegin,
 *                         Moho::SSTICommandSource *srcEnd,
 *                         Moho::SSTICommandSource *destBegin);
 *
 * What it does:
 * Copy-assigns one half-open `SSTICommandSource` source range `[srcBegin,srcEnd)`
 * into already-constructed destination lanes starting at `destBegin`, returning
 * the destination cursor one past the last written entry. If a copy-assignment
 * throws, the entries written so far are destroyed before the exception is
 * rethrown. This is the fill lane invoked by the command-source vector
 * copy-construct helper (`FUN_0074C500`); it is a distinct emission from the
 * shape-identical `CopyAssignSSTICommandSourceHalfOpenRange` (`FUN_007CECC0`).
 */
SSTICommandSource* CopyAssignCommandSourceRangeForVectorFill(
  const SSTICommandSource* const srcBegin,
  const SSTICommandSource* const srcEnd,
  SSTICommandSource* const destBegin
)
{
  SSTICommandSource* destCursor = destBegin;
  try {
    for (const SSTICommandSource* srcCursor = srcBegin; srcCursor != srcEnd;
         ++srcCursor, ++destCursor) {
      *destCursor = *srcCursor;
    }
    return destCursor;
  } catch (...) {
    for (SSTICommandSource* rollbackCursor = destBegin; rollbackCursor != destCursor;
         ++rollbackCursor) {
      rollbackCursor->~SSTICommandSource();
    }
    throw;
  }
}

/**
 * Address: 0x0074C500 (FUN_0074C500, sub_74C500)
 *
 * IDA signature:
 * std::vector_SSTICommandSource *__thiscall
 * sub_74C500(Moho::SCommandSource *this, std::vector_SSTICommandSource *out);
 *
 * What it does:
 * Copy-constructs one command-source vector lane out of the source vector held
 * by a `SLaunchCommandSources` block (its `mSrcs` lane). The destination `out`
 * is first reset to empty; if the source is non-empty its capacity is reserved,
 * the destination lanes are value-initialized, and each element is copy-assigned
 * from the source through `CopyAssignCommandSourceRangeForVectorFill`
 * (`FUN_00755810`). Mirrors the binary's reserve + default-construct + assign
 * sequence exactly (the `Sim` constructor uses this to seed `mCommandSources`
 * from `LaunchInfoBase::mCommandSources.mSrcs`).
 */
msvc8::vector<SSTICommandSource>* CopyConstructCommandSourceVector(
  const msvc8::vector<SSTICommandSource>& src,
  msvc8::vector<SSTICommandSource>* const out
)
{
  out->release_storage_without_free();

  const std::size_t count = src.size();
  if (count != 0U) {
    // Reserve + value-construct the destination lanes, then copy-assign over
    // them from the source range (binary: sub_543480 reserve -> sub_755810 fill).
    out->resize(count);
    (void)CopyAssignCommandSourceRangeForVectorFill(src.begin(), src.end(), out->data());
  }

  return out;
}
} // namespace moho
