#include "moho/sim/SSTICommandSource.h"

#include <cstring>
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
 * Address: 0x007CCE20 (FUN_007CCE20, ??1vec_SSTICommandSource@@QAE@@Z)
 * Mangled: ??1vec_SSTICommandSource@@QAE@@Z
 *
 * What it does:
 * Copy-assigns one prototype command source into `count` contiguous
 * destination lanes with EH cleanup that destroys already-written entries.
 */
void CopyAssignSSTICommandSourceRange(
  const SSTICommandSource& prototype,
  const std::uint32_t count,
  SSTICommandSource* const destination
)
{
  if (!destination || count == 0U) {
    return;
  }

  SSTICommandSource* const begin = destination;
  SSTICommandSource* cursor = destination;
  try {
    for (std::uint32_t i = 0; i < count; ++i, ++cursor) {
      *cursor = prototype;
    }
  } catch (...) {
    for (SSTICommandSource* it = begin; it != cursor; ++it) {
      it->~SSTICommandSource();
    }
    throw;
  }
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
} // namespace moho
