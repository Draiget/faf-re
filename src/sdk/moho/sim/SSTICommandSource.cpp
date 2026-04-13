#include "moho/sim/SSTICommandSource.h"

namespace moho
{
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
} // namespace moho
