#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  struct SSTICommandSource
  {
    SSTICommandSource() = default;

    /**
     * Address: 0x007BF390 (FUN_007BF390, ??0SSTICommandSource@Moho@@QAE@@Z)
     * Mangled: ??0SSTICommandSource@Moho@@QAE@IHPBD@Z
     *
     * What it does:
     * Initializes one command-source record from `(index, playerName, timeouts)`.
     * The string lane is reset to empty SSO state before copying player-name
     * bytes, then timeout lanes are committed.
     */
    SSTICommandSource(std::uint32_t index, const char* playerName, std::int32_t timeouts);

    /**
     * Address: 0x005452B0 (FUN_005452B0, ??1SSTICommandSource@Moho@@QAE@@Z)
     * Mangled: ??1SSTICommandSource@Moho@@QAE@@Z
     *
     * What it does:
     * Releases heap-backed string storage (when present) and restores empty
     * SSO string lanes for this command source record.
     */
    ~SSTICommandSource();

    /**
     * Address: 0x00756B60 (FUN_00756B60, ??4SSTICommandSource@Moho@@QAE@@Z)
     * Mangled: ??4SSTICommandSource@Moho@@QAE@@Z
     *
     * What it does:
     * Reinitializes the name string lane to empty SSO state, then copies index,
     * name, and timeout values from another command-source record.
     */
    SSTICommandSource& operator=(const SSTICommandSource& other);

    std::uint32_t mIndex; // +0x00
    msvc8::string mName;  // +0x04
    std::int32_t mTimeouts; // +0x20
  };

  static_assert(offsetof(SSTICommandSource, mIndex) == 0x00, "SSTICommandSource::mIndex offset must be 0x00");
  static_assert(offsetof(SSTICommandSource, mName) == 0x04, "SSTICommandSource::mName offset must be 0x04");
  static_assert(offsetof(SSTICommandSource, mTimeouts) == 0x20, "SSTICommandSource::mTimeouts offset must be 0x20");
  static_assert(sizeof(SSTICommandSource) == 0x24, "SSTICommandSource size must be 0x24");

  /**
   * Address: 0x007CCE20 (FUN_007CCE20, ??1vec_SSTICommandSource@@QAE@@Z)
   * Mangled: ??1vec_SSTICommandSource@@QAE@@Z
   *
   * What it does:
   * Writes `count` copies of one prototype command source into contiguous
   * destination lanes, and if a copy throws, destroys already-assigned lanes
   * before rethrowing.
   */
  void CopyAssignSSTICommandSourceRange(
    const SSTICommandSource& prototype,
    std::uint32_t count,
    SSTICommandSource* destination
  );

  /**
   * Address: 0x007CECC0 (FUN_007CECC0)
   *
   * What it does:
   * Copy-assigns one half-open `SSTICommandSource` source range into
   * destination lanes and, if assignment throws, destroys already-written
   * destination entries before rethrowing.
   */
  SSTICommandSource* CopyAssignSSTICommandSourceHalfOpenRange(
    const SSTICommandSource* sourceBegin,
    const SSTICommandSource* sourceEnd,
    SSTICommandSource* destinationBegin
  );

  /**
   * Address: 0x007C84D0 (FUN_007C84D0, func_vec_SSTICommandSource_Append)
   *
   * What it does:
   * Appends one `SSTICommandSource` entry to a command-source vector lane,
   * preserving the original capacity-fast-path behavior.
   */
  void AppendSSTICommandSource(
    msvc8::vector<SSTICommandSource>& commandSources,
    const SSTICommandSource& entry
  );
} // namespace moho
