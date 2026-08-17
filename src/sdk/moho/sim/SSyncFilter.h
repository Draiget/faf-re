#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/BVIntSet.h"
#include "moho/render/camera/GeomCamera3.h"
#include "platform/Platform.h"

namespace moho
{
  /**
   * Compact sync mask payload used in CSimDriver::SetSyncFilterMaskA/SetSyncFilterMaskB.
   *
   * This is not a distinct type: the payload the binary stores here is a plain
   * `BVIntSet` (base word index +0x00, metadata word +0x04, packed word vector
   * +0x08, size 0x20). `Sim::AdvanceBeat` proves it by calling
   * `BVIntSet::GetNext` directly on `mSyncFilter.maskA` (0x0074A26C, with
   * `this` = Sim+0x0AA8), and `CWldSession` builds the payload as a `BVIntSet`
   * before storing it.
   *
   * Layout reconstructed from 0x0073B3F0, 0x0073B4B0, and 0x0073DD10.
   */
  using SSyncFilterMaskBlock = BVIntSet;

  /**
   * Address: 0x004028E0 (FUN_004028E0, helper lane used by FUN_0073DD10)
   *
   * What it does:
   * Copies only the binary-significant mask payload (base word index and the
   * packed word vector). `BVIntSet::operator=` would additionally copy the
   * per-instance metadata word, which the binary deliberately leaves alone.
   */
  void CopySyncFilterMaskPayload(SSyncFilterMaskBlock& target, const SSyncFilterMaskBlock& source);

  /**
   * Sim sync filter state.
   *
   * Full size: 0x70 bytes.
   */
  struct SSyncFilter
  {
    int32_t focusArmy = -1;             // +0x00
    msvc8::vector<GeomCamera3> geoCams; // +0x04
    // +0x14..+0x1F are not copied by FUN_0073DD10 / sub_1030E200.
    uint32_t geoCamVectorAuxWords[3]{}; // +0x14
    SSyncFilterMaskBlock maskA;         // +0x20
    bool optionFlag = false;            // +0x40
    // +0x41..+0x4F are not copied by FUN_0073DD10 / sub_1030E200.
    uint8_t optionFlagAuxBytes[0x0F]{}; // +0x41
    SSyncFilterMaskBlock maskB;         // +0x50

    /**
     * Address: 0x0073B980 (FUN_0073B980)
     * Mangled: ??1struct_SimDriverSubObj1@@QAE@@Z
     *
     * What it does:
     * Rebinds both fast mask vectors back to inline storage before the
     * compiler-generated member teardown continues with `geoCams`.
     */
    ~SSyncFilter();

    /**
     * Address: 0x0073DD10 (FUN_0073DD10)
     *
     * What it does:
     * Copies the binary-significant sync-filter payload:
     * focus army, geom-camera vector, both mask blocks, and option flag.
     */
    void CopyFrom(const SSyncFilter& source);
  };

  static_assert(sizeof(SSyncFilter) == 0x70, "SSyncFilter size must be 0x70");
  static_assert(offsetof(SSyncFilter, focusArmy) == 0x00, "focusArmy offset mismatch");
  static_assert(offsetof(SSyncFilter, geoCams) == 0x04, "geoCams offset mismatch");
  static_assert(offsetof(SSyncFilter, geoCamVectorAuxWords) == 0x14, "geoCamVectorAuxWords offset mismatch");
  static_assert(offsetof(SSyncFilter, maskA) == 0x20, "maskA offset mismatch");
  static_assert(offsetof(SSyncFilter, optionFlag) == 0x40, "optionFlag offset mismatch");
  static_assert(offsetof(SSyncFilter, optionFlagAuxBytes) == 0x41, "optionFlagAuxBytes offset mismatch");
  static_assert(offsetof(SSyncFilter, maskB) == 0x50, "maskB offset mismatch");
} // namespace moho
