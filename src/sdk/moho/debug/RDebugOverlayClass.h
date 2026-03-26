#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2343C
   * COL: 0x00E7D6D4
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugOverlayClass : public gpg::RType
  {
  public:
    /**
     * Address: 0x0064C170 (FUN_0064C170, ?GetClass@RDebugOverlayClass@Moho@@UBEPAVRType@gpg@@XZ)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugOverlayClass`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0064C190 (FUN_0064C190, ?GetDerivedObjectRef@RDebugOverlayClass@Moho@@UAE?AVRRef@gpg@@XZ)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0064C4D0 (FUN_0064C4D0, scalar deleting body)
     * Slot: 2
     */
    ~RDebugOverlayClass() override;

    /**
     * Address: 0x00651920 (FUN_00651920)
     *
     * What it does:
     * Stores overlay description/token labels and links this descriptor into
     * the process-global debug-overlay-class registry list.
     */
    void RegisterOverlayClass(const char* overlayDescription, const char* overlayToken);

    /**
     * Recovery helper:
     * Compatibility wrapper for older callsites that only recovered token.
     */
    void RegisterOverlayClassToken(const char* overlayToken);

  public:
    std::uint32_t mOverlayClassPad0064;                       // +0x64 (observed gap before intrusive link base)
    TDatListItem<RDebugOverlayClass, void> mOverlayClassLink; // +0x68
    msvc8::string mOverlayToken;                              // +0x70
    msvc8::string mOverlayDescription;                        // +0x8C
  };

  static_assert(
    offsetof(RDebugOverlayClass, mOverlayClassPad0064) == 0x64,
    "RDebugOverlayClass::mOverlayClassPad0064 offset must be 0x64"
  );
  static_assert(
    offsetof(RDebugOverlayClass, mOverlayClassLink) == 0x68, "RDebugOverlayClass::mOverlayClassLink offset must be 0x68"
  );
  static_assert(
    offsetof(RDebugOverlayClass, mOverlayToken) == 0x70, "RDebugOverlayClass::mOverlayToken offset must be 0x70"
  );
  static_assert(
    offsetof(RDebugOverlayClass, mOverlayDescription) == 0x8C,
    "RDebugOverlayClass::mOverlayDescription offset must be 0x8C"
  );
  static_assert(sizeof(RDebugOverlayClass) == 0xA8, "RDebugOverlayClass size must be 0xA8");
} // namespace moho
