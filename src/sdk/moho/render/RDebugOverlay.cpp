#include "RDebugOverlay.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  /**
   * Address: 0x0064C1B0 (FUN_0064C1B0, Moho::RDebugOverlay non-deleting dtor body)
   *
   * What it does:
   * Unlinks this debug-overlay intrusive list node and restores singleton link
   * state before base `gpg::RObject` teardown.
   */
  void DestroyRDebugOverlayNonDeletingBody(moho::RDebugOverlay* const overlay) noexcept
  {
    if (overlay == nullptr) {
      return;
    }

    auto* const node = static_cast<moho::TDatListItem<moho::RDebugOverlay, void>*>(overlay);
    node->ListUnlinkSelf();
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugOverlay::sType = nullptr;

  /**
   * Address: 0x00651AE0 (FUN_00651AE0)
   *
   * What it does:
   * Initializes the debug-overlay base lane and seeds intrusive links as a
   * singleton ring.
   */
  RDebugOverlay::RDebugOverlay() = default;

  /**
   * Address: 0x0064C1E0 (FUN_0064C1E0, scalar deleting body)
   */
  RDebugOverlay::~RDebugOverlay()
  {
    DestroyRDebugOverlayNonDeletingBody(this);
  }

  /**
   * Address: 0x00651AF0 (FUN_00651AF0, nullsub_1684)
   */
  void RDebugOverlay::Tick(Sim* /*sim*/) {}

  /**
   * Address: 0x006527B0 (FUN_006527B0, Moho::RDebugOverlay::NewPtr)
   *
   * What it does:
   * Creates one reflected object through `typeInfo`, upcasts it to
   * `RDebugOverlay`, and returns the typed object pointer.
   */
  RDebugOverlay* RDebugOverlay::NewPtr(gpg::RType& typeInfo)
  {
    if (typeInfo.newRefFunc_ == nullptr) {
      return nullptr;
    }

    const gpg::RRef source = typeInfo.newRefFunc_();

    gpg::RType* overlayType = sType;
    if (overlayType == nullptr) {
      overlayType = gpg::LookupRType(typeid(RDebugOverlay));
      sType = overlayType;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, overlayType);
    if (upcast.mObj == nullptr) {
      gpg::HandleAssertFailure(
        "result",
        540,
        "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflection.h"
      );
      return nullptr;
    }

    return static_cast<RDebugOverlay*>(upcast.mObj);
  }
} // namespace moho
