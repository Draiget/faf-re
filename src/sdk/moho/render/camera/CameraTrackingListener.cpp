#include "moho/render/camera/CameraTrackingListener.h"

#include <exception>
#include <string>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CWldSession.h"

namespace moho
{
  /**
   * Address: 0x008714B0 (FUN_008714B0, Moho::CameraTrackingListener::Receive)
   *
   * What it does:
   * Imports `/lua/ui/game/tracking.lua` on the active world-session Lua
   * state, fetches its `OnTrackUnit` field, wraps it as a callable
   * `LuaFunction`, and invokes it with
   * `(event.mCameraName, event.mTransitionFlag)`. Any Lua-side exception
   * thrown by the call is caught and routed through `gpg::Warnf` using the
   * original `"Error running '/lua/ui/game/tracking.lua:OnTrackUnit': %s"`
   * template.
   *
   * Binary fidelity notes:
   * - The `SCameraTracking` payload is passed by value (32 bytes inline on
   *   the stack); the `ret 0x20` cleanup covers the 28-byte string plus the
   *   padded one-byte transition flag.
   * - The binary builds a `std::string` temporary and calls
   *   `std::string::assign(&temp, &event.mCameraName, 0, 0xFFFFFFFF)` before
   *   handing it to `LuaFunction::Call_StringBool`. Because `msvc8::string`
   *   is the MSVC8 `std::string` ABI layout, we recover this as a single
   *   `to_std()` copy producing the same content + same lifetime semantics.
   * - The SEH frame in the original wraps just the Lua call; we mirror that
   *   with a try/catch around `Call_StringBool` so non-call paths
   *   (SCR_Import, operator[], LuaFunction ctor) propagate exceptions to the
   *   broadcaster splice loop unmodified, matching the original control flow.
   * - The original binary frees the by-value `mCameraName` heap buffer at
   *   the function epilogue with `operator delete` when `_Myres >= 0x10`.
   *   `msvc8::string` is intentionally trivial (no destructor) in this SDK
   *   because the engine retains ownership through the broadcaster lane,
   *   so no explicit free is needed in the recovered form.
   */
  void CameraTrackingListener::OnEvent(SCameraTracking event)
  {
    CWldSession* const activeSession = WLD_GetSession();
    if (activeSession == nullptr) {
      return;
    }

    LuaPlus::LuaState* const luaState = activeSession->mState;
    if (luaState == nullptr) {
      return;
    }

    const LuaPlus::LuaObject trackingModule = SCR_Import(luaState, "/lua/ui/game/tracking.lua");
    const LuaPlus::LuaObject onTrackUnitObj = trackingModule["OnTrackUnit"];
    LuaPlus::LuaFunction<> onTrackUnitFn(onTrackUnitObj);

    const std::string cameraNameStd = event.mCameraName.to_std();
    const bool transitionFlagBool = (event.mTransitionFlag != 0);

    try {
      onTrackUnitFn.Call_StringBool(cameraNameStd, transitionFlagBool);
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '/lua/ui/game/tracking.lua:OnTrackUnit': %s",
        exception.what() != nullptr ? exception.what() : "<unknown>"
      );
    } catch (...) {
      gpg::Warnf("Error running '/lua/ui/game/tracking.lua:OnTrackUnit': %s", "<unknown>");
    }
  }

  namespace
  {
    /**
     * Address: 0x00F5B668 (.data, CameraTrackingListener singleton instance)
     *
     * Layout evidence:
     * - Static-init thunk FUN_008715C0 writes the primary vtable
     *   `??_7CameraTrackingListener@Moho@@6B@` (`.rdata:0x00E49158`) to
     *   `*off_F5B668` and self-links the inherited `Broadcaster
     *   mListenerLink` at `off_F5B66C`/`off_F5B670` (`mPrev`/`mNext`).
     * - The instance is the broadcaster sink registered with the world camera
     *   when `func_SetWorldCamera` (FUN_00871640) attaches the camera's
     *   broadcaster lane to the singleton's sentinel.
     * - Atexit reset thunks (FUN_008715E0 / FUN_00871620) restore the base
     *   `Listener<SCameraTracking>` vtable and re-initialize the lane on
     *   teardown.
     *
     * The engine constructs exactly one `CameraTrackingListener` for the
     * process lifetime; every camera target-mode transition is broadcast
     * through this singleton's vtable slot 0 (`OnEvent`) to the Lua side.
     */
    [[nodiscard]] CameraTrackingListener& GlobalCameraTrackingListener() noexcept
    {
      static CameraTrackingListener sListener;
      return sListener;
    }

    /**
     * Address: 0x008715C0 (FUN_008715C0, CameraTrackingListener static-init thunk)
     *
     * What it does:
     * Constructs the process-global `CameraTrackingListener` instance during
     * CRT `__xc_a` static initialization, keeping the singleton reachable
     * from the binary's startup graph so that the `OnEvent` slot is later
     * dispatched whenever a camera target-mode transition is broadcast.
     */
    [[maybe_unused]] const bool kCameraTrackingListenerStaticInit = []() noexcept {
      (void)GlobalCameraTrackingListener();
      return true;
    }();
  } // namespace
} // namespace moho
