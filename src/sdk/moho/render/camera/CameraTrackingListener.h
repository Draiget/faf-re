#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "moho/misc/Listener.h"

namespace moho
{
  /**
   * ABI-compatible view of a single intrusive broadcaster link node used by
   * the camera-tracking broadcaster.
   *
   * Layout note: this is layout-equivalent to `moho::Broadcaster` (the
   * `Listener<T>::mListenerLink` field type), but with field names that
   * match the existing `CameraImpl.cpp` dispatcher idiom. Both names refer
   * to the same two-pointer node; field offsets (`+0x00`, `+0x04`) carry
   * the prev/next pair in TDatList semantics. Used by
   * `BroadcastCameraTrackingEvent` to walk the broadcaster ring without
   * depending on the typed `Listener<T>::mListenerLink` accessor.
   */
  /**
   * Intrusive link for the camera tracking broadcaster list.
   *
   * The field order here is the binary's: slot `+0x00` is **next** and `+0x04`
   * is **prev**, confirmed by `FUN_007AE2B0`
   * (`Broadcaster<SCameraTracking>::BroadcastEvent`), which splices with
   * `X->[+0]->[+4] = S` / `X->[+4]->[+0] = S` and tests emptiness on `[+4]`.
   *
   * Note that `moho::TDatListItem` names the same two slots the opposite way
   * round. See the warning on that template before mixing the two, and never
   * reinterpret one as the other and then use the field names.
   */
  struct CameraTrackingBroadcasterLink
  {
    CameraTrackingBroadcasterLink* mListNext = nullptr; // +0x00
    CameraTrackingBroadcasterLink* mListPrev = nullptr; // +0x04
  };
  static_assert(
    offsetof(CameraTrackingBroadcasterLink, mListNext) == 0x00,
    "CameraTrackingBroadcasterLink::mListNext offset must be 0x00"
  );
  static_assert(
    offsetof(CameraTrackingBroadcasterLink, mListPrev) == 0x04,
    "CameraTrackingBroadcasterLink::mListPrev offset must be 0x04"
  );
  static_assert(sizeof(CameraTrackingBroadcasterLink) == 0x08, "CameraTrackingBroadcasterLink size must be 0x08");

  /**
   * Camera-tracking event payload.
   *
   * Layout evidence:
   * - Dispatched by `Moho::Broadcaster<Moho::SCameraTracking>::BroadcastEvent`
   *   (FUN_007AE2B0). The IDA-emitted broadcaster signature is
   *   `?BroadcastEvent@?$Broadcaster@USCameraTracking@Moho@@@Moho@@IAEXUSCameraTracking@2@@Z`,
   *   confirming the event-type name `Moho::SCameraTracking`.
   * - Two-field POD: a camera name (`msvc8::string`, 28 bytes) and a
   *   transition flag (`bool`, padded to 4 bytes). Total 32 bytes on the stack
   *   for by-value pass; matches the `ret 0x20` cleanup at FUN_008714B0.
   * - Producer call sites in `CameraImpl` always pass `runtime->mName` (the
   *   active camera name) and a 0/1 flag (1 for transition-active /
   *   target-acquired, 0 for transition-cleared / target-released).
   *
   * The struct itself doesn't appear in the binary as an addressable type
   * because every instance is constructed inline on the broadcaster's stack
   * frame and then passed straight into the listener's virtual; the name is
   * the IDA demangled label of the Broadcaster template parameter.
   */
  struct SCameraTracking
  {
    msvc8::string mCameraName{};        // +0x00, 28 bytes
    std::uint8_t  mTransitionFlag = 0;  // +0x1C, 1 byte (padded to 4 on the stack)
  };

  static_assert(
    offsetof(SCameraTracking, mCameraName) == 0x00,
    "SCameraTracking::mCameraName offset must be 0x00"
  );
  static_assert(
    offsetof(SCameraTracking, mTransitionFlag) == 0x1C,
    "SCameraTracking::mTransitionFlag offset must be 0x1C"
  );

  /**
   * Moho::CameraTrackingListener
   *
   * Layout evidence:
   * - Vtable: `??_7CameraTrackingListener@Moho@@6B@` at 0x00E49158, slot 0
   *   pointing to `Moho::CameraTrackingListener::Receive` (FUN_008714B0).
   * - Singleton instance at `.data:0x00F5B668`, constructed by static-init
   *   thunk FUN_008715C0 which writes the vtable to `off_F5B668` and
   *   self-links the broadcaster sentinel at `off_F5B66C`/`off_F5B670`
   *   (`mPrev`/`mNext` of the `Broadcaster mListenerLink` inherited from
   *   `Listener<SCameraTracking>`).
   * - Atexit reset thunk FUN_008715E0 writes
   *   `Moho::Listener<Moho::SCameraTracking>::vftable` back into
   *   `off_F5B668`, confirming the base class is `Listener<SCameraTracking>`.
   * - Size 12 (0x0C): vtable pointer (4) + inherited `Broadcaster
   *   mListenerLink` (8).
   *
   * Calling convention for the binary `Receive` symbol: the IDA demangler
   * names the override `?Receive@...` though it overrides
   * `Listener<SCameraTracking>::OnEvent`. The override is by-value-`event`,
   * but because `SCameraTracking` is a POD of `{ msvc8::string + uint8_t }`,
   * MSVC passes its members member-wise on the stack: 28 bytes of string +
   * 4-byte padded bool = 32-byte `ret 0x20` cleanup. The recovered override
   * is named `OnEvent` to match the engine-wide `Listener<T>` contract.
   *
   * Dispatch chain: CRT `__xc_a` static-init invokes FUN_008715C0 once at
   * process startup; thereafter, every camera target-mode transition in
   * `moho::CameraImpl` (TargetEntity / TargetNothing / Reset / SnapTo /
   * TimedMove etc.) calls `BroadcastCameraTrackingEvent`, which walks the
   * broadcaster ring at `camera+0x04` and dispatches via this vtable slot.
   * The runtime payload is forwarded to the Lua side at
   * `/lua/ui/game/tracking.lua:OnTrackUnit(cameraName, transitionFlag)`.
   */
  class CameraTrackingListener : public Listener<SCameraTracking>
  {
  public:
    /**
     * Address: 0x008715C0 (FUN_008715C0, ctor of the singleton instance)
     *
     * What it does:
     * Initializes the listener's broadcaster lane to the self-linked sentinel
     * state via `Listener<SCameraTracking>::Listener()`. The vtable pointer
     * is written by the CRT static-init thunk that constructs the global
     * singleton.
     */
    CameraTrackingListener() noexcept = default;

    CameraTrackingListener(const CameraTrackingListener&) = delete;
    CameraTrackingListener& operator=(const CameraTrackingListener&) = delete;

    /**
     * Address: 0x008714B0 (FUN_008714B0)
     * Mangled: ?Receive@CameraTrackingListener@Moho@@UAEXV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z
     * Slot: 0 (Listener<SCameraTracking> vtable, single virtual method)
     *
     * IDA signature:
     * void __stdcall Moho::CameraTrackingListener::Receive(std::string str1, LuaPlus::LuaState *a2);
     * (decompiler-typed `a2` as `LuaState*`; binary truth is a one-byte
     *  `mTransitionFlag` passed as a 4-byte stack slot, i.e. the second
     *  member of the by-value `SCameraTracking` event)
     *
     * What it does:
     * Looks up `/lua/ui/game/tracking.lua:OnTrackUnit` on the active world
     * session's Lua state and invokes it with
     * `(event.mCameraName, event.mTransitionFlag)`. Lua-side errors are
     * caught and routed through `gpg::Warnf` with the
     * `"Error running '/lua/ui/game/tracking.lua:OnTrackUnit': %s"` template.
     */
    void OnEvent(SCameraTracking event) override;
  };

  static_assert(sizeof(CameraTrackingListener) == 0x0C, "CameraTrackingListener size must be 0x0C");
} // namespace moho
