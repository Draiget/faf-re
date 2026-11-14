#include "WinApp.h"
#include "moho/misc/WideStringRange.h"
#include "platform/X87Precision.h"

#include "platform/Platform.h"

#include <DbgHelp.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <intrin.h>
#include <limits>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>
#include <vector>

#include <float.h>
#include <commctrl.h>
#include <objbase.h>
#include <TlHelp32.h>

#include "legacy/thread/Mutex.h"
#include "CWaitHandleSet.h"
#include "CScApp.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/time/Timer.h"
#include "IWinApp.h"
#include "legacy/containers/Vector.h"
#include "AppRuntimeTypes.h"
#include "moho/app/WEmitterEditor.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/TimeBar.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/resource/ResourceManager.h"
#include "moho/core/Thread.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/console/CConCommand.h"
#include "platform/Window.h"
#include "platform/sdl/TestInput.h"
#if FAFRE_PLATFORM_POSIX
#include "platform/posix/Win32WindowPosix.h" // the window system's clipboard (issue #256)
#endif

#pragma warning(push)
#pragma warning(disable : 4996)

/**
 * wx builds the application object through this: wxCreateApp (0x004F1E90)
 * checks the build options and news a MohoApp, the wxAppInitializer's static
 * constructor (0x00BC7260) registers it, and wxGetApp (0x004F1FF0) is the
 * accessor DECLARE_APP names in WxRuntimeTypes.h. wxEntry, called by
 * WIN_AppExecute, runs it. MohoApp's constructor (0x004F1F10) and deleting
 * destructor (0x004F1F60) are the compiler's, and 0x004F1B50 / 0x004F1B90
 * are the wxAppInitializer constructor out of line (`wxApp::m_appInitFn =
 * wxCreateApp`, the second returning the initializer).
 */
IMPLEMENT_APP_NO_MAIN(
  moho::MohoApp
)

namespace moho
{
  struct STimeBarThreadInfo;

  /**
   * The log window's target (0x010A9BA0). Its static initialiser 0x00BC7340,
   * listed in the CRT's initialiser table at 0x00C0FA60, runs the
   * constructor (0x004F38F0) and registers the exit-time destructor thunk
   * 0x00BF18D0, which calls ~CWinLogTarget (0x004F39B0).
   */
  CWinLogTarget sLogWindowTarget{};
} // namespace moho

namespace
{
  constexpr float kMaxFiniteTimeoutMs = 4294967300.0f;
  constexpr float kInfiniteWakeupMs = std::numeric_limits<float>::infinity();

  moho::IWinApp* sSupComApp = nullptr;
#if FAFRE_PLATFORM_WINDOWS
  HHOOK sWindowHook = nullptr;
#endif
  gpg::time::Timer wakeupTimer;
  float wakeupTimerDur = kInfiniteWakeupMs;
#if FAFRE_PLATFORM_WINDOWS
  [[maybe_unused]] constexpr DWORD kPlatformSymbolHandlerOptions =
    SYMOPT_FAIL_CRITICAL_ERRORS | // suppress critical-error UI while probing symbols.
    SYMOPT_LOAD_LINES |           // include source line records for resolved addresses.
    SYMOPT_DEFERRED_LOADS |       // lazily load module symbols as needed.
    SYMOPT_UNDNAME;               // undecorate C++ names in symbol output.
  static_assert(
    kPlatformSymbolHandlerOptions == 0x216u,
    "PLAT_Init symbol options must match recovered SymSetOptions(0x216)"
  );
#endif

  // The splash screen WINX_InitSplash shows (0x010A9BE4, a `std::auto_ptr<wxSplashScreen>` in the
  // binary) is the window system's (platform::window::ShowSplash, issue #407).

  using LegacyUnaryCdeclCallback = int(__cdecl*)(int value);
  using LegacyUnaryDispatchAdapter = int(__cdecl*)(LegacyUnaryCdeclCallback* callbackLane, int value);
  using LegacyTypeInfoLane = const std::type_info*;
  using LegacyTypeInfoDispatchAdapter = LegacyTypeInfoLane*(__cdecl*)(LegacyTypeInfoLane * sourceLane,
                                                                      LegacyTypeInfoLane* destinationLane,
                                                                      LegacyTypeInfoLane* queryLane);
  using LegacyCallbackLifecycleAdapter = int(__cdecl*)(void* sourceLane, void* destinationLane, int action);

  struct LegacyCallbackPayloadLane
  {
    LegacyCallbackLifecycleAdapter lifecycleAdapter;
    std::uint32_t reserved04;
    std::byte payload[0x18];
  };
  static_assert(sizeof(LegacyCallbackPayloadLane) == 0x20, "LegacyCallbackPayloadLane size must be 0x20");

  LegacyUnaryDispatchAdapter gLegacyTimeBarUnaryDispatchAdapter = nullptr;
  LegacyTypeInfoDispatchAdapter gLegacyTimeBarTypeInfoDispatchAdapter = nullptr;

  /**
   * Address: 0x004E82D0 (FUN_004E82D0)
   *
   * What it does:
   * Invokes one stored unary cdecl callback with the given value. Installed
   * into `gLegacyTimeBarUnaryDispatchAdapter`/`gLegacyTssAdapterUnaryDispatchAdapter`
   * as the manager/invoker install for a `boost::function1<void,
   * Moho::STimeBarThreadInfo*>`-shaped TSS-slot dispatcher.
   */
  int __cdecl LegacyInvokeUnaryCallback(
    LegacyUnaryCdeclCallback* const callbackLane,
    const int value
  )
  {
    return (*callbackLane)(value);
  }

  /**
   * Address: 0x004E82E0 (FUN_004E82E0)
   *
   * What it does:
   * `basic_vtable<F>::manager`-shaped RTTI/clone/reset dispatcher for the
   * same TSS-slot deleter Functor `LegacyInvokeUnaryCallback` invokes:
   * publishes `typeid(TimeBarThreadCallback)` on the publish-type query,
   * copies/resets/compares the stored callback slot on the other query
   * codes. Installed into `gLegacyTimeBarTypeInfoDispatchAdapter`.
   */
  LegacyTypeInfoLane* __cdecl LegacyResolveTimeBarThreadCallbackTypeInfo(
    LegacyTypeInfoLane* const sourceLane,
    LegacyTypeInfoLane* const destinationLane,
    LegacyTypeInfoLane* const queryLane
  )
  {
    using TimeBarThreadCallback = void(__cdecl*)(moho::STimeBarThreadInfo*);

    constexpr std::uintptr_t kQueryCopy = 0u;
    constexpr std::uintptr_t kQueryReset = 1u;
    constexpr std::uintptr_t kQueryPublishType = 3u;

    LegacyTypeInfoLane* result = queryLane;
    const std::uintptr_t queryToken = reinterpret_cast<std::uintptr_t>(queryLane);
    const LegacyTypeInfoLane callbackTypeInfo = &typeid(TimeBarThreadCallback);

    if (queryToken == kQueryPublishType) {
      *destinationLane = callbackTypeInfo;
      return result;
    }

    if (queryToken == kQueryCopy) {
      *destinationLane = *sourceLane;
      return sourceLane;
    }

    if (queryToken == kQueryReset) {
      *destinationLane = nullptr;
      return destinationLane;
    }

    result = (*destinationLane == callbackTypeInfo) ? sourceLane : nullptr;
    *destinationLane = (result != nullptr) ? *result : nullptr;
    return result;
  }

  /**
   * Address: 0x004E81C0 (FUN_004E81C0)
   *
   * IDA signature:
   * int __usercall sub_4E81C0@<eax>(_DWORD *source@<edx>, _DWORD *destination);
   *
   * What it does:
   * Copies one legacy callback payload lane into an already-allocated
   * destination buffer. First clears `destination->lifecycleAdapter`, then
   * when the source's adapter is non-null, copies the adapter pointer and
   * invokes it with `action = 0` (kCopy) so the adapter moves its heap-owned
   * payload bytes from source into destination. Returns the same destination
   * pointer (or the passed-in lane when destination is null).
   *
   * This is the in-place per-lane copy used by `CloneLegacyCallbackPayloadLaneToHeap`
   * (FUN_004E7F70) and its neighbors; it is the non-allocating counterpart
   * that existing recovered clone paths invoke by name.
   */
  LegacyCallbackPayloadLane* CopyLegacyCallbackPayloadLaneIntoExisting(
    LegacyCallbackPayloadLane* const sourceLane,
    LegacyCallbackPayloadLane* const destinationLane
  )
  {
    if (destinationLane == nullptr) {
      return destinationLane;
    }

    destinationLane->lifecycleAdapter = nullptr;
    if (sourceLane != nullptr && sourceLane->lifecycleAdapter != nullptr) {
      destinationLane->lifecycleAdapter = sourceLane->lifecycleAdapter;
      destinationLane->lifecycleAdapter(sourceLane->payload, destinationLane->payload, 0);
    }

    return destinationLane;
  }

  /**
   * Address: 0x004E7F70 (FUN_004E7F70)
   *
   * What it does:
   * Clones one 0x20-byte legacy callback payload lane to heap storage and
   * returns the callback adapter lane after running the source cleanup path.
   */
  LegacyCallbackLifecycleAdapter CloneLegacyCallbackPayloadLaneToHeap(
    LegacyCallbackPayloadLane* const sourceLane,
    LegacyCallbackPayloadLane** const destinationHeapLane
  )
  {
    auto* const destinationLane =
      static_cast<LegacyCallbackPayloadLane*>(::operator new(sizeof(LegacyCallbackPayloadLane)));

    // Copy lifecycle adapter + payload bytes via the in-place lane copy
    // helper (FUN_004E81C0). This is the exact subroutine the binary calls
    // from 0x004E7F9F inside this function.
    (void)CopyLegacyCallbackPayloadLaneIntoExisting(sourceLane, destinationLane);

    *destinationHeapLane = destinationLane;

    LegacyCallbackLifecycleAdapter result = (sourceLane != nullptr) ? sourceLane->lifecycleAdapter : nullptr;
    if (result != nullptr) {
      result(sourceLane->payload, sourceLane->payload, 1);
    }

    return result;
  }

  /**
   * Address: 0x004E7ED0 (FUN_004E7ED0)
   *
   * What it does:
   * Publishes the legacy CRT callback adapter pair used by RTTI callback
   * dispatch for TimeBar thread callback lanes.
   */
  // Forward decl for the bootstrap helper that drives FUN_004E7B40.
  LegacyTypeInfoLane* LegacyBootstrapTimeBarUnaryFunctionSlotTypeInfo(
    LegacyTypeInfoLane* const sourceSlot,
    LegacyTypeInfoLane* const destinationSlot
  ) noexcept;

  [[maybe_unused]] void InitializeLegacyTimeBarTypeInfoDispatchAdapters()
  {
    gLegacyTimeBarUnaryDispatchAdapter = &LegacyInvokeUnaryCallback;
    gLegacyTimeBarTypeInfoDispatchAdapter = &LegacyResolveTimeBarThreadCallbackTypeInfo;
    // Anchor the FUN_004E7B40 unary-adapter pair publisher in source. The
    // call is a no-op when destinationSlot is null, so threading is safe.
    (void)LegacyBootstrapTimeBarUnaryFunctionSlotTypeInfo(nullptr, nullptr);
  }

  // ---------------------------------------------------------------------------
  // Legacy boost::thread_specific_ptr<STimeBarThreadInfo> bootstrap lanes
  // ---------------------------------------------------------------------------
  //
  // The original 2007 source used `boost::thread_specific_ptr<STimeBarThreadInfo>`
  // to manage per-thread TimeBar state, with a boost::function1<void,
  // STimeBarThreadInfo*> deleter wired through the once-init adapter pair
  // (published in `gLegacyTimeBar*DispatchAdapter`). The modern source replaced
  // that whole TSS apparatus with a single `thread_local TimeBarThreadSlot
  // gThreadSlot;` declaration in `moho/misc/TimeBar.cpp` plus a
  // `std::call_once`-driven runtime bootstrap.
  //
  // The binary still emits the full boost::function/tss adapter machinery
  // because it was instantiated against the engine type
  // `Moho::STimeBarThreadInfo`. Per the recovery policy
  // (`feedback_no_template_emission_skipping`) those engine-instantiated
  // template emissions must be recovered as modern named helpers with their
  // own Doxygen address blocks, even though the modern equivalent of the
  // top-of-chain (`boost::thread_specific_ptr<...>::ctor`) is a single
  // `thread_local` declaration.
  //
  // The helpers below collectively model:
  //
  //   FUN_004E7B40 — once-init publisher for the unary-callback adapter pair
  //                  (`gLegacyTimeBarUnaryDispatchAdapter`,
  //                   `gLegacyTimeBarTypeInfoDispatchAdapter`) and slot-reset
  //                  via `kQueryReset`.
  //   FUN_004E77D0 — copy-construct trampoline that pulls the source slot's
  //                  typeinfo, zeroes the destination, and re-publishes via
  //                  `LegacyPublishTimeBarUnaryDispatchAdaptersOnce`.
  //   FUN_004E77F0 — boost::function1<>::function1(F&) lifecycle wrapper that
  //                  invokes the buffer's `kQueryCopy` adapter call, then
  //                  delegates the actual assign to
  //                  `LegacyOnceInitAndAssignTimeBarCallbackBuffer`.
  //   FUN_004E7990 — boost::function1<>::assign_a once-init path that runs the
  //                  unary-publisher once and the per-instance functor copy.
  //   FUN_004E7BA0 — boost::function1<>::clear path that clears the per-this
  //                  payload lanes and delegates to
  //                  `LegacyPublishTssAdapterDispatchPairOnce`.
  //   FUN_004E7C50 — boost::function1<>::manage that runs the source's
  //                  `kQueryCopy` adapter call and delegates allocate-and-fill
  //                  to `LegacyAllocateAndFillTssAdapterPayload`.
  //   FUN_004E7D30 — once-init publisher for the tss_adapter dispatch pair
  //                  (publishes into `gLegacyTssAdapter*DispatchAdapter`).
  //   FUN_004E7DF0 — boost::function1<>::manage::do_alloc path that allocates
  //                  the function buffer, calls
  //                  `LegacyAllocateTssAdapterFunctionBuffer`, and gates on
  //                  the safe-context predicate.
  //   FUN_004E8010 — typeinfo resolver for `tss_adapter<STimeBarThreadInfo>`
  //                  (modern: `LegacyResolveTssAdapterStimeBarThreadInfoTypeInfo`).
  //   FUN_004E80B0 — `tss_adapter<>` lifecycle: `kQueryCreate` allocates
  //                  storage via `LegacyAllocateTssAdapterFunctionBuffer`,
  //                  `kQueryDestroy` deletes it, `kQueryCompareType` compares
  //                  against the `tss_adapter<STimeBarThreadInfo>` RTTI.
  //   FUN_004E7430 — the "F" in `boost::function1<void, STimeBarThreadInfo*>
  //                  ::function1(F&)`: TSS-slot deleter callback
  //                  (`LegacyDeleteTimeBarThreadInfoTssPayload`) that
  //                  unlinks the payload from its intrusive ring
  //                  (`TDatListItem<STimeBarThreadInfo, void>::
  //                  ListUnlinkSelf()`) then releases it. Address-taken by
  //                  `FUN_004E7130` and passed into `FUN_004E7B40`; not a
  //                  member of the internal chain diagram below (it is the
  //                  payload the chain carries, not a link in it). Formerly
  //                  mis-recovered as a hand-rolled `IntrusiveListNode
  //                  a deleted overlay/deleted overlay pair in
  //                  `gpg/core/containers/FastVectorInsertLanes.cpp` (wrong
  //                  subsystem, wrong field order, zero real xrefs there) --
  //                  removed; this is the corrected home.
  //
  // Source-level invocation: the modern equivalent of the top-of-chain ctor
  // (`boost::thread_specific_ptr<STimeBarThreadInfo>::ctor`, FUN_004E7130) is
  // the `thread_local TimeBarThreadSlot gThreadSlot;` declaration in
  // `moho/misc/TimeBar.cpp:808`. The internal chain below is wired by name
  // (each helper calls its successor by C++ identifier), so the linker
  // preserves the per-T symbol shape.
  //
  // ---------------------------------------------------------------------------

  // Shared adapter-pair guard byte mirroring `dword_10C7B04 & 1` in the
  // binary. Static-storage `std::once_flag` would be the modern idiom, but we
  // keep the binary's single-byte guard to preserve byte layout in the .data
  // section that other recovered helpers reference by address.
  bool gLegacyTimeBarUnaryAdapterPairPublished = false;

  // Adapter pair for the `tss_adapter<STimeBarThreadInfo>` lifecycle, used by
  // the boost::function1 manage / clear / manage::do_alloc lanes.
  LegacyUnaryDispatchAdapter gLegacyTssAdapterUnaryDispatchAdapter = nullptr;
  LegacyTypeInfoDispatchAdapter gLegacyTssAdapterTypeInfoDispatchAdapter = nullptr;

  // Synthetic engine-T binding for the `boost::detail::tss_adapter<T>` RTTI
  // Type Descriptor referenced at 0x00F61928 in the binary.
  // (RTTI string: `??_R0?AU?$tss_adapter@USTimeBarThreadInfo@Moho@@@detail@boost@@@8`)
  // The size matches the binary's tss_adapter<T> layout: { deleter_fn_ptr,
  // payload_ptr } = 8 bytes on x86. Used only as a typeid anchor — instances
  // are never constructed; only `&typeid(TssAdapterStimeBarThreadInfo)` is
  // compared.
  struct TssAdapterStimeBarThreadInfo
  {
    void* mDeleterCallback;
    moho::STimeBarThreadInfo* mPayload;
  };
  static_assert(sizeof(TssAdapterStimeBarThreadInfo) == 0x08, "TssAdapterStimeBarThreadInfo size must be 0x08");

  /**
   * Address: 0x004E8010 (FUN_004E8010)
   *
   * IDA signature:
   * int __cdecl sub_4E8010(int a1, type_info **a2, int a3);
   *
   * What it does:
   * Typeinfo resolver for `boost::detail::tss_adapter<Moho::STimeBarThreadInfo>`
   * used as the boost::function1<>::manage adapter callback. On
   * `kQueryPublishType` (a3 == 3) it writes the RTTI Type Descriptor for
   * `tss_adapter<STimeBarThreadInfo>` into `*a2`. All other queries delegate
   * to `LegacyDispatchTssAdapterLifecycleQuery` (FUN_004E80B0).
   */
  LegacyTypeInfoLane* __cdecl LegacyResolveTssAdapterStimeBarThreadInfoTypeInfo(
    LegacyTypeInfoLane* const sourceLane,
    LegacyTypeInfoLane* const destinationLane,
    LegacyTypeInfoLane* const queryLane
  );

  /**
   * Address: 0x004E80B0 (FUN_004E80B0)
   *
   * IDA signature:
   * void __usercall sub_4E80B0(int a1@<eax>, type_info **a2@<ecx>,
   *                            type_info **a3@<edi>);
   *
   * What it does:
   * Lifecycle adapter for `boost::detail::tss_adapter<STimeBarThreadInfo>` —
   * the operator new / operator delete / RTTI-compare path used by the
   * boost::function1 manage chain. The `query` token selects:
   *   - kQueryCreate (0): allocate a fresh adapter buffer via
   *     `LegacyAllocateTssAdapterFunctionBuffer` (FUN_004E8170), publish it
   *     via `LegacyCopyTssAdapterFunctionBufferIntoExisting` (FUN_004E81C0),
   *     and store it in `*destinationLane`.
   *   - kQueryDestroy (1): walk the buffer's lifecycle adapter, invoke
   *     `kQueryReset` on it, then `operator delete` the buffer.
   *   - default (any other): compare `*destinationLane`'s RTTI against the
   *     `tss_adapter<STimeBarThreadInfo>` Type Descriptor and either follow
   *     the equal branch (assign source through) or clear the destination
   *     lane.
   */
  void LegacyDispatchTssAdapterLifecycleQuery(
    const std::uintptr_t queryToken,
    LegacyTypeInfoLane* const sourceLane,
    LegacyTypeInfoLane* const destinationLane
  )
  {
    const LegacyTypeInfoLane tssAdapterTypeInfo = &typeid(TssAdapterStimeBarThreadInfo);

    if (queryToken == 0u) {
      // kQueryCreate: allocate one fresh function-buffer lane and stamp the
      // adapter pair into it. The 1-element call to the byte-count throw-
      // capping allocator mirrors `sub_4E8170(1)` in the binary, which is
      // bounded at 32 bytes per element with `bad_alloc` on overflow.
      LegacyCallbackPayloadLane* const sourceBuffer = reinterpret_cast<LegacyCallbackPayloadLane*>(sourceLane);
      auto* const adapterBuffer =
        static_cast<LegacyCallbackPayloadLane*>(::operator new(sizeof(LegacyCallbackPayloadLane)));
      (void)CopyLegacyCallbackPayloadLaneIntoExisting(sourceBuffer, adapterBuffer);
      *destinationLane = reinterpret_cast<LegacyTypeInfoLane>(adapterBuffer);
      return;
    }

    if (queryToken == 1u) {
      // kQueryDestroy: cleanly tear down the stored callback lane (run its
      // own kQueryReset op via the lifecycle adapter), then free the buffer.
      auto* const adapterBuffer =
        const_cast<LegacyCallbackPayloadLane*>(reinterpret_cast<const LegacyCallbackPayloadLane*>(*destinationLane));
      if (adapterBuffer != nullptr) {
        auto* const innerLane = reinterpret_cast<LegacyCallbackPayloadLane*>(adapterBuffer->payload);
        if (innerLane != nullptr) {
          LegacyCallbackLifecycleAdapter const lifecycleAdapter = innerLane->lifecycleAdapter;
          if (lifecycleAdapter != nullptr) {
            lifecycleAdapter(innerLane, innerLane, 1);
          }
          // Mirror `mov dword ptr [esi], 0` at 0x4E80F3.
          adapterBuffer->lifecycleAdapter = nullptr;
        }
        ::operator delete(adapterBuffer);
      }
      *destinationLane = nullptr;
      return;
    }

    // kQueryCompareType (any other value): RTTI compare against the
    // `tss_adapter<STimeBarThreadInfo>` Type Descriptor. If equal, publish
    // the source through; otherwise clear the destination.
    const LegacyTypeInfoLane currentType = *destinationLane;
    if (currentType != nullptr && *currentType == *tssAdapterTypeInfo) {
      *destinationLane = *sourceLane;
    } else {
      *destinationLane = nullptr;
    }
  }

  void LegacyDispatchTssAdapterLifecycleQueryEntry(
    const std::uintptr_t queryToken,
    LegacyTypeInfoLane* const sourceLane,
    LegacyTypeInfoLane* const destinationLane
  )
  {
    LegacyDispatchTssAdapterLifecycleQuery(queryToken, sourceLane, destinationLane);
  }

  LegacyTypeInfoLane* __cdecl LegacyResolveTssAdapterStimeBarThreadInfoTypeInfo(
    LegacyTypeInfoLane* const sourceLane,
    LegacyTypeInfoLane* const destinationLane,
    LegacyTypeInfoLane* const queryLane
  )
  {
    // Synthetic engine-T binding for the boost::detail::tss_adapter<T> RTTI
    // Type Descriptor referenced at 0x00F61928 in the binary.
    // (RTTI string: `??_R0?AU?$tss_adapter@USTimeBarThreadInfo@Moho@@@detail@boost@@@8`)
    struct TssAdapterStimeBarThreadInfo
    {
      void* mDeleterCallback;
      moho::STimeBarThreadInfo* mPayload;
    };

    constexpr std::uintptr_t kQueryPublishType = 3u;
    const LegacyTypeInfoLane tssAdapterTypeInfo = &typeid(TssAdapterStimeBarThreadInfo);
    const std::uintptr_t queryToken = reinterpret_cast<std::uintptr_t>(queryLane);

    if (queryToken == kQueryPublishType) {
      *destinationLane = tssAdapterTypeInfo;
      return queryLane;
    }

    LegacyDispatchTssAdapterLifecycleQueryEntry(queryToken, sourceLane, destinationLane);
    return queryLane;
  }

  /**
   * Address: 0x004E7B40 (FUN_004E7B40)
   *
   * IDA signature:
   * type_info **(__cdecl *__usercall sub_4E7B40@<eax>(type_info *a1@<ebx>,
   *                                                   type_info **a2@<edi>))
   *                                                   (type_info **,
   *                                                    type_info **,
   *                                                    type_info **);
   *
   * What it does:
   * Once-init publisher for the unary-callback adapter pair used by the
   * `boost::function1<void, STimeBarThreadInfo*>` slot inside
   * `boost::thread_specific_ptr<STimeBarThreadInfo>`. Mirrors the binary's
   * `dword_10C7B04 & 1` once-flag protection of
   * `dword_10C7938`/`dword_10C793C` (the same lane pair that
   * `InitializeLegacyTimeBarTypeInfoDispatchAdapters` publishes). After the
   * once-init, runs `kQueryReset (=1)` on the published typeinfo resolver to
   * clear `slot[+2..+3]`, then attaches the new typeinfo (`a1`) to
   * `slot[+2]` and sets `*slot` to the published lane pair pointer.
   */
  LegacyTypeInfoDispatchAdapter LegacyPublishTimeBarUnaryDispatchAdaptersOnce(
    const LegacyTypeInfoLane sourceTypeInfo,
    LegacyTypeInfoLane* const slotBase
  ) noexcept
  {
    LegacyTypeInfoDispatchAdapter typeInfoAdapter;
    if (!gLegacyTimeBarUnaryAdapterPairPublished) {
      gLegacyTimeBarUnaryAdapterPairPublished = true;
      InitializeLegacyTimeBarTypeInfoDispatchAdapters();
      typeInfoAdapter = gLegacyTimeBarTypeInfoDispatchAdapter;
    } else {
      typeInfoAdapter = gLegacyTimeBarTypeInfoDispatchAdapter;
    }

    LegacyTypeInfoLane* const innerSlot = slotBase + 2;
    if (typeInfoAdapter != nullptr) {
      // kQueryReset: zero out the inner slot via the published resolver.
      (void)typeInfoAdapter(innerSlot, innerSlot, reinterpret_cast<LegacyTypeInfoLane*>(1));
    }

    if (sourceTypeInfo != nullptr) {
      innerSlot[0] = sourceTypeInfo;
      *slotBase = reinterpret_cast<LegacyTypeInfoLane>(&gLegacyTimeBarUnaryDispatchAdapter);
    } else {
      *slotBase = nullptr;
    }
    return typeInfoAdapter;
  }

  // Source-level wire-up anchor for FUN_004E7B40
  // (`LegacyPublishTimeBarUnaryDispatchAdaptersOnce`). The binary calls
  // FUN_004E7B40 from FUN_004E7130 (boost::thread_specific_ptr<...>::ctor)
  // and from FUN_004E77D0 (EH copy thunk — `skip`'d as compiler emission).
  // We invoke the modern helper once at TimeBar runtime bootstrap to keep
  // its symbol shape; the inner once-init guard makes repeat calls cheap.
  LegacyTypeInfoLane* LegacyBootstrapTimeBarUnaryFunctionSlotTypeInfo(
    LegacyTypeInfoLane* const sourceSlot,
    LegacyTypeInfoLane* const destinationSlot
  ) noexcept
  {
    const LegacyTypeInfoLane sourceTypeInfo = (sourceSlot != nullptr) ? *sourceSlot : nullptr;
    if (destinationSlot != nullptr) {
      *destinationSlot = nullptr;
      (void)LegacyPublishTimeBarUnaryDispatchAdaptersOnce(sourceTypeInfo, destinationSlot);
    }
    return destinationSlot;
  }

  /**
   * Address: 0x004E7990 (FUN_004E7990)
   *
   * IDA signature:
   * void (__cdecl *__userpurge sub_4E7990@<eax>(_DWORD *a1@<edi>,
   *                                              void (__cdecl **a2)(char*, char*, int),
   *                                              ...))(char*, char*, int);
   *
   * What it does:
   * boost::function1<>::assign_a-style internal: gates on
   * `gLegacyTssAdapterDispatchPairPublished` to once-publish the tss_adapter
   * dispatch pair, then runs the per-instance allocate-and-fill path via
   * `LegacyAllocateAndFillTssAdapterPayload`. Mirrors the binary's
   * `dword_1104098 & 1` guard around the FUN_004E7BA0 publisher path.
   */
  bool LegacyAllocateAndFillTssAdapterPayload(
    LegacyCallbackPayloadLane* const outBuffer,
    LegacyCallbackPayloadLane* const sourceCallback,
    const std::byte* const localStackBytes
  );

  // Forward declaration for the FUN_004E7D30 once-init publisher, used by the
  // FUN_004E7BA0 clear-path further down.
  LegacyUnaryDispatchAdapter
  LegacyPublishTssAdapterDispatchPairOnce(LegacyCallbackPayloadLane* const sourceCallback, const int a2, const char a3);

  // Forward decl for LegacyManageTssAdapterFunctionSlot (FUN_004E7C50).
  bool LegacyManageTssAdapterFunctionSlot(
    LegacyCallbackPayloadLane* const outBufferTail,
    LegacyCallbackPayloadLane* const sourceCallback,
    const char a4
  );

  // Forward decl for LegacyClearAndPublishTssAdapterPair (FUN_004E7BA0).
  LegacyUnaryDispatchAdapter*
  LegacyClearAndPublishTssAdapterPair(LegacyCallbackPayloadLane* const sourceCallback, const int a2, const char a3);

  /**
   * Address: 0x004E7BA0 (FUN_004E7BA0)
   *
   * IDA signature:
   * int *__stdcall sub_4E7BA0(void (__cdecl **a1)(char*, char*, int),
   *                            int a2, char a3, ...);
   *
   * What it does:
   * boost::function1<>::clear-style entry: zeroes the
   * `gLegacyTssAdapter*DispatchAdapter` lane pair, prepares a local
   * function-buffer view from the source callback, and delegates the
   * adapter-pair publish to `LegacyPublishTssAdapterDispatchPairOnce`. After
   * the inner publish, runs `kQueryReset` on the source callback.
   */
  LegacyUnaryDispatchAdapter* LegacyClearAndPublishTssAdapterPair(
    LegacyCallbackPayloadLane* const sourceCallback,
    [[maybe_unused]] const int a2,
    const char a3
  )
  {
    gLegacyTssAdapterUnaryDispatchAdapter = nullptr;
    gLegacyTssAdapterTypeInfoDispatchAdapter = nullptr;

    LegacyCallbackPayloadLane localBuffer{};
    char localKey = a3;
    char localCopyStorage = 0;

    if (sourceCallback != nullptr) {
      localBuffer = *sourceCallback;
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localCopyStorage, 0);
      }
    }

    (void)LegacyPublishTssAdapterDispatchPairOnce(&localBuffer, a2, localCopyStorage);

    if (sourceCallback != nullptr) {
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localKey, 1);
      }
    }
    return &gLegacyTssAdapterUnaryDispatchAdapter;
  }

  /**
   * Address: 0x004E7C50 (FUN_004E7C50)
   *
   * IDA signature:
   * char __thiscall sub_4E7C50(void *this, void (__cdecl **a2)(...),
   *                              int a3, char a4, ...);
   *
   * What it does:
   * boost::function1<>::manage-style entry: clones the source callback's
   * payload via `kQueryCopy`, then delegates allocate-and-fill to
   * `LegacyAllocateAndFillTssAdapterPayload` (which calls the
   * heap-allocating manage::do_alloc path at FUN_004E7DF0). Returns the
   * boolean result of the allocate path.
   */
  bool LegacyManageTssAdapterFunctionSlot(
    LegacyCallbackPayloadLane* const outBufferTail,
    LegacyCallbackPayloadLane* const sourceCallback,
    const char a4
  )
  {
    LegacyCallbackPayloadLane localBuffer{};
    char localKey = a4;
    char localCopyStorage = 0;

    if (sourceCallback != nullptr) {
      localBuffer = *sourceCallback;
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localCopyStorage, 0);
      }
    }

    const bool result = LegacyAllocateAndFillTssAdapterPayload(
      outBufferTail, &localBuffer, reinterpret_cast<const std::byte*>(&localCopyStorage)
    );

    if (sourceCallback != nullptr) {
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localKey, 1);
      }
    }
    return result;
  }

  /**
   * Address: 0x004E7D30 (FUN_004E7D30)
   *
   * IDA signature:
   * int (__cdecl *__stdcall sub_4E7D30(int (__cdecl *a1)(char*, char*, int),
   *                                      int a2, char a3, ...))(char*, char*, int);
   *
   * What it does:
   * Once-init publisher for the `tss_adapter<STimeBarThreadInfo>` dispatch
   * pair. Runs `kQueryCopy` on the source callback first (to materialize the
   * adapter's typeinfo payload), then publishes the pair into the global
   * lane variables. Finally runs `kQueryReset` on the source callback.
   */
  LegacyUnaryDispatchAdapter LegacyPublishTssAdapterDispatchPairOnce(
    LegacyCallbackPayloadLane* const sourceCallback,
    [[maybe_unused]] const int /*a2*/,
    const char a3
  )
  {
    char localKey = a3;
    char localCopyStorage[24]{};

    if (sourceCallback != nullptr) {
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(reinterpret_cast<void*>(&localKey), reinterpret_cast<void*>(localCopyStorage), 0);
      }
    }

    gLegacyTssAdapterUnaryDispatchAdapter = &LegacyInvokeUnaryCallback;
    gLegacyTssAdapterTypeInfoDispatchAdapter = &LegacyResolveTssAdapterStimeBarThreadInfoTypeInfo;

    if (sourceCallback != nullptr) {
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localKey, 1);
      }
    }

    LegacyCallbackLifecycleAdapter sourceLifecycle = nullptr;
    if (sourceCallback != nullptr) {
      sourceLifecycle = sourceCallback->lifecycleAdapter;
    }
    return reinterpret_cast<LegacyUnaryDispatchAdapter>(reinterpret_cast<void (*)()>(sourceLifecycle));
  }

  /**
   * Address: 0x004E7DF0 (FUN_004E7DF0)
   *
   * IDA signature:
   * char __thiscall sub_4E7DF0(void (__cdecl ***this)(...),
   *                              void (__cdecl **a2)(...), int a3, char a4,
   *                              ..., _DWORD *a10, int a11);
   *
   * What it does:
   * boost::function1<>::manage::do_alloc path: gates on the
   * `sub_412B30` early-process predicate (modern: `IsRecoveredEarlyProcess`
   * — `false` means we may allocate; `true` means the allocate is a no-op
   * because we're too early in startup). On the allocate branch, runs
   * `kQueryCopy` on the source, then allocates and fills the tss_adapter
   * function buffer via `LegacyAllocateTssAdapterFunctionBuffer`
   * (FUN_004E8170) + `LegacyForwardTssAdapterFunctionBufferToHeap`
   * (FUN_004E7F70). Returns false when gated, true on success.
   */
  bool LegacyAllocateAndFillTssAdapterPayload(
    LegacyCallbackPayloadLane* const outBuffer,
    LegacyCallbackPayloadLane* const sourceCallback,
    [[maybe_unused]] const std::byte* const localStackBytes
  )
  {
    // FUN_00412B30 is a `return 0;` predicate in the binary — always false —
    // so the binary's `if (sub_412B30()) { return 0; }` gate is unreachable
    // in modern source. We collapse it away and fall through to the
    // allocate-and-fill path that the binary always takes.
    LegacyCallbackPayloadLane localBuffer{};
    char localKey = 0;
    char localCopyStorage = 0;

    if (sourceCallback != nullptr) {
      localBuffer = *sourceCallback;
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localCopyStorage, 0);
      }
    }

    // FUN_004E7F70 is `CloneLegacyCallbackPayloadLaneToHeap` already in this
    // file; for the tss_adapter manage path we reuse the same heap-clone
    // helper to produce an out-of-line owned buffer.
    LegacyCallbackPayloadLane* heapLane = nullptr;
    (void)CloneLegacyCallbackPayloadLaneToHeap(&localBuffer, &heapLane);
    if (outBuffer != nullptr) {
      outBuffer->lifecycleAdapter = (heapLane != nullptr) ? heapLane->lifecycleAdapter : nullptr;
    }

    if (sourceCallback != nullptr) {
      LegacyCallbackLifecycleAdapter const lifecycleAdapter = sourceCallback->lifecycleAdapter;
      if (lifecycleAdapter != nullptr) {
        lifecycleAdapter(&localKey, &localKey, 1);
      }
    }
    return true;
  }

  [[maybe_unused]] const bool gWinAppBootstrap = []() {
    moho::register_startTime();
    moho::register_wakeupTimer();
    return true;
  }();

#if FAFRE_PLATFORM_WINDOWS
  constexpr wchar_t kDxdiagOutputFileName[] = L"dxdiag.txt";
  constexpr wchar_t kDxdiagCommandPrefix[] = L"dxdiag.exe ";
#endif // FAFRE_PLATFORM_WINDOWS: dxdiag

  /**
   * Address: 0x004A0EC0 (FUN_004A0EC0, sub_4A0EC0)
   *
   * What it does:
   * Returns the inline-buffer subobject pointer (`this + 4`) for one recovered
   * legacy wide-string layout view.
   */
  struct LegacyWideStringObject
  {
    std::uint32_t allocatorState = 0;
    union
    {
      wchar_t* heap = nullptr;
      wchar_t inlineBuffer[8];
    } storage;
    std::uint32_t length = 0;
    std::uint32_t capacity = 7;
  };

#if defined(_M_IX86)
  static_assert(sizeof(LegacyWideStringObject) == 0x1C, "LegacyWideStringObject size must be 0x1C");
#endif

  /**
   * Address: 0x004A1820 (FUN_004A1820, sub_4A1820)
   *
   * What it does:
   * Appends one zero-terminated wide source to the destination string.
   */
  [[maybe_unused]] std::wstring* AppendWideStringFromNullTerminatedInputA(
    std::wstring* const destination,
    const wchar_t* const source
  )
  {
    const wchar_t* const safeSource = (source != nullptr) ? source : L"";
    return moho::AppendWideRangePreservingOverlap(destination, safeSource, std::wcslen(safeSource));
  }

  struct LegacyWideStringVectorAccessor
  {
    std::uint32_t reserved = 0;
    LegacyWideStringObject* first = nullptr;
  };

  /**
   * Address: 0x004A1BF0 (FUN_004A1BF0)
   * Mangled:
   * ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@ABV10@PB_W@Z
   *
   * What it does:
   * Builds `lhs + rhs` for one wide-string plus zero-terminated wide literal.
   */
  [[maybe_unused]] std::wstring BuildWideStringPlusWideLiteral(
    const std::wstring& lhs,
    const wchar_t* const rhs
  )
  {
    std::wstring tmp(lhs);
    const wchar_t* const safeRhs = (rhs != nullptr) ? rhs : L"";
    tmp += safeRhs;
    return tmp;
  }

  /**
   * Address: 0x004A1D50 (FUN_004A1D50)
   * Mangled:
   * ??$?H_WU?$char_traits@_W@std@@V?$allocator@_W@1@@std@@YA?AV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@0@ABV10@0@Z
   *
   * What it does:
   * Builds `lhs + rhs` for one wide-string plus wide-string pair.
   */
  [[maybe_unused]] std::wstring BuildWideStringPlusWideString(
    const std::wstring& lhs,
    const std::wstring& rhs
  )
  {
    std::wstring tmp(lhs);
    tmp.append(rhs, 0, std::wstring::npos);
    return tmp;
  }

  /**
   * Address: 0x004A1E10 (FUN_004A1E10, j__strrchr)
   *
   * What it does:
   * Forwards one C-string reverse-character search to CRT `strrchr`.
   */
  [[maybe_unused]] char* FindLastCharacterInCString(
    char* const text,
    const int character
  ) noexcept
  {
    return std::strrchr(text, character);
  }

  struct LegacyUint32PairEmitter
  {
    std::uint32_t reserved0 = 0;
    std::uint32_t secondValue = 0;
    std::uint32_t firstBase = 0;
  };

  struct LegacyUint32Pair
  {
    std::uint32_t first = 0;
    std::uint32_t second = 0;
  };

#if defined(_M_IX86)
  static_assert(sizeof(LegacyUint32PairEmitter) == 0x0C, "LegacyUint32PairEmitter size must be 0x0C");
  static_assert(sizeof(LegacyUint32Pair) == 0x08, "LegacyUint32Pair size must be 0x08");
#endif

  // The registry, dxdiag, the Windows-key hook, the crash dialog and the structured-exception
  // filter are Windows' (the Linux client, issue #255).
#if FAFRE_PLATFORM_WINDOWS
  struct ParsedRegistryPath
  {
    HKEY rootKey = HKEY_CURRENT_USER;
    char* subKey = nullptr;
    const char* valueName = nullptr;
  };

  [[nodiscard]] HKEY ResolveRegistryRootKey(
    const char* const rootKeyName
  ) noexcept
  {
    if (rootKeyName == nullptr) {
      return HKEY_CURRENT_USER;
    }
    if (_stricmp(rootKeyName, "HKEY_CLASSES_ROOT") == 0) {
      return HKEY_CLASSES_ROOT;
    }
    if (_stricmp(rootKeyName, "HKEY_CURRENT_USER") == 0) {
      return HKEY_CURRENT_USER;
    }
    if (_stricmp(rootKeyName, "HKEY_LOCAL_MACHINE") == 0) {
      return HKEY_LOCAL_MACHINE;
    }
    if (_stricmp(rootKeyName, "HKEY_USERS") == 0) {
      return HKEY_USERS;
    }
    if (_stricmp(rootKeyName, "HKEY_CURRENT_CONFIG") == 0) {
      return HKEY_CURRENT_CONFIG;
    }
    if (_stricmp(rootKeyName, "HKEY_DYN_DATA") == 0) {
      return reinterpret_cast<HKEY>(static_cast<std::uintptr_t>(0x80000006u));
    }
    if (_stricmp(rootKeyName, "HKEY_PERFORMANCE_DATA") == 0) {
      return HKEY_PERFORMANCE_DATA;
    }
    return HKEY_CURRENT_USER;
  }

  [[nodiscard]] ParsedRegistryPath ParseRegistryPathInPlace(
    char* const mutablePath
  ) noexcept
  {
    ParsedRegistryPath parsed{};
    if (mutablePath == nullptr) {
      return parsed;
    }

    char* subKey = std::strchr(mutablePath, '\\');
    const char* valueName = subKey;
    if (subKey != nullptr) {
      ++subKey;
      subKey[-1] = '\0';

      char* const lastSeparator = FindLastCharacterInCString(subKey, '\\');
      if (lastSeparator != nullptr) {
        *lastSeparator = '\0';
        valueName = lastSeparator + 1;
      } else {
        valueName = subKey;
        subKey = nullptr;
      }
    } else {
      valueName = nullptr;
      subKey = nullptr;
    }

    parsed.rootKey = ResolveRegistryRootKey(mutablePath);
    parsed.subKey = subKey;
    parsed.valueName = valueName;
    return parsed;
  }
#endif // FAFRE_PLATFORM_WINDOWS: the registry

  [[nodiscard]]
  std::wstring GetErrorReportOutputDirSnapshot()
  {
    // Engine addition (dedicated-server plan WPL.4): the attachment registry
    // is moho/misc/WinPlatform.cpp's.
    return moho::PLAT_GetErrorReportOutputDir();
  }

#if FAFRE_PLATFORM_WINDOWS
  /**
   * Address: 0x004A1CA0 (FUN_004A1CA0, sub_4A1CA0)
   *
   * What it does:
   * Builds `prefix + suffix` for wide-string command fragments used by the
   * crash-report dxdiag launcher.
   */
  [[nodiscard]]
  std::wstring BuildDxdiagCommandLine(
    const std::wstring& outputPath
  )
  {
    return BuildWideStringPlusWideLiteral(std::wstring(kDxdiagCommandPrefix), outputPath.c_str());
  }

  /**
   * Address: 0x004A1030 (FUN_004A1030, sub_4A1030)
   *
   * What it does:
   * Launches `dxdiag.exe` with an output path under the report directory, waits
   * up to 60 seconds for completion, then registers the file when it exists.
   */
  void PLAT_CreateDxdiagForReport()
  {
    const std::wstring outputPath = GetErrorReportOutputDirSnapshot() + kDxdiagOutputFileName;
    const std::wstring commandLineText = BuildDxdiagCommandLine(outputPath);

    std::vector<wchar_t> commandLine(commandLineText.begin(), commandLineText.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInformation{};

    if (
      ::CreateProcessW(
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        0x4000020u,
        nullptr,
        nullptr,
        &startupInfo,
        &processInformation
      ) != FALSE
    ) {
      (void)::WaitForSingleObject(processInformation.hProcess, 60000u);
      (void)::CloseHandle(processInformation.hProcess);
      (void)::CloseHandle(processInformation.hThread);
    }

    const fa::string outputPathUtf8 = gpg::STR_WideToUtf8(outputPath.c_str());
    if (moho::FILE_GetFileInfo(outputPathUtf8.c_str(), nullptr, false)) {
      moho::PLAT_RegisterFileForErrorReport(outputPath.c_str());
    }
  }
#endif // FAFRE_PLATFORM_WINDOWS: dxdiag

  /**
   * Address: 0x004F2000 (FUN_004F2000, func_HasCorrectPlatform)
   *
   * What it does:
   * Returns true when OS version probing fails or platform is not
   * `VER_PLATFORM_WIN32_WINDOWS`.
   */
  bool HasCorrectPlatform()
  {
    OSVERSIONINFOW versionInfo{};
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    return !::GetVersionExW(&versionInfo) || versionInfo.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS;
  }

  /**
   * Address: 0x004F1540 (FUN_004F1540, func_ProbeWakeTimer)
   *
   * What it does:
   * Returns elapsed wake-timer milliseconds and resets the timer origin.
   */
  float ProbeWakeTimerMs()
  {
    const LONGLONG elapsedCycles = wakeupTimer.ElapsedCyclesAndReset();
    return gpg::time::CyclesToMilliseconds(elapsedCycles);
  }

  /**
   * Address: 0x0040D820 (FUN_0040D820, func_round)
   *
   * float
   *
   * What it does:
   * Applies x87 `frndint` rounding, then adjusts down by one when the original
   * value is below the rounded lane (floor-equivalent in default rounding mode).
   */
  [[nodiscard]] int FloorFrndintAdjustDown(
    const float value
  ) noexcept
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value < rounded) ? -1 : 0);
  }

  /**
   * Engine addition: one event of the window system (platform/Window.h), through the application
   * shell, without waiting. The window library's `App::Dispatch` (GetMessage) could wait for a message the
   * `App::Pending` check had seen; the window system answers HasEvents from what it has read.
   */
  bool DispatchPendingMessage()
  {
    if (!gShellApp->Pending()) {
      return false;
    }
    gShellApp->Dispatch();
    return true;
  }

  DWORD ComputeWaitTimeoutMs()
  {
    const float remainingMs = wakeupTimerDur - ProbeWakeTimerMs();
    if (remainingMs < 0.0f) {
      return 0;
    }

    if (remainingMs > kMaxFiniteTimeoutMs) {
      return INFINITE;
    }

    return static_cast<DWORD>(FloorFrndintAdjustDown(remainingMs));
  }

  /**
   * Address: 0x004F2050 (FUN_004F2050, func_WindowHook)
   *
   * What it does:
   * Suppresses left/right Windows keys for low-level keyboard hook events when
   * app-level key suppression is enabled; otherwise forwards to next hook.
   */
#if FAFRE_PLATFORM_WINDOWS
  LRESULT CALLBACK WindowHook(
    const int code,
    const WPARAM wParam,
    const LPARAM lParam
  )
  {
    if (code == HC_ACTION && sSupComApp->AppDoSuppressWindowsKeys() && wParam >= WM_KEYDOWN && wParam <= WM_KEYUP) {
      const auto* const keyData = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
      if (keyData->vkCode == VK_LWIN || keyData->vkCode == VK_RWIN) {
        return 1;
      }
    }

    return ::CallNextHookEx(sWindowHook, code, wParam, lParam);
  }

  [[maybe_unused]] constexpr WORD kCrashDialogTemplateId = 0x7A;
  struct CrashDialogInitData
  {
    gpg::StrArg caption;
    gpg::StrArg body;
  };

  /**
   * Suspends every thread of this process except the calling one, so a crash
   * report can walk their stacks without them moving. Counterpart to
   * `ResumeSiblingThreads` semantics: callers must terminate the process
   * afterwards; the retail BugSplat path never resumed them either.
   */
  void SuspendSiblingThreadsForCrashReport()
  {
    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
      return;
    }

    THREADENTRY32 threadEntry{};
    threadEntry.dwSize = sizeof(threadEntry);
    if (::Thread32First(snapshot, &threadEntry) == FALSE) {
      ::CloseHandle(snapshot);
      return;
    }

    const DWORD processId = ::GetCurrentProcessId();
    const DWORD currentThreadId = ::GetCurrentThreadId();
    do {
      if (threadEntry.th32OwnerProcessID != processId || threadEntry.th32ThreadID == currentThreadId) {
        continue;
      }

      HANDLE threadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
      if (threadHandle != nullptr) {
        (void)::SuspendThread(threadHandle);
        ::CloseHandle(threadHandle);
      }
    } while (::Thread32Next(snapshot, &threadEntry) != FALSE);

    ::CloseHandle(snapshot);
  }

  void TryReportFault(
    _EXCEPTION_POINTERS* const exceptionInfo
  )
  {
    if (exceptionInfo == nullptr) {
      return;
    }

    using ReportFaultFn = DWORD(WINAPI*)(LPEXCEPTION_POINTERS, DWORD);
    HMODULE faultReportingModule = ::GetModuleHandleW(L"faultrep.dll");
    bool loadedNow = false;
    if (faultReportingModule == nullptr) {
      faultReportingModule = ::LoadLibraryW(L"faultrep.dll");
      loadedNow = (faultReportingModule != nullptr);
    }

    if (faultReportingModule != nullptr) {
      const auto reportFault = reinterpret_cast<ReportFaultFn>(::GetProcAddress(faultReportingModule, "ReportFault"));
      if (reportFault != nullptr) {
        (void)reportFault(exceptionInfo, 0);
      }
    }

    if (loadedNow && faultReportingModule != nullptr) {
      (void)::FreeLibrary(faultReportingModule);
    }
  }

  /**
   * Address: 0x004A2930 (FUN_004A2930)
   *
   * What it does:
   * Maps Windows structured-exception codes to fixed symbolic names.
   */
  const char* StructuredExceptionToString(
    const DWORD exceptionCode
  )
  {
    switch (exceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
      return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
      return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_BREAKPOINT:
      return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_SINGLE_STEP:
      return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_IN_PAGE_ERROR:
      return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_ILLEGAL_INSTRUCTION:
      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
      return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_INVALID_DISPOSITION:
      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_FLT_DENORMAL_OPERAND:
      return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
      return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:
      return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:
      return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:
      return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:
      return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:
      return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
      return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:
      return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_PRIV_INSTRUCTION:
      return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW:
      return "EXCEPTION_STACK_OVERFLOW";
    default:
      return "Unknown structured exception";
    }
  }

  /**
   * The crash record's second home, written with a bare `FILE*` that is closed
   * before this function returns.
   *
   * `gpg::Logf` reaches the `.sclog` through a `std::ofstream` (see
   * `TryInitializeStartupLogTarget`, moho/app/IWinApp.cpp), which buffers. The
   * BugSplat arm of `TopLevelExceptionFilter` then blocks forever in a report
   * this build never completes, so the process never exits, the stream is
   * never flushed, and the whole crash record dies in that buffer - which is
   * exactly what a crash looks like from outside: the log stops mid-frame at
   * whatever was last flushed, no `CRASH:` line anywhere, no Windows Error
   * Reporting event either, because the filter handled the exception. Every
   * line also goes here, and this file is flushed and closed line by line, so
   * a faulted process always leaves its symbolised stack on disk.
   */
  void WriteCrashRecordLine(
    const char* const format,
    ...
  )
  {
    std::FILE* const file = std::fopen("crash_callstack.txt", "a");
    if (file == nullptr) {
      return;
    }

    std::va_list args;
    va_start(args, format);
    (void)std::vfprintf(file, format, args);
    va_end(args);

    (void)std::fputc('\n', file);
    (void)std::fclose(file);
  }

  /**
   * Writes the fault and its symbolised callstack to the log.
   *
   * Not in the binary: this build has no working crash dialog resource and no
   * reachable BugSplat endpoint, so without this a crash leaves no trace at
   * all. Kept deliberately small and allocation-light - it runs inside an
   * exception filter, on a process that has already faulted.
   */
  void LogCrashSummaryAndCallstack(
    _EXCEPTION_POINTERS* const exceptionInfo
  )
  {
    if (exceptionInfo == nullptr || exceptionInfo->ExceptionRecord == nullptr) {
      return;
    }

    // Start a fresh record for this fault, so the file always describes the
    // crash that just happened rather than accumulating across runs.
    if (std::FILE* const truncate = std::fopen("crash_callstack.txt", "w"); truncate != nullptr) {
      (void)std::fclose(truncate);
    }

    const EXCEPTION_RECORD& record = *exceptionInfo->ExceptionRecord;
    const std::uintptr_t faultAddress = reinterpret_cast<std::uintptr_t>(record.ExceptionAddress);

    gpg::Logf(
      "CRASH: %s (0x%08X) at address %p",
      StructuredExceptionToString(record.ExceptionCode),
      static_cast<unsigned int>(record.ExceptionCode),
      record.ExceptionAddress
    );
    WriteCrashRecordLine(
      "CRASH: %s (0x%08X) at address %p",
      StructuredExceptionToString(record.ExceptionCode),
      static_cast<unsigned int>(record.ExceptionCode),
      record.ExceptionAddress
    );

    if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record.NumberParameters >= 2u) {
      gpg::Logf(
        "CRASH: attempted to %s memory at %p",
        record.ExceptionInformation[0] == 8u ? "execute" : (record.ExceptionInformation[0] != 0u ? "write" : "read"),
        reinterpret_cast<const void*>(record.ExceptionInformation[1])
      );
      WriteCrashRecordLine(
        "CRASH: attempted to %s memory at %p",
        record.ExceptionInformation[0] == 8u ? "execute" : (record.ExceptionInformation[0] != 0u ? "write" : "read"),
        reinterpret_cast<const void*>(record.ExceptionInformation[1])
      );
    }

    // The module and offset of the fault. The exe is built with ASLR, so the
    // raw address alone cannot be looked up in main.pdb afterwards.
    HMODULE faultModule = nullptr;
    char faultModulePath[MAX_PATH]{};
    if (
      ::GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        static_cast<LPCSTR>(record.ExceptionAddress),
        &faultModule
      ) != FALSE &&
      ::GetModuleFileNameA(faultModule, faultModulePath, MAX_PATH) != 0u
    ) {
      const char* moduleName = std::strrchr(faultModulePath, '\\');
      moduleName = moduleName != nullptr ? moduleName + 1 : faultModulePath;
      const std::uintptr_t moduleBase = reinterpret_cast<std::uintptr_t>(faultModule);
      const std::uintptr_t offset = faultAddress - moduleBase;
      gpg::Logf("CRASH: fault is %s+0x%zX (module base %p)", moduleName, offset, static_cast<void*>(faultModule));
      WriteCrashRecordLine(
        "CRASH: fault is %s+0x%zX (module base %p)", moduleName, offset, static_cast<void*>(faultModule)
      );
    }

    std::uintptr_t stackFrames[64]{};
    std::uint32_t frameCount = moho::PLAT_GetCallStack(exceptionInfo->ContextRecord, 64, stackFrames);
    if (frameCount == 0u) {
      // A fault late in shutdown comes after PLAT_Exit has released the symbol
      // handler, and the walk then yields nothing. Bring it back for the report.
      moho::PLAT_Init();
      frameCount = moho::PLAT_GetCallStack(exceptionInfo->ContextRecord, 64, stackFrames);
    }
    if (frameCount == 0u) {
      gpg::Logf("CRASH callstack: unavailable.");
      WriteCrashRecordLine("CRASH callstack: unavailable.");
      return;
    }

    const fa::string callstackText = moho::PLAT_FormatCallstack(0, static_cast<std::int32_t>(frameCount), stackFrames);

    // One Logf per frame. gpg::Logf formats through a bounded buffer, so a
    // single multi-line call silently loses everything past the first frame or
    // two -- which is precisely the part that names the faulting engine code.
    gpg::Logf("CRASH callstack: %u frames", static_cast<unsigned int>(frameCount));
    WriteCrashRecordLine("CRASH callstack: %u frames", static_cast<unsigned int>(frameCount));
    const char* const text = callstackText.c_str();
    std::size_t lineStart = 0u;
    for (std::size_t i = 0u;; ++i) {
      const char ch = text[i];
      if (ch != '\n' && ch != '\0') {
        continue;
      }
      std::size_t lineLength = i - lineStart;
      if (lineLength > 400u) {
        lineLength = 400u; // keep each line well inside Logf's buffer
      }
      if (lineLength != 0u) {
        gpg::Logf("CRASH   %.*s", static_cast<int>(lineLength), text + lineStart);
        WriteCrashRecordLine("CRASH   %.*s", static_cast<int>(lineLength), text + lineStart);
      }
      if (ch == '\0') {
        break;
      }
      lineStart = i + 1u;
    }

    // Raw return addresses as well: when symbolisation fails for a frame the
    // text above says nothing useful, but these still resolve against main.pdb.
    for (std::uint32_t frame = 0u; frame < frameCount; ++frame) {
      gpg::Logf("CRASH   frame[%u] = %p", frame, reinterpret_cast<const void*>(stackFrames[frame]));
      WriteCrashRecordLine("CRASH   frame[%u] = %p", frame, reinterpret_cast<const void*>(stackFrames[frame]));
    }
  }

  /**
   * Address: 0x004A2B30 (FUN_004A2B30, TopLevelExceptionFilter)
   *
   * What it does:
   * Handles unhandled structured exceptions: writes the local crash report
   * first, then offers WER ReportFault when `/bugreport` is present, then
   * shows the local crash-report dialog.
   *
   * Deviation from the 2007 binary (documented): the BugSplat
   * `MiniDmpSender` arm is removed. The FAF distribution carries no
   * BugSplat.dll and no reachable endpoint, and the sender blocks forever
   * waiting for a report that never completes - a crash presented as a
   * silent freeze. The local report replaces it unconditionally.
   */
  LONG WINAPI TopLevelExceptionFilter(
    _EXCEPTION_POINTERS* const exceptionInfo
  )
  {
    if (exceptionInfo == nullptr || exceptionInfo->ExceptionRecord == nullptr) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    // The full report first, before anything that can block or fail: all
    // threads, registers, modules, log tail. Everything after this line is
    // best-effort.
    gpg::diag::CrashReportContext reportContext{};
    reportContext.exceptionInfo = exceptionInfo;
    (void)gpg::diag::WriteCrashReport(reportContext);
    (void)gpg::diag::WriteCrashMinidump(exceptionInfo);

    // Same record into the engine log and the legacy per-crash file.
    LogCrashSummaryAndCallstack(exceptionInfo);

    if (moho::sMainWindow != nullptr) {
      (void)::DestroyWindow(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle())));
    }

    if (moho::CFG_GetArgOption("/bugreport", 0, nullptr)) {
      // Windows Error Reporting, opt-in (the retail default reached for a
      // BugSplat sender that never completes in the FAF distribution). The
      // game log and dxdiag are still generated and registered as report
      // attachments, as the BugSplat callback used to do.
      moho::PLAT_CreateGameLogForReport();
      PLAT_CreateDxdiagForReport();
      SuspendSiblingThreadsForCrashReport();
      TryReportFault(exceptionInfo);
    }

    if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
      return EXCEPTION_CONTINUE_SEARCH;
    }

    gpg::diag::ShowCrashReportDialog(gpg::diag::CrashLatestReportPath());
    return EXCEPTION_CONTINUE_SEARCH;
  }
#endif // FAFRE_PLATFORM_WINDOWS: the Windows-key hook, the crash dialog and the exception filter

} // namespace

/**
 * Address: 0x004F2730 (FUN_004F2730, ?WIN_CopyToClipboard@Moho@@YA_NVStrArgW@gpg@@@Z)
 *
 * What it does:
 * Copies a wide-string payload to the Windows clipboard as `CF_UNICODETEXT`,
 * allocating a movable global block, locking it, copying the data, and
 * publishing it under an exclusive open/empty/set/close cycle.
 */
bool moho::WIN_CopyToClipboard(
  const wchar_t* const text
)
{
  if (text == nullptr) {
    return false;
  }

#if !FAFRE_PLATFORM_WINDOWS
  // The window system's clipboard, in UTF-8 (platform/posix/Win32WindowPosix.h, issue #256).
  return platform::posix::gSetClipboardTextHook != nullptr &&
    platform::posix::gSetClipboardTextHook(gpg::STR_WideToUtf8(text).c_str());
#else
  const std::size_t characterCount = std::wcslen(text) + 1;
  const std::size_t payloadBytes = characterCount * sizeof(wchar_t);

  if (::OpenClipboard(nullptr) == FALSE) {
    return false;
  }

  (void)::EmptyClipboard();
  HGLOBAL globalBlock = ::GlobalAlloc(GMEM_MOVEABLE, payloadBytes);
  if (globalBlock == nullptr) {
    ::CloseClipboard();
    return false;
  }

  void* const targetBuffer = ::GlobalLock(globalBlock);
  if (targetBuffer == nullptr) {
    ::GlobalFree(globalBlock);
    ::CloseClipboard();
    return false;
  }

  // Raw clipboard blob copy (text payload incl. NUL) into the HGLOBAL.
  std::copy_n(text, payloadBytes / sizeof(wchar_t), static_cast<wchar_t*>(targetBuffer));
  ::GlobalUnlock(globalBlock);

  if (::SetClipboardData(CF_UNICODETEXT, globalBlock) == nullptr) {
    ::GlobalFree(globalBlock);
    ::CloseClipboard();
    return false;
  }

  ::CloseClipboard();
  return true;
#endif
}

/**
 * Address: 0x00BC7230 (FUN_00BC7230, register_startTime)
 *
 * What it does:
 * Re-initializes the shared wakeup timer baseline used by the main loop.
 */
void moho::register_startTime()
{
  new (&wakeupTimer) gpg::time::Timer();
}

/**
 * Address: 0x00BC7240 (FUN_00BC7240, register_wakeupTimer)
 *
 * What it does:
 * Restores the wakeup timer duration lane to the process-default infinity
 * value used at startup.
 */
void moho::register_wakeupTimer()
{
  wakeupTimerDur = kInfiniteWakeupMs;
}

/**
 * Address: 0x004F2480 (FUN_004F2480, ?WIN_GetBeforeEventsStage@Moho@@YAAAVCTaskStage@1@XZ)
 * Address: 0x00BF1860 (FUN_00BF1860, atexit destructor of the stage)
 *
 * What it does:
 * Returns the task stage run before each frame's window events (0x011043CC).
 */
moho::CTaskStage& moho::WIN_GetBeforeEventsStage()
{
  static CTaskStage sBeforeEventsStage;
  return sBeforeEventsStage;
}

/**
 * Address: 0x004F24F0 (FUN_004F24F0, ?WIN_GetBeforeWaitStage@Moho@@YAAAVCTaskStage@1@XZ)
 * Address: 0x00BF1870 (FUN_00BF1870, atexit destructor of the stage)
 *
 * What it does:
 * Returns the task stage run before each frame's idle wait (0x011043B4).
 */
moho::CTaskStage& moho::WIN_GetBeforeWaitStage()
{
  static CTaskStage sBeforeWaitStage;
  return sBeforeWaitStage;
}

/**
 * Address: 0x004F2420 (FUN_004F2420, Moho::WIN_GetWaitHandleSet)
 *
 * What it does:
 * Lazily constructs and returns one process-global wait-handle set used by
 * WinApp main-loop wait orchestration.
 */
moho::CWaitHandleSet* moho::WIN_GetWaitHandleSet()
{
  // 0x011043E0
  static CWaitHandleSet sWaitHandleSet{};
  return &sWaitHandleSet;
}

/**
 * Address: 0x004F2560 (FUN_004F2560, ?WIN_SetWakeupTimer@Moho@@YAXM@Z)
 *
 * What it does:
 * Converts non-negative relative timeout to an absolute wakeup deadline and
 * keeps only the earliest deadline; negative input requests immediate wake.
 */
void moho::WIN_SetWakeupTimer(
  float milliseconds
)
{
  float resolvedWakeup = 0.0f;
  if (milliseconds >= 0.0f) {
    const float absoluteWakeupMs = gpg::time::CyclesToMilliseconds(wakeupTimer.ElapsedCycles()) + milliseconds;
    if (wakeupTimerDur <= absoluteWakeupMs) {
      return;
    }
    milliseconds = absoluteWakeupMs;
    resolvedWakeup = milliseconds;
  }

  wakeupTimerDur = resolvedWakeup;
}

/**
 * Address: 0x004F2400 (FUN_004F2400, ?WIN_AppRequestExit@Moho@@YAXXZ_0)
 * Address: 0x004F2B40 (FUN_004F2B40, ?WIN_AppRequestExit@Moho@@YAXXZ)
 *
 * What it does:
 * Requests immediate exit from the active wx app main loop. The two
 * addresses are byte-identical bodies of this one definition.
 */
void moho::WIN_AppRequestExit()
{
  gShellApp->ExitMainLoop();
}

/**
 * Address: 0x004F25C0 (FUN_004F25C0, ?WIN_SetMainWindow@Moho@@YAXPAVwxWindow@@@Z)
 *
 * What it does:
 * Updates the process-global main-window owner pointer.
 */
void moho::WIN_SetMainWindow(
  ShellWindow* const mainWindow
)
{
  sMainWindow = mainWindow;
}

namespace
{
  // Engine addition: `/testinput <file>`, a test run's scripted input (platform/sdl/TestInput.h). Its
  // console steps run through CON_Execute, and every logged line reaches its waits.
  class TestInputLogTarget final : public gpg::LogTarget
  {
  public:
    TestInputLogTarget()
      : gpg::LogTarget(true)
    {}

    void OnMessage(
      const gpg::LogSeverity level,
      const fa::string& message,
      const fa::vector<fa::string>& context,
      const int previousDepth
    ) override
    {
      (void)level;
      (void)context;
      (void)previousDepth;
      platform::window::test::NoteLogLine(message.c_str());
    }
  };

  void RunTestInputCommand(
    const char* const command
  )
  {
    moho::CON_Execute(command);
  }

  void StartTestInput()
  {
    fa::vector<fa::string> args;
    if (!moho::CFG_GetArgOption("/testinput", 1, &args) || args.empty()) {
      return;
    }
    static TestInputLogTarget sLogTarget; // registered for the rest of the process
    (void)platform::window::test::Start(args[0].c_str(), &RunTestInputCommand);
  }
} // namespace

/**
 * Address: 0x004F20B0 (FUN_004F20B0)
 *
 * IWinApp *
 *
 * What it does:
 * Drives app bootstrap, frame pumping, and shutdown around the IWinApp interface.
 */
void moho::WIN_AppExecute(
  IWinApp* const app
)
{
  if (app == nullptr) {
    return;
  }

  sSupComApp = app;
  // The window system (platform/Window.h, SDL3) before anything makes a window (issue #407).
  if (!platform::window::Init()) {
    WIN_OkBox("Forged Alliance", "The window system could not be started. See the log for the reason.");
    sSupComApp = nullptr;
    return;
  }
#if !FAFRE_PLATFORM_WINDOWS
  // No low-level keyboard hook: the window system keeps the desktop's keys (issue #256).
  HMODULE const selfModule = ::GetModuleHandleW(nullptr);
#else
  const HMODULE module = ::GetModuleHandleW(nullptr);
  sWindowHook = ::SetWindowsHookExW(WH_KEYBOARD_LL, &WindowHook, module, 0);

  HMODULE selfModule = nullptr;
  ::GetModuleHandleExW(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    reinterpret_cast<LPCWSTR>(&WindowHook),
    &selfModule
  );
#endif
  // enterLoop = false: wx initialises and builds the MohoApp, and the loop
  // below pumps it (0x004F2117, wxEntry 0x00992FF0).
  ShellEntry(reinterpret_cast<ShellInstanceHandle>(selfModule), nullptr, nullptr, 0, false);

  if (!HasCorrectPlatform()) {
    WIN_OkBox(
      "Old OS Version",
      "This application requires Windows NT, 2000, XP, or newer, to operate.\n"
      "Windows 95, 98, and ME are not supported."
    );
    sSupComApp = nullptr;
    return;
  }

  THREAD_SetAffinity(true);
  ::InitCommonControls();
  ::CoInitialize(nullptr);
  PLAT_Init();
  PLAT_CatchStructuredExceptions();
  wakeupTimer.Reset();
  wakeupTimerDur = kInfiniteWakeupMs;

  if (!app->Init()) {
    ::TerminateProcess(::GetCurrentProcess(), 1u);
  }
  // 0x004F2227..0x004F2233: wxApp::m_exitOnFrameDelete (+0x44) = Yes and
  // m_keepGoing (+0x5C) = TRUE, the flag this loop runs on.
  gShellApp->SetExitOnFrameDelete(true);
  ShellGetApp().SetKeepGoing();
  StartTestInput();

  platform::SetX87PrecisionControl(_PC_24); // _controlfp(0x20000, 0x30000)

  bool success = true;
  bool acceptNewEvent = true;
  for (;;) {
    while (acceptNewEvent) {
      ::SleepEx(0, TRUE);
      WIN_GetBeforeEventsStage().UserFrame();
      acceptNewEvent = false;
    }

    // Engine change: taking the message is the check, as a second PeekMessage per pass was 7 % of
    // an uncapped frame. TheApp->Dispatch() could also block, see there.
    if (DispatchPendingMessage()) {
      success = true;
      continue;
    }

#if FAFRE_PLATFORM_POSIX
    // Engine addition: a window size that has settled reaches the device between frames.
    WSupComFrame::ApplyPendingResize();
#endif
    // Engine addition: where the frame's WM_PAINT would come, after the messages and before idle.
    if (moho::D3D_RunDirectPaint()) {
      success = true;
    }

    // Engine change: with idle work done this goes on to the next frame without asking for messages
    // a second or third time; one that arrives now waits for the top of the next frame.
    if (success) {
      success = gShellApp->ProcessIdle();
      if (success) {
        continue;
      }
    }

    if (!ShellGetApp().KeepGoing()) {
      break;
    }

    app->Main();
    // Engine addition (issue #412): the developer windows draw once a frame.
    platform::tools::RenderAll();
    // Engine addition: a test run's scripted input takes its next steps.
    platform::window::test::Tick();
    success = true;
    acceptNewEvent = true;

    WIN_GetBeforeWaitStage().UserFrame();

    const DWORD timeoutMs = ComputeWaitTimeoutMs();
    wakeupTimerDur = kInfiniteWakeupMs;
    // Engine addition: no paint message wakes this wait for a frame that draws without one.
    WIN_GetWaitHandleSet()->MsgWaitEx(moho::D3D_IsDirectPaintPending() ? 0u : timeoutMs);
  }

  app->Destroy();
  WINX_Exit();
  PLAT_Exit();

  // Drain what the teardown queued (0x004F2345..0x004F2382), then let wx go.
  if (gShellApp != nullptr) {
    bool moreIdle = true;
    for (;;) {
      if (gShellApp->Pending()) {
        gShellApp->Dispatch();
        moreIdle = true;
        continue;
      }
      if (!moreIdle) {
        break;
      }
      moreIdle = gShellApp->ProcessIdle();
    }
    gShellApp->OnExit();
    ShellApp::CleanUp();
  }

#if FAFRE_PLATFORM_WINDOWS
  if (sWindowHook != nullptr) {
    ::UnhookWindowsHookEx(sWindowHook);
    sWindowHook = nullptr;
  }
#endif

  RES_Exit();
  platform::window::Shutdown();
  sSupComApp = nullptr;
}

/**
 * Address: 0x004A2D30 (FUN_004A2D30)
 *
 * What it does:
 * Installs the engine top-level SEH filter.
 */
void moho::PLAT_CatchStructuredExceptions()
{
#if FAFRE_PLATFORM_WINDOWS
  (void)::SetUnhandledExceptionFilter(&TopLevelExceptionFilter);
#endif
  // Elsewhere crashes are signals, which gpg/core/diagnostics/posix/DiagnosticsPosix.cpp reports.
}

/**
 * Address: 0x0047A4F0 (FUN_0047A4F0)
 * Mangled:
 * ?LOG_GetRecentLines@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
 *
 * What it does:
 * Produces one UTF-8 log-history text blob consumed by crash/report export
 * paths. The current recovered logging backend already applies bounded history.
 */
fa::string moho::LOG_GetRecentLines(
  const std::uint32_t maxLines
)
{
  (void)maxLines;
  return gpg::GetRecentLogLines();
}

/**
 * Address: 0x004A1230 (FUN_004A1230)
 * Mangled: ?PLAT_CreateGameLogForReport@Moho@@YAXXZ
 *
 * What it does:
 * Writes current in-memory log history to `<report_dir><app_short_name>.sclog`
 * and registers the generated file as a crash-report attachment.
 */
void moho::PLAT_CreateGameLogForReport()
{
  const fa::string recentLogLines = LOG_GetRecentLines(0);
  const char* const appShortName =
    (sSupComApp != nullptr && !sSupComApp->shortName.empty()) ? sSupComApp->shortName.c_str() : "SupCom";
  const std::wstring logFilePrefix =
    BuildWideStringPlusWideString(GetErrorReportOutputDirSnapshot(), gpg::STR_Utf8ToWide(appShortName));
  const std::wstring logFilePath = BuildWideStringPlusWideLiteral(logFilePrefix, L".sclog");

  HANDLE logFileHandle =
    ::CreateFileW(logFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (logFileHandle == INVALID_HANDLE_VALUE) {
    const fa::string errorText = WIN_GetLastError();
    const fa::string utf8Path = gpg::STR_WideToUtf8(logFilePath.c_str());
    gpg::Warnf("PLAT_CreateGameLogForReport(\"%s\") log file creation failed: %s", utf8Path.c_str(), errorText.c_str());
    return;
  }

  DWORD bytesWritten = 0;
  if (
    ::WriteFile(
      logFileHandle, recentLogLines.c_str(), static_cast<DWORD>(recentLogLines.size()), &bytesWritten, nullptr
    ) == FALSE
  ) {
    const fa::string errorText = WIN_GetLastError();
    const fa::string utf8Path = gpg::STR_WideToUtf8(logFilePath.c_str());
    gpg::Warnf("PLAT_CreateGameLogForReport(\"%s\") log file writing failed: %s", utf8Path.c_str(), errorText.c_str());
    (void)::CloseHandle(logFileHandle);
    return;
  }

  PLAT_RegisterFileForErrorReport(logFilePath.c_str());
  (void)::CloseHandle(logFileHandle);
}

/**
 * Address: 0x004A2D40 (FUN_004A2D40)
 *
 * What it does:
 * Reads one registry value payload into `outData` and returns byte count read.
 * Binary behavior clamps read size to 0x100 bytes.
 */
std::uint32_t moho::PLAT_GetRegistryValue(
  const char* const keyPath,
  void* const outData,
  const std::uint32_t maxDataBytes
)
{
  (void)maxDataBytes;
  if (keyPath == nullptr || outData == nullptr) {
    return 0;
  }

#if !FAFRE_PLATFORM_WINDOWS
  // No registry: nothing to read, as for a key Windows doesn't have (the Linux client, issue #255).
  gpg::Logf("PLAT_GetRegistryValue: Unable to open registry key \"%s\"", keyPath);
  return 0;
#else
  // The shipped body builds a mutable copy of the path in a byte vector so
  // `ParseRegistryPathInPlace` can split it; the vector frees itself on every
  // return path, which is what the explicit teardown calls at each `return`
  // used to model.
  fa::vector<std::uint8_t, false> keyBuffer{};
  keyBuffer.resize(std::strlen(keyPath) + 1U);

  char* const mutableKeyPath = reinterpret_cast<char*>(keyBuffer.begin());
  std::strcpy(mutableKeyPath, keyPath);
  const ParsedRegistryPath parsedPath = ParseRegistryPathInPlace(mutableKeyPath);

  HKEY openedKey = nullptr;
  if (::RegOpenKeyExA(parsedPath.rootKey, parsedPath.subKey, 0, 0x20019u, &openedKey) != ERROR_SUCCESS) {
    gpg::Logf("PLAT_GetRegistryValue: Unable to open registry key \"%s\"", keyPath);
    return 0;
  }

  DWORD bytesRead = 0x100u;
  if (
    ::RegQueryValueExA(
      openedKey, parsedPath.valueName, nullptr, nullptr, reinterpret_cast<LPBYTE>(outData), &bytesRead
    ) != ERROR_SUCCESS
  ) {
    (void)::RegCloseKey(openedKey);
    gpg::Logf("PLAT_GetRegistryValue: Unable to read registry key \"%s\"", keyPath);
    return 0;
  }

  (void)::RegCloseKey(openedKey);
  return bytesRead;
#endif
}

/**
 * Address: 0x004F25D0 (FUN_004F25D0)
 * Mangled:
 * ?WIN_GetClipboardText@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ
 *
 * What it does:
 * Reads `CF_UNICODETEXT` from the Windows clipboard (owned by main window when
 * present), converts UTF-16 content to UTF-8, and returns empty text when
 * unavailable.
 */
fa::string moho::WIN_GetClipboardText()
{
#if !FAFRE_PLATFORM_WINDOWS
  // The window system's clipboard, in UTF-8 (platform/posix/Win32WindowPosix.h, issue #256).
  if (platform::posix::gGetClipboardTextHook == nullptr) {
    return {};
  }
  const std::string text = platform::posix::gGetClipboardTextHook();
  return fa::string(text.c_str());
#else
  const HWND ownerWindow =
    sMainWindow != nullptr ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(sMainWindow->GetHandle())) : nullptr;

  if (::IsClipboardFormatAvailable(CF_UNICODETEXT) == FALSE || ::OpenClipboard(ownerWindow) == FALSE) {
    return {};
  }

  fa::string clipboardText{};
  const HANDLE clipboardData = ::GetClipboardData(CF_UNICODETEXT);
  if (clipboardData != nullptr) {
    const wchar_t* const lockedText = static_cast<const wchar_t*>(::GlobalLock(clipboardData));
    if (lockedText != nullptr) {
      clipboardText = gpg::STR_WideToUtf8(lockedText);
      (void)::GlobalUnlock(clipboardData);
    }
  }

  (void)::CloseClipboard();
  return clipboardText;
#endif
}

namespace
{
  // Engine addition (dedicated-server plan WPL.4, WPR.12): WIN_OkBox's box
  // (moho/misc/WinPlatform.cpp), as the binary showed it (0x004F2800): owned by
  // the main window when there is one, MB_SETFOREGROUND.
  void ShowOkBox(
    const gpg::StrArg caption,
    const gpg::StrArg text
  )
  {
    const HWND ownerWindow = moho::sMainWindow != nullptr
      ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()))
      : nullptr;
    const std::wstring wideCaption = gpg::STR_Utf8ToWide(caption);
    const std::wstring wideText = gpg::STR_Utf8ToWide(text);
    (void)::MessageBoxW(ownerWindow, wideText.c_str(), wideCaption.c_str(), 0x40000u);
  }

  [[maybe_unused]] const bool gOkBoxPresenterSet = (moho::sOkBoxPresenter = &ShowOkBox, true);

  // Engine addition (dedicated-server plan WPL.4): sAppExitMainLoop, what
  // cfunc_EndLoggingStatsL (moho/misc/StatItem.cpp) did before the move.
  void AppExitMainLoop()
  {
    if (gShellApp != nullptr) {
      gShellApp->ExitMainLoop();
    }
  }

  [[maybe_unused]] const bool gAppExitMainLoopSet = (moho::sAppExitMainLoop = &AppExitMainLoop, true);

  // Engine addition (dedicated-server plan WPL.4): sAppPumpEvents, the event
  // pump CSimDriver::PerformNextEvent (moho/sim/SimDriver.cpp) ran before the
  // move (0x0073F430).
  void AppPumpEvents()
  {
    bool keepIdle = true;
    for (;;) {
      if (gShellApp->Pending()) {
        gShellApp->Dispatch();
        keepIdle = true;
        continue;
      }

      if (!keepIdle) {
        break;
      }

      keepIdle = gShellApp->ProcessIdle();
    }
  }

  [[maybe_unused]] const bool gAppPumpEventsSet = (moho::sAppPumpEvents = &AppPumpEvents, true);

  // Engine addition (dedicated-server plan WPL.4): sAppPumpStep, the loop body of
  // PausedMainThread::WaitUntilResumedAndDelete (moho/misc/PausedThread.cpp,
  // 0x004B45F0) before the move.
  bool AppPumpStep(
    bool& processIdle
  )
  {
    if (gShellApp != nullptr && gShellApp->Pending()) {
      gShellApp->Dispatch();
      return true;
    }

    // Engine addition (issue #412): the developer windows (the Lua debugger that holds the main
    // thread here) draw while it waits.
    platform::tools::RenderAll();
    // Engine addition: a test run's scripted input goes on while the debugger holds the thread.
    platform::window::test::Tick();
    if (processIdle && gShellApp != nullptr) {
      processIdle = gShellApp->ProcessIdle();
    }
    return false;
  }

  [[maybe_unused]] const bool gAppPumpStepSet = (moho::sAppPumpStep = &AppPumpStep, true);
} // namespace

/**
 * Address: 0x004F3A60 (FUN_004F3A60, ?WINX_Exit@Moho@@YAXXZ)
 *
 * What it does:
 * Destroys all managed dialog/frame windows and unlinks their registry slots.
 */
void moho::WINX_Exit()
{
  // The binary destroyed its managed dialogs here (managedWindows, 0x010A9B94), the log window
  // among them; it is the one left (issue #412).
  if (WWinLogWindow* const logWindow = sLogWindowTarget.dialog; logWindow != nullptr) {
    delete logWindow; // ~WWinLogWindow detaches it from the target
  }

  // The managed frames (managedFrames, 0x010A9BD8) were the emitter editors.
  WEmitterEditor::DestroyAll();
}

/**
 * Address: 0x004F3CE0 (FUN_004F3CE0)
 * Mangled: ?WINX_InitSplash@Moho@@YAXVStrArg@gpg@@@Z
 *
 * gpg::StrArg
 *
 * What it does:
 * Initializes splash PNG handler state, clears any existing splash object,
 * then loads and creates a splash-screen runtime when the file is available.
 */
void moho::WINX_InitSplash(
  const gpg::StrArg filename
)
{
  platform::window::HideSplash();

  int splashWidth = 1024;
  int splashHeight = 768;
  RECT desktopRect{};
  if (::GetWindowRect(nullptr, &desktopRect) != 0) {
    splashWidth = desktopRect.right - desktopRect.left;
    if (splashWidth >= 1600) {
      splashWidth = 1600;
    }
    // top - bottom, as the binary computes it (0x004F3DFC): never above
    // 1200 for a real rectangle, so the height comes out as 1200.
    splashHeight = desktopRect.top - desktopRect.bottom;
    if (splashHeight < 1200) {
      splashHeight = 1200;
    }
  }

  // SplashScreen(bitmap rescaled to the size, SPLASH_CENTRE_ON_SCREEN, SIMPLE_BORDER |
  // STAY_ON_TOP) in the binary.
  (void)platform::window::ShowSplash(filename, splashWidth, splashHeight);
}

/**
 * Address: 0x004F67E0 (FUN_004F67E0, ?WINX_PrecreateLogWindow@Moho@@YAXXZ)
 * Thunk entry: 0x004F3CD0 (FUN_004F3CD0)
 *
 * What it does:
 * Lazily allocates the global log window object and stores it under the
 * shared log-window target lock.
 */
void moho::WINX_PrecreateLogWindow()
{
  if (sLogWindowTarget.dialog != nullptr) {
    return;
  }

  WWinLogWindow* const createdLogWindow = new WWinLogWindow();
  fa::mutex::scoped_lock lock(sLogWindowTarget.lock);
  sLogWindowTarget.dialog = createdLogWindow;
}

/**
 * Engine addition (issue #412): Dialog::ShowModal's loop for the developer windows on Dear
 * ImGui. The window system's events go through the shell as in the main loop, and the developer
 * windows are drawn, until `done` answers true or the program is asked to end.
 */
void moho::WINX_RunModal(
  const std::function<bool()>& done
)
{
  while (!done()) {
    if (gShellApp == nullptr) {
      return;
    }
    while (gShellApp->Pending()) {
      gShellApp->Dispatch();
    }
    if (!ShellGetApp().KeepGoing()) {
      return;
    }
    platform::tools::RenderAll();
    ::Sleep(5);
  }
}

/**
 * Address: 0x004F3F30 (FUN_004F3F30, ?WINX_ExitSplash@Moho@@YAXXZ)
 *
 * What it does:
 * Deletes the active splash-screen object through its deleting-dtor slot and
 * clears the global splash pointer.
 */
void moho::WINX_ExitSplash()
{
  platform::window::HideSplash();
}

#pragma warning(pop)
