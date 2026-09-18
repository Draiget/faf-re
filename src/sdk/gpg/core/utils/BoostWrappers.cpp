#include "BoostWrappers.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <sstream>

#include <boost/ptr_container/exception.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/thread.hpp>
#include <boost/thread/tss.hpp>

#include "moho/terrain/TerrainFactory.h"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d10/EffectD3D10.hpp"
#include "gpg/gal/backends/d3d10/EffectTechniqueD3D10.hpp"
#include "gpg/gal/backends/d3d10/EffectVariableD3D10.hpp"
#include "gpg/gal/backends/d3d10/PipelineStateD3D10.hpp"
#include "moho/animation/CAniPose.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/Stats.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/resource/RScaResource.h"
#include "moho/resource/RScmResource.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  class AudioEngine;
}

/**
 * Address: 0x00AC6070 (FUN_00AC6070, tss_cleanup_implemented)
 *
 * What it does:
 * Placeholder TSS cleanup hook used by the boost thread-local bootstrap lane;
 * this binary variant is a no-op.
 */
void tss_cleanup_implemented()
{
}

namespace
{
  struct WinMutexHandleRuntime
  {
    HANDLE handle = nullptr;
  };

  struct WinMutexHandlePairRuntime
  {
    HANDLE handle = nullptr;
    std::uint32_t lane04 = 0;
  };

  [[noreturn]] void ThrowThreadResourceErrorRuntime()
  {
    throw boost::thread_resource_error();
  }
} // namespace

namespace boost
{
  /**
   * Address: 0x00AC1980 (FUN_00AC1980)
   *
   * What it does:
   * Creates one named Win32 mutex lane and throws
   * `boost::thread_resource_error` when handle creation fails.
   */
  void EnsureNamedMutexHandleCreatedOrThrow(
    const char* const mutexName
  )
  {
    const HANDLE mutexHandle = ::CreateMutexA(nullptr, FALSE, mutexName);
    if (mutexHandle == nullptr || mutexHandle == INVALID_HANDLE_VALUE) {
      ThrowThreadResourceErrorRuntime();
    }
  }

  /**
   * Address: 0x00AC5080 (FUN_00AC5080)
   *
   * What it does:
   * Secondary named-mutex creation lane mirroring
   * `EnsureNamedMutexHandleCreatedOrThrow`.
   */
  void EnsureNamedMutexHandleCreatedOrThrowSecondary(
    const char* const mutexName
  )
  {
    EnsureNamedMutexHandleCreatedOrThrow(mutexName);
  }

  /**
   * Address: 0x00AC1C90 (FUN_00AC1C90)
   *
   * What it does:
   * Initializes one single-lane Win32 mutex owner and throws
   * `boost::thread_resource_error` when mutex creation fails.
   */
  WinMutexHandleRuntime* InitializeUnnamedMutexHandleOrThrow(
    WinMutexHandleRuntime* const outHandle
  )
  {
    if (outHandle == nullptr) {
      return nullptr;
    }

    outHandle->handle = nullptr;
    const HANDLE mutexHandle = ::CreateMutexA(nullptr, FALSE, nullptr);
    if (mutexHandle == nullptr || mutexHandle == INVALID_HANDLE_VALUE) {
      ThrowThreadResourceErrorRuntime();
    }

    outHandle->handle = mutexHandle;
    return outHandle;
  }

  /**
   * Address: 0x00AC5480 (FUN_00AC5480)
   *
   * What it does:
   * Initializes one two-lane Win32 mutex owner (`handle`, `lane04`) and throws
   * `boost::thread_resource_error` when mutex creation fails.
   */
  WinMutexHandlePairRuntime* InitializeUnnamedMutexHandlePairOrThrow(
    WinMutexHandlePairRuntime* const outHandlePair
  )
  {
    if (outHandlePair == nullptr) {
      return nullptr;
    }

    outHandlePair->handle = nullptr;
    outHandlePair->lane04 = 0;

    const HANDLE mutexHandle = ::CreateMutexA(nullptr, FALSE, nullptr);
    if (mutexHandle == nullptr || mutexHandle == INVALID_HANDLE_VALUE) {
      ThrowThreadResourceErrorRuntime();
    }

    outHandlePair->handle = mutexHandle;
    return outHandlePair;
  }

  // boost::detail::condition_impl::condition_impl()/~condition_impl() and
  // boost::thread::~thread() are NOT defined in this TU: the vendored
  // dependencies/boost_1_34_1/libs/thread/src/condition.cpp and thread.cpp
  // are compiled directly into this project (main.vcxproj ->
  // boost_thread_condition.obj / boost_thread_thread.obj) and already
  // provide these symbols. A hand-written duplicate here would be an ODR
  // violation masked only by this project's /FORCE link setting (see
  // project_force_hides_declonly_bridges memory note) -- real address
  // citations for these two now live on the vendored definitions themselves
  // (0x00AC2190/0x00AC2760), with an explanatory note on condition_impl's
  // ctor about the UNICODE/ANSI CreateSemaphore/CreateMutex divergence that
  // main.vcxproj's condition.cpp ClCompile entry now corrects for.

  /**
   * Address: 0x00935E30 (FUN_00935E30)
   *
   * What it does:
   * Clears one current-thread TSS payload lane and then destroys one
   * `boost::detail::tss` descriptor, preserving destructor-unwind semantics.
   */
  void ResetCurrentThreadValueAndDestroyTss(detail::tss* const tssSlot)
  {
    struct ScopedTssDestroy
    {
      detail::tss* slot;
      ~ScopedTssDestroy()
      {
        slot->~tss();
      }
    } destroyGuard{ tssSlot };

    void* const currentValue = tssSlot->get();
    if (currentValue != nullptr) {
      tssSlot->set(nullptr);
      tssSlot->cleanup(currentValue);
    }
  }

  namespace
  {
    // NOTE (2026-08-20 audit): despite the "Weak" name inherited from the public
    // wrappers below, FUN_0043D940 (one of the addresses backing this core, see
    // `AssignWeakPairFromShared`) proves both lanes are ordinary strong
    // shared-count ownership, not weak: the acquire step is `lock xadd [pi+4],1`
    // (`use_count_` at +0x04 - `add_ref_copy()`, not `weak_add_ref()`) and the
    // release step calls FUN_004229B0, which is `sp_counted_base::release()`
    // (dispose-then-weak-release fused; see BoostWrappers.h), not
    // `weak_release()`. The public entry points (`AssignWeakPairFromShared`,
    // `AssignWeakPairFromSharedReversed`) are called from outside this TU
    // (AudioEngine.cpp, BeamRenderHelpers.cpp, CWorldParticles.cpp,
    // CD3DDevice.cpp, ResourceManager.cpp) so their names are kept stable;
    // only the body is corrected here.
    template <typename OutPairT, typename SourcePairT>
    SharedCountPair* AssignWeakPairFromSharedCore(OutPairT* const outPair, const SourcePairT* const sourcePair) noexcept
    {
      outPair->px = sourcePair->px;

      detail::sp_counted_base* const sourceControl = sourcePair->pi;
      if (sourceControl != outPair->pi) {
        if (sourceControl != nullptr) {
          sourceControl->add_ref_copy();
        }
        if (outPair->pi != nullptr) {
          outPair->pi->release();
        }
        outPair->pi = sourceControl;
      }

      return outPair;
    }

    template <typename OutPairT, typename SourcePairT>
    SharedCountPair* AssignSharedPairRetainCore(OutPairT* const outPair, const SourcePairT* const sourcePair) noexcept
    {
      outPair->px = sourcePair->px;
      outPair->pi = sourcePair->pi;
      if (outPair->pi != nullptr) {
        outPair->pi->add_ref_copy();
      }
      return outPair;
    }
  } // namespace

  /**
   * Address: 0x0043D940 (FUN_0043D940)
   * Address: 0x0043EED0 (FUN_0043EED0)
   * Address: 0x0043F2E0 (FUN_0043F2E0)
   * Address: 0x004438C0 (FUN_004438C0)
   *
   * NOTE (2026-08-20 audit): the name is a legacy misnomer kept for external
   * callers (AudioEngine.cpp, BeamRenderHelpers.cpp, CWorldParticles.cpp,
   * CD3DDevice.cpp, ResourceManager.cpp) - FUN_0043D940 proves this is a
   * strong shared-count rebind (`add_ref_copy()` on acquire, real
   * `release()` via FUN_004229B0 on the replaced lane), not a weak one. See
   * `AssignWeakPairFromSharedCore` above for the evidence.
   *
   * What it does:
   * Copies one `(px,pi)` pair and rebinds control ownership by retaining the
   * incoming `pi` then releasing the previous `pi`.
   */
  SharedCountPair* AssignWeakPairFromShared(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignWeakPairFromSharedCore(outPair, sourcePair);
  }

  /**
   * Address: 0x004414F0 (FUN_004414F0)
   * Address: 0x0043F7E0 (FUN_0043F7E0)
   * Address: 0x0043FCF0 (FUN_0043FCF0)
   * Address: 0x0063FD90 (FUN_0063FD90)
   * Address: 0x0089AE50 (FUN_0089AE50, Moho::WeakPtr_UICommandGraph::cpy)
   *
   * What it does:
   * Executes the same strong shared-count pair rebind as
   * `AssignWeakPairFromShared` (see its 2026-08-20 audit note), but receives
   * arguments in `(source, destination)` order.
   */
  SharedCountPair* AssignWeakPairFromSharedReversed(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignWeakPairFromSharedCore(outPair, sourcePair);
  }

  struct SharedCountPairOwnerAtOffset32
  {
    std::uint8_t pad00[0x20];
    SharedCountPair weakPair;
  };
  static_assert(
    offsetof(SharedCountPairOwnerAtOffset32, weakPair) == 0x20,
    "SharedCountPairOwnerAtOffset32::weakPair offset must be 0x20"
  );

  /**
   * Address: 0x0088B790 (FUN_0088B790)
   *
   * What it does:
   * Writes one source `(px,pi)` pair into an owner slot at `+0x20` and rebinds
   * control ownership with strong retain/release rules (see the 2026-08-20
   * audit note on `AssignWeakPairFromShared` - the field is still named
   * `weakPair` for layout-name stability, but the control block it owns is a
   * strong reference).
   */
  void AssignWeakPairToOwnerOffset32(
    const SharedCountPair* const sourcePair,
    void* const ownerBase
  ) noexcept
  {
    if (sourcePair == nullptr || ownerBase == nullptr) {
      return;
    }

    auto* const owner = reinterpret_cast<SharedCountPairOwnerAtOffset32*>(ownerBase);
    (void)AssignWeakPairFromShared(&owner->weakPair, sourcePair);
  }

  /**
   * Address: 0x007DD160 (FUN_007DD160)
   *
   * NOTE (2026-08-20 audit): renamed from `...WithWeakRelease`. FUN_007DD160's
   * release step calls FUN_004229B0, which is `sp_counted_base::release()`
   * (dispose-then-weak-release fused; see BoostWrappers.h), never a standalone
   * weak drop. Zero external callers at rename time (grep-verified).
   *
   * What it does:
   * Copies one `(px,pi)` pair and rebinds ownership by shared-retaining the
   * incoming control lane and shared-releasing the previously bound lane.
   */
  SharedCountPair* AssignSharedPairRetainAndRelease(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    outPair->px = sourcePair->px;

    detail::sp_counted_base* const incomingControl = sourcePair->pi;
    if (incomingControl != outPair->pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (outPair->pi != nullptr) {
        outPair->pi->release();
      }
      outPair->pi = incomingControl;
    }

    return outPair;
  }

  /**
   * Address: 0x006FE320 (FUN_006FE320)
   *
   * What it does:
   * Source-first adapter lane for
   * `AssignSharedPairRetainAndRelease`.
   */
  SharedCountPair* AssignSharedPairRetainAndReleaseSourceFirst(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainAndRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x007485A0 (FUN_007485A0)
   *
   * What it does:
   * Source-first adapter lane for shared-pair assignment with retained
   * incoming shared-control ownership and shared-release of the replaced lane.
   */
  SharedCountPair* AssignSharedPairRetainAndReleaseSourceFirstAdapterA(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainAndRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x007485D0 (FUN_007485D0)
   *
   * What it does:
   * Secondary source-first adapter lane for
   * `AssignSharedPairRetainAndRelease`.
   */
  SharedCountPair* AssignSharedPairRetainAndReleaseSourceFirstAdapterB(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainAndRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x00895880 (FUN_00895880)
   *
   * What it does:
   * Source-first adapter lane for shared-pair assignment with retained
   * incoming shared-control ownership and shared-release of the replaced lane.
   */
  SharedCountPair* AssignSharedPairRetainAndReleaseSourceFirstAdapterC(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainAndRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x0055AA60 (FUN_0055AA60)
   *
   * NOTE (2026-08-20 audit): despite the `...Weak` name (kept for the external
   * caller in Entity.cpp), FUN_0055AA60 is byte-for-byte the same shape as
   * FUN_0043D940 (see `AssignWeakPairFromShared`'s audit note): the acquire
   * step is `lock xadd [pi+4],1` (`use_count_` at +0x04 - `add_ref_copy()`)
   * and the release step calls FUN_004229B0, i.e. real `release()`, not
   * `weak_release()`. This is an ordinary strong `shared_ptr<RScmResource>`
   * rebind, not a weak one.
   *
   * What it does:
   * Rebinds one borrowed `boost::shared_ptr<RScmResource>` lane to another by
   * shared-retaining the incoming control block and shared-releasing the
   * previous one, while always copying the raw pointee lane.
   */
  moho::RScmResource** AssignSharedPtrRScmResourceWeak(
    const SharedPtrRaw<moho::RScmResource>* const sourceShared,
    SharedPtrRaw<moho::RScmResource>* const outShared
  ) noexcept
  {
    outShared->px = sourceShared->px;

    detail::sp_counted_base* const incomingControl = sourceShared->pi;
    if (incomingControl != outShared->pi) {
      if (incomingControl != nullptr) {
        incomingControl->add_ref_copy();
      }
      if (outShared->pi != nullptr) {
        outShared->pi->release();
      }
      outShared->pi = incomingControl;
    }

    return &outShared->px;
  }

  /**
   * Address: 0x0055FBD0 (FUN_0055FBD0, Moho::WeakPtr_RScmResource::WeakPtr_RScmResource)
   *
   * NOTE (2026-08-20 audit): FUN_0055FBD0 is its own independent inlined copy
   * of the same strong retain/release shape as FUN_0055AA60 (not literally a
   * call to it), confirmed by direct disassembly comparison. Forwarding to
   * the now-corrected `AssignSharedPtrRScmResourceWeak` models it faithfully.
   *
   * What it does:
   * Constructor/assign adapter lane for `RScmResource` pointer pairs that
   * mirrors `AssignSharedPtrRScmResourceWeak`.
   */
  moho::RScmResource** ConstructWeakPtrRScmResourceFromShared(
    const SharedPtrRaw<moho::RScmResource>* const sourceShared,
    SharedPtrRaw<moho::RScmResource>* const outWeak
  ) noexcept
  {
    return AssignSharedPtrRScmResourceWeak(sourceShared, outWeak);
  }

  /**
   * Address: 0x00539450 (FUN_00539450, boost::enable_shared_from_this<Moho::RScmResource>::shared_from_this)
   * Mangled: ?shared_from_this@?$enable_shared_from_this@VRScmResource@Moho@@@boost@@QAE?AV?$shared_ptr@VRScmResource@Moho@@@2@XZ
   *
   * What it does:
   * Constructs one `shared_ptr<RScmResource>` from one
   * `enable_shared_from_this<RScmResource>` weak-this lane.
   */
  SharedPtrRaw<moho::RScmResource>* ConstructSharedPtrRScmResourceFromWeakThis(
    const SharedPtrRaw<moho::RScmResource>* const sourceWeakThis,
    SharedPtrRaw<moho::RScmResource>* const outShared
  )
  {
    (void)SpCountedBaseWeakConstructFromSharedOrThrow(&outShared->pi, &sourceWeakThis->pi);
    outShared->px = sourceWeakThis->px;
    return outShared;
  }

  /**
   * Address: 0x00796D40 (FUN_00796D40, boost::enable_shared_from_this<Moho::CMauiFrame>::shared_from_this)
   * Mangled: ?shared_from_this@?$enable_shared_from_this@VCMauiFrame@Moho@@@boost@@QAE?AV?$shared_ptr@VCMauiFrame@Moho@@@2@XZ
   *
   * What it does:
   * Constructs one `shared_ptr<CMauiFrame>` from one
   * `enable_shared_from_this<CMauiFrame>` weak-this lane.
   */
  SharedPtrRaw<moho::CMauiFrame>* ConstructSharedPtrCMauiFrameFromWeakThis(
    const SharedPtrRaw<moho::CMauiFrame>* const sourceWeakThis,
    SharedPtrRaw<moho::CMauiFrame>* const outShared
  )
  {
    (void)SpCountedBaseWeakConstructFromSharedOrThrow(&outShared->pi, &sourceWeakThis->pi);
    outShared->px = sourceWeakThis->px;
    return outShared;
  }

  /**
   * Address: 0x0043DCF0 (FUN_0043DCF0)
   * Address: 0x0043F500 (FUN_0043F500)
   * Address: 0x0043F8E0 (FUN_0043F8E0)
   * Address: 0x0043FD90 (FUN_0043FD90)
   * Address: 0x00446A80 (FUN_00446A80)
   * Address: 0x004456E0 (FUN_004456E0)
   * Address: 0x00445860 (FUN_00445860)
   * Address: 0x004459A0 (FUN_004459A0)
   * Address: 0x004459C0 (FUN_004459C0)
   * Address: 0x004459E0 (FUN_004459E0)
   * Address: 0x00446150 (FUN_00446150)
   * Address: 0x004462F0 (FUN_004462F0)
   * Address: 0x00539AA0 (FUN_00539AA0)
   * Address: 0x00539F70 (FUN_00539F70)
   * Address: 0x00544340 (FUN_00544340)
   * Address: 0x006FE350 (FUN_006FE350, ex `CopySharedOwnerPairAndRetain` in
   * `LegacyContainerFillLanes.cpp`)
   * Address: 0x00796DC0 (FUN_00796DC0, ex `CopySharedOwnerPairWithUseRetain`
   * in `LegacyContainerFillLanes.cpp`)
   * Address: 0x00895F50 (FUN_00895F50, ex
   * `LegacyCopySharedOwnerPairRetainedRuntimeSlot1` in
   * `WinApiImportThunks.cpp`)
   * Address: 0x008971D0 (FUN_008971D0, ex
   * `LegacyCopySharedOwnerPairRetainedRuntimeSlot2` in
   * `WinApiImportThunks.cpp`)
   *
   * What it does:
   * Copies one `(px,pi)` pair and retains one shared control-block reference.
   */
  SharedCountPair* AssignSharedPairRetain(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignSharedPairRetainCore(outPair, sourcePair);
  }

  /**
   * Address: 0x00784190 (FUN_00784190)
   * Address: 0x007842E0 (FUN_007842E0)
   *
   * What it does:
   * Source-first adapter lane that copies one `(px,pi)` pair into destination
   * storage when present and retains one shared control-block reference.
   */
  SharedCountPair* AssignSharedPairRetainSourceFirstIfOutputPresent(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    if (outPair == nullptr) {
      return nullptr;
    }
    return AssignSharedPairRetainCore(outPair, sourcePair);
  }

  /**
   * Address: 0x005486D0 (FUN_005486D0)
   * Address: 0x00549080 (FUN_00549080)
   *
   * What it does:
   * Copies one raw shared-pair payload `(px,pi)` without refcount mutation.
   */
  SharedCountPair* CopySharedPairAliasNoRetain(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return CopySharedPair(outPair, sourcePair);
  }

  /**
   * Address: 0x0043E3B0 (FUN_0043E3B0)
   *
   * What it does:
   * Duplicate codegen lane of `AssignSharedPairRetain`.
   */
  SharedCountPair* AssignSharedPairRetainAlias(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignSharedPairRetainCore(outPair, sourcePair);
  }

  /**
   * Address: 0x00539420 (FUN_00539420)
   * Address: 0x005395D0 (FUN_005395D0)
   * Address: 0x00539AC0 (FUN_00539AC0)
   * Address: 0x0053A080 (FUN_0053A080)
   *
   * What it does:
   * Clears one two-dword lane and returns the caller-owned output slot.
   */
  [[nodiscard]] SharedCountPair* ZeroDwordPairLane(SharedCountPair* const outLane) noexcept
  {
    outLane->px = nullptr;
    outLane->pi = nullptr;
    return outLane;
  }

  /**
   * Address: 0x00539470 (FUN_00539470)
   * Address: 0x0053B480 (FUN_0053B480)
   * Address: 0x00540250 (FUN_00540250)
   * Address: 0x00540820 (FUN_00540820)
   * Address: 0x00540D80 (FUN_00540D80)
   * Address: 0x00540DA0 (FUN_00540DA0)
   *
   * What it does:
   * Stores one dword lane value into caller-provided output storage.
   */
  [[nodiscard]] std::uint32_t* StoreDwordLane(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    *outLane = value;
    return outLane;
  }

  /**
   * Address: 0x00540D90 (FUN_00540D90)
   * Address: 0x0056FCC0 (FUN_0056FCC0)
   * Address: 0x0056FD00 (FUN_0056FD00)
   * Address: 0x00570460 (FUN_00570460)
   *
   * What it does:
   * Copies one dword lane value from source storage into caller output.
   */
  [[nodiscard]] std::uint32_t* CopyDwordLane(
    std::uint32_t* const outLane,
    const std::uint32_t* const sourceLane
  ) noexcept
  {
    *outLane = *sourceLane;
    return outLane;
  }

  /**
   * Address: 0x00539AD0 (FUN_00539AD0)
   *
   * What it does:
   * Swaps one dword lane between two caller-provided output slots.
   */
  [[nodiscard]] std::uint32_t* SwapDwordLane(
    std::uint32_t* const leftLane,
    std::uint32_t* const rightLane
  ) noexcept
  {
    const std::uint32_t temp = *rightLane;
    *rightLane = *leftLane;
    *leftLane = temp;
    return leftLane;
  }

  struct RuntimeSharedCountTailRecord20
  {
    std::uint32_t lane00;        // +0x00
    std::uint32_t lane04;        // +0x04
    std::uint32_t lane08;        // +0x08
    detail::shared_count lane0C; // +0x0C
    std::uint32_t lane10;        // +0x10
  };
  static_assert(sizeof(RuntimeSharedCountTailRecord20) == 0x14, "RuntimeSharedCountTailRecord20 size must be 0x14");
  static_assert(offsetof(RuntimeSharedCountTailRecord20, lane0C) == 0x0C, "RuntimeSharedCountTailRecord20::lane0C offset must be 0x0C");

  /**
   * Address: 0x00950280 (FUN_00950280)
   *
   * What it does:
   * Copy-assigns one five-lane runtime record where lane `+0x0C` is a
   * `boost::detail::shared_count` payload requiring retained assignment.
   */
  RuntimeSharedCountTailRecord20* AssignRuntimeSharedCountTailRecord20(
    RuntimeSharedCountTailRecord20* const destination,
    const RuntimeSharedCountTailRecord20* const source
  )
  {
    destination->lane00 = source->lane00;
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;
    destination->lane10 = source->lane10;
    return destination;
  }

  struct RuntimeSharedCountTripleBlock
  {
    std::uint32_t lane00;             // +0x00
    std::uint32_t lane04;             // +0x04
    detail::shared_count lane08;      // +0x08
    std::uint32_t lane0C;             // +0x0C
    std::uint32_t lane10;             // +0x10
    detail::shared_count lane14;      // +0x14
    std::uint32_t lane18;             // +0x18
    detail::shared_count lane1C;      // +0x1C
  };

  /**
   * Address: 0x008E67C0 (FUN_008E67C0)
   *
   * What it does:
   * Copy-assigns one mixed runtime block with three `shared_count` lanes and
   * five scalar lanes.
   */
  RuntimeSharedCountTripleBlock* AssignRuntimeSharedCountTripleBlock(
    RuntimeSharedCountTripleBlock* const destination,
    const RuntimeSharedCountTripleBlock* const source
  )
  {
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;
    destination->lane10 = source->lane10;
    destination->lane14 = source->lane14;
    destination->lane18 = source->lane18;
    destination->lane1C = source->lane1C;
    return destination;
  }

  /**
   * Address: 0x0053B090 (FUN_0053B090)
   *
   * What it does:
   * Clears one shared-count payload pair `(px,pi)` to null lanes.
   */
  SharedCountPair* ClearSharedCountPair(SharedCountPair* const pair) noexcept
  {
    pair->px = nullptr;
    pair->pi = nullptr;
    return pair;
  }

  /**
   * Address: 0x0053B0A0 (FUN_0053B0A0)
   *
   * What it does:
   * Swaps full shared-count payload pairs `(px,pi)` between two owner slots.
   */
  SharedCountPair* SwapSharedCountPair(
    SharedCountPair* const lhs,
    SharedCountPair* const rhs
  ) noexcept
  {
    void* const px = rhs->px;
    rhs->px = lhs->px;
    lhs->px = px;

    detail::sp_counted_base* const pi = rhs->pi;
    rhs->pi = lhs->pi;
    lhs->pi = pi;
    return lhs;
  }

  /**
   * Address: 0x0053B2E0 (FUN_0053B2E0)
   *
   * What it does:
   * Swaps only the raw pointee lane (`px`) between two shared-count payload
   * slots without touching control blocks.
   */
  SharedCountPair* SwapSharedCountPairPointerLaneOnly(
    SharedCountPair* const lhs,
    SharedCountPair* const rhs
  ) noexcept
  {
    void* const px = rhs->px;
    rhs->px = lhs->px;
    lhs->px = px;
    return lhs;
  }

  /**
   * Address: 0x00740270 (FUN_00740270)
   *
   * What it does:
   * Releases one shared control block and disposes/destroys the control block
   * on the final strong and weak transitions.
   */
  void ReleaseSharedCount(detail::sp_counted_base* const control) noexcept
  {
    if (control != nullptr) {
      control->release();
    }
  }

  using SpCountedDeletingDtorFn = int (__thiscall*)(detail::sp_counted_base*, int);

  /**
   * Address: 0x00545490 (FUN_00545490)
   *
   * What it does:
   * Invokes one deleting-destructor vtable lane with delete flag `1` when the
   * control pointer is non-null.
   */
  [[nodiscard]] int InvokeSpCountedDeletingDtorIfPresent(detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return 0;
    }

    auto** const vtable = *reinterpret_cast<void***>(control);
    auto* const deletingDtor = reinterpret_cast<SpCountedDeletingDtorFn>(vtable[0]);
    return deletingDtor(control, 1);
  }

  /**
   * Address: 0x008E8BC0 (FUN_008E8BC0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<TextureD3D9>` control lane when present.
   */
  int DeleteSpCountedImplTextureD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8BE0 (FUN_008E8BE0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<RenderTargetD3D9>` control lane when present.
   */
  int DeleteSpCountedImplRenderTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8C00 (FUN_008E8C00)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<CubeRenderTargetD3D9>` control lane when present.
   */
  int DeleteSpCountedImplCubeRenderTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8C20 (FUN_008E8C20)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<DepthStencilTargetD3D9>` control lane when present.
   */
  int DeleteSpCountedImplDepthStencilTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8C40 (FUN_008E8C40)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<VertexFormatD3D9>` control lane when present.
   */
  int DeleteSpCountedImplVertexFormatD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8C60 (FUN_008E8C60)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<VertexBufferD3D9>` control lane when present.
   */
  int DeleteSpCountedImplVertexBufferD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8C80 (FUN_008E8C80)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<IndexBufferD3D9>` control lane when present.
   */
  int DeleteSpCountedImplIndexBufferD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8CA0 (FUN_008E8CA0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<EffectD3D9>` control lane when present.
   */
  int DeleteSpCountedImplEffectD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008E8DC0 (FUN_008E8DC0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<PipelineStateD3D9>` control lane when present.
   */
  int DeleteSpCountedImplPipelineStateD3D9IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x008F91E0 (FUN_008F91E0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for one
   * `sp_counted_impl_p<EffectD3D10>` control lane when present.
   */
  int DeleteSpCountedImplEffectD3D10IfPresent(detail::sp_counted_base* const control) noexcept
  {
    return InvokeSpCountedDeletingDtorIfPresent(control);
  }

  /**
   * Address: 0x006FE370 (FUN_006FE370)
   * Address: 0x00743FA0 (FUN_00743FA0)
   * Address: 0x007841B0 (FUN_007841B0)
   * Address: 0x00784300 (FUN_00784300)
   * Address: 0x00784340 (FUN_00784340)
   * Address: 0x007F7AC0 (FUN_007F7AC0)
   * Address: 0x008806C0 (FUN_008806C0)
   *
   * What it does:
   * Releases the shared control block stored in one `(px,pi)` pair lane without
   * mutating the pair fields, then returns the original pair pointer.
   */
  SharedCountPair* ReleaseSharedPairControlNoReset(SharedCountPair* const pair) noexcept
  {
    if (pair != nullptr && pair->pi != nullptr) {
      pair->pi->release();
    }
    return pair;
  }

  /**
   * Address: 0x00784070 (FUN_00784070)
   * Address: 0x00857630 (FUN_00857630)
   *
   * What it does:
   * Releases one half-open range of shared-pair slots by releasing each
   * control block referenced from the pair lanes.
   */
  SharedCountPair* ReleaseSharedCountRange(
    SharedCountPair* const begin,
    SharedCountPair* const end
  ) noexcept
  {
    SharedCountPair* cursor = begin;
    while (cursor != end) {
      ReleaseSharedCount(cursor->pi);
      ++cursor;
    }

    return cursor;
  }

  /**
   * Address: 0x007E27C0 (FUN_007E27C0)
   * Address: 0x007E2820 (FUN_007E2820)
   * Address: 0x007E28A0 (FUN_007E28A0)
   *
   * What it does:
   * Clears one `(px,pi)` pair to `{nullptr,nullptr}` and releases the shared
   * control block that used to be bound.
   */
  SharedCountPair* ReleaseSharedPairAndClear(SharedCountPair* const pair) noexcept
  {
    pair->px = nullptr;
    detail::sp_counted_base* const control = pair->pi;
    pair->pi = nullptr;
    ReleaseSharedCount(control);
    return pair;
  }

  /**
   * Address: 0x007832B0 (FUN_007832B0)
   * Address: 0x00783DE0 (FUN_00783DE0)
   *
   * What it does:
   * Adapter lane for `ReleaseSharedCountRange` that receives
   * `(rangeEnd, rangeBegin)` and returns one-past the released tail.
   */
  SharedCountPair* ReleaseSharedCountRangeReverseArgs(
    SharedCountPair* const rangeEnd,
    SharedCountPair* const rangeBegin
  ) noexcept
  {
    return ReleaseSharedCountRange(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x00783270 (FUN_00783270)
   *
   * What it does:
   * Releases one raw storage lane with global `operator delete`.
   */
  void DeleteSharedPairStorage(void* const storage) noexcept
  {
    ::operator delete(storage);
  }

  /**
   * Address: 0x004DE240 (FUN_004DE240)
   *
   * What it does:
   * Stores one 32-bit source lane into destination and returns destination.
   */
  std::uint32_t* StoreDwordValueAdapterA(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    *destination = value;
    return destination;
  }

  /**
   * Address: 0x004DE250 (FUN_004DE250)
   *
   * What it does:
   * Sibling lane that stores one 32-bit source value and returns destination.
   */
  std::uint32_t* StoreDwordValueAdapterB(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    *destination = value;
    return destination;
  }

  /**
   * Address: 0x004DE2B0 (FUN_004DE2B0)
   *
   * What it does:
   * Tertiary lane that stores one 32-bit source value and returns destination.
   */
  std::uint32_t* StoreDwordValueAdapterC(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    *destination = value;
    return destination;
  }

  /**
   * Address: 0x004DE2C0 (FUN_004DE2C0)
   *
   * What it does:
   * Fourth adapter lane for one 32-bit destination store.
   */
  std::uint32_t* StoreDwordValueAdapterD(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    *destination = value;
    return destination;
  }

  /**
   * Address: 0x004DE710 (FUN_004DE710)
   *
   * What it does:
   * Copies one 32-bit lane from source into destination and returns destination.
   */
  std::uint32_t* CopyDwordFromSourcePointerAdapterA(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x004DE720 (FUN_004DE720)
   *
   * What it does:
   * Sibling adapter lane that performs the same 32-bit source-to-destination
   * copy and returns destination.
   */
  std::uint32_t* CopyDwordFromSourcePointerAdapterB(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x004DE9B0 (FUN_004DE9B0)
   *
   * What it does:
   * Loads one 32-bit lane through two pointer indirections.
   */
  std::uint32_t LoadFirstDwordViaDoublePointerAdapterA(
    const std::uint32_t* const* const source
  ) noexcept
  {
    return **source;
  }

  /**
   * Address: 0x004DE9C0 (FUN_004DE9C0)
   *
   * What it does:
   * Sibling lane that loads one 32-bit value through two pointer indirections.
   */
  std::uint32_t LoadFirstDwordViaDoublePointerAdapterB(
    const std::uint32_t* const* const source
  ) noexcept
  {
    return **source;
  }

  /**
   * Address: 0x00446F30 (FUN_00446F30)
   *
   * What it does:
   * Attempts to acquire one shared-owner reference only when the current
   * use-count is non-zero.
   */
  bool SpCountedBaseAddRefLock(detail::sp_counted_base* const control) noexcept
  {
    return control != nullptr && control->add_ref_lock();
  }

  /**
   * Address: 0x00446F70 (FUN_00446F70)
   *
   * What it does:
   * Atomically increments one weak-count lane.
   *
   * The body is `add ecx, 8; mov eax, 1; lock xadd [ecx], eax; ret` - the
   * BOOST_INTERLOCKED_INCREMENT(&weak_count_) that `sp_counted_base::
   * weak_add_ref()` compiles to, with `weak_count_` at +0x08. The old value
   * left in EAX is the xadd's register residue, not a return: boost's
   * `weak_add_ref()` is void, and none of this function's callers ever read
   * it. So it dispatches to the member instead of reaching past it.
   */
  void SpCountedBaseWeakAddRef(detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return;
    }

    control->weak_add_ref();
  }

  /**
   * Address: 0x00446F80 (FUN_00446F80)
   *
   * What it does:
   * Returns one shared-owner use-count lane.
   */
  std::int32_t SpCountedBaseUseCount(const detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(control->use_count());
  }

  /**
   * Address: 0x00446FB0 (FUN_00446FB0)
   *
   * What it does:
   * Increments one weak-count lane and returns the same control pointer.
   */
  detail::sp_counted_base* SpCountedBaseWeakAddRefReturn(detail::sp_counted_base* const control) noexcept
  {
    SpCountedBaseWeakAddRef(control);
    return control;
  }

  /**
   * Address: 0x00446FC0 (FUN_00446FC0)
   *
   * CONFIRMED (2026-08-20 audit): this is the genuine standalone
   * `weak_release()` shape - `lock xadd [pi+8], -1` (`weak_count_` only) then,
   * on zero, a tail-call through vtable slot +0x08 (`destroy()`). It never
   * touches `use_count_` at +0x04 and never calls `dispose()`, unlike
   * FUN_004229B0 (`release()`, see BoostWrappers.h). This call site and
   * `SpCountedBaseWeakAssignSlot` below are correct as written.
   *
   * What it does:
   * Releases one weak-owner reference from one control-pointer slot.
   */
  detail::sp_counted_base* SpCountedBaseWeakReleaseFromSlot(detail::sp_counted_base** const controlSlot) noexcept
  {
    if (controlSlot == nullptr) {
      return nullptr;
    }

    detail::sp_counted_base* const control = *controlSlot;
    if (control != nullptr) {
      control->weak_release();
    }
    return control;
  }

  /**
   * Address: 0x00446FE0 (FUN_00446FE0)
   *
   * What it does:
   * Rebinds one weak control-pointer slot by weak-retaining the incoming
   * source control and weak-releasing the previously bound control.
   */
  detail::sp_counted_base** SpCountedBaseWeakAssignSlot(
    detail::sp_counted_base** const targetControlSlot,
    detail::sp_counted_base* const* const sourceControlSlot
  ) noexcept
  {
    if (targetControlSlot == nullptr) {
      return nullptr;
    }

    detail::sp_counted_base* const incomingControl =
      sourceControlSlot != nullptr ? *sourceControlSlot : nullptr;
    if (incomingControl != nullptr) {
      SpCountedBaseWeakAddRef(incomingControl);
    }

    if (*targetControlSlot != nullptr) {
      (*targetControlSlot)->weak_release();
    }

    *targetControlSlot = incomingControl;
    return targetControlSlot;
  }

  /**
   * Address: 0x00796FC0 (FUN_00796FC0)
   * Address: 0x007BD790 (FUN_007BD790)
   *
   * What it does:
   * Rebinds one weak-owner `(px,pi)` pair from a raw incoming shared control
   * slot: copies the new `px`, then delegates the control-block rebind to
   * `SpCountedBaseWeakAssignSlot`.
   */
  SharedCountPair* AssignWeakPairFromSharedControlSlot(
    SharedCountPair* const destination,
    void* const incomingObject,
    detail::sp_counted_base* const* const incomingControlSlot
  ) noexcept
  {
    destination->px = incomingObject;
    (void)SpCountedBaseWeakAssignSlot(&destination->pi, incomingControlSlot);
    return destination;
  }

  /**
   * Address: 0x00447020 (FUN_00447020)
   *
   * What it does:
   * Returns shared-owner use-count from one control-pointer slot, or zero when
   * no control block is present.
   */
  std::int32_t SpCountedBaseUseCountFromSlotOrZero(detail::sp_counted_base* const* const controlSlot) noexcept
  {
    if (controlSlot == nullptr || *controlSlot == nullptr) {
      return 0;
    }
    return SpCountedBaseUseCount(*controlSlot);
  }

  /**
   * Address: 0x0044DDD0 (FUN_0044DDD0, throw_BadWeakPtrException)
   *
   * IDA signature:
   * void __cdecl __noreturn throw_BadWeakPtrException(std::exception *a1);
   *
   * What it does:
   * Raises `boost::bad_weak_ptr`. The binary factors the throw out of the
   * weak-construct path into this one no-return helper, which builds the
   * exception object and hands it to _CxxThrowException.
   */
  [[noreturn]] void ThrowBadWeakPtr()
  {
    throw boost::bad_weak_ptr();
  }

  /**
   * Address: 0x00447030 (FUN_00447030)
   *
   * What it does:
   * Constructs/rebinds one weak control-pointer slot from one shared slot and
   * throws `boost::bad_weak_ptr` when the shared owner is absent or lock fails.
   */
  detail::sp_counted_base** SpCountedBaseWeakConstructFromSharedOrThrow(
    detail::sp_counted_base** const outWeakControlSlot,
    detail::sp_counted_base* const* const sourceSharedControlSlot
  )
  {
    if (outWeakControlSlot == nullptr) {
      ThrowBadWeakPtr();
    }

    detail::sp_counted_base* const sourceControl =
      sourceSharedControlSlot != nullptr ? *sourceSharedControlSlot : nullptr;
    *outWeakControlSlot = sourceControl;

    if (sourceControl == nullptr || !SpCountedBaseAddRefLock(sourceControl)) {
      ThrowBadWeakPtr();
    }

    return outWeakControlSlot;
  }

  /**
   * Address: 0x007BB290 (FUN_007BB290)
   *
   * What it does:
   * Builds one weak/shared pair from a source shared pair by constructing the
   * destination weak-control lane from the source control slot and then
   * copying the raw pointee lane.
   */
  SharedCountPair* ConstructWeakPairFromSharedPair(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  )
  {
    if (sourcePair == nullptr || outPair == nullptr) {
      return outPair;
    }

    (void)SpCountedBaseWeakConstructFromSharedOrThrow(&outPair->pi, &sourcePair->pi);
    outPair->px = sourcePair->px;
    return outPair;
  }

  /**
   * Address: 0x004470A0 (FUN_004470A0)
   *
   * What it does:
   * Constructs one `boost::bad_weak_ptr` exception object in caller-provided
   * storage.
   */
  boost::bad_weak_ptr* ConstructBadWeakPtr(boost::bad_weak_ptr* const outException)
  {
    return ::new (static_cast<void*>(outException)) boost::bad_weak_ptr();
  }

  /**
   * Address: 0x004470D0 (FUN_004470D0)
   *
   * What it does:
   * Runs one `boost::bad_weak_ptr` deleting-destructor lane controlled by
   * the low bit of `deleteFlag`.
   */
  boost::bad_weak_ptr* DestructBadWeakPtr(
    boost::bad_weak_ptr* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    exceptionObject->~bad_weak_ptr();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }

  namespace
  {
    [[noreturn]] void ThrowBadPointerForNullPushBackRuntime()
    {
      throw bad_pointer();
    }
  } // namespace

  /**
   * Address: 0x004DBBC0 (FUN_004DBBC0)
   *
   * What it does:
   * Validates one ptr-container `push_back` input pointer and throws
   * `boost::bad_pointer` when the pointer is null.
   */
  void EnsurePtrContainerPushBackInputNotNull(
    const void* const inputPointer
  )
  {
    if (inputPointer == nullptr) {
      ThrowBadPointerForNullPushBackRuntime();
    }
  }

  /**
   * Address: 0x004DBC70 (FUN_004DBC70)
   *
   * What it does:
   * Secondary ptr-container `push_back` null-pointer guard lane with the same
   * `boost::bad_pointer` throw semantics.
   */
  void EnsurePtrContainerPushBackInputNotNullSecondary(
    const void* const inputPointer
  )
  {
    if (inputPointer == nullptr) {
      ThrowBadPointerForNullPushBackRuntime();
    }
  }

  /**
   * Address: 0x0049C140 (FUN_0049C140)
   *
   * What it does:
   * Copy-constructs one `boost::bad_pointer` exception into caller-provided
   * storage, preserving the legacy pointer-container exception chain.
   */
  boost::bad_pointer* ConstructBadPointerFromCopy(
    boost::bad_pointer* const outException,
    const boost::bad_pointer& sourceException
  )
  {
    return ::new (static_cast<void*>(outException)) boost::bad_pointer(sourceException);
  }

  /**
   * Address: 0x0049C170 (FUN_0049C170)
   *
   * What it does:
   * Copy-constructs one `boost::bad_ptr_container_operation` exception into
   * caller-provided storage.
   */
  boost::bad_ptr_container_operation* ConstructBadPtrContainerOperationFromCopy(
    boost::bad_ptr_container_operation* const outException,
    const boost::bad_ptr_container_operation& sourceException
  )
  {
    return ::new (static_cast<void*>(outException)) boost::bad_ptr_container_operation(sourceException);
  }

  namespace
  {
    struct BadPtrContainerOperationRuntimeView
    {
      void* vftable;
      std::uint32_t stdExceptionWhat;
      std::uint32_t stdExceptionDoFree;
      const char* message;
    };

    static_assert(
      offsetof(BadPtrContainerOperationRuntimeView, message) == 0x0C,
      "BadPtrContainerOperationRuntimeView::message offset must be 0x0C"
    );
  } // namespace

  /**
   * Address: 0x00491350 (FUN_00491350)
   *
   * What it does:
   * Returns the pointer-container exception message lane used by both
   * `boost::bad_ptr_container_operation` and `boost::bad_pointer`.
   */
  const char* GetBadPtrContainerMessage(const boost::bad_ptr_container_operation* const exceptionObject) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    const auto* const view = reinterpret_cast<const BadPtrContainerOperationRuntimeView*>(exceptionObject);
    return view->message;
  }

  /**
   * Address: 0x00491360 (FUN_00491360)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `boost::bad_ptr_container_operation`,
   * forwarding through `std::exception` teardown and optional operator delete.
   */
  boost::bad_ptr_container_operation* DestructBadPtrContainerOperation(
    boost::bad_ptr_container_operation* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    static_cast<std::exception*>(exceptionObject)->~exception();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }

  /**
   * Address: 0x004913B0 (FUN_004913B0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `boost::bad_pointer`,
   * forwarding through `std::exception` teardown and optional operator delete.
   */
  boost::bad_pointer* DestructBadPointer(
    boost::bad_pointer* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    static_cast<std::exception*>(exceptionObject)->~exception();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }
  namespace
  {
    [[nodiscard]] void* SpCountedImplGetDeleterNullResult(boost::detail::sp_typeinfo const&) noexcept
    {
      return nullptr;
    }

    template <class TPointee>
    void DisposeSpCountedImplPointee(
      boost::SpCountedImplStorage<TPointee>* const countedImpl
    ) noexcept
    {
      if (countedImpl == nullptr || countedImpl->px == nullptr) {
        return;
      }

      delete countedImpl->px;
      countedImpl->px = nullptr;
    }

    /**
     * `boost::detail::sp_counted_base`-derived control blocks' `destroy()`
     * virtual slot: called once `weak_count_` also reaches zero, after
     * `dispose()` has already released the pointee. Every `sp_counted_impl_p<T>`/
     * `sp_counted_impl_pd<T,D>` instantiation compiles to the identical
     * `{ delete this; }` body regardless of `T` -- there is nothing left that
     * depends on the pointee type at this point.
     */
    template <class TStorage>
    void DestroySpCountedImplSelf(TStorage* const self) noexcept
    {
      delete self;
    }

    template <class TPointee>
    [[nodiscard]] SpCountedImplStorage<TPointee>* SpCountedImplDeletingDtorLane(
      SpCountedImplStorage<TPointee>* const countedImpl,
      const unsigned char deleteFlag
    ) noexcept
    {
      return SpCountedImplDeletingDtor(countedImpl, deleteFlag);
    }

    template <class TPointee>
    struct SpCountedImplPdRuntimeView
    {
      void* vftable;
      std::int32_t useCount;
      std::int32_t weakCount;
      TPointee* px;
      std::uint8_t deleterStorage[4];
    };

    static_assert(
      offsetof(SpCountedImplPdRuntimeView<void>, deleterStorage) == 0x10,
      "SpCountedImplPdRuntimeView::deleterStorage offset must be 0x10"
    );

    [[nodiscard]] bool SpTypeInfoMatchesRawName(
      const boost::detail::sp_typeinfo& requestedType,
      const char* const expectedRawName
    ) noexcept
    {
#if defined(_MSC_VER)
      const char* const rawName = requestedType.raw_name();
      if (rawName != nullptr && std::strcmp(rawName, expectedRawName) == 0) {
        return true;
      }
#endif

      const char* const name = requestedType.name();
      return name != nullptr && std::strcmp(name, expectedRawName) == 0;
    }

    template <class TPointee>
    [[nodiscard]] void* GetSpCountedImplPdDeleterStorage(
      SpCountedImplStorage<TPointee>* const countedImpl
    ) noexcept
    {
      if (countedImpl == nullptr) {
        return nullptr;
      }

      auto* const runtime = reinterpret_cast<SpCountedImplPdRuntimeView<TPointee>*>(countedImpl);
      return static_cast<void*>(runtime->deleterStorage);
    }

    class RecoveredSpCountedBaseVtableProbe final : public detail::sp_counted_base
    {
    public:
      void dispose() noexcept override
      {
      }

      void* get_deleter(detail::sp_typeinfo const&) noexcept override
      {
        return nullptr;
      }
    };

    [[nodiscard]] void* RecoveredSpCountedImplPVtable() noexcept
    {
      static RecoveredSpCountedBaseVtableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }

    /**
     * Dedicated (non-shared) vtable probe for `sp_counted_impl_p<gpg::HaStar::
     * ClusterCache::Impl>`. Unlike `RecoveredSpCountedBaseVtableProbe` above
     * -- whose `dispose()` is a no-op shared by every other `<T>`/`<void>`
     * instantiation in this file -- this probe's `dispose()` genuinely
     * dispatches to `SpCountedImplPDisposeClusterCacheImpl`, so that
     * `Cluster.cpp`'s local `ReleaseSharedCount(void*)` (which drives
     * `dispose()` through a real `vtable[1]` indirect call, not a by-name
     * call) actually frees the `ClusterCacheImpl` pointee instead of
     * silently no-oping.
     */
    class RecoveredSpCountedBaseVtableProbeClusterCacheImpl final : public detail::sp_counted_base
    {
    public:
      void dispose() noexcept override
      {
        SpCountedImplPDisposeClusterCacheImpl(reinterpret_cast<SpCountedImplStorage<void>*>(this));
      }

      void* get_deleter(detail::sp_typeinfo const& requestedType) noexcept override
      {
        return SpCountedImplPGetDeleterNullClusterCacheImpl(requestedType);
      }
    };

    [[nodiscard]] void* RecoveredSpCountedImplPVtableClusterCacheImpl() noexcept
    {
      static RecoveredSpCountedBaseVtableProbeClusterCacheImpl probe;
      return *reinterpret_cast<void**>(&probe);
    }
  } // namespace

  /**
   * Address: 0x00931EB0 (FUN_00931EB0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for one owned
   * `ClusterCache::Impl` lane. Unlike every other `SpCountedImplPConstruct*`
   * in this file, this one is wired to `RecoveredSpCountedImplPVtableClusterCacheImpl()`
   * (a dedicated, genuinely-dispatching vtable) rather than the shared
   * `RecoveredSpCountedImplPVtable()` stub: `gpg::HaStar::ClusterCache`'s own
   * `~ClusterCache()`/`MakeClusterCache()` (`Cluster.cpp`) release the
   * control block through a real `vtable[1]` indirect call
   * (`ReleaseSharedCount`), not a by-name call, so `dispose()` has to
   * actually be reachable through the vtable for this one instantiation.
   */
  SpCountedImplStorage<void>* SpCountedImplPConstructClusterCacheImpl(
    SpCountedImplStorage<void>* const countedImpl,
    void* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtableClusterCacheImpl(), ownedPointee);
  }


  /**
   * Address: 0x0053B3D0 (FUN_0053B3D0, boost::detail::sp_counted_impl_p<Moho::RScaResource>::dispose)
   *
   * What it does:
   * Deletes one owned `RScaResource` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeRScaResource(
    SpCountedImplStorage<moho::RScaResource>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x0053B400 (FUN_0053B400, boost::detail::sp_counted_impl_p<Moho::RScaResource>::destroy)
   *
   * What it does:
   * Frees the control block itself once both use and weak counts reach
   * zero (the pointee was already released by `dispose()`).
   */
  void SpCountedImplPDestroyRScaResource(
    SpCountedImplStorage<moho::RScaResource>* const self
  ) noexcept
  {
    DestroySpCountedImplSelf(self);
  }

  /**
   * Address: 0x005CC7E0 (FUN_005CC7E0, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::dispose)
   *
   * What it does:
   * Deletes one owned `Stats_StatItem` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeStatsStatItem(
    SpCountedImplStorage<moho::Stats_StatItem>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }


  /**
   * Address: 0x007FBE60 (FUN_007FBE60, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::dispose)
   *
   * What it does:
   * Releases one owned `IRenTerrain` pointee through its scalar-deleting
   * destructor when present.
   *
   * The body is `mov ecx,[this+0x0C]; test ecx,ecx; je end; mov eax,[ecx];
   * mov edx,[eax]; push 1; call edx` -- the pointee's scalar deleting
   * destructor, vtable slot 0, free flag set. `moho::IRenTerrain` does not
   * declare that virtual destructor yet (the class carries only static
   * helpers even though its vftable at 0x00E41994 has fifteen slots), so this
   * calls `IRenTerrain::DeleteWithFlag` -- the recovered 0x007FF8B0 body for
   * exactly this operation -- rather than indexing the vtable by hand through
   * a stand-in struct, which is what it used to do.
   */
  void SpCountedImplPDisposeIRenTerrain(
    SpCountedImplStorage<moho::IRenTerrain>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr || countedImpl->px == nullptr) {
      return;
    }

    (void)moho::IRenTerrain::DeleteWithFlag(countedImpl->px, 1u);
    countedImpl->px = nullptr;
  }

  /**
   * Address: 0x00765720 (FUN_00765720, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dispose)
   *
   * What it does:
   * Destroys one owned `PathPreviewFinder` through its real destructor chain
   * (see `moho::DeletePathPreviewFinder`, `moho/sim/PathPreviewFinder.h`),
   * which unlinks it from its intrusive path-queue ring before the owned
   * pointee allocation is released.
   */
  void SpCountedImplPDisposePathPreviewFinder(
    SpCountedImplStorage<moho::PathPreviewFinder>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr || countedImpl->px == nullptr) {
      return;
    }

    moho::DeletePathPreviewFinder(countedImpl->px);
    countedImpl->px = nullptr;
  }

  /**
   * Address: 0x00884810 (FUN_00884810, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::dispose)
   *
   * What it does:
   * Closes one owned `FILE*` lane through `fclose` when that file pointer is
   * present in the file-star-closer control block.
   */
  void SpCountedImplPdDisposeSFileStarCloser(
    SpCountedImplStorage<void>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return;
    }

    std::FILE* const file = static_cast<std::FILE*>(countedImpl->px);
    if (file != nullptr) {
      (void)std::fclose(file);
    }
  }

  struct SpCountedImplPdFunctionDeleterRuntimeView
  {
    void* vftable;
    std::int32_t useCount;
    std::int32_t weakCount;
    void* px;
    void(__cdecl* deleter)(void*);
  };
  static_assert(
    offsetof(SpCountedImplPdFunctionDeleterRuntimeView, deleter) == 0x10,
    "SpCountedImplPdFunctionDeleterRuntimeView::deleter offset must be 0x10"
  );

  /**
   * Address: 0x0054EDC0 (FUN_0054EDC0, boost::detail::sp_counted_impl_pd<Moho::CAniDefaultSkel *, void (__cdecl *)(void *)>::dispose)
   *
   * What it does:
   * Invokes the stored raw-function deleter lane for one `CAniDefaultSkel*`
   * pointee in this `sp_counted_impl_pd` control block.
   */
  void SpCountedImplPdDisposeCAniDefaultSkelFunctionDeleter(
    SpCountedImplStorage<void>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return;
    }

    auto* const runtime = reinterpret_cast<SpCountedImplPdFunctionDeleterRuntimeView*>(countedImpl);
    runtime->deleter(runtime->px);
  }

  /**
   * Address: 0x0054EE00 (FUN_0054EE00, boost::detail::sp_counted_impl_pd<Moho::CAniDefaultSkel *, void (__cdecl *)(void *)>::destroy)
   *
   * What it does:
   * Frees the control block itself once both use and weak counts reach
   * zero (the pointee was already released by `dispose()`).
   */
  void SpCountedImplPdDestroyCAniDefaultSkelFunctionDeleter(
    SpCountedImplStorage<void>* const self
  ) noexcept
  {
    DestroySpCountedImplSelf(self);
  }

  /**
   * Address: 0x0054EDD0 (FUN_0054EDD0, boost::detail::sp_counted_impl_pd<Moho::CAniDefaultSkel *, void (__cdecl *)(void *)>::get_deleter)
   *
   * What it does:
   * Returns the stored raw-function deleter lane at offset `+0x10` when the
   * queried `type_info` matches `void (__cdecl *)(void *)`.
   */
  void* SpCountedImplPdGetDeleterCAniDefaultSkelFunctionDeleter(
    SpCountedImplStorage<void>* const countedImpl,
    const detail::sp_typeinfo& requestedType
  ) noexcept
  {
    if (!detail::sp_typeinfo_equal(requestedType, BOOST_SP_TYPEID(void (*)(void*)))) {
      return nullptr;
    }
    return GetSpCountedImplPdDeleterStorage(countedImpl);
  }

  /**
   * Address: 0x00923920 (FUN_00923920, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::dispose)
   *
   * What it does:
   * Deletes one owned `std::basic_stringstream<char,...>` pointee bound to
   * this shared-count control lane when present.
   */
  void SpCountedImplPDisposeStdStringstreamChar(
    SpCountedImplStorage<void>* const countedImpl
  ) noexcept
  {
    using StdStringstreamChar = std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>;

    if (countedImpl == nullptr) {
      return;
    }

    auto* const typedStorage = reinterpret_cast<SpCountedImplStorage<StdStringstreamChar>*>(countedImpl);
    DisposeSpCountedImplPointee(typedStorage);
  }

  /**
   * Address: 0x00935520 (FUN_00935520, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::dispose)
   *
   * What it does:
   * Deletes one owned `ClusterCache::Impl` pointee bound to this
   * shared-count control lane when present. `ClusterCacheImpl` stays
   * opaque here (only complete in `Cluster.cpp`), so the actual
   * destruction is delegated to `gpg::HaStar::DestroyClusterCacheImplPointee`
   * rather than the generic `DisposeSpCountedImplPointee<T>` the other
   * `<void>`-typed instantiation above uses -- that generic path needs a
   * complete `TPointee` to instantiate `delete px`, which is only true in
   * `Cluster.cpp`'s translation unit.
   */
  void SpCountedImplPDisposeClusterCacheImpl(
    SpCountedImplStorage<void>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr || countedImpl->px == nullptr) {
      return;
    }

    gpg::HaStar::DestroyClusterCacheImplPointee(countedImpl->px);
    countedImpl->px = nullptr;
  }

  /**
   * Address: 0x009418D0 (FUN_009418D0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::dispose)
   *
   * What it does:
   * Deletes one owned `EffectTechniqueD3D9` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeEffectTechniqueD3D9(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x009418E0 (FUN_009418E0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::dispose)
   *
   * What it does:
   * Deletes one owned `EffectVariableD3D9` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeEffectVariableD3D9(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x0094B7E0 (FUN_0094B7E0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::dispose)
   *
   * What it does:
   * Deletes one owned `EffectTechniqueD3D10` pointee bound to this
   * shared-count control lane when present.
   */
  void SpCountedImplPDisposeEffectTechniqueD3D10(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x0094B7F0 (FUN_0094B7F0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::dispose)
   *
   * What it does:
   * Deletes one owned `EffectVariableD3D10` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeEffectVariableD3D10(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x0094E0A0 (FUN_0094E0A0, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::dispose)
   *
   * What it does:
   * Invokes the stored byte-pointer deleter lane for one
   * `sp_counted_impl_pd<char*,void(*)(void*)>` control block.
   */
  void SpCountedImplPdDisposeCharPointerFunctionDeleter(
    SpCountedImplPdCharPointerStorage* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return;
    }

    countedImpl->deleter(static_cast<void*>(countedImpl->px));
  }

  /**
   * Address: 0x005CC830 (FUN_005CC830, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::Stats_StatItem>* SpCountedImplPDeletingDtorStatsStatItem(
    SpCountedImplStorage<moho::Stats_StatItem>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x00756080 (FUN_00756080, boost::detail::sp_counted_impl_p<Moho::ISimResources>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::ISimResources>* SpCountedImplPDeletingDtorISimResources(
    SpCountedImplStorage<moho::ISimResources>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }


  /**
   * Address: 0x00765770 (FUN_00765770, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::PathPreviewFinder>* SpCountedImplPDeletingDtorPathPreviewFinder(
    SpCountedImplStorage<moho::PathPreviewFinder>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }


  /**
   * Address: 0x007FBE80 (FUN_007FBE80, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::IRenTerrain>* SpCountedImplPDeletingDtorIRenTerrain(
    SpCountedImplStorage<moho::IRenTerrain>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007FC1F0 (FUN_007FC1F0, boost::detail::sp_counted_impl_p<Moho::CD3DTextureBatcher>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CD3DTextureBatcher>* SpCountedImplPDeletingDtorCD3DTextureBatcher(
    SpCountedImplStorage<moho::CD3DTextureBatcher>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007FC210 (FUN_007FC210, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CD3DPrimBatcher>* SpCountedImplPDeletingDtorCD3DPrimBatcher(
    SpCountedImplStorage<moho::CD3DPrimBatcher>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }


  /**
   * Address: 0x00884870 (FUN_00884870, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<void>* SpCountedImplPdDeletingDtorFileStarCloser(
    SpCountedImplStorage<void>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }


  /**
   * Address: 0x0089B910 (FUN_0089B910, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::SSessionSaveData>* SpCountedImplPDeletingDtorSSessionSaveData(
    SpCountedImplStorage<moho::SSessionSaveData>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x0089BCC0 (FUN_0089BCC0, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::UICommandGraph>* SpCountedImplPDeletingDtorUICommandGraph(
    SpCountedImplStorage<moho::UICommandGraph>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x00884820 (FUN_00884820, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::get_deleter)
   *
   * What it does:
   * Returns one file-closer deleter lane at offset `+0x10` when the queried
   * `type_info` matches `Moho::SFileStarCloser`.
   */
  void* SpCountedImplPdGetDeleterSFileStarCloser(
    SpCountedImplStorage<void>* const countedImpl,
    const detail::sp_typeinfo& requestedType
  ) noexcept
  {
    if (!detail::sp_typeinfo_equal(requestedType, BOOST_SP_TYPEID(moho::SFileStarCloser))) {
      return nullptr;
    }
    return GetSpCountedImplPdDeleterStorage(countedImpl);
  }

  /**
   * Address: 0x00923740 (FUN_00923740)
   *
   * What it does:
   * Deletes one `std::stringstream` raw-pointer lane during
   * `shared_count<stringstream>` constructor unwind.
   */
  int DeleteStdStringstreamSharedCountCtorPointeeOnUnwind(
    std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>* const stream
  ) noexcept
  {
    if (stream != nullptr) {
      delete stream;
    }
    return 0;
  }

  /**
   * Address: 0x00923960 (FUN_00923960)
   *
   * What it does:
   * Constructs one `boost::shared_ptr<std::stringstream>` from one raw
   * `std::stringstream*` lane.
   */
  boost::shared_ptr<std::stringstream>* ConstructSharedStdStringstreamFromRaw(
    boost::shared_ptr<std::stringstream>* const outSharedStream,
    std::stringstream* const stream
  )
  {
    return ::new (outSharedStream) boost::shared_ptr<std::stringstream>(stream);
  }

  /**
   * Address: 0x00923940 (FUN_00923940, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<void>* SpCountedImplPDeletingDtorStdStringstreamChar(
    SpCountedImplStorage<void>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x009325F0 (FUN_009325F0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<void>* SpCountedImplPDeletingDtorClusterCacheImpl(
    SpCountedImplStorage<void>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  namespace
  {
    using deleting_dtor_fn = int(__thiscall*)(void*, int);

    template <class TObject>
    [[nodiscard]] int DeletePolymorphicSharedCountCtorPointeeOnUnwind(
      TObject* const pointer
    ) noexcept
    {
      if (pointer == nullptr) {
        return 0;
      }

      auto** const vtable = *reinterpret_cast<void***>(pointer);
      auto* const deletingDtor = reinterpret_cast<deleting_dtor_fn>(vtable[0]);
      return deletingDtor(pointer, 1);
    }
  } // namespace

  /**
   * Address: 0x009416E0 (FUN_009416E0)
   *
   * What it does:
   * Executes one deleting-destructor lane for an
   * `EffectTechniqueD3D9` pointee during `shared_count` constructor unwind.
   */
  int DeleteEffectTechniqueD3D9SharedCountCtorPointeeOnUnwind(
    gpg::gal::EffectTechniqueD3D9* const effectTechnique
  ) noexcept
  {
    return DeletePolymorphicSharedCountCtorPointeeOnUnwind(effectTechnique);
  }

  /**
   * Address: 0x00941700 (FUN_00941700)
   *
   * What it does:
   * Executes one deleting-destructor lane for an
   * `EffectVariableD3D9` pointee during `shared_count` constructor unwind.
   */
  int DeleteEffectVariableD3D9SharedCountCtorPointeeOnUnwind(
    gpg::gal::EffectVariableD3D9* const effectVariable
  ) noexcept
  {
    return DeletePolymorphicSharedCountCtorPointeeOnUnwind(effectVariable);
  }

  /**
   * Address: 0x009418F0 (FUN_009418F0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* SpCountedImplPDeletingDtorEffectTechniqueD3D9(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x00941910 (FUN_00941910, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* SpCountedImplPDeletingDtorEffectVariableD3D9(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x0094B800 (FUN_0094B800, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* SpCountedImplPDeletingDtorEffectTechniqueD3D10(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x0094B820 (FUN_0094B820, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* SpCountedImplPDeletingDtorEffectVariableD3D10(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x0094E260 (FUN_0094E260, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplPdCharPointerStorage* SpCountedImplPdDeletingDtorCharPointerFunctionDeleter(
    SpCountedImplPdCharPointerStorage* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtor(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x004DE780 (FUN_004DE780, boost::detail::sp_counted_impl_p<Moho::AudioEngine>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullAudioEngine(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x0053B3F0 (FUN_0053B3F0, boost::detail::sp_counted_impl_p<Moho::RScaResource>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullRScaResource(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00755FD0 (FUN_00755FD0, boost::detail::sp_counted_impl_p<Moho::ISimResources>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullISimResources(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }


  /**
   * Address: 0x00765760 (FUN_00765760, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullPathPreviewFinder(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }


  /**
   * Address: 0x007FBE70 (FUN_007FBE70, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullIRenTerrain(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x007FC190 (FUN_007FC190, boost::detail::sp_counted_impl_p<Moho::CD3DTextureBatcher>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCD3DTextureBatcher(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x007FC1E0 (FUN_007FC1E0, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCD3DPrimBatcher(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x0089B8A0 (FUN_0089B8A0, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullSSessionSaveData(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x0089BCB0 (FUN_0089BCB0, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullUICommandGraph(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00923720 (FUN_00923720, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullStdStringstreamChar(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00931ED0 (FUN_00931ED0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullClusterCacheImpl(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00941680 (FUN_00941680, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullEffectTechniqueD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x009416B0 (FUN_009416B0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullEffectVariableD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x0094E0B0 (FUN_0094E0B0, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::get_deleter)
   *
   * What it does:
   * Returns the stored deleter lane when queried with
   * `typeid(void (__cdecl*)(void*))`; otherwise returns null.
   */
  void* SpCountedImplPdGetDeleterCharPointerFunctionDeleter(
    SpCountedImplPdCharPointerStorage* const countedImpl,
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    if (requestedType == BOOST_SP_TYPEID(SharedByteDeleterFn)) {
      return static_cast<void*>(&countedImpl->deleter);
    }
    return nullptr;
  }

  /**
   * Address: 0x00883F60 (FUN_00883F60, boost::shared_ptr<Moho::LaunchInfoLoad>::shared_ptr)
   * Mangled: ??0?$shared_ptr@VLaunchInfoLoad@Moho@@@boost@@QAE@PAVLaunchInfoLoad@Moho@@@Z
   *
   * IDA signature:
   * boost::shared_ptr_LaunchInfoLoad *__userpurge sub_883F60@<eax>(
   *     Moho::LaunchInfoLoad **a1@<edi>, boost::shared_ptr_LaunchInfoLoad *this);
   *
   * What it does:
   * Placement-new constructs one `boost::shared_ptr<LaunchInfoLoad>` over an
   * uninitialized output slot from one raw `LaunchInfoLoad*` pointee, taking
   * strong ownership through a freshly allocated sp_counted_impl_p<LaunchInfoLoad>
   * control block (use/weak counts = 1). LaunchInfoLoad does not derive
   * enable_shared_from_this, so the trailing sp_enable_shared_from_this hook is a
   * no-op. Engine-instantiated boost templated ctor emission.
   */
  boost::shared_ptr<moho::LaunchInfoLoad>* ConstructSharedLaunchInfoLoadFromRaw(
    boost::shared_ptr<moho::LaunchInfoLoad>* const outLaunchInfo,
    moho::LaunchInfoLoad* const rawLaunchInfo
  )
  {
    return ::new (static_cast<void*>(outLaunchInfo))
      boost::shared_ptr<moho::LaunchInfoLoad>(rawLaunchInfo);
  }
} // namespace boost
