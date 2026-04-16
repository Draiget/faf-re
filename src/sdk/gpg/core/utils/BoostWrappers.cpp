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
#include "moho/sim/SConditionTriggerTypes.h"

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
  [[maybe_unused]] void EnsureNamedMutexHandleCreatedOrThrow(
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
  [[maybe_unused]] void EnsureNamedMutexHandleCreatedOrThrowSecondary(
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
  [[maybe_unused]] WinMutexHandleRuntime* InitializeUnnamedMutexHandleOrThrow(
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
  [[maybe_unused]] WinMutexHandlePairRuntime* InitializeUnnamedMutexHandlePairOrThrow(
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

  namespace detail
  {
#if defined(BOOST_HAS_WINTHREADS)
    /**
     * Address: 0x00AC2190 (FUN_00AC2190, boost::detail::condition_impl::condition_impl)
     *
     * What it does:
     * Initializes Win32 semaphore/mutex primitives for one condition
     * implementation lane and throws `boost::thread_resource_error` when any
     * primitive allocation fails.
     */
    condition_impl::condition_impl() : m_gate(nullptr), m_queue(nullptr), m_mutex(nullptr), m_gone(0), m_blocked(0), m_waiting(0)
    {
      m_gate = ::CreateSemaphoreA(nullptr, 1, 1, nullptr);
      m_queue = ::CreateSemaphoreA(nullptr, 0, 0x7FFFFFFF, nullptr);
      m_mutex = ::CreateMutexA(nullptr, FALSE, nullptr);

      if (m_gate != nullptr && m_queue != nullptr && m_mutex != nullptr) {
        return;
      }

      if (m_gate != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(m_gate));
        m_gate = nullptr;
      }
      if (m_queue != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(m_queue));
        m_queue = nullptr;
      }
      if (m_mutex != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(m_mutex));
        m_mutex = nullptr;
      }

      throw boost::thread_resource_error();
    }
#endif
  } // namespace detail

#if defined(BOOST_HAS_WINTHREADS)
  /**
   * Address: 0x00AC2760 (FUN_00AC2760, boost::thread::~thread)
   *
   * What it does:
   * Closes one native thread handle when this thread lane is still marked
   * joinable.
   */
  thread::~thread()
  {
    if (m_joinable) {
      ::CloseHandle(static_cast<HANDLE>(m_thread));
    }
  }
#endif

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
    struct SpCountedBaseRuntimeView
    {
      void* vftable;
      volatile LONG useCount;
      volatile LONG weakCount;
    };

    static_assert(sizeof(SpCountedBaseRuntimeView) == 0x0C, "SpCountedBaseRuntimeView size must be 0x0C");

    struct SharedCountWithTailLaneView
    {
      detail::sp_counted_base* control;
      detail::shared_count tailSharedCount;
    };
    static_assert(
      offsetof(SharedCountWithTailLaneView, tailSharedCount) == 0x04,
      "SharedCountWithTailLaneView::tailSharedCount offset must be 0x04"
    );

    struct WeakCountWithTailLaneView
    {
      detail::sp_counted_base* control;
      detail::weak_count tailWeakCount;
    };
    static_assert(
      offsetof(WeakCountWithTailLaneView, tailWeakCount) == 0x04,
      "WeakCountWithTailLaneView::tailWeakCount offset must be 0x04"
    );

    [[nodiscard]] inline SpCountedBaseRuntimeView* AsRuntimeView(detail::sp_counted_base* const control) noexcept
    {
      return reinterpret_cast<SpCountedBaseRuntimeView*>(control);
    }

    template <typename OutPairT, typename SourcePairT>
    SharedCountPair* AssignWeakPairFromSharedCore(OutPairT* const outPair, const SourcePairT* const sourcePair) noexcept
    {
      outPair->px = sourcePair->px;

      detail::sp_counted_base* const sourceControl = sourcePair->pi;
      if (sourceControl != outPair->pi) {
        if (sourceControl != nullptr) {
          sourceControl->weak_add_ref();
        }
        if (outPair->pi != nullptr) {
          outPair->pi->weak_release();
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

  template <typename PayloadT>
  struct SpCountedImplPointerCtorRuntimeView
  {
    void* vtable = nullptr;      // +0x00
    volatile LONG useCount = 0;  // +0x04
    volatile LONG weakCount = 0; // +0x08
    PayloadT* payload = nullptr; // +0x0C
  };

  static_assert(
    sizeof(SpCountedImplPointerCtorRuntimeView<moho::IRenTerrain>) == 0x10,
    "SpCountedImplPointerCtorRuntimeView<moho::IRenTerrain> size must be 0x10"
  );
  static_assert(
    sizeof(SpCountedImplPointerCtorRuntimeView<moho::CD3DTextureBatcher>) == 0x10,
    "SpCountedImplPointerCtorRuntimeView<moho::CD3DTextureBatcher> size must be 0x10"
  );

  template <typename PayloadT>
  struct SharedControlPayloadRuntimeView
  {
    void* vtable = nullptr;      // +0x00
    volatile LONG useCount = 0;  // +0x04
    volatile LONG weakCount = 0; // +0x08
    PayloadT* payload = nullptr; // +0x0C
  };

  static_assert(
    offsetof(SharedControlPayloadRuntimeView<void>, payload) == 0x0C,
    "SharedControlPayloadRuntimeView::payload offset must be 0x0C"
  );
  static_assert(
    sizeof(SharedControlPayloadRuntimeView<void>) == 0x10,
    "SharedControlPayloadRuntimeView size must be 0x10"
  );

  template <typename PayloadT>
  [[nodiscard]] inline PayloadT* ReadSharedControlPayloadLane(
    detail::sp_counted_base* const control
  ) noexcept
  {
    auto* const runtimeView = reinterpret_cast<SharedControlPayloadRuntimeView<PayloadT>*>(control);
    return runtimeView->payload;
  }

  /**
   * Address: 0x007FBEA0 (FUN_007FBEA0)
   *
   * What it does:
   * Rebinds one control-block runtime lane to the base
   * `boost::detail::sp_counted_base` vtable tag.
   */
  [[maybe_unused]] SpCountedBaseRuntimeView* RebindSpCountedBaseVtableLaneA(
    SpCountedBaseRuntimeView* const runtimeView
  ) noexcept
  {
    static std::uint8_t sSpCountedBaseVtableTag = 0;
    if (runtimeView != nullptr) {
      runtimeView->vftable = &sSpCountedBaseVtableTag;
    }
    return runtimeView;
  }

  /**
   * Address: 0x007FBE40 (FUN_007FBE40)
   *
   * What it does:
   * Initializes one `sp_counted_impl_p<IRenTerrain>` runtime lane by setting
   * use/weak counts to `1`, rebinding control vtable state, and storing payload
   * ownership pointer.
   */
  [[maybe_unused]] SpCountedImplPointerCtorRuntimeView<moho::IRenTerrain>* InitializeSpCountedImplPIRenTerrainLaneA(
    SpCountedImplPointerCtorRuntimeView<moho::IRenTerrain>* const runtimeView,
    moho::IRenTerrain* const payload
  ) noexcept
  {
    static std::uint8_t sSpCountedImplIRenTerrainVtableTag = 0;
    if (runtimeView != nullptr) {
      runtimeView->useCount = 1;
      runtimeView->weakCount = 1;
      runtimeView->vtable = &sSpCountedImplIRenTerrainVtableTag;
      runtimeView->payload = payload;
    }
    return runtimeView;
  }

  /**
   * Address: 0x007FC150 (FUN_007FC150)
   *
   * What it does:
   * Initializes one `sp_counted_impl_p<CD3DTextureBatcher>` runtime lane by
   * setting use/weak counts to `1`, rebinding control vtable state, and storing
   * payload ownership pointer.
   */
  [[maybe_unused]] SpCountedImplPointerCtorRuntimeView<moho::CD3DTextureBatcher>*
  InitializeSpCountedImplPCD3DTextureBatcherLaneA(
    SpCountedImplPointerCtorRuntimeView<moho::CD3DTextureBatcher>* const runtimeView,
    moho::CD3DTextureBatcher* const payload
  ) noexcept
  {
    static std::uint8_t sSpCountedImplCD3DTextureBatcherVtableTag = 0;
    if (runtimeView != nullptr) {
      runtimeView->useCount = 1;
      runtimeView->weakCount = 1;
      runtimeView->vtable = &sSpCountedImplCD3DTextureBatcherVtableTag;
      runtimeView->payload = payload;
    }
    return runtimeView;
  }

  /**
   * Address: 0x0043D940 (FUN_0043D940)
   * Address: 0x0043EED0 (FUN_0043EED0)
   * Address: 0x0043F2E0 (FUN_0043F2E0)
   * Address: 0x004438C0 (FUN_004438C0)
   *
   * What it does:
   * Copies one `(px,pi)` pair and rebinds control ownership by retaining the
   * incoming `pi` then weak-releasing the previous `pi`.
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
   * Executes the same weak-owner pair rebind as `AssignWeakPairFromShared`,
   * but receives arguments in `(source, destination)` order.
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
   * Writes one source shared/weak pair into an owner slot at `+0x20` and
   * rebinds weak control ownership with legacy weak-retain/weak-release rules.
   */
  [[maybe_unused]] void AssignWeakPairToOwnerOffset32(
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
   * What it does:
   * Copies one `(px,pi)` pair and rebinds ownership by shared-retaining the
   * incoming control lane and weak-releasing the previously bound lane.
   */
  SharedCountPair* AssignSharedPairRetainWithWeakRelease(
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
        outPair->pi->weak_release();
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
   * `AssignSharedPairRetainWithWeakRelease`.
   */
  [[maybe_unused]] SharedCountPair* AssignSharedPairRetainWithWeakReleaseSourceFirst(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainWithWeakRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x007485A0 (FUN_007485A0)
   *
   * What it does:
   * Source-first adapter lane for shared-pair assignment with retained
   * incoming shared-control ownership and weak-release of the replaced lane.
   */
  [[maybe_unused]] SharedCountPair* AssignSharedPairRetainWithWeakReleaseSourceFirstAdapterA(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainWithWeakRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x007485D0 (FUN_007485D0)
   *
   * What it does:
   * Secondary source-first adapter lane for
   * `AssignSharedPairRetainWithWeakRelease`.
   */
  [[maybe_unused]] SharedCountPair* AssignSharedPairRetainWithWeakReleaseSourceFirstAdapterB(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainWithWeakRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x00895880 (FUN_00895880)
   *
   * What it does:
   * Source-first adapter lane for shared-pair assignment with retained
   * incoming shared-control ownership and weak-release of the replaced lane.
   */
  [[maybe_unused]] SharedCountPair* AssignSharedPairRetainWithWeakReleaseSourceFirstAdapterC(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignSharedPairRetainWithWeakRelease(outPair, sourcePair);
  }

  /**
   * Address: 0x0055AA60 (FUN_0055AA60)
   *
   * What it does:
   * Rebinds one borrowed `boost::shared_ptr<RScmResource>` lane to another by
   * weak-retaining the incoming control block and weak-releasing the previous
   * one, while always copying the raw pointee lane.
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
        incomingControl->weak_add_ref();
      }
      if (outShared->pi != nullptr) {
        outShared->pi->weak_release();
      }
      outShared->pi = incomingControl;
    }

    return &outShared->px;
  }

  /**
   * Address: 0x0055FBD0 (FUN_0055FBD0, Moho::WeakPtr_RScmResource::WeakPtr_RScmResource)
   *
   * What it does:
   * Constructor/assign adapter lane for weak `RScmResource` pointer pairs that
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
  [[maybe_unused]] SharedCountPair* AssignSharedPairRetainSourceFirstIfOutputPresent(
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
  [[maybe_unused]] SharedCountPair* CopySharedPairAliasNoRetain(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return CopySharedPair(outPair, sourcePair);
  }

  /**
   * Address: 0x0054A830 (FUN_0054A830)
   *
   * What it does:
   * Reads one control payload pointer lane at `+0x0C` from the control block
   * stored in one shared-pair `pi` lane.
   */
  [[maybe_unused]] void* ReadSharedPairControlPayloadLane(
    const SharedCountPair* const sharedPair
  ) noexcept
  {
    return ReadSharedControlPayloadLane<void>(sharedPair->pi);
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
   * Address: 0x0053B470 (FUN_0053B470)
   * Address: 0x0056FC70 (FUN_0056FC70)
   * Address: 0x0056FC90 (FUN_0056FC90)
   * Address: 0x0056FEA0 (FUN_0056FEA0)
   * Address: 0x005703F0 (FUN_005703F0)
   *
   * What it does:
   * Clears one single dword lane and returns the caller-owned output slot.
   */
  [[nodiscard]] std::uint32_t* ZeroDwordLane(std::uint32_t* const outLane) noexcept
  {
    *outLane = 0u;
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
  [[maybe_unused]] RuntimeSharedCountTailRecord20* AssignRuntimeSharedCountTailRecord20(
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
  [[maybe_unused]] RuntimeSharedCountTripleBlock* AssignRuntimeSharedCountTripleBlock(
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
  [[maybe_unused]] int DeleteSpCountedImplTextureD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplRenderTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplCubeRenderTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplDepthStencilTargetD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplVertexFormatD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplVertexBufferD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplIndexBufferD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplEffectD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplPipelineStateD3D9IfPresent(detail::sp_counted_base* const control) noexcept
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
  [[maybe_unused]] int DeleteSpCountedImplEffectD3D10IfPresent(detail::sp_counted_base* const control) noexcept
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
   * Address: 0x007832B0 (FUN_007832B0)
   * Address: 0x00783DE0 (FUN_00783DE0)
   *
   * What it does:
   * Adapter lane for `ReleaseSharedCountRange` that receives
   * `(rangeEnd, rangeBegin)` and returns one-past the released tail.
   */
  [[maybe_unused]] SharedCountPair* ReleaseSharedCountRangeReverseArgs(
    SharedCountPair* const rangeEnd,
    SharedCountPair* const rangeBegin
  ) noexcept
  {
    return ReleaseSharedCountRange(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x00784040 (FUN_00784040)
   *
   * What it does:
   * Uninitialized-copies `count` shared-pair lanes from `sourceBegin` into
   * `destinationBegin` and returns one-past the constructed destination tail.
   */
  [[nodiscard]] SharedCountPair* UninitializedCopySharedPairCountRetain(
    const std::uint32_t count,
    SharedCountPair* const destinationBegin,
    const SharedCountPair* const sourceBegin
  ) noexcept
  {
    return UninitializedCopySharedPairRangeRetain(
      destinationBegin,
      sourceBegin,
      sourceBegin + static_cast<std::ptrdiff_t>(count)
    );
  }

  /**
   * Address: 0x00783220 (FUN_00783220)
   * Address: 0x00783D70 (FUN_00783D70)
   *
   * What it does:
   * Adapter lane for count-based uninitialized shared-pair copy used by vector
   * growth/copy paths.
   */
  [[maybe_unused]] SharedCountPair* UninitializedCopySharedPairCountRetainAlias(
    SharedCountPair* const destinationBegin,
    const std::uint32_t count,
    const SharedCountPair* const sourceBegin
  ) noexcept
  {
    return UninitializedCopySharedPairCountRetain(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x00783270 (FUN_00783270)
   *
   * What it does:
   * Releases one raw storage lane with global `operator delete`.
   */
  [[maybe_unused]] void DeleteSharedPairStorage(void* const storage) noexcept
  {
    ::operator delete(storage);
  }

  /**
   * Address: 0x004DE370 (FUN_004DE370)
   * Address: 0x00783FC0 (FUN_00783FC0)
   *
   * What it does:
   * Copy-assigns one shared-pair half-open range `[sourceBegin, sourceEnd)`
   * into already-constructed destination lanes, retaining incoming control
   * blocks and releasing previously bound controls per slot.
   */
  SharedCountPair* CopyAssignSharedPairRangeRetain(
    SharedCountPair* destination,
    const SharedCountPair* sourceBegin,
    const SharedCountPair* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      destination->px = sourceBegin->px;

      detail::sp_counted_base* const incomingControl = sourceBegin->pi;
      if (incomingControl != destination->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (destination->pi != nullptr) {
          destination->pi->release();
        }
        destination->pi = incomingControl;
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x004DE570 (FUN_004DE570)
   * Address: 0x007840E0 (FUN_007840E0)
   *
   * What it does:
   * Fill-assigns one shared-pair value over one already-constructed
   * destination range `[destinationBegin, destinationEnd)`, retaining incoming
   * controls and releasing previously bound controls per slot.
   */
  SharedCountPair* FillAssignSharedPairRangeRetain(
    SharedCountPair* destinationBegin,
    SharedCountPair* const destinationEnd,
    const SharedCountPair& value
  ) noexcept
  {
    SharedCountPair* cursor = destinationBegin;
    while (cursor != destinationEnd) {
      cursor->px = value.px;

      detail::sp_counted_base* const incomingControl = value.pi;
      if (incomingControl != cursor->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (cursor->pi != nullptr) {
          cursor->pi->release();
        }
        cursor->pi = incomingControl;
      }

      ++cursor;
    }

    return cursor;
  }

  /**
   * Address: 0x004DE830 (FUN_004DE830)
   * Address: 0x00784260 (FUN_00784260)
   *
   * What it does:
   * Copy-assigns one shared-pair range backward from `[sourceBegin, sourceEnd)`
   * into destination lanes ending at `destinationEnd`, preserving overlap-safe
   * copy-backward semantics while retaining/releasing control blocks.
   */
  SharedCountPair* CopyAssignSharedPairRangeBackwardRetain(
    SharedCountPair* destinationEnd,
    const SharedCountPair* const sourceBegin,
    const SharedCountPair* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;

      destinationEnd->px = sourceEnd->px;

      detail::sp_counted_base* const incomingControl = sourceEnd->pi;
      if (incomingControl != destinationEnd->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (destinationEnd->pi != nullptr) {
          destinationEnd->pi->release();
        }
        destinationEnd->pi = incomingControl;
      }
    }

    return destinationEnd;
  }

  /**
   * Address: 0x00783E40 (FUN_00783E40)
   *
   * What it does:
   * Adapter lane that forwards backward shared-pair range copy-assign into the
   * canonical `CopyAssignSharedPairRangeBackwardRetain` helper.
   */
  [[maybe_unused]] [[nodiscard]] SharedCountPair* CopyAssignSharedPairRangeBackwardRetainAdapterA(
    const SharedCountPair* const sourceBegin,
    const SharedCountPair* const sourceEnd,
    SharedCountPair* const destinationEnd
  ) noexcept
  {
    return CopyAssignSharedPairRangeBackwardRetain(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00857230 (FUN_00857230)
   *
   * What it does:
   * Three-argument adapter lane that forwards one backward shared-pair range
   * assignment into `CopyAssignSharedPairRangeBackwardRetain`.
   */
  [[maybe_unused]] [[nodiscard]] SharedCountPair* CopyAssignSharedPairRangeBackwardRetainAdapterB(
    SharedCountPair* const destinationEnd,
    const SharedCountPair* const sourceBegin,
    const SharedCountPair* const sourceEnd
  ) noexcept
  {
    return CopyAssignSharedPairRangeBackwardRetain(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004DEA20 (FUN_004DEA20)
   * Address: 0x007840C0 (FUN_007840C0)
   * Address: 0x00784240 (FUN_00784240)
   * Address: 0x00784620 (FUN_00784620)
   * Address: 0x00784700 (FUN_00784700)
   * Address: 0x007846C0 (FUN_007846C0)
   * Address: 0x00784800 (FUN_00784800)
   *
   * What it does:
   * Uninitialized-copies one shared-pair range `[sourceBegin, sourceEnd)` into
   * destination lanes starting at `destinationBegin`, retaining the copied
   * control blocks and returning one-past the final destination slot.
   */
  SharedCountPair* UninitializedCopySharedPairRangeRetain(
    SharedCountPair* destinationBegin,
    const SharedCountPair* sourceBegin,
    const SharedCountPair* const sourceEnd
  ) noexcept
  {
    SharedCountPair* destination = destinationBegin;
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        destination->px = sourceBegin->px;
        destination->pi = sourceBegin->pi;
        if (destination->pi != nullptr) {
          destination->pi->add_ref_copy();
        }
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x004DE240 (FUN_004DE240)
   *
   * What it does:
   * Stores one 32-bit source lane into destination and returns destination.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordValueAdapterA(
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
  [[maybe_unused]] std::uint32_t* StoreDwordValueAdapterB(
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
  [[maybe_unused]] std::uint32_t* StoreDwordValueAdapterC(
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
  [[maybe_unused]] std::uint32_t* StoreDwordValueAdapterD(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    *destination = value;
    return destination;
  }

  /**
   * Address: 0x004DE550 (FUN_004DE550)
   *
   * What it does:
   * Adapter lane that forwards into `UninitializedCopySharedPairRangeRetain`
   * with an explicitly empty source range.
   */
  [[maybe_unused]] SharedCountPair* UninitializedCopySharedPairEmptySourceAdapterA(
    const SharedCountPair* const /*unusedSourceOwner*/,
    SharedCountPair* const destinationBegin
  ) noexcept
  {
    return UninitializedCopySharedPairRangeRetain(destinationBegin, nullptr, nullptr);
  }

  /**
   * Address: 0x004DE810 (FUN_004DE810)
   *
   * What it does:
   * Sibling adapter lane that forwards the same empty-source copy request into
   * `UninitializedCopySharedPairRangeRetain`.
   */
  [[maybe_unused]] SharedCountPair* UninitializedCopySharedPairEmptySourceAdapterB(
    const SharedCountPair* const /*unusedSourceOwner*/,
    SharedCountPair* const destinationBegin
  ) noexcept
  {
    return UninitializedCopySharedPairRangeRetain(destinationBegin, nullptr, nullptr);
  }

  /**
   * Address: 0x004DE9D0 (FUN_004DE9D0)
   *
   * What it does:
   * Third empty-source adapter lane for `UninitializedCopySharedPairRangeRetain`.
   */
  [[maybe_unused]] SharedCountPair* UninitializedCopySharedPairEmptySourceAdapterC(
    const SharedCountPair* const /*unusedSourceOwner*/,
    SharedCountPair* const destinationBegin
  ) noexcept
  {
    return UninitializedCopySharedPairRangeRetain(destinationBegin, nullptr, nullptr);
  }

  /**
   * Address: 0x004DE710 (FUN_004DE710)
   *
   * What it does:
   * Copies one 32-bit lane from source into destination and returns destination.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordFromSourcePointerAdapterA(
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
  [[maybe_unused]] std::uint32_t* CopyDwordFromSourcePointerAdapterB(
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
  [[maybe_unused]] std::uint32_t LoadFirstDwordViaDoublePointerAdapterA(
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
  [[maybe_unused]] std::uint32_t LoadFirstDwordViaDoublePointerAdapterB(
    const std::uint32_t* const* const source
  ) noexcept
  {
    return **source;
  }

  struct ByteFlagOffset4RuntimeView
  {
    std::uint8_t pad_00_04[0x04];
    std::uint8_t flagAtOffset4;
  };
  static_assert(
    offsetof(ByteFlagOffset4RuntimeView, flagAtOffset4) == 0x04,
    "ByteFlagOffset4RuntimeView::flagAtOffset4 offset must be 0x04"
  );

  /**
   * Address: 0x004DEA90 (FUN_004DEA90)
   *
   * What it does:
   * Reads and returns one byte-flag lane at object offset `+0x04`.
   */
  [[maybe_unused]] std::uint8_t LoadByteFlagAtOffset4(
    const ByteFlagOffset4RuntimeView* const objectView
  ) noexcept
  {
    return objectView->flagAtOffset4;
  }

  /**
   * Address: 0x0075FF10 (FUN_0075FF10)
   * Address: 0x00760310 (FUN_00760310)
   * Address: 0x007568D0 (FUN_007568D0)
   *
   * What it does:
   * Uninitialized-copies one 12-byte `(lane0,lane1,pi)` range
   * `[sourceBegin, sourceEnd)` into destination lanes and retains each copied
   * shared control lane.
   */
  SharedControlTriplet* UninitializedCopySharedControlTripletRangeRetain(
    SharedControlTriplet* destinationBegin,
    const SharedControlTriplet* sourceBegin,
    const SharedControlTriplet* const sourceEnd
  ) noexcept
  {
    SharedControlTriplet* destination = destinationBegin;
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        destination->lane0 = sourceBegin->lane0;
        destination->lane1 = sourceBegin->lane1;
        destination->pi = sourceBegin->pi;
        if (destination->pi != nullptr) {
          destination->pi->add_ref_copy();
        }
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x00755CE0 (FUN_00755CE0)
   *
   * What it does:
   * Source-first forwarding adapter lane that routes one 12-byte shared-control
   * triplet uninitialized-copy range into `FUN_007568D0` while discarding one
   * zero scratch lane.
   */
  [[maybe_unused]] SharedControlTriplet* UninitializedCopySharedControlTripletRangeRetainNullScratchAdapterA(
    const SharedControlTriplet* sourceBegin,
    const SharedControlTriplet* sourceEnd,
    SharedControlTriplet* destinationBegin
  ) noexcept
  {
    return UninitializedCopySharedControlTripletRangeRetain(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0075FC70 (FUN_0075FC70)
   *
   * What it does:
   * Source-first forwarding adapter lane that routes one 12-byte shared-control
   * triplet uninitialized-copy range into `FUN_007568D0` for append/grow
   * vector lanes.
   */
  [[maybe_unused]] SharedControlTriplet* UninitializedCopySharedControlTripletRangeRetainNullScratchAdapterB(
    const SharedControlTriplet* sourceBegin,
    const SharedControlTriplet* sourceEnd,
    SharedControlTriplet* destinationBegin
  ) noexcept
  {
    return UninitializedCopySharedControlTripletRangeRetain(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00755C50 (FUN_00755C50)
   *
   * What it does:
   * Copy-assigns one 12-byte `(lane0,lane1,pi)` range into initialized
   * destination slots, retaining incoming controls and releasing previously
   * bound controls per slot when they differ.
   */
  SharedControlTriplet* CopyAssignSharedControlTripletRangeRetain(
    SharedControlTriplet* destination,
    const SharedControlTriplet* sourceBegin,
    const SharedControlTriplet* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      destination->lane0 = sourceBegin->lane0;
      destination->lane1 = sourceBegin->lane1;

      detail::sp_counted_base* const incomingControl = sourceBegin->pi;
      if (incomingControl != destination->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (destination->pi != nullptr) {
          destination->pi->release();
        }
        destination->pi = incomingControl;
      }

      ++sourceBegin;
      ++destination;
    }

    return destination;
  }

  /**
   * Address: 0x0075FCA0 (FUN_0075FCA0)
   * Address: 0x0075FF30 (FUN_0075FF30)
   *
   * What it does:
   * Fill-assigns one `(lane0,lane1,pi)` value into initialized destination
   * slots, retaining incoming controls and releasing previously bound controls
   * when they differ.
   */
  SharedControlTriplet* FillAssignSharedControlTripletRangeRetain(
    SharedControlTriplet* destinationBegin,
    SharedControlTriplet* const destinationEnd,
    const SharedControlTriplet& value
  ) noexcept
  {
    SharedControlTriplet* cursor = destinationBegin;
    while (cursor != destinationEnd) {
      cursor->lane0 = value.lane0;
      cursor->lane1 = value.lane1;

      detail::sp_counted_base* const incomingControl = value.pi;
      if (incomingControl != cursor->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (cursor->pi != nullptr) {
          cursor->pi->release();
        }
        cursor->pi = incomingControl;
      }

      ++cursor;
    }

    return cursor;
  }

  /**
   * Address: 0x0075FFC0 (FUN_0075FFC0)
   * Address: 0x00760330 (FUN_00760330)
   *
   * What it does:
   * Copy-assigns one 12-byte `(lane0,lane1,pi)` range backward from
   * `[sourceBegin, sourceEnd)` into destination slots ending at
   * `destinationEnd`, retaining incoming controls and releasing previously
   * bound controls per slot when they differ.
   */
  SharedControlTriplet* CopyAssignSharedControlTripletRangeBackwardRetain(
    SharedControlTriplet* destinationEnd,
    const SharedControlTriplet* const sourceBegin,
    const SharedControlTriplet* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;

      destinationEnd->lane0 = sourceEnd->lane0;
      destinationEnd->lane1 = sourceEnd->lane1;

      detail::sp_counted_base* const incomingControl = sourceEnd->pi;
      if (incomingControl != destinationEnd->pi) {
        if (incomingControl != nullptr) {
          incomingControl->add_ref_copy();
        }
        if (destinationEnd->pi != nullptr) {
          destinationEnd->pi->release();
        }
        destinationEnd->pi = incomingControl;
      }
    }

    return destinationEnd;
  }

  /**
   * Address: 0x004DDDC0 (FUN_004DDDC0)
   * Address: 0x00783D40 (FUN_00783D40)
   *
   * What it does:
   * Alias lane of `CopyAssignSharedPairRangeRetain`.
   */
  SharedCountPair* CopyAssignSharedPairRangeRetainAlias(
    SharedCountPair* destination,
    const SharedCountPair* sourceBegin,
    const SharedCountPair* const sourceEnd
  ) noexcept
  {
    return CopyAssignSharedPairRangeRetain(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004DDF70 (FUN_004DDF70)
   *
   * What it does:
   * Wrapper lane of `UninitializedCopySharedPairRangeRetain` used by vector
   * insertion paths to shift one shared-pair tail into uninitialized storage.
   */
  SharedCountPair* UninitializedCopySharedPairRangeRetainAlias(
    SharedCountPair* destinationBegin,
    const SharedCountPair* sourceBegin,
    const SharedCountPair* const sourceEnd
  ) noexcept
  {
    return UninitializedCopySharedPairRangeRetain(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004DDFA0 (FUN_004DDFA0)
   * Address: 0x00783E30 (FUN_00783E30)
   *
   * What it does:
   * Alias lane of `FillAssignSharedPairRangeRetain`.
   */
  SharedCountPair* FillAssignSharedPairRangeRetainAlias(
    SharedCountPair* destinationBegin,
    SharedCountPair* const destinationEnd,
    const SharedCountPair& value
  ) noexcept
  {
    return FillAssignSharedPairRangeRetain(destinationBegin, destinationEnd, value);
  }

  /**
   * Address: 0x004DDFB0 (FUN_004DDFB0)
   * Address: 0x00784160 (FUN_00784160)
   *
   * What it does:
   * Alias lane of `CopyAssignSharedPairRangeBackwardRetain`.
   */
  SharedCountPair* CopyAssignSharedPairRangeBackwardRetainAlias(
    SharedCountPair* destinationEnd,
    const SharedCountPair* const sourceBegin,
    const SharedCountPair* sourceEnd
  ) noexcept
  {
    return CopyAssignSharedPairRangeBackwardRetain(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004DE5F0 (FUN_004DE5F0)
   *
   * What it does:
   * Forwards one backward shared-pair copy lane into
   * `CopyAssignSharedPairRangeBackwardRetain` with one trailing caller lane
   * kept as an ABI-preserved but behavior-unused parameter.
   */
  [[maybe_unused]] SharedCountPair* CopyAssignSharedPairRangeBackwardRetainAliasWithUnusedTail(
    const SharedCountPair* const sourceBegin,
    const SharedCountPair* const sourceEnd,
    SharedCountPair* const destinationEnd,
    const SharedCountPair* const /*unusedTailLane*/
  ) noexcept
  {
    return CopyAssignSharedPairRangeBackwardRetain(destinationEnd, sourceBegin, sourceEnd);
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
   * Atomically increments one weak-count lane and returns the previous value.
   */
  std::int32_t SpCountedBaseWeakAddRef(detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return 0;
    }

    SpCountedBaseRuntimeView* const runtime = AsRuntimeView(control);
    return static_cast<std::int32_t>(InterlockedExchangeAdd(&runtime->weakCount, 1));
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
      throw boost::bad_weak_ptr();
    }

    detail::sp_counted_base* const sourceControl =
      sourceSharedControlSlot != nullptr ? *sourceSharedControlSlot : nullptr;
    *outWeakControlSlot = sourceControl;

    if (sourceControl == nullptr || !SpCountedBaseAddRefLock(sourceControl)) {
      throw boost::bad_weak_ptr();
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
  [[maybe_unused]] SharedCountPair* ConstructWeakPairFromSharedPair(
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
   * Address: 0x00796EE0 (FUN_00796EE0)
   *
   * What it does:
   * Constructs one `boost::detail::weak_count` tail lane from one source
   * `boost::detail::shared_count` tail lane, then copies the leading
   * control-pointer lane.
   */
  [[maybe_unused]] WeakCountWithTailLaneView* ConstructWeakCountFromSharedTailLane(
    WeakCountWithTailLaneView* const outWeakCount,
    const SharedCountWithTailLaneView* const sourceSharedCount
  )
  {
    ::new (static_cast<void*>(&outWeakCount->tailWeakCount))
      detail::weak_count(sourceSharedCount->tailSharedCount);
    outWeakCount->control = sourceSharedCount->control;
    return outWeakCount;
  }

  /**
   * Address: 0x008F3930 (FUN_008F3930)
   *
   * What it does:
   * Forwarding lane that builds one weak-count tail from one shared-count tail
   * and copies the leading control-pointer lane.
   */
  [[maybe_unused]] WeakCountWithTailLaneView* ConstructWeakCountFromSharedTailLaneAdapterA(
    WeakCountWithTailLaneView* const outWeakCount,
    const SharedCountWithTailLaneView* const sourceSharedCount
  )
  {
    return ConstructWeakCountFromSharedTailLane(outWeakCount, sourceSharedCount);
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
  [[maybe_unused]] void EnsurePtrContainerPushBackInputNotNull(
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
  [[maybe_unused]] void EnsurePtrContainerPushBackInputNotNullSecondary(
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

    struct VirtualDeleteTargetRuntimeView
    {
      void** vtable;
    };

    using VirtualDeleteOneCall = std::intptr_t(__thiscall*)(void* self, std::int32_t deleteFlag);

    template <class TPointee>
    void DisposeSpCountedImplPointeeViaVirtualDeleteSlot(
      boost::SpCountedImplStorage<TPointee>* const countedImpl,
      const std::size_t vtableSlot
    ) noexcept
    {
      if (countedImpl == nullptr || countedImpl->px == nullptr) {
        return;
      }

      auto* const runtime = reinterpret_cast<VirtualDeleteTargetRuntimeView*>(countedImpl->px);
      const auto destroy = reinterpret_cast<VirtualDeleteOneCall>(runtime->vtable[vtableSlot]);
      (void)destroy(static_cast<void*>(countedImpl->px), 1);
      countedImpl->px = nullptr;
    }

    template <class TPointee>
    void DisposeSpCountedImplPointeeViaVirtualDelete(
      boost::SpCountedImplStorage<TPointee>* const countedImpl
    ) noexcept
    {
      DisposeSpCountedImplPointeeViaVirtualDeleteSlot(countedImpl, 0u);
    }

    struct PathPreviewFinderDisposeRuntimeView
    {
      void* vftable;
      PathPreviewFinderDisposeRuntimeView* next;
      PathPreviewFinderDisposeRuntimeView* prev;
    };
    static_assert(
      offsetof(PathPreviewFinderDisposeRuntimeView, next) == 0x04,
      "PathPreviewFinderDisposeRuntimeView::next offset must be 0x04"
    );
    static_assert(
      offsetof(PathPreviewFinderDisposeRuntimeView, prev) == 0x08,
      "PathPreviewFinderDisposeRuntimeView::prev offset must be 0x08"
    );
    static_assert(sizeof(PathPreviewFinderDisposeRuntimeView) == 0x0C, "PathPreviewFinderDisposeRuntimeView size must be 0x0C");

    /**
     * Address: 0x007657D0 (FUN_007657D0)
     *
     * What it does:
     * Unlinks one `PathPreviewFinder` intrusive queue node from its neighbors,
     * rewires it to self-linked sentinel links, and releases its allocation.
     */
    [[maybe_unused]] PathPreviewFinderDisposeRuntimeView* DestroyPathPreviewFinderRuntime(
      PathPreviewFinderDisposeRuntimeView* const finder
    ) noexcept
    {
      if (finder == nullptr) {
        return nullptr;
      }

      finder->prev->next = finder->next;
      finder->next->prev = finder->prev;
      finder->next = finder;
      finder->prev = finder;

      ::operator delete(static_cast<void*>(finder));
      return finder;
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

    template <class TPointee>
    struct SpCountedImplPdMeshCacheRuntimeView
    {
      void* vftable;
      std::int32_t useCount;
      std::int32_t weakCount;
      TPointee* px;
      std::uint32_t deleterWord0;
      std::uint32_t deleterWord1;
    };

    static_assert(
      offsetof(SpCountedImplPdMeshCacheRuntimeView<void>, deleterWord0) == 0x10,
      "SpCountedImplPdMeshCacheRuntimeView::deleterWord0 offset must be 0x10"
    );
    static_assert(
      offsetof(SpCountedImplPdMeshCacheRuntimeView<void>, deleterWord1) == 0x14,
      "SpCountedImplPdMeshCacheRuntimeView::deleterWord1 offset must be 0x14"
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

    [[nodiscard]] bool IsMeshRefCountedCacheDeleterType(
      const boost::detail::sp_typeinfo& requestedType
    ) noexcept
    {
      constexpr const char* kMeshCacheDeleterRawName =
        ".?AUDeleter@?$RefCountedCache@VMeshKey@Moho@@VMesh@2@@Moho@@";

      if (SpTypeInfoMatchesRawName(requestedType, kMeshCacheDeleterRawName)) {
        return true;
      }

      const char* const name = requestedType.name();
      return name != nullptr &&
        std::strstr(name, "RefCountedCache") != nullptr &&
        std::strstr(name, "MeshKey") != nullptr &&
        std::strstr(name, "Mesh") != nullptr &&
        std::strstr(name, "Deleter") != nullptr;
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

    [[nodiscard]] void* RecoveredSpCountedBaseVtable() noexcept
    {
      static RecoveredSpCountedBaseVtableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }

    [[nodiscard]] void* RecoveredSpCountedImplPVtable() noexcept
    {
      static RecoveredSpCountedBaseVtableProbe probe;
      return *reinterpret_cast<void**>(&probe);
    }
  } // namespace

  /**
   * Address: 0x004DE730 (FUN_004DE730, boost::detail::sp_counted_impl_p<Moho::AudioEngine>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `AudioEngine`.
   */
  [[maybe_unused]] SpCountedImplStorage<moho::AudioEngine>* SpCountedImplPConstructAudioEngine(
    SpCountedImplStorage<moho::AudioEngine>* const countedImpl,
    moho::AudioEngine* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x004DE790 (FUN_004DE790, boost::detail::sp_counted_base::dtr)
   *
   * What it does:
   * Runs one scalar-deleting destructor lane for the base control block by
   * rebinding the base vtable and optionally deleting storage.
   */
  [[maybe_unused]] detail::sp_counted_base* SpCountedBaseDeletingDtorAudioEngine(
    detail::sp_counted_base* const control,
    const unsigned char deleteFlag
  ) noexcept
  {
    AsRuntimeView(control)->vftable = RecoveredSpCountedBaseVtable();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(control));
    }
    return control;
  }

  /**
   * Address: 0x0053A220 (FUN_0053A220, boost::detail::sp_counted_impl_p<Moho::RScmResource>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `RScmResource`.
   */
  SpCountedImplStorage<moho::RScmResource>* SpCountedImplPConstructRScmResource(
    SpCountedImplStorage<moho::RScmResource>* const countedImpl,
    moho::RScmResource* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00545340 (FUN_00545340, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `LaunchInfoNew`.
   */
  SpCountedImplStorage<moho::LaunchInfoNew>* SpCountedImplPConstructLaunchInfoNew(
    SpCountedImplStorage<moho::LaunchInfoNew>* const countedImpl,
    moho::LaunchInfoNew* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x005791B0 (FUN_005791B0, boost::detail::sp_counted_impl_p<Moho::CHeightField>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `CHeightField`.
   */
  SpCountedImplStorage<moho::CHeightField>* SpCountedImplPConstructCHeightField(
    SpCountedImplStorage<moho::CHeightField>* const countedImpl,
    moho::CHeightField* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x005CC7C0 (FUN_005CC7C0, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `Stats_StatItem`.
   */
  SpCountedImplStorage<moho::Stats_StatItem>* SpCountedImplPConstructStatsStatItem(
    SpCountedImplStorage<moho::Stats_StatItem>* const countedImpl,
    moho::Stats_StatItem* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x005CD540 (FUN_005CD540)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `CIntelGrid`.
   */
  SpCountedImplStorage<moho::CIntelGrid>* SpCountedImplPConstructCIntelGrid(
    SpCountedImplStorage<moho::CIntelGrid>* const countedImpl,
    moho::CIntelGrid* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0063E760 (FUN_0063E760)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `CAniPose`.
   */
  SpCountedImplStorage<moho::CAniPose>* SpCountedImplPConstructCAniPose(
    SpCountedImplStorage<moho::CAniPose>* const countedImpl,
    moho::CAniPose* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00714670 (FUN_00714670, boost::detail::sp_counted_impl_p<Moho::STrigger>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `STrigger`.
   */
  SpCountedImplStorage<moho::STrigger>* SpCountedImplPConstructSTrigger(
    SpCountedImplStorage<moho::STrigger>* const countedImpl,
    moho::STrigger* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00755FA0 (FUN_00755FA0, boost::detail::sp_counted_impl_p<Moho::ISimResources>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `ISimResources`.
   */
  SpCountedImplStorage<moho::ISimResources>* SpCountedImplPConstructISimResources(
    SpCountedImplStorage<moho::ISimResources>* const countedImpl,
    moho::ISimResources* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00755FE0 (FUN_00755FE0, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `CDebugCanvas`.
   */
  SpCountedImplStorage<moho::CDebugCanvas>* SpCountedImplPConstructCDebugCanvas(
    SpCountedImplStorage<moho::CDebugCanvas>* const countedImpl,
    moho::CDebugCanvas* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00756030 (FUN_00756030, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `SParticleBuffer`.
   */
  SpCountedImplStorage<moho::SParticleBuffer>* SpCountedImplPConstructSParticleBuffer(
    SpCountedImplStorage<moho::SParticleBuffer>* const countedImpl,
    moho::SParticleBuffer* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00765700 (FUN_00765700, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `PathPreviewFinder`.
   */
  SpCountedImplStorage<moho::PathPreviewFinder>* SpCountedImplPConstructPathPreviewFinder(
    SpCountedImplStorage<moho::PathPreviewFinder>* const countedImpl,
    moho::PathPreviewFinder* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007BDC20 (FUN_007BDC20, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `CGpgNetInterface`.
   */
  SpCountedImplStorage<moho::CGpgNetInterface>* SpCountedImplPConstructCGpgNetInterface(
    SpCountedImplStorage<moho::CGpgNetInterface>* const countedImpl,
    moho::CGpgNetInterface* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007E6550 (FUN_007E6550, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `MeshMaterial`.
   */
  SpCountedImplStorage<moho::MeshMaterial>* SpCountedImplPConstructMeshMaterial(
    SpCountedImplStorage<moho::MeshMaterial>* const countedImpl,
    moho::MeshMaterial* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007E6590 (FUN_007E6590, boost::detail::sp_counted_impl_p<Moho::Mesh>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `Mesh`.
   */
  SpCountedImplStorage<moho::Mesh>* SpCountedImplPConstructMesh(
    SpCountedImplStorage<moho::Mesh>* const countedImpl,
    moho::Mesh* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007E6920 (FUN_007E6920, boost::detail::sp_counted_impl_p<Moho::RMeshBlueprintLOD>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `RMeshBlueprintLOD`.
   */
  SpCountedImplStorage<moho::RMeshBlueprintLOD>* SpCountedImplPConstructRMeshBlueprintLOD(
    SpCountedImplStorage<moho::RMeshBlueprintLOD>* const countedImpl,
    moho::RMeshBlueprintLOD* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007E6970 (FUN_007E6970, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `MeshBatch`.
   */
  SpCountedImplStorage<moho::MeshBatch>* SpCountedImplPConstructMeshBatch(
    SpCountedImplStorage<moho::MeshBatch>* const countedImpl,
    moho::MeshBatch* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007E69B0 (FUN_007E69B0, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::sp_counted_impl_pd)
   *
   * What it does:
   * Initializes one recovered mesh-cache `sp_counted_impl_pd` control block
   * and stores one 8-byte deleter payload at `+0x10`.
   */
  SpCountedImplStorage<moho::Mesh>* SpCountedImplPdConstructMeshRefCountedCache(
    SpCountedImplStorage<moho::Mesh>* const countedImpl,
    moho::Mesh* const ownedPointee,
    const std::uint32_t deleterWord0,
    const std::uint32_t deleterWord1
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
    auto* const runtime = reinterpret_cast<SpCountedImplPdMeshCacheRuntimeView<moho::Mesh>*>(countedImpl);
    runtime->deleterWord0 = deleterWord0;
    runtime->deleterWord1 = deleterWord1;
    return countedImpl;
  }

  /**
   * Address: 0x008E8990 (FUN_008E8990, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `TextureD3D9`.
   */
  SpCountedImplStorage<gpg::gal::TextureD3D9>* SpCountedImplPConstructTextureD3D9(
    SpCountedImplStorage<gpg::gal::TextureD3D9>* const countedImpl,
    gpg::gal::TextureD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E89C0 (FUN_008E89C0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `RenderTargetD3D9`.
   */
  SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* SpCountedImplPConstructRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* const countedImpl,
    gpg::gal::RenderTargetD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E89F0 (FUN_008E89F0, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `CubeRenderTargetD3D9`.
   */
  SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* SpCountedImplPConstructCubeRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* const countedImpl,
    gpg::gal::CubeRenderTargetD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8A20 (FUN_008E8A20, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `DepthStencilTargetD3D9`.
   */
  SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* SpCountedImplPConstructDepthStencilTargetD3D9(
    SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* const countedImpl,
    gpg::gal::DepthStencilTargetD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8A50 (FUN_008E8A50, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `VertexFormatD3D9`.
   */
  SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* SpCountedImplPConstructVertexFormatD3D9(
    SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* const countedImpl,
    gpg::gal::VertexFormatD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8A80 (FUN_008E8A80, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `VertexBufferD3D9`.
   */
  SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* SpCountedImplPConstructVertexBufferD3D9(
    SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* const countedImpl,
    gpg::gal::VertexBufferD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8AB0 (FUN_008E8AB0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `IndexBufferD3D9`.
   */
  SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* SpCountedImplPConstructIndexBufferD3D9(
    SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* const countedImpl,
    gpg::gal::IndexBufferD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8AE0 (FUN_008E8AE0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `EffectD3D9`.
   */
  SpCountedImplStorage<gpg::gal::EffectD3D9>* SpCountedImplPConstructEffectD3D9(
    SpCountedImplStorage<gpg::gal::EffectD3D9>* const countedImpl,
    gpg::gal::EffectD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008E8D80 (FUN_008E8D80, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `PipelineStateD3D9`.
   */
  SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* SpCountedImplPConstructPipelineStateD3D9(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* const countedImpl,
    gpg::gal::PipelineStateD3D9* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F8FC0 (FUN_008F8FC0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `EffectD3D10`.
   */
  SpCountedImplStorage<gpg::gal::EffectD3D10>* SpCountedImplPConstructEffectD3D10(
    SpCountedImplStorage<gpg::gal::EffectD3D10>* const countedImpl,
    gpg::gal::EffectD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F8FF0 (FUN_008F8FF0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `TextureD3D10`.
   */
  SpCountedImplStorage<gpg::gal::TextureD3D10>* SpCountedImplPConstructTextureD3D10(
    SpCountedImplStorage<gpg::gal::TextureD3D10>* const countedImpl,
    gpg::gal::TextureD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F9020 (FUN_008F9020, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `RenderTargetD3D10`.
   */
  SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* SpCountedImplPConstructRenderTargetD3D10(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* const countedImpl,
    gpg::gal::RenderTargetD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00941660 (FUN_00941660, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `EffectTechniqueD3D9`.
   */
  SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* SpCountedImplPConstructEffectTechniqueD3D9(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* const countedImpl,
    gpg::gal::EffectTechniqueD3D9* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00941690 (FUN_00941690, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `EffectVariableD3D9`.
   */
  SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* SpCountedImplPConstructEffectVariableD3D9(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* const countedImpl,
    gpg::gal::EffectVariableD3D9* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0094B600 (FUN_0094B600, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `EffectTechniqueD3D10`.
   */
  SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* SpCountedImplPConstructEffectTechniqueD3D10(
    SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* const countedImpl,
    gpg::gal::EffectTechniqueD3D10* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0094B630 (FUN_0094B630, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `EffectVariableD3D10`.
   */
  SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* SpCountedImplPConstructEffectVariableD3D10(
    SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* const countedImpl,
    gpg::gal::EffectVariableD3D10* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0094E070 (FUN_0094E070, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::sp_counted_impl_pd)
   *
   * What it does:
   * Initializes one recovered byte-pointer `sp_counted_impl_pd` control block
   * with one owned `char*` lane and one raw-function deleter lane.
   */
  SpCountedImplPdCharPointerStorage* SpCountedImplPdConstructCharPointerFunctionDeleter(
    SpCountedImplPdCharPointerStorage* const countedImpl,
    char* const ownedPointee,
    const SharedByteDeleterFn deleter
  ) noexcept
  {
    auto* const baseStorage = reinterpret_cast<SpCountedImplStorage<char>*>(countedImpl);
    InitSpCountedImplStorage(baseStorage, RecoveredSpCountedImplPVtable(), ownedPointee);
    countedImpl->deleter = deleter;
    return countedImpl;
  }

  /**
   * Address: 0x008F9050 (FUN_008F9050, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `CubeRenderTargetD3D10`.
   */
  SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* SpCountedImplPConstructCubeRenderTargetD3D10(
    SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* const countedImpl,
    gpg::gal::CubeRenderTargetD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F9080 (FUN_008F9080, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `DepthStencilTargetD3D10`.
   */
  SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* SpCountedImplPConstructDepthStencilTargetD3D10(
    SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* const countedImpl,
    gpg::gal::DepthStencilTargetD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F90B0 (FUN_008F90B0, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `VertexFormatD3D10`.
   */
  SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* SpCountedImplPConstructVertexFormatD3D10(
    SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* const countedImpl,
    gpg::gal::VertexFormatD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F90E0 (FUN_008F90E0, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `VertexBufferD3D10`.
   */
  SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* SpCountedImplPConstructVertexBufferD3D10(
    SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* const countedImpl,
    gpg::gal::VertexBufferD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F9110 (FUN_008F9110, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `IndexBufferD3D10`.
   */
  SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* SpCountedImplPConstructIndexBufferD3D10(
    SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* const countedImpl,
    gpg::gal::IndexBufferD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008F9380 (FUN_008F9380, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `PipelineStateD3D10`.
   */
  SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* SpCountedImplPConstructPipelineStateD3D10(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* const countedImpl,
    gpg::gal::PipelineStateD3D10* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00923700 (FUN_00923700, boost::detail::sp_counted_impl_p<std::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for one owned
   * `std::basic_stringstream<char,...>` lane.
   */
  SpCountedImplStorage<void>* SpCountedImplPConstructStdStringstreamChar(
    SpCountedImplStorage<void>* const countedImpl,
    void* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00931EB0 (FUN_00931EB0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for one owned
   * `ClusterCache::Impl` lane.
   */
  SpCountedImplStorage<void>* SpCountedImplPConstructClusterCacheImpl(
    SpCountedImplStorage<void>* const countedImpl,
    void* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00797040 (FUN_00797040, boost::detail::sp_counted_impl_p<Moho::CMauiFrame>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `CMauiFrame`.
   */
  SpCountedImplStorage<moho::CMauiFrame>* SpCountedImplPConstructCMauiFrame(
    SpCountedImplStorage<moho::CMauiFrame>* const countedImpl,
    moho::CMauiFrame* const ownedPointee
  ) noexcept
  {
    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007FC1A0 (FUN_007FC1A0, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `CD3DPrimBatcher`.
   */
  SpCountedImplStorage<moho::CD3DPrimBatcher>* SpCountedImplPConstructCD3DPrimBatcher(
    SpCountedImplStorage<moho::CD3DPrimBatcher>* const countedImpl,
    moho::CD3DPrimBatcher* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x007FF6B0 (FUN_007FF6B0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `ID3DVertexSheet`.
   */
  SpCountedImplStorage<moho::ID3DVertexSheet>* SpCountedImplPConstructID3DVertexSheet(
    SpCountedImplStorage<moho::ID3DVertexSheet>* const countedImpl,
    moho::ID3DVertexSheet* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008142A0 (FUN_008142A0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `ShoreCell`.
   */
  SpCountedImplStorage<moho::ShoreCell>* SpCountedImplPConstructShoreCell(
    SpCountedImplStorage<moho::ShoreCell>* const countedImpl,
    moho::ShoreCell* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00832A00 (FUN_00832A00, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for `MeshInstance`.
   */
  SpCountedImplStorage<moho::MeshInstance>* SpCountedImplPConstructMeshInstance(
    SpCountedImplStorage<moho::MeshInstance>* const countedImpl,
    moho::MeshInstance* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x008847F0 (FUN_008847F0, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::sp_counted_impl_pd)
   *
   * What it does:
   * Initializes one recovered file-closer `sp_counted_impl_pd` control block
   * with one owned `FILE*` lane.
   */
  SpCountedImplStorage<void>* SpCountedImplPdConstructSFileStarCloser(
    SpCountedImplStorage<void>* const countedImpl,
    void* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x00884EF0 (FUN_00884EF0, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `LaunchInfoLoad`.
   */
  SpCountedImplStorage<moho::LaunchInfoLoad>* SpCountedImplPConstructLaunchInfoLoad(
    SpCountedImplStorage<moho::LaunchInfoLoad>* const countedImpl,
    moho::LaunchInfoLoad* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0089B840 (FUN_0089B840, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `SSessionSaveData`.
   */
  SpCountedImplStorage<moho::SSessionSaveData>* SpCountedImplPConstructSSessionSaveData(
    SpCountedImplStorage<moho::SSessionSaveData>* const countedImpl,
    moho::SSessionSaveData* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x0089BC70 (FUN_0089BC70, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::sp_counted_impl_p)
   *
   * What it does:
   * Initializes one recovered shared-count control block for
   * `UICommandGraph`.
   */
  SpCountedImplStorage<moho::UICommandGraph>* SpCountedImplPConstructUICommandGraph(
    SpCountedImplStorage<moho::UICommandGraph>* const countedImpl,
    moho::UICommandGraph* const ownedPointee
  ) noexcept
  {
    if (countedImpl == nullptr) {
      return nullptr;
    }

    return InitSpCountedImplStorage(countedImpl, RecoveredSpCountedImplPVtable(), ownedPointee);
  }

  /**
   * Address: 0x004DE7B0 (FUN_004DE7B0, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `AudioEngine` control-block init path.
   */
  [[maybe_unused]] detail::sp_counted_base* InitializeSpCountedBaseLaneForAudioEngine(
    detail::sp_counted_base* const control
  ) noexcept
  {
    AsRuntimeView(control)->vftable = RecoveredSpCountedBaseVtable();
    return control;
  }

  /**
   * Address: 0x005CC850 (FUN_005CC850)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `Stats_StatItem` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForStatsStatItem(
    detail::sp_counted_base* const control
  ) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    AsRuntimeView(control)->vftable = RecoveredSpCountedBaseVtable();
    return control;
  }

  /**
   * Address: 0x00884890 (FUN_00884890, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * file-closer `sp_counted_impl_pd` init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForFileStarCloser(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x00884F50 (FUN_00884F50, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `LaunchInfoLoad` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForLaunchInfoLoad(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x0089B930 (FUN_0089B930, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `SSessionSaveData` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForSSessionSaveData(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x0089BCE0 (FUN_0089BCE0, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `UICommandGraph` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForUICommandGraph(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x005CD5E0 (FUN_005CD5E0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CIntelGrid` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCIntelGrid(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x0063E7D0 (FUN_0063E7D0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CAniPose` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCAniPose(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x007146E0 (FUN_007146E0, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane for the trigger
   * shared-count constructor path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForSTrigger(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStatsStatItem(control);
  }

  /**
   * Address: 0x007560E0 (FUN_007560E0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `ISimResources` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForISimResources(
    detail::sp_counted_base* const control
  ) noexcept
  {
    AsRuntimeView(control)->vftable = RecoveredSpCountedBaseVtable();
    return control;
  }

  /**
   * Address: 0x007560F0 (FUN_007560F0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CDebugCanvas` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCDebugCanvas(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForISimResources(control);
  }

  /**
   * Address: 0x00756100 (FUN_00756100)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `SParticleBuffer` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForSParticleBuffer(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForISimResources(control);
  }

  /**
   * Address: 0x00765790 (FUN_00765790)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `PathPreviewFinder` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForPathPreviewFinder(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForISimResources(control);
  }

  /**
   * Address: 0x007970B0 (FUN_007970B0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CMauiFrame` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCMauiFrame(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForISimResources(control);
  }

  /**
   * Address: 0x0053A290 (FUN_0053A290)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `RScmResource` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForRScmResource(
    detail::sp_counted_base* const control
  ) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    AsRuntimeView(control)->vftable = RecoveredSpCountedBaseVtable();
    return control;
  }

  /**
   * Address: 0x0053B420 (FUN_0053B420)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `RScaResource` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForRScaResource(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x00545460 (FUN_00545460)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `LaunchInfoNew` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForLaunchInfoNew(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x0054EE20 (FUN_0054EE20)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CAniDefaultSkel` function-deleter control path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForAniDefaultSkelDeleter(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x00579210 (FUN_00579210)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CHeightField` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCHeightField(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007BDC80 (FUN_007BDC80)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CGpgNetInterface` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCGpgNetInterface(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007E6620 (FUN_007E6620)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `MeshMaterial` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshMaterial(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007E6630 (FUN_007E6630)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `Mesh` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForMesh(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007E6AA0 (FUN_007E6AA0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `RMeshBlueprintLOD` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForRMeshBlueprintLOD(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007E6AB0 (FUN_007E6AB0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `MeshBatch` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshBatch(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007E6AC0 (FUN_007E6AC0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * mesh-cache `sp_counted_impl_pd` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshRefCountedCache(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x008E8B10 (FUN_008E8B10, boost::detail::sp_counted_base::sp_counted_base)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `TextureD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForTextureD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x008E8B20 (FUN_008E8B20)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `RenderTargetD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForRenderTargetD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B30 (FUN_008E8B30)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CubeRenderTargetD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCubeRenderTargetD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B40 (FUN_008E8B40)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `DepthStencilTargetD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForDepthStencilTargetD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B50 (FUN_008E8B50)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `VertexFormatD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexFormatD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B60 (FUN_008E8B60)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `VertexBufferD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexBufferD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B70 (FUN_008E8B70)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `IndexBufferD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForIndexBufferD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8B80 (FUN_008E8B80)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008E8DB0 (FUN_008E8DB0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `PipelineStateD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForPipelineStateD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008F9140 (FUN_008F9140)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x008F9150 (FUN_008F9150)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `TextureD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForTextureD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForEffectD3D10(control);
  }

  /**
   * Address: 0x008F9160 (FUN_008F9160)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `RenderTargetD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForRenderTargetD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D10(control);
  }

  /**
   * Address: 0x008F9170 (FUN_008F9170)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CubeRenderTargetD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCubeRenderTargetD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRenderTargetD3D10(control);
  }

  /**
   * Address: 0x008F9180 (FUN_008F9180)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `DepthStencilTargetD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForDepthStencilTargetD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForCubeRenderTargetD3D10(control);
  }

  /**
   * Address: 0x008F9190 (FUN_008F9190)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `VertexFormatD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexFormatD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForDepthStencilTargetD3D10(control);
  }

  /**
   * Address: 0x008F91A0 (FUN_008F91A0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `VertexBufferD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexBufferD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForVertexFormatD3D10(control);
  }

  /**
   * Address: 0x008F91B0 (FUN_008F91B0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `IndexBufferD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForIndexBufferD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForVertexBufferD3D10(control);
  }

  /**
   * Address: 0x008F93B0 (FUN_008F93B0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `PipelineStateD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForPipelineStateD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForIndexBufferD3D10(control);
  }

  /**
   * Address: 0x00923730 (FUN_00923730)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `std::basic_stringstream<char,...>` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForStdStringstreamChar(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForPipelineStateD3D10(control);
  }

  /**
   * Address: 0x00931EE0 (FUN_00931EE0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `ClusterCache::Impl` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForClusterCacheImpl(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForStdStringstreamChar(control);
  }

  /**
   * Address: 0x009416C0 (FUN_009416C0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectTechniqueD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectTechniqueD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x009416D0 (FUN_009416D0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectVariableD3D9` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectVariableD3D9(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForEffectTechniqueD3D9(control);
  }

  /**
   * Address: 0x0094B660 (FUN_0094B660)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectTechniqueD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectTechniqueD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x0094B670 (FUN_0094B670)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `EffectVariableD3D10` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectVariableD3D10(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForEffectTechniqueD3D10(control);
  }

  /**
   * Address: 0x0094E0E0 (FUN_0094E0E0)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `char*` function-deleter control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCharPointerFunctionDeleter(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForTextureD3D9(control);
  }

  /**
   * Address: 0x007FC230 (FUN_007FC230)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CD3DTextureBatcher` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCD3DTextureBatcher(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007FC240 (FUN_007FC240)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `CD3DPrimBatcher` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForCD3DPrimBatcher(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x007FF710 (FUN_007FF710)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `ID3DVertexSheet` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForID3DVertexSheet(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x00814300 (FUN_00814300)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `ShoreCell` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForShoreCell(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x00832A60 (FUN_00832A60)
   *
   * What it does:
   * Restores one abstract `sp_counted_base` vtable lane used by the
   * `MeshInstance` control-block init path.
   */
  detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshInstance(
    detail::sp_counted_base* const control
  ) noexcept
  {
    return InitializeSpCountedBaseLaneForRScmResource(control);
  }

  /**
   * Address: 0x0053A240 (FUN_0053A240, boost::detail::sp_counted_impl_p<Moho::RScmResource>::dispose)
   *
   * What it does:
   * Deletes one owned `RScmResource` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeRScmResource(
    SpCountedImplStorage<moho::RScmResource>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
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
   * Address: 0x00545360 (FUN_00545360, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::dispose)
   *
   * What it does:
   * Deletes one owned `LaunchInfoNew` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeLaunchInfoNew(
    SpCountedImplStorage<moho::LaunchInfoNew>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
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
   * Address: 0x005CD560 (FUN_005CD560, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::dispose)
   *
   * What it does:
   * Deletes one owned `CIntelGrid` pointee bound to this shared-count control
   * lane when present.
   */
  void SpCountedImplPDisposeCIntelGrid(
    SpCountedImplStorage<moho::CIntelGrid>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x0063E780 (FUN_0063E780, boost::detail::sp_counted_impl_p<Moho::CAniPose>::dispose)
   *
   * What it does:
   * Deletes one owned `CAniPose` pointee bound to this shared-count control
   * lane when present.
   */
  void SpCountedImplPDisposeCAniPose(
    SpCountedImplStorage<moho::CAniPose>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x00714690 (FUN_00714690, boost::detail::sp_counted_impl_p<Moho::STrigger>::dispose)
   *
   * What it does:
   * Deletes one owned `STrigger` pointee bound to this shared-count control
   * lane when present.
   */
  void SpCountedImplPDisposeSTrigger(
    SpCountedImplStorage<moho::STrigger>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x00756000 (FUN_00756000, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::dispose)
   *
   * What it does:
   * Deletes one owned `CDebugCanvas` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeCDebugCanvas(
    SpCountedImplStorage<moho::CDebugCanvas>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x00756050 (FUN_00756050, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::dispose)
   *
   * What it does:
   * Deletes one owned `SParticleBuffer` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposeSParticleBuffer(
    SpCountedImplStorage<moho::SParticleBuffer>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x007BDC40 (FUN_007BDC40, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::dispose)
   *
   * What it does:
   * Releases one owned `CGpgNetInterface` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeCGpgNetInterface(
    SpCountedImplStorage<moho::CGpgNetInterface>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x007E6570 (FUN_007E6570, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::dispose)
   *
   * What it does:
   * Releases one owned `MeshMaterial` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeMeshMaterial(
    SpCountedImplStorage<moho::MeshMaterial>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x007E65B0 (FUN_007E65B0, boost::detail::sp_counted_impl_p<Moho::Mesh>::dispose)
   *
   * What it does:
   * Releases one owned `Mesh` pointee through its secondary deleting
   * virtual destructor lane (`vtable[1]`) when present.
   */
  void SpCountedImplPDisposeMesh(
    SpCountedImplStorage<moho::Mesh>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDeleteSlot(countedImpl, 1u);
  }

  /**
   * Address: 0x007E6990 (FUN_007E6990, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::dispose)
   *
   * What it does:
   * Releases one owned `MeshBatch` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeMeshBatch(
    SpCountedImplStorage<moho::MeshBatch>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x007FBE60 (FUN_007FBE60, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::dispose)
   *
   * What it does:
   * Releases one owned `IRenTerrain` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeIRenTerrain(
    SpCountedImplStorage<moho::IRenTerrain>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x007FF6D0 (FUN_007FF6D0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::dispose)
   *
   * What it does:
   * Releases one owned `ID3DVertexSheet` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeID3DVertexSheet(
    SpCountedImplStorage<moho::ID3DVertexSheet>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008142C0 (FUN_008142C0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::dispose)
   *
   * What it does:
   * Releases one owned `ShoreCell` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeShoreCell(
    SpCountedImplStorage<moho::ShoreCell>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x00832A20 (FUN_00832A20, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::dispose)
   *
   * What it does:
   * Releases one owned `MeshInstance` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeMeshInstance(
    SpCountedImplStorage<moho::MeshInstance>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x00884F10 (FUN_00884F10, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::dispose)
   *
   * What it does:
   * Releases one owned `LaunchInfoLoad` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeLaunchInfoLoad(
    SpCountedImplStorage<moho::LaunchInfoLoad>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x00765720 (FUN_00765720, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dispose)
   *
   * What it does:
   * Unlinks one owned `PathPreviewFinder` from its intrusive queue links and
   * releases the owned pointee allocation.
   */
  void SpCountedImplPDisposePathPreviewFinder(
    SpCountedImplStorage<moho::PathPreviewFinder>* const countedImpl
  ) noexcept
  {
    if (countedImpl == nullptr || countedImpl->px == nullptr) {
      return;
    }

    auto* const finder = reinterpret_cast<PathPreviewFinderDisposeRuntimeView*>(countedImpl->px);
    (void)DestroyPathPreviewFinderRuntime(finder);
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
   * Address: 0x008E9840 (FUN_008E9840, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `TextureD3D9` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeTextureD3D9(
    SpCountedImplStorage<gpg::gal::TextureD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9850 (FUN_008E9850, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `RenderTargetD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9860 (FUN_008E9860, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `CubeRenderTargetD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeCubeRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9870 (FUN_008E9870, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `DepthStencilTargetD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeDepthStencilTargetD3D9(
    SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9880 (FUN_008E9880, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `VertexFormatD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeVertexFormatD3D9(
    SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9890 (FUN_008E9890, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `VertexBufferD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeVertexBufferD3D9(
    SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E98A0 (FUN_008E98A0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `IndexBufferD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeIndexBufferD3D9(
    SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E98B0 (FUN_008E98B0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `EffectD3D9` pointee through its scalar-deleting
   * virtual destructor lane when present.
   */
  void SpCountedImplPDisposeEffectD3D9(
    SpCountedImplStorage<gpg::gal::EffectD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008E9A70 (FUN_008E9A70, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::dispose)
   *
   * What it does:
   * Releases one owned `PipelineStateD3D9` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposePipelineStateD3D9(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008F9F40 (FUN_008F9F40, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dispose variant)
   *
   * What it does:
   * Releases one owned `EffectD3D10` pointee through its scalar-deleting
   * virtual destructor lane when present (alternate emitted lane).
   */
  void SpCountedImplPDisposeEffectD3D10VariantA(
    SpCountedImplStorage<gpg::gal::EffectD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008F9F60 (FUN_008F9F60, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::dispose)
   *
   * What it does:
   * Releases one owned `RenderTargetD3D10` pointee through its
   * scalar-deleting virtual destructor lane when present.
   */
  void SpCountedImplPDisposeRenderTargetD3D10(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointeeViaVirtualDelete(countedImpl);
  }

  /**
   * Address: 0x008F9FB0 (FUN_008F9FB0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dispose)
   *
   * What it does:
   * Deletes one owned `EffectD3D10` pointee bound to this shared-count control
   * lane when present.
   */
  void SpCountedImplPDisposeEffectD3D10(
    SpCountedImplStorage<gpg::gal::EffectD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
  }

  /**
   * Address: 0x008FA190 (FUN_008FA190, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::dispose)
   *
   * What it does:
   * Deletes one owned `PipelineStateD3D10` pointee bound to this shared-count
   * control lane when present.
   */
  void SpCountedImplPDisposePipelineStateD3D10(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* const countedImpl
  ) noexcept
  {
    DisposeSpCountedImplPointee(countedImpl);
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
   * Address: 0x005CD5C0 (FUN_005CD5C0, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CIntelGrid>* SpCountedImplPDeletingDtorCIntelGrid(
    SpCountedImplStorage<moho::CIntelGrid>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x0063E7B0 (FUN_0063E7B0, boost::detail::sp_counted_impl_p<Moho::CAniPose>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CAniPose>* SpCountedImplPDeletingDtorCAniPose(
    SpCountedImplStorage<moho::CAniPose>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007146C0 (FUN_007146C0, boost::detail::sp_counted_impl_p<Moho::STrigger>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::STrigger>* SpCountedImplPDeletingDtorSTrigger(
    SpCountedImplStorage<moho::STrigger>* const countedImpl,
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
   * Address: 0x007560A0 (FUN_007560A0, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CDebugCanvas>* SpCountedImplPDeletingDtorCDebugCanvas(
    SpCountedImplStorage<moho::CDebugCanvas>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007560C0 (FUN_007560C0, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::SParticleBuffer>* SpCountedImplPDeletingDtorSParticleBuffer(
    SpCountedImplStorage<moho::SParticleBuffer>* const countedImpl,
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
   * Address: 0x00797090 (FUN_00797090, boost::detail::sp_counted_impl_p<Moho::CMauiFrame>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CMauiFrame>* SpCountedImplPDeletingDtorCMauiFrame(
    SpCountedImplStorage<moho::CMauiFrame>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007BDC60 (FUN_007BDC60, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::CGpgNetInterface>* SpCountedImplPDeletingDtorCGpgNetInterface(
    SpCountedImplStorage<moho::CGpgNetInterface>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E65E0 (FUN_007E65E0, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::MeshMaterial>* SpCountedImplPDeletingDtorMeshMaterial(
    SpCountedImplStorage<moho::MeshMaterial>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E6600 (FUN_007E6600, boost::detail::sp_counted_impl_p<Moho::Mesh>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::Mesh>* SpCountedImplPDeletingDtorMesh(
    SpCountedImplStorage<moho::Mesh>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E6A40 (FUN_007E6A40, boost::detail::sp_counted_impl_p<Moho::RMeshBlueprintLOD>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::RMeshBlueprintLOD>* SpCountedImplPDeletingDtorRMeshBlueprintLOD(
    SpCountedImplStorage<moho::RMeshBlueprintLOD>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E6A60 (FUN_007E6A60, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::MeshBatch>* SpCountedImplPDeletingDtorMeshBatch(
    SpCountedImplStorage<moho::MeshBatch>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E6A80 (FUN_007E6A80, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::Mesh>* SpCountedImplPdDeletingDtorMeshRefCountedCache(
    SpCountedImplStorage<moho::Mesh>* const countedImpl,
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
   * Address: 0x007FF6F0 (FUN_007FF6F0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::ID3DVertexSheet>* SpCountedImplPDeletingDtorID3DVertexSheet(
    SpCountedImplStorage<moho::ID3DVertexSheet>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008142E0 (FUN_008142E0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::ShoreCell>* SpCountedImplPDeletingDtorShoreCell(
    SpCountedImplStorage<moho::ShoreCell>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x00832A40 (FUN_00832A40, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::MeshInstance>* SpCountedImplPDeletingDtorMeshInstance(
    SpCountedImplStorage<moho::MeshInstance>* const countedImpl,
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
   * Address: 0x00884F30 (FUN_00884F30, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<moho::LaunchInfoLoad>* SpCountedImplPDeletingDtorLaunchInfoLoad(
    SpCountedImplStorage<moho::LaunchInfoLoad>* const countedImpl,
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
   * Address: 0x008E98C0 (FUN_008E98C0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::TextureD3D9>* SpCountedImplPDeletingDtorTextureD3D9(
    SpCountedImplStorage<gpg::gal::TextureD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E98E0 (FUN_008E98E0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* SpCountedImplPDeletingDtorRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9900 (FUN_008E9900, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* SpCountedImplPDeletingDtorCubeRenderTargetD3D9(
    SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9920 (FUN_008E9920, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* SpCountedImplPDeletingDtorDepthStencilTargetD3D9(
    SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9940 (FUN_008E9940, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* SpCountedImplPDeletingDtorVertexFormatD3D9(
    SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9960 (FUN_008E9960, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* SpCountedImplPDeletingDtorVertexBufferD3D9(
    SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9980 (FUN_008E9980, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* SpCountedImplPDeletingDtorIndexBufferD3D9(
    SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E99A0 (FUN_008E99A0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectD3D9>* SpCountedImplPDeletingDtorEffectD3D9(
    SpCountedImplStorage<gpg::gal::EffectD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008E9A80 (FUN_008E9A80, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* SpCountedImplPDeletingDtorPipelineStateD3D9(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008F9FC0 (FUN_008F9FC0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::EffectD3D10>* SpCountedImplPDeletingDtorEffectD3D10(
    SpCountedImplStorage<gpg::gal::EffectD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x007E6A10 (FUN_007E6A10, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::get_deleter)
   *
   * What it does:
   * Returns one mesh-cache deleter lane at offset `+0x10` when the queried
   * `type_info` matches the cache-deleter type.
   */
  void* SpCountedImplPdGetDeleterMeshRefCountedCache(
    SpCountedImplStorage<moho::Mesh>* const countedImpl,
    const detail::sp_typeinfo& requestedType
  ) noexcept
  {
    if (!IsMeshRefCountedCacheDeleterType(requestedType)) {
      return nullptr;
    }
    return GetSpCountedImplPdDeleterStorage(countedImpl);
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
   * Address: 0x008F9FE0 (FUN_008F9FE0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::TextureD3D10>* SpCountedImplPDeletingDtorTextureD3D10(
    SpCountedImplStorage<gpg::gal::TextureD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA000 (FUN_008FA000, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* SpCountedImplPDeletingDtorRenderTargetD3D10(
    SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA020 (FUN_008FA020, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* SpCountedImplPDeletingDtorCubeRenderTargetD3D10(
    SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA040 (FUN_008FA040, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* SpCountedImplPDeletingDtorDepthStencilTargetD3D10(
    SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA060 (FUN_008FA060, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* SpCountedImplPDeletingDtorVertexFormatD3D10(
    SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA080 (FUN_008FA080, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* SpCountedImplPDeletingDtorVertexBufferD3D10(
    SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA0A0 (FUN_008FA0A0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* SpCountedImplPDeletingDtorIndexBufferD3D10(
    SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x008FA1A0 (FUN_008FA1A0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::dtr)
   *
   * What it does:
   * Executes one scalar-deleting destructor thunk for this control-block
   * specialization.
   */
  SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* SpCountedImplPDeletingDtorPipelineStateD3D10(
    SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* const countedImpl,
    const unsigned char deleteFlag
  ) noexcept
  {
    return SpCountedImplDeletingDtorLane(countedImpl, deleteFlag);
  }

  /**
   * Address: 0x00923740 (FUN_00923740)
   *
   * What it does:
   * Deletes one `std::stringstream` raw-pointer lane during
   * `shared_count<stringstream>` constructor unwind.
   */
  [[maybe_unused]] int DeleteStdStringstreamSharedCountCtorPointeeOnUnwind(
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
  [[maybe_unused]] boost::shared_ptr<std::stringstream>* ConstructSharedStdStringstreamFromRaw(
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
  [[maybe_unused]] int DeleteEffectTechniqueD3D9SharedCountCtorPointeeOnUnwind(
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
  [[maybe_unused]] int DeleteEffectVariableD3D9SharedCountCtorPointeeOnUnwind(
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
   * Address: 0x0053A260 (FUN_0053A260, boost::detail::sp_counted_impl_p<Moho::RScmResource>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullRScmResource(
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
   * Address: 0x00545370 (FUN_00545370, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullLaunchInfoNew(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x005791E0 (FUN_005791E0, boost::detail::sp_counted_impl_p<Moho::CHeightField>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCHeightField(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x005CD5B0 (FUN_005CD5B0, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCIntelGrid(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x0063E7A0 (FUN_0063E7A0, boost::detail::sp_counted_impl_p<Moho::CAniPose>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCAniPose(
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
   * Address: 0x00756020 (FUN_00756020, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCDebugCanvas(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00756070 (FUN_00756070, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullSParticleBuffer(
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
   * Address: 0x007BDC50 (FUN_007BDC50, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullCGpgNetInterface(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x007E6580 (FUN_007E6580, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullMeshMaterial(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x007E65D0 (FUN_007E65D0, boost::detail::sp_counted_impl_p<Moho::Mesh>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullMesh(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x007E69A0 (FUN_007E69A0, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullMeshBatch(
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
   * Address: 0x007FF6E0 (FUN_007FF6E0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullID3DVertexSheet(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008142D0 (FUN_008142D0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullShoreCell(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00832A30 (FUN_00832A30, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullMeshInstance(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x00884F20 (FUN_00884F20, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullLaunchInfoLoad(
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
   * Address: 0x008E89B0 (FUN_008E89B0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullTextureD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E89E0 (FUN_008E89E0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullRenderTargetD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8A40 (FUN_008E8A40, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullDepthStencilTargetD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8A70 (FUN_008E8A70, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullVertexFormatD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8AA0 (FUN_008E8AA0, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullVertexBufferD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8AD0 (FUN_008E8AD0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullIndexBufferD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8B00 (FUN_008E8B00, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullEffectD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008E8DA0 (FUN_008E8DA0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullPipelineStateD3D9(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008F8FE0 (FUN_008F8FE0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullEffectD3D10(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008F9040 (FUN_008F9040, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullRenderTargetD3D10(
    detail::sp_typeinfo const& requestedType
  ) noexcept
  {
    return SpCountedImplGetDeleterNullResult(requestedType);
  }

  /**
   * Address: 0x008F93A0 (FUN_008F93A0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::get_deleter)
   *
   * What it does:
   * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
   */
  void* SpCountedImplPGetDeleterNullPipelineStateD3D10(
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
} // namespace boost
