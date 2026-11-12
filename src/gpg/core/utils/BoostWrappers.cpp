#include "BoostWrappers.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <sstream>

#include <boost/ptr_container/exception.hpp>

#include "moho/terrain/TerrainFactory.h"
// Engine addition (dedicated-server plan WPL.5): the Direct3D backends' types exist on Windows only.
#if FAFRE_PLATFORM_WINDOWS
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d10/EffectD3D10.hpp"
#include "gpg/gal/backends/d3d10/EffectTechniqueD3D10.hpp"
#include "gpg/gal/backends/d3d10/EffectVariableD3D10.hpp"
#include "gpg/gal/backends/d3d10/PipelineStateD3D10.hpp"
#endif
#include "moho/animation/CAniPose.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/Stats.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/resource/RScaResource.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  class AudioEngine;
}

namespace boost
{
  // boost.thread is no longer built: what the engine used of it is src/legacy/thread (fa::mutex, fa::condition,
  // fa::thread), with the binary's layout and behaviour; condition_impl's constructor (0x00AC2190) and
  // thread::~thread (0x00AC2760) are cited there. The binary's two Win32 kernel-mutex helpers FUN_00AC1C90 and
  // FUN_00AC5480 had no caller here and were removed with it.

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
    SharedCountPair* AssignWeakPairFromSharedCore(
      OutPairT* const outPair,
      const SourcePairT* const sourcePair
    ) noexcept
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
    SharedCountPair* AssignSharedPairRetainCore(
      OutPairT* const outPair,
      const SourcePairT* const sourcePair
    ) noexcept
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
   * Address: 0x00740270 (FUN_00740270)
   *
   * What it does:
   * Releases one shared control block and disposes/destroys the control block
   * on the final strong and weak transitions.
   */
  void ReleaseSharedCount(
    detail::sp_counted_base* const control
  ) noexcept
  {
    if (control != nullptr) {
      control->release();
    }
  }

  namespace
  {
    [[noreturn]] void ThrowBadPointerForNullPushBack()
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
      ThrowBadPointerForNullPushBack();
    }
  }

  namespace
  {
  } // namespace

  namespace
  {
    [[nodiscard]] void* SpCountedImplGetDeleterNullResult(
      boost::detail::sp_typeinfo const&
    ) noexcept
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

      GPG_NONVIRTUAL_DESTROY(delete countedImpl->px);
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
    void DestroySpCountedImplSelf(
      TStorage* const self
    ) noexcept
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
    struct SpCountedImplPd
    {
      void* vftable;
      std::int32_t useCount;
      std::int32_t weakCount;
      TPointee* px;
      std::uint8_t deleterStorage[4];
    };

    static_assert(
      offsetof(SpCountedImplPd<void>, deleterStorage) == 0x10,
      "SpCountedImplPd::deleterStorage offset must be 0x10"
    );

    template <class TPointee>
    [[nodiscard]] void* GetSpCountedImplPdDeleterStorage(
      SpCountedImplStorage<TPointee>* const countedImpl
    ) noexcept
    {
      if (countedImpl == nullptr) {
        return nullptr;
      }

      auto* const runtime = reinterpret_cast<SpCountedImplPd<TPointee>*>(countedImpl);
      return static_cast<void*>(runtime->deleterStorage);
    }

    class RecoveredSpCountedBaseVtableProbe final : public detail::sp_counted_base
    {
    public:
      void dispose() noexcept override {}

      void* get_deleter(
        detail::sp_typeinfo const&
      ) noexcept override
      {
        return nullptr;
      }
    };

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

      void* get_deleter(
        detail::sp_typeinfo const& requestedType
      ) noexcept override
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
   * Address: 0x00931EB0 (FUN_00931EB0,
   * boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::sp_counted_impl_p)
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

  struct SpCountedImplPdFunctionDeleter
  {
    void* vftable;
    std::int32_t useCount;
    std::int32_t weakCount;
    void* px;
    void(__cdecl* deleter)(void*);
  };
  static_assert(
    offsetof(SpCountedImplPdFunctionDeleter, deleter) == 0x10,
    "SpCountedImplPdFunctionDeleter::deleter offset must be 0x10"
  );

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

  // Engine addition (dedicated-server plan WPL.5): the Direct3D backends' types exist on Windows only.
#if FAFRE_PLATFORM_WINDOWS

#endif // _WIN32

  // Engine addition (dedicated-server plan WPL.5): the Direct3D backends' types exist on Windows only.
#if FAFRE_PLATFORM_WINDOWS
  namespace
  {
    template <class TObject>
    [[nodiscard]] int DeletePolymorphicSharedCountCtorPointeeOnUnwind(
      TObject* const pointer
    ) noexcept
    {
      if (pointer == nullptr) {
        return 0;
      }

      // `TObject` is polymorphic (virtual dtor at slot 0), so `delete`
      // reproduces the binary's slot-0 deleting-destructor dispatch.
      delete pointer;
      return 0;
    }
  } // namespace

#endif // _WIN32

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

  // Engine addition (dedicated-server plan WPL.5): the Direct3D backends' types exist on Windows only.
#if FAFRE_PLATFORM_WINDOWS

#endif // _WIN32

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
    return ::new (static_cast<void*>(outLaunchInfo)) boost::shared_ptr<moho::LaunchInfoLoad>(rawLaunchInfo);
  }
} // namespace boost
