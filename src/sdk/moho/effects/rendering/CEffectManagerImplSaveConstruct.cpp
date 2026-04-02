#include "moho/effects/rendering/CEffectManagerImplSaveConstruct.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace moho
{
  gpg::SerHelperBase* cleanup_CEffectManagerImplSaveConstruct();
} // namespace moho

namespace
{
  gpg::RType* gSimType = nullptr;
  moho::CEffectManagerImplSaveConstruct gCEffectManagerImplSaveConstruct;

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x0066BA60 (FUN_0066BA60, SaveConstructArgs_CEffectManagerImpl_Core)
   *
   * What it does:
   * Writes `CEffectManagerImpl::mSim` as an unowned tracked pointer for
   * save-construct serialization and marks the helper result as unowned.
   */
  void SaveConstructArgs_CEffectManagerImpl_Core(
    moho::CEffectManagerImpl* const object,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    if (!archive || !object) {
      return;
    }

    moho::Sim* const ownerSim = object->GetSim();
    gpg::RRef ownerRef{};
    ownerRef.mObj = ownerSim;
    ownerRef.mType = ownerSim ? ResolveCachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x0066B9E0 (FUN_0066B9E0, SaveConstructArgs_CEffectManagerImpl)
   *
   * What it does:
   * Callback thunk that adapts helper callback ABI and forwards to the
   * concrete save-construct owner-pointer writer.
   */
  void SaveConstructArgs_CEffectManagerImpl(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::CEffectManagerImpl*>(static_cast<std::uintptr_t>(objectPtr));
    SaveConstructArgs_CEffectManagerImpl_Core(object, archive, result);
  }

  void cleanup_CEffectManagerImplSaveConstruct_atexit()
  {
    (void)moho::cleanup_CEffectManagerImplSaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0066C060 (FUN_0066C060, gpg::SerSaveConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall gpg::SerSaveConstructHelper_CEffectManagerImpl::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *, int version, int, gpg::SerConstructResult *));
   */
  void CEffectManagerImplSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BFC000 (FUN_00BFC000, cleanup_CEffectManagerImplSaveConstruct)
   *
   * What it does:
   * Unlinks startup `CEffectManagerImplSaveConstruct` helper node and restores
   * self-linked sentinel state.
   */
  gpg::SerHelperBase* cleanup_CEffectManagerImplSaveConstruct()
  {
    return UnlinkHelperNode(gCEffectManagerImplSaveConstruct);
  }

  /**
   * Address: 0x00BD4590 (FUN_00BD4590, register_CEffectManagerImplSaveConstruct)
   *
   * What it does:
   * Initializes startup save-construct helper callback slots for
   * `CEffectManagerImpl` and installs process-exit cleanup.
   */
  int register_CEffectManagerImplSaveConstruct()
  {
    InitializeHelperNode(gCEffectManagerImplSaveConstruct);
    gCEffectManagerImplSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CEffectManagerImpl);
    gCEffectManagerImplSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&cleanup_CEffectManagerImplSaveConstruct_atexit);
  }
} // namespace moho

namespace
{
  struct CEffectManagerImplSaveConstructBootstrap
  {
    CEffectManagerImplSaveConstructBootstrap()
    {
      (void)moho::register_CEffectManagerImplSaveConstruct();
    }
  };

  [[maybe_unused]] CEffectManagerImplSaveConstructBootstrap gCEffectManagerImplSaveConstructBootstrap;
} // namespace
