#include "moho/effects/rendering/CEffectManagerImplSaveConstruct.h"

#include <cstdint>
#include <cstdlib>

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

  // Declared locally: gpg::RRef_Sim (defined + address-cited in
  // src/sdk/gpg/core/containers/ArchiveSerialization.cpp) has external
  // linkage but is not yet exposed from a shared header.
  RRef* RRef_Sim(RRef* outRef, moho::Sim* value);
} // namespace gpg

namespace
{
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

    gpg::RRef ownerRef{};
    gpg::RRef_Sim(&ownerRef, object->GetSim());
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

  // Address: 0x010B3CA4 -- process-global `CEffectManagerImplSaveConstruct`
  // singleton. Constructing it runs
  // CEffectManagerImplSaveConstruct::CEffectManagerImplSaveConstruct()
  // (0x00BD4590), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEffectManagerImplSaveConstruct gCEffectManagerImplSaveConstruct;

  /**
   * Address: 0x00BFC000 (FUN_00BFC000, cleanup_CEffectManagerImplSaveConstruct)
   *
   * What it does:
   * Process-exit cleanup that unlinks the `CEffectManagerImplSaveConstruct`
   * helper node. The real ctor pushes this plain free function (not a
   * mangled destructor) as its atexit target.
   */
  void cleanup_CEffectManagerImplSaveConstruct()
  {
    gCEffectManagerImplSaveConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD4590 (FUN_00BD4590, register_CEffectManagerImplSaveConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field, then registers
   * `cleanup_CEffectManagerImplSaveConstruct` as the explicit atexit
   * teardown.
   */
  CEffectManagerImplSaveConstruct::CEffectManagerImplSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CEffectManagerImpl)
      )
  {
    (void)std::atexit(&cleanup_CEffectManagerImplSaveConstruct);
  }

  /**
   * Address: 0x0066C060 (FUN_0066C060, gpg::SerSaveConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall gpg::SerSaveConstructHelper_CEffectManagerImpl::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *, int version, int, gpg::SerConstructResult *));
   */
  void CEffectManagerImplSaveConstruct::Init()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho
