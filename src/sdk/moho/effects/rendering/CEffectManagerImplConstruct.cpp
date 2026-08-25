#include "moho/effects/rendering/CEffectManagerImplConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  [[nodiscard]] moho::Sim* ReadOwnerSim(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    moho::Sim* ownerSim = nullptr;
    const gpg::RRef ownerRef{};
    (void)archive->ReadPointer_Sim(&ownerSim, &ownerRef);
    return ownerSim;
  }

  /**
   * Address: 0x0066BB40 (FUN_0066BB40, Construct_CEffectManagerImpl)
   *
   * What it does:
   * Reads the owner `Sim` pointer from the archive's tracked-pointer
   * payload, allocates a `CEffectManagerImpl` bound to it, and returns the
   * new object through `SerConstructResult`.
   */
  void Construct_CEffectManagerImpl(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    moho::Sim* const ownerSim = ReadOwnerSim(archive);
    moho::CEffectManagerImpl* const object = new moho::CEffectManagerImpl(ownerSim);

    if (!result) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = moho::CEffectManagerImpl::StaticGetClass();
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x0066C280 (FUN_0066C280, Delete_CEffectManagerImpl)
   *
   * What it does:
   * Executes deleting-dtor semantics for one `CEffectManagerImpl` instance.
   */
  void Delete_CEffectManagerImpl(void* const objectPtr)
  {
    auto* const object = static_cast<moho::CEffectManagerImpl*>(objectPtr);
    delete object;
  }

  // Address: 0x010B3CB4 -- process-global `CEffectManagerImplConstruct`
  // singleton. Constructing it runs
  // CEffectManagerImplConstruct::CEffectManagerImplConstruct()
  // (0x00BD45C0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEffectManagerImplConstruct gCEffectManagerImplConstruct;

  /**
   * Address: 0x00BFC030 (FUN_00BFC030, cleanup_CEffectManagerImplConstruct)
   *
   * What it does:
   * Process-exit cleanup that unlinks the `CEffectManagerImplConstruct`
   * helper node. The real ctor pushes this plain free function (not a
   * mangled destructor) as its atexit target.
   */
  void cleanup_CEffectManagerImplConstruct()
  {
    gCEffectManagerImplConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD45C0 (FUN_00BD45C0, register_CEffectManagerImplConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields, then registers
   * `cleanup_CEffectManagerImplConstruct` as the explicit atexit teardown.
   */
  CEffectManagerImplConstruct::CEffectManagerImplConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CEffectManagerImpl))
    , mDeleteCallback(&Delete_CEffectManagerImpl)
  {
    (void)std::atexit(&cleanup_CEffectManagerImplConstruct);
  }

  /**
   * Address: 0x0066C0E0 (FUN_0066C0E0, gpg::SerConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * int __thiscall gpg::SerConstructHelper_CEffectManagerImpl::Init(void (__cdecl **this)(void *));
   */
  void CEffectManagerImplConstruct::Init()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
