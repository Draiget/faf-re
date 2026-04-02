#include "moho/sim/ReconBlipSaveConstruct.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gSimType = nullptr;
  moho::ReconBlipSaveConstruct gReconBlipSaveConstruct;

  [[nodiscard]] gpg::SerHelperBase* SaveConstructNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gReconBlipSaveConstruct.mHelperNext);
  }

  void ResetReconBlipSaveConstructLinksImpl() noexcept
  {
    gReconBlipSaveConstruct.mHelperNext->mPrev = gReconBlipSaveConstruct.mHelperPrev;
    gReconBlipSaveConstruct.mHelperPrev->mNext = gReconBlipSaveConstruct.mHelperNext;

    gpg::SerHelperBase* const self = SaveConstructNode();
    gReconBlipSaveConstruct.mHelperPrev = self;
    gReconBlipSaveConstruct.mHelperNext = self;
  }

  /**
   * Address: 0x005BFA80 (FUN_005BFA80)
   *
   * What it does:
   * Unlinks ReconBlip save-construct helper node from the global helper list
   * and rewires it as a self-linked singleton.
   */
  [[nodiscard]] gpg::SerHelperBase* ResetReconBlipSaveConstructLinksPrimary()
  {
    ResetReconBlipSaveConstructLinksImpl();
    return SaveConstructNode();
  }

  /**
   * Address: 0x005BFAB0 (FUN_005BFAB0)
   *
   * What it does:
   * Duplicate entry that performs the same save-construct helper unlink and
   * self-link operation as 0x005BFA80.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* ResetReconBlipSaveConstructLinksSecondary()
  {
    return ResetReconBlipSaveConstructLinksPrimary();
  }

  /**
   * Address: 0x005BFA30 (FUN_005BFA30)
   *
   * What it does:
   * Writes owning `Sim*` pointer for `ReconBlip` save-construct arguments and
   * marks the serializer lane as unowned.
   */
  void SaveConstructArgs_ReconBlip(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::ReconBlip*>(static_cast<std::uintptr_t>(objectPtr));
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef simRef{};
    simRef.mObj = object->SimulationRef;
    simRef.mType = object->SimulationRef ? CachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x005BFAE0 (FUN_005BFAE0)
   *
   * What it does:
   * Calling-convention variant thunk for ReconBlip save-construct-args write
   * path; forwards into the canonical callback implementation.
   */
  [[maybe_unused]] void SaveConstructArgs_ReconBlipObjectThunk(
    moho::ReconBlip* const object, gpg::WriteArchive* const archive
  )
  {
    SaveConstructArgs_ReconBlip(
      archive,
      static_cast<int>(reinterpret_cast<std::uintptr_t>(object)),
      0,
      reinterpret_cast<gpg::SerSaveConstructArgsResult*>(archive)
    );
  }

  /**
   * Address: 0x00BF78D0 (FUN_00BF78D0, cleanup_ReconBlipSaveConstruct)
   *
   * What it does:
   * Process-exit cleanup that unlinks ReconBlip save-construct helper node.
   */
  void cleanup_ReconBlipSaveConstruct()
  {
    (void)ResetReconBlipSaveConstructLinksPrimary();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005C42B0 (FUN_005C42B0, gpg::SerSaveConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs save-construct-args callback
   * from this helper into the type descriptor.
   */
  void ReconBlipSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BCDC70 (FUN_00BCDC70, register_ReconBlipSaveConstruct)
   *
   * What it does:
   * Initializes recovered ReconBlip save-construct helper callback and binds it
   * into reflected RTTI, then registers process-exit cleanup.
   */
  void register_ReconBlipSaveConstruct()
  {
    gpg::SerHelperBase* const self = SaveConstructNode();
    gReconBlipSaveConstruct.mHelperNext = self;
    gReconBlipSaveConstruct.mHelperPrev = self;
    gReconBlipSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_ReconBlip);
    gReconBlipSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&cleanup_ReconBlipSaveConstruct);
  }
} // namespace moho

namespace
{
  struct ReconBlipSaveConstructBootstrap
  {
    ReconBlipSaveConstructBootstrap()
    {
      moho::register_ReconBlipSaveConstruct();
    }
  };

  [[maybe_unused]] ReconBlipSaveConstructBootstrap gReconBlipSaveConstructBootstrap;
} // namespace
