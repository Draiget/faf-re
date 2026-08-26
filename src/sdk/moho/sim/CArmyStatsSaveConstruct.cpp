#include "moho/sim/CArmyStatsSaveConstruct.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/ai/CAiBrain.h"
#include "moho/sim/CArmyStats.h"

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

  gpg::RType* gCAiBrainType = nullptr;

  /**
   * Address: 0x0070DF60 (FUN_0070DF60, sub_70DF60)
   */
  void SaveConstructArgs_CArmyStats(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::CArmyStats*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = object->mOwnerArmy;
    ownerRef.mType = object->mOwnerArmy ? CachedType<moho::CAiBrain>(gCAiBrainType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA1A0 (FUN_00BDA1A0, dynamic initializer for the global
   * `CArmyStatsSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  CArmyStatsSaveConstruct::CArmyStatsSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CArmyStats)
      )
  {}

  /**
   * Address: 0x00BFF7F0 (FUN_00BFF7F0, atexit target registered by the real
   * ctor above)
   */
  CArmyStatsSaveConstruct::~CArmyStatsSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0070F4E0 (FUN_0070F4E0, gpg::SerSaveConstructHelper_CArmyStats::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall sub_70F4E0(void (__cdecl **this)(...));
   */
  void CArmyStatsSaveConstruct::Init()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B902C -- process-global `CArmyStatsSaveConstruct` singleton.
  moho::CArmyStatsSaveConstruct gCArmyStatsSaveConstruct;
} // namespace
