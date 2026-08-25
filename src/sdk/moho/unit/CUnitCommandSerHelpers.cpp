#include "moho/unit/CUnitCommandSerHelpers.h"

#include <cstdlib>
#include <typeinfo>

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006E91B0 (FUN_006E91B0, Moho::CUnitCommandConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow to `CUnitCommand::MemberConstruct`.
   */
  void CUnitCommandConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    if (result == nullptr) {
      return;
    }

    CUnitCommand::MemberConstruct(result);
  }

  /**
   * Address: 0x006EB710 (FUN_006EB710, Moho::CUnitCommandConstruct::Deconstruct)
   *
   * What it does:
   * Runs deleting-dtor teardown for one `CUnitCommand`.
   */
  void CUnitCommandConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const command = static_cast<CUnitCommand*>(objectPtr);
    if (command == nullptr) {
      return;
    }

    delete command;
  }

  /**
   * Address: 0x006EA060 (FUN_006EA060, Moho::CUnitCommandConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds `CUnitCommand` construct/delete callbacks into RTTI.
   */
  void CUnitCommandConstruct::Init()
  {
    gpg::RType* type = CUnitCommand::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(CUnitCommand));
      CUnitCommand::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BD8F50 (FUN_00BD8F50, register_CUnitCommandConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  CUnitCommandConstruct::CUnitCommandConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CUnitCommandConstruct::Construct))
    , mDeconstructCallback(&CUnitCommandConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00BFEBE0 (FUN_00BFEBE0, Moho::CUnitCommandConstruct::~CUnitCommandConstruct)
   */
  CUnitCommandConstruct::~CUnitCommandConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006E9250 (FUN_006E9250, Moho::CUnitCommandSerializer::Deserialize)
   *
   * What it does:
   * Loads the serialized `CUnitCommand` payload lanes.
   */
  void CUnitCommandSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef*
  )
  {
    auto* const command = reinterpret_cast<CUnitCommand*>(objectPtr);
    if (archive == nullptr || command == nullptr) {
      return;
    }

    CUnitCommand::MemberDeserialize(archive, command, version);
  }

  /**
   * Address: 0x006E9270 (FUN_006E9270, Moho::CUnitCommandSerializer::Serialize)
   *
   * What it does:
   * Saves the serialized `CUnitCommand` payload lanes.
   */
  void CUnitCommandSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef*
  )
  {
    auto* const command = reinterpret_cast<CUnitCommand*>(objectPtr);
    if (archive == nullptr || command == nullptr) {
      return;
    }

    CUnitCommand::MemberSerialize(command, archive, version);
  }

  /**
   * Address: 0x006EA0E0 (FUN_006EA0E0, gpg::SerSaveLoadHelper<Moho::CUnitCommand>::Init)
   *
   * What it does:
   * Binds `CUnitCommand` load/save callbacks onto its reflected type
   * metadata; asserts neither slot is already claimed before installing them.
   */
  void CUnitCommandSerializer::Init()
  {
    gpg::RType* const type = CUnitCommand::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD8F90 (FUN_00BD8F90, register_CUnitCommandSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCommandSerializer::CUnitCommandSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&CUnitCommandSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&CUnitCommandSerializer::Serialize))
  {}

  /**
   * Address: 0x00BFEC10 (FUN_00BFEC10, Moho::CUnitCommandSerializer::~CUnitCommandSerializer)
   */
  CUnitCommandSerializer::~CUnitCommandSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  // Address: 0x010B7FA8 -- process-global `CUnitCommandConstruct` singleton.
  moho::CUnitCommandConstruct gCUnitCommandConstruct;

  // Address: 0x010B7F28 -- process-global `CUnitCommandSerializer` singleton.
  moho::CUnitCommandSerializer gCUnitCommandSerializer;
} // namespace
