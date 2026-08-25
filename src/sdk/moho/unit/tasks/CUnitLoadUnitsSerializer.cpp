#include "moho/unit/tasks/CUnitLoadUnitsSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitLoadUnits.h"

namespace
{
  /**
   * Address: 0x00BD1CB0 (FUN_00BD1CB0, dynamic initializer for the global
   * `CUnitLoadUnitsSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`).
   */
  moho::CUnitLoadUnitsSerializer gCUnitLoadUnitsSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00624FF0 (FUN_00624FF0, Moho::CUnitLoadUnitsSerializer::Deserialize)
   */
  void CUnitLoadUnitsSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<CUnitLoadUnits*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00625000 (FUN_00625000, Moho::CUnitLoadUnitsSerializer::Serialize)
   */
  void CUnitLoadUnitsSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const task = reinterpret_cast<CUnitLoadUnits*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BD1CB0 (FUN_00BD1CB0, register_CUnitLoadUnitsSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitLoadUnitsSerializer::CUnitLoadUnitsSerializer()
    : mDeserialize(&CUnitLoadUnitsSerializer::Deserialize)
    , mSerialize(&CUnitLoadUnitsSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFA5B0 (FUN_00BFA5B0, cleanup_CUnitLoadUnitsSerializer)
   */
  CUnitLoadUnitsSerializer::~CUnitLoadUnitsSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00626F90 (FUN_00626F90, gpg::SerSaveLoadHelper<Moho::CUnitLoadUnits>::Init)
   */
  void CUnitLoadUnitsSerializer::Init()
  {
    if (CUnitLoadUnits::sType == nullptr) {
      CUnitLoadUnits::sType = gpg::LookupRType(typeid(CUnitLoadUnits));
    }

    gpg::RType* const type = CUnitLoadUnits::sType;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
