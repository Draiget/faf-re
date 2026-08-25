#include "moho/ai/CBuilderArmManipulatorSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/CBuilderArmManipulator.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCBuilderArmManipulatorType()
  {
    gpg::RType* type = moho::CBuilderArmManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CBuilderArmManipulator));
      moho::CBuilderArmManipulator::sType = type;
    }
    return type;
  }

  // Address: 0x010B24BC -- process-global `CBuilderArmManipulatorSerializer`
  // singleton. Constructing it runs CBuilderArmManipulatorSerializer::
  // CBuilderArmManipulatorSerializer() (0x00635B20), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction. Its destructor
  // (~CBuilderArmManipulatorSerializer, 0x00BFAAC0) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration.
  moho::CBuilderArmManipulatorSerializer gCBuilderArmManipulatorSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00635AF0 (FUN_00635AF0, Moho::CBuilderArmManipulatorSerializer::Deserialize)
   */
  void CBuilderArmManipulatorSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<CBuilderArmManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CBuilderArmManipulator::MemberDeserialize(object, archive);
  }

  /**
   * Address: 0x00635B00 (FUN_00635B00, Moho::CBuilderArmManipulatorSerializer::Serialize)
   */
  void CBuilderArmManipulatorSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<const CBuilderArmManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CBuilderArmManipulator::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00635B20 (FUN_00635B20, dynamic initializer for the global
   * `CBuilderArmManipulatorSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`) and binds the load/save callback fields.
   */
  CBuilderArmManipulatorSerializer::CBuilderArmManipulatorSerializer()
    : mDeserialize(&CBuilderArmManipulatorSerializer::Deserialize)
    , mSerialize(&CBuilderArmManipulatorSerializer::Serialize)
  {}

  CBuilderArmManipulatorSerializer::~CBuilderArmManipulatorSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00636F80 (FUN_00636F80)
   * Slot: 0
   *
   * What it does:
   * Lazily resolves `CBuilderArmManipulator` RTTI and installs this helper's
   * load/save callbacks into the type descriptor.
   */
  void CBuilderArmManipulatorSerializer::Init()
  {
    gpg::RType* const type = CachedCBuilderArmManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
