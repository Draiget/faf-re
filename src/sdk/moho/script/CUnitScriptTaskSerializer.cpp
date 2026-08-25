#include "moho/script/CUnitScriptTaskSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/script/CUnitScriptTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    gpg::RType* type = moho::CUnitScriptTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitScriptTask));
      moho::CUnitScriptTask::sType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD19A0 (FUN_00BD19A0, dynamic initializer for the global
   * `CUnitScriptTaskSerializer` singleton)
   */
  CUnitScriptTaskSerializer::CUnitScriptTaskSerializer()
    : mLoadCallback(&CUnitScriptTaskSerializer::Deserialize)
    , mSaveCallback(&CUnitScriptTaskSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFA470 (FUN_00BFA470, Moho::CUnitScriptTaskSerializer::~CUnitScriptTaskSerializer)
   */
  CUnitScriptTaskSerializer::~CUnitScriptTaskSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00622EA0 (FUN_00622EA0, Moho::CUnitScriptTaskSerializer::Deserialize)
   */
  void CUnitScriptTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    CUnitScriptTask::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitScriptTask*>(static_cast<std::uintptr_t>(objectPtr)),
      version
    );
  }

  /**
   * Address: 0x00622EC0 (FUN_00622EC0, Moho::CUnitScriptTaskSerializer::Serialize)
   */
  void CUnitScriptTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const
  )
  {
    CUnitScriptTask::MemberSerialize(
      reinterpret_cast<CUnitScriptTask*>(static_cast<std::uintptr_t>(objectPtr)),
      archive,
      version
    );
  }

  /**
   * Address: 0x00623BB0 (FUN_00623BB0)
   */
  void CUnitScriptTaskSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitScriptTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B1D30 -- process-global `CUnitScriptTaskSerializer` singleton.
  moho::CUnitScriptTaskSerializer gCUnitScriptTaskSerializer;
} // namespace
