#include "moho/sim/SMassInfoSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/sim/SMassInfo.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSMassInfoType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(moho::SMassInfo));
    }
    return sCachedType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCB700 (FUN_00BCB700, dynamic initializer for the global
   * `SMassInfoSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SMassInfoSerializer::SMassInfoSerializer()
    : mLoadCallback(&SMassInfoSerializer::Deserialize)
    , mSaveCallback(&SMassInfoSerializer::Serialize)
  {}

  SMassInfoSerializer::~SMassInfoSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00585E10 (FUN_00585E10, Moho::SMassInfoSerializer::Deserialize)
   */
  void SMassInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<SMassInfo*>(static_cast<std::uintptr_t>(objectPtr));
    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00585E20 (FUN_00585E20, Moho::SMassInfoSerializer::Serialize)
   */
  void SMassInfoSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    const auto* const info = reinterpret_cast<const SMassInfo*>(static_cast<std::uintptr_t>(objectPtr));
    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x00591B90 (FUN_00591B90)
   *
   * What it does:
   * Lazily resolves SMassInfo RTTI and installs load/save callbacks from this
   * helper object into the type descriptor.
   */
  void SMassInfoSerializer::Init()
  {
    gpg::RType* const type = CachedSMassInfoType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010AE004 -- process-global `SMassInfoSerializer` singleton.
  moho::SMassInfoSerializer gSMassInfoSerializer;
} // namespace
