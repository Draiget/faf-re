#include "moho/sim/IdPoolSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/IdPool.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedIdPoolType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    GPG_ASSERT(type != nullptr);
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2DA0 (FUN_00BC2DA0, dynamic initializer for the global
   * `IdPoolSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  IdPoolSerializer::IdPoolSerializer()
    : mLoadCallback(&IdPoolSerializer::Deserialize)
    , mSaveCallback(&IdPoolSerializer::Serialize)
  {}

  IdPoolSerializer::~IdPoolSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00403B90 (FUN_00403B90, Moho::IdPoolSerializer::Deserialize)
   */
  void IdPoolSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<IdPool*>(objectPtr);
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00403BA0 (FUN_00403BA0, Moho::IdPoolSerializer::Serialize)
   */
  void IdPoolSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const IdPool*>(objectPtr);
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00403DC0 (FUN_00403DC0, gpg::SerSaveLoadHelper<class Moho::IdPool>::Init)
   */
  void IdPoolSerializer::Init()
  {
    gpg::RType* const type = CachedIdPoolType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010A6584 -- process-global `IdPoolSerializer` singleton.
  moho::IdPoolSerializer gIdPoolSerializer;
} // namespace
