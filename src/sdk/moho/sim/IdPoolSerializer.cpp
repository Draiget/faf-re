#include "moho/sim/IdPoolSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/IdPool.h"

// Keep IdPool serializer registration in the lib init segment so runtime
// bootstrap sees the callbacks before first IdPool RTTI lookup.
#pragma init_seg(lib)

namespace moho
{
  void register_IdPoolSerializer();
}

namespace
{
  extern moho::IdPoolSerializer gIdPoolSerializer;

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

  /**
   * Address: 0x00403B90 (FUN_00403B90, Moho::IdPoolSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive loading to `IdPool::MemberDeserialize`.
   */
  void DeserializeIdPool(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<moho::IdPool*>(objectPtr);
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00403BA0 (FUN_00403BA0, Moho::IdPoolSerializer::Serialize)
   *
   * What it does:
   * Forwards archive saving to `IdPool::MemberSerialize`.
   */
  void SerializeIdPool(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const moho::IdPool*>(objectPtr);
    object->MemberSerialize(archive);
  }

  struct SerHelperNode
  {
    SerHelperNode* prev;
    SerHelperNode* next;

    void ListUnlink()
    {
      if (!prev || !next) {
        prev = this;
        next = this;
        return;
      }

      next->prev = prev;
      prev->next = next;
      prev = this;
      next = this;
    }
  };

  [[nodiscard]] SerHelperNode* SerializerNode(moho::IdPoolSerializer* const serializer)
  {
    return reinterpret_cast<SerHelperNode*>(&serializer->mHelperNext);
  }

  /**
   * Address: 0x00BEE060 (FUN_00BEE060, ??1IdPoolSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks global IdPool serializer helper node from intrusive registration list.
   */
  void cleanup_IdPoolSerializer()
  {
    SerializerNode(&gIdPoolSerializer)->ListUnlink();
  }

  moho::IdPoolSerializer gIdPoolSerializer;

  struct IdPoolSerializerRegistration
  {
    IdPoolSerializerRegistration()
    {
      moho::register_IdPoolSerializer();
      gIdPoolSerializer.RegisterSerializeFunctions();
    }
  };

  IdPoolSerializerRegistration gIdPoolSerializerRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2DA0 (FUN_00BC2DA0, register_IdPoolSerializer)
   *
   * What it does:
   * Materializes startup `IdPoolSerializer` storage, installs serializer
   * callback lanes, and registers process-exit teardown.
   */
  void register_IdPoolSerializer()
  {
    gIdPoolSerializer.mHelperNext = nullptr;
    gIdPoolSerializer.mHelperPrev = nullptr;
    gIdPoolSerializer.mLoadCallback = &DeserializeIdPool;
    gIdPoolSerializer.mSaveCallback = &SerializeIdPool;
    (void)std::atexit(&cleanup_IdPoolSerializer);
  }

  /**
   * Address: 0x00403DC0 (FUN_00403DC0, gpg::SerSaveLoadHelper<class Moho::IdPool>::Init)
   */
  void IdPoolSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIdPoolType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
