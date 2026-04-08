#include "moho/sim/COGridSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/COGrid.h"

// Keep startup serializer registration in the library init segment so RTTI
// callback lanes are ready before first COGrid archive traffic.
#pragma init_seg(lib)

namespace
{
  moho::COGridSerializer gCOGridSerializer{};

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

  [[nodiscard]] SerHelperNode* SerializerNode(moho::COGridSerializer* const serializer)
  {
    return reinterpret_cast<SerHelperNode*>(&serializer->mHelperNext);
  }

  [[nodiscard]] gpg::RType* CachedCOGridType()
  {
    gpg::RType* type = moho::COGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::COGrid));
      moho::COGrid::sType = type;
    }
    GPG_ASSERT(type != nullptr);
    return type;
  }

  /**
   * Address: 0x00C003E0 (FUN_00C003E0, ??1COGridSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks global `COGridSerializer` intrusive helper node from registration list.
   */
  void cleanup_COGridSerializer()
  {
    SerializerNode(&gCOGridSerializer)->ListUnlink();
  }

  struct COGridSerializerBootstrap
  {
    COGridSerializerBootstrap()
    {
      moho::register_COGridSerializer();
      gCOGridSerializer.RegisterSerializeFunctions();
    }
  };

  [[maybe_unused]] COGridSerializerBootstrap gCOGridSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00722CC0 (FUN_00722CC0, Moho::COGridSerializer::Deserialize)
   */
  void COGridSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const grid = reinterpret_cast<COGrid*>(static_cast<std::uintptr_t>(objectPtr));
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->TrackPointer(selfRef);
  }

  /**
   * Address: 0x00722D00 (FUN_00722D00, Moho::COGridSerializer::Serialize)
   */
  void COGridSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const grid = reinterpret_cast<COGrid*>(static_cast<std::uintptr_t>(objectPtr));
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->PreCreatedPtr(selfRef);
  }

  /**
   * Address: 0x00BDAAB0 (FUN_00BDAAB0, register_COGridSerializer)
   */
  void register_COGridSerializer()
  {
    SerHelperNode* const self = SerializerNode(&gCOGridSerializer);
    self->prev = self;
    self->next = self;

    gCOGridSerializer.mLoadCallback = &COGridSerializer::Deserialize;
    gCOGridSerializer.mSaveCallback = &COGridSerializer::Serialize;
    (void)std::atexit(&cleanup_COGridSerializer);
  }

  /**
   * Address: 0x00722F90 (FUN_00722F90, gpg::SerSaveLoadHelper_COGrid::Init)
   */
  void COGridSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCOGridType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
