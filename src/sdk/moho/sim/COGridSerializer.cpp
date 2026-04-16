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
  [[nodiscard]] gpg::SerHelperBase* UnlinkCOGridSerializerNode()
  {
    SerializerNode(&gCOGridSerializer)->ListUnlink();
    return reinterpret_cast<gpg::SerHelperBase*>(SerializerNode(&gCOGridSerializer));
  }

  void cleanup_COGridSerializer()
  {
    (void)UnlinkCOGridSerializerNode();
  }

  struct COGridSerializerBootstrap
  {
    COGridSerializerBootstrap()
    {
      moho::register_COGridSerializer();
    }
  };

  [[maybe_unused]] COGridSerializerBootstrap gCOGridSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00723590 (FUN_00723590)
   *
   * What it does:
   * Builds one reflected `COGrid` reference and tracks it as a pre-created
   * pointer in the read-archive lane.
   */
  [[maybe_unused]] gpg::ReadArchive* TrackCOGridReadPointerLaneA(COGrid* const grid, gpg::ReadArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->TrackPointer(selfRef);
    return archive;
  }

  /**
   * Address: 0x007235D0 (FUN_007235D0)
   *
   * What it does:
   * Builds one reflected `COGrid` reference and marks it as pre-created in the
   * write-archive lane.
   */
  [[maybe_unused]] gpg::WriteArchive* TrackCOGridWritePointerLaneA(COGrid* const grid, gpg::WriteArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->PreCreatedPtr(selfRef);
    return archive;
  }

  /**
   * Address: 0x007236D0 (FUN_007236D0)
   *
   * What it does:
   * Duplicate read-archive lane that tracks one reflected `COGrid` pointer.
   */
  [[maybe_unused]] gpg::ReadArchive* TrackCOGridReadPointerLaneB(COGrid* const grid, gpg::ReadArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->TrackPointer(selfRef);
    return archive;
  }

  /**
   * Address: 0x00723710 (FUN_00723710)
   *
   * What it does:
   * Duplicate write-archive lane that marks one reflected `COGrid` pointer as
   * pre-created.
   */
  [[maybe_unused]] gpg::WriteArchive* TrackCOGridWritePointerLaneB(COGrid* const grid, gpg::WriteArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->PreCreatedPtr(selfRef);
    return archive;
  }

  /**
   * Address: 0x00723990 (FUN_00723990)
   *
   * What it does:
   * Secondary duplicate read-archive lane for reflected `COGrid` pointer
   * tracking.
   */
  [[maybe_unused]] gpg::ReadArchive* TrackCOGridReadPointerLaneC(COGrid* const grid, gpg::ReadArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->TrackPointer(selfRef);
    return archive;
  }

  /**
   * Address: 0x007239D0 (FUN_007239D0)
   *
   * What it does:
   * Secondary duplicate write-archive lane for reflected `COGrid` pre-created
   * pointer publication.
   */
  [[maybe_unused]] gpg::WriteArchive* TrackCOGridWritePointerLaneC(COGrid* const grid, gpg::WriteArchive* const archive)
  {
    gpg::RRef selfRef{};
    gpg::RRef_COGrid(&selfRef, grid);
    archive->PreCreatedPtr(selfRef);
    return archive;
  }

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
   * Address: 0x00722D40 (FUN_00722D40)
   *
   * What it does:
   * Initializes startup `COGridSerializer` helper links and callback lanes.
   */
  [[maybe_unused]] [[nodiscard]] COGridSerializer* InitializeCOGridSerializerHelperStoragePrimary()
  {
    SerHelperNode* const self = SerializerNode(&gCOGridSerializer);
    self->prev = self;
    self->next = self;
    gCOGridSerializer.mLoadCallback = &COGridSerializer::Deserialize;
    gCOGridSerializer.mSaveCallback = &COGridSerializer::Serialize;
    return &gCOGridSerializer;
  }

  /**
   * Address: 0x00722F60 (FUN_00722F60)
   *
   * What it does:
   * Secondary startup `COGridSerializer` helper initialization variant.
   */
  [[maybe_unused]] [[nodiscard]] COGridSerializer* InitializeCOGridSerializerHelperStorageSecondary()
  {
    SerHelperNode* const self = SerializerNode(&gCOGridSerializer);
    self->prev = self;
    self->next = self;
    gCOGridSerializer.mLoadCallback = &COGridSerializer::Deserialize;
    gCOGridSerializer.mSaveCallback = &COGridSerializer::Serialize;
    return &gCOGridSerializer;
  }

  /**
   * Address: 0x00BDAAB0 (FUN_00BDAAB0, register_COGridSerializer)
   */
  void register_COGridSerializer()
  {
    (void)InitializeCOGridSerializerHelperStoragePrimary();
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

  /**
   * Address: 0x00722D70 (FUN_00722D70)
   *
   * What it does:
   * Duplicated teardown lane for `COGridSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_COGridSerializer_variant_primary()
  {
    return UnlinkCOGridSerializerNode();
  }

  /**
   * Address: 0x00722DA0 (FUN_00722DA0)
   *
   * What it does:
   * Secondary duplicated teardown lane for `COGridSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_COGridSerializer_variant_secondary()
  {
    return UnlinkCOGridSerializerNode();
  }
} // namespace moho
