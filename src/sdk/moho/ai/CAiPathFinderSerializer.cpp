#include "moho/ai/CAiPathFinderSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  alignas(CAiPathFinderSerializer) unsigned char gCAiPathFinderSerializerStorage[sizeof(CAiPathFinderSerializer)] = {};
  bool gCAiPathFinderSerializerConstructed = false;

  [[nodiscard]] CAiPathFinderSerializer* AcquireCAiPathFinderSerializer()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      new (gCAiPathFinderSerializerStorage) CAiPathFinderSerializer();
      gCAiPathFinderSerializerConstructed = true;
    }

    return reinterpret_cast<CAiPathFinderSerializer*>(gCAiPathFinderSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  /**
   * Address: 0x005AAED0 (FUN_005AAED0)
   *
   * What it does:
   * Loads `serializer->mHelperNext->mNext` into an output pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreSerializerNextOfNext(
    gpg::SerHelperBase** const outNode,
    const CAiPathFinderSerializer* const serializer
  ) noexcept
  {
    if (!outNode) {
      return nullptr;
    }

    gpg::SerHelperBase* next = nullptr;
    if (serializer && serializer->mHelperNext) {
      next = serializer->mHelperNext->mNext;
    }
    *outNode = next;
    return outNode;
  }

  /**
   * Address: 0x005AAEE0 (FUN_005AAEE0)
   *
   * What it does:
   * Loads `serializer->mHelperNext` into an output pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreSerializerNext(
    gpg::SerHelperBase** const outNode,
    const CAiPathFinderSerializer* const serializer
  ) noexcept
  {
    if (!outNode) {
      return nullptr;
    }

    *outNode = serializer ? serializer->mHelperNext : nullptr;
    return outNode;
  }

  /**
   * Address: 0x005AB1A0 (FUN_005AB1A0)
   *
   * What it does:
   * Advances one helper-node cursor to `(*cursor)->mNext`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** AdvanceHelperNodeCursor(
    gpg::SerHelperBase** const cursor
  ) noexcept
  {
    if (cursor && *cursor) {
      *cursor = (*cursor)->mNext;
    }
    return cursor;
  }

  /**
   * Address: 0x005AB280 (FUN_005AB280)
   *
   * What it does:
   * Unlinks one intrusive helper node and restores it to self-linked state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkAndResetHelperNode(
    gpg::SerHelperBase* const node
  ) noexcept
  {
    if (!node) {
      return nullptr;
    }

    if (node->mNext && node->mPrev) {
      node->mNext->mPrev = node->mPrev;
      node->mPrev->mNext = node->mNext;
    }
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x005AB2A0 (FUN_005AB2A0)
   *
   * What it does:
   * Alias lane for loading `serializer->mHelperNext` into an output pointer.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreSerializerNextAlias(
    gpg::SerHelperBase** const outNode,
    const CAiPathFinderSerializer* const serializer
  ) noexcept
  {
    return StoreSerializerNext(outNode, serializer);
  }

  /**
   * Address: 0x005AB590 (FUN_005AB590)
   *
   * What it does:
   * Stores one helper-node pointer through an output pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreHelperNodePointer(
    gpg::SerHelperBase** const outNode,
    gpg::SerHelperBase* const value
  ) noexcept
  {
    if (outNode) {
      *outNode = value;
    }
    return outNode;
  }

  /**
   * Address: 0x005AB5C0 (FUN_005AB5C0)
   *
   * What it does:
   * Alias lane for advancing one helper-node cursor.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** AdvanceHelperNodeCursorAlias(
    gpg::SerHelperBase** const cursor
  ) noexcept
  {
    return AdvanceHelperNodeCursor(cursor);
  }

  /**
   * Address: 0x005AB6C0 (FUN_005AB6C0)
   *
   * What it does:
   * Alias lane for loading `serializer->mHelperNext->mNext`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreSerializerNextOfNextAlias(
    gpg::SerHelperBase** const outNode,
    const CAiPathFinderSerializer* const serializer
  ) noexcept
  {
    return StoreSerializerNextOfNext(outNode, serializer);
  }

  /**
   * Address: 0x005AB6D0 (FUN_005AB6D0)
   *
   * What it does:
   * Secondary alias lane for loading `serializer->mHelperNext`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreSerializerNextAlias2(
    gpg::SerHelperBase** const outNode,
    const CAiPathFinderSerializer* const serializer
  ) noexcept
  {
    return StoreSerializerNext(outNode, serializer);
  }

  /**
   * Address: 0x005AB830 (FUN_005AB830)
   *
   * What it does:
   * Pops one helper node from `*cursor`, stores it to `outNode`, and advances
   * `*cursor` to the popped node's next link.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** PopHelperNodeCursor(
    gpg::SerHelperBase** const outNode,
    gpg::SerHelperBase** const cursor
  ) noexcept
  {
    if (!outNode || !cursor || !*cursor) {
      return outNode;
    }

    gpg::SerHelperBase* const node = *cursor;
    *outNode = node;
    *cursor = node->mNext;
    return outNode;
  }

  /**
   * Address: 0x005AB840 (FUN_005AB840)
   *
   * What it does:
   * Alias lane for storing one helper-node pointer.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase** StoreHelperNodePointerAlias(
    gpg::SerHelperBase** const outNode,
    gpg::SerHelperBase* const value
  ) noexcept
  {
    return StoreHelperNodePointer(outNode, value);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    (void)StoreHelperNodePointer(&serializer.mHelperNext, self);
    (void)StoreHelperNodePointerAlias(&serializer.mHelperPrev, self);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    return UnlinkAndResetHelperNode(self);
  }

  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    gpg::RType* type = CAiPathFinder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathFinder));
      CAiPathFinder::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7240 (FUN_00BF7240, cleanup_CAiPathFinderSerializer)
   *
   * What it does:
   * Unlinks the global path-finder serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiPathFinderSerializer()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathFinderSerializer());
  }

  /**
   * Address: 0x005AAC80 (FUN_005AAC80)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * CAiPathFinder serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiPathFinderSerializerStartupThunkA()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathFinderSerializer());
  }

  /**
   * Address: 0x005AACB0 (FUN_005AACB0)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * CAiPathFinder serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiPathFinderSerializerStartupThunkB()
  {
    if (!gCAiPathFinderSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathFinderSerializer());
  }

  void cleanup_CAiPathFinderSerializer_atexit()
  {
    (void)cleanup_CAiPathFinderSerializer();
  }
} // namespace

/**
 * Address: 0x005AAC30 (FUN_005AAC30, Moho::CAiPathFinderSerializer::Deserialize)
 */
void CAiPathFinderSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberDeserialize(archive, version);
}

/**
 * Address: 0x005AAC40 (FUN_005AAC40, Moho::CAiPathFinderSerializer::Serialize)
 */
void CAiPathFinderSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::RRef* const
)
{
  auto* const pathFinder = reinterpret_cast<CAiPathFinder*>(static_cast<std::uintptr_t>(objectPtr));
  if (!pathFinder) {
    return;
  }

  pathFinder->MemberSerialize(archive, version);
}

/**
 * Address: 0x005AB210 (FUN_005AB210)
 *
 * What it does:
 * Lazily resolves CAiPathFinder RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathFinderSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiPathFinderType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCCD70 (FUN_00BCCD70, register_CAiPathFinderSerializer)
 *
 * What it does:
 * Initializes the global path-finder serializer helper callbacks and installs
 * process-exit cleanup.
 */
int moho::register_CAiPathFinderSerializer()
{
  CAiPathFinderSerializer* const serializer = AcquireCAiPathFinderSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiPathFinderSerializer::Deserialize;
  serializer->mSaveCallback = &CAiPathFinderSerializer::Serialize;
  return std::atexit(&cleanup_CAiPathFinderSerializer_atexit);
}

namespace
{
  struct CAiPathFinderSerializerBootstrap
  {
    CAiPathFinderSerializerBootstrap()
    {
      (void)moho::register_CAiPathFinderSerializer();
    }
  };

  [[maybe_unused]] CAiPathFinderSerializerBootstrap gCAiPathFinderSerializerBootstrap;
} // namespace
