#include "moho/containers/BVIntSetSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/containers/BVIntSet.h"
#include "moho/containers/TDatList.h"
#include "moho/containers/BVIntSetTypeInfo.h"

// Make BVIntSet registration run before default-segment bootstrap objects that
// query BVIntSet RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  extern moho::BVIntSetSerializer gBVIntSetSerializer;

  /**
   * Address: 0x004028B0 (FUN_004028B0)
   *
   * What it does:
   * Lazily resolves and caches reflection type descriptor for `moho::BVIntSet`.
   */
  [[nodiscard]] gpg::RType* CachedBVIntSetType()
  {
    gpg::RType* type = moho::BVIntSet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::BVIntSet));
      moho::BVIntSet::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00402C40 (FUN_00402C40, j_Moho::BVIntSet::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `BVIntSet::MemberDeserialize`.
   */
  void BVIntSetMemberDeserializeThunk(moho::BVIntSet* const set, gpg::ReadArchive* const archive)
  {
    if (set) {
      set->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00402C50 (FUN_00402C50, j_Moho::BVIntSet::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `BVIntSet::MemberSerialize`.
   */
  void BVIntSetMemberSerializeThunk(const moho::BVIntSet* const set, gpg::WriteArchive* const archive)
  {
    if (set) {
      set->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x004015A0 (FUN_004015A0)
   *
   * What it does:
   * Loads BVIntSet payload through the member deserializer wrapper.
   */
  void LoadBVIntSet(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const set = reinterpret_cast<moho::BVIntSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(set != nullptr);
    if (!archive || !set) {
      return;
    }

    BVIntSetMemberDeserializeThunk(set, archive);
  }

  /**
   * Address: 0x004015B0 (FUN_004015B0)
   *
   * What it does:
   * Saves BVIntSet payload through the member serializer wrapper.
   */
  void SaveBVIntSet(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const set = reinterpret_cast<const moho::BVIntSet*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(set != nullptr);
    if (!archive || !set) {
      return;
    }

    BVIntSetMemberSerializeThunk(set, archive);
  }

  /**
   * Address: 0x004025F0 (FUN_004025F0)
   *
   * What it does:
   * Initializes the global BVIntSet serializer helper callbacks and returns it.
   */
  [[nodiscard]] moho::BVIntSetSerializer* InitializeBVIntSetSerializer()
  {
    gBVIntSetSerializer.mHelperNext = nullptr;
    gBVIntSetSerializer.mHelperPrev = nullptr;
    gBVIntSetSerializer.mLoadCallback = &LoadBVIntSet;
    gBVIntSetSerializer.mSaveCallback = &SaveBVIntSet;
    return &gBVIntSetSerializer;
  }

  using SerHelperNode = moho::TDatListItem<void, void>;

  struct SerHelperLayout
  {
    void* mVfptr;
    SerHelperNode mNode;
  };

  [[nodiscard]] SerHelperNode* SerializerNode(moho::BVIntSetSerializer* const serializer)
  {
    return reinterpret_cast<SerHelperNode*>(&serializer->mHelperNext);
  }

  /**
   * Address: 0x004015F0 (FUN_004015F0)
   *
   * What it does:
   * Unlinks global BVIntSet serializer helper node from intrusive list and
   * resets it to a self-linked singleton node.
   */
  [[maybe_unused]] SerHelperNode* ResetGlobalBVIntSetSerializerNodeA()
  {
    SerHelperNode* const node = SerializerNode(&gBVIntSetSerializer);
    node->ListUnlink();
    return node;
  }

  /**
   * Address: 0x00401620 (FUN_00401620)
   *
   * What it does:
   * Unlinks `helper->mNode` from intrusive list and resets it to self-linked state.
   */
  [[maybe_unused]] SerHelperNode* ResetSerializerNode(SerHelperLayout* const helper)
  {
    SerHelperNode* const node = helper ? &helper->mNode : nullptr;
    node->ListUnlink();
    return node;
  }

  /**
   * Address: 0x00401640 (FUN_00401640)
   *
   * What it does:
   * Duplicate global atexit lane that unlinks and self-resets BVIntSet serializer node.
   */
  [[maybe_unused]] SerHelperNode* ResetGlobalBVIntSetSerializerNodeB()
  {
    SerHelperNode* const node = SerializerNode(&gBVIntSetSerializer);
    node->ListUnlink();
    return node;
  }

  moho::BVIntSetTypeInfo gBVIntSetTypeInfo;
  moho::BVIntSetSerializer gBVIntSetSerializer;

  struct BVIntSetReflectionRegistration
  {
    BVIntSetReflectionRegistration()
    {
      InitializeBVIntSetSerializer()->RegisterSerializeFunctions();
    }
  };

  BVIntSetReflectionRegistration gBVIntSetReflectionRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x004015C0 (FUN_004015C0)
   *
   * What it does:
   * Initializes serializer callback slots for BVIntSet load/save forwarding.
   */
  BVIntSetSerializer::BVIntSetSerializer()
    : mHelperNext(nullptr)
    , mHelperPrev(nullptr)
    , mLoadCallback(&LoadBVIntSet)
    , mSaveCallback(&SaveBVIntSet)
  {}

  /**
   * Address: 0x00402620 (FUN_00402620, gpg::SerSaveLoadHelper<class Moho::BVIntSet>::Init)
   *
   * What it does:
   * Resolves BVIntSet RTTI and installs load/save callbacks from this helper.
   */
  void BVIntSetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedBVIntSetType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
