#include "moho/ai/CAiPathSplineSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  alignas(CAiPathSplineSerializer) unsigned char gCAiPathSplineSerializerStorage[sizeof(CAiPathSplineSerializer)];
  bool gCAiPathSplineSerializerConstructed = false;

  /**
   * Address: 0x005B56F0 (FUN_005B56F0, j_Moho::CAiPathSpline::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiPathSpline::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberDeserializeThunk(
    moho::CAiPathSpline* const pathSpline, gpg::ReadArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005B5700 (FUN_005B5700, j_Moho::CAiPathSpline::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiPathSpline::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberSerializeThunk(
    moho::CAiPathSpline* const pathSpline, gpg::WriteArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberSerialize(archive);
  }

  /**
   * Address: 0x005B5A70 (FUN_005B5A70, j_Moho::CAiPathSpline::MemberDeserialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiPathSpline::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberDeserializeThunkSecondary(
    moho::CAiPathSpline* const pathSpline, gpg::ReadArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005B5A80 (FUN_005B5A80, j_Moho::CAiPathSpline::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiPathSpline::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberSerializeThunkSecondary(
    moho::CAiPathSpline* const pathSpline, gpg::WriteArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberSerialize(archive);
  }

  [[nodiscard]] CAiPathSplineSerializer* AcquireCAiPathSplineSerializer()
  {
    if (!gCAiPathSplineSerializerConstructed) {
      new (gCAiPathSplineSerializerStorage) CAiPathSplineSerializer();
      gCAiPathSplineSerializerConstructed = true;
    }

    return reinterpret_cast<CAiPathSplineSerializer*>(gCAiPathSplineSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedCAiPathSplineType()
  {
    gpg::RType* type = CAiPathSpline::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathSpline));
      CAiPathSpline::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00BF7540 (FUN_00BF7540, cleanup_CAiPathSplineSerializer)
   *
   * What it does:
   * Unlinks the startup serializer helper node from the intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiPathSplineSerializer()
  {
    if (!gCAiPathSplineSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathSplineSerializer());
  }

  /**
   * Address: 0x005B24F0 (FUN_005B24F0)
   *
   * What it does:
   * Startup cleanup variant that unlinks and self-resets the global
   * CAiPathSpline serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiPathSplineSerializerStartupThunkA()
  {
    if (!gCAiPathSplineSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathSplineSerializer());
  }

  /**
   * Address: 0x005B2520 (FUN_005B2520)
   *
   * What it does:
   * Secondary startup cleanup variant that unlinks and self-resets the global
   * CAiPathSpline serializer helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CAiPathSplineSerializerStartupThunkB()
  {
    if (!gCAiPathSplineSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireCAiPathSplineSerializer());
  }

  void CleanupCAiPathSplineSerializerAtexit()
  {
    (void)cleanup_CAiPathSplineSerializer();
  }
} // namespace

/**
 * Address: 0x005B24A0 (FUN_005B24A0, Moho::CAiPathSplineSerializer::Deserialize)
 */
void CAiPathSplineSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const pathSpline = reinterpret_cast<CAiPathSpline*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !pathSpline) {
    return;
  }

  if (ownerRef != nullptr) {
    pathSpline->MemberDeserialize(archive);
    return;
  }

  CAiPathSplineMemberDeserializeThunk(pathSpline, archive);
}

/**
 * Address: 0x005B24B0 (FUN_005B24B0, Moho::CAiPathSplineSerializer::Serialize)
 */
void CAiPathSplineSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const pathSpline = reinterpret_cast<CAiPathSpline*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !pathSpline) {
    return;
  }

  if (ownerRef != nullptr) {
    pathSpline->MemberSerialize(archive);
    return;
  }

  CAiPathSplineMemberSerializeThunk(pathSpline, archive);
}

/**
 * Address: 0x005B48E0 (FUN_005B48E0)
 */
void CAiPathSplineSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiPathSplineType();

  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCD350 (FUN_00BCD350, register_CAiPathSplineSerializer)
 *
 * What it does:
 * Initializes startup serializer callbacks for `CAiPathSpline` and installs
 * process-exit helper unlink cleanup.
 */
int moho::register_CAiPathSplineSerializer()
{
  CAiPathSplineSerializer* const serializer = AcquireCAiPathSplineSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiPathSplineSerializer::Deserialize;
  serializer->mSaveCallback = &CAiPathSplineSerializer::Serialize;
  return std::atexit(&CleanupCAiPathSplineSerializerAtexit);
}

namespace
{
  struct CAiPathSplineSerializerBootstrap
  {
    CAiPathSplineSerializerBootstrap()
    {
      (void)moho::register_CAiPathSplineSerializer();
    }
  };

  [[maybe_unused]] CAiPathSplineSerializerBootstrap gCAiPathSplineSerializerBootstrap;
} // namespace
