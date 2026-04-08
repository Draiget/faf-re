#include "moho/path/SNavGoal.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

#pragma init_seg(lib)

namespace
{
  alignas(moho::SNavGoalTypeInfo) unsigned char gSNavGoalTypeInfoStorage[sizeof(moho::SNavGoalTypeInfo)];
  bool gSNavGoalTypeInfoConstructed = false;

  alignas(moho::SNavGoalSerializer) unsigned char gSNavGoalSerializerStorage[sizeof(moho::SNavGoalSerializer)];
  bool gSNavGoalSerializerConstructed = false;

  [[nodiscard]] moho::SNavGoalTypeInfo& SNavGoalTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SNavGoalTypeInfo*>(gSNavGoalTypeInfoStorage);
  }

  [[nodiscard]] moho::SNavGoalSerializer& SNavGoalSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SNavGoalSerializer*>(gSNavGoalSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeHelperNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  void UnlinkHelperNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeHelperNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* cached = gpg::Rect2i::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedELayerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ELayer));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSNavGoalType()
  {
    gpg::RType* cached = moho::SNavGoal::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = cached;
    }
    return cached;
  }

  void CleanupSNavGoalTypeInfoAtExit()
  {
    if (!gSNavGoalTypeInfoConstructed) {
      return;
    }

    SNavGoalTypeInfoStorageRef().~SNavGoalTypeInfo();
    gSNavGoalTypeInfoConstructed = false;
  }

  void CleanupSNavGoalSerializerAtExit()
  {
    if (!gSNavGoalSerializerConstructed) {
      return;
    }

    moho::SNavGoalSerializer& serializer = SNavGoalSerializerStorageRef();
    UnlinkHelperNode(serializer);
    serializer.~SNavGoalSerializer();
    gSNavGoalSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  gpg::RType* SNavGoal::sType = nullptr;

  /**
   * Address: 0x0050CDB0 (FUN_0050CDB0, Moho::SNavGoal::MemberDeserialize)
   *
   * What it does:
   * Loads the first rectangle, secondary rectangle, and layer payload in
   * exact binary archive order.
   */
  void SNavGoal::MemberDeserialize(SNavGoal* const object, gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Read(CachedRect2iType(), &object->mPos1, ownerRef);
    archive->Read(CachedRect2iType(), &object->mPos2, ownerRef);
    archive->Read(CachedELayerType(), &object->mLayer, ownerRef);
  }

  /**
   * Address: 0x0050CE60 (FUN_0050CE60, Moho::SNavGoal::MemberSerialize)
   *
   * What it does:
   * Stores the first rectangle, secondary rectangle, and layer payload in
   * exact binary archive order.
   */
  void SNavGoal::MemberSerialize(const SNavGoal* const object, gpg::WriteArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Write(CachedRect2iType(), &object->mPos1, ownerRef);
    archive->Write(CachedRect2iType(), &object->mPos2, ownerRef);
    archive->Write(CachedELayerType(), &object->mLayer, ownerRef);
  }

  /**
   * Address: 0x0050C030 (FUN_0050C030, Moho::SNavGoalTypeInfo::SNavGoalTypeInfo)
   *
   * What it does:
   * Preregisters the `SNavGoal` RTTI descriptor with the reflection map.
   */
  SNavGoalTypeInfo::SNavGoalTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SNavGoal), this);
  }

  /**
   * Address: 0x00BF21D0 (FUN_00BF21D0, Moho::SNavGoalTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SNavGoalTypeInfo::~SNavGoalTypeInfo() = default;

  /**
   * Address: 0x0050C0B0 (FUN_0050C0B0, Moho::SNavGoalTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SNavGoal`.
   */
  const char* SNavGoalTypeInfo::GetName() const
  {
    return "SNavGoal";
  }

  /**
   * Address: 0x0050C090 (FUN_0050C090, Moho::SNavGoalTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size and finalizes the type.
   */
  void SNavGoalTypeInfo::Init()
  {
    size_ = sizeof(SNavGoal);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0050C170 (FUN_0050C170, Moho::SNavGoalSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive loading to `SNavGoal::MemberDeserialize`.
   */
  void SNavGoalSerializer::Deserialize(gpg::ReadArchive* const archive, SNavGoal* const goal)
  {
    SNavGoal::MemberDeserialize(goal, archive);
  }

  /**
   * Address: 0x0050C180 (FUN_0050C180, Moho::SNavGoalSerializer::Serialize)
   *
   * What it does:
   * Forwards archive saving to `SNavGoal::MemberSerialize`.
   */
  void SNavGoalSerializer::Serialize(gpg::WriteArchive* const archive, SNavGoal* const goal)
  {
    SNavGoal::MemberSerialize(goal, archive);
  }

  /**
   * Address: 0x0050C870 (FUN_0050C870, Moho::SNavGoalSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Binds the serializer callbacks into `SNavGoal` RTTI.
   */
  void SNavGoalSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSNavGoalType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7D80 (FUN_00BC7D80, register_SNavGoalTypeInfo)
   *
   * What it does:
   * Installs the static `SNavGoalTypeInfo` instance and its shutdown hook.
   */
  void register_SNavGoalTypeInfo()
  {
    if (!gSNavGoalTypeInfoConstructed) {
      new (gSNavGoalTypeInfoStorage) SNavGoalTypeInfo();
      gSNavGoalTypeInfoConstructed = true;
    }

    (void)std::atexit(&CleanupSNavGoalTypeInfoAtExit);
  }

  /**
   * Address: 0x00BC7DA0 (FUN_00BC7DA0, register_SNavGoalSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `SNavGoal` and registers shutdown
   * unlink/destruction.
   */
  void register_SNavGoalSerializer()
  {
    if (!gSNavGoalSerializerConstructed) {
      new (gSNavGoalSerializerStorage) SNavGoalSerializer();
      gSNavGoalSerializerConstructed = true;
    }

    InitializeHelperNode(SNavGoalSerializerStorageRef());
    SNavGoalSerializerStorageRef().mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&SNavGoalSerializer::Deserialize);
    SNavGoalSerializerStorageRef().mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SNavGoalSerializer::Serialize);
    SNavGoalSerializerStorageRef().RegisterSerializeFunctions();
    (void)std::atexit(&CleanupSNavGoalSerializerAtExit);
  }

  SNavGoalSerializer::~SNavGoalSerializer() noexcept = default;
} // namespace moho

namespace
{
  struct SNavGoalBootstrap
  {
    SNavGoalBootstrap()
    {
      moho::register_SNavGoalTypeInfo();
      moho::register_SNavGoalSerializer();
    }
  };

  [[maybe_unused]] SNavGoalBootstrap gSNavGoalBootstrap;
} // namespace
