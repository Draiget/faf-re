#include "moho/ai/ESiloBuildStageTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

using namespace moho;

namespace
{
  alignas(ESiloBuildStageTypeInfo) unsigned char gESiloBuildStageTypeInfoStorage[sizeof(ESiloBuildStageTypeInfo)];
  bool gESiloBuildStageTypeInfoConstructed = false;

  alignas(ESiloBuildStagePrimitiveSerializer)
    unsigned char gESiloBuildStagePrimitiveSerializerStorage[sizeof(ESiloBuildStagePrimitiveSerializer)];
  bool gESiloBuildStagePrimitiveSerializerConstructed = false;

  [[nodiscard]] ESiloBuildStageTypeInfo* AcquireESiloBuildStageTypeInfo()
  {
    if (!gESiloBuildStageTypeInfoConstructed) {
      auto* const typeInfo = new (gESiloBuildStageTypeInfoStorage) ESiloBuildStageTypeInfo();
      gpg::PreRegisterRType(typeid(ESiloBuildStage), typeInfo);
      gESiloBuildStageTypeInfoConstructed = true;
    }

    return reinterpret_cast<ESiloBuildStageTypeInfo*>(gESiloBuildStageTypeInfoStorage);
  }

  /**
   * Address: 0x005CE9F0 (FUN_005CE9F0, sub_5CE9F0)
   *
   * What it does:
   * Constructs and preregisters the static `ESiloBuildStageTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloBuildStageTypeInfo()
  {
    return AcquireESiloBuildStageTypeInfo();
  }

  [[nodiscard]] ESiloBuildStagePrimitiveSerializer* AcquireESiloBuildStagePrimitiveSerializer()
  {
    if (!gESiloBuildStagePrimitiveSerializerConstructed) {
      new (gESiloBuildStagePrimitiveSerializerStorage) ESiloBuildStagePrimitiveSerializer();
      gESiloBuildStagePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<ESiloBuildStagePrimitiveSerializer*>(gESiloBuildStagePrimitiveSerializerStorage);
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
  void UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedESiloBuildStageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(ESiloBuildStage));
    }
    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkESiloBuildStagePrimitiveSerializerHelperNode()
  {
    if (!gESiloBuildStagePrimitiveSerializerConstructed) {
      return nullptr;
    }

    ESiloBuildStagePrimitiveSerializer* const serializer = AcquireESiloBuildStagePrimitiveSerializer();
    UnlinkSerializerNode(*serializer);
    return SerializerSelfNode(*serializer);
  }

  /**
   * Address: 0x00BF7E00 (FUN_00BF7E00, sub_BF7E00)
   *
   * What it does:
   * Tears down recovered static `ESiloBuildStageTypeInfo` storage.
   */
  void cleanup_ESiloBuildStageTypeInfo()
  {
    if (!gESiloBuildStageTypeInfoConstructed) {
      return;
    }

    AcquireESiloBuildStageTypeInfo()->~ESiloBuildStageTypeInfo();
    gESiloBuildStageTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF7E10 (FUN_00BF7E10, sub_BF7E10)
   *
   * What it does:
   * Unlinks recovered primitive serializer helper node and restores self-links.
   */
  void cleanup_ESiloBuildStagePrimitiveSerializer()
  {
    if (!gESiloBuildStagePrimitiveSerializerConstructed) {
      return;
    }

    (void)UnlinkESiloBuildStagePrimitiveSerializerHelperNode();
    gESiloBuildStagePrimitiveSerializerConstructed = false;
  }

  /**
   * Address: 0x005CEAC0 (FUN_005CEAC0)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks the recovered `ESiloBuildStage`
   * primitive serializer helper node and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_ESiloBuildStagePrimitiveSerializerStartupThunkA()
  {
    return UnlinkESiloBuildStagePrimitiveSerializerHelperNode();
  }

  /**
   * Address: 0x005CEAF0 (FUN_005CEAF0)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same `ESiloBuildStage`
   * primitive serializer helper unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_ESiloBuildStagePrimitiveSerializerStartupThunkB()
  {
    return UnlinkESiloBuildStagePrimitiveSerializerHelperNode();
  }
} // namespace

/**
 * Address: 0x005CEA80 (FUN_005CEA80, scalar deleting thunk)
 */
ESiloBuildStageTypeInfo::~ESiloBuildStageTypeInfo() = default;

/**
 * Address: 0x005CEA70 (FUN_005CEA70, ?GetName@ESiloBuildStageTypeInfo@Moho@@UBEPBDXZ)
 */
const char* ESiloBuildStageTypeInfo::GetName() const
{
  return "ESiloBuildStage";
}

/**
 * Address: 0x005CEA50 (FUN_005CEA50, ?Init@ESiloBuildStageTypeInfo@Moho@@UAEXXZ)
 */
void ESiloBuildStageTypeInfo::Init()
{
  size_ = sizeof(ESiloBuildStage);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005CFFB0 (FUN_005CFFB0, sub_5CFFB0)
 *
 * What it does:
 * Deserializes one `ESiloBuildStage` enum value from archive storage.
 */
void ESiloBuildStagePrimitiveSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  int value = 0;
  archive->ReadInt(&value);
  *reinterpret_cast<ESiloBuildStage*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ESiloBuildStage>(value);
}

/**
 * Address: 0x005CFFD0 (FUN_005CFFD0, sub_5CFFD0)
 *
 * What it does:
 * Serializes one `ESiloBuildStage` enum value to archive storage.
 */
void ESiloBuildStagePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const ESiloBuildStage*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

/**
 * Address: 0x005CFAC0 (FUN_005CFAC0, sub_5CFAC0)
 *
 * What it does:
 * Binds load/save callbacks into `ESiloBuildStage` reflected metadata.
 */
void ESiloBuildStagePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedESiloBuildStageType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
 *
 * What it does:
 * Registers `ESiloBuildStage` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_ESiloBuildStageTypeInfo()
{
  (void)preregister_ESiloBuildStageTypeInfo();
  return std::atexit(&cleanup_ESiloBuildStageTypeInfo);
}

/**
 * Address: 0x00BCE050 (FUN_00BCE050, register_ESiloBuildStagePrimitiveSerializer)
 *
 * What it does:
 * Registers primitive serializer callbacks for `ESiloBuildStage` and
 * installs process-exit cleanup.
 */
int moho::register_ESiloBuildStagePrimitiveSerializer()
{
  ESiloBuildStagePrimitiveSerializer* const serializer = AcquireESiloBuildStagePrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &ESiloBuildStagePrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &ESiloBuildStagePrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_ESiloBuildStagePrimitiveSerializer);
}

namespace
{
  struct ESiloBuildStageReflectionBootstrap
  {
    ESiloBuildStageReflectionBootstrap()
    {
      (void)moho::register_ESiloBuildStageTypeInfo();
      (void)moho::register_ESiloBuildStagePrimitiveSerializer();
    }
  };

  [[maybe_unused]] ESiloBuildStageReflectionBootstrap gESiloBuildStageReflectionBootstrap;
} // namespace
