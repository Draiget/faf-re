#include "moho/sim/SThreatSerializer.h"

#include <cstddef>
#include <cstdint>

#include "moho/sim/CInfluenceMap.h"

namespace
{
  moho::SThreatSerializer gSThreatSerializer{};

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  enum class EThreatTypeHelperLane : std::uint32_t
  {
    Primitive = 0u,
    SaveLoad = 1u,
  };

  struct EThreatTypeSerializerHelperStorage
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EThreatTypeSerializerHelperStorage, mHelperNext) == 0x04,
    "EThreatTypeSerializerHelperStorage::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EThreatTypeSerializerHelperStorage, mHelperPrev) == 0x08,
    "EThreatTypeSerializerHelperStorage::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EThreatTypeSerializerHelperStorage, mLoadCallback) == 0x0C,
    "EThreatTypeSerializerHelperStorage::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EThreatTypeSerializerHelperStorage, mSaveCallback) == 0x10,
    "EThreatTypeSerializerHelperStorage::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(EThreatTypeSerializerHelperStorage) == 0x14, "EThreatTypeSerializerHelperStorage size must be 0x14");

  using SerializerWord = std::uint32_t;

  struct SerializerSlot36ByPointerVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord* value);
  };

  struct SerializerSlot36ByValueVTable
  {
    void* reserved[9];
    int(__thiscall* invoke)(void* self, SerializerWord value);
  };

  struct SerializerSlot36RuntimeByPointer
  {
    SerializerSlot36ByPointerVTable* vtable;
  };

  struct SerializerSlot36RuntimeByValue
  {
    SerializerSlot36ByValueVTable* vtable;
  };

  EThreatTypeSerializerHelperStorage gEThreatTypeSerializerHelperStorage{};
  EThreatTypeHelperLane gEThreatTypeHelperLane = EThreatTypeHelperLane::Primitive;

  // Alias of FUN_00719FB0 behavior from CInfluenceMap.cpp.
  int InvokeEThreatTypeSerializerWordByPointerLane(void* const helperObject, SerializerWord* const valueSlot)
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByPointer*>(helperObject);
    SerializerWord value = static_cast<SerializerWord>(reinterpret_cast<std::uintptr_t>(helperObject));
    const int result = helper->vtable->invoke(helperObject, &value);
    *valueSlot = value;
    return result;
  }

  // Alias of FUN_00719FD0 behavior from CInfluenceMap.cpp.
  int InvokeEThreatTypeSerializerWordByValueLane(void* const helperObject, SerializerWord* const valueSlot)
  {
    auto* const helper = static_cast<SerializerSlot36RuntimeByValue*>(helperObject);
    return helper->vtable->invoke(helperObject, *valueSlot);
  }

  /**
   * Address: 0x007188D0 (FUN_007188D0)
   *
   * What it does:
   * Initializes startup `EThreatType` primitive-helper links and callbacks.
   */
  [[maybe_unused]] [[nodiscard]] EThreatTypeSerializerHelperStorage* InitializeEThreatTypePrimitiveHelperStorage() noexcept
  {
    InitializeHelperNode(gEThreatTypeSerializerHelperStorage);
    gEThreatTypeSerializerHelperStorage.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&InvokeEThreatTypeSerializerWordByPointerLane);
    gEThreatTypeSerializerHelperStorage.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&InvokeEThreatTypeSerializerWordByValueLane);
    gEThreatTypeHelperLane = EThreatTypeHelperLane::Primitive;
    return &gEThreatTypeSerializerHelperStorage;
  }

  /**
   * Address: 0x00719FF0 (FUN_00719FF0)
   *
   * What it does:
   * Initializes startup `EThreatType` save/load-helper links and callbacks.
   */
  [[maybe_unused]] [[nodiscard]] EThreatTypeSerializerHelperStorage* InitializeEThreatTypeSaveLoadHelperStorage() noexcept
  {
    InitializeHelperNode(gEThreatTypeSerializerHelperStorage);
    gEThreatTypeSerializerHelperStorage.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&InvokeEThreatTypeSerializerWordByPointerLane);
    gEThreatTypeSerializerHelperStorage.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&InvokeEThreatTypeSerializerWordByValueLane);
    gEThreatTypeHelperLane = EThreatTypeHelperLane::SaveLoad;
    return &gEThreatTypeSerializerHelperStorage;
  }

  /**
   * Address: 0x00719340 (FUN_00719340)
   *
   * What it does:
   * Initializes startup `SThreatSerializer` helper links and callback lanes.
   */
  [[maybe_unused]] [[nodiscard]] moho::SThreatSerializer* InitializeSThreatSerializerHelperStorage() noexcept
  {
    InitializeHelperNode(gSThreatSerializer);
    gSThreatSerializer.mLoadCallback = &moho::SThreatSerializer::Deserialize;
    gSThreatSerializer.mSaveCallback = &moho::SThreatSerializer::Serialize;
    return &gSThreatSerializer;
  }

  struct SThreatSerializerNodeBootstrap
  {
    SThreatSerializerNodeBootstrap()
    {
      (void)InitializeSThreatSerializerHelperStorage();
      (void)InitializeEThreatTypePrimitiveHelperStorage();
      (void)InitializeEThreatTypeSaveLoadHelperStorage();
    }
  };

  SThreatSerializerNodeBootstrap gSThreatSerializerNodeBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00717AF0 (FUN_00717AF0, Moho::SThreatSerializer::Deserialize)
   *
   * What it does:
   * Reads one 14-float `SThreat` record from archive.
   */
  void SThreatSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const threat = reinterpret_cast<SThreat*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || threat == nullptr) {
      return;
    }

    float* const lanes = reinterpret_cast<float*>(threat);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->ReadFloat(&lanes[i]);
    }
  }

  /**
   * Address: 0x00717B00 (FUN_00717B00, Moho::SThreatSerializer::Serialize)
   *
   * What it does:
   * Writes one 14-float `SThreat` record to archive.
   */
  void SThreatSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const threat = reinterpret_cast<const SThreat*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || threat == nullptr) {
      return;
    }

    const float* const lanes = reinterpret_cast<const float*>(threat);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->WriteFloat(lanes[i]);
    }
  }

  /**
   * Address: 0x00719370 (FUN_00719370, gpg::SerSaveLoadHelper_SThreat::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_719370(void (__cdecl **this)(...)))(...);
   */
  void SThreatSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SThreat::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00717B50 (FUN_00717B50)
   *
   * What it does:
   * Duplicated teardown lane for `SThreatSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SThreatSerializer_variant_primary()
  {
    return UnlinkHelperNode(gSThreatSerializer);
  }

  /**
   * Address: 0x00717B80 (FUN_00717B80)
   *
   * What it does:
   * Secondary duplicated teardown lane for `SThreatSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SThreatSerializer_variant_secondary()
  {
    return UnlinkHelperNode(gSThreatSerializer);
  }
} // namespace moho
