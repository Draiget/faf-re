#include "moho/unit/ECommandEventTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

namespace
{
  alignas(moho::ECommandEventTypeInfo) unsigned char gECommandEventTypeInfoStorage[sizeof(moho::ECommandEventTypeInfo)];
  bool gECommandEventTypeInfoConstructed = false;
  moho::ECommandEventPrimitiveSerializer gECommandEventPrimitiveSerializer;

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <class THelper>
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

  /**
   * Address: 0x006E7D60 (FUN_006E7D60, sub_6E7D60)
   *
   * What it does:
   * Constructs the `ECommandEvent` enum type descriptor and preregisters RTTI.
   */
  gpg::REnumType* construct_ECommandEventTypeInfo_00()
  {
    if (!gECommandEventTypeInfoConstructed) {
      new (gECommandEventTypeInfoStorage) moho::ECommandEventTypeInfo();
      gECommandEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gECommandEventTypeInfoStorage);
  }

  [[nodiscard]] moho::ECommandEventTypeInfo& GetECommandEventTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ECommandEventTypeInfo*>(construct_ECommandEventTypeInfo_00());
  }

  /**
   * Address: 0x00BFEB40 (FUN_00BFEB40, sub_BFEB40)
   *
   * What it does:
   * Tears down the recovered `ECommandEvent` enum descriptor at process exit.
   */
  void cleanup_ECommandEventTypeInfo()
  {
    if (!gECommandEventTypeInfoConstructed) {
      return;
    }

    GetECommandEventTypeInfo().~ECommandEventTypeInfo();
    gECommandEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFEB50 (FUN_00BFEB50, sub_BFEB50)
   *
   * What it does:
   * Unlinks the recovered `ECommandEvent` primitive serializer helper node.
   */
  gpg::SerHelperBase* cleanup_ECommandEventPrimitiveSerializer()
  {
    return UnlinkHelperNode(gECommandEventPrimitiveSerializer);
  }

  void cleanup_ECommandEventPrimitiveSerializer_atexit()
  {
    (void)cleanup_ECommandEventPrimitiveSerializer();
  }

  /**
   * Address: 0x006EA730 (FUN_006EA730, sub_6EA730)
   *
   * What it does:
   * Reads one `int` enum lane from archive and stores it into `ECommandEvent`.
   */
  void Deserialize_ECommandEvent_00(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::ECommandEvent*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::ECommandEvent>(value);
  }

  /**
   * Address: 0x006EA750 (FUN_006EA750, sub_6EA750)
   *
   * What it does:
   * Writes one `ECommandEvent` enum lane as an `int` to archive.
   */
  void Serialize_ECommandEvent_00(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const eventValue =
      reinterpret_cast<const moho::ECommandEvent*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(*eventValue));
  }

  /**
   * Address: 0x006EA770 (FUN_006EA770)
   *
   * What it does:
   * Initializes the generic save/load helper lane for `ECommandEvent`.
   */
  [[nodiscard]] moho::ECommandEventPrimitiveSerializer* InitializeECommandEventGenericHelperLane()
  {
    InitializeHelperNode(gECommandEventPrimitiveSerializer);
    gECommandEventPrimitiveSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(
      &Deserialize_ECommandEvent_00
    );
    gECommandEventPrimitiveSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&Serialize_ECommandEvent_00);
    return &gECommandEventPrimitiveSerializer;
  }

  /**
   * Address: 0x006E9730 (FUN_006E9730)
   *
   * What it does:
   * Initializes the primitive enum helper lane for `ECommandEvent`.
   */
  [[nodiscard]] moho::ECommandEventPrimitiveSerializer* InitializeECommandEventPrimitiveHelperLane()
  {
    return InitializeECommandEventGenericHelperLane();
  }
} // namespace

namespace moho
{
  ECommandEventTypeInfo::ECommandEventTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ECommandEvent), this);
  }

  ECommandEventTypeInfo::~ECommandEventTypeInfo() = default;

  const char* ECommandEventTypeInfo::GetName() const
  {
    return "ECommandEvent";
  }

  void ECommandEventTypeInfo::Init()
  {
    size_ = sizeof(ECommandEvent);
    gpg::RType::Init();
    Finish();
  }

  void ECommandEventPrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = &GetECommandEventTypeInfo();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD8ED0 (FUN_00BD8ED0, sub_BD8ED0)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is registered and schedules teardown.
   */
  int register_ECommandEventTypeInfo()
  {
    (void)GetECommandEventTypeInfo();
    return std::atexit(&cleanup_ECommandEventTypeInfo);
  }

  /**
   * Address: 0x00BD8EF0 (FUN_00BD8EF0, sub_BD8EF0)
   *
   * What it does:
   * Registers enum primitive load/save helper callbacks for `ECommandEvent`.
   */
  int register_ECommandEventPrimitiveSerializer()
  {
    (void)InitializeECommandEventPrimitiveHelperLane();
    return std::atexit(&cleanup_ECommandEventPrimitiveSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct ECommandEventTypeInfoBootstrap
  {
    ECommandEventTypeInfoBootstrap()
    {
      (void)moho::register_ECommandEventTypeInfo();
      (void)moho::register_ECommandEventPrimitiveSerializer();
    }
  };

  ECommandEventTypeInfoBootstrap gECommandEventTypeInfoBootstrap;
} // namespace
