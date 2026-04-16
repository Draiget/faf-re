#include "moho/sim/ESquadClassTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

namespace
{
  alignas(moho::ESquadClassTypeInfo) unsigned char gESquadClassTypeInfoStorage[sizeof(moho::ESquadClassTypeInfo)]{};
  bool gESquadClassTypeInfoConstructed = false;
  struct ESquadClassSerializerHelper
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(ESquadClassSerializerHelper, mHelperNext) == 0x04,
    "ESquadClassSerializerHelper::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ESquadClassSerializerHelper, mHelperPrev) == 0x08,
    "ESquadClassSerializerHelper::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ESquadClassSerializerHelper, mDeserialize) == 0x0C,
    "ESquadClassSerializerHelper::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ESquadClassSerializerHelper, mSerialize) == 0x10,
    "ESquadClassSerializerHelper::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(ESquadClassSerializerHelper) == 0x14, "ESquadClassSerializerHelper size must be 0x14");

  ESquadClassSerializerHelper gESquadClassSerializerHelper{};

  /**
   * Address: 0x00723B10 (FUN_00723B10, ESquadClassTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `ESquadClassTypeInfo` object and pre-registers RTTI
   * ownership for `ESquadClass`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructESquadClassTypeInfo()
  {
    if (!gESquadClassTypeInfoConstructed) {
      new (gESquadClassTypeInfoStorage) moho::ESquadClassTypeInfo();
      gESquadClassTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::ESquadClassTypeInfo*>(gESquadClassTypeInfoStorage);
    gpg::PreRegisterRType(typeid(moho::ESquadClass), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00723BC0 (FUN_00723BC0, REnumType dtor thunk for ESquadClass block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant1(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  [[nodiscard]] gpg::RType* CachedESquadClassType()
  {
    gpg::RType* type = gpg::LookupRType(typeid(moho::ESquadClass));
    if (type == nullptr) {
      type = ConstructESquadClassTypeInfo();
    }
    return type;
  }

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

  void DeserializeESquadClassFromArchive(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::ESquadClass*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::ESquadClass>(value);
  }

  void SerializeESquadClassToArchive(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const value = reinterpret_cast<const moho::ESquadClass*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(*value));
  }

  void RegisterESquadClassSerializerCallbacks()
  {
    gpg::RType* const type = CachedESquadClassType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == gESquadClassSerializerHelper.mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == gESquadClassSerializerHelper.mSerialize);
    type->serLoadFunc_ = gESquadClassSerializerHelper.mDeserialize;
    type->serSaveFunc_ = gESquadClassSerializerHelper.mSerialize;
  }

  /**
   * Address: 0x0072A4A0 (FUN_0072A4A0)
   *
   * What it does:
   * Initializes startup ESquadClass primitive-serializer helper links and binds
   * int load/save callbacks.
   */
  [[nodiscard]] ESquadClassSerializerHelper* InitializeESquadClassPrimitiveSerializerHelper()
  {
    InitializeHelperNode(gESquadClassSerializerHelper);
    gESquadClassSerializerHelper.mDeserialize = &DeserializeESquadClassFromArchive;
    gESquadClassSerializerHelper.mSerialize = &SerializeESquadClassToArchive;
    RegisterESquadClassSerializerCallbacks();
    return &gESquadClassSerializerHelper;
  }

  /**
   * Address: 0x0072A9F0 (FUN_0072A9F0)
   *
   * What it does:
   * Reinitializes startup ESquadClass save/load helper links and rebinds the
   * same int load/save callbacks.
   */
  [[nodiscard]] ESquadClassSerializerHelper* InitializeESquadClassSaveLoadSerializerHelper()
  {
    return InitializeESquadClassPrimitiveSerializerHelper();
  }

  struct ESquadClassSerializerBootstrap
  {
    ESquadClassSerializerBootstrap()
    {
      (void)InitializeESquadClassSaveLoadSerializerHelper();
    }
  };

  [[maybe_unused]] ESquadClassSerializerBootstrap gESquadClassSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00723BA0 (FUN_00723BA0, Moho::ESquadClassTypeInfo::dtr)
   */
  ESquadClassTypeInfo::~ESquadClassTypeInfo() = default;

  /**
   * Address: 0x00723B90 (FUN_00723B90, Moho::ESquadClassTypeInfo::GetName)
   */
  const char* ESquadClassTypeInfo::GetName() const
  {
    return "ESquadClass";
  }

  /**
   * Address: 0x00723B70 (FUN_00723B70, Moho::ESquadClassTypeInfo::Init)
   */
  void ESquadClassTypeInfo::Init()
  {
    size_ = sizeof(ESquadClass);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00723BD0 (FUN_00723BD0, Moho::ESquadClassTypeInfo::AddEnums)
   */
  void ESquadClassTypeInfo::AddEnums()
  {
    mPrefix = "SQUADCLASS_";
    AddEnum(StripPrefix("SQUADCLASS_Unassigned"), static_cast<std::int32_t>(ESquadClass::Unassigned));
    AddEnum(StripPrefix("SQUADCLASS_Attack"), static_cast<std::int32_t>(ESquadClass::Attack));
    AddEnum(StripPrefix("SQUADCLASS_Artillery"), static_cast<std::int32_t>(ESquadClass::Artillery));
    AddEnum(StripPrefix("SQUADCLASS_Guard"), static_cast<std::int32_t>(ESquadClass::Guard));
    AddEnum(StripPrefix("SQUADCLASS_Support"), static_cast<std::int32_t>(ESquadClass::Support));
    AddEnum(StripPrefix("SQUADCLASS_Scout"), static_cast<std::int32_t>(ESquadClass::Scout));
  }
} // namespace moho
