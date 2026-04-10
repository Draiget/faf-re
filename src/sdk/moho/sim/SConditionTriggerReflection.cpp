#include "moho/sim/SConditionTriggerTypes.h"

#include <cstdlib>
#include <cstdint>
#include <list>
#include <map>
#include <new>
#include <string>
#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/Stats.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyStats.h"

namespace
{
  constexpr const char kReflectSharedPtrHeaderPath[] =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflect_shared_ptr.h";

  class ETriggerOperatorTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0070AE30 (FUN_0070AE30, Moho::ETriggerOperatorTypeInfo::ETriggerOperatorTypeInfo)
     */
    ETriggerOperatorTypeInfo()
      : gpg::REnumType()
    {
      gpg::PreRegisterRType(typeid(moho::ETriggerOperator), this);
    }

    /**
     * Address: 0x0070AEC0 (FUN_0070AEC0, Moho::ETriggerOperatorTypeInfo::dtr)
     */
    ~ETriggerOperatorTypeInfo() override = default;

    /**
     * Address: 0x0070AEB0 (FUN_0070AEB0, Moho::ETriggerOperatorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      return "ETriggerOperator";
    }

    /**
     * Address: 0x0070AE90 (FUN_0070AE90, Moho::ETriggerOperatorTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(moho::ETriggerOperator);
      gpg::RType::Init();
      AddEnums();
      Finish();
    }

    /**
     * Address: 0x0070AEF0 (FUN_0070AEF0, sub_70AEF0)
     */
    void AddEnums()
    {
      mPrefix = "TRIGGER_";
      AddEnum(StripPrefix("TRIGGER_GreaterThan"), moho::TRIGGER_GreaterThan);
      AddEnum(StripPrefix("TRIGGER_GreaterThanOrEqual"), moho::TRIGGER_GreaterThanOrEqual);
      AddEnum(StripPrefix("TRIGGER_LessThan"), moho::TRIGGER_LessThan);
      AddEnum(StripPrefix("TRIGGER_LessThanOrEqual"), moho::TRIGGER_LessThanOrEqual);
    }
  };
  static_assert(sizeof(ETriggerOperatorTypeInfo) == 0x78, "ETriggerOperatorTypeInfo size must be 0x78");

  class SConditionTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0070AFE0 (FUN_0070AFE0, Moho::SConditionTypeInfo::SConditionTypeInfo)
     */
    SConditionTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(moho::SCondition), this);
    }

    /**
     * Address: 0x0070B070 (FUN_0070B070, Moho::SConditionTypeInfo::dtr)
     */
    ~SConditionTypeInfo() override = default;

    /**
     * Address: 0x0070B060 (FUN_0070B060, Moho::SConditionTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      return "SCondition";
    }

    /**
     * Address: 0x0070B040 (FUN_0070B040, Moho::SConditionTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(moho::SCondition);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(SConditionTypeInfo) == 0x64, "SConditionTypeInfo size must be 0x64");

  [[nodiscard]] gpg::RRef MakeSTriggerRef(moho::STrigger* const trigger)
  {
    gpg::RRef out{};
    out.mObj = trigger;
    out.mType = moho::STrigger::StaticGetClass();
    return out;
  }

  class STriggerTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0070B220 (FUN_0070B220, sub_70B220)
     */
    STriggerTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(moho::STrigger), this);
    }

    /**
     * Address: 0x0070B2D0 (FUN_0070B2D0, Moho::STriggerTypeInfo::dtr)
     */
    ~STriggerTypeInfo() override = default;

    /**
     * Address: 0x0070B2C0 (FUN_0070B2C0, Moho::STriggerTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      return "STrigger";
    }

    static gpg::RRef NewRef()
    {
      // Address: 0x00711030 (FUN_00711030)
      moho::STrigger* const object = new (std::nothrow) moho::STrigger();
      return MakeSTriggerRef(object);
    }

    static gpg::RRef CtrRef(void* const objectPtr)
    {
      // Address: 0x007110F0 (FUN_007110F0)
      auto* const object = reinterpret_cast<moho::STrigger*>(objectPtr);
      if (object) {
        new (object) moho::STrigger();
      }
      return MakeSTriggerRef(object);
    }

    static void Delete(void* const objectPtr)
    {
      // Address: 0x007110D0 (FUN_007110D0)
      auto* const object = reinterpret_cast<moho::STrigger*>(objectPtr);
      delete object;
    }

    static void Destruct(void* const objectPtr)
    {
      // Address: 0x00711190 (FUN_00711190)
      auto* const object = reinterpret_cast<moho::STrigger*>(objectPtr);
      if (object) {
        object->~STrigger();
      }
    }

    /**
     * Address: 0x0070B280 (FUN_0070B280, Moho::STriggerTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(moho::STrigger);
      newRefFunc_ = &STriggerTypeInfo::NewRef;
      ctorRefFunc_ = &STriggerTypeInfo::CtrRef;
      deleteFunc_ = &STriggerTypeInfo::Delete;
      dtrFunc_ = &STriggerTypeInfo::Destruct;
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(STriggerTypeInfo) == 0x64, "STriggerTypeInfo size must be 0x64");

  class SConditionSerializer final
  {
  public:
    /**
     * Address: 0x0070B120 (FUN_0070B120, Moho::SConditionSerializer::Deserialize)
     */
    static void Deserialize(
      gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
    )
    {
      auto* const object = reinterpret_cast<moho::SCondition*>(objectPtr);
      if (archive && object) {
        object->MemberDeserialize(archive);
      }
    }

    /**
     * Address: 0x0070B130 (FUN_0070B130, Moho::SConditionSerializer::Serialize)
     */
    static void Serialize(
      gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
    )
    {
      auto* const object = reinterpret_cast<const moho::SCondition*>(objectPtr);
      if (archive && object) {
        object->MemberSerialize(archive);
      }
    }

    void RegisterSerializeFunctions()
    {
      gpg::RType* const type = moho::SCondition::StaticGetClass();
      GPG_ASSERT(type != nullptr);
      if (!type) {
        return;
      }

      GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
      GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
      type->serLoadFunc_ = mLoadCallback;
      type->serSaveFunc_ = mSaveCallback;
    }

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(sizeof(SConditionSerializer) == 0x14, "SConditionSerializer size must be 0x14");
#endif

  class STriggerSerializer final
  {
  public:
    /**
     * Address: 0x0070B380 (FUN_0070B380, Moho::STriggerSerializer::Deserialize)
     */
    static void Deserialize(
      gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
    )
    {
      auto* const object = reinterpret_cast<moho::STrigger*>(objectPtr);
      if (archive && object) {
        object->MemberDeserialize(archive);
      }
    }

    /**
     * Address: 0x0070B390 (FUN_0070B390, Moho::STriggerSerializer::Serialize)
     */
    static void Serialize(
      gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
    )
    {
      auto* const object = reinterpret_cast<const moho::STrigger*>(objectPtr);
      if (archive && object) {
        object->MemberSerialize(archive);
      }
    }

    void RegisterSerializeFunctions()
    {
      gpg::RType* const type = moho::STrigger::StaticGetClass();
      GPG_ASSERT(type != nullptr);
      if (!type) {
        return;
      }

      GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
      GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
      type->serLoadFunc_ = mLoadCallback;
      type->serSaveFunc_ = mSaveCallback;
    }

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(sizeof(STriggerSerializer) == 0x14, "STriggerSerializer size must be 0x14");
#endif

  msvc8::string gFastVectorSConditionTypeName;
  bool gFastVectorSConditionTypeNameCleanupRegistered = false;

  [[nodiscard]] gpg::RType* CachedSConditionType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SCondition));
    }
    return cached;
  }

  void cleanup_FastVectorSConditionTypeName()
  {
    gFastVectorSConditionTypeName = msvc8::string{};
    gFastVectorSConditionTypeNameCleanupRegistered = false;
  }

  class RFastVectorSConditionTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    RFastVectorSConditionTypeInfo()
      : gpg::RType()
      , gpg::RIndexed()
    {
      gpg::PreRegisterRType(typeid(gpg::fastvector<moho::SCondition>), this);
    }

    ~RFastVectorSConditionTypeInfo() override = default;

    /**
     * Address: 0x0070E620 (FUN_0070E620, gpg::RFastVectorType_SCondition::GetName)
     *
     * What it does:
     * Lazily builds and caches the reflected `fastvector<SCondition>` name and
     * registers process-exit cleanup for the cached string storage.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if (gFastVectorSConditionTypeName.empty()) {
        const gpg::RType* const elementType = CachedSConditionType();
        const char* const elementName = elementType ? elementType->GetName() : "SCondition";
        gFastVectorSConditionTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SCondition");
        if (!gFastVectorSConditionTypeNameCleanupRegistered) {
          gFastVectorSConditionTypeNameCleanupRegistered = true;
          (void)std::atexit(&cleanup_FastVectorSConditionTypeName);
        }
      }

      return gFastVectorSConditionTypeName.c_str();
    }

    /**
     * Address: 0x0070E6E0 (FUN_0070E6E0, gpg::RFastVectorType_SCondition::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current fastvector size.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
    }

    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override
    {
      return this;
    }

    static void Deserialize(gpg::ReadArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto& view = gpg::AsFastVectorRuntimeView<moho::SCondition>(reinterpret_cast<void*>(objectPtr));
      unsigned int count = 0;
      archive->ReadUInt(&count);

      const moho::SCondition fill{};
      gpg::FastVectorRuntimeResizeFill(&fill, count, view);

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        archive->Read(moho::SCondition::StaticGetClass(), view.ElementAtUnchecked(i), owner);
      }
    }

    static void Serialize(gpg::WriteArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      const auto& view = gpg::AsFastVectorRuntimeView<moho::SCondition>(reinterpret_cast<void*>(objectPtr));
      const unsigned int count = static_cast<unsigned int>(view.Size());
      archive->WriteUInt(count);

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        archive->Write(moho::SCondition::StaticGetClass(), view.ElementAtUnchecked(i), owner);
      }
    }

    void Init() override
    {
      size_ = 0x10;
      version_ = 1;
      serLoadFunc_ = &RFastVectorSConditionTypeInfo::Deserialize;
      serSaveFunc_ = &RFastVectorSConditionTypeInfo::Serialize;
    }

    gpg::RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      gpg::RRef out{};
      out.mType = moho::SCondition::StaticGetClass();

      if (!obj || ind < 0) {
        return out;
      }

      auto& view = gpg::AsFastVectorRuntimeView<moho::SCondition>(obj);
      if (!view.Data() || static_cast<std::size_t>(ind) >= view.Size()) {
        return out;
      }

      out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
      return out;
    }

    size_t GetCount(void* const obj) const override
    {
      if (!obj) {
        return 0u;
      }

      const auto& view = gpg::AsFastVectorRuntimeView<moho::SCondition>(obj);
      return view.Data() ? view.Size() : 0u;
    }

    void SetCount(void* const obj, const int count) const override
    {
      if (!obj || count < 0) {
        return;
      }

      auto& view = gpg::AsFastVectorRuntimeView<moho::SCondition>(obj);
      const moho::SCondition fill{};
      gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
    }
  };
  static_assert(sizeof(RFastVectorSConditionTypeInfo) == 0x68, "RFastVectorSConditionTypeInfo size must be 0x68");

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  extern msvc8::string gSharedPtrSTriggerTypeName;
  extern std::uint32_t gSharedPtrSTriggerTypeNameInitGuard;
  extern msvc8::string gListSharedPtrSTriggerTypeName;
  extern std::uint32_t gListSharedPtrSTriggerTypeNameInitGuard;
  void cleanup_SharedPtrSTriggerTypeName();
  void cleanup_ListSharedPtrSTriggerTypeName();

  [[nodiscard]] gpg::RType* CachedSharedPtrSTriggerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(boost::shared_ptr<moho::STrigger>));
    }
    return cached;
  }

  class RSharedPointerSTriggerTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    RSharedPointerSTriggerTypeInfo()
      : gpg::RType()
      , gpg::RIndexed()
    {
      gpg::PreRegisterRType(typeid(boost::shared_ptr<moho::STrigger>), this);
    }

    ~RSharedPointerSTriggerTypeInfo() override = default;

    /**
     * Address: 0x0070EA60 (FUN_0070EA60, gpg::RSharedPointerType_STrigger::GetName)
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gSharedPtrSTriggerTypeNameInitGuard & 1u) == 0u) {
        gSharedPtrSTriggerTypeNameInitGuard |= 1u;

        gpg::RType* triggerType = moho::STrigger::StaticGetClass();
        if (triggerType == nullptr) {
          triggerType = gpg::LookupRType(typeid(moho::STrigger));
        }
        const char* const triggerName = triggerType != nullptr ? triggerType->GetName() : "STrigger";
        gSharedPtrSTriggerTypeName = gpg::STR_Printf("boost::shared_ptr<%s>", triggerName);
        (void)std::atexit(&cleanup_SharedPtrSTriggerTypeName);
      }
      return gSharedPtrSTriggerTypeName.c_str();
    }

    /**
     * Address: 0x0070EB10 (FUN_0070EB10, gpg::RSharedPointerType_STrigger::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      auto* const ptr = static_cast<boost::shared_ptr<moho::STrigger>*>(ref.mObj);
      if (!ptr || !ptr->get()) {
        return msvc8::string("NULL");
      }

      gpg::RRef objectRef{};
      objectRef.mObj = ptr->get();
      objectRef.mType = moho::STrigger::StaticGetClass();
      return gpg::STR_Printf("[%s]", objectRef.GetLexical().c_str());
    }

    /**
     * Address: 0x0070EC90 (FUN_0070EC90, gpg::RSharedPointerType_STrigger::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override
    {
      return this;
    }

    /**
     * Address: 0x0070ECA0 (FUN_0070ECA0, gpg::RSharedPointerType_STrigger::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override
    {
      return this;
    }

    static void Deserialize(gpg::ReadArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const out = reinterpret_cast<boost::shared_ptr<moho::STrigger>*>(objectPtr);
      if (!archive || !out) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, owner);
      if (!tracked.object) {
        *out = boost::shared_ptr<moho::STrigger>();
        return;
      }

      if (tracked.state == gpg::TrackedPointerState::Unowned) {
        GPG_ASSERT(tracked.type != nullptr && tracked.type->deleteFunc_ != nullptr);
        auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
          tracked.object, ReflectedObjectDeleter{tracked.type ? tracked.type->deleteFunc_ : nullptr}
        );
        tracked.sharedObject = tracked.object;
        tracked.sharedControl = control;
        tracked.state = gpg::TrackedPointerState::Shared;
      }

      gpg::RRef sourceRef{};
      sourceRef.mObj = tracked.object;
      sourceRef.mType = tracked.type ? tracked.type : moho::STrigger::StaticGetClass();
      const gpg::RRef upcastRef = gpg::REF_UpcastPtr(sourceRef, moho::STrigger::StaticGetClass());
      if (!upcastRef.mObj) {
        *out = boost::shared_ptr<moho::STrigger>();
        return;
      }

      boost::SharedPtrRaw<moho::STrigger> raw{};
      raw.px = static_cast<moho::STrigger*>(upcastRef.mObj);
      raw.pi = tracked.sharedControl;
      *out = boost::SharedPtrFromRawRetained(raw);
    }

    static void Serialize(gpg::WriteArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const pointer = reinterpret_cast<const boost::shared_ptr<moho::STrigger>*>(objectPtr);
      if (!archive || !pointer) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      const boost::SharedPtrRaw<moho::STrigger> raw = boost::SharedPtrRawFromSharedBorrow(*pointer);

      gpg::RRef objectRef{};
      objectRef.mObj = raw.px;
      objectRef.mType = moho::STrigger::StaticGetClass();
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Shared, owner);
    }

    /**
     * Address: 0x0070EB00 (FUN_0070EB00, gpg::RSharedPointerType_STrigger::Init)
     */
    void Init() override
    {
      size_ = sizeof(boost::shared_ptr<moho::STrigger>);
      version_ = 1;
      serLoadFunc_ = &RSharedPointerSTriggerTypeInfo::Deserialize;
      serSaveFunc_ = &RSharedPointerSTriggerTypeInfo::Serialize;
    }

    /**
     * Address: 0x0070ECC0 (FUN_0070ECC0, gpg::RSharedPointerType_STrigger::SubscriptIndex)
     *
     * What it does:
     * Asserts `index == 0` and returns the pointee of `boost::shared_ptr<STrigger>` as an `RRef`.
     */
    gpg::RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      if (ind != 0) {
        gpg::HandleAssertFailure("index == 0", 65, kReflectSharedPtrHeaderPath);
      }

      auto* const ptr = static_cast<boost::shared_ptr<moho::STrigger>*>(obj);
      return MakeSTriggerRef(ptr->get());
    }

    size_t GetCount(void* const obj) const override
    {
      if (!obj) {
        return 0u;
      }
      auto* const ptr = static_cast<boost::shared_ptr<moho::STrigger>*>(obj);
      return (ptr && ptr->get()) ? 1u : 0u;
    }
  };
  static_assert(sizeof(RSharedPointerSTriggerTypeInfo) == 0x68, "RSharedPointerSTriggerTypeInfo size must be 0x68");

  class RListSharedPtrSTriggerTypeInfo final : public gpg::RType
  {
  public:
    RListSharedPtrSTriggerTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(std::list<boost::shared_ptr<moho::STrigger>>), this);
    }

    ~RListSharedPtrSTriggerTypeInfo() override = default;

    /**
     * Address: 0x0070F360 (FUN_0070F360, gpg::RListType_shared_ptr_STrigger::GetName)
     *
     * What it does:
     * Lazily builds and caches the reflected lexical type label
     * `list<boost::shared_ptr<STrigger>>`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gListSharedPtrSTriggerTypeNameInitGuard & 1u) == 0u) {
        gListSharedPtrSTriggerTypeNameInitGuard |= 1u;

        gpg::RType* valueType = CachedSharedPtrSTriggerType();
        const char* const valueTypeName = valueType ? valueType->GetName() : "boost::shared_ptr<STrigger>";
        gListSharedPtrSTriggerTypeName =
          gpg::STR_Printf("list<%s>", valueTypeName ? valueTypeName : "boost::shared_ptr<STrigger>");
        (void)std::atexit(&cleanup_ListSharedPtrSTriggerTypeName);
      }

      return gListSharedPtrSTriggerTypeName.c_str();
    }

    /**
     * Address: 0x0070F420 (FUN_0070F420, gpg::RListType_shared_ptr_STrigger::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current list element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const list = static_cast<const std::list<boost::shared_ptr<moho::STrigger>>*>(ref.mObj);
      const int size = list ? static_cast<int>(list->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
    }
  };
  static_assert(sizeof(RListSharedPtrSTriggerTypeInfo) == 0x64, "RListSharedPtrSTriggerTypeInfo size must be 0x64");

  using UnitBlueprintWeightMap = std::map<const moho::RUnitBlueprint*, float>;
  using StringToArmyStatItemMap = std::map<std::string, moho::CArmyStatItem*>;
  msvc8::string gSharedPtrSTriggerTypeName{};
  std::uint32_t gSharedPtrSTriggerTypeNameInitGuard = 0u;
  msvc8::string gListSharedPtrSTriggerTypeName{};
  std::uint32_t gListSharedPtrSTriggerTypeNameInitGuard = 0u;
  msvc8::string gMapUnitBlueprintFloatTypeName{};
  std::uint32_t gMapUnitBlueprintFloatTypeNameInitGuard = 0u;
  msvc8::string gMapStringArmyStatItemPtrTypeName{};
  std::uint32_t gMapStringArmyStatItemPtrTypeNameInitGuard = 0u;
  msvc8::string gStatsCArmyStatItemTypeName{};
  std::uint32_t gStatsCArmyStatItemTypeNameInitGuard = 0u;

  /**
   * Address: 0x00BFF940 (sub_BFF940)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RSharedPointerType_STrigger::GetName`.
   */
  void cleanup_SharedPtrSTriggerTypeName()
  {
    gSharedPtrSTriggerTypeName.clear();
    gSharedPtrSTriggerTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00BFF880 (FUN_00BFF880, cleanup_ListSharedPtrSTriggerTypeName)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RListType_shared_ptr_STrigger::GetName`.
   */
  void cleanup_ListSharedPtrSTriggerTypeName()
  {
    gListSharedPtrSTriggerTypeName.clear();
    gListSharedPtrSTriggerTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00BFF910 (FUN_00BFF910)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RMapType_RUnitBlueprintP_float::GetName`.
   */
  void cleanup_MapUnitBlueprintFloatTypeName()
  {
    gMapUnitBlueprintFloatTypeName.clear();
    gMapUnitBlueprintFloatTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00BFF8B0 (FUN_00BFF8B0)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RMapType_string_CArmyStateItemP::GetName`.
   */
  void cleanup_MapStringArmyStatItemPtrTypeName()
  {
    gMapStringArmyStatItemPtrTypeName.clear();
    gMapStringArmyStatItemPtrTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00BFF8E0 (FUN_00BFF8E0, cleanup_StatsCArmyStatItemTypeName)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::StatsRType_CArmyStatItem::GetName`.
   */
  void cleanup_StatsCArmyStatItemTypeName()
  {
    gStatsCArmyStatItemTypeName.clear();
    gStatsCArmyStatItemTypeNameInitGuard = 0u;
  }

  class RMapUnitBlueprintFloatTypeInfo final : public gpg::RType
  {
  public:
    RMapUnitBlueprintFloatTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(UnitBlueprintWeightMap), this);
    }

    ~RMapUnitBlueprintFloatTypeInfo() override = default;

    /**
     * Address: 0x0070ED30 (FUN_0070ED30, gpg::RMapType_RUnitBlueprintP_float::GetName)
     *
     * What it does:
     * Builds/caches one lexical map type label from runtime key/value RTTI
     * names and returns `"map<key,value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gMapUnitBlueprintFloatTypeNameInitGuard & 1u) == 0u) {
        gMapUnitBlueprintFloatTypeNameInitGuard |= 1u;

        gpg::RType* keyType = gpg::LookupRType(typeid(const moho::RUnitBlueprint*));
        if (keyType == nullptr) {
          keyType = gpg::LookupRType(typeid(moho::RUnitBlueprint*));
        }

        gpg::RType* valueType = gpg::LookupRType(typeid(float));
        const char* const keyName = keyType != nullptr ? keyType->GetName() : "Moho::RUnitBlueprint const *";
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "float";

        gMapUnitBlueprintFloatTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
        (void)std::atexit(&cleanup_MapUnitBlueprintFloatTypeName);
      }

      return gMapUnitBlueprintFloatTypeName.c_str();
    }

    /**
     * Address: 0x0070EE00 (FUN_0070EE00, gpg::RMapType_RUnitBlueprintP_float::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current map element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const map = static_cast<const UnitBlueprintWeightMap*>(ref.mObj);
      const int size = map ? static_cast<int>(map->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
    }

    /**
     * Address: 0x0070EDE0 (FUN_0070EDE0, gpg::RMapType_RUnitBlueprintP_float::Init)
     *
     * What it does:
     * Sets reflected map storage size/version lanes.
     */
    void Init() override
    {
      size_ = sizeof(UnitBlueprintWeightMap);
      version_ = 1;
    }
  };

  class StatsCArmyStatItemTypeInfo final : public gpg::RType
  {
  public:
    StatsCArmyStatItemTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(moho::Stats<moho::CArmyStatItem>), this);
    }

    ~StatsCArmyStatItemTypeInfo() override = default;

    /**
     * Address: 0x0070F130 (FUN_0070F130, Moho::StatsRType_CArmyStatItem::GetName)
     *
     * What it does:
     * Lazily builds and caches reflected lexical type label
     * `Stats<CArmyStatItem>` using runtime RTTI element name.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gStatsCArmyStatItemTypeNameInitGuard & 1u) == 0u) {
        gStatsCArmyStatItemTypeNameInitGuard |= 1u;

        gpg::RType* itemType = moho::CArmyStatItem::sType;
        if (itemType == nullptr) {
          itemType = gpg::LookupRType(typeid(moho::CArmyStatItem));
          moho::CArmyStatItem::sType = itemType;
        }
        const char* const itemTypeName = itemType != nullptr ? itemType->GetName() : "CArmyStatItem";
        gStatsCArmyStatItemTypeName = gpg::STR_Printf("Stats<%s>", itemTypeName ? itemTypeName : "CArmyStatItem");
        (void)std::atexit(&cleanup_StatsCArmyStatItemTypeName);
      }

      return gStatsCArmyStatItemTypeName.c_str();
    }

    void Init() override
    {
      size_ = sizeof(moho::Stats<moho::CArmyStatItem>);
      gpg::RType::Init();
      Finish();
    }
  };

  class RMapStringArmyStatItemPtrTypeInfo final : public gpg::RType
  {
  public:
    RMapStringArmyStatItemPtrTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(StringToArmyStatItemMap), this);
    }

    ~RMapStringArmyStatItemPtrTypeInfo() override = default;

    /**
     * Address: 0x0070F200 (FUN_0070F200, gpg::RMapType_string_CArmyStateItemP::GetName)
     *
     * What it does:
     * Builds/caches one lexical map type label from runtime key/value RTTI
     * names and returns `"map<key,value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gMapStringArmyStatItemPtrTypeNameInitGuard & 1u) == 0u) {
        gMapStringArmyStatItemPtrTypeNameInitGuard |= 1u;

        gpg::RType* keyType = gpg::LookupRType(typeid(std::string));
        if (keyType == nullptr) {
          keyType = gpg::LookupRType(typeid(msvc8::string));
        }

        gpg::RType* valueType = gpg::LookupRType(typeid(moho::CArmyStatItem*));
        const char* const keyName = keyType != nullptr ? keyType->GetName() : "std::string";
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "Moho::CArmyStatItem *";

        gMapStringArmyStatItemPtrTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
        (void)std::atexit(&cleanup_MapStringArmyStatItemPtrTypeName);
      }

      return gMapStringArmyStatItemPtrTypeName.c_str();
    }

    /**
     * Address: 0x0070F2D0 (FUN_0070F2D0, gpg::RMapType_string_CArmyStateItemP::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current map element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const map = static_cast<const StringToArmyStatItemMap*>(ref.mObj);
      const int size = map ? static_cast<int>(map->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
    }

    /**
     * Address: 0x0070F2B0 (FUN_0070F2B0, gpg::RMapType_string_CArmyStateItemP::Init)
     *
     * What it does:
     * Sets reflected map storage size/version lanes.
     */
    void Init() override
    {
      size_ = sizeof(StringToArmyStatItemMap);
      version_ = 1;
    }
  };

  ETriggerOperatorTypeInfo gETriggerOperatorTypeInfo;
  SConditionTypeInfo gSConditionTypeInfo;
  SConditionSerializer gSConditionSerializer;
  STriggerTypeInfo gSTriggerTypeInfo;
  STriggerSerializer gSTriggerSerializer;

  RFastVectorSConditionTypeInfo gFastVectorSConditionTypeInfo;
  RSharedPointerSTriggerTypeInfo gSharedPointerSTriggerTypeInfo;
  RListSharedPtrSTriggerTypeInfo gListSharedPtrSTriggerTypeInfo;
  RMapUnitBlueprintFloatTypeInfo gMapUnitBlueprintFloatTypeInfo;
  StatsCArmyStatItemTypeInfo gStatsCArmyStatItemTypeInfo;
  RMapStringArmyStatItemPtrTypeInfo gMapStringArmyStatItemPtrTypeInfo;

  std::string gDesktopPath;

  /**
   * Address: 0x00712D40 (FUN_00712D40, GetFastVectorSConditionTypeInfo)
   */
  [[nodiscard]] gpg::RType* GetFastVectorSConditionTypeInfo()
  {
    return &gFastVectorSConditionTypeInfo;
  }

  /**
   * Address: 0x00712DB0 (FUN_00712DB0, GetSharedPtrSTriggerTypeInfo)
   */
  [[nodiscard]] gpg::RType* GetSharedPtrSTriggerTypeInfo()
  {
    return &gSharedPointerSTriggerTypeInfo;
  }

  /**
   * Address: 0x00712E20 (FUN_00712E20, GetMapUnitBlueprintFloatTypeInfo)
   */
  [[nodiscard]] gpg::RType* GetMapUnitBlueprintFloatTypeInfo()
  {
    return &gMapUnitBlueprintFloatTypeInfo;
  }

  /**
   * Address: 0x00712E80 (FUN_00712E80, GetStatsCArmyStatItemTypeInfo)
   */
  [[nodiscard]] gpg::RType* GetStatsCArmyStatItemTypeInfo()
  {
    return &gStatsCArmyStatItemTypeInfo;
  }

  /**
   * Address: 0x00712EE0 (FUN_00712EE0, GetMapStringArmyStatItemPtrTypeInfo)
   */
  [[nodiscard]] gpg::RType* GetMapStringArmyStatItemPtrTypeInfo()
  {
    return &gMapStringArmyStatItemPtrTypeInfo;
  }

  /**
   * Address: 0x0070F8E0 (FUN_0070F8E0, sub_70F8E0)
   */
  void DeserializeETriggerOperator(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const value = reinterpret_cast<int*>(objectPtr);
    if (archive && value) {
      archive->ReadInt(value);
    }
  }

  /**
   * Address: 0x0070F900 (FUN_0070F900, sub_70F900)
   */
  void SerializeETriggerOperator(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const value = reinterpret_cast<const int*>(objectPtr);
    if (archive && value) {
      archive->WriteInt(*value);
    }
  }

  /**
   * Address: 0x0070B180 (FUN_0070B180, UnlinkSConditionSerializerHelper)
   */
  gpg::SerHelperBase* UnlinkSConditionSerializerHelper()
  {
    auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSConditionSerializer.mHelperNext);
    GPG_ASSERT(gSConditionSerializer.mHelperNext != nullptr);
    GPG_ASSERT(gSConditionSerializer.mHelperPrev != nullptr);
    gSConditionSerializer.mHelperNext->mPrev = gSConditionSerializer.mHelperPrev;
    gSConditionSerializer.mHelperPrev->mNext = gSConditionSerializer.mHelperNext;
    gSConditionSerializer.mHelperPrev = self;
    gSConditionSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x0070B1B0 (FUN_0070B1B0, UnlinkSConditionSerializerHelperAlias)
   */
  gpg::SerHelperBase* UnlinkSConditionSerializerHelperAlias()
  {
    return UnlinkSConditionSerializerHelper();
  }

  /**
   * Address: 0x0070B3D0 (FUN_0070B3D0, UnlinkSTriggerSerializerHelper)
   */
  gpg::SerHelperBase* UnlinkSTriggerSerializerHelper()
  {
    auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSTriggerSerializer.mHelperNext);
    GPG_ASSERT(gSTriggerSerializer.mHelperNext != nullptr);
    GPG_ASSERT(gSTriggerSerializer.mHelperPrev != nullptr);
    gSTriggerSerializer.mHelperNext->mPrev = gSTriggerSerializer.mHelperPrev;
    gSTriggerSerializer.mHelperPrev->mNext = gSTriggerSerializer.mHelperNext;
    gSTriggerSerializer.mHelperPrev = self;
    gSTriggerSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x0070B400 (FUN_0070B400, UnlinkSTriggerSerializerHelperAlias)
   */
  gpg::SerHelperBase* UnlinkSTriggerSerializerHelperAlias()
  {
    return UnlinkSTriggerSerializerHelper();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD9FE0 (FUN_00BD9FE0, register_ETriggerOperatorTypeInfo)
   */
  void register_ETriggerOperatorTypeInfo()
  {
    (void)gETriggerOperatorTypeInfo;
  }

  /**
   * Address: 0x00BDA000 (FUN_00BDA000, sub_BDA000)
   */
  void register_ETriggerOperatorPrimitiveSerializer()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(ETriggerOperator));
    GPG_ASSERT(type != nullptr);
    if (!type) {
      return;
    }

    type->serLoadFunc_ = &DeserializeETriggerOperator;
    type->serSaveFunc_ = &SerializeETriggerOperator;
  }

  /**
   * Address: 0x00BDA040 (FUN_00BDA040, register_SConditionTypeInfo)
   */
  void register_SConditionTypeInfo()
  {
    (void)gSConditionTypeInfo;
  }

  /**
   * Address: 0x00BDA060 (FUN_00BDA060, register_SConditionSerializer)
   */
  void register_SConditionSerializer()
  {
    auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSConditionSerializer.mHelperNext);
    gSConditionSerializer.mHelperNext = self;
    gSConditionSerializer.mHelperPrev = self;
    gSConditionSerializer.mLoadCallback = &SConditionSerializer::Deserialize;
    gSConditionSerializer.mSaveCallback = &SConditionSerializer::Serialize;
    gSConditionSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00BDA0A0 (FUN_00BDA0A0, sub_BDA0A0)
   */
  void register_STriggerTypeInfo()
  {
    (void)gSTriggerTypeInfo;
  }

  /**
   * Address: 0x00BDA0C0 (FUN_00BDA0C0, register_STriggerSerializer)
   */
  void register_STriggerSerializer()
  {
    auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&gSTriggerSerializer.mHelperNext);
    gSTriggerSerializer.mHelperNext = self;
    gSTriggerSerializer.mHelperPrev = self;
    gSTriggerSerializer.mLoadCallback = &STriggerSerializer::Deserialize;
    gSTriggerSerializer.mSaveCallback = &STriggerSerializer::Serialize;
    gSTriggerSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00BDA160 (FUN_00BDA160, sub_BDA160)
   */
  void register_desktop_path_string()
  {
    gDesktopPath.clear();
  }

  /**
   * Address: 0x00BDA250 (FUN_00BDA250, sub_BDA250)
   */
  void register_fastvector_SCondition_type()
  {
    (void)GetFastVectorSConditionTypeInfo();
  }

  /**
   * Address: 0x00BDA270 (FUN_00BDA270, sub_BDA270)
   */
  void register_shared_ptr_STrigger_type()
  {
    (void)GetSharedPtrSTriggerTypeInfo();
  }

  /**
   * Address: 0x00BDA290 (FUN_00BDA290, sub_BDA290)
   */
  void register_map_RUnitBlueprintFloat_type()
  {
    (void)GetMapUnitBlueprintFloatTypeInfo();
  }

  /**
   * Address: 0x00BDA2B0 (FUN_00BDA2B0, sub_BDA2B0)
   */
  void register_stats_CArmyStatItem_type()
  {
    (void)GetStatsCArmyStatItemTypeInfo();
  }

  /**
   * Address: 0x00BDA2D0 (FUN_00BDA2D0, sub_BDA2D0)
   */
  void register_map_StringCArmyStatItemPtr_type()
  {
    (void)GetMapStringArmyStatItemPtrTypeInfo();
  }
} // namespace moho

namespace
{
  struct SConditionTriggerBootstrap
  {
    SConditionTriggerBootstrap()
    {
      moho::register_ETriggerOperatorTypeInfo();
      moho::register_ETriggerOperatorPrimitiveSerializer();
      moho::register_SConditionTypeInfo();
      moho::register_SConditionSerializer();
      moho::register_STriggerTypeInfo();
      moho::register_STriggerSerializer();
      moho::register_desktop_path_string();
      moho::register_fastvector_SCondition_type();
      moho::register_shared_ptr_STrigger_type();
      moho::register_map_RUnitBlueprintFloat_type();
      moho::register_stats_CArmyStatItem_type();
      moho::register_map_StringCArmyStatItemPtr_type();
    }
  };

  SConditionTriggerBootstrap gSConditionTriggerBootstrap;
} // namespace
