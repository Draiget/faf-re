#include "legacy/containers/Vector.h"
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
#include "gpg/core/reflection/RListType.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/misc/Stats.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyStats.h"
#include "gpg/core/reflection/RSharedPointerType.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
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
     * Address: 0x0070E9A0 (FUN_0070E9A0)
     *
     * What it does:
     * Installs `STrigger` allocation/construct/delete/destruct callback slots
     * on one reflected type descriptor.
     */
    static gpg::RType* AssignSTriggerLifecycleCallbacks(gpg::RType* const typeInfo)
    {
      typeInfo->newRefFunc_ = &STriggerTypeInfo::NewRef;
      typeInfo->ctorRefFunc_ = &STriggerTypeInfo::CtrRef;
      typeInfo->deleteFunc_ = &STriggerTypeInfo::Delete;
      typeInfo->dtrFunc_ = &STriggerTypeInfo::Destruct;
      return typeInfo;
    }

    /**
     * Address: 0x0070B280 (FUN_0070B280, Moho::STriggerTypeInfo::Init)
     */
    void Init() override
    {
      size_ = sizeof(moho::STrigger);
      (void)AssignSTriggerLifecycleCallbacks(this);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(STriggerTypeInfo) == 0x64, "STriggerTypeInfo size must be 0x64");

#if defined(MOHO_ABI_MSVC8_COMPAT)
#endif

#if defined(MOHO_ABI_MSVC8_COMPAT)
#endif

  [[nodiscard]] gpg::RType* CachedSConditionType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SCondition));
    }
    return cached;
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

    /**
     * Address: 0x00713130 (FUN_00713130, gpg::RFastVectorType_SCondition::dtr)
     */
    ~RFastVectorSConditionTypeInfo() override = default;

    /**
     * Address: 0x0070E620 (FUN_0070E620, gpg::RFastVectorType_SCondition::GetName)
     * Address: 0x00BFF970 (FUN_00BFF970, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `fastvector<SCondition>` once and returns it.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = gpg::STR_Printf("fastvector<%s>", CachedSConditionType()->GetName());
      return sName.c_str();
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

    /**
     * Address: 0x0070F950 (FUN_0070F950, gpg::RFastVectorType_SCondition::SerLoad)
     *
     * IDA signature:
     * void __cdecl sub_70F950(gpg::ReadArchive *a1, _DWORD *a2, int a3, gpg::RRef *a6);
     *
     * What it does:
     * Inverse of `Serialize` (0x0070FA50): reads the element count through
     * `ReadArchive::ReadUInt`, sizes the `fastvector<SCondition>` lane to it
     * with a default-constructed fill element, then reads each element back
     * through the reflected `SCondition` type.
     *
     * The binary's element walk strides by 56 (`v6 += 56`), confirming
     * `sizeof(moho::SCondition) == 56`, and caches the reflected type in the
     * `Moho::SCondition::sType` static, populating it on first use via
     * `gpg::LookupRType` — which is exactly what
     * `moho::SCondition::StaticGetClass()` does here. The `Resize` call is
     * the `gpg::fastvector<SCondition>::Resize` emission at 0x0070FC40, and
     * the `operator delete[]` right after it is that call's inlined
     * scratch-buffer teardown, not a source statement.
     *
     * Invocation: installed as this type's `serLoadFunc_` in the
     * registration block below, which is how the archive layer reaches it.
     */
    static void Deserialize(gpg::ReadArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto& vec = *reinterpret_cast<gpg::fastvector_n<moho::SCondition, 2>*>(objectPtr);
      unsigned int count = 0;
      archive->ReadUInt(&count);

      const moho::SCondition fill{};
      vec.Resize(static_cast<std::size_t>(count), fill);

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        archive->Read(moho::SCondition::StaticGetClass(), &vec[i], owner);
      }
    }

    /**
     * Address: 0x0070FA50 (FUN_0070FA50)
     *
     * What it does:
     * Serializes one `fastvector<SCondition>` lane by writing element count and
     * then each `SCondition` payload through reflected write callbacks.
     */
    static void Serialize(gpg::WriteArchive* archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto& vec = *reinterpret_cast<gpg::fastvector_n<moho::SCondition, 2>*>(objectPtr);
      const unsigned int count = static_cast<unsigned int>(vec.size());
      archive->WriteUInt(count);

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0; i < count; ++i) {
        archive->Write(moho::SCondition::StaticGetClass(), &vec[i], owner);
      }
    }

    void Init() override
    {
      static_assert(sizeof(gpg::core::FastVectorInline<moho::SCondition>) == 0x10, "gpg::core::FastVectorInline<moho::SCondition> is 0x10 bytes on x86");
      size_ = sizeof(gpg::core::FastVectorInline<moho::SCondition>);
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

      auto& vec = *static_cast<gpg::fastvector_n<moho::SCondition, 2>*>(obj);
      if (vec.Data() == nullptr || static_cast<std::size_t>(ind) >= vec.size()) {
        return out;
      }

      out.mObj = &vec[static_cast<std::size_t>(ind)];
      return out;
    }

    size_t GetCount(void* const obj) const override
    {
      if (!obj) {
        return 0u;
      }

      auto& vec = *static_cast<gpg::fastvector_n<moho::SCondition, 2>*>(obj);
      return vec.size();
    }

    /**
     * Address: 0x0070E7A0 (FUN_0070E7A0, gpg::RFastVectorType_SCondition::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<SCondition>` lane and value-initializes
     * appended elements.
     */
    void SetCount(void* const obj, const int count) const override
    {
      if (!obj || count < 0) {
        return;
      }

      auto& vec = *static_cast<gpg::fastvector_n<moho::SCondition, 2>*>(obj);
      const moho::SCondition fill{};
      vec.Resize(static_cast<unsigned int>(count), fill);
    }
  };
  static_assert(sizeof(RFastVectorSConditionTypeInfo) == 0x68, "RFastVectorSConditionTypeInfo size must be 0x68");

  using UnitBlueprintWeightMap = std::map<const moho::RUnitBlueprint*, float>;
  using StringToArmyStatItemMap = std::map<std::string, moho::CArmyStatItem*>;

  /**
   * Address: 0x0070FE00 (FUN_0070FE00, gpg::RMapType_RUnitBlueprintP_float::SerLoad)
   *
   * What it does:
   * Clears destination storage, then reads `count` serialized
   * `RUnitBlueprint* -> float` lanes from the archive.
   */
  void DeserializeUnitBlueprintWeightMap(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<UnitBlueprintWeightMap*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);
    destination->clear();

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int index = 0u; index < count; ++index) {
      moho::RUnitBlueprint* blueprint = nullptr;
      float value = 0.0f;
      archive->ReadPointer(&blueprint, &owner);
      archive->ReadFloat(&value);
      (*destination)[blueprint] = value;
    }
  }

  /**
   * Address: 0x0070FEB0 (FUN_0070FEB0, gpg::RMapType_RUnitBlueprintP_float::SerSave)
   *
   * What it does:
   * Writes map size followed by each `RUnitBlueprint* -> float` pair in
   * map-order.
   */
  void SerializeUnitBlueprintWeightMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const UnitBlueprintWeightMap*>(objectPtr);
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);
    if (source == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (const auto& entry : *source) {
      archive->WritePointer<moho::RUnitBlueprint>(const_cast<moho::RUnitBlueprint*>(entry.first), gpg::TrackedPointerState::Unowned, owner);
      archive->WriteFloat(entry.second);
    }
  }

  /**
   * Address: 0x00710460 (FUN_00710460,
   * gpg::RMapType_string_CArmyStateItemP::SerLoad)
   *
   * What it does:
   * Clears destination storage, then reads `count` serialized
   * `string -> CArmyStatItem*` lanes from the archive.
   *
   * Paired with the save lane at 0x007105A0 below, which the same `Init`
   * installs as `serSaveFunc_`. The binary reaches the count through the
   * archive vtable slot at +0x20, then per entry calls the named import
   * `gpg::ReadArchive::ReadPointer_CArmyStatItem` and assigns the key
   * through `std::string::assign(str, 0, -1)` before the map insert -- the
   * import is what identifies this body rather than its sibling.
   */
  void DeserializeStringArmyStatItemMap(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const destination = reinterpret_cast<StringToArmyStatItemMap*>(objectPtr);
    unsigned int count = 0u;
    archive->ReadUInt(&count);
    destination->clear();

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int index = 0u; index < count; ++index) {
      msvc8::string key{};
      moho::CArmyStatItem* value = nullptr;
      archive->ReadString(&key);
      archive->ReadPointer(&value, &owner);
      (*destination)[key.c_str()] = value;
    }
  }

  /**
   * Address: 0x007105A0 (FUN_007105A0, gpg::RMapType_string_CArmyStateItemP::SerSave)
   *
   * What it does:
   * Writes map size followed by each `string -> CArmyStatItem*` pair in
   * map-order.
   */
  void SerializeStringArmyStatItemMap(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const auto* const source = reinterpret_cast<const StringToArmyStatItemMap*>(objectPtr);
    const unsigned int count = source != nullptr ? static_cast<unsigned int>(source->size()) : 0u;
    archive->WriteUInt(count);
    if (source == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (const auto& entry : *source) {
      msvc8::string key(entry.first.c_str());
      archive->WriteString(&key);

      gpg::RRef pointerRef{};
      gpg::RRef_CArmyStatItem(&pointerRef, entry.second);
      gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x007102B0 (FUN_007102B0)
   *
   * What it does:
   * Locks one `Stats<CArmyStatItem>` lane, reads an owned root pointer from
   * archive, swaps it into `mItem`, and deletes the previous root.
   */
  void DeserializeStatsCArmyStatItemOwnedRootLane(gpg::ReadArchive* const archive, const int ownerToken)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::CArmyStatItem>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(ownerToken))
    );
    if (archive == nullptr || stats == nullptr) {
      return;
    }

    boost::mutex::scoped_lock lock(stats->mLock);
    moho::CArmyStatItem* loadedRoot = nullptr;
    const gpg::RRef owner{};
    archive->ReadPointerOwned(&loadedRoot, &owner);

    stats->mItem.reset(loadedRoot);
  }

  /**
   * Address: 0x00710340 (FUN_00710340)
   *
   * What it does:
   * Writes the root stat item as an owned pointer with no owner, under the
   * stats lock: `RRef_CArmyStatItem` 0x00713BE0, then `WriteRawPointer`
   * 0x00953320 with state 2. The lock is taken on `+0x08` itself
   * (`lea esi, [edi+8]`), so the binary's lock is embedded where this layout
   * keeps a pointer; the load half above locks the same way.
   */
  void SerializeStatsCArmyStatItemOwnedRoot(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::CArmyStatItem>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    boost::mutex::scoped_lock lock(stats->mLock);
    archive->WritePointer(stats->mItem.get(), gpg::TrackedPointerState::Owned, gpg::RRef{});
  }

  /**
   * Address: 0x007103D0 (FUN_007103D0)
   *
   * What it does:
   * Allocates one `Stats<CArmyStatItem>`, wraps it in typed `RRef`, and
   * publishes it as an unowned serializer construct result.
   */
  void ConstructStatsCArmyStatItemForSerializer(
    const int, const int, gpg::RRef* const, gpg::SerConstructResult* const constructResult
  )
  {
    auto* const stats = new (std::nothrow) moho::Stats<moho::CArmyStatItem>();
    if (constructResult == nullptr) {
      delete stats;
      return;
    }

    gpg::RRef statsRef{};
    statsRef = gpg::MakeRRef<moho::Stats<moho::CArmyStatItem>>(stats);
    constructResult->SetUnowned(statsRef, 0u);
  }

  /**
   * Address: 0x00712780 (FUN_00712780)
   *
   * What it does:
   * Destroys one `Stats<CArmyStatItem>` object and releases its storage when
   * the pointer is non-null.
   */
  void DeleteStatsCArmyStatItemOwnedObject(void* const object)
  {
    delete static_cast<moho::Stats<moho::CArmyStatItem>*>(object);
  }

  class RMapUnitBlueprintFloatTypeInfo final : public gpg::RType
  {
  public:
    RMapUnitBlueprintFloatTypeInfo()
      : gpg::RType()
    {
      gpg::PreRegisterRType(typeid(UnitBlueprintWeightMap), this);
    }

    /**
     * Address: 0x007131F0 (FUN_007131F0, gpg::RMapType_RUnitBlueprintP_float::dtr)
     */
    ~RMapUnitBlueprintFloatTypeInfo() override = default;

    /**
     * Address: 0x0070ED30 (FUN_0070ED30, gpg::RMapType_RUnitBlueprintP_float::GetName)
     * Address: 0x00BFF910 (FUN_00BFF910, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `map<RUnitBlueprint*,float>` once from the key/value RTTI names
     * and returns it. The key is `RUnitBlueprint::GetPointerType()`, as in
     * the binary (0x0070ED7F).
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = gpg::STR_Printf(
        "map<%s,%s>", moho::RUnitBlueprint::GetPointerType()->GetName(), gpg::LookupRType(typeid(float))->GetName()
      );
      return sName.c_str();
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
      serLoadFunc_ = &DeserializeUnitBlueprintWeightMap;
      serSaveFunc_ = &SerializeUnitBlueprintWeightMap;
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
     * Address: 0x00BFF8E0 (FUN_00BFF8E0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `Stats<CArmyStatItem>` once and returns it.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = gpg::STR_Printf("Stats<%s>", moho::CArmyStatItem::StaticGetClass()->GetName());
      return sName.c_str();
    }

    /**
     * Address: 0x0070F1D0 (FUN_0070F1D0, Moho::StatsRType_CArmyStatItem::Init)
     *
     * What it does:
     * Sets reflected Stats<CArmyStatItem> size/version lanes and installs
     * save/construct/load/delete callback helpers in original binary order.
     */
    void Init() override
    {
      size_ = sizeof(moho::Stats<moho::CArmyStatItem>);
      version_ = 1;
      serLoadFunc_ = reinterpret_cast<gpg::RType::load_func_t>(&DeserializeStatsCArmyStatItemOwnedRootLane);
      serSaveFunc_ = &SerializeStatsCArmyStatItemOwnedRoot;
      serConstructFunc_ = reinterpret_cast<gpg::RType::construct_func_t>(&ConstructStatsCArmyStatItemForSerializer);
      deleteFunc_ = &DeleteStatsCArmyStatItemOwnedObject;
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

    /**
     * Address: 0x007132B0 (FUN_007132B0, gpg::RMapType_string_CArmyStateItemP::dtr)
     */
    ~RMapStringArmyStatItemPtrTypeInfo() override = default;

    /**
     * Address: 0x0070F200 (FUN_0070F200, gpg::RMapType_string_CArmyStateItemP::GetName)
     * Address: 0x00BFF8B0 (FUN_00BFF8B0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `map<std::string,CArmyStatItem*>` once from the key/value RTTI
     * names and returns it. The key is the engine ABI string type (see
     * RMapStringFloatTypeInfo.cpp); the value is
     * `CArmyStatItem::GetPointerType()`, as in the binary (0x0070F232).
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = gpg::STR_Printf(
        "map<%s,%s>", gpg::LookupRType(typeid(msvc8::string))->GetName(), moho::CArmyStatItem::GetPointerType()->GetName()
      );
      return sName.c_str();
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
      serLoadFunc_ = &DeserializeStringArmyStatItemMap;
      serSaveFunc_ = &SerializeStringArmyStatItemMap;
    }
  };

  ETriggerOperatorTypeInfo gETriggerOperatorTypeInfo;

  // Address: 0x010B8F78 -- process-global `gpg::PrimitiveSerHelper<
  // Moho::ETriggerOperator,int>` singleton (constructed by FUN_00BDA000,
  // self-registering via `__xc_a`; see `ETriggerOperatorPrimitiveSerializer`
  // above for the full real-ctor/Init/atexit evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ETriggerOperator,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ETriggerOperator@Moho@@H@gpg'`):
   * `FUN_00BDA000` (real, `__xc_a`-reachable at depth 0, sole writer to
   * global storage 0x010B8F78 -- no dead duplicate ctor found). Confirmed
   * via raw asm: default-constructs `gpg::SerHelperBase`, binds
   * `mLoadCallback`/`mSaveCallback` to `FUN_0070F8E0`/`FUN_0070F900`,
   * installs the `PrimitiveSerHelper<ETriggerOperator,int>` vtable, and
   * pushes plain unmangled `FUN_00BFF580` (bare unlink-then-self-link shape,
   * matching the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target --
   * modeled by the template's own real destructor, no explicit `atexit`
   * call needed. `FUN_0070AF50`/`FUN_0070AF80` are dead, zero-xref
   * duplicate-emission twins of that exact `FUN_00BFF580` body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneAU` and its two reset thunks; removed in
   * favor of this citation.
   *
   * `FUN_0070F8E0`/`FUN_0070F900` decompile byte-identically to this
   * template's own generic `Deserialize`/`Serialize` (archive->ReadInt /
   * WriteInt through vtable slot 9 / offset 0x24 on a plain `int` lane, no
   * branches at all) -- this instantiation needs no per-type override.
   *
   * `FUN_0070E510` is this template's own `Init()` body (confirmed via raw
   * asm: thiscall on the helper, reads `this+0x0C`/`this+0x10`, writes the
   * looked-up `ETriggerOperator` RType's `serLoadFunc_`/`serSaveFunc_` with
   * the usual `"!type->mSerLoadFunc"`/`"!type->mSerSaveFunc"` asserts,
   * including the same IDA-mislabeled `Moho::ETriggerOperator::sType`
   * global that is really this template's own per-instantiation
   * `sCachedType` static -- see the `PrimitiveSerHelper` class comment in
   * Reflection.h). It is a vtable-slot-0 target shared by both the real
   * `PrimitiveSerHelper<ETriggerOperator,int>` vtable (0x00E31060) and a
   * dead, zero-writer `SerSaveLoadHelper<ETriggerOperator>` sibling vtable
   * (0x00E31068), same shared-body pattern documented on `PrimitiveSerHelper`
   * for ESquadClass/EThreatType/EScrollType.
   *
   * This resolves what looked like two competing binding mechanisms for the
   * same enum: a 2026-08-26 `ArchiveSerialization.cpp` dead-duplicate audit
   * independently flagged `FUN_0070E510` as a second candidate distinct from
   * this file's own `register_ETriggerOperatorPrimitiveSerializer`
   * (previously cited at 0x00BDA000). They are not competitors -- ground-
   * truth asm shows `FUN_00BDA000` is the real ctor and `FUN_0070E510` is
   * that same ctor's `Init()` method; both belong to this one
   * self-registering `PrimitiveSerHelper<ETriggerOperator,int>`
   * instantiation, and neither is a dead/unreachable duplicate of the other.
   *
   * The previous recovery modeled `register_ETriggerOperatorPrimitiveSerializer`
   * as an eager free function -- `LookupRType(typeid(ETriggerOperator))`
   * followed by directly storing `&DeserializeETriggerOperator`/
   * `&SerializeETriggerOperator` onto the type's `serLoadFunc_`/
   * `serSaveFunc_` -- called from `SConditionTriggerBootstrap`'s
   * constructor. Ground-truth asm at 0x00BDA000 contains no `LookupRType`
   * call, no `typeid` push, and no direct field store at all: it is the
   * standard `SerHelperBase`-derived ctor shape (base-ctor call, callback
   * fields, vtable install, `atexit`) used by every other confirmed
   * `PrimitiveSerHelper<T,int>` instantiation in this codebase -- the
   * "fabricated eager register free-function" anti-pattern the
   * `PrimitiveSerHelper` class comment (Reflection.h) already warns about.
   * `DeserializeETriggerOperator`/`SerializeETriggerOperator` likewise added
   * `if (archive && value)` null checks absent from `FUN_0070F8E0`/
   * `FUN_0070F900`'s real, unconditional bodies. Both are replaced by this
   * self-registering template instantiation, the actual live wiring.
   */
  gpg::PrimitiveSerHelper<moho::ETriggerOperator, int> gETriggerOperatorPrimitiveSerializer;

  SConditionTypeInfo gSConditionTypeInfo;
  STriggerTypeInfo gSTriggerTypeInfo;

  RFastVectorSConditionTypeInfo gFastVectorSConditionTypeInfo;
  gpg::RSharedPointerType<moho::STrigger> gSharedPointerSTriggerTypeInfo;
  /**
   * `gpg::RListType<boost::shared_ptr<moho::STrigger>>` (the trigger lists):
   *
   * Address: 0x00712F40 (FUN_00712F40 -- its construction, preregistering it for
   * `typeid(msvc8::list<boost::shared_ptr<moho::STrigger>>)`.)
   * Address: 0x00713310 (FUN_00713310 -- the implicit scalar deleting destructor.)
   * Address: 0x0070F360 (FUN_0070F360 -- `GetName`, from the looked-up `boost::shared_ptr<STrigger>` type's name.)
   * Address: 0x00BFF880 (FUN_00BFF880 -- the atexit destructor of `GetName`'s name string.)
   * Address: 0x0070F420 (FUN_0070F420 -- `GetLexical`.)
   * Address: 0x0070F400 (FUN_0070F400 -- `Init`.)
   * Address: 0x00710620 (FUN_00710620 -- `SerLoad`; each trigger read by `ReadPointerShared<STrigger>` 0x007142F0.)
   * Address: 0x00710720 (FUN_00710720 -- `SerSave`; each trigger written `Shared` through `MakeRRef<STrigger>` 0x00713700.)
   */
  gpg::RListType<boost::shared_ptr<moho::STrigger>> gListSharedPtrSTriggerTypeInfo;
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
   * Address: 0x00BDA000 (FUN_00BDA000, register_ETriggerOperatorPrimitiveSerializer)
   *
   * What it does:
   * Forces the self-registering `gpg::PrimitiveSerHelper<ETriggerOperator,
   * int>` global to link in; the ctor at this same address is what actually
   * performs the registration (it is `__xc_a`-reachable and constructs
   * before any consumer runs), so this odr-use is the whole job -- same
   * idiom as `register_ETriggerOperatorTypeInfo` just above. See
   * `ETriggerOperatorPrimitiveSerializer`'s declaration for the full
   * ctor/Init/atexit evidence.
   */
  void register_ETriggerOperatorPrimitiveSerializer()
  {
    (void)gETriggerOperatorPrimitiveSerializer;
  }

  /**
   * Address: 0x00BDA040 (FUN_00BDA040, register_SConditionTypeInfo)
   */
  void register_SConditionTypeInfo()
  {
    (void)gSConditionTypeInfo;
  }

  /**
   * Address: 0x00BDA0A0 (FUN_00BDA0A0, sub_BDA0A0)
   */
  void register_STriggerTypeInfo()
  {
    (void)gSTriggerTypeInfo;
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
      moho::register_STriggerTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ETriggerOperatorTypeInfo_61eef0, moho::register_ETriggerOperatorTypeInfo)
GPG_PREREGISTER_INIT(register_SConditionTypeInfo_61eef0, moho::register_SConditionTypeInfo)
GPG_PREREGISTER_INIT(register_STriggerTypeInfo_61eef0, moho::register_STriggerTypeInfo)
