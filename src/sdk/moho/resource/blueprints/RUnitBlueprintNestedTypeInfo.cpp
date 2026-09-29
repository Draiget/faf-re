#include "RUnitBlueprintNestedTypeInfo.h"

#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/Entity.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"


namespace
{
  using GeneralTypeInfo = moho::RUnitBlueprintGeneralTypeInfo;
  using DisplayTypeInfo = moho::RUnitBlueprintDisplayTypeInfo;
  using PhysicsTypeInfo = moho::RUnitBlueprintPhysicsTypeInfo;
  using AirTypeInfo = moho::RUnitBlueprintAirTypeInfo;
  using TransportTypeInfo = moho::RUnitBlueprintTransportTypeInfo;
  using AITypeInfo = moho::RUnitBlueprintAITypeInfo;
  using DefenseTypeInfo = moho::RUnitBlueprintDefenseTypeInfo;
  using IntelTypeInfo = moho::RUnitBlueprintIntelTypeInfo;
  using EconomyTypeInfo = moho::RUnitBlueprintEconomyTypeInfo;
  using WeaponTypeInfo = moho::RUnitBlueprintWeaponTypeInfo;
  using VectorFloatType = msvc8::vector<float>;
  void EnsureVectorFloatLoadCapacity(VectorFloatType& storage, std::size_t requiredCount);
  [[nodiscard]] gpg::RType* CachedFloatType();

  /**
   * Address: 0x00524780 (FUN_00524780)
   *
   * Forward declaration; defined after the reflection class body. Inserts
   * `insertCount` copies of `*fillValue` at `insertPosition` into `storage`,
   * growing the underlying buffer geometrically when capacity is exhausted.
   * Returns the (possibly relocated) `start_` pointer of `storage`.
   */

  /**
   * Address: 0x00527EE0 (FUN_00527EE0)
   * Address: 0x00527CD0 (FUN_00527CD0)
   *
   * What it does:
   * Copies one contiguous float range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the last destination lane.
   */
  float* CopyFloatRangeNullable(
    float* destination,
    const float* const sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const float* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<float*>(destinationAddress) = *source;
      }
      destinationAddress += sizeof(float);
    }

    return reinterpret_cast<float*>(destinationAddress);
  }

  // Addresses 0x00525FA0 (StdcallThunkA), 0x00527190 (CdeclThunkA),
  // 0x005275C0 (StdcallThunkB), 0x005279C0 (CdeclThunkB), 0x00527B10
  // (CdeclThunkC), and 0x00527C20 (CdeclThunkD) -- six calling-convention
  // variant thunks formerly modeled here, all one-line forwards into
  // CopyFloatRangeNullable -- are dead: zero data_refs and zero *incoming*
  // call_edges for all six, and no source-level caller anywhere in
  // src/sdk/**. CopyFloatRangeNullable itself is confirmed real and
  // heavily used: its two compiled addresses (0x00527EE0/0x00527CD0) carry
  // 8 real incoming call_edges total, two of which are NOT any of these six
  // thunks -- FUN_005240D0 (recovered further below in this file) and
  // Moho::CopyOccupyRects (0x005267A0, 8 real callers of its own).

  class VectorFloatReflectionType final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00526340 (FUN_00526340, gpg::RVectorType_float::RVectorType_float)
     *
     * What it does:
     * Constructs and preregisters startup reflection RTTI for
     * `msvc8::vector<float>`.
     */
    VectorFloatReflectionType();

    /**
     * Address: 0x005266E0 (FUN_005266E0, gpg::RVectorType_float::dtr)
     */
    ~VectorFloatReflectionType() override;

    /**
     * Address: 0x005232C0 (FUN_005232C0, gpg::RVectorType_float::GetName)
     *
     * IDA signature:
     * std::string::_Bxty *gpg::RVectorType_float::GetName();
     *
     * What it does:
     * Lazily builds `"vector<float>"` once from the reflected element type's
     * own name and caches it.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00523380 (FUN_00523380, gpg::RVectorType_float::GetLexical)
     *
     * IDA signature:
     * std::string *__thiscall gpg::RVectorType_float::GetLexical(
     *     gpg::RType *this, std::string *dest, _DWORD *a3);
     *
     * What it does:
     * Vtable slot override for `gpg::RVectorType<float>::GetLexical`. Returns
     * base lexical text from the parent `gpg::RType::GetLexical` lane plus the
     * reflected vector size formatted as ", size=%d". Mirrors the binary's
     * `??_7?$RVectorType@M@gpg@@6B@` slot at `+0x04`.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override
    {
      return this;
    }

    /**
     * Address: 0x00523360 (FUN_00523360, gpg::RVectorType_float::Init)
     *
     * What it does:
     * Sets reflected `vector<float>` metadata and installs typed archive
     * callbacks. The `&SerLoad` address-take at line below is the FRAMEWORK
     * DISPATCH bind site for FUN_00523C00 (`gpg::RVectorType_float::SerLoad`).
     */
    void Init() override
    {
      size_ = sizeof(VectorFloatType);
      version_ = 1;
      serLoadFunc_ = &VectorFloatReflectionType::SerLoad;
      serSaveFunc_ = &VectorFloatReflectionType::SerSave;
    }

    [[nodiscard]] gpg::RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      gpg::RRef out{};
      out.mObj = nullptr;
      out.mType = nullptr;

      auto* const storage = static_cast<VectorFloatType*>(obj);
      if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
        return out;
      }

      gpg::RRef_float(&out, &(*storage)[static_cast<std::size_t>(ind)]);
      return out;
    }

    [[nodiscard]] size_t GetCount(void* const obj) const override
    {
      const auto* const storage = static_cast<const VectorFloatType*>(obj);
      return storage ? storage->size() : 0u;
    }

    /**
     * Address: 0x005241C0 (FUN_005241C0, gpg::RVectorType_float::SetCount)
     *
     * What it does:
     * Resizes one reflected `msvc8::vector<float>` lane and default-fills
     * appended elements with `0.0f`.
     */
    void SetCount(void* const obj, const int count) const override
    {
      if (!obj || count < 0) {
        return;
      }

      auto* const storage = static_cast<VectorFloatType*>(obj);
      storage->resize(static_cast<std::size_t>(count));
    }

  private:
    /**
     * Address: 0x00523C00 (FUN_00523C00, gpg::RVectorType_float::SerLoad)
     *
     * IDA signature:
     * void __cdecl gpg::RVectorType_float::SerLoad(int a1, _DWORD *a2);
     *
     * What it does:
     * Reflected `SerLoad` callback for `msvc8::vector<float>`: reads the
     * incoming element count from the archive, clears the destination, and
     * loads each float with push_back -- the binary's emission either appends
     * into spare capacity or routes a fill-insert through the geometric grow
     * lane (`_Insert_n`, FUN_00524780, cited on msvc8::vector<T>::insert),
     * which is exactly what push_back does.
     *
     * Bound at runtime by `gpg::RVectorType_float::Init` (FUN_00523360) which
     * installs `&SerLoad` into the reflection vtable slot at offset +0x1C
     * (caller address 0x52336E in the binary). The address-take is the
     * source-level invocation that keeps the per-T body in the final binary.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
    {
      if (!archive || objectPtr == 0) {
        return;
      }

      auto* const storage = reinterpret_cast<VectorFloatType*>(objectPtr);
      unsigned int count = 0u;
      archive->ReadUInt(&count);

      storage->clear();
      EnsureVectorFloatLoadCapacity(*storage, static_cast<std::size_t>(count));

      // Each archive read either writes into spare capacity or routes one
      // fill-insert through the grow lane: both arms are push_back. That is
      // the binary's SerLoad shape (FUN_00523C00) exactly.
      for (unsigned int i = 0u; i < count; ++i) {
        float value = 0.0f;
        archive->ReadFloat(&value);
        storage->push_back(value);
      }
    }

    /**
     * Address: 0x00523D00 (FUN_00523D00, gpg::RVectorType_float::SerSave)
     *
     * What it does:
     * Writes the reflected float vector as an element count followed by each
     * float.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
    {
      if (!archive) {
        return;
      }

      const auto* const storage = reinterpret_cast<const VectorFloatType*>(objectPtr);
      const unsigned int count = storage ? static_cast<unsigned int>(storage->size()) : 0u;
      archive->WriteUInt(count);
      if (!storage) {
        return;
      }

      for (const float value : *storage) {
        archive->WriteFloat(value);
      }
    }
  };

  /**
   * Address: 0x00526340 (FUN_00526340, gpg::RVectorType_float::RVectorType_float)
   *
   * What it does:
   * Preregisters this descriptor under `typeid(msvc8::vector<float>)`.
   */
  VectorFloatReflectionType::VectorFloatReflectionType()
  {
    gpg::PreRegisterRType(typeid(VectorFloatType), this);
  }

  VectorFloatReflectionType::~VectorFloatReflectionType() = default;

  /**
   * Address: 0x005232C0 (FUN_005232C0, gpg::RVectorType_float::GetName)
   * Address: 0x00BF3840 (FUN_00BF3840, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `vector<float>` once from the reflected `float` descriptor's name
   * and returns it.
   */
  const char* VectorFloatReflectionType::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("vector<%s>", CachedFloatType()->GetName());
    return sName.c_str();
  }

  /**
   * Address: 0x00523380 (FUN_00523380, gpg::RVectorType_float::GetLexical)
   *
   * What it does:
   * Vtable slot override that combines parent `gpg::RType::GetLexical` text
   * with the reflected vector size as ", size=%d". Out-of-line definition
   * binds the binary symbol to the `??_7?$RVectorType@M@gpg@@6B@ +0x04` slot.
   */
  msvc8::string VectorFloatReflectionType::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x005238B0 (FUN_005238B0)
   *
   * What it does:
   * Tail-thunk alias that forwards reflected vector-float count updates into
   * `VectorFloatReflectionType::SetCount`.
   */
  [[maybe_unused]] void SetVectorFloatReflectionCountThunk(
    const VectorFloatReflectionType* const typeInfo,
    void* const storage,
    const int count
  )
  {
    if (typeInfo != nullptr) {
      typeInfo->SetCount(storage, count);
    }
  }

  /**
   * Address: 0x005240D0 (FUN_005240D0)
   *
   * What it does:
   * Ensures one `msvc8::vector<float>` can hold at least `requiredCount`
   * elements before reflected load appends them.
   */
  void EnsureVectorFloatLoadCapacity(VectorFloatType& storage, const std::size_t requiredCount)
  {
    if (requiredCount > 0x3FFFFFFFu) {
      throw std::bad_alloc{};
    }

    if (requiredCount <= storage.capacity()) {
      return;
    }

    storage.reserve(requiredCount);
  }

  static_assert(sizeof(VectorFloatReflectionType) == 0x68, "VectorFloatReflectionType size must be 0x68");

  /**
   * Address: 0x00BF32C0 (FUN_00BF32C0, atexit destructor of the RUnitBlueprintGeneralTypeInfo object)
   */
  [[nodiscard]] GeneralTypeInfo& AcquireRUnitBlueprintGeneralTypeInfo()
  {
    static GeneralTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3320 (FUN_00BF3320, atexit destructor of the RUnitBlueprintDisplayTypeInfo object)
   */
  [[nodiscard]] DisplayTypeInfo& AcquireRUnitBlueprintDisplayTypeInfo()
  {
    static DisplayTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3380 (FUN_00BF3380, atexit destructor of the RUnitBlueprintPhysicsTypeInfo object)
   */
  [[nodiscard]] PhysicsTypeInfo& AcquireRUnitBlueprintPhysicsTypeInfo()
  {
    static PhysicsTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF33E0 (FUN_00BF33E0, atexit destructor of the RUnitBlueprintAirTypeInfo object)
   */
  [[nodiscard]] AirTypeInfo& AcquireRUnitBlueprintAirTypeInfo()
  {
    static AirTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3440 (FUN_00BF3440, atexit destructor of the RUnitBlueprintTransportTypeInfo object)
   */
  [[nodiscard]] TransportTypeInfo& AcquireRUnitBlueprintTransportTypeInfo()
  {
    static TransportTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF34A0 (FUN_00BF34A0, atexit destructor of the RUnitBlueprintAITypeInfo object)
   */
  [[nodiscard]] AITypeInfo& AcquireRUnitBlueprintAITypeInfo()
  {
    static AITypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3560 (FUN_00BF3560, atexit destructor of the RUnitBlueprintDefenseTypeInfo object)
   */
  [[nodiscard]] DefenseTypeInfo& AcquireRUnitBlueprintDefenseTypeInfo()
  {
    static DefenseTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF35C0 (FUN_00BF35C0, atexit destructor of the RUnitBlueprintIntelTypeInfo object)
   */
  [[nodiscard]] IntelTypeInfo& AcquireRUnitBlueprintIntelTypeInfo()
  {
    static IntelTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3620 (FUN_00BF3620, atexit destructor of the RUnitBlueprintEconomyTypeInfo object)
   */
  [[nodiscard]] EconomyTypeInfo& AcquireRUnitBlueprintEconomyTypeInfo()
  {
    static EconomyTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF3690 (FUN_00BF3690, atexit destructor of the RUnitBlueprintWeaponTypeInfo object)
   */
  [[nodiscard]] WeaponTypeInfo& AcquireRUnitBlueprintWeaponTypeInfo()
  {
    static WeaponTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF38D0 (FUN_00BF38D0, atexit destructor of the VectorFloatReflectionType object)
   */
  [[nodiscard]] VectorFloatReflectionType& AcquireVectorFloatReflectionType()
  {
    static VectorFloatReflectionType sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BC8D10 (FUN_00BC8D10, register_VectorFloatReflectionType)
   *
   * What it does:
   * Startup lane that constructs and preregisters `vector<float>` reflection
   * type metadata.
   */
  void register_VectorFloatReflectionType()
  {
    (void)AcquireVectorFloatReflectionType();
  }

  template <typename T>
  [[nodiscard]] gpg::RType* CachedType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedBoolType()
  {
    return CachedType<bool>();
  }

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    return CachedType<float>();
  }

  [[nodiscard]] gpg::RType* CachedInt32Type()
  {
    return CachedType<std::int32_t>();
  }

  [[nodiscard]] gpg::RType* CachedUInt32Type()
  {
    return CachedType<std::uint32_t>();
  }

  [[nodiscard]] gpg::RType* CachedStringType()
  {
    return CachedType<msvc8::string>();
  }

  [[nodiscard]] gpg::RType* CachedRResIdType()
  {
    return CachedType<moho::RResId>();
  }

  [[nodiscard]] gpg::RType* CachedCommandCapsType()
  {
    return CachedType<moho::ERuleBPUnitCommandCaps>();
  }

  [[nodiscard]] gpg::RType* CachedToggleCapsType()
  {
    return CachedType<moho::ERuleBPUnitToggleCaps>();
  }

  [[nodiscard]] gpg::RType* CachedMovementType()
  {
    return CachedType<moho::ERuleBPUnitMovementType>();
  }

  [[nodiscard]] gpg::RType* CachedLayerType()
  {
    return CachedType<moho::ELayer>();
  }

  [[nodiscard]] gpg::RType* CachedBuildRestrictionType()
  {
    return CachedType<moho::ERuleBPUnitBuildRestriction>();
  }

  [[nodiscard]] gpg::RType* CachedDefenseShieldType()
  {
    return CachedType<moho::RUnitBlueprintDefenseShield>();
  }

  [[nodiscard]] gpg::RType* CachedSMinMaxUInt32Type()
  {
    return CachedType<moho::SMinMax<std::uint32_t>>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponRangeCategoryType()
  {
    return CachedType<moho::UnitWeaponRangeCategory>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponBallisticArcType()
  {
    return CachedType<moho::ERuleBPUnitWeaponBallisticArc>();
  }

  [[nodiscard]] gpg::RType* CachedWeaponTargetType()
  {
    return CachedType<moho::ERuleBPUnitWeaponTargetType>();
  }

  [[nodiscard]] gpg::RField* AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
    return &typeInfo->fields_.back();
  }

  void SetLastFieldName(gpg::RType* const typeInfo, const char* const fieldName)
  {
    if (typeInfo->fields_.empty()) {
      return;
    }
    typeInfo->fields_.back().mName = fieldName;
  }

  struct RUnitBlueprintNestedTypeInfoBootstrap
  {
    RUnitBlueprintNestedTypeInfoBootstrap()
    {
      register_VectorFloatReflectionType();
      moho::register_RUnitBlueprintGeneralTypeInfo();
      moho::register_RUnitBlueprintDisplayTypeInfo();
      moho::register_RUnitBlueprintPhysicsTypeInfo();
      moho::register_RUnitBlueprintAirTypeInfo();
      moho::register_RUnitBlueprintTransportTypeInfo();
      moho::register_RUnitBlueprintAITypeInfo();
      moho::register_RUnitBlueprintDefenseTypeInfo();
      moho::register_RUnitBlueprintIntelTypeInfo();
      moho::register_RUnitBlueprintEconomyTypeInfo();
      moho::register_RUnitBlueprintWeaponTypeInfo();
    }
  };

  RUnitBlueprintNestedTypeInfoBootstrap gRUnitBlueprintNestedTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00520530 (FUN_00520530, Moho::RUnitBlueprintGeneralTypeInfo::RUnitBlueprintGeneralTypeInfo)
   */
  RUnitBlueprintGeneralTypeInfo::RUnitBlueprintGeneralTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintGeneral), this);
  }

  /**
   * Address: 0x005205C0 (FUN_005205C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintGeneralTypeInfo::~RUnitBlueprintGeneralTypeInfo() = default;

  /**
   * Address: 0x005205B0 (FUN_005205B0)
   */
  const char* RUnitBlueprintGeneralTypeInfo::GetName() const
  {
    return "RUnitBlueprintGeneral";
  }

  /**
   * Address: 0x005252A0 (FUN_005252A0, gpg::RType::AddField_ERuleBPUnitCommandCaps_0x0CommandCaps)
   *
   * What it does:
   * Appends the reflected `CommandCaps` field descriptor at offset `0x00`.
   */
  gpg::RField* RUnitBlueprintGeneralTypeInfo::AddFieldCommandCaps(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("CommandCaps", CachedCommandCapsType(), offsetof(RUnitBlueprintGeneral, CommandCaps), offsetof(RUnitBlueprintGeneral, CommandCaps), nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525320 (FUN_00525320, gpg::RType::AddField_ERuleBPUnitToggleCaps_0x4ToggleCaps)
   *
   * What it does:
   * Appends the reflected `ToggleCaps` field descriptor at offset `0x04`.
   */
  gpg::RField* RUnitBlueprintGeneralTypeInfo::AddFieldToggleCaps(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("ToggleCaps", CachedToggleCapsType(), offsetof(RUnitBlueprintGeneral, ToggleCaps), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00520660 (FUN_00520660)
   *
   * What it does:
   * Registers `RUnitBlueprintGeneral` field descriptors and descriptions.
   */
  void RUnitBlueprintGeneralTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* const commandCapsField = AddFieldCommandCaps(typeInfo);
    commandCapsField->v4 = 3;
    commandCapsField->mDesc = "Command capability flags for this unit";

    gpg::RField* const toggleCapsField = AddFieldToggleCaps(typeInfo);
    toggleCapsField->v4 = 3;
    toggleCapsField->mDesc = "Command capability flags for this unit";

    AddFieldWithDescription(typeInfo, "UpgradesTo", CachedRResIdType(), offsetof(RUnitBlueprintGeneral, UpgradesTo), "What unit, if any, does this unit upgrade to.");
    AddFieldWithDescription(typeInfo, "UpgradesFrom", CachedRResIdType(), offsetof(RUnitBlueprintGeneral, UpgradesFrom), "What unit, if any, was this unit upgrade from.");
    AddFieldWithDescription(
      typeInfo,
      "UpgradesFromBase",
      CachedRResIdType(),
      offsetof(RUnitBlueprintGeneral, UpgradesFromBase),
      "What unit, if any, was this unit upgrade from base."
    );
    AddFieldWithDescription(typeInfo, "SeedUnit", CachedRResIdType(), offsetof(RUnitBlueprintGeneral, SeedUnit), "What unit, if any, was this unit seeded from.");
    AddFieldWithDescription(
      typeInfo,
      "QuickSelectPriority",
      CachedInt32Type(),
      offsetof(RUnitBlueprintGeneral, QuickSelectPriority),
      "Indicates unit has it's own avatar button in the quick select interface, and it's sorting priority"
    );
    AddFieldWithDescription(typeInfo, "CapCost", CachedFloatType(), offsetof(RUnitBlueprintGeneral, CapCost), "Cost of unit towards unit cap");
    AddFieldWithDescription(
      typeInfo,
      "SelectionPriority",
      CachedInt32Type(),
      offsetof(RUnitBlueprintGeneral, SelectionPriority),
      "Determines if a unit will be selected in a drag selection, only the highest priority units will get selected (1 is highest)"
    );
  }

  /**
   * Address: 0x00520590 (FUN_00520590)
   *
   * What it does:
   * Sets `RUnitBlueprintGeneral` size and publishes general field metadata.
   */
  void RUnitBlueprintGeneralTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintGeneral);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00520730 (FUN_00520730, Moho::RUnitBlueprintDisplayTypeInfo::RUnitBlueprintDisplayTypeInfo)
   */
  RUnitBlueprintDisplayTypeInfo::RUnitBlueprintDisplayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintDisplay), this);
  }

  /**
   * Address: 0x005207C0 (FUN_005207C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintDisplayTypeInfo::~RUnitBlueprintDisplayTypeInfo() = default;

  /**
   * Address: 0x005207B0 (FUN_005207B0)
   */
  const char* RUnitBlueprintDisplayTypeInfo::GetName() const
  {
    return "RUnitBlueprintDisplay";
  }

  /**
   * Address: 0x00520860 (FUN_00520860)
   *
   * What it does:
   * Registers `RUnitBlueprintDisplay` field descriptors and descriptions.
   */
  void RUnitBlueprintDisplayTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "DisplayName", CachedStringType(), offsetof(RUnitBlueprintDisplay, DisplayName), "Displayed name of unit");
    AddFieldWithDescription(typeInfo, "MeshBlueprint", CachedRResIdType(), offsetof(RUnitBlueprintDisplay, MeshBlueprint), "Mesh blueprint we use for display");
    AddFieldWithDescription(
      typeInfo,
      "PlaceholderMeshName",
      CachedStringType(),
      offsetof(RUnitBlueprintDisplay, PlaceholderMeshName),
      "Name of placeholder mesh to use for the unit when normal mesh isn't available"
    );
    AddFieldWithDescription(typeInfo, "IconName", CachedRResIdType(), offsetof(RUnitBlueprintDisplay, IconName), "Name of icon to use for the unit");
    AddFieldWithDescription(typeInfo, "UniformScale", CachedFloatType(), offsetof(RUnitBlueprintDisplay, UniformScale), "Uniform scale to be applied to mesh");
    AddFieldWithDescription(typeInfo, "SpawnRandomRotation", CachedBoolType(), offsetof(RUnitBlueprintDisplay, SpawnRandomRotation), "Spawn with a small random rotation");
    AddFieldWithDescription(typeInfo, "HideLifebars", CachedBoolType(), offsetof(RUnitBlueprintDisplay, HideLifebars), "Hide lifebars if true");
  }

  /**
   * Address: 0x00520790 (FUN_00520790)
   *
   * What it does:
   * Sets `RUnitBlueprintDisplay` size and publishes display field metadata.
   */
  void RUnitBlueprintDisplayTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintDisplay);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00520910 (FUN_00520910, Moho::RUnitBlueprintPhysicsTypeInfo::RUnitBlueprintPhysicsTypeInfo)
   */
  RUnitBlueprintPhysicsTypeInfo::RUnitBlueprintPhysicsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintPhysics), this);
  }

  /**
   * Address: 0x005209A0 (FUN_005209A0, scalar deleting destructor thunk)
   */
  RUnitBlueprintPhysicsTypeInfo::~RUnitBlueprintPhysicsTypeInfo() = default;

  /**
   * Address: 0x00520990 (FUN_00520990)
   */
  const char* RUnitBlueprintPhysicsTypeInfo::GetName() const
  {
    return "RUnitBlueprintPhysics";
  }

  /**
   * Address: 0x005253A0 (FUN_005253A0, gpg::RType::AddField_ERuleBPUnitMovementType)
   *
   * What it does:
   * Appends a reflected movement-type field descriptor at the requested offset.
   */
  gpg::RField* RUnitBlueprintPhysicsTypeInfo::AddFieldMovementType(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    const int offset
  )
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField(fieldName, CachedMovementType(), offset, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525420 (FUN_00525420, gpg::RType::AddField_ELayer_0x7CBuildOnLayerCaps)
   *
   * What it does:
   * Appends the reflected `BuildOnLayerCaps` field descriptor at offset `0x7C`.
   */
  gpg::RField* RUnitBlueprintPhysicsTypeInfo::AddFieldBuildOnLayerCaps(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("BuildOnLayerCaps", CachedLayerType(), offsetof(RUnitBlueprintPhysics, BuildOnLayerCapsMask), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x005254A0 (FUN_005254A0, gpg::RType::AddField_ERuleBPUnitBuildRestriction_0x80BuildRestriction)
   *
   * What it does:
   * Appends the reflected `BuildRestriction` field descriptor at offset `0x80`.
   */
  gpg::RField* RUnitBlueprintPhysicsTypeInfo::AddFieldBuildRestriction(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("BuildRestriction", CachedBuildRestrictionType(), offsetof(RUnitBlueprintPhysics, BuildRestriction), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525520 (FUN_00525520, gpg::RType::AddField_vector_float)
   *
   * What it does:
   * Appends a reflected `vector<float>` field descriptor.
   */
  gpg::RField* RUnitBlueprintPhysicsTypeInfo::AddFieldVectorFloat(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    const int offset
  )
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    static gpg::RType* cachedVectorFloatType = nullptr;
    if (!cachedVectorFloatType) {
      cachedVectorFloatType = gpg::LookupRType(typeid(msvc8::vector<float>));
    }

    typeInfo->fields_.push_back(gpg::RField(fieldName, cachedVectorFloatType, offset, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00520A40 (FUN_00520A40)
   *
   * What it does:
   * Registers `RUnitBlueprintPhysics` field descriptors and descriptions.
   */
  void RUnitBlueprintPhysicsTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(
      typeInfo,
      "FlattenSkirt",
      CachedBoolType(),
      offsetof(RUnitBlueprintPhysics, FlattenSkirt),
      "If true, terrain under building's skirt will be flattened."
    );
    AddFieldWithDescription(
      typeInfo,
      "SkirtOffsetX",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, SkirtOffsetX),
      "Offset of left edge of skirt from left edge of footprint. Should be <= 0."
    );
    AddFieldWithDescription(
      typeInfo,
      "SkirtOffsetZ",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, SkirtOffsetZ),
      "Offset of top edge of skirt from top edge of footprint. Should be <= 0."
    );
    AddFieldWithDescription(typeInfo, "SkirtSizeX", CachedFloatType(), offsetof(RUnitBlueprintPhysics, SkirtSizeX), "Unit construction pad Size X for building");
    AddFieldWithDescription(typeInfo, "SkirtSizeZ", CachedFloatType(), offsetof(RUnitBlueprintPhysics, SkirtSizeZ), "Unit construction pad Size Z for building");
    AddFieldWithDescription(
      typeInfo,
      "MaxGroundVariation",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, MaxGroundVariation),
      "Maximum elevation difference across skirt for build site"
    );
    gpg::RField* const motionTypeField = AddFieldMovementType(typeInfo, "MotionType", offsetof(RUnitBlueprintPhysics, MotionType));
    motionTypeField->v4 = 3;
    motionTypeField->mDesc = "Method of locomotion";
    gpg::RField* const altMotionTypeField = AddFieldMovementType(typeInfo, "AltMotionType", offsetof(RUnitBlueprintPhysics, AltMotionType));
    altMotionTypeField->v4 = 3;
    altMotionTypeField->mDesc = "Alternate method of locomotion";
    AddFieldWithDescription(typeInfo, "StandUpright", CachedBoolType(), offsetof(RUnitBlueprintPhysics, StandUpright), "Stands upright regardless of terrain");
    AddFieldWithDescription(typeInfo, "SinkLower", CachedBoolType(), offsetof(RUnitBlueprintPhysics, SinkLower), "Stands upright regardless of terrain");
    AddFieldWithDescription(
      typeInfo,
      "RotateBodyWhileMoving",
      CachedBoolType(),
      offsetof(RUnitBlueprintPhysics, RotateBodyWhileMoving),
      "Ability to rotate body to aim weapon slaved to body while in still in motion"
    );
    AddFieldWithDescription(typeInfo, "DiveSurfaceSpeed", CachedFloatType(), offsetof(RUnitBlueprintPhysics, DiveSurfaceSpeed), "Dive/surface speed for the sub units");
    AddFieldWithDescription(typeInfo, "MaxSpeed", CachedFloatType(), offsetof(RUnitBlueprintPhysics, MaxSpeed), "Maximum speed for the unit");
    AddFieldWithDescription(typeInfo, "MaxSpeedReverse", CachedFloatType(), offsetof(RUnitBlueprintPhysics, MaxSpeedReverse), "Maximum speed for the unit in reverse");
    AddFieldWithDescription(typeInfo, "MaxAcceleration", CachedFloatType(), offsetof(RUnitBlueprintPhysics, MaxAcceleration), "Maximum acceleration for the unit");
    AddFieldWithDescription(typeInfo, "MaxBrake", CachedFloatType(), offsetof(RUnitBlueprintPhysics, MaxBrake), "Maximum braking acceleration for the unit");
    AddFieldWithDescription(
      typeInfo,
      "MaxSteerForce",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, MaxSteerForce),
      "Maximum steer force magnitude that can be applied to acceleration"
    );
    AddFieldWithDescription(
      typeInfo,
      "BankingSlope",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, BankingSlope),
      "How much the unit banks in corners (negative to lean outwards)"
    );
    AddFieldWithDescription(
      typeInfo,
      "RollStability",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, RollStability),
      "How stable the unit is against rolling (0 to 1)"
    );
    AddFieldWithDescription(
      typeInfo,
      "RollDamping",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, RollDamping),
      "How much damping there is against rolling motion (1 = no motion at all)"
    );
    AddFieldWithDescription(typeInfo, "WobbleFactor", CachedFloatType(), offsetof(RUnitBlueprintPhysics, WobbleFactor), "How much wobbling for the unit while hovering");
    AddFieldWithDescription(
      typeInfo,
      "WobbleSpeed",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, WobbleSpeed),
      "How fast is the wobble. The faster the less stable looking"
    );
    AddFieldWithDescription(typeInfo, "TurnRadius", CachedFloatType(), offsetof(RUnitBlueprintPhysics, TurnRadius), "Turn radius for the unit, in world units");
    AddFieldWithDescription(typeInfo, "TurnRate", CachedFloatType(), offsetof(RUnitBlueprintPhysics, TurnRate), "Turn rate for the unit, in degrees per second");
    AddFieldWithDescription(
      typeInfo,
      "TurnFacingRate",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, TurnFacingRate),
      "Turn facing damping for the unit, usually used for hover units only"
    );
    AddFieldWithDescription(typeInfo, "RotateOnSpot", CachedBoolType(), offsetof(RUnitBlueprintPhysics, RotateOnSpot), "This unit can tries to rotate on the spot.");
    AddFieldWithDescription(
      typeInfo,
      "RotateOnSpotThreshold",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, RotateOnSpotThreshold),
      "Threshold for rotate on spot to take effect when moving."
    );
    AddFieldWithDescription(
      typeInfo,
      "Elevation",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, Elevation),
      "Preferred height above (-below) land or water surface"
    );
    AddFieldWithDescription(
      typeInfo,
      "AttackElevation",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, AttackElevation),
      "Preferred attack height when attacking ground targets... used by dive bombers"
    );
    gpg::RField* const buildOnLayerCapsField = AddFieldBuildOnLayerCaps(typeInfo);
    buildOnLayerCapsField->v4 = 3;
    buildOnLayerCapsField->mDesc = "Unit may be built on these layers (only applies to structures";
    gpg::RField* const buildRestrictionField = AddFieldBuildRestriction(typeInfo);
    buildRestrictionField->v4 = 3;
    buildRestrictionField->mDesc = "Special build restrictions (mass deposit, thermal vent, etc)";
    AddFieldWithDescription(
      typeInfo,
      "CatchUpAcc",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, CatchUpAcc),
      "Acceleration to allow unit to catch up to the target when it starts to drift"
    );
    AddFieldWithDescription(
      typeInfo,
      "BackUpDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, BackUpDistance),
      "Distance that the unit will just back up if it's easier to do so"
    );
    AddFieldWithDescription(
      typeInfo,
      "LayerChangeOffsetHeight",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, LayerChangeOffsetHeight),
      "An offset to the layer change height used during the transition between seabed/water and land"
    );
    AddFieldWithDescription(
      typeInfo,
      "LayerTransitionDuration",
      CachedFloatType(),
      offsetof(RUnitBlueprintPhysics, LayerTransitionDuration),
      "Transition time in seconds when going from water/land and land/water"
    );
    AddFieldWithDescription(typeInfo, "FuelUseTime", CachedFloatType(), offsetof(RUnitBlueprintPhysics, FuelUseTime), "Unit has fuel for this number of seconds");
    AddFieldWithDescription(typeInfo, "FuelRechargeRate", CachedFloatType(), offsetof(RUnitBlueprintPhysics, FuelRechargeRate), "Unit fuels up at this rate per second");
    AddFieldWithDescription(typeInfo, "GroundCollisionOffset", CachedFloatType(), offsetof(RUnitBlueprintPhysics, GroundCollisionOffset), "Collision with ground offset");

    gpg::RField* const raisedPlatformsField = AddFieldVectorFloat(typeInfo, "RaisedPlatforms", offsetof(RUnitBlueprintPhysics, RaisedPlatforms));
    raisedPlatformsField->mName = "RaisedPlatforms";
    raisedPlatformsField->v4 = 3;
    raisedPlatformsField->mDesc = "Raised platoform definition for ground units to move on";

    gpg::RField* const occupyRectsField = AddFieldVectorFloat(typeInfo, "OccupyRects", offsetof(RUnitBlueprintPhysics, OccupyRects));
    occupyRectsField->mName = "OccupyRects";
    occupyRectsField->v4 = 3;
    occupyRectsField->mDesc = "Set up the occupy rectangles of the unit that will override the footprint.";
  }

  /**
   * Address: 0x00520970 (FUN_00520970)
   *
   * What it does:
   * Sets `RUnitBlueprintPhysics` size and publishes physics field metadata.
   */
  void RUnitBlueprintPhysicsTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintPhysics);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00520E10 (FUN_00520E10, Moho::RUnitBlueprintAirTypeInfo::RUnitBlueprintAirTypeInfo)
   */
  RUnitBlueprintAirTypeInfo::RUnitBlueprintAirTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintAir), this);
  }

  /**
   * Address: 0x00520EA0 (FUN_00520EA0, scalar deleting destructor thunk)
   */
  RUnitBlueprintAirTypeInfo::~RUnitBlueprintAirTypeInfo() = default;

  /**
   * Address: 0x00520E90 (FUN_00520E90)
   */
  const char* RUnitBlueprintAirTypeInfo::GetName() const
  {
    return "RUnitBlueprintAir";
  }

  /**
   * Address: 0x00520F40 (FUN_00520F40)
   *
   * What it does:
   * Registers `RUnitBlueprintAir` field descriptors and descriptions.
   */
  void RUnitBlueprintAirTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "CanFly", CachedBoolType(), offsetof(RUnitBlueprintAir, CanFly), "Is the unit capable of flight?");
    AddFieldWithDescription(typeInfo, "Winged", CachedBoolType(), offsetof(RUnitBlueprintAir, Winged), "Does the unit use wings for forward flight?");
    AddFieldWithDescription(typeInfo, "FlyInWater", CachedBoolType(), offsetof(RUnitBlueprintAir, FlyInWater), "Can this unit fly under water?");
    AddFieldWithDescription(typeInfo, "AutoLandTime", CachedFloatType(), offsetof(RUnitBlueprintAir, AutoLandTime), "Timer to automatically initate landing on ground if idle");
    AddFieldWithDescription(typeInfo, "MaxAirspeed", CachedFloatType(), offsetof(RUnitBlueprintAir, MaxAirspeed), "Maximum airspeed");
    AddFieldWithDescription(typeInfo, "MinAirspeed", CachedFloatType(), offsetof(RUnitBlueprintAir, MinAirspeed), "Minimum combat airspeed");
    AddFieldWithDescription(typeInfo, "TurnSpeed", CachedFloatType(), offsetof(RUnitBlueprintAir, TurnSpeed), "Regular turn speed of the unit");
    AddFieldWithDescription(
      typeInfo,
      "CombatTurnSpeed",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CombatTurnSpeed),
      "Maximum combat turn speed of the unit for special manuvers"
    );
    AddFieldWithDescription(
      typeInfo,
      "StartTurnDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, StartTurnDistance),
      "Distance from target at which to start turning to align with it"
    );
    AddFieldWithDescription(
      typeInfo,
      "TightTurnMultiplier",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, TightTurnMultiplier),
      "Additional turning multiplier ability during a tight turn manuver"
    );
    AddFieldWithDescription(
      typeInfo,
      "SustainedTurnThreshold",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, SustainedTurnThreshold),
      "Length of time allowed for sustained turn before we re-try a different approach"
    );
    AddFieldWithDescription(typeInfo, "LiftFactor", CachedFloatType(), offsetof(RUnitBlueprintAir, LiftFactor), "How much altitude the unit can gain/loose per second");
    AddFieldWithDescription(typeInfo, "BankFactor", CachedFloatType(), offsetof(RUnitBlueprintAir, BankFactor), "How much aircraft banks in turns; negative to lean out");
    AddFieldWithDescription(
      typeInfo,
      "BankForward",
      CachedBoolType(),
      offsetof(RUnitBlueprintAir, BankForward),
      "True if aircraft banks forward/back as well as sideways"
    );
    AddFieldWithDescription(
      typeInfo,
      "EngageDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, EngageDistance),
      "Distance to being engaging enemy target in attack task"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffTrigger",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, BreakOffTrigger),
      "Distance to target to trigger the breaking off attack"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, BreakOffDistance),
      "Distnace to break off before turning around for another attack run"
    );
    AddFieldWithDescription(
      typeInfo,
      "BreakOffIfNearNewTarget",
      CachedBoolType(),
      offsetof(RUnitBlueprintAir, BreakOffIfNearNewTarget),
      "If our new target is close by then perform break off first to increase distance between the 2"
    );
    AddFieldWithDescription(
      typeInfo,
      "KMove",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, KMove),
      "Controller proportional parameter for horizontal motion"
    );
    AddFieldWithDescription(typeInfo, "KMoveDamping", CachedFloatType(), offsetof(RUnitBlueprintAir, KMoveDamping), "Controller damping parameter for horizontal motion");
    AddFieldWithDescription(typeInfo, "KLift", CachedFloatType(), offsetof(RUnitBlueprintAir, KLift), "Controller proportional parameter for vertical motion");
    AddFieldWithDescription(typeInfo, "KLiftDamping", CachedFloatType(), offsetof(RUnitBlueprintAir, KLiftDamping), "Controller damping parameter for vertical motion");
    AddFieldWithDescription(typeInfo, "KTurn", CachedFloatType(), offsetof(RUnitBlueprintAir, KTurn), "Controller proportional parameter for heading changes");
    AddFieldWithDescription(typeInfo, "KTurnDamping", CachedFloatType(), offsetof(RUnitBlueprintAir, KTurnDamping), "Controller damping parameter for heading changes");
    AddFieldWithDescription(typeInfo, "KRoll", CachedFloatType(), offsetof(RUnitBlueprintAir, KRoll), "Controller proportional parameter for roll changes");
    AddFieldWithDescription(typeInfo, "KRollDamping", CachedFloatType(), offsetof(RUnitBlueprintAir, KRollDamping), "Controller damping parameter for roll changes");
    AddFieldWithDescription(typeInfo, "CirclingTurnMult", CachedFloatType(), offsetof(RUnitBlueprintAir, CirclingTurnMult), "Adjust turning ability when in circling mode");
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusChangeMinRatio",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CirclingRadiusChangeMinRatio),
      "Min circling radius ratio for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusChangeMaxRatio",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CirclingRadiusChangeMaxRatio),
      "Max circling radius ratio for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingRadiusVsAirMult",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CirclingRadiusVsAirMult),
      "Multiplier to the circling radius when targetting another air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingElevationChangeRatio",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CirclingElevationChangeRatio),
      "Elevation change ratio of unit when circling"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingFlightChangeFrequency",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, CirclingFlightChangeFrequency),
      "Frequency of flight pattern change for unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "CirclingDirChange",
      CachedBoolType(),
      offsetof(RUnitBlueprintAir, CirclingDirChange),
      "Whether unit should ever change flight direction while circling"
    );
    AddFieldWithDescription(
      typeInfo,
      "HoverOverAttack",
      CachedBoolType(),
      offsetof(RUnitBlueprintAir, HoverOverAttack),
      "Whether unit should hover over the target directly to attack... used for cases like the C.Z.A.R"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomBreakOffDistanceMult",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, RandomBreakOffDistanceMult),
      "Random multiplier applied to the break off distance for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomMinChangeCombatStateTime",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, RandomMinChangeCombatStateTime),
      "Random min time to switch combat state in seconds for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "RandomMaxChangeCombatStateTime",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, RandomMaxChangeCombatStateTime),
      "Random max time to switch combat state in seconds for winged aircrafts"
    );
    AddFieldWithDescription(
      typeInfo,
      "TransportHoverHeight",
      CachedFloatType(),
      offsetof(RUnitBlueprintAir, TransportHoverHeight),
      "This transport will stay at this height when picking up and dropping off units"
    );
    AddFieldWithDescription(typeInfo, "PredictAheadForBombDrop", CachedFloatType(), offsetof(RUnitBlueprintAir, PredictAheadForBombDrop), "Time to predict ahead for moving targets?");
  }

  /**
   * Address: 0x00520E70 (FUN_00520E70)
   *
   * What it does:
   * Sets `RUnitBlueprintAir` size and publishes air field metadata.
   */
  void RUnitBlueprintAirTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintAir);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521300 (FUN_00521300, Moho::RUnitBlueprintTransportTypeInfo::RUnitBlueprintTransportTypeInfo)
   */
  RUnitBlueprintTransportTypeInfo::RUnitBlueprintTransportTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintTransport), this);
  }

  /**
   * Address: 0x00521390 (FUN_00521390, scalar deleting destructor thunk)
   */
  RUnitBlueprintTransportTypeInfo::~RUnitBlueprintTransportTypeInfo() = default;

  /**
   * Address: 0x00521380 (FUN_00521380)
   */
  const char* RUnitBlueprintTransportTypeInfo::GetName() const
  {
    return "RUnitBlueprintTransport";
  }

  /**
   * Address: 0x00521430 (FUN_00521430)
   *
   * What it does:
   * Registers `RUnitBlueprintTransport` field descriptors and descriptions.
   */
  void RUnitBlueprintTransportTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "TransportClass", CachedInt32Type(), offsetof(RUnitBlueprintTransport, TransportClass), "Type of attach points required on transports");
    AddFieldWithDescription(typeInfo, "ClassGenericUpTo", CachedInt32Type(), offsetof(RUnitBlueprintTransport, ClassGenericUpTo), "Generic slots up to the specified class");
    AddFieldWithDescription(typeInfo, "Class2AttachSize", CachedInt32Type(), offsetof(RUnitBlueprintTransport, Class2AttachSize), "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "Class3AttachSize", CachedInt32Type(), offsetof(RUnitBlueprintTransport, Class3AttachSize), "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "Class4AttachSize", CachedInt32Type(), offsetof(RUnitBlueprintTransport, Class4AttachSize), "Number of class 1 attach points this affects");
    AddFieldWithDescription(typeInfo, "ClassSAttachSize", CachedInt32Type(), offsetof(RUnitBlueprintTransport, ClassSAttachSize), "Number of class 1 attach points this affects");
    AddFieldWithDescription(
      typeInfo,
      "AirClass",
      CachedBoolType(),
      offsetof(RUnitBlueprintTransport, AirClass),
      "These define that the unit can only land on air staging platforms"
    );
    AddFieldWithDescription(
      typeInfo,
      "StorageSlots",
      CachedInt32Type(),
      offsetof(RUnitBlueprintTransport, StorageSlots),
      "How many internal storage slots available for the transport on top of the attach points"
    );
    AddFieldWithDescription(
      typeInfo,
      "DockingSlots",
      CachedInt32Type(),
      offsetof(RUnitBlueprintTransport, DockingSlots),
      "How many external docking slots available for air staging platforms"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairRate",
      CachedFloatType(),
      offsetof(RUnitBlueprintTransport, RepairRate),
      "Repairs units attached to me at this % of max health per second"
    );
  }

  /**
   * Address: 0x00521360 (FUN_00521360)
   *
   * What it does:
   * Sets `RUnitBlueprintTransport` size and publishes transport field metadata.
   */
  void RUnitBlueprintTransportTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintTransport);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521530 (FUN_00521530, Moho::RUnitBlueprintAITypeInfo::RUnitBlueprintAITypeInfo)
   */
  RUnitBlueprintAITypeInfo::RUnitBlueprintAITypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintAI), this);
  }

  /**
   * Address: 0x005215C0 (FUN_005215C0, scalar deleting destructor thunk)
   */
  RUnitBlueprintAITypeInfo::~RUnitBlueprintAITypeInfo() = default;

  /**
   * Address: 0x005215B0 (FUN_005215B0)
   */
  const char* RUnitBlueprintAITypeInfo::GetName() const
  {
    return "RUnitBlueprintAI";
  }

  /**
   * Address: 0x00521660 (FUN_00521660)
   *
   * What it does:
   * Registers `RUnitBlueprintAI` field descriptors and descriptions.
   */
  void RUnitBlueprintAITypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "GuardScanRadius", CachedFloatType(), offsetof(RUnitBlueprintAI, GuardScanRadius), "Guard range for the unit");
    AddFieldWithDescription(
      typeInfo,
      "GuardReturnRadius",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, GuardReturnRadius),
      "Maximum range from the guarded unit before initiating return"
    );
    AddFieldWithDescription(
      typeInfo,
      "StagingPlatformScanRadius",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, StagingPlatformScanRadius),
      "Range for staging platforms to look for planes to repair and refuel when they are on patrol"
    );
    AddFieldWithDescription(
      typeInfo,
      "ShowAssistRangeOnSelect",
      CachedBoolType(),
      offsetof(RUnitBlueprintAI, ShowAssistRangeOnSelect),
      "Show assist range for the unit if selected"
    );
    AddFieldWithDescription(
      typeInfo,
      "GuardFormationName",
      CachedStringType(),
      offsetof(RUnitBlueprintAI, GuardFormationName),
      "The formation name used for guarding this unit"
    );
    AddFieldWithDescription(typeInfo, "NeedUnpack", CachedBoolType(), offsetof(RUnitBlueprintAI, NeedUnpack), "Unit should unpack before firing weapon");
    AddFieldWithDescription(typeInfo, "InitialAutoMode", CachedBoolType(), offsetof(RUnitBlueprintAI, InitialAutoMode), "Initial auto mode behavior for the unit");
    AddFieldWithDescription(
      typeInfo,
      "BeaconName",
      CachedStringType(),
      offsetof(RUnitBlueprintAI, BeaconName),
      "Thie is the beacon that this unit will create under some circumstances"
    );
    gpg::RField* const targetBonesField = typeInfo->AddFieldVectorString("TargetBones", offsetof(RUnitBlueprintAI, TargetBones));
    targetBonesField->v4 = 3;
    targetBonesField->mDesc = "Some target bones setup for other units to aim at instead of the default center pos";
    AddFieldWithDescription(
      typeInfo,
      "RefuelingMultiplier",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, RefuelingMultiplier),
      "This multiplier is applied when a staging platform is refueling an air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "RefuelingRepairAmount",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, RefuelingRepairAmount),
      "This amount of repair per second offered to refueling air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairConsumeEnergy",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, RepairConsumeEnergy),
      "This amount of energy per second required to repair air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "RepairConsumeMass",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, RepairConsumeMass),
      "This amount of mass per second require to repair air unit"
    );
    AddFieldWithDescription(
      typeInfo,
      "AutoSurfaceToAttack",
      CachedBoolType(),
      offsetof(RUnitBlueprintAI, AutoSurfaceToAttack),
      "Automatically surface to attack ground targets"
    );
    AddFieldWithDescription(
      typeInfo,
      "AttackAngle",
      CachedFloatType(),
      offsetof(RUnitBlueprintAI, AttackAngle),
      "Desired angle to face target to maximize the number of guns able to hit the targets"
    );
  }

  /**
   * Address: 0x00521590 (FUN_00521590)
   *
   * What it does:
   * Sets `RUnitBlueprintAI` size and publishes AI field metadata.
   */
  void RUnitBlueprintAITypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintAI);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521980 (FUN_00521980, Moho::RUnitBlueprintDefenseTypeInfo::RUnitBlueprintDefenseTypeInfo)
   */
  RUnitBlueprintDefenseTypeInfo::RUnitBlueprintDefenseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintDefense), this);
  }

  /**
   * Address: 0x00521A10 (FUN_00521A10, scalar deleting destructor thunk)
   */
  RUnitBlueprintDefenseTypeInfo::~RUnitBlueprintDefenseTypeInfo() = default;

  /**
   * Address: 0x00521A00 (FUN_00521A00)
   */
  const char* RUnitBlueprintDefenseTypeInfo::GetName() const
  {
    return "RUnitBlueprintDefense";
  }

  /**
   * Address: 0x005255A0 (FUN_005255A0, gpg::RType::AddField_RUnitBlueprintDefenseShield_0x38Shield)
   *
   * What it does:
   * Appends the reflected `Shield` field descriptor at offset `0x38`.
   */
  gpg::RField* RUnitBlueprintDefenseTypeInfo::AddFieldShield(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("Shield", CachedDefenseShieldType(), offsetof(RUnitBlueprintDefense, Shield), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00521AB0 (FUN_00521AB0)
   *
   * What it does:
   * Registers `RUnitBlueprintDefense` field descriptors and descriptions.
   */
  void RUnitBlueprintDefenseTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "MaxHealth", CachedFloatType(), offsetof(RUnitBlueprintDefense, MaxHealth), "Max health value for the unit");
    AddFieldWithDescription(typeInfo, "Health", CachedFloatType(), offsetof(RUnitBlueprintDefense, Health), "Starting health value for the unit");
    AddFieldWithDescription(typeInfo, "RegenRate", CachedFloatType(), offsetof(RUnitBlueprintDefense, RegenRate), "Amount of health to regenerate per second");
    AddFieldWithDescription(
      typeInfo,
      "AirThreatLevel",
      CachedFloatType(),
      offsetof(RUnitBlueprintDefense, AirThreatLevel),
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "SurfaceThreatLevel",
      CachedFloatType(),
      offsetof(RUnitBlueprintDefense, SurfaceThreatLevel),
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "SubThreatLevel",
      CachedFloatType(),
      offsetof(RUnitBlueprintDefense, SubThreatLevel),
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(
      typeInfo,
      "EconomyThreatLevel",
      CachedFloatType(),
      offsetof(RUnitBlueprintDefense, EconomyThreatLevel),
      "Amount of threat this poses to the enemy air units"
    );
    AddFieldWithDescription(typeInfo, "ArmorType", CachedStringType(), offsetof(RUnitBlueprintDefense, ArmorType), "The Armor type name");
    gpg::RField* const shieldField = AddFieldShield(typeInfo);
    shieldField->v4 = 3;
    shieldField->mDesc = "Shield information";
  }

  /**
   * Address: 0x005219E0 (FUN_005219E0)
   *
   * What it does:
   * Sets `RUnitBlueprintDefense` size and publishes defense field metadata.
   */
  void RUnitBlueprintDefenseTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintDefense);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00521B80 (FUN_00521B80, Moho::RUnitBlueprintIntelTypeInfo::RUnitBlueprintIntelTypeInfo)
   */
  RUnitBlueprintIntelTypeInfo::RUnitBlueprintIntelTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintIntel), this);
  }

  /**
   * Address: 0x00521C10 (FUN_00521C10, scalar deleting destructor thunk)
   */
  RUnitBlueprintIntelTypeInfo::~RUnitBlueprintIntelTypeInfo() = default;

  /**
   * Address: 0x00521C00 (FUN_00521C00)
   */
  const char* RUnitBlueprintIntelTypeInfo::GetName() const
  {
    return "RUnitBlueprintIntel";
  }

  /**
   * Address: 0x00525620 (FUN_00525620, gpg::RType::AddFieldSMinMaxUint)
   *
   * What it does:
   * Appends a reflected `SMinMax<uint32_t>` field descriptor.
   */
  gpg::RField* RUnitBlueprintIntelTypeInfo::AddFieldSMinMaxUInt(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    const int offset
  )
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField(fieldName, CachedSMinMaxUInt32Type(), offset, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00521CB0 (FUN_00521CB0)
   *
   * What it does:
   * Registers `RUnitBlueprintIntel` field descriptors and descriptions.
   */
  void RUnitBlueprintIntelTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "VisionRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, VisionRadius), "How far we can see above water");
    AddFieldWithDescription(typeInfo, "WaterVisionRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, WaterVisionRadius), "How far we can see underwater");
    AddFieldWithDescription(typeInfo, "RadarRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, RadarRadius), "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "SonarRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, SonarRadius), "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "OmniRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, OmniRadius), "How far our radar coverage goes");
    AddFieldWithDescription(typeInfo, "RadarStealth", CachedBoolType(), offsetof(RUnitBlueprintIntel, RadarStealth), "Single unit radar stealth");
    AddFieldWithDescription(typeInfo, "SonarStealth", CachedBoolType(), offsetof(RUnitBlueprintIntel, SonarStealth), "Single unit sonar stealth");
    AddFieldWithDescription(typeInfo, "Cloak", CachedBoolType(), offsetof(RUnitBlueprintIntel, Cloak), "Single unit cloaking");
    AddFieldWithDescription(typeInfo, "ShowIntelOnSelect", CachedBoolType(), offsetof(RUnitBlueprintIntel, ShowIntelOnSelect), "Show intel radius of unit if selected");
    AddFieldWithDescription(
      typeInfo,
      "RadarStealthFieldRadius",
      CachedUInt32Type(),
      offsetof(RUnitBlueprintIntel, RadarStealthFieldRadius),
      "How far our radar stealth goes"
    );
    AddFieldWithDescription(
      typeInfo,
      "SonarStealthFieldRadius",
      CachedUInt32Type(),
      offsetof(RUnitBlueprintIntel, SonarStealthFieldRadius),
      "How far our sonar stealth goes"
    );
    AddFieldWithDescription(typeInfo, "CloakFieldRadius", CachedUInt32Type(), offsetof(RUnitBlueprintIntel, CloakFieldRadius), "How far our cloaking goes");
    gpg::RField* const jamRadiusField = AddFieldSMinMaxUInt(typeInfo, "JamRadius", offsetof(RUnitBlueprintIntel, JamRadius));
    jamRadiusField->v4 = 3;
    jamRadiusField->mDesc = "How far we create fake blips";
    gpg::RField* const spoofRadiusField = AddFieldSMinMaxUInt(typeInfo, "SpoofRadius", offsetof(RUnitBlueprintIntel, SpoofRadius));
    spoofRadiusField->v4 = 3;
    spoofRadiusField->mDesc = "How far off to displace blip";
    gpg::RField* const jammerBlipsField = typeInfo->AddFieldUChar("JammerBlips", offsetof(RUnitBlueprintIntel, JammerBlips));
    jammerBlipsField->v4 = 3;
    jammerBlipsField->mDesc = "How many blips does a jammer produce?";
  }

  /**
   * Address: 0x00521BE0 (FUN_00521BE0)
   *
   * What it does:
   * Sets `RUnitBlueprintIntel` size and publishes intel field metadata.
   */
  void RUnitBlueprintIntelTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintIntel);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00521E10 (FUN_00521E10, Moho::RUnitBlueprintEconomyTypeInfo::RUnitBlueprintEconomyTypeInfo)
   */
  RUnitBlueprintEconomyTypeInfo::RUnitBlueprintEconomyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintEconomy), this);
  }

  /**
   * Address: 0x00521EA0 (FUN_00521EA0, scalar deleting destructor thunk)
   */
  RUnitBlueprintEconomyTypeInfo::~RUnitBlueprintEconomyTypeInfo() = default;

  /**
   * Address: 0x00521E90 (FUN_00521E90)
   */
  const char* RUnitBlueprintEconomyTypeInfo::GetName() const
  {
    return "RUnitBlueprintEconomy";
  }

  /**
   * Address: 0x00521F40 (FUN_00521F40)
   *
   * What it does:
   * Registers `RUnitBlueprintEconomy` field descriptors and descriptions.
   */
  void RUnitBlueprintEconomyTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BuildCostEnergy", CachedFloatType(), offsetof(RUnitBlueprintEconomy, BuildCostEnergy), "Energy cost to build this unit");
    AddFieldWithDescription(typeInfo, "BuildCostMass", CachedFloatType(), offsetof(RUnitBlueprintEconomy, BuildCostMass), "Mass cost to build this unit");
    AddFieldWithDescription(typeInfo, "BuildRate", CachedFloatType(), offsetof(RUnitBlueprintEconomy, BuildRate), "How efficient a unit is at building");
    AddFieldWithDescription(typeInfo, "BuildTime", CachedFloatType(), offsetof(RUnitBlueprintEconomy, BuildTime), "How long it takes to build this unit (in seconds)");
    AddFieldWithDescription(
      typeInfo,
      "StorageEnergy",
      CachedFloatType(),
      offsetof(RUnitBlueprintEconomy, StorageEnergy),
      "Energy storage capacity provided by this unit"
    );
    AddFieldWithDescription(typeInfo, "StorageMass", CachedFloatType(), offsetof(RUnitBlueprintEconomy, StorageMass), "Mass storage capacity provided by this unit");
    AddFieldWithDescription(
      typeInfo,
      "NaturalProducer",
      CachedBoolType(),
      offsetof(RUnitBlueprintEconomy, NaturalProducer),
      "Produces resouce naturally and does not consume anything"
    );

    gpg::RField* const buildableCategoriesField = typeInfo->AddFieldVectorString("BuildableCategories", offsetof(RUnitBlueprintEconomy, BuildableCategories));
    buildableCategoriesField->v4 = 3;
    buildableCategoriesField->mDesc = "One of the unit categories that can be built by this unit";
    SetLastFieldName(typeInfo, "BuildableCategory");

    gpg::RField* const rebuildBonusIdsField = typeInfo->AddFieldVectorString("RebuildBonusIds", offsetof(RUnitBlueprintEconomy, RebuildBonusIds));
    rebuildBonusIdsField->v4 = 3;
    rebuildBonusIdsField->mDesc = "You will get bonus if you rebuild this unit over the wreckage of these wreckages";

    AddFieldWithDescription(typeInfo, "InitialRallyX", CachedFloatType(), offsetof(RUnitBlueprintEconomy, InitialRallyX), "default rally point Xfor the factory");
    AddFieldWithDescription(typeInfo, "InitialRallyZ", CachedFloatType(), offsetof(RUnitBlueprintEconomy, InitialRallyZ), "default rally point Z for the factory");
    AddFieldWithDescription(
      typeInfo,
      "NeedToFaceTargetToBuild",
      CachedBoolType(),
      offsetof(RUnitBlueprintEconomy, NeedToFaceTargetToBuild),
      "builder needs to face target before it can build/repair"
    );
    AddFieldWithDescription(
      typeInfo,
      "SacrificeMassMult",
      CachedFloatType(),
      offsetof(RUnitBlueprintEconomy, SacrificeMassMult),
      "builder will kill self but provide this amount of mass based on builder's mass cost to the unit it is helping"
    );
    AddFieldWithDescription(
      typeInfo,
      "SacrificeEnergyMult",
      CachedFloatType(),
      offsetof(RUnitBlueprintEconomy, SacrificeEnergyMult),
      "builder will kill self but provide this amount of energy based on the builder's energy cost to the unit it is helping"
    );
    AddFieldWithDescription(
      typeInfo,
      "MaxBuildDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintEconomy, MaxBuildDistance),
      "Maximum build range of the unit. The target must be within this range before the builder can perform operation"
    );
  }

  /**
   * Address: 0x00521E70 (FUN_00521E70)
   *
   * What it does:
   * Sets `RUnitBlueprintEconomy` size and publishes economy field metadata.
   */
  void RUnitBlueprintEconomyTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintEconomy);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }
  /**
   * Address: 0x00522210 (FUN_00522210, Moho::RUnitBlueprintWeaponTypeInfo::RUnitBlueprintWeaponTypeInfo)
   */
  RUnitBlueprintWeaponTypeInfo::RUnitBlueprintWeaponTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RUnitBlueprintWeapon), this);
  }

  /**
   * Address: 0x005222A0 (FUN_005222A0, scalar deleting destructor thunk)
   */
  RUnitBlueprintWeaponTypeInfo::~RUnitBlueprintWeaponTypeInfo() = default;

  /**
   * Address: 0x00522290 (FUN_00522290)
   */
  const char* RUnitBlueprintWeaponTypeInfo::GetName() const
  {
    return "RUnitBlueprintWeapon";
  }

  /**
   * Address: 0x005256A0 (FUN_005256A0, gpg::RType::AddField_UnitWeaponRangeCategory_0x40RangeCategory)
   *
   * What it does:
   * Appends the reflected `RangeCategory` field descriptor at offset `0x40`.
   */
  gpg::RField* RUnitBlueprintWeaponTypeInfo::AddFieldRangeCategory(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("RangeCategory", CachedWeaponRangeCategoryType(), offsetof(RUnitBlueprintWeapon, RangeCategory), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00525720 (FUN_00525720, gpg::RType::AddField_ERuleBPUnitWeaponBallisticArc_0xE4BallisticArc)
   *
   * What it does:
   * Appends the reflected `BallisticArc` field descriptor at offset `0xE4`.
   */
  gpg::RField* RUnitBlueprintWeaponTypeInfo::AddFieldBallisticArc(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("BallisticArc", CachedWeaponBallisticArcType(), offsetof(RUnitBlueprintWeapon, BallisticArc), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x005257A0 (FUN_005257A0, gpg::RType::AddField_ERuleBPUnitWeaponTargetType_0x130TargetType)
   *
   * What it does:
   * Appends the reflected `TargetType` field descriptor at offset `0x130`.
   */
  gpg::RField* RUnitBlueprintWeaponTypeInfo::AddFieldTargetType(gpg::RType* const typeInfo)
  {
    if (!typeInfo) {
      return nullptr;
    }

    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->fields_.push_back(gpg::RField("TargetType", CachedWeaponTargetType(), offsetof(RUnitBlueprintWeapon, TargetType), 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00522340 (FUN_00522340)
   *
   * What it does:
   * Registers `RUnitBlueprintWeapon` field descriptors and descriptions.
   */
  void RUnitBlueprintWeaponTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "Label", CachedStringType(), offsetof(RUnitBlueprintWeapon, Label), "The label to pass to scripts to id this weapon.");
    AddFieldWithDescription(typeInfo, "DisplayName", CachedStringType(), offsetof(RUnitBlueprintWeapon, DisplayName), "The display name of this weapon.");
    gpg::RField* const rangeCategoryField = AddFieldRangeCategory(typeInfo);
    rangeCategoryField->v4 = 3;
    rangeCategoryField->mDesc = "The range category this weapon satisfies.";
    AddFieldWithDescription(
      typeInfo,
      "DummyWeapon",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, DummyWeapon),
      "True if the engine should not create an actual weapon for this blueprint. This is used for special damage like the Spiderbot's feet, where no real weapon exists, but we still want a consistent way to spec damage types etc."
    );
    AddFieldWithDescription(typeInfo, "TargetCheckInterval", CachedFloatType(), offsetof(RUnitBlueprintWeapon, TargetCheckInterval), "Interval between checks for a new weapon target. Default is three seconds.");
    AddFieldWithDescription(
      typeInfo,
      "AlwaysRecheckTarget",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, AlwaysRecheckTarget),
      "Always recheck for better target regardless of whether you already have one or not."
    );
    AddFieldWithDescription(
      typeInfo,
      "PrefersPrimaryWeaponTarget",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, PrefersPrimaryWeaponTarget),
      "Flag to specify if the weapon prefers to target what the primary weapon is currently targetting."
    );
    AddFieldWithDescription(
      typeInfo,
      "StopOnPrimaryWeaponBusy",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, StopOnPrimaryWeaponBusy),
      "Flag to specify to not make weapon active if the primary weapon has a current target."
    );
    AddFieldWithDescription(
      typeInfo,
      "SlavedToBody",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, SlavedToBody),
      "Flag to specify if the weapon is slaved to the unit body, thus requiring unit to face target to fire."
    );
    AddFieldWithDescription(typeInfo, "SlavedToBodyArcRange", CachedFloatType(), offsetof(RUnitBlueprintWeapon, SlavedToBodyArcRange), "Range of arc to be considered slaved to a target.");
    AddFieldWithDescription(
      typeInfo,
      "AutoInitiateAttackCommand",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, AutoInitiateAttackCommand),
      "Flag to specify if the unit will initate an attack command when idle if an enemy target comes within firing/tracking range."
    );
    AddFieldWithDescription(typeInfo, "MinRadius", CachedFloatType(), offsetof(RUnitBlueprintWeapon, MinRadius), "The minimum range we must be to fire at our target.");
    AddFieldWithDescription(typeInfo, "MaxRadius", CachedFloatType(), offsetof(RUnitBlueprintWeapon, MaxRadius), "The maximum range we can be to fire at our target.");
    AddFieldWithDescription(typeInfo, "EffectiveRadius", CachedFloatType(), offsetof(RUnitBlueprintWeapon, EffectiveRadius), "The effective range that this weapon really is.");
    AddFieldWithDescription(
      typeInfo,
      "MaxHeightDiff",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, MaxHeightDiff),
      "The maximum height diff range for the weapon. Keep in mind weapons are now cylinder in nature."
    );
    AddFieldWithDescription(
      typeInfo,
      "TrackingRadius",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, TrackingRadius),
      "The range where we begin tracking a unit but will not fire yet; multiplier of the weapon's MaxRadius"
    );
    AddFieldWithDescription(typeInfo, "HeadingArcCenter", CachedFloatType(), offsetof(RUnitBlueprintWeapon, HeadingArcCenter), "Center of firing arc for this weapon, in degrees. Default is 0");
    AddFieldWithDescription(
      typeInfo,
      "HeadingArcRange",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, HeadingArcRange),
      "Maximum angle from HeadingArcCenter, in degrees. Default is 180, meaning weapon can aim anywhere."
    );
    AddFieldWithDescription(typeInfo, "FiringTolerance", CachedFloatType(), offsetof(RUnitBlueprintWeapon, FiringTolerance), "How accurate do we have to be aimed before we take a shot.  In degrees.");
    AddFieldWithDescription(typeInfo, "FiringRandomness", CachedFloatType(), offsetof(RUnitBlueprintWeapon, FiringRandomness), "How many degrees of arc can we randomly be off by (gaussian)");
    AddFieldWithDescription(typeInfo, "IgnoreIfDisabled", CachedBoolType(), offsetof(RUnitBlueprintWeapon, IgnoreIfDisabled), "Does not consider weapon when attacking targets if it is disabled");
    AddFieldWithDescription(typeInfo, "CannotAttackGround", CachedBoolType(), offsetof(RUnitBlueprintWeapon, CannotAttackGround), "Weapon cannot attack ground positions");
    AddFieldWithDescription(typeInfo, "RequiresEnergy", CachedFloatType(), offsetof(RUnitBlueprintWeapon, RequiresEnergy), "Weapon requires this much available energy to fire");
    AddFieldWithDescription(typeInfo, "RequiresMass", CachedFloatType(), offsetof(RUnitBlueprintWeapon, RequiresMass), "Weapon requires this much available mass to fire");
    AddFieldWithDescription(typeInfo, "MuzzleVelocity", CachedFloatType(), offsetof(RUnitBlueprintWeapon, MuzzleVelocity), "Weapon's muzzle velocity");
    AddFieldWithDescription(typeInfo, "MuzzleVelocityRandom", CachedFloatType(), offsetof(RUnitBlueprintWeapon, MuzzleVelocityRandom), "Random variation for muzzle velocity (gaussian)");
    AddFieldWithDescription(
      typeInfo,
      "MuzzleVelocityReduceDistance",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, MuzzleVelocityReduceDistance),
      "Target distance at which weapon will start reducing muzzle velocity to maintain a higher firing arc."
    );
    AddFieldWithDescription(typeInfo, "LeadTarget", CachedBoolType(), offsetof(RUnitBlueprintWeapon, LeadTarget), "True if weapon should lead its target when aiming.");
    AddFieldWithDescription(
      typeInfo,
      "ProjectileLifetime",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, ProjectileLifetime),
      "Lifetime for projectile in seconds. If 0, the projectile will use the lifetime from its own blueprint."
    );
    AddFieldWithDescription(
      typeInfo,
      "ProjectileLifetimeUsesMultiplier",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, ProjectileLifetimeUsesMultiplier),
      "Lifetime for projectile based on lifetime equation of Multiplier * (MaxRadius/MuzzleVelocity)"
    );
    AddFieldWithDescription(typeInfo, "Damage", CachedFloatType(), offsetof(RUnitBlueprintWeapon, Damage), "How much damage to cause.");
    AddFieldWithDescription(typeInfo, "DamageRadius", CachedFloatType(), offsetof(RUnitBlueprintWeapon, DamageRadius), "Radius to inflict damage in.");
    AddFieldWithDescription(typeInfo, "DamageType", CachedStringType(), offsetof(RUnitBlueprintWeapon, DamageType), "Type of damage this weapon deals");
    AddFieldWithDescription(typeInfo, "RateOfFire", CachedFloatType(), offsetof(RUnitBlueprintWeapon, RateOfFire), "How many shots/second we can fire.");
    AddFieldWithDescription(typeInfo, "ProjectileId", CachedRResIdType(), offsetof(RUnitBlueprintWeapon, ProjectileId), "Blueprint Id for projectile, if any.");
    gpg::RField* const ballisticArcField = AddFieldBallisticArc(typeInfo);
    ballisticArcField->v4 = 3;
    ballisticArcField->mDesc = "High or low arc for projectiles";
    AddFieldWithDescription(
      typeInfo,
      "TargetRestrictOnlyAllow",
      CachedStringType(),
      offsetof(RUnitBlueprintWeapon, TargetRestrictOnlyAllow),
      "Comma separated list of Entity Category that are the only valid targets."
    );
    AddFieldWithDescription(
      typeInfo,
      "TargetRestrictDisallow",
      CachedStringType(),
      offsetof(RUnitBlueprintWeapon, TargetRestrictDisallow),
      "Comma separated list of Entity Category that are always invalid targets."
    );
    gpg::RField* const targetTypeField = AddFieldTargetType(typeInfo);
    targetTypeField->v4 = 3;
    targetTypeField->mDesc = "The type of entity this unit can target.";
    AddFieldWithDescription(typeInfo, "ManualFire", CachedBoolType(), offsetof(RUnitBlueprintWeapon, ManualFire), "Never fires automaticly.");
    AddFieldWithDescription(typeInfo, "NukeWeapon", CachedBoolType(), offsetof(RUnitBlueprintWeapon, NukeWeapon), "Nuke weapon flag.");
    AddFieldWithDescription(typeInfo, "OverChargeWeapon", CachedBoolType(), offsetof(RUnitBlueprintWeapon, OverChargeWeapon), "Overcharge weapon flag.");
    AddFieldWithDescription(typeInfo, "NeedPrep", CachedBoolType(), offsetof(RUnitBlueprintWeapon, NeedPrep), "Weapon needs prep time (applies to most Aeon units).");
    AddFieldWithDescription(typeInfo, "CountedProjectile", CachedBoolType(), offsetof(RUnitBlueprintWeapon, CountedProjectile), "This projectile needs to be built and stored before the weapon can fire");
    AddFieldWithDescription(typeInfo, "MaxProjectileStorage", CachedInt32Type(), offsetof(RUnitBlueprintWeapon, MaxProjectileStorage), "This weapon can only hold this many counted projectiles");
    AddFieldWithDescription(typeInfo, "IgnoreIfDisabled", CachedBoolType(), offsetof(RUnitBlueprintWeapon, IgnoreIfDisabled), "Ignore trying to use the weapon if it's disabled.");
    AddFieldWithDescription(typeInfo, "IgnoresAlly", CachedBoolType(), offsetof(RUnitBlueprintWeapon, IgnoresAlly), "This determines whether the weapon affect ally units or not");
    AddFieldWithDescription(typeInfo, "AttackGroundTries", CachedInt32Type(), offsetof(RUnitBlueprintWeapon, AttackGroundTries), "This determines the number of shots at a ground target before moving on to the enxt target");
    AddFieldWithDescription(typeInfo, "AimsStraightOnDisable", CachedBoolType(), offsetof(RUnitBlueprintWeapon, AimsStraightOnDisable), "This weapon will aim straight ahead when disabled");
    AddFieldWithDescription(typeInfo, "Turreted", CachedBoolType(), offsetof(RUnitBlueprintWeapon, Turreted), "This weapon is on a turret");
    AddFieldWithDescription(typeInfo, "YawOnlyOnTarget", CachedBoolType(), offsetof(RUnitBlueprintWeapon, YawOnlyOnTarget), "This weapon is considered on target if the yaw is facing the target");
    AddFieldWithDescription(typeInfo, "AboveWaterFireOnly", CachedBoolType(), offsetof(RUnitBlueprintWeapon, AboveWaterFireOnly), "This weapon will only fire if it is above water");
    AddFieldWithDescription(typeInfo, "BelowWaterFireOnly", CachedBoolType(), offsetof(RUnitBlueprintWeapon, BelowWaterFireOnly), "This weapon will only fire if it is below water");
    AddFieldWithDescription(typeInfo, "AboveWaterTargetsOnly", CachedBoolType(), offsetof(RUnitBlueprintWeapon, AboveWaterTargetsOnly), "This weapon will only at targets above water");
    AddFieldWithDescription(typeInfo, "BelowWaterTargetsOnly", CachedBoolType(), offsetof(RUnitBlueprintWeapon, BelowWaterTargetsOnly), "This weapon will only at targets below water");
    AddFieldWithDescription(typeInfo, "NeedToComputeBombDrop", CachedBoolType(), offsetof(RUnitBlueprintWeapon, NeedToComputeBombDrop), "This to compute when to drop bomb?");
    AddFieldWithDescription(typeInfo, "BombDropThreshold", CachedFloatType(), offsetof(RUnitBlueprintWeapon, BombDropThreshold), "Threshold to release point before releasing ordinance?");
    AddFieldWithDescription(typeInfo, "ReTargetOnMiss", CachedBoolType(), offsetof(RUnitBlueprintWeapon, ReTargetOnMiss), "This weapon will find new target on miss events");
    AddFieldWithDescription(
      typeInfo,
      "UseFiringSolutionInsteadOfAimBone",
      CachedBoolType(),
      offsetof(RUnitBlueprintWeapon, UseFiringSolutionInsteadOfAimBone),
      "This weapon uses the recent firing solution to create projectile istead of the aim bone transform"
    );
    AddFieldWithDescription(
      typeInfo,
      "UIMinRangeVisualId",
      CachedStringType(),
      offsetof(RUnitBlueprintWeapon, UIMinRangeVisualId),
      "Allows the UI to know what kind of minimum range indicator to draw for this weapon."
    );
    AddFieldWithDescription(
      typeInfo,
      "UIMaxRangeVisualId",
      CachedStringType(),
      offsetof(RUnitBlueprintWeapon, UIMaxRangeVisualId),
      "Allows the UI to know what kind of maximum range indicator to draw for this weapon."
    );
    AddFieldWithDescription(
      typeInfo,
      "MaximumBeamLength",
      CachedFloatType(),
      offsetof(RUnitBlueprintWeapon, MaximumBeamLength),
      "Allows the setting of the Maximum Beam length so beams and radius can be different. Default to MaxRadius."
    );
  }

  /**
   * Address: 0x00522270 (FUN_00522270)
   *
   * What it does:
   * Sets `RUnitBlueprintWeapon` size and publishes weapon field metadata.
   */
  void RUnitBlueprintWeaponTypeInfo::Init()
  {
    size_ = sizeof(RUnitBlueprintWeapon);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8A90 (FUN_00BC8A90, register_RUnitBlueprintGeneralTypeInfo)
   */
  void register_RUnitBlueprintGeneralTypeInfo()
  {
    (void)AcquireRUnitBlueprintGeneralTypeInfo();
  }

  /**
   * Address: 0x00BC8AB0 (FUN_00BC8AB0, register_RUnitBlueprintDisplayTypeInfo)
   */
  void register_RUnitBlueprintDisplayTypeInfo()
  {
    (void)AcquireRUnitBlueprintDisplayTypeInfo();
  }

  /**
   * Address: 0x00BC8AD0 (FUN_00BC8AD0, register_RUnitBlueprintPhysicsTypeInfo)
   */
  void register_RUnitBlueprintPhysicsTypeInfo()
  {
    (void)AcquireRUnitBlueprintPhysicsTypeInfo();
  }

  /**
   * Address: 0x00BC8AF0 (FUN_00BC8AF0, register_RUnitBlueprintAirTypeInfo)
   */
  void register_RUnitBlueprintAirTypeInfo()
  {
    (void)AcquireRUnitBlueprintAirTypeInfo();
  }

  /**
   * Address: 0x00BC8B10 (FUN_00BC8B10, register_RUnitBlueprintTransportTypeInfo)
   */
  void register_RUnitBlueprintTransportTypeInfo()
  {
    (void)AcquireRUnitBlueprintTransportTypeInfo();
  }

  /**
   * Address: 0x00BC8B30 (FUN_00BC8B30, register_RUnitBlueprintAITypeInfo)
   */
  void register_RUnitBlueprintAITypeInfo()
  {
    (void)AcquireRUnitBlueprintAITypeInfo();
  }

  /**
   * Address: 0x00BC8B70 (FUN_00BC8B70, register_RUnitBlueprintDefenseTypeInfo)
   */
  void register_RUnitBlueprintDefenseTypeInfo()
  {
    (void)AcquireRUnitBlueprintDefenseTypeInfo();
  }

  /**
   * Address: 0x00BC8B90 (FUN_00BC8B90, register_RUnitBlueprintIntelTypeInfo)
   */
  void register_RUnitBlueprintIntelTypeInfo()
  {
    (void)AcquireRUnitBlueprintIntelTypeInfo();
  }

  /**
   * Address: 0x00BC8BB0 (FUN_00BC8BB0, register_RUnitBlueprintEconomyTypeInfo)
   */
  void register_RUnitBlueprintEconomyTypeInfo()
  {
    (void)AcquireRUnitBlueprintEconomyTypeInfo();
  }

  /**
   * Address: 0x00BC8BF0 (FUN_00BC8BF0, register_RUnitBlueprintWeaponTypeInfo)
   */
  void register_RUnitBlueprintWeaponTypeInfo()
  {
    (void)AcquireRUnitBlueprintWeaponTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RUnitBlueprintGeneralTypeInfo_db3407, moho::register_RUnitBlueprintGeneralTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintDisplayTypeInfo_db3407, moho::register_RUnitBlueprintDisplayTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintPhysicsTypeInfo_db3407, moho::register_RUnitBlueprintPhysicsTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintAirTypeInfo_db3407, moho::register_RUnitBlueprintAirTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintTransportTypeInfo_db3407, moho::register_RUnitBlueprintTransportTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintAITypeInfo_db3407, moho::register_RUnitBlueprintAITypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintDefenseTypeInfo_db3407, moho::register_RUnitBlueprintDefenseTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintIntelTypeInfo_db3407, moho::register_RUnitBlueprintIntelTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintEconomyTypeInfo_db3407, moho::register_RUnitBlueprintEconomyTypeInfo)
GPG_PREREGISTER_INIT(register_RUnitBlueprintWeaponTypeInfo_db3407, moho::register_RUnitBlueprintWeaponTypeInfo)

GPG_PREREGISTER_INIT(register_VectorFloatReflectionType_db3407, register_VectorFloatReflectionType)
