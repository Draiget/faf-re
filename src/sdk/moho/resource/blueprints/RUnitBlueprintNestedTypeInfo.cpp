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

      out = gpg::MakeRRef<float>(&(*storage)[static_cast<std::size_t>(ind)]);
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

  [[nodiscard]] gpg::RType* CachedFloatType()
  {
    return gpg::RTypeOf<float>();
  }

  [[nodiscard]] gpg::RType* CachedMovementType()
  {
    return gpg::RTypeOf<moho::ERuleBPUnitMovementType>();
  }

  [[nodiscard]] gpg::RType* CachedSMinMaxUInt32Type()
  {
    return gpg::RTypeOf<moho::SMinMax<std::uint32_t>>();
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
   * Address: 0x00520660 (FUN_00520660)
   *
   * What it does:
   * Registers `RUnitBlueprintGeneral` field descriptors and descriptions.
   */
  void RUnitBlueprintGeneralTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* const commandCapsField = typeInfo->AddField<moho::ERuleBPUnitCommandCaps>("CommandCaps", offsetof(RUnitBlueprintGeneral, CommandCaps));
    commandCapsField->mFlags = 3;
    commandCapsField->mDesc = "Command capability flags for this unit";

    gpg::RField* const toggleCapsField = typeInfo->AddField<moho::ERuleBPUnitToggleCaps>("ToggleCaps", offsetof(RUnitBlueprintGeneral, ToggleCaps));
    toggleCapsField->mFlags = 3;
    toggleCapsField->mDesc = "Command capability flags for this unit";

    typeInfo->AddField<moho::RResId>("UpgradesTo", offsetof(RUnitBlueprintGeneral, UpgradesTo), 3, "What unit, if any, does this unit upgrade to.");
    typeInfo->AddField<moho::RResId>("UpgradesFrom", offsetof(RUnitBlueprintGeneral, UpgradesFrom), 3, "What unit, if any, was this unit upgrade from.");
    typeInfo->AddField<moho::RResId>("UpgradesFromBase", offsetof(RUnitBlueprintGeneral, UpgradesFromBase), 3, "What unit, if any, was this unit upgrade from base.");
    typeInfo->AddField<moho::RResId>("SeedUnit", offsetof(RUnitBlueprintGeneral, SeedUnit), 3, "What unit, if any, was this unit seeded from.");
    typeInfo->AddField<std::int32_t>("QuickSelectPriority", offsetof(RUnitBlueprintGeneral, QuickSelectPriority), 3, "Indicates unit has it's own avatar button in the quick select interface, and it's sorting priority");
    typeInfo->AddField<float>("CapCost", offsetof(RUnitBlueprintGeneral, CapCost), 3, "Cost of unit towards unit cap");
    typeInfo->AddField<std::int32_t>("SelectionPriority", offsetof(RUnitBlueprintGeneral, SelectionPriority), 3, "Determines if a unit will be selected in a drag selection, only the highest priority units will get selected (1 is highest)");
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
    typeInfo->AddField<msvc8::string>("DisplayName", offsetof(RUnitBlueprintDisplay, DisplayName), 3, "Displayed name of unit");
    typeInfo->AddField<moho::RResId>("MeshBlueprint", offsetof(RUnitBlueprintDisplay, MeshBlueprint), 3, "Mesh blueprint we use for display");
    typeInfo->AddField<msvc8::string>("PlaceholderMeshName", offsetof(RUnitBlueprintDisplay, PlaceholderMeshName), 3, "Name of placeholder mesh to use for the unit when normal mesh isn't available");
    typeInfo->AddField<moho::RResId>("IconName", offsetof(RUnitBlueprintDisplay, IconName), 3, "Name of icon to use for the unit");
    typeInfo->AddField<float>("UniformScale", offsetof(RUnitBlueprintDisplay, UniformScale), 3, "Uniform scale to be applied to mesh");
    typeInfo->AddField<bool>("SpawnRandomRotation", offsetof(RUnitBlueprintDisplay, SpawnRandomRotation), 3, "Spawn with a small random rotation");
    typeInfo->AddField<bool>("HideLifebars", offsetof(RUnitBlueprintDisplay, HideLifebars), 3, "Hide lifebars if true");
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
    typeInfo->AddField<bool>("FlattenSkirt", offsetof(RUnitBlueprintPhysics, FlattenSkirt), 3, "If true, terrain under building's skirt will be flattened.");
    typeInfo->AddField<float>("SkirtOffsetX", offsetof(RUnitBlueprintPhysics, SkirtOffsetX), 3, "Offset of left edge of skirt from left edge of footprint. Should be <= 0.");
    typeInfo->AddField<float>("SkirtOffsetZ", offsetof(RUnitBlueprintPhysics, SkirtOffsetZ), 3, "Offset of top edge of skirt from top edge of footprint. Should be <= 0.");
    typeInfo->AddField<float>("SkirtSizeX", offsetof(RUnitBlueprintPhysics, SkirtSizeX), 3, "Unit construction pad Size X for building");
    typeInfo->AddField<float>("SkirtSizeZ", offsetof(RUnitBlueprintPhysics, SkirtSizeZ), 3, "Unit construction pad Size Z for building");
    typeInfo->AddField<float>("MaxGroundVariation", offsetof(RUnitBlueprintPhysics, MaxGroundVariation), 3, "Maximum elevation difference across skirt for build site");
    gpg::RField* const motionTypeField = AddFieldMovementType(typeInfo, "MotionType", offsetof(RUnitBlueprintPhysics, MotionType));
    motionTypeField->mFlags = 3;
    motionTypeField->mDesc = "Method of locomotion";
    gpg::RField* const altMotionTypeField = AddFieldMovementType(typeInfo, "AltMotionType", offsetof(RUnitBlueprintPhysics, AltMotionType));
    altMotionTypeField->mFlags = 3;
    altMotionTypeField->mDesc = "Alternate method of locomotion";
    typeInfo->AddField<bool>("StandUpright", offsetof(RUnitBlueprintPhysics, StandUpright), 3, "Stands upright regardless of terrain");
    typeInfo->AddField<bool>("SinkLower", offsetof(RUnitBlueprintPhysics, SinkLower), 3, "Stands upright regardless of terrain");
    typeInfo->AddField<bool>("RotateBodyWhileMoving", offsetof(RUnitBlueprintPhysics, RotateBodyWhileMoving), 3, "Ability to rotate body to aim weapon slaved to body while in still in motion");
    typeInfo->AddField<float>("DiveSurfaceSpeed", offsetof(RUnitBlueprintPhysics, DiveSurfaceSpeed), 3, "Dive/surface speed for the sub units");
    typeInfo->AddField<float>("MaxSpeed", offsetof(RUnitBlueprintPhysics, MaxSpeed), 3, "Maximum speed for the unit");
    typeInfo->AddField<float>("MaxSpeedReverse", offsetof(RUnitBlueprintPhysics, MaxSpeedReverse), 3, "Maximum speed for the unit in reverse");
    typeInfo->AddField<float>("MaxAcceleration", offsetof(RUnitBlueprintPhysics, MaxAcceleration), 3, "Maximum acceleration for the unit");
    typeInfo->AddField<float>("MaxBrake", offsetof(RUnitBlueprintPhysics, MaxBrake), 3, "Maximum braking acceleration for the unit");
    typeInfo->AddField<float>("MaxSteerForce", offsetof(RUnitBlueprintPhysics, MaxSteerForce), 3, "Maximum steer force magnitude that can be applied to acceleration");
    typeInfo->AddField<float>("BankingSlope", offsetof(RUnitBlueprintPhysics, BankingSlope), 3, "How much the unit banks in corners (negative to lean outwards)");
    typeInfo->AddField<float>("RollStability", offsetof(RUnitBlueprintPhysics, RollStability), 3, "How stable the unit is against rolling (0 to 1)");
    typeInfo->AddField<float>("RollDamping", offsetof(RUnitBlueprintPhysics, RollDamping), 3, "How much damping there is against rolling motion (1 = no motion at all)");
    typeInfo->AddField<float>("WobbleFactor", offsetof(RUnitBlueprintPhysics, WobbleFactor), 3, "How much wobbling for the unit while hovering");
    typeInfo->AddField<float>("WobbleSpeed", offsetof(RUnitBlueprintPhysics, WobbleSpeed), 3, "How fast is the wobble. The faster the less stable looking");
    typeInfo->AddField<float>("TurnRadius", offsetof(RUnitBlueprintPhysics, TurnRadius), 3, "Turn radius for the unit, in world units");
    typeInfo->AddField<float>("TurnRate", offsetof(RUnitBlueprintPhysics, TurnRate), 3, "Turn rate for the unit, in degrees per second");
    typeInfo->AddField<float>("TurnFacingRate", offsetof(RUnitBlueprintPhysics, TurnFacingRate), 3, "Turn facing damping for the unit, usually used for hover units only");
    typeInfo->AddField<bool>("RotateOnSpot", offsetof(RUnitBlueprintPhysics, RotateOnSpot), 3, "This unit can tries to rotate on the spot.");
    typeInfo->AddField<float>("RotateOnSpotThreshold", offsetof(RUnitBlueprintPhysics, RotateOnSpotThreshold), 3, "Threshold for rotate on spot to take effect when moving.");
    typeInfo->AddField<float>("Elevation", offsetof(RUnitBlueprintPhysics, Elevation), 3, "Preferred height above (-below) land or water surface");
    typeInfo->AddField<float>("AttackElevation", offsetof(RUnitBlueprintPhysics, AttackElevation), 3, "Preferred attack height when attacking ground targets... used by dive bombers");
    gpg::RField* const buildOnLayerCapsField = typeInfo->AddField<moho::ELayer>("BuildOnLayerCaps", offsetof(RUnitBlueprintPhysics, BuildOnLayerCapsMask));
    buildOnLayerCapsField->mFlags = 3;
    buildOnLayerCapsField->mDesc = "Unit may be built on these layers (only applies to structures";
    gpg::RField* const buildRestrictionField = typeInfo->AddField<moho::ERuleBPUnitBuildRestriction>("BuildRestriction", offsetof(RUnitBlueprintPhysics, BuildRestriction));
    buildRestrictionField->mFlags = 3;
    buildRestrictionField->mDesc = "Special build restrictions (mass deposit, thermal vent, etc)";
    typeInfo->AddField<float>("CatchUpAcc", offsetof(RUnitBlueprintPhysics, CatchUpAcc), 3, "Acceleration to allow unit to catch up to the target when it starts to drift");
    typeInfo->AddField<float>("BackUpDistance", offsetof(RUnitBlueprintPhysics, BackUpDistance), 3, "Distance that the unit will just back up if it's easier to do so");
    typeInfo->AddField<float>("LayerChangeOffsetHeight", offsetof(RUnitBlueprintPhysics, LayerChangeOffsetHeight), 3, "An offset to the layer change height used during the transition between seabed/water and land");
    typeInfo->AddField<float>("LayerTransitionDuration", offsetof(RUnitBlueprintPhysics, LayerTransitionDuration), 3, "Transition time in seconds when going from water/land and land/water");
    typeInfo->AddField<float>("FuelUseTime", offsetof(RUnitBlueprintPhysics, FuelUseTime), 3, "Unit has fuel for this number of seconds");
    typeInfo->AddField<float>("FuelRechargeRate", offsetof(RUnitBlueprintPhysics, FuelRechargeRate), 3, "Unit fuels up at this rate per second");
    typeInfo->AddField<float>("GroundCollisionOffset", offsetof(RUnitBlueprintPhysics, GroundCollisionOffset), 3, "Collision with ground offset");

    gpg::RField* const raisedPlatformsField = AddFieldVectorFloat(typeInfo, "RaisedPlatforms", offsetof(RUnitBlueprintPhysics, RaisedPlatforms));
    raisedPlatformsField->mName = "RaisedPlatforms";
    raisedPlatformsField->mFlags = 3;
    raisedPlatformsField->mDesc = "Raised platoform definition for ground units to move on";

    gpg::RField* const occupyRectsField = AddFieldVectorFloat(typeInfo, "OccupyRects", offsetof(RUnitBlueprintPhysics, OccupyRects));
    occupyRectsField->mName = "OccupyRects";
    occupyRectsField->mFlags = 3;
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
    typeInfo->AddField<bool>("CanFly", offsetof(RUnitBlueprintAir, CanFly), 3, "Is the unit capable of flight?");
    typeInfo->AddField<bool>("Winged", offsetof(RUnitBlueprintAir, Winged), 3, "Does the unit use wings for forward flight?");
    typeInfo->AddField<bool>("FlyInWater", offsetof(RUnitBlueprintAir, FlyInWater), 3, "Can this unit fly under water?");
    typeInfo->AddField<float>("AutoLandTime", offsetof(RUnitBlueprintAir, AutoLandTime), 3, "Timer to automatically initate landing on ground if idle");
    typeInfo->AddField<float>("MaxAirspeed", offsetof(RUnitBlueprintAir, MaxAirspeed), 3, "Maximum airspeed");
    typeInfo->AddField<float>("MinAirspeed", offsetof(RUnitBlueprintAir, MinAirspeed), 3, "Minimum combat airspeed");
    typeInfo->AddField<float>("TurnSpeed", offsetof(RUnitBlueprintAir, TurnSpeed), 3, "Regular turn speed of the unit");
    typeInfo->AddField<float>("CombatTurnSpeed", offsetof(RUnitBlueprintAir, CombatTurnSpeed), 3, "Maximum combat turn speed of the unit for special manuvers");
    typeInfo->AddField<float>("StartTurnDistance", offsetof(RUnitBlueprintAir, StartTurnDistance), 3, "Distance from target at which to start turning to align with it");
    typeInfo->AddField<float>("TightTurnMultiplier", offsetof(RUnitBlueprintAir, TightTurnMultiplier), 3, "Additional turning multiplier ability during a tight turn manuver");
    typeInfo->AddField<float>("SustainedTurnThreshold", offsetof(RUnitBlueprintAir, SustainedTurnThreshold), 3, "Length of time allowed for sustained turn before we re-try a different approach");
    typeInfo->AddField<float>("LiftFactor", offsetof(RUnitBlueprintAir, LiftFactor), 3, "How much altitude the unit can gain/loose per second");
    typeInfo->AddField<float>("BankFactor", offsetof(RUnitBlueprintAir, BankFactor), 3, "How much aircraft banks in turns; negative to lean out");
    typeInfo->AddField<bool>("BankForward", offsetof(RUnitBlueprintAir, BankForward), 3, "True if aircraft banks forward/back as well as sideways");
    typeInfo->AddField<float>("EngageDistance", offsetof(RUnitBlueprintAir, EngageDistance), 3, "Distance to being engaging enemy target in attack task");
    typeInfo->AddField<float>("BreakOffTrigger", offsetof(RUnitBlueprintAir, BreakOffTrigger), 3, "Distance to target to trigger the breaking off attack");
    typeInfo->AddField<float>("BreakOffDistance", offsetof(RUnitBlueprintAir, BreakOffDistance), 3, "Distnace to break off before turning around for another attack run");
    typeInfo->AddField<bool>("BreakOffIfNearNewTarget", offsetof(RUnitBlueprintAir, BreakOffIfNearNewTarget), 3, "If our new target is close by then perform break off first to increase distance between the 2");
    typeInfo->AddField<float>("KMove", offsetof(RUnitBlueprintAir, KMove), 3, "Controller proportional parameter for horizontal motion");
    typeInfo->AddField<float>("KMoveDamping", offsetof(RUnitBlueprintAir, KMoveDamping), 3, "Controller damping parameter for horizontal motion");
    typeInfo->AddField<float>("KLift", offsetof(RUnitBlueprintAir, KLift), 3, "Controller proportional parameter for vertical motion");
    typeInfo->AddField<float>("KLiftDamping", offsetof(RUnitBlueprintAir, KLiftDamping), 3, "Controller damping parameter for vertical motion");
    typeInfo->AddField<float>("KTurn", offsetof(RUnitBlueprintAir, KTurn), 3, "Controller proportional parameter for heading changes");
    typeInfo->AddField<float>("KTurnDamping", offsetof(RUnitBlueprintAir, KTurnDamping), 3, "Controller damping parameter for heading changes");
    typeInfo->AddField<float>("KRoll", offsetof(RUnitBlueprintAir, KRoll), 3, "Controller proportional parameter for roll changes");
    typeInfo->AddField<float>("KRollDamping", offsetof(RUnitBlueprintAir, KRollDamping), 3, "Controller damping parameter for roll changes");
    typeInfo->AddField<float>("CirclingTurnMult", offsetof(RUnitBlueprintAir, CirclingTurnMult), 3, "Adjust turning ability when in circling mode");
    typeInfo->AddField<float>("CirclingRadiusChangeMinRatio", offsetof(RUnitBlueprintAir, CirclingRadiusChangeMinRatio), 3, "Min circling radius ratio for unit");
    typeInfo->AddField<float>("CirclingRadiusChangeMaxRatio", offsetof(RUnitBlueprintAir, CirclingRadiusChangeMaxRatio), 3, "Max circling radius ratio for unit");
    typeInfo->AddField<float>("CirclingRadiusVsAirMult", offsetof(RUnitBlueprintAir, CirclingRadiusVsAirMult), 3, "Multiplier to the circling radius when targetting another air unit");
    typeInfo->AddField<float>("CirclingElevationChangeRatio", offsetof(RUnitBlueprintAir, CirclingElevationChangeRatio), 3, "Elevation change ratio of unit when circling");
    typeInfo->AddField<float>("CirclingFlightChangeFrequency", offsetof(RUnitBlueprintAir, CirclingFlightChangeFrequency), 3, "Frequency of flight pattern change for unit");
    typeInfo->AddField<bool>("CirclingDirChange", offsetof(RUnitBlueprintAir, CirclingDirChange), 3, "Whether unit should ever change flight direction while circling");
    typeInfo->AddField<bool>("HoverOverAttack", offsetof(RUnitBlueprintAir, HoverOverAttack), 3, "Whether unit should hover over the target directly to attack... used for cases like the C.Z.A.R");
    typeInfo->AddField<float>("RandomBreakOffDistanceMult", offsetof(RUnitBlueprintAir, RandomBreakOffDistanceMult), 3, "Random multiplier applied to the break off distance for winged aircrafts");
    typeInfo->AddField<float>("RandomMinChangeCombatStateTime", offsetof(RUnitBlueprintAir, RandomMinChangeCombatStateTime), 3, "Random min time to switch combat state in seconds for winged aircrafts");
    typeInfo->AddField<float>("RandomMaxChangeCombatStateTime", offsetof(RUnitBlueprintAir, RandomMaxChangeCombatStateTime), 3, "Random max time to switch combat state in seconds for winged aircrafts");
    typeInfo->AddField<float>("TransportHoverHeight", offsetof(RUnitBlueprintAir, TransportHoverHeight), 3, "This transport will stay at this height when picking up and dropping off units");
    typeInfo->AddField<float>("PredictAheadForBombDrop", offsetof(RUnitBlueprintAir, PredictAheadForBombDrop), 3, "Time to predict ahead for moving targets?");
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
    typeInfo->AddField<std::int32_t>("TransportClass", offsetof(RUnitBlueprintTransport, TransportClass), 3, "Type of attach points required on transports");
    typeInfo->AddField<std::int32_t>("ClassGenericUpTo", offsetof(RUnitBlueprintTransport, ClassGenericUpTo), 3, "Generic slots up to the specified class");
    typeInfo->AddField<std::int32_t>("Class2AttachSize", offsetof(RUnitBlueprintTransport, Class2AttachSize), 3, "Number of class 1 attach points this affects");
    typeInfo->AddField<std::int32_t>("Class3AttachSize", offsetof(RUnitBlueprintTransport, Class3AttachSize), 3, "Number of class 1 attach points this affects");
    typeInfo->AddField<std::int32_t>("Class4AttachSize", offsetof(RUnitBlueprintTransport, Class4AttachSize), 3, "Number of class 1 attach points this affects");
    typeInfo->AddField<std::int32_t>("ClassSAttachSize", offsetof(RUnitBlueprintTransport, ClassSAttachSize), 3, "Number of class 1 attach points this affects");
    typeInfo->AddField<bool>("AirClass", offsetof(RUnitBlueprintTransport, AirClass), 3, "These define that the unit can only land on air staging platforms");
    typeInfo->AddField<std::int32_t>("StorageSlots", offsetof(RUnitBlueprintTransport, StorageSlots), 3, "How many internal storage slots available for the transport on top of the attach points");
    typeInfo->AddField<std::int32_t>("DockingSlots", offsetof(RUnitBlueprintTransport, DockingSlots), 3, "How many external docking slots available for air staging platforms");
    typeInfo->AddField<float>("RepairRate", offsetof(RUnitBlueprintTransport, RepairRate), 3, "Repairs units attached to me at this % of max health per second");
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
    typeInfo->AddField<float>("GuardScanRadius", offsetof(RUnitBlueprintAI, GuardScanRadius), 3, "Guard range for the unit");
    typeInfo->AddField<float>("GuardReturnRadius", offsetof(RUnitBlueprintAI, GuardReturnRadius), 3, "Maximum range from the guarded unit before initiating return");
    typeInfo->AddField<float>("StagingPlatformScanRadius", offsetof(RUnitBlueprintAI, StagingPlatformScanRadius), 3, "Range for staging platforms to look for planes to repair and refuel when they are on patrol");
    typeInfo->AddField<bool>("ShowAssistRangeOnSelect", offsetof(RUnitBlueprintAI, ShowAssistRangeOnSelect), 3, "Show assist range for the unit if selected");
    typeInfo->AddField<msvc8::string>("GuardFormationName", offsetof(RUnitBlueprintAI, GuardFormationName), 3, "The formation name used for guarding this unit");
    typeInfo->AddField<bool>("NeedUnpack", offsetof(RUnitBlueprintAI, NeedUnpack), 3, "Unit should unpack before firing weapon");
    typeInfo->AddField<bool>("InitialAutoMode", offsetof(RUnitBlueprintAI, InitialAutoMode), 3, "Initial auto mode behavior for the unit");
    typeInfo->AddField<msvc8::string>("BeaconName", offsetof(RUnitBlueprintAI, BeaconName), 3, "Thie is the beacon that this unit will create under some circumstances");
    gpg::RField* const targetBonesField = typeInfo->AddField<msvc8::vector<msvc8::string>>("TargetBones", offsetof(RUnitBlueprintAI, TargetBones));
    targetBonesField->mFlags = 3;
    targetBonesField->mDesc = "Some target bones setup for other units to aim at instead of the default center pos";
    typeInfo->AddField<float>("RefuelingMultiplier", offsetof(RUnitBlueprintAI, RefuelingMultiplier), 3, "This multiplier is applied when a staging platform is refueling an air unit");
    typeInfo->AddField<float>("RefuelingRepairAmount", offsetof(RUnitBlueprintAI, RefuelingRepairAmount), 3, "This amount of repair per second offered to refueling air units");
    typeInfo->AddField<float>("RepairConsumeEnergy", offsetof(RUnitBlueprintAI, RepairConsumeEnergy), 3, "This amount of energy per second required to repair air unit");
    typeInfo->AddField<float>("RepairConsumeMass", offsetof(RUnitBlueprintAI, RepairConsumeMass), 3, "This amount of mass per second require to repair air unit");
    typeInfo->AddField<bool>("AutoSurfaceToAttack", offsetof(RUnitBlueprintAI, AutoSurfaceToAttack), 3, "Automatically surface to attack ground targets");
    typeInfo->AddField<float>("AttackAngle", offsetof(RUnitBlueprintAI, AttackAngle), 3, "Desired angle to face target to maximize the number of guns able to hit the targets");
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
   * Address: 0x00521AB0 (FUN_00521AB0)
   *
   * What it does:
   * Registers `RUnitBlueprintDefense` field descriptors and descriptions.
   */
  void RUnitBlueprintDefenseTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    typeInfo->AddField<float>("MaxHealth", offsetof(RUnitBlueprintDefense, MaxHealth), 3, "Max health value for the unit");
    typeInfo->AddField<float>("Health", offsetof(RUnitBlueprintDefense, Health), 3, "Starting health value for the unit");
    typeInfo->AddField<float>("RegenRate", offsetof(RUnitBlueprintDefense, RegenRate), 3, "Amount of health to regenerate per second");
    typeInfo->AddField<float>("AirThreatLevel", offsetof(RUnitBlueprintDefense, AirThreatLevel), 3, "Amount of threat this poses to the enemy air units");
    typeInfo->AddField<float>("SurfaceThreatLevel", offsetof(RUnitBlueprintDefense, SurfaceThreatLevel), 3, "Amount of threat this poses to the enemy air units");
    typeInfo->AddField<float>("SubThreatLevel", offsetof(RUnitBlueprintDefense, SubThreatLevel), 3, "Amount of threat this poses to the enemy air units");
    typeInfo->AddField<float>("EconomyThreatLevel", offsetof(RUnitBlueprintDefense, EconomyThreatLevel), 3, "Amount of threat this poses to the enemy air units");
    typeInfo->AddField<msvc8::string>("ArmorType", offsetof(RUnitBlueprintDefense, ArmorType), 3, "The Armor type name");
    gpg::RField* const shieldField = typeInfo->AddField<moho::RUnitBlueprintDefenseShield>("Shield", offsetof(RUnitBlueprintDefense, Shield));
    shieldField->mFlags = 3;
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
    typeInfo->AddField<std::uint32_t>("VisionRadius", offsetof(RUnitBlueprintIntel, VisionRadius), 3, "How far we can see above water");
    typeInfo->AddField<std::uint32_t>("WaterVisionRadius", offsetof(RUnitBlueprintIntel, WaterVisionRadius), 3, "How far we can see underwater");
    typeInfo->AddField<std::uint32_t>("RadarRadius", offsetof(RUnitBlueprintIntel, RadarRadius), 3, "How far our radar coverage goes");
    typeInfo->AddField<std::uint32_t>("SonarRadius", offsetof(RUnitBlueprintIntel, SonarRadius), 3, "How far our radar coverage goes");
    typeInfo->AddField<std::uint32_t>("OmniRadius", offsetof(RUnitBlueprintIntel, OmniRadius), 3, "How far our radar coverage goes");
    typeInfo->AddField<bool>("RadarStealth", offsetof(RUnitBlueprintIntel, RadarStealth), 3, "Single unit radar stealth");
    typeInfo->AddField<bool>("SonarStealth", offsetof(RUnitBlueprintIntel, SonarStealth), 3, "Single unit sonar stealth");
    typeInfo->AddField<bool>("Cloak", offsetof(RUnitBlueprintIntel, Cloak), 3, "Single unit cloaking");
    typeInfo->AddField<bool>("ShowIntelOnSelect", offsetof(RUnitBlueprintIntel, ShowIntelOnSelect), 3, "Show intel radius of unit if selected");
    typeInfo->AddField<std::uint32_t>("RadarStealthFieldRadius", offsetof(RUnitBlueprintIntel, RadarStealthFieldRadius), 3, "How far our radar stealth goes");
    typeInfo->AddField<std::uint32_t>("SonarStealthFieldRadius", offsetof(RUnitBlueprintIntel, SonarStealthFieldRadius), 3, "How far our sonar stealth goes");
    typeInfo->AddField<std::uint32_t>("CloakFieldRadius", offsetof(RUnitBlueprintIntel, CloakFieldRadius), 3, "How far our cloaking goes");
    gpg::RField* const jamRadiusField = AddFieldSMinMaxUInt(typeInfo, "JamRadius", offsetof(RUnitBlueprintIntel, JamRadius));
    jamRadiusField->mFlags = 3;
    jamRadiusField->mDesc = "How far we create fake blips";
    gpg::RField* const spoofRadiusField = AddFieldSMinMaxUInt(typeInfo, "SpoofRadius", offsetof(RUnitBlueprintIntel, SpoofRadius));
    spoofRadiusField->mFlags = 3;
    spoofRadiusField->mDesc = "How far off to displace blip";
    gpg::RField* const jammerBlipsField = typeInfo->AddField<unsigned char>("JammerBlips", offsetof(RUnitBlueprintIntel, JammerBlips));
    jammerBlipsField->mFlags = 3;
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
    typeInfo->AddField<float>("BuildCostEnergy", offsetof(RUnitBlueprintEconomy, BuildCostEnergy), 3, "Energy cost to build this unit");
    typeInfo->AddField<float>("BuildCostMass", offsetof(RUnitBlueprintEconomy, BuildCostMass), 3, "Mass cost to build this unit");
    typeInfo->AddField<float>("BuildRate", offsetof(RUnitBlueprintEconomy, BuildRate), 3, "How efficient a unit is at building");
    typeInfo->AddField<float>("BuildTime", offsetof(RUnitBlueprintEconomy, BuildTime), 3, "How long it takes to build this unit (in seconds)");
    typeInfo->AddField<float>("StorageEnergy", offsetof(RUnitBlueprintEconomy, StorageEnergy), 3, "Energy storage capacity provided by this unit");
    typeInfo->AddField<float>("StorageMass", offsetof(RUnitBlueprintEconomy, StorageMass), 3, "Mass storage capacity provided by this unit");
    typeInfo->AddField<bool>("NaturalProducer", offsetof(RUnitBlueprintEconomy, NaturalProducer), 3, "Produces resouce naturally and does not consume anything");

    gpg::RField* const buildableCategoriesField = typeInfo->AddField<msvc8::vector<msvc8::string>>("BuildableCategories", offsetof(RUnitBlueprintEconomy, BuildableCategories));
    buildableCategoriesField->mFlags = 3;
    buildableCategoriesField->mDesc = "One of the unit categories that can be built by this unit";
    SetLastFieldName(typeInfo, "BuildableCategory");

    gpg::RField* const rebuildBonusIdsField = typeInfo->AddField<msvc8::vector<msvc8::string>>("RebuildBonusIds", offsetof(RUnitBlueprintEconomy, RebuildBonusIds));
    rebuildBonusIdsField->mFlags = 3;
    rebuildBonusIdsField->mDesc = "You will get bonus if you rebuild this unit over the wreckage of these wreckages";

    typeInfo->AddField<float>("InitialRallyX", offsetof(RUnitBlueprintEconomy, InitialRallyX), 3, "default rally point Xfor the factory");
    typeInfo->AddField<float>("InitialRallyZ", offsetof(RUnitBlueprintEconomy, InitialRallyZ), 3, "default rally point Z for the factory");
    typeInfo->AddField<bool>("NeedToFaceTargetToBuild", offsetof(RUnitBlueprintEconomy, NeedToFaceTargetToBuild), 3, "builder needs to face target before it can build/repair");
    typeInfo->AddField<float>("SacrificeMassMult", offsetof(RUnitBlueprintEconomy, SacrificeMassMult), 3, "builder will kill self but provide this amount of mass based on builder's mass cost to the unit it is helping");
    typeInfo->AddField<float>("SacrificeEnergyMult", offsetof(RUnitBlueprintEconomy, SacrificeEnergyMult), 3, "builder will kill self but provide this amount of energy based on the builder's energy cost to the unit it is helping");
    typeInfo->AddField<float>("MaxBuildDistance", offsetof(RUnitBlueprintEconomy, MaxBuildDistance), 3, "Maximum build range of the unit. The target must be within this range before the builder can perform operation");
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
   * Address: 0x00522340 (FUN_00522340)
   *
   * What it does:
   * Registers `RUnitBlueprintWeapon` field descriptors and descriptions.
   */
  void RUnitBlueprintWeaponTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    typeInfo->AddField<msvc8::string>("Label", offsetof(RUnitBlueprintWeapon, Label), 3, "The label to pass to scripts to id this weapon.");
    typeInfo->AddField<msvc8::string>("DisplayName", offsetof(RUnitBlueprintWeapon, DisplayName), 3, "The display name of this weapon.");
    gpg::RField* const rangeCategoryField = typeInfo->AddField<moho::UnitWeaponRangeCategory>("RangeCategory", offsetof(RUnitBlueprintWeapon, RangeCategory));
    rangeCategoryField->mFlags = 3;
    rangeCategoryField->mDesc = "The range category this weapon satisfies.";
    typeInfo->AddField<bool>("DummyWeapon", offsetof(RUnitBlueprintWeapon, DummyWeapon), 3, "True if the engine should not create an actual weapon for this blueprint. This is used for special damage like the Spiderbot's feet, where no real weapon exists, but we still want a consistent way to spec damage types etc.");
    typeInfo->AddField<float>("TargetCheckInterval", offsetof(RUnitBlueprintWeapon, TargetCheckInterval), 3, "Interval between checks for a new weapon target. Default is three seconds.");
    typeInfo->AddField<bool>("AlwaysRecheckTarget", offsetof(RUnitBlueprintWeapon, AlwaysRecheckTarget), 3, "Always recheck for better target regardless of whether you already have one or not.");
    typeInfo->AddField<bool>("PrefersPrimaryWeaponTarget", offsetof(RUnitBlueprintWeapon, PrefersPrimaryWeaponTarget), 3, "Flag to specify if the weapon prefers to target what the primary weapon is currently targetting.");
    typeInfo->AddField<bool>("StopOnPrimaryWeaponBusy", offsetof(RUnitBlueprintWeapon, StopOnPrimaryWeaponBusy), 3, "Flag to specify to not make weapon active if the primary weapon has a current target.");
    typeInfo->AddField<bool>("SlavedToBody", offsetof(RUnitBlueprintWeapon, SlavedToBody), 3, "Flag to specify if the weapon is slaved to the unit body, thus requiring unit to face target to fire.");
    typeInfo->AddField<float>("SlavedToBodyArcRange", offsetof(RUnitBlueprintWeapon, SlavedToBodyArcRange), 3, "Range of arc to be considered slaved to a target.");
    typeInfo->AddField<bool>("AutoInitiateAttackCommand", offsetof(RUnitBlueprintWeapon, AutoInitiateAttackCommand), 3, "Flag to specify if the unit will initate an attack command when idle if an enemy target comes within firing/tracking range.");
    typeInfo->AddField<float>("MinRadius", offsetof(RUnitBlueprintWeapon, MinRadius), 3, "The minimum range we must be to fire at our target.");
    typeInfo->AddField<float>("MaxRadius", offsetof(RUnitBlueprintWeapon, MaxRadius), 3, "The maximum range we can be to fire at our target.");
    typeInfo->AddField<float>("EffectiveRadius", offsetof(RUnitBlueprintWeapon, EffectiveRadius), 3, "The effective range that this weapon really is.");
    typeInfo->AddField<float>("MaxHeightDiff", offsetof(RUnitBlueprintWeapon, MaxHeightDiff), 3, "The maximum height diff range for the weapon. Keep in mind weapons are now cylinder in nature.");
    typeInfo->AddField<float>("TrackingRadius", offsetof(RUnitBlueprintWeapon, TrackingRadius), 3, "The range where we begin tracking a unit but will not fire yet; multiplier of the weapon's MaxRadius");
    typeInfo->AddField<float>("HeadingArcCenter", offsetof(RUnitBlueprintWeapon, HeadingArcCenter), 3, "Center of firing arc for this weapon, in degrees. Default is 0");
    typeInfo->AddField<float>("HeadingArcRange", offsetof(RUnitBlueprintWeapon, HeadingArcRange), 3, "Maximum angle from HeadingArcCenter, in degrees. Default is 180, meaning weapon can aim anywhere.");
    typeInfo->AddField<float>("FiringTolerance", offsetof(RUnitBlueprintWeapon, FiringTolerance), 3, "How accurate do we have to be aimed before we take a shot.  In degrees.");
    typeInfo->AddField<float>("FiringRandomness", offsetof(RUnitBlueprintWeapon, FiringRandomness), 3, "How many degrees of arc can we randomly be off by (gaussian)");
    typeInfo->AddField<bool>("IgnoreIfDisabled", offsetof(RUnitBlueprintWeapon, IgnoreIfDisabled), 3, "Does not consider weapon when attacking targets if it is disabled");
    typeInfo->AddField<bool>("CannotAttackGround", offsetof(RUnitBlueprintWeapon, CannotAttackGround), 3, "Weapon cannot attack ground positions");
    typeInfo->AddField<float>("RequiresEnergy", offsetof(RUnitBlueprintWeapon, RequiresEnergy), 3, "Weapon requires this much available energy to fire");
    typeInfo->AddField<float>("RequiresMass", offsetof(RUnitBlueprintWeapon, RequiresMass), 3, "Weapon requires this much available mass to fire");
    typeInfo->AddField<float>("MuzzleVelocity", offsetof(RUnitBlueprintWeapon, MuzzleVelocity), 3, "Weapon's muzzle velocity");
    typeInfo->AddField<float>("MuzzleVelocityRandom", offsetof(RUnitBlueprintWeapon, MuzzleVelocityRandom), 3, "Random variation for muzzle velocity (gaussian)");
    typeInfo->AddField<float>("MuzzleVelocityReduceDistance", offsetof(RUnitBlueprintWeapon, MuzzleVelocityReduceDistance), 3, "Target distance at which weapon will start reducing muzzle velocity to maintain a higher firing arc.");
    typeInfo->AddField<bool>("LeadTarget", offsetof(RUnitBlueprintWeapon, LeadTarget), 3, "True if weapon should lead its target when aiming.");
    typeInfo->AddField<float>("ProjectileLifetime", offsetof(RUnitBlueprintWeapon, ProjectileLifetime), 3, "Lifetime for projectile in seconds. If 0, the projectile will use the lifetime from its own blueprint.");
    typeInfo->AddField<float>("ProjectileLifetimeUsesMultiplier", offsetof(RUnitBlueprintWeapon, ProjectileLifetimeUsesMultiplier), 3, "Lifetime for projectile based on lifetime equation of Multiplier * (MaxRadius/MuzzleVelocity)");
    typeInfo->AddField<float>("Damage", offsetof(RUnitBlueprintWeapon, Damage), 3, "How much damage to cause.");
    typeInfo->AddField<float>("DamageRadius", offsetof(RUnitBlueprintWeapon, DamageRadius), 3, "Radius to inflict damage in.");
    typeInfo->AddField<msvc8::string>("DamageType", offsetof(RUnitBlueprintWeapon, DamageType), 3, "Type of damage this weapon deals");
    typeInfo->AddField<float>("RateOfFire", offsetof(RUnitBlueprintWeapon, RateOfFire), 3, "How many shots/second we can fire.");
    typeInfo->AddField<moho::RResId>("ProjectileId", offsetof(RUnitBlueprintWeapon, ProjectileId), 3, "Blueprint Id for projectile, if any.");
    gpg::RField* const ballisticArcField = typeInfo->AddField<moho::ERuleBPUnitWeaponBallisticArc>("BallisticArc", offsetof(RUnitBlueprintWeapon, BallisticArc));
    ballisticArcField->mFlags = 3;
    ballisticArcField->mDesc = "High or low arc for projectiles";
    typeInfo->AddField<msvc8::string>("TargetRestrictOnlyAllow", offsetof(RUnitBlueprintWeapon, TargetRestrictOnlyAllow), 3, "Comma separated list of Entity Category that are the only valid targets.");
    typeInfo->AddField<msvc8::string>("TargetRestrictDisallow", offsetof(RUnitBlueprintWeapon, TargetRestrictDisallow), 3, "Comma separated list of Entity Category that are always invalid targets.");
    gpg::RField* const targetTypeField = typeInfo->AddField<moho::ERuleBPUnitWeaponTargetType>("TargetType", offsetof(RUnitBlueprintWeapon, TargetType));
    targetTypeField->mFlags = 3;
    targetTypeField->mDesc = "The type of entity this unit can target.";
    typeInfo->AddField<bool>("ManualFire", offsetof(RUnitBlueprintWeapon, ManualFire), 3, "Never fires automaticly.");
    typeInfo->AddField<bool>("NukeWeapon", offsetof(RUnitBlueprintWeapon, NukeWeapon), 3, "Nuke weapon flag.");
    typeInfo->AddField<bool>("OverChargeWeapon", offsetof(RUnitBlueprintWeapon, OverChargeWeapon), 3, "Overcharge weapon flag.");
    typeInfo->AddField<bool>("NeedPrep", offsetof(RUnitBlueprintWeapon, NeedPrep), 3, "Weapon needs prep time (applies to most Aeon units).");
    typeInfo->AddField<bool>("CountedProjectile", offsetof(RUnitBlueprintWeapon, CountedProjectile), 3, "This projectile needs to be built and stored before the weapon can fire");
    typeInfo->AddField<std::int32_t>("MaxProjectileStorage", offsetof(RUnitBlueprintWeapon, MaxProjectileStorage), 3, "This weapon can only hold this many counted projectiles");
    typeInfo->AddField<bool>("IgnoreIfDisabled", offsetof(RUnitBlueprintWeapon, IgnoreIfDisabled), 3, "Ignore trying to use the weapon if it's disabled.");
    typeInfo->AddField<bool>("IgnoresAlly", offsetof(RUnitBlueprintWeapon, IgnoresAlly), 3, "This determines whether the weapon affect ally units or not");
    typeInfo->AddField<std::int32_t>("AttackGroundTries", offsetof(RUnitBlueprintWeapon, AttackGroundTries), 3, "This determines the number of shots at a ground target before moving on to the enxt target");
    typeInfo->AddField<bool>("AimsStraightOnDisable", offsetof(RUnitBlueprintWeapon, AimsStraightOnDisable), 3, "This weapon will aim straight ahead when disabled");
    typeInfo->AddField<bool>("Turreted", offsetof(RUnitBlueprintWeapon, Turreted), 3, "This weapon is on a turret");
    typeInfo->AddField<bool>("YawOnlyOnTarget", offsetof(RUnitBlueprintWeapon, YawOnlyOnTarget), 3, "This weapon is considered on target if the yaw is facing the target");
    typeInfo->AddField<bool>("AboveWaterFireOnly", offsetof(RUnitBlueprintWeapon, AboveWaterFireOnly), 3, "This weapon will only fire if it is above water");
    typeInfo->AddField<bool>("BelowWaterFireOnly", offsetof(RUnitBlueprintWeapon, BelowWaterFireOnly), 3, "This weapon will only fire if it is below water");
    typeInfo->AddField<bool>("AboveWaterTargetsOnly", offsetof(RUnitBlueprintWeapon, AboveWaterTargetsOnly), 3, "This weapon will only at targets above water");
    typeInfo->AddField<bool>("BelowWaterTargetsOnly", offsetof(RUnitBlueprintWeapon, BelowWaterTargetsOnly), 3, "This weapon will only at targets below water");
    typeInfo->AddField<bool>("NeedToComputeBombDrop", offsetof(RUnitBlueprintWeapon, NeedToComputeBombDrop), 3, "This to compute when to drop bomb?");
    typeInfo->AddField<float>("BombDropThreshold", offsetof(RUnitBlueprintWeapon, BombDropThreshold), 3, "Threshold to release point before releasing ordinance?");
    typeInfo->AddField<bool>("ReTargetOnMiss", offsetof(RUnitBlueprintWeapon, ReTargetOnMiss), 3, "This weapon will find new target on miss events");
    typeInfo->AddField<bool>("UseFiringSolutionInsteadOfAimBone", offsetof(RUnitBlueprintWeapon, UseFiringSolutionInsteadOfAimBone), 3, "This weapon uses the recent firing solution to create projectile istead of the aim bone transform");
    typeInfo->AddField<msvc8::string>("UIMinRangeVisualId", offsetof(RUnitBlueprintWeapon, UIMinRangeVisualId), 3, "Allows the UI to know what kind of minimum range indicator to draw for this weapon.");
    typeInfo->AddField<msvc8::string>("UIMaxRangeVisualId", offsetof(RUnitBlueprintWeapon, UIMaxRangeVisualId), 3, "Allows the UI to know what kind of maximum range indicator to draw for this weapon.");
    typeInfo->AddField<float>("MaximumBeamLength", offsetof(RUnitBlueprintWeapon, MaximumBeamLength), 3, "Allows the setting of the Maximum Beam length so beams and radius can be different. Default to MaxRadius.");
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
