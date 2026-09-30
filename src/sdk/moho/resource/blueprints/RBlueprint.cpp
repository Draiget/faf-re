#include "RBlueprint.h"

#include <Windows.h>

#include <cstring>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RBlueprintTypeInfo;

  [[nodiscard]] gpg::RType* CachedRObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::RObject));
    }
    return cached;
  }

  /**
   * Address: 0x00BF23C0 (FUN_00BF23C0, atexit destructor of the RBlueprintTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireRBlueprintTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  struct SerializerCallbackRuntimeView
  {
    void* vtableLane;            // +0x00
    void* helperNextLane;        // +0x04
    void* helperPrevLane;        // +0x08
    void* deserializeCallback;   // +0x0C
    void* serializeCallback;     // +0x10
  };

  static_assert(
    offsetof(SerializerCallbackRuntimeView, deserializeCallback) == 0x0C,
    "SerializerCallbackRuntimeView::deserializeCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerializerCallbackRuntimeView, serializeCallback) == 0x10,
    "SerializerCallbackRuntimeView::serializeCallback offset must be 0x10"
  );
  static_assert(sizeof(SerializerCallbackRuntimeView) == 0x14, "SerializerCallbackRuntimeView size must be 0x14");

  /**
   * Address: 0x0050DB70 (FUN_0050DB70)
   *
   * What it does:
   * Stores one serializer deserialize callback lane at offset `+0x0C`.
   */
  [[maybe_unused]] [[nodiscard]] SerializerCallbackRuntimeView* SetSerializerDeserializeCallbackLane(
    SerializerCallbackRuntimeView* const result,
    void* const callback
  ) noexcept
  {
    result->deserializeCallback = callback;
    return result;
  }

  /**
   * Address: 0x0050DB80 (FUN_0050DB80)
   *
   * What it does:
   * Stores one serializer serialize callback lane at offset `+0x10`.
   */
  [[maybe_unused]] [[nodiscard]] SerializerCallbackRuntimeView* SetSerializerSerializeCallbackLane(
    SerializerCallbackRuntimeView* const result,
    void* const callback
  ) noexcept
  {
    result->serializeCallback = callback;
    return result;
  }

  /**
   * Address: 0x0050DB90 (FUN_0050DB90)
   *
   * What it does:
   * Returns mutable string data pointer using legacy MSVC8 SSO policy
   * (`myRes < 16` uses inline buffer, otherwise heap pointer).
   */
  [[maybe_unused]] [[nodiscard]] char* ResolveLegacyStringDataPointer(msvc8::string* const text) noexcept
  {
    return text->myRes < 16u ? text->bx.buf : text->bx.ptr;
  }
} // namespace

namespace moho
{
  gpg::RType* RBlueprint::sPointerType = nullptr;

  /**
   * Address: 0x0050DD60 (FUN_0050DD60)
   * Mangled: ??0RBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
   *
   * IDA signature:
   * Moho::RBlueprint *__thiscall Moho::RBlueprint::RBlueprint(
   *         Moho::RBlueprint *this@<ecx>,
   *         Moho::RRuleGameRules *rules,
   *         Moho::RResId const &resId);
   *
   * What it does:
   * Initializes a base `RBlueprint` from `(rules, resId)` (the
   * `InstanceCounter<RBlueprint>` base counts it): captures the owning rules,
   * copies the resource id string into `mBlueprintId` (uses `strlen` of the
   * resource id buffer to honor the original byte-exact behavior),
   * default-initializes `mDescription` and `mSource`, and assigns the next
   * blueprint ordinal from the rules' virtual `AssignNextOrdinal` slot.
   */
  RBlueprint::RBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : mOwner(owner)
    , mBlueprintId()
    , mDescription()
    , mSource()
    , mBlueprintOrdinal(0)
  {
    InitIdentity(owner, resId, mBlueprintId, mBlueprintOrdinal);
  }

  void RBlueprint::InitIdentity(
    RRuleGameRules* const owner,
    const RResId& resId,
    msvc8::string& outBlueprintId,
    std::int32_t& outOrdinal
  )
  {
    // The original ctor reads the source-id buffer with `strlen`, so a string
    // containing embedded null bytes truncates exactly the same way.
    const char* const sourceData = resId.name.c_str();
    const std::size_t sourceLen = std::strlen(sourceData);
    outBlueprintId.assign(sourceData, sourceLen);

    outOrdinal = owner->AssignNextOrdinal();
  }

  /**
   * Address: 0x0050DE60 (FUN_0050DE60)
   * Mangled: ??1RBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Releases base blueprint string lanes; the `InstanceCounter<RBlueprint>`
   * base then takes the instance count back and `gpg::RObject` restores its
   * vtable lane.
   */
  RBlueprint::~RBlueprint()
  {
    mSource.tidy(true, 0U);
    mDescription.tidy(true, 0U);
    mBlueprintId.tidy(true, 0U);

    // The binary ends here by storing the gpg::RObject vtable into the object's
    // first word. That is the inlined base destructor, and the compiler emits it
    // now that RObject is a declared base rather than a hand-modelled word -- so
    // there is nothing to write here.
  }

  /**
   * Address: 0x0050DE40 (FUN_0050DE40, deleting-destructor thunk)
   *
   * What it does:
   * Runs one `RBlueprint` destructor lane and conditionally frees this object
   * storage when the low delete flag bit is set.
   */
  [[maybe_unused]] RBlueprint* DestroyRBlueprintAndMaybeDelete(
    RBlueprint* const object,
    const unsigned char deleteFlag
  ) noexcept
  {
    object->~RBlueprint();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(object));
    }
    return object;
  }

  /**
   * Address: 0x0050DF10 (FUN_0050DF10, Moho::RBlueprint::InitBlueprint)
   *
   * What it does:
   * Builds reflected fields from one Lua blueprint table, runs polymorphic
   * post-init, then merges resolved fields back into the same table.
   */
  void RBlueprint::InitBlueprint(LuaPlus::LuaObject& luaBlueprint)
  {
    gpg::RRef destination{};
    destination = gpg::MakeRRef<moho::RBlueprint>(this);

    LuaPlus::LuaObject valueObject(luaBlueprint);
    (void)SCR_LuaBuildObject(valueObject, destination, true);

    // 0x0050DF4D: slot 3 on this object's own vtable. An ordinary virtual
    // call now that the base is declared rather than hand-modelled.
    OnInitBlueprint();

    gpg::RRef source{};
    source = gpg::MakeRRef<moho::RBlueprint>(this);
    SCR_RObjectToLuaMerge(source, luaBlueprint);
  }

  /**
   * Address: 0x0050DBA0 (FUN_0050DBA0)
   * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Base blueprint post-load hook; default implementation is empty.
   */
  void RBlueprint::OnInitBlueprint() {}

  namespace
  {
    /**
     * Address: 0x00556FF0 (FUN_00556FF0)
     * Address: 0x00BF4CA0 (FUN_00BF4CA0, atexit destructor of the RPointerType<RBlueprint> object)
     *
     * What it does:
     * Constructs the `RPointerType<RBlueprint>` descriptor (the binary's
     * `Moho::RBlueprint::PointerType`) once and preregisters it under the `RBlueprint*`
     * type-info key. The binary holds the descriptor as a function-local static
     * of `GetPointerType`; it lives here because the preregister phase has to
     * construct it before any consumer looks up `RBlueprint*`.
     */
    gpg::RType* PreregisterRBlueprintPointerType()
    {
      static gpg::RPointerType<moho::RBlueprint> sDescriptor;
      gpg::PreRegisterRType(typeid(moho::RBlueprint*), &sDescriptor);
      return &sDescriptor;
    }
  } // namespace

  /**
   * Address: 0x00556CE0 (FUN_00556CE0, Moho::RBlueprint::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<RBlueprint>`
   * descriptor. After that, lazily caches the
   * `LookupRType(typeid(RBlueprint*))` result in `sPointerType` and returns it.
   */
  gpg::RType* RBlueprint::GetPointerType()
  {
    static const bool sOnceInit = (PreregisterRBlueprintPointerType(), true);
    (void)sOnceInit;

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(RBlueprint*));
      sPointerType = cached;
    }
    return cached;
  }

  /**
   * Address: 0x0050DBB0 (FUN_0050DBB0, Moho::RBlueprintTypeInfo::RBlueprintTypeInfo)
   *
   * What it does:
   * Preregisters the `RBlueprint` RTTI instance at startup.
   */
  RBlueprintTypeInfo::RBlueprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RBlueprint), this);
  }

  /**
   * Address: 0x0050DC50 (FUN_0050DC50, Moho::RBlueprintTypeInfo::dtr)
   * Address: 0x0050DCB0 (FUN_0050DCB0, core dtor body)
   *
   * What it does:
   * Releases the startup-owned reflection descriptor and restores the base
   * `gpg::RObject` vtable.
   */
  RBlueprintTypeInfo::~RBlueprintTypeInfo() = default;

  /**
   * Address: 0x0050DC40 (FUN_0050DC40, Moho::RBlueprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the RTTI label for `RBlueprint`.
   */
  const char* RBlueprintTypeInfo::GetName() const
  {
    return "RBlueprint";
  }

  /**
 * Address: 0x0050E190 (FUN_0050E190, Moho::RBlueprintTypeInfo::AddBase_RObject)
 *
 * What it does:
 * Registers `gpg::RObject` as this type's reflected base at offset 0 -
 * RBlueprint derives from it singly.
*/
void RBlueprintTypeInfo::AddBase_RObject(gpg::RType* const typeInfo)
{
  gpg::RType* const rObjectType = CachedRObjectType();
  gpg::RField baseField{};
  baseField.mName = rObjectType->GetName();
  baseField.mType = rObjectType;
  baseField.mOffset = 0;
  baseField.mFlags = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
   * Address: 0x0050DC10 (FUN_0050DC10, Moho::RBlueprintTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size, registers the `gpg::RObject` base lane, and
   * publishes the `RBlueprint` field metadata.
   */
  void RBlueprintTypeInfo::Init()
  {
    size_ = sizeof(RBlueprint);
    AddBase_RObject(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050DF90 (FUN_0050DF90, Moho::RBlueprint::GetLuaBlueprint)
   *
   * What it does:
   * Returns `__blueprints[BlueprintOrdinal]` from the active Lua globals.
   */
  LuaPlus::LuaObject RBlueprint::GetLuaBlueprint(LuaPlus::LuaState* const state) const
  {
    if (!state) {
      return LuaPlus::LuaObject{};
    }

    LuaPlus::LuaObject allBlueprints = state->GetGlobal("__blueprints");
    return allBlueprints[static_cast<int>(mBlueprintOrdinal)];
  }

  /**
   * Address: 0x0050DCF0 (FUN_0050DCF0, Moho::RBlueprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers the base blueprint reflection fields and writes version/description
   * metadata for editor/runtime inspection lanes.
   */
  gpg::RField* RBlueprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    gpg::RField* field = typeInfo->AddField<msvc8::string>("BlueprintId", offsetof(RBlueprint, mBlueprintId));
    field->mFlags = 1;
    field->mDesc = "Blueprint Id";

    field = typeInfo->AddField<msvc8::string>("Description", offsetof(RBlueprint, mDescription));
    field->mFlags = 3;
    field->mDesc = "Generic type of unit (non-display name)";

    field = typeInfo->AddField<msvc8::string>("Source", offsetof(RBlueprint, mSource));
    field->mFlags = 1;
    field->mDesc = "File this blueprint was defined in";

    return typeInfo->AddField<int>("BlueprintOrdinal", offsetof(RBlueprint, mBlueprintOrdinal));
  }

  /**
   * Address: 0x00BC7FC0 (FUN_00BC7FC0, register_RBlueprintTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes `RBlueprintTypeInfo`.
   */
  void register_RBlueprintTypeInfo()
  {
    (void)AcquireRBlueprintTypeInfo();
  }
} // namespace moho

namespace
{
  struct RBlueprintTypeInfoBootstrap
  {
    RBlueprintTypeInfoBootstrap()
    {
      moho::register_RBlueprintTypeInfo();
    }
  };

  RBlueprintTypeInfoBootstrap gRBlueprintTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RBlueprintTypeInfo_c294bc, moho::register_RBlueprintTypeInfo)

GPG_PREREGISTER_INIT(PreregisterRBlueprintPointerType_c294bc, moho::PreregisterRBlueprintPointerType)
