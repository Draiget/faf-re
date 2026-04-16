#include "moho/ai/CAiFormationDBImpl.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = gpg::LookupRType(typeid(Sim));
    }
    return Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedFormationInstanceVectorType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::fastvector<IFormationInstance*>));
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeSimRef(Sim* sim)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedSimType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!sim || !staticType) {
      out.mObj = sim;
      return out;
    }

    gpg::RType* const dynamicType = gpg::LookupRType(typeid(*sim));
    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = sim;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(sim) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] Sim* ReadPointerSim(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedSimType();
    if (!expectedType || !tracked.type) {
      return static_cast<Sim*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<Sim*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "Sim",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  void WritePointerSim(gpg::WriteArchive* const archive, Sim* const sim, const gpg::RRef& ownerRef)
  {
    const gpg::RRef objectRef = MakeSimRef(sim);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  constexpr const char* kFormationModulePath = "/lua/formations.lua";
  constexpr const char* kFormationBuckets[] = {
    "SurfaceFormations",
    "AirFormations",
  };
  constexpr const char* kPickBestFinalFormationIndexName = "PickBestFinalFormationIndex";
  constexpr int kFormationBucketCount = static_cast<int>(sizeof(kFormationBuckets) / sizeof(kFormationBuckets[0]));

  [[nodiscard]] int ToFormationBucketIndex(const EFormationType type)
  {
    const int bucket = static_cast<int>(type);
    if (bucket < 0 || bucket >= kFormationBucketCount) {
      return 0;
    }
    return bucket;
  }

  [[nodiscard]] LuaPlus::LuaObject ResolveFormationBucket(LuaPlus::LuaState* state, const EFormationType formationType)
  {
    LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
    if (!module || !module.IsTable()) {
      return {};
    }

    const char* const bucketName = kFormationBuckets[ToFormationBucketIndex(formationType)];
    LuaPlus::LuaObject bucket = SCR_GetLuaTableField(state, module, bucketName);
    if (!bucket.IsTable()) {
      return {};
    }

    return bucket;
  }

  struct FormationTypeSelectionSetRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    const std::uint32_t* begin; // +0x08
    const std::uint32_t* end;   // +0x0C
  };
  static_assert(
    offsetof(FormationTypeSelectionSetRuntimeView, begin) == 0x08,
    "FormationTypeSelectionSetRuntimeView::begin offset must be 0x08"
  );
  static_assert(
    offsetof(FormationTypeSelectionSetRuntimeView, end) == 0x0C,
    "FormationTypeSelectionSetRuntimeView::end offset must be 0x0C"
  );

  /**
   * Address: 0x0062EE40 (FUN_0062EE40)
   *
   * What it does:
   * Scans one packed weak-unit set lane, queries each unit's formation-bucket
   * class tag (`+0x290` in the slot-7 runtime-info object), and returns:
   * `0 = no air bucket`, `1 = only air bucket`, `2 = mixed buckets`.
   */
  [[nodiscard]] int ResolveFormationBucketTypeFromPackedWeakSetLane(const std::uint32_t packedWeakSetLane)
  {
    // Some callsites pass a direct enum lane instead of a packed weak-set view.
    if (packedWeakSetLane <= static_cast<std::uint32_t>(EFormationType::Mixed)) {
      return static_cast<int>(packedWeakSetLane);
    }

    auto* const weakSet =
      reinterpret_cast<const FormationTypeSelectionSetRuntimeView*>(static_cast<std::uintptr_t>(packedWeakSetLane));
    if (weakSet == nullptr || weakSet->begin == weakSet->end) {
      return 0;
    }

    using QueryRuntimeInfoFn = void* (__thiscall*)(void*);
    bool hasAirBucket = false;
    bool hasNonAirBucket = false;

    for (const std::uint32_t* cursor = weakSet->begin; cursor != weakSet->end; ++cursor) {
      const std::uint32_t weakWord = *cursor;
      void* const unitObject =
        (weakWord != 0u) ? reinterpret_cast<void*>(static_cast<std::uintptr_t>(weakWord) - 8u) : nullptr;
      if (unitObject == nullptr) {
        hasNonAirBucket = true;
        continue;
      }

      auto** const vtable = *reinterpret_cast<void***>(unitObject);
      if (vtable == nullptr) {
        hasNonAirBucket = true;
        continue;
      }

      auto* const queryRuntimeInfo = reinterpret_cast<QueryRuntimeInfoFn>(vtable[7]);
      void* const runtimeInfo = (queryRuntimeInfo != nullptr) ? queryRuntimeInfo(unitObject) : nullptr;
      const std::uint32_t classTag = (runtimeInfo != nullptr)
        ? *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(runtimeInfo) + 0x290u)
        : 0u;
      if (classTag == 2u) {
        hasAirBucket = true;
      } else {
        hasNonAirBucket = true;
      }
    }

    if (!hasAirBucket) {
      return 0;
    }

    return hasNonAirBucket ? 2 : 1;
  }

  void UnlinkLinkedIUnitRef(SFormationLinkedUnitRef& linkRef) noexcept
  {
    if (!linkRef.ownerChainHead) {
      return;
    }

    std::uint32_t* cursor = linkRef.ownerChainHead;
    const std::uint32_t selfWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&linkRef));
    while (*cursor != selfWord) {
      cursor = SFormationLinkedUnitRef::NextChainLinkSlot(*cursor);
    }

    *cursor = linkRef.nextChainLink;
    linkRef.ownerChainHead = nullptr;
    linkRef.nextChainLink = 0;
  }

  class ScopedLinkedIUnitRefs final
  {
  public:
    explicit ScopedLinkedIUnitRefs(const SFormationUnitWeakRefSet* const unitWeakSet)
    {
      if (!unitWeakSet) {
        return;
      }

      const SFormationUnitWeakRef* const begin = unitWeakSet->begin();
      const SFormationUnitWeakRef* const end = unitWeakSet->end();
      if (!begin || begin == end) {
        return;
      }

      const std::size_t count = static_cast<std::size_t>(end - begin);
      mLinkedRefs.Reserve(count);
      for (const SFormationUnitWeakRef* src = begin; src != end; ++src) {
        SFormationLinkedUnitRef linkedValue{};
        mLinkedRefs.Append(linkedValue);
        SFormationLinkedUnitRef& linked = mLinkedRefs.back();
        linked.ownerChainHead = src->DecodeOwnerChainHead();
        if (!linked.ownerChainHead) {
          linked.nextChainLink = 0;
          continue;
        }

        linked.nextChainLink = *linked.ownerChainHead;
        *linked.ownerChainHead = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&linked));
      }
    }

    ~ScopedLinkedIUnitRefs()
    {
      for (SFormationLinkedUnitRef* it = mLinkedRefs.begin(); it != mLinkedRefs.end(); ++it) {
        UnlinkLinkedIUnitRef(*it);
      }
    }

    [[nodiscard]] const gpg::fastvector_n<SFormationLinkedUnitRef, 4>& refs() const noexcept
    {
      return mLinkedRefs;
    }

  private:
    gpg::fastvector_n<SFormationLinkedUnitRef, 4> mLinkedRefs;
  };

  [[nodiscard]] CAiFormationInstance* TryConstructFormationInstance(
    CAiFormationDBImpl& formationDb,
    const char* scriptName,
    const SCoordsVec2* formationCenter,
    const float orientX,
    const float orientY,
    const float orientZ,
    const float orientW,
    const int commandType,
    const gpg::fastvector_n<SFormationLinkedUnitRef, 4>& linkedUnits
  )
  {
    (void)formationDb;
    (void)scriptName;
    (void)formationCenter;
    (void)orientX;
    (void)orientY;
    (void)orientZ;
    (void)orientW;
    (void)commandType;
    (void)linkedUnits;

    // Full constructor lift remains blocked on unresolved CFormationInstance path:
    // - FUN_005694B0 (constructor)
    // - FUN_0056B200 and dependent container helpers it initializes.
    return nullptr;
  }
} // namespace

/**
 * Address: 0x00575A30 (FUN_00575A30, ?FORMATION_GetNumScripts@Moho@@YAIPAVLuaState@LuaPlus@@W4EFormationType@1@@Z)
 *
 * What it does:
 * Loads `/lua/formations.lua`, resolves the selected formation bucket table,
 * and returns the number of scripts in that bucket.
 */
unsigned int moho::FORMATION_GetNumScripts(LuaPlus::LuaState* const state, const EFormationType formationType)
{
  msvc8::string bucketName{kFormationBuckets[ToFormationBucketIndex(formationType)]};

  LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
  if (module.IsNil()) {
    gpg::Warnf("can't load the formations module -- no formations for you.");
    return 0;
  }

  LuaPlus::LuaObject scripts = module.GetByName(bucketName.c_str());
  if (!scripts.IsTable()) {
    gpg::Warnf("The formations module didn't define formations.  Hmm Odd?");
    return 0;
  }

  return static_cast<unsigned int>(scripts.GetN());
}

/**
 * Address: 0x00575BD0 (FUN_00575BD0, ?FORMATION_GetScriptName@Moho@@YAPBDPAVLuaState@LuaPlus@@HW4EFormationType@1@@Z)
 *
 * What it does:
 * Loads `/lua/formations.lua`, resolves the selected formation bucket table,
 * and returns the script-name string for the requested index.
 */
const char* moho::FORMATION_GetScriptName(
  LuaPlus::LuaState* const state,
  const int scriptIndex,
  const EFormationType formationType
)
{
  if (!state) {
    return nullptr;
  }

  msvc8::string bucketName{kFormationBuckets[ToFormationBucketIndex(formationType)]};

  LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
  if (module.IsNil()) {
    gpg::Warnf("can't load the formations module -- no formations for you.");
    return nullptr;
  }

  LuaPlus::LuaObject scripts = module.GetByName(bucketName.c_str());
  if (!scripts.IsTable()) {
    gpg::Warnf("The formations module didn't define formations.  Hmm Odd?");
    return nullptr;
  }

  const int scriptCount = scripts.GetN();
  const int luaIndex = (scriptIndex >= scriptCount) ? 1 : (scriptIndex + 1);
  LuaPlus::LuaObject scriptObject = scripts.GetByIndex(luaIndex);
  return scriptObject.GetString();
}

/**
 * Address: 0x00575DB0 (FUN_00575DB0, ?FORMATION_GetScriptIndex@Moho@@YAHPAVLuaState@LuaPlus@@VStrArg@gpg@@W4EFormationType@1@@Z)
 *
 * What it does:
 * Loads `/lua/formations.lua`, resolves the selected formation bucket table,
 * and returns the zero-based index of the requested script name (or `-1` if
 * not present).
 */
int moho::FORMATION_GetScriptIndex(
  LuaPlus::LuaState* const state,
  const gpg::StrArg scriptName,
  const EFormationType formationType
)
{
  msvc8::string bucketName{kFormationBuckets[ToFormationBucketIndex(formationType)]};

  LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
  if (module.IsNil()) {
    gpg::Warnf("Couldn't load the formations module -- no formations for you.");
    return 0;
  }

  LuaPlus::LuaObject scripts = module.GetByName(bucketName.c_str());
  if (!scripts.IsTable()) {
    gpg::Warnf("The formations module didn't define formations.  Hmm Odd?");
    return 0;
  }

  const int scriptCount = scripts.GetN();
  for (int luaIndex = 1; luaIndex <= scriptCount; ++luaIndex) {
    LuaPlus::LuaObject scriptObj = scripts.GetByIndex(luaIndex);
    if (!scriptObj.IsString()) {
      continue;
    }

    const char* const candidate = scriptObj.GetString();
    if (gpg::STR_EqualsNoCase(candidate, scriptName)) {
      return luaIndex - 1;
    }
  }

  return -1;
}

/**
 * Address: 0x00576350 (FUN_00576350, ?FORMATION_PickBestFormation@Moho@@YAHPAVLuaState@LuaPlus@@W4EFormationType@1@M@Z)
 *
 * What it does:
 * Calls `/lua/formations.lua`::`PickBestFinalFormationIndex(formationType, radius)`
 * and returns the chosen formation index (or `0` on import/call failure).
 */
int moho::FORMATION_PickBestFormation(
  LuaPlus::LuaState* const state,
  const EFormationType formationType,
  const float radius
)
{
  LuaPlus::LuaObject formationTypeArg;
  formationTypeArg.AssignString(state, kFormationBuckets[ToFormationBucketIndex(formationType)]);

  LuaPlus::LuaObject radiusArg;
  radiusArg.AssignNumber(state, radius);

  LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
  if (!module.IsTable()) {
    return 0;
  }

  LuaPlus::LuaObject pickBestFn = module.GetByName(kPickBestFinalFormationIndexName);
  if (!pickBestFn.IsFunction()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  pickBestFn.PushStack(rawState);
  formationTypeArg.PushStack(rawState);
  radiusArg.PushStack(rawState);
  if (lua_pcall(rawState, 2, 1, 0) != 0) {
    lua_settop(rawState, savedTop);
    return 0;
  }

  const LuaPlus::LuaStackObject resultSlot(state, -1);
  const LuaPlus::LuaObject result(resultSlot);
  const int bestIndex = result.GetInteger();

  lua_settop(rawState, savedTop);
  return bestIndex;
}

/**
 * Address: 0x0059BFA0 (FUN_0059BFA0)
 *
 * What it does:
 * Initializes formation-DB runtime lanes, binds the concrete vtable, and
 * seeds inline storage for the formation-instance fastvector.
 */
CAiFormationDBImpl::CAiFormationDBImpl() noexcept
  : IAiFormationDB()
  , mSim(nullptr)
  , mFormInstances()
{
}

/**
 * Address: 0x0059BFE0 (FUN_0059BFE0, non-deleting dtor body)
 * Address: 0x0059C340 (FUN_0059C340)
 *
 * What it does:
 * Resets inline-backed formation-instance storage before base teardown.
 */
CAiFormationDBImpl::~CAiFormationDBImpl()
{
  mFormInstances.ResetStorageToInline();
}

/**
 * Address: 0x0059EA20 (FUN_0059EA20, Moho::CAiFormationDBImpl::MemberDeserialize)
 *
 * What it does:
 * Reads serialized formation DB members from archive lanes.
 */
void CAiFormationDBImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef owner{};
  mSim = ReadPointerSim(archive, owner);

  gpg::RType* const vectorType = CachedFormationInstanceVectorType();
  gpg::RRef vectorOwner{};
  archive->Read(vectorType, &mFormInstances, vectorOwner);
}

/**
 * Address: 0x0059EA90 (FUN_0059EA90, Moho::CAiFormationDBImpl::MemberSerialize)
 *
 * What it does:
 * Writes serialized formation DB members to archive lanes.
 */
void CAiFormationDBImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  gpg::RRef owner{};
  WritePointerSim(archive, mSim, owner);

  gpg::RType* const vectorType = CachedFormationInstanceVectorType();
  gpg::RRef vectorOwner{};
  archive->Write(vectorType, &mFormInstances, vectorOwner);
}

/**
 * Address: 0x0059DBF0 (FUN_0059DBF0)
 *
 * What it does:
 * Serializer bridge thunk that forwards to `CAiFormationDBImpl::MemberSerialize`.
 */
[[maybe_unused]] void CAiFormationDbMemberSerializeBridgeA(
  const CAiFormationDBImpl* const formationDb,
  gpg::WriteArchive* const archive
)
{
  if (formationDb != nullptr) {
    formationDb->MemberSerialize(archive);
  }
}

/**
 * Address: 0x0059E030 (FUN_0059E030)
 *
 * What it does:
 * Serializer bridge thunk that forwards to `CAiFormationDBImpl::MemberSerialize`.
 */
[[maybe_unused]] void CAiFormationDbMemberSerializeBridgeB(
  const CAiFormationDBImpl* const formationDb,
  gpg::WriteArchive* const archive
)
{
  if (formationDb != nullptr) {
    formationDb->MemberSerialize(archive);
  }
}

/**
 * Address: 0x0059C030 (FUN_0059C030)
 */
void CAiFormationDBImpl::Update()
{
  for (CAiFormationInstance** it = mFormInstances.begin(); it != mFormInstances.end(); ++it) {
    (*it)->Update();
  }
}

/**
 * Address: 0x0059C060 (FUN_0059C060)
 */
void CAiFormationDBImpl::RemoveFormation(CAiFormationInstance* const formation)
{
  CAiFormationInstance** begin = mFormInstances.begin();
  CAiFormationInstance** end = mFormInstances.end();
  for (CAiFormationInstance** it = begin; it != end; ++it) {
    if (*it != formation) {
      continue;
    }

    for (CAiFormationInstance **src = it + 1, **dst = it; src != end; ++src, ++dst) {
      *dst = *src;
    }

    const std::size_t newSize = static_cast<std::size_t>((end - begin) - 1);
    mFormInstances.SetSizeUnchecked(newSize);
    return;
  }
}

/**
 * Address: 0x0059C0C0 (FUN_0059C0C0)
 */
const char* CAiFormationDBImpl::GetScriptName(const int scriptIndex, const EFormationType formationType)
{
  if (!mSim) {
    return nullptr;
  }

  const int resolvedBucket =
    ResolveFormationBucketTypeFromPackedWeakSetLane(static_cast<std::uint32_t>(formationType));
  return FORMATION_GetScriptName(
    mSim->GetLuaState(),
    scriptIndex,
    static_cast<EFormationType>(resolvedBucket)
  );
}

/**
 * Address: 0x0059C0F0 (FUN_0059C0F0)
 */
int CAiFormationDBImpl::GetScriptIndex(const gpg::StrArg scriptName, const EFormationType formationType)
{
  if (!mSim) {
    return 0;
  }

  const int resolvedBucket =
    ResolveFormationBucketTypeFromPackedWeakSetLane(static_cast<std::uint32_t>(formationType));
  return FORMATION_GetScriptIndex(
    mSim->GetLuaState(),
    scriptName,
    static_cast<EFormationType>(resolvedBucket)
  );
}

/**
 * Address: 0x0059C120 (FUN_0059C120)
 */
CAiFormationInstance* CAiFormationDBImpl::NewFormation(
  const SFormationUnitWeakRefSet* const unitWeakSet,
  const char* const scriptName,
  const SCoordsVec2* const formationCenter,
  const float orientX,
  const float orientY,
  const float orientZ,
  const float orientW,
  const int commandType
)
{
  ScopedLinkedIUnitRefs linkedUnits(unitWeakSet);
  CAiFormationInstance* const formation = TryConstructFormationInstance(
    *this, scriptName, formationCenter, orientX, orientY, orientZ, orientW, commandType, linkedUnits.refs()
  );
  if (!formation) {
    return nullptr;
  }

  CAiFormationInstance* formationForAppend = formation;
  mFormInstances.Append(formationForAppend);
  return formation;
}
