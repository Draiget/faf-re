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
#include "lua/LuaTableIterator.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"
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

  /// Distinct from `kFormationBuckets`: `PickBestTravelFormationIndex` (Lua)
  /// takes a per-type name string covering all three `EFormationType` values,
  /// including a dedicated "Combo" name for `Mixed`, unlike the two-entry
  /// script-bucket table the other `FORMATION_*` helpers clamp into. Verified
  /// against the binary's `formationtype_names` rdata array at 0x00F58C44
  /// (indexed directly by `EFormationType` with no bounds clamp).
  constexpr const char* kFormationTravelTypeNames[] = {
    "SurfaceFormations",
    "AirFormations",
    "ComboFormations",
  };
  constexpr const char* kPickBestTravelFormationIndexName = "PickBestTravelFormationIndex";

  /**
   * The category-word universe lane is a 4-byte handle that the sim fills with
   * the owning `RRuleGameRules` instance (`mov [slot+8], rules` at
   * 0x00576960, later overwritten by `mov edx,[category]` at 0x00576A21). This
   * keeps the one narrowing conversion in a single named place instead of
   * spelling a pointer cast at the assignment site.
   */
  [[nodiscard]] std::uint32_t ToCategoryUniverseHandle(const RRuleGameRules* const gameRules) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(gameRules));
  }

  [[nodiscard]] int ToFormationBucketIndex(const EFormationType type)
  {
    const int bucket = static_cast<int>(type);
    if (bucket < 0 || bucket >= kFormationBucketCount) {
      return 0;
    }
    return bucket;
  }

  /**
   * Orphan: no caller found anywhere in src/sdk, and this function has no
   * `Address:` citation of its own (no evidence it corresponds to a distinct
   * compiled function in the binary). The six real, address-cited
   * `FORMATION_*` entry points below (`FORMATION_GetNumScripts`,
   * `FORMATION_GetScriptName`, `FORMATION_GetScriptIndex`,
   * `FORMATION_PickTravelFormation`, `FORMATION_PickBestFormation`,
   * `FORMATION_RunScript`) each independently import `/lua/formations.lua`
   * and resolve a bucket/table, but none matches this function's exact
   * shape: they use `module.GetByName(...)`/`SCR_Import`, not
   * `SCR_GetLuaTableField`, and each has its own distinct warning-message
   * behavior on failure (`ResolveFormationBucket` fails silently). Redirecting
   * any of them to call this instead would risk changing that
   * binary-observed behavior without evidence, so none were touched.
   */
  [[maybe_unused]] [[nodiscard]] LuaPlus::LuaObject ResolveFormationBucket(LuaPlus::LuaState* state, const EFormationType formationType)
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
   * Scans one unit set's weak-entry lane and returns which movement buckets it
   * spans: `0 = no air bucket`, `1 = only air bucket`, `2 = mixed buckets`.
   *
   * A unit counts as air when its blueprint's `Physics.MotionType` is
   * `RULEUMT_Air`. The binary reaches that through vtable slot 7 and a raw
   * `+0x290` read: slot 7 is `Unit::GetBlueprint` (0x006A8B20, annotated
   * `Slot: 7` in Unit.h), and `+0x290` lands in `Physics` (which starts at
   * `RUnitBlueprint + 0x278`) at its `MotionType` field (`Physics + 0x18`).
   * The compared constant 2 is `RULEUMT_Air`.
   *
   * The unit set is taken type-erased: callers pass two distinct but
   * layout-compatible types -- `moho::SEntitySetTemplateUnit` (GetScriptIndex) and
   * `moho::SCommandUnitSet` (GetScriptName) -- both exposing the weak-entry
   * begin/end lane at the same offsets, viewed here through
   * `FormationTypeSelectionSetRuntimeView`.
   */
  [[nodiscard]] int ResolveFormationBucketTypeFromUnitSet(const void* const unitSet)
  {
    const auto* const weakSet = static_cast<const FormationTypeSelectionSetRuntimeView*>(unitSet);
    if (weakSet == nullptr || weakSet->begin == weakSet->end) {
      return 0;
    }

    bool hasAirBucket = false;
    bool hasNonAirBucket = false;

    for (const std::uint32_t* cursor = weakSet->begin; cursor != weakSet->end; ++cursor) {
      // The weak entry stores the referenced unit biased by 8; the entity base
      // sits at `Unit + 0x08`, so unbiasing yields the owning `Unit`.
      const std::uint32_t weakWord = *cursor;
      auto* const unit = (weakWord != 0u)
        ? reinterpret_cast<const moho::Unit*>(static_cast<std::uintptr_t>(weakWord) - 8u)
        : nullptr;

      const moho::RUnitBlueprint* const blueprint =
        (unit != nullptr) ? unit->GetBlueprint() : nullptr;

      if (blueprint != nullptr && blueprint->Physics.MotionType == moho::RULEUMT_Air) {
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
    explicit ScopedLinkedIUnitRefs(const SWeakUnitRefList* const unitWeakSet)
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
 * Address: 0x00576010 (FUN_00576010, ?FORMATION_PickTravelFormation@Moho@@YAHPAVLuaState@LuaPlus@@W4EFormationType@1@M@Z)
 *
 * IDA signature:
 * int __usercall Moho::FORMATION_PickTravelFormation@<eax>(
 *     int formationType, float dist, LuaPlus::LuaState *state@<ecx>);
 *
 * What it does:
 * Calls `/lua/formations.lua`::`PickBestTravelFormationIndex(formationTypeName, dist)`
 * and returns the chosen travel-formation index (or `0` on import/lookup/call
 * failure).
 */
int moho::FORMATION_PickTravelFormation(
  LuaPlus::LuaState* const state,
  const EFormationType formationType,
  const float dist
)
{
  LuaPlus::LuaObject formationTypeArg;
  formationTypeArg.AssignString(state, kFormationTravelTypeNames[static_cast<int>(formationType)]);

  LuaPlus::LuaObject distArg;
  distArg.AssignNumber(state, dist);

  LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
  if (!module.IsTable()) {
    return 0;
  }

  LuaPlus::LuaObject pickTravelFn = module.GetByName(kPickBestTravelFormationIndexName);
  if (!pickTravelFn.IsFunction()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  pickTravelFn.PushStack(rawState);
  formationTypeArg.PushStack(rawState);
  distArg.PushStack(rawState);
  if (lua_call(rawState, 2, 1) != 0) {
    lua_settop(rawState, savedTop);
    return 0;
  }

  const LuaPlus::LuaStackObject resultSlot(state, -1);
  const LuaPlus::LuaObject result(resultSlot);
  const int travelFormationIndex = result.GetInteger();

  lua_settop(rawState, savedTop);
  return travelFormationIndex;
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
  if (lua_call(rawState, 2, 1) != 0) {
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
 * Address: 0x00570390 (FUN_00570390, sub_570390)
 *
 * IDA signature:
 * unsigned int *__usercall sub_570390@<eax>(
 *     Moho::SFormationScriptSlot *first@<eax>, Moho::SFormationScriptSlot *last@<ebx>);
 *
 * What it does:
 * Releases each slot's category word lane and rebinds it to the inline run:
 * `if (words.start != words.origin) { delete[] words.start; words.start =
 * words.origin; words.capacity = *words.origin; } words.finish = words.start;`
 * - exactly the loop at 0x0057039A..0x005703C1 over a 0x38 stride.
 */
void moho::ReleaseFormationScriptSlotCategoryStorage(
  SFormationScriptSlot* const first,
  SFormationScriptSlot* const last
) noexcept
{
  for (SFormationScriptSlot* slot = first; slot != last; ++slot) {
    slot->mCategory.mBits.mWords.ResetStorageToInline();
  }
}

/**
 * Address: 0x00568320 (FUN_00568320, sub_568320)
 *
 * IDA signature:
 * unsigned int __usercall sub_568320@<eax>(Moho::SFormationScriptResult *this@<esi>);
 *
 * What it does:
 * Destroys the produced slots (0x00568327 `call sub_570390` over
 * `[mObjs.start, mObjs.finish)`), then releases the slot vector's heap buffer
 * and rebinds the lanes to the inline run.
 */
moho::SFormationScriptResult::~SFormationScriptResult()
{
  ReleaseFormationScriptSlotCategoryStorage(mObjs.begin(), mObjs.end());
  mObjs.ResetStorageToInline();
}

/**
 * Address: 0x00576690 (FUN_00576690)
 * Mangled:
 * ?FORMATION_RunScript@Moho@@YA?AUSFormationScriptResult@1@PAVLuaState@LuaPlus@@PAVRRuleGameRules@1@VStrArg@gpg@@ABVLuaObject@4@@Z
 *
 * IDA signature:
 * Moho::SFormationScriptResult *__usercall Moho::FORMATION_RunScript@<eax>(
 *     Moho::SFormationScriptResult *result,
 *     Moho::RRuleGameRules *gameRules,
 *     const char *scriptName,
 *     LuaPlus::LuaObject *unitTable,
 *     LuaPlus::LuaState *state@<ecx>);
 *
 * What it does:
 * Imports `/lua/formations.lua`, resolves `scriptName` in it, and calls it with
 * the caller's table of unit Lua objects. Every returned five-element tuple
 * `{offsetX, offsetZ, category, weight, flag}` becomes one
 * `SFormationScriptSlot`; the flag of the last well-formed tuple is what ends
 * up in `mSuccess`. A missing module returns an empty result silently; a
 * missing function, a script error, a non-table return value and a malformed
 * tuple each warn and leave the slots produced so far untouched.
 */
moho::SFormationScriptResult moho::FORMATION_RunScript(
  LuaPlus::LuaState* const state,
  RRuleGameRules* const gameRules,
  const gpg::StrArg scriptName,
  const LuaPlus::LuaObject& unitTable
)
{
  SFormationScriptResult result{};

  // 0x00576716: the module lookup is the plain SCR_Import lane, and a
  // non-table result returns an empty, unsuccessful descriptor *without* a
  // warning - unlike the four sibling FORMATION_* entry points.
  LuaPlus::LuaObject module = SCR_Import(state, kFormationModulePath);
  if (!module.IsTable()) {
    return result;
  }

  LuaPlus::LuaObject scriptFunc = module.GetByName(scriptName);
  if (!scriptFunc.IsFunction()) {
    gpg::Warnf("Could not find lua create formation function %s.", scriptName);
    return result;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  scriptFunc.PushStack(state);
  unitTable.PushStack(state);
  if (lua_call(rawState, 1, 1) != 0) {
    const LuaPlus::LuaStackObject errorSlot(state, -1);
    gpg::Warnf("Formation script %s threw an error:\n%s", scriptName, errorSlot.GetString());
    lua_settop(rawState, savedTop);
    return result;
  }

  {
    const LuaPlus::LuaStackObject returnedSlot(state, -1);
    LuaPlus::LuaObject slotTable(returnedSlot);
    if (!slotTable.IsTable()) {
      gpg::Warnf("Formation script did not retuan a table!");
    } else {
      for (LuaPlus::LuaTableIterator entryIt(slotTable, 1); entryIt.IsValid(); entryIt.Next()) {
        LuaPlus::LuaObject entry = entryIt.GetValue();
        if (!entry.IsTable() || entry.GetCount() != 5) {
          gpg::Warnf("Error in the formation slot! Either not a table or num params != 5.");
          continue;
        }

        // 0x00576952..0x00576991: the slot is seeded with the caller's rules
        // pointer as the category universe handle before anything else; the
        // category read below then overwrites it with the category's own.
        SFormationScriptSlot slot{};
        slot.mCategory.mUniverse.mWordUniverseHandle = ToCategoryUniverseHandle(gameRules);

        slot.mOffset.x = static_cast<float>(entry[1].GetNumber());
        slot.mOffset.z = static_cast<float>(entry[2].GetNumber());

        const EntityCategorySet* const category = func_GetCObj_EntityCategory(entry[3]);
        slot.mCategory.mUniverse = category->mUniverse;
        slot.mCategory.mBits.mFirstWordIndex = category->mBits.mFirstWordIndex;
        // 0x00576A39: `gpg::fastvector_uint::cpy` over the word lanes only -
        // the two reserved dwords are deliberately not carried across.
        slot.mCategory.mBits.mWords = category->mBits.mWords;

        slot.mWeight = static_cast<float>(entry[4].GetNumber());
        result.mSuccess = entry[5].GetBoolean();

        result.mObjs.push_back(slot);
      }
    }
  }

  lua_settop(rawState, savedTop);
  return result;
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
const char* CAiFormationDBImpl::GetScriptName(const int scriptIndex, const void* const unitSet)
{
  if (!mSim) {
    return nullptr;
  }

  const int resolvedBucket = ResolveFormationBucketTypeFromUnitSet(unitSet);
  return FORMATION_GetScriptName(
    mSim->GetLuaState(),
    scriptIndex,
    static_cast<EFormationType>(resolvedBucket)
  );
}

/**
 * Address: 0x0059C0F0 (FUN_0059C0F0)
 */
int CAiFormationDBImpl::GetScriptIndex(const gpg::StrArg scriptName, const void* const unitSet)
{
  if (!mSim) {
    return 0;
  }

  const int resolvedBucket = ResolveFormationBucketTypeFromUnitSet(unitSet);
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
  const SWeakUnitRefList* const unitWeakSet,
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
