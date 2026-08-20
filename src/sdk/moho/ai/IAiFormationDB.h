// Reconstructed from FA binary evidence (vtable + callsites + decomp).
#pragma once

#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/containers/TDatList.h"
#include "moho/entity/EntityCategoryReflection.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CAiFormationInstance;
  class RRuleGameRules;
  class Unit;

  /**
   * Formation script bucket type used by `/lua/formations.lua`.
   * Evidence: `FUN_00575A30`, `FUN_00575BD0`, `FUN_00575DB0`.
   */
  enum class EFormationType : std::int32_t
  {
    Surface = 0,
    Air = 1,
    Mixed = 2,
  };

  /**
   * 32-bit intrusive weak-unit slot word used by the formation creation path.
   *
   * Evidence:
   * - `FUN_0059C120` walks source entries as 4-byte words and re-links through
   *   owner-chain slot heads before passing a temporary linked view to
   *   `CFormationInstance` ctor (`FUN_005694B0`).
   */
  struct SFormationUnitWeakRef
  {
    /// The same word spelled two ways: guard-ring code handles it as the
    /// encoded owner-link slot pointer, formation code as a raw word.
    union
    {
      std::uint32_t ownerLinkSlotWord;
      void* ownerLinkSlot;
    };

    [[nodiscard]] static SFormationUnitWeakRef FromUnit(Unit* unit) noexcept;
    [[nodiscard]] std::uint32_t* DecodeOwnerChainHead() const noexcept;
  };
  static_assert(sizeof(SFormationUnitWeakRef) == 0x04, "SFormationUnitWeakRef size must be 0x04");

  /**
   * The capacity-independent head of a weak-unit reference set: an owner-chain
   * node followed by the slot lane. `CAiFormationDBImpl::NewFormation`
   * (0x0059C120) takes one of these by pointer and reads the lane at +0x08
   * (`mov esi,[edi+8]` / `mov eax,[edi+0Ch]`), which is why the lane cannot sit
   * at offset 0 the way a plain `fastvector_n` would put it.
   *
   * `Unit::GuardedByList` (`SGuardedByRuntimeList`) is the same shape with four
   * inline slots instead of eight; the two should eventually share this head.
   */
  struct SWeakUnitRefList
  {
    TDatListItem<void, void> mOwnerNode;                        // +0x00
    gpg::fastvector_runtime_view<SFormationUnitWeakRef> mSlots; // +0x08

    [[nodiscard]] const SFormationUnitWeakRef* begin() const noexcept { return mSlots.begin; }
    [[nodiscard]] const SFormationUnitWeakRef* end() const noexcept { return mSlots.end; }
    [[nodiscard]] bool empty() const noexcept { return mSlots.begin == mSlots.end; }
  };
  static_assert(sizeof(SWeakUnitRefList) == 0x18, "SWeakUnitRefList size must be 0x18");
  static_assert(offsetof(SWeakUnitRefList, mSlots) == 0x08, "SWeakUnitRefList::mSlots offset must be 0x08");

  /**
   * A weak-unit reference set with room for eight slots before it has to reach
   * the heap. Sized from the binary: the lane starts at +0x18 and the whole
   * object is 0x38 bytes, so the inline run is exactly eight entries.
   */
  struct SFormationUnitWeakRefSet : SWeakUnitRefList
  {
    SFormationUnitWeakRef mInlineSlots[8]; // +0x18

    SFormationUnitWeakRefSet() noexcept
    {
      mSlots.begin = mInlineSlots;
      mSlots.end = mInlineSlots;
      mSlots.capacityEnd = mInlineSlots + 8;
      mSlots.metadata = mInlineSlots;
    }

    /// Append one reference, spilling to the heap once the inline run is full.
    void Append(const SFormationUnitWeakRef& ref)
    {
      // Returns the insertion point, which a plain append has no use for.
      (void)gpg::FastVectorRuntimeInsertRange(mSlots, mSlots.end, &ref, &ref + 1);
    }
  };
  static_assert(sizeof(SFormationUnitWeakRefSet) == 0x38, "SFormationUnitWeakRefSet size must be 0x38");
  static_assert(
    offsetof(SFormationUnitWeakRefSet, mInlineSlots) == 0x18,
    "SFormationUnitWeakRefSet::mInlineSlots offset must be 0x18"
  );

  /**
   * One entry of the slot table `/lua/formations.lua` hands back: the
   * script-space offset from the formation centre, the unit category allowed
   * to take that slot, and the slot's ordering weight.
   *
   * Layout is proven instruction-by-instruction from `FORMATION_RunScript`
   * (0x00576690), which builds one of these in its own frame at
   * `entry_esp-0x530` and appends it. Displacements below are relative to that
   * base:
   *   +0x00 `mOffset.x`  `fstp` @0x005769C0 (`GetNumber` on Lua index 1)
   *   +0x04 `mOffset.z`  `fstp` @0x005769F3 (`GetNumber` on Lua index 2)
   *   +0x08 `mCategory.mUniverse`               `mov` @0x00576960, @0x00576A23
   *   +0x10 `mCategory.mBits.mFirstWordIndex`   `mov` @0x00576A35
   *   +0x18 `mCategory.mBits.mWords` pointer lanes @0x00576981..0x0057698D,
   *         with `capacity == &mWeight`, which pins the two-word inline run at
   *         +0x28..+0x30 and therefore `mCategory` at exactly 0x28 bytes
   *   +0x30 `mWeight`    `fstp` @0x00576A5D (`GetNumber` on Lua index 4)
   *
   * The 0x38 stride is proven twice more inside
   * `CAiFormationInstance::RunScript` (0x00567300): the `0x92492493` multiply
   * plus `sar edx,5` divide-by-56 at 0x00567838, and the `add ebx,38h` cursor
   * step at 0x00567939. `sub_570390` (the element destroy-range) walks the same
   * 0x38 stride and frees the nested word lane at +0x18/+0x24.
   *
   * Two lanes are never written by the binary and therefore carry stack garbage
   * in the shipped build: `mCategory.mReserved04` (+0x0C),
   * `mCategory.mBits.mReservedMetaWord` (+0x14) and `mReserved34` (+0x34). The
   * recovered form value-initializes them, which differs byte-wise from the
   * binary but is not observable - nothing reads them.
   */
  struct SFormationScriptSlot
  {
    SCoordsVec2 mOffset{};            // +0x00
    EntityCategorySet mCategory{};    // +0x08
    float mWeight{0.0f};              // +0x30
    /// Tail word the binary neither writes nor reads; present only because the
    /// element stride is provably 0x38 and the fields above end at 0x34.
    std::uint32_t mReserved34{0};     // +0x34
  };
  static_assert(sizeof(SFormationScriptSlot) == 0x38, "SFormationScriptSlot size must be 0x38");
  static_assert(offsetof(SFormationScriptSlot, mOffset) == 0x00, "SFormationScriptSlot::mOffset offset must be 0x00");
  static_assert(
    offsetof(SFormationScriptSlot, mCategory) == 0x08, "SFormationScriptSlot::mCategory offset must be 0x08"
  );
  static_assert(offsetof(SFormationScriptSlot, mWeight) == 0x30, "SFormationScriptSlot::mWeight offset must be 0x30");

  /**
   * Address: 0x00570390 (FUN_00570390, sub_570390)
   *
   * IDA signature:
   * unsigned int *__usercall sub_570390@<eax>(
   *     Moho::SFormationScriptSlot *first@<eax>, Moho::SFormationScriptSlot *last@<ebx>);
   *
   * What it does:
   * The emitted destroy-range for `SFormationScriptSlot`: for every slot in
   * `[first, last)` it releases the category word lane's heap buffer when one
   * is active and rebinds the lane to its inline run. Idempotent - a second
   * pass over the same range is a no-op, which is why the binary can both call
   * it from `~SFormationScriptResult` and let the container teardown follow.
   */
  void ReleaseFormationScriptSlotCategoryStorage(SFormationScriptSlot* first, SFormationScriptSlot* last) noexcept;

  /**
   * The value `FORMATION_RunScript` (0x00576690) returns: whether the script
   * reported success, plus the slot table it produced.
   *
   * Layout proven from the `FORMATION_RunScript` frame, where the local sits at
   * `entry_esp-0x488`:
   *   +0x00 `mSuccess`   byte store @0x005766D0, byte load @0x00576736
   *   +0x08 `mObjs` pointer lanes @0x005766D8..0x005766ED; the capacity lane is
   *         set to `inline + 0x460`, and 0x460 / 0x38 == 20 inline slots
   *   +0x18 inline slot run
   * `sub_576C20` (the `mObjs` copy constructor) writes the same shape onto the
   * returned object: `[dst+0x00..0x0C] = dst+0x10`, `capacity = dst+0x10+0x460`.
   * `sub_568320` (the destructor) reads `+0x08`/`+0x0C`/`+0x14`, i.e. the
   * vector's start/finish/origin lanes at `mObjs+0x00/+0x04/+0x0C`.
   *
   * The four bytes at +0x04 are never written; the vector simply starts at the
   * next 8-byte boundary.
   */
  struct SFormationScriptResult
  {
    bool mSuccess{false};                                 // +0x00
    std::uint8_t mPad01[3]{};                             // +0x01
    std::uint32_t mReserved04{0};                         // +0x04
    gpg::fastvector_n<SFormationScriptSlot, 20> mObjs{};  // +0x08

    SFormationScriptResult() = default;
    SFormationScriptResult(const SFormationScriptResult&) = default;
    SFormationScriptResult& operator=(const SFormationScriptResult&) = default;

    /**
     * Address: 0x00568320 (FUN_00568320, sub_568320)
     *
     * IDA signature:
     * unsigned int __usercall sub_568320@<eax>(Moho::SFormationScriptResult *this@<esi>);
     *
     * What it does:
     * Destroys every produced slot's category word lane, then releases the slot
     * vector's heap buffer and rebinds it to the inline run.
     */
    ~SFormationScriptResult();
  };
  static_assert(sizeof(SFormationScriptResult) == 0x478, "SFormationScriptResult size must be 0x478");
  static_assert(
    offsetof(SFormationScriptResult, mSuccess) == 0x00, "SFormationScriptResult::mSuccess offset must be 0x00"
  );
  static_assert(offsetof(SFormationScriptResult, mObjs) == 0x08, "SFormationScriptResult::mObjs offset must be 0x08");

  /**
   * Address: 0x00575A30 (FUN_00575A30, ?FORMATION_GetNumScripts@Moho@@YAIPAVLuaState@LuaPlus@@W4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * the number of scripts in that bucket.
   */
  unsigned int FORMATION_GetNumScripts(LuaPlus::LuaState* state, EFormationType formationType);

  /**
   * Address: 0x00575BD0 (FUN_00575BD0, ?FORMATION_GetScriptName@Moho@@YAPBDPAVLuaState@LuaPlus@@HW4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * one script-name string for the requested index.
   */
  const char* FORMATION_GetScriptName(LuaPlus::LuaState* state, int scriptIndex, EFormationType formationType);

  /**
   * Address: 0x00575DB0 (FUN_00575DB0, ?FORMATION_GetScriptIndex@Moho@@YAHPAVLuaState@LuaPlus@@VStrArg@gpg@@W4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * the zero-based index for one script name (`-1` when missing).
   */
  int FORMATION_GetScriptIndex(LuaPlus::LuaState* state, gpg::StrArg scriptName, EFormationType formationType);

  /**
   * Address: 0x00576010 (FUN_00576010, ?FORMATION_PickTravelFormation@Moho@@YAHPAVLuaState@LuaPlus@@W4EFormationType@1@M@Z)
   *
   * What it does:
   * Calls `/lua/formations.lua`::`PickBestTravelFormationIndex(formationTypeName, dist)`
   * and returns the chosen travel-formation index (or `0` on import/lookup/call
   * failure). Used by `CFormation::ChooseFormation` once the drag distance
   * exceeds 200 units.
   */
  int FORMATION_PickTravelFormation(LuaPlus::LuaState* state, EFormationType formationType, float dist);

  /**
   * Address: 0x00576350 (FUN_00576350, ?FORMATION_PickBestFormation@Moho@@YAHPAVLuaState@LuaPlus@@W4EFormationType@1@M@Z)
   *
   * What it does:
   * Calls `/lua/formations.lua` helper `PickBestFinalFormationIndex` and returns
   * the selected formation index.
   */
  int FORMATION_PickBestFormation(LuaPlus::LuaState* state, EFormationType formationType, float radius);

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
   * Imports `/lua/formations.lua`, calls the named formation function with the
   * caller's table of unit Lua objects, and converts the returned array of
   * `{offsetX, offsetZ, category, weight, flag}` tuples into slot descriptors.
   * The boolean of the last well-formed tuple becomes `mSuccess`; malformed
   * tuples are warned about and skipped.
   *
   * The shipped call site (0x005673F5 in `CAiFormationInstance::RunScript`) is
   * LTCG-customised: `state` arrives in ECX and the caller cleans the four
   * pushed dwords itself even though the mangled name claims `__cdecl`.
   */
  [[nodiscard]] SFormationScriptResult FORMATION_RunScript(
    LuaPlus::LuaState* state,
    RRuleGameRules* gameRules,
    gpg::StrArg scriptName,
    const LuaPlus::LuaObject& unitTable
  );

  /**
   * VFTABLE: 0x00E1B45C
   * COL:  0x00E70BD8
   */
  class IAiFormationDB
  {
  public:
    /**
     * Address: 0x0059C360 (FUN_0059C360)
     *
     * What it does:
     * Initializes one IAiFormationDB interface subobject vtable lane.
     */
    IAiFormationDB();

    /**
     * Address: 0x0059A3D0 (FUN_0059A3D0)
     *
     * What it does:
     * Base deleting-destructor thunk for formation DB interface.
     */
    virtual ~IAiFormationDB();

    /**
     * Address: 0x0059C0C0 (FUN_0059C0C0)
     * Mangled: ?GetScriptName@CAiFormationDBImpl@Moho@@UAEPBDHW4EFormationType@2@@Z
     *
     * What it does:
     * Returns the script-name string for a formation script index, selecting the
     * formation bucket from the passed unit set's composition. The PDB mangles the
     * second parameter as `EFormationType`, but the binary actually passes a
     * type-erased unit-set pointer (`SEntitySetTemplateUnit`/`SCommandUnitSet`)
     * whose unit composition `ResolveFormationBucketTypeFromUnitSet` scans to
     * derive the bucket -- it is NOT a caller-chosen formation-type enum.
     */
    virtual const char* GetScriptName(int scriptIndex, const void* unitSet) = 0;

    /**
     * Address: 0x0059C0F0 (FUN_0059C0F0)
     * Mangled: ?GetScriptIndex@CAiFormationDBImpl@Moho@@UAEHPBDW4EFormationType@2@@Z
     *
     * What it does:
     * Resolves a formation script name into its zero-based index within the
     * bucket derived from the passed unit set. As with GetScriptName, the second
     * parameter is a type-erased unit-set pointer that the PDB mislabels as
     * `EFormationType`.
     */
    virtual int GetScriptIndex(gpg::StrArg scriptName, const void* unitSet) = 0;

    /**
     * Address: 0x0059C060 (FUN_0059C060)
     * Mangled: ?RemoveFormation@CAiFormationDBImpl@Moho@@UAEXPAVCAiFormationInstance@2@@Z
     *
     * What it does:
     * Removes one formation-instance pointer from the DB storage.
     */
    virtual void RemoveFormation(CAiFormationInstance* formation) = 0;

    /**
     * Address: 0x0059C030 (FUN_0059C030)
     * Mangled: ?Update@CAiFormationDBImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Advances all live formation instances for the current sim tick.
     */
    virtual void Update() = 0;

    /**
     * Address: 0x0059C120 (FUN_0059C120)
     *
     * What it does:
     * Builds a temporary linked weak-unit view, constructs a new formation
     * instance, then appends it to this DB.
     */
    virtual CAiFormationInstance* NewFormation(
      const SWeakUnitRefList* unitWeakSet,
      const char* scriptName,
      const SCoordsVec2* formationCenter,
      float orientX,
      float orientY,
      float orientZ,
      float orientW,
      int commandType
    ) = 0;
  };

  static_assert(sizeof(IAiFormationDB) == 0x04, "IAiFormationDB size must be 0x04");
} // namespace moho
