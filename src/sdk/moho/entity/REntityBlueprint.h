#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/collision/ECollisionShape.h"
#include "moho/sim/SFootprint.h"

namespace gpg
{
  class RType;
}

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace moho
{
  class CD3DBatchTexture;
  struct RResId;
  class RRuleGameRules;
  struct RUnitBlueprint;

  /**
   * Recovered layout prefix for Moho::REntityBlueprint.
   *
   * Verified from constructor/users:
   * - 0x00677360 (`func_FindBlueprintScriptModule`) for script-id/module/class strings
   * - 0x00678370 (`Entity::StandardInit`) for display/name strings
   * - 0x0067AE70 (`Entity::RefreshCollisionShapeFromBlueprint`) for collision block
   * - 0x00678880 (`Entity::GetFootprint`) for footprint offsets
   * - 0x0067B050 (`Entity::IsInCategory`) for category bit index
   * - 0x00512870 (`REntityBlueprintTypeInfo::AddFields`), 0x00511E80
   *   (`~REntityBlueprint`, including its `std::vector<std::string>::~vector`
   *   subobject-destructor trampoline) and 0x005289D0
   *   (`RegisterBlueprintCategoryMembership`) for `mCategories` at +0x60 -
   *   see the field's own doc comment for the full resolution of a
   *   previously-flagged (and now closed) +0x60-vs-+0x64 discrepancy.
   */
  struct REntityBlueprint
  {
    // +0x00 is the vtable word. It is a real vptr rather than an opaque pointer
    // field, because the type tests below are virtuals in the binary
    // (`??_7RUnitBlueprint@Moho@@6B@` slots 4 and 5) and nothing here ever
    // fills in a hand-rolled table. Being polymorphic is also what lets the
    // blueprint-kind test work: 0x00677360 asks the reflection system to
    // upcast the blueprint to RUnitBlueprint, which needs a dynamic type.
    RRuleGameRules* mOwner;                                   // +0x04 (owner game-rules pointer)
    msvc8::string mBlueprintId;                               // +0x08
    msvc8::string mBlueprintLabel;                            // +0x24 (optional label used by unique-name formatting)
    msvc8::string mSource;                                    // +0x40 (source blueprint path/id string)
    std::uint32_t mCategoryBitIndex;                          // +0x5C
    /**
     * Address: 0x00512870 (`Moho::REntityBlueprintTypeInfo::AddFields`) --
     * `push 60h` / `push offset "Categories"` / `call
     * gpg::RType::AddField<msvc8::vector<msvc8::string>>` registers the
     * reflected "Categories" field at `this+0x60` with an explicit
     * `vector<string>` type descriptor; the very next reflected field
     * (`push 70h` / "ScriptModule" / `AddField<msvc8::string>`) starts
     * exactly 0x10 bytes later, so the reflected field spans the full
     * `[0x60, 0x70)` range with no gap.
     *
     * Address: 0x00511E80 (`REntityBlueprint::~REntityBlueprint`) --
     * `lea edi,[esi+60h]` then reads/destroys/frees the vector through
     * `[edi+4]`/`[edi+8]`/`[edi+0Ch]` and zeroes that same triple; the
     * function's own address-taken subobject-destructor trampoline is even
     * more direct: `add ecx,60h` immediately followed by a tail-call to
     * `??1vector_string@std@@QAE@@Z` (`std::vector<std::string>::~vector()`).
     * That is the linker's own mangled-symbol confirmation that the
     * `vector<string>` subobject lives at `this+0x60`.
     *
     * `FUN_005289D0` (`RegisterBlueprintCategoryMembership`) and the
     * `REntityBlueprint` constructor (`FUN_00511C30`) both read/zero
     * `this+0x64`/`this+0x68`(/`+0x6C`) -- at first glance 4 bytes later
     * than this field's own offset, and a prior pass flagged that as an
     * unresolved discrepancy against the reflection/destructor evidence.
     * It is not one: `msvc8::vector<T>` in this codebase is 16 bytes
     * (`legacy/containers/Vector.h`, `myProxy_`/`first_`/`last_`/`end_`,
     * matching VC8's `_SECURE_SCL=1` `_Container_base12` proxy pointer that
     * ships even in Release), so `begin()`/`end()` (`first_`/`last_`) sit
     * at the *vector object's* `+0x4`/`+0x8`, i.e. `this+0x64`/`this+0x68`
     * when the vector object itself starts at `this+0x60`. The ctor's
     * zero-triple at `+0x64`/`+0x68`/`+0x6C` is exactly `first_`/`last_`/
     * `end_`; `+0x60` (`myProxy_`) is left uninitialized by the ctor for
     * the same reason the following string's allocator-cookie word
     * (`mScriptModule`'s `alVal` at `+0x70`) is also left unzeroed -
     * neither is read anywhere in this binary. All four sources therefore
     * agree on one layout; none actually conflicts.
     */
    msvc8::vector<msvc8::string> mCategories;                // +0x60
    msvc8::string mScriptModule;                              // +0x70
    msvc8::string mScriptClass;                               // +0x8C
    ECollisionShape mCollisionShape;                          // +0xA8
    float mSizeX;                                             // +0xAC
    float mSizeY;                                             // +0xB0
    float mSizeZ;                                             // +0xB4
    float mAverageDensity;                                    // +0xB8
    float mInertiaTensorX;                                    // +0xBC
    float mInertiaTensorY;                                    // +0xC0
    float mInertiaTensorZ;                                    // +0xC4
    float mCollisionOffsetX;                                  // +0xC8
    float mCollisionOffsetY;                                  // +0xCC
    float mCollisionOffsetZ;                                  // +0xD0
    std::int32_t mDesiredShooterCap;                          // +0xD4
    SFootprint mFootprint;                                    // +0xD8
    SFootprint mAltFootprint;                                 // +0xE8
    std::uint8_t mLifeBarRender;                              // +0xF8
    std::uint8_t mLifeBarPadding00F9_00FB[3];                 // +0xF9
    float mLifeBarOffset;                                     // +0xFC
    float mLifeBarSize;                                       // +0x100
    float mLifeBarHeight;                                     // +0x104
    float mSelectionSizeX;                                    // +0x108
    float mSelectionSizeY;                                    // +0x10C
    float mSelectionSizeZ;                                    // +0x110
    float mSelectionCenterOffsetX;                            // +0x114
    float mSelectionCenterOffsetY;                            // +0x118
    float mSelectionCenterOffsetZ;                            // +0x11C
    float mSelectionYOffset;                                  // +0x120
    float mSelectionMeshScaleX;                               // +0x124
    float mSelectionMeshScaleY;                               // +0x128
    float mSelectionMeshScaleZ;                               // +0x12C
    float mSelectionMeshUseTopAmount;                         // +0x130
    float mSelectionThickness;                                // +0x134
    float mUseOOBTestZoom;                                    // +0x138
    msvc8::string mStrategicIconName;                         // +0x13C
    /**
     * Strategic-icon draw-order tier. `CWldSession::RenderStrategicIcons`
     * (0x0085B6E0) reads it with a single-byte compare against `'A'` (0x41)
     * - `cmp byte ptr [edx+158h], 41h` at 0x0085C2C0 - to decide whether a
     * unit's icon has its own high-priority texture (>= 'A') or falls back
     * to the shared ground/air icon runs. Byte-sized, not the 32-bit word
     * this lane used to be typed as; the three bytes at +0x159..+0x15B are
     * unused padding up to `mStrategicIconRest`.
     */
    std::uint8_t mStrategicIconSortPriority;                  // +0x158
    std::uint8_t mStrategicIconSortPriorityPad0159_015B[3];    // +0x159
    /**
     * Four cached strategic-icon textures for this blueprint - rest, selected,
     * mouse-over and selected+mouse-over - read by the icon-texture picker
     * inlined into `CWldSession::RenderStrategicIcons`'s callee chain
     * (0x0085D880/0x0085CBD0). Retyped from `boost::weak_ptr` to
     * `boost::shared_ptr` (same 8-byte `{px, pn}` layout, so the offsets
     * below are unaffected): the reader promotes each one with a bare
     * `lock xadd [pn+4], 1` (0x0085D90A/0x0085D944/0x0085D992/0x0085CC15 et
     * al.) and no zero-check beforehand. A real `weak_ptr::lock()` goes
     * through `shared_count(weak_count const&)`'s `add_ref_lock()`, which
     * *does* check for an expired control block first
     * (`dependencies/boost_1_34_1/boost/detail/shared_count.hpp`) - the
     * binary never does that check here, so this is an ordinary
     * `shared_ptr` copy-construct (unconditional increment when the control
     * block pointer is non-null), not a weak-to-shared promotion.
     */
    boost::shared_ptr<CD3DBatchTexture> mStrategicIconRest;     // +0x15C
    boost::shared_ptr<CD3DBatchTexture> mStrategicIconSelected; // +0x164
    boost::shared_ptr<CD3DBatchTexture> mStrategicIconOver;     // +0x16C
    boost::shared_ptr<CD3DBatchTexture> mStrategicIconSelectedOver; // +0x174

    static gpg::RType* sType;

    /**
     * Local source compatibility constructor for scratch/entity-copy lanes
     * that need default-initialized storage.
     */
    REntityBlueprint();

    /**
     * Address: 0x00511C30 (FUN_00511C30)
     * Mangled: ??0REntityBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Runs base blueprint construction and seeds entity-blueprint physical,
     * footprint, life-bar, selection, and strategic-icon defaults.
     */
    REntityBlueprint(RRuleGameRules* owner, const RResId& resId);

    /**
     * Address: 0x00511E80 (FUN_00511E80)
     * Mangled: ??1REntityBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Releases strategic-icon weak-pointer lanes, destroys derived entity
     * string/vector fields, then tears down base blueprint ownership lanes.
     */
    virtual ~REntityBlueprint();

    /**
     * Address: 0x00512060 (FUN_00512060)
     *
     * What it does:
     * Initializes default footprint extents and inertia tensor values for
     * entity blueprints before derived blueprint init code runs.
     */
    void OnInitBlueprint();

    /**
     * Address: 0x00511B60 (FUN_00511B60)
     *
     * What it does:
     * Base entity-blueprint mobility query. Returns false for the base type.
     */
    [[nodiscard]] virtual bool IsMobile() const;

    /**
     * Address: 0x00511B70 (FUN_00511B70)
     *
     * What it does:
     * Base entity-blueprint unit cast hook. Returns nullptr for the base type.
     */
    [[nodiscard]] virtual const RUnitBlueprint* IsUnitBlueprint() const;

    /**
     * Address: 0x0050DF90 (FUN_0050DF90, Moho::RBlueprint::GetLuaBlueprint)
     *
     * What it does:
     * Returns `__blueprints[BlueprintOrdinal]` through the base `RBlueprint`
     * layout prefix shared by `REntityBlueprint`.
     */
    [[nodiscard]] LuaPlus::LuaObject GetLuaBlueprint(LuaPlus::LuaState* state) const;
  };

  static_assert(offsetof(REntityBlueprint, mOwner) == 0x04, "REntityBlueprint::mOwner offset must be 0x04");
  static_assert(offsetof(REntityBlueprint, mBlueprintId) == 0x08, "REntityBlueprint::mBlueprintId offset must be 0x08");
  static_assert(
    offsetof(REntityBlueprint, mBlueprintLabel) == 0x24, "REntityBlueprint::mBlueprintLabel offset must be 0x24"
  );
  static_assert(offsetof(REntityBlueprint, mSource) == 0x40, "REntityBlueprint::mSource offset must be 0x40");
  static_assert(
    offsetof(REntityBlueprint, mCategoryBitIndex) == 0x5C, "REntityBlueprint::mCategoryBitIndex offset must be 0x5C"
  );
  static_assert(
    offsetof(REntityBlueprint, mCategories) == 0x60, "REntityBlueprint::mCategories offset must be 0x60"
  );
  static_assert(
    offsetof(REntityBlueprint, mScriptModule) == 0x70, "REntityBlueprint::mScriptModule offset must be 0x70"
  );
  static_assert(offsetof(REntityBlueprint, mScriptClass) == 0x8C, "REntityBlueprint::mScriptClass offset must be 0x8C");
  static_assert(
    offsetof(REntityBlueprint, mCollisionShape) == 0xA8, "REntityBlueprint::mCollisionShape offset must be 0xA8"
  );
  static_assert(offsetof(REntityBlueprint, mSizeX) == 0xAC, "REntityBlueprint::mSizeX offset must be 0xAC");
  static_assert(offsetof(REntityBlueprint, mSizeY) == 0xB0, "REntityBlueprint::mSizeY offset must be 0xB0");
  static_assert(offsetof(REntityBlueprint, mSizeZ) == 0xB4, "REntityBlueprint::mSizeZ offset must be 0xB4");
  static_assert(
    offsetof(REntityBlueprint, mCollisionOffsetX) == 0xC8, "REntityBlueprint::mCollisionOffsetX offset must be 0xC8"
  );
  static_assert(
    offsetof(REntityBlueprint, mDesiredShooterCap) == 0xD4, "REntityBlueprint::mDesiredShooterCap offset must be 0xD4"
  );
  static_assert(offsetof(REntityBlueprint, mFootprint) == 0xD8, "REntityBlueprint::mFootprint offset must be 0xD8");
  static_assert(
    offsetof(REntityBlueprint, mAltFootprint) == 0xE8, "REntityBlueprint::mAltFootprint offset must be 0xE8"
  );
  static_assert(offsetof(REntityBlueprint, mLifeBarRender) == 0xF8, "REntityBlueprint::mLifeBarRender offset must be 0xF8");
  static_assert(offsetof(REntityBlueprint, mLifeBarOffset) == 0xFC, "REntityBlueprint::mLifeBarOffset offset must be 0xFC");
  static_assert(offsetof(REntityBlueprint, mLifeBarSize) == 0x100, "REntityBlueprint::mLifeBarSize offset must be 0x100");
  static_assert(offsetof(REntityBlueprint, mLifeBarHeight) == 0x104, "REntityBlueprint::mLifeBarHeight offset must be 0x104");
  static_assert(offsetof(REntityBlueprint, mSelectionSizeX) == 0x108, "REntityBlueprint::mSelectionSizeX offset must be 0x108");
  static_assert(
    offsetof(REntityBlueprint, mSelectionCenterOffsetX) == 0x114,
    "REntityBlueprint::mSelectionCenterOffsetX offset must be 0x114"
  );
  static_assert(
    offsetof(REntityBlueprint, mSelectionYOffset) == 0x120, "REntityBlueprint::mSelectionYOffset offset must be 0x120"
  );
  static_assert(
    offsetof(REntityBlueprint, mSelectionMeshScaleX) == 0x124,
    "REntityBlueprint::mSelectionMeshScaleX offset must be 0x124"
  );
  static_assert(
    offsetof(REntityBlueprint, mSelectionMeshUseTopAmount) == 0x130,
    "REntityBlueprint::mSelectionMeshUseTopAmount offset must be 0x130"
  );
  static_assert(
    offsetof(REntityBlueprint, mUseOOBTestZoom) == 0x138, "REntityBlueprint::mUseOOBTestZoom offset must be 0x138"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconName) == 0x13C, "REntityBlueprint::mStrategicIconName offset must be 0x13C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconSortPriority) == 0x158,
    "REntityBlueprint::mStrategicIconSortPriority offset must be 0x158"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconRest) == 0x15C, "REntityBlueprint::mStrategicIconRest offset must be 0x15C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconSelected) == 0x164,
    "REntityBlueprint::mStrategicIconSelected offset must be 0x164"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconOver) == 0x16C, "REntityBlueprint::mStrategicIconOver offset must be 0x16C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconSelectedOver) == 0x174,
    "REntityBlueprint::mStrategicIconSelectedOver offset must be 0x174"
  );
  static_assert(sizeof(REntityBlueprint) == 0x17C, "REntityBlueprint size must be 0x17C");
} // namespace moho
