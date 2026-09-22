#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"
#include "legacy/containers/String.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Tilts one watched bone so it points along the thrust its unit's motion is
   * producing, easing toward the new direction at a bounded turn rate, so a
   * hovering or flying unit's engine nozzles visibly swivel.
   *
   * VFTABLE: 0x00E231CC (primary, 2 slots: the scalar deleting destructor
   *   0x0064A480 and `ManipulatorUpdate` 0x0064A800)
   * VFTABLE: 0x00E231D8 (`CScriptObject` subobject at +0x10, 4 slots:
   *   `GetClass` 0x0064A190, `GetDerivedObjectRef` 0x0064A1B0, the destructor
   *   adjustor thunk 0x0064BA50 -- `sub ecx, 0x10; jmp 0x64A480` -- and
   *   0x004C70A0, inherited unchanged from `CScriptObject`)
   *
   * The layout comes off the default constructor at 0x0064A3E0, which after
   * chaining to `IAniManipulator::IAniManipulator` writes both vftables, then
   * `mov [esi+0x80], 0` / `mov [esi+0x84], 0` (the weak-pointer node),
   * `mov byte [esi+0x8c], 0` / `mov [esi+0x9c], 0` / `mov [esi+0xa0], 0xf`
   * (`msvc8::string`'s `_Bx._Buf[0]` / `_Mysize` / `_Myres`, which is what
   * pins `mLabel` to +0x88), `mov byte [esi+0xa8], 0`, the two cap vectors,
   * and the two turn scalars. `sizeof` is pinned twice over: by
   * `CThrustManipulatorTypeInfo::Init` (0x0064A230), whose first store is
   * `mov [esi+8], 0xE8`, and by `NewRef` (0x0064B1E0), which passes 0xE8 to
   * `::operator new`.
   *
   * `mThrustBoneIndex`, `mRestDirection` and `mOrientation` are deliberately
   * absent from that list: neither constructor initializes them before the
   * watched bone is resolved, and the default constructor never does at all.
   *
   * This class previously existed only as reach-in views over an empty stub of
   * the same name -- `CThrustManipulatorSerializerRuntimeView` in this
   * subsystem's .cpp and `CThrustManipulatorLuaRuntimeView` in
   * `moho/sim/ManipulatorLuaFunctionThunks.cpp` -- with every use going
   * through a `reinterpret_cast`. The stub inherited `IAniManipulator::sType`,
   * so `gpg::SerSaveLoadHelper<CThrustManipulator>::Init` (0x0064B150) bound
   * this class's load/save callbacks onto `IAniManipulator`'s reflected type
   * instead of the descriptor the binary keeps at 0x010C73E0; `sType` below is
   * what separates them again.
   */
  class CThrustManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x0064A3E0 (FUN_0064A3E0, ??0CThrustManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds detached/default thrust-manipulator state for the reflection
     * construction paths (`CThrustManipulatorTypeInfo::NewRef`/`CtrRef`): no
     * bound unit, empty label, thrust unclamped between -100 and +100 on each
     * axis, unit turn force, 0.3 rad turn step.
     */
    CThrustManipulator();

    /**
     * Address: 0x0064A4A0 (FUN_0064A4A0, ??0CThrustManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds a thrust manipulator bound to `unit`'s actor and sim, watching
     * `thrustBoneIndex`, then creates its Lua object and seeds
     * `mRestDirection` from the watched bone's local orientation (its local
     * +Z axis) and `mOrientation` from the shortest arc between world up and
     * that axis.
     *
     * The parameter order is fixed by the compiler's register assignment for
     * this TU-local body: `ecx` carries the string it runs `strlen` over and
     * `edx` the unit whose `+0x150`/`+0x540` it reads for the base
     * constructor, so `label` precedes `unit`.
     */
    CThrustManipulator(const char* label, Unit* unit, int thrustBoneIndex);

    /**
     * Address: 0x0064A740 (FUN_0064A740, ??1CThrustManipulator@Moho@@UAE@XZ)
     * Address: 0x0064A480 (FUN_0064A480, ??_GCThrustManipulator@Moho@@UAEPAXI@Z)
     *
     * VFTable SLOT: 0
     *
     * What it does:
     * Nothing of its own. Every instruction in 0x0064A740 is compiler output:
     * the two vftable restores, `~basic_string` inlined (`cmp [esi+0xa0],
     * 0x10` / free / reset to `{0, 0xF}`), `~WeakPtr` inlined (the owner-chain
     * splice at 0x0064A783-0x0064A79C), and `jmp 0x62FC70` to
     * `~IAniManipulator`. 0x0064A480 is the scalar deleting destructor MSVC
     * parks in slot 0, and 0x0064BA50 its `CScriptObject`-subobject adjustor.
     */
    ~CThrustManipulator() override = default;

    /**
     * Address: 0x0064A800 (FUN_0064A800, Moho::CThrustManipulator::MoveManipulator)
     *
     * VFTable SLOT: 1
     *
     * What it does:
     * Turns the unit's motion force plus its roll-induced bone displacement
     * into a thrust direction, clamps it per-axis into the configured caps,
     * and rotates the watched bone toward it by at most `mTurnSpeed` radians.
     * A unit still under construction holds its current orientation.
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x0064B6E0 (FUN_0064B6E0, Moho::CThrustManipulator::MemberDeserialize)
     *
     * What it does:
     * Reads the `IAniManipulator` base payload, the owning unit's weak
     * pointer, the label, the watched bone index and thrusting flag, both cap
     * vectors, both turn scalars, the rest direction and the orientation.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0064B890 (FUN_0064B890, Moho::CThrustManipulator::MemberSerialize)
     *
     * What it does:
     * Writes the same eleven payloads `MemberDeserialize` reads, in the same
     * order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0064A190 (FUN_0064A190)
     *
     * VFTable SLOT: 0 (`CScriptObject` subobject at +0x10)
     *
     * What it does:
     * Resolves and caches this class's reflected type descriptor, the global
     * the binary keeps at 0x010C73E0. Unlike `CStorageManipulator`, which
     * carries this body twice (0x006498C0 and 0x00648D70), the thrust
     * manipulator has exactly one copy and no ICF twin, because nothing in
     * the binary calls the static form -- every such use was inlined, the
     * serializer helper's included.
     *
     * Leaving it off the class left this slot resolving to
     * `IAniManipulator`'s own 0x0062FC30, which answers with the wrong
     * reflected type.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0064A1B0 (FUN_0064A1B0, ?GetDerivedObjectRef@CThrustManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1 (`CScriptObject` subobject at +0x10)
     *
     * What it does:
     * Pairs the complete object with its dynamic reflected type. The body
     * dispatches `GetClass` through the subobject vptr and then walks `this`
     * back by the subobject offset (`add esi, -0x10`), which is why the
     * reference names the `CThrustManipulator` and not its `CScriptObject`.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /// Cached reflected type descriptor -- the binary's 0x010C73E0, filled
    /// from `gpg::LookupRType` with the descriptor at 0x00F73B00.
    static gpg::RType* sType;

    /// The unit whose motion drives the thrust direction. Null on an instance
    /// built by the reflection construction paths, until deserialization
    /// binds one.
    WeakPtr<Unit> mUnit;           // +0x80
    /// Name this manipulator was created under. Written by both constructors
    /// and carried through save/load; no code in the binary reads it back.
    msvc8::string mLabel;          // +0x88
    /// Bone this manipulator swivels, and the bone whose world transform the
    /// roll correction is measured at.
    std::int32_t mThrustBoneIndex; // +0xA4
    /// Written `false` by both constructors and carried through save/load.
    /// Like `mLabel`, nothing in the binary reads it back -- no code path
    /// outside the two serializers touches +0xA8.
    bool mThrusting;               // +0xA8
    std::uint8_t mPadA9_AB[3]{};   // +0xA9
    /// Per-axis lower bound on the bone-local thrust direction.
    Wm3::Vector3f mCapMin;         // +0xAC
    /// Per-axis upper bound on the bone-local thrust direction.
    Wm3::Vector3f mCapMax;         // +0xB8
    /// Scales how much the roll-induced bone displacement adds to the thrust.
    float mTurnForceMult;          // +0xC4
    /// Largest orientation change allowed per tick, in radians.
    float mTurnSpeed;              // +0xC8
    /// The watched bone's local +Z axis at construction -- the direction the
    /// nozzle points before any thrust is applied, and the `currentUp` every
    /// shortest-arc delta is measured from.
    Wm3::Vector3f mRestDirection;  // +0xCC
    /// The delta rotation applied to the watched bone last tick.
    Wm3::Quaternionf mOrientation; // +0xD8
  };

  static_assert(offsetof(CThrustManipulator, mUnit) == 0x80, "CThrustManipulator::mUnit offset must be 0x80");
  static_assert(offsetof(CThrustManipulator, mLabel) == 0x88, "CThrustManipulator::mLabel offset must be 0x88");
  static_assert(
    offsetof(CThrustManipulator, mThrustBoneIndex) == 0xA4,
    "CThrustManipulator::mThrustBoneIndex offset must be 0xA4"
  );
  static_assert(
    offsetof(CThrustManipulator, mThrusting) == 0xA8,
    "CThrustManipulator::mThrusting offset must be 0xA8"
  );
  static_assert(offsetof(CThrustManipulator, mCapMin) == 0xAC, "CThrustManipulator::mCapMin offset must be 0xAC");
  static_assert(offsetof(CThrustManipulator, mCapMax) == 0xB8, "CThrustManipulator::mCapMax offset must be 0xB8");
  static_assert(
    offsetof(CThrustManipulator, mTurnForceMult) == 0xC4,
    "CThrustManipulator::mTurnForceMult offset must be 0xC4"
  );
  static_assert(
    offsetof(CThrustManipulator, mTurnSpeed) == 0xC8,
    "CThrustManipulator::mTurnSpeed offset must be 0xC8"
  );
  static_assert(
    offsetof(CThrustManipulator, mRestDirection) == 0xCC,
    "CThrustManipulator::mRestDirection offset must be 0xCC"
  );
  static_assert(
    offsetof(CThrustManipulator, mOrientation) == 0xD8,
    "CThrustManipulator::mOrientation offset must be 0xD8"
  );
  static_assert(sizeof(CThrustManipulator) == 0xE8, "CThrustManipulator size must be 0xE8");
} // namespace moho
