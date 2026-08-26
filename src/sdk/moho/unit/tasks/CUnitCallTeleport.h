#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Quaternion.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class Unit;
  class VTransform;

  class CUnitCallTeleport : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    CUnitCallTeleport() = default;

    /**
     * Address: 0x00600E90 (FUN_00600E90, ??0CUnitCallTeleport@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes a teleport-call task using parent dispatch context, binds a
     * weak target-unit link, clears runtime flags, and sets the teleport state
     * bit on the owning unit.
     */
    CUnitCallTeleport(CCommandTask* parentTask, Unit* targetUnit);

    /**
     * Address: 0x00600EF0 (FUN_00600EF0, Moho::CUnitCallTeleport::~CUnitCallTeleport)
     *
     * What it does:
     * Clears call-teleport state flags on the owner unit, removes transport
     * waiting/pickup links when needed, publishes dispatch result, and unlinks
     * the weak transport-unit lane.
     */
    ~CUnitCallTeleport() override;

    /**
     * Address: 0x00603CD0 (FUN_00603CD0)
     *
     * What it does:
     * Loads base command-task state plus teleport-task weak-unit and status
     * flags from archive data.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00603D60 (FUN_00603D60)
     *
     * What it does:
     * Saves base command-task state plus teleport-task weak-unit and status
     * flags into archive data.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, const CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006013D0 (FUN_006013D0, Moho::CUnitCallTeleport::TaskTick)
     *
     * What it does:
     * Runs teleport-call state transitions between pickup staging, attach
     * movement, and teleport-task spawn while keeping O-grid occupancy state.
     */
    int Execute() override;

  private:
    /**
     * Address: 0x005E2340 (FUN_005E2340, CUnitCallTeleport::BuildGroundTeleportTarget)
     *
     * What it does:
     * Builds one ground-target payload from world position, clears entity-link
     * lanes, and resets target-point/mobile flags.
     */
    [[nodiscard]] static CAiTarget BuildGroundTeleportTarget(const Wm3::Vector3f& worldPos) noexcept;

  public:
    WeakPtr<Unit> mTargetTransportUnit; // 0x30
    bool mCompletedSuccessfully;         // 0x38
    bool mIsOccupying;                  // 0x39
    std::uint8_t mPadding3A[2];         // 0x3A
  };

  static_assert(sizeof(CUnitCallTeleport) == 0x3C, "CUnitCallTeleport size must be 0x3C");
  static_assert(
    offsetof(CUnitCallTeleport, mTargetTransportUnit) == 0x30,
    "CUnitCallTeleport::mTargetTransportUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mCompletedSuccessfully) == 0x38,
    "CUnitCallTeleport::mCompletedSuccessfully offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mIsOccupying) == 0x39,
    "CUnitCallTeleport::mIsOccupying offset must be 0x39"
  );

  class CUnitTeleportTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0060AB20 (FUN_0060AB20, Moho::CUnitTeleportTask::CUnitTeleportTask)
     *
     * What it does:
     * Initializes one teleport execution task with copied target payload,
     * weak-linked beacon lane, and source orientation snapshot.
     */
    CUnitTeleportTask(
      CCommandTask* parentTask,
      const CAiTarget& target,
      Unit* teleportBeaconUnit,
      const VTransform& sourceTransform
    );

    /**
     * Address: 0x0060AEC0 (FUN_0060AEC0, Moho::CUnitTeleportTask::~CUnitTeleportTask)
     *
     * What it does:
     * Clears unit teleport state, publishes dispatch result, restores motion
     * collision processing, and unlinks beacon/target weak references.
     */
    ~CUnitTeleportTask() override;

    /**
     * Address: 0x0060AAC0 (FUN_0060AAC0, Moho::CUnitTeleportTask::operator new)
     *
     * What it does:
     * Allocates one teleport execution task and forwards constructor arguments
     * into in-place construction.
     */
    static CUnitTeleportTask* Create(
      CAiTarget* target,
      CCommandTask* parentTask,
      Unit* teleportBeaconUnit,
      const VTransform* sourceTransform
    );

    /**
     * Address: 0x0060AC00 (FUN_0060AC00, Moho::CUnitTeleportTask::TaskTick)
     *
     * What it does:
     * Runs teleport execution state transitions, validating beacon readiness,
     * reserving teleport placement viability, and dispatching script callback
     * payloads for teleport application.
     */
    int Execute() override;

    /**
     * Address: 0x0060D270 (FUN_0060D270, Moho::CUnitTeleportTask::MemberDeserialize)
     *
     * What it does:
     * Loads base `CCommandTask` state plus teleport target, beacon weak-link,
     * and source-orientation lanes from archive data.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0060D350 (FUN_0060D350, Moho::CUnitTeleportTask::MemberSerialize)
     *
     * What it does:
     * Writes base `CCommandTask` state plus teleport target, beacon weak-link,
     * and source-orientation lanes to archive data.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    CAiTarget mTarget;              // 0x30
    WeakPtr<Unit> mTeleportBeaconUnit; // 0x50
    Wm3::Quaternionf mOrientation;  // 0x58
  };

  static_assert(sizeof(CUnitTeleportTask) == 0x68, "CUnitTeleportTask size must be 0x68");
  static_assert(offsetof(CUnitTeleportTask, mTarget) == 0x30, "CUnitTeleportTask::mTarget offset must be 0x30");
  static_assert(
    offsetof(CUnitTeleportTask, mTeleportBeaconUnit) == 0x50,
    "CUnitTeleportTask::mTeleportBeaconUnit offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitTeleportTask, mOrientation) == 0x58,
    "CUnitTeleportTask::mOrientation offset must be 0x58"
  );

  /**
   * VFTABLE: 0x00E20348 (`??_7CUnitTeleportTaskSerializer@Moho@@6B@`)
   *
   * Demangled: Moho::CUnitTeleportTaskSerializer
   *
   * Confirmed via RTTI (`dumps/rtti_dump_all.hpp`) as a genuinely distinct,
   * single-inheritance derived class of `gpg::SerSaveLoadHelper<CUnitTeleportTask>`
   * (`HierarchyAttribs: 0x0`, `mdisp=0`) -- not a bare template instantiation.
   * IDA's data-xref scan independently shows two adjacent RTTI-backed vtables
   * sharing the same `Init()` install (see below), which is the ordinary MSVC
   * shape for a derived class that adds no members and overrides nothing: the
   * base subobject's own vtable pointer is written first, then immediately
   * overwritten by this derived level's vtable pointer -- so only the final
   * (derived) write survives as a visible store in the ctor.
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see
   * `gpg::SerSaveLoadHelper<T>`'s class-level comment in Reflection.h for the
   * template's general shape):
   *  - VFTABLE (own, most-derived): 0x00E20348
   *    (`??_7CUnitTeleportTaskSerializer@Moho@@6B@`)
   *  - VFTABLE (base `SerSaveLoadHelper<CUnitTeleportTask>`, adjacent; its
   *    write is elided in the ctor below since it is immediately
   *    overwritten): 0x00E20350
   *    (`??_7?$SerSaveLoadHelper@VCUnitTeleportTask@Moho@@@gpg@@6B@`)
   *  - ctor / compiler dynamic-initializer (`register_CUnitTeleportTaskSerializer`):
   *    0x00BD0650 (`__xc_a`-reachable; no dead zero-xref COMDAT duplicate found)
   *  - dtor / atexit target (ResetLinks()-shaped unlink-then-self-link body,
   *    no separately recovered mangled symbol): 0x00BF9C60
   *  - Init(): 0x0060BBA0 (shared vtable-slot-0 body for both vtables above;
   *    raw IDA decompile matches the template's generic `Init()` exactly --
   *    lazy `CUnitTeleportTask::sType` lookup, then the two `GPG_ASSERT`-
   *    guarded `serLoadFunc_`/`serSaveFunc_` assignments from `this+0x0C`/
   *    `this+0x10`)
   *  - Deserialize(): 0x0060AA10 (confirmed via raw asm: `objectPtr` in EAX,
   *    `archive` in EDI, tail-calls `CUnitTeleportTask::MemberDeserialize`'s
   *    custom-ABI body at 0x0060D270 -- matches the template's
   *    `reinterpret_cast<T*>(objectPtr)->MemberDeserialize(archive)` exactly)
   *  - Serialize(): 0x0060AA20 (same shape, tail-calls
   *    `CUnitTeleportTask::MemberSerialize` at 0x0060D350)
   *
   * The pre-existing free functions this instantiation supersedes
   * (`CUnitTeleportTaskSerializerLoad`/`CUnitTeleportTaskSerializerSave` and
   * their `g...Callback` volatile-pointer anchors, previously in
   * CUnitCallTeleport.cpp) mis-attributed addresses 0x0060AA10/0x0060AA20 to
   * a hand-written 2-argument shape; the real compiled signature there is the
   * template's 4-argument `RType::load_func_t`/`save_func_t`, confirmed by
   * the real ctor (0x00BD0650) storing those two addresses directly into
   * `mLoadCallback`/`mSaveCallback`.
   */
  class CUnitTeleportTaskSerializer final : public gpg::SerSaveLoadHelper<CUnitTeleportTask>
  {
  };

  /**
   * Address: 0x00BD0650 (FUN_00BD0650, register_CUnitTeleportTaskSerializer)
   *
   * What it does:
   * Forces this translation unit's global `CUnitTeleportTaskSerializer`
   * instance to link into the reflection bootstrap sequence. The
   * ctor/vtable-install/atexit-dtor-registration sequence this address
   * decompiles to is MSVC's own compiler-generated dynamic initializer for
   * that global, not hand-written source -- see `gpg::SerSaveLoadHelper<T>`
   * in Reflection.h.
   */
  void register_CUnitTeleportTaskSerializer();
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00603530 (FUN_00603530, gpg::RRef_CUnitCallTeleport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTeleport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTeleport(gpg::RRef* outRef, moho::CUnitCallTeleport* value);
} // namespace gpg
