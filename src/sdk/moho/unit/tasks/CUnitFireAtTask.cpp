#include "moho/unit/tasks/CUnitFireAtTask.h"

#include <cmath>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/math/Vector3f.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

namespace
{
  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] bool MatchesManualFireProfile(const moho::RUnitBlueprintWeapon* const weaponBlueprint, const std::int32_t isNuclearMode)
  {
    if (weaponBlueprint == nullptr) {
      return false;
    }

    if (weaponBlueprint->ManualFire == 0u || weaponBlueprint->OverChargeWeapon != 0u) {
      return false;
    }

    const bool isNukeWeapon = weaponBlueprint->NukeWeapon != 0u;
    if (isNuclearMode == 1) {
      return isNukeWeapon;
    }

    if (isNuclearMode == 0) {
      return !isNukeWeapon;
    }

    return false;
  }

  [[nodiscard]] gpg::RType* CachedCUnitFireAtTaskType()
  {
    gpg::RType* type = moho::CUnitFireAtTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFireAtTask));
      moho::CUnitFireAtTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = moho::CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiTarget));
      moho::CAiTarget::sType = type;
    }
    return type;
  }

  // Mirrors the file-local `CachedESiloTypeType()` helper already established
  // in CAiSiloBuildImplTypeInfo.cpp: `ESiloType` is an enum, so it cannot
  // host its own `sType` static member the way class/struct reflected types
  // do -- IDA's decompiler displays the underlying global as
  // `Moho::ESiloType::sType`, but that is a plain per-TU cache, not a member.
  [[nodiscard]] gpg::RType* CachedESiloTypeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ESiloType));
    }
    return cached;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitFireAtTask::sType = nullptr;

  /**
   * Address: 0x0060B800 (FUN_0060B800, ??1CUnitFireAtTask@Moho@@QAE@@Z)
   * Address: 0x0060B240 (FUN_0060B240, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   * Mangled: ??1CUnitFireAtTask@Moho@@QAE@@Z
   *
   * What it does:
   * Clears the owner-unit busy bit, unlinks the embedded target weak node,
   * and then falls through to inherited command-task teardown.
   */
  CUnitFireAtTask::~CUnitFireAtTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Busy));
    }

    mTarget.targetEntity.UnlinkFromOwnerChain();
    mTarget.targetEntity.ClearLinkState();
  }

  /**
   * Address: 0x0060B1B0 (FUN_0060B1B0, ??2CUnitFireAtTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Allocates one fire-at task object and forwards constructor arguments into
   * in-place task construction.
   */
  CUnitFireAtTask* CUnitFireAtTask::Create(
    IAiCommandDispatchImpl* const dispatchTask,
    CAiTarget* const target,
    const std::int32_t isNuclear
  )
  {
    void* const storage = ::operator new(sizeof(CUnitFireAtTask), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CUnitFireAtTask(static_cast<CCommandTask*>(dispatchTask), target, isNuclear);
  }

  /**
   * Address: 0x0060B260 (FUN_0060B260, ??0CUnitFireAtTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one fire-at task from dispatch context and picks the first
   * matching manual-fire weapon lane for the requested nuke/non-nuke mode.
   */
  CUnitFireAtTask::CUnitFireAtTask(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    const std::int32_t isNuclear
  )
    : CCommandTask(dispatchTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(dispatchTask))
    , mTarget()
    , mWeapon(nullptr)
    , mIsNuclear(isNuclear)
  {
    if (target != nullptr) {
      mTarget = *target;
    }

    Unit* const unit = mUnit;
    CAiAttackerImpl* const attacker = (unit != nullptr) ? unit->AiAttacker : nullptr;
    if (attacker == nullptr) {
      return;
    }

    const int weaponCount = attacker->GetWeaponCount();
    for (int weaponIndex = 0; weaponIndex < weaponCount; ++weaponIndex) {
      UnitWeapon* const weapon = attacker->GetWeapon(weaponIndex);
      if (weapon == nullptr) {
        continue;
      }

      if (!MatchesManualFireProfile(weapon->mWeaponBlueprint, mIsNuclear)) {
        continue;
      }

      mWeapon = weapon;
      break;
    }
  }

  /**
   * Address: 0x0060B380 (FUN_0060B380, Moho::CUnitFireAtTask::TaskTick)
   *
   * IDA signature:
   * int __thiscall Moho::CUnitFireAtTask::TaskTick(Moho::CUnitFireAtTask *this);
   *
   * What it does:
   * Drives one manual-fire order: closes to (or backs off to) the chosen
   * weapon's firing band, waits for the silo to hold a round, fires once, and
   * ends when the unit stops being busy.
   */
  int CUnitFireAtTask::Execute()
  {
    UnitWeapon* const weapon = mWeapon;
    if (!weapon || weapon->mEnabled == 0u) {
      // No usable weapon was matched at construction: report the order as
      // rejected rather than sitting on it.
      *mDispatchResult = static_cast<EAiResult>(3);
      return -1;
    }

    Unit* const unit = mUnit;
    IAiNavigator* const navigator = unit->AiNavigator;

    // A negative per-instance radius means "inherit the blueprint's".
    float minRadius = weapon->mAttributes.mMinRadius;
    if (minRadius < 0.0f) {
      minRadius = weapon->mAttributes.mBlueprint->MinRadius;
    }
    float maxRadius = weapon->mAttributes.mMaxRadius;
    if (maxRadius < 0.0f) {
      maxRadius = weapon->mAttributes.mBlueprint->MaxRadius;
    }

    // Range is measured on the ground plane only; height difference does not
    // count against a weapon's firing band.
    const Wm3::Vec3f targetPos = mTarget.GetTargetPosGun(false);
    const Wm3::Vec3f unitPos = unit->GetPosition();
    const float groundDistance = std::sqrt(
      ((unitPos.x - targetPos.x) * (unitPos.x - targetPos.x))
      + ((unitPos.z - targetPos.z) * (unitPos.z - targetPos.z))
    );

    switch (mTaskState) {
    case TASKSTATE_Preparing: {
      if (minRadius > groundDistance) {
        // Too close to fire. Immobile units simply cannot comply.
        if (!unit->IsMobile() || !navigator) {
          return -1;
        }

        if (navigator->GetStatus() == AINAVSTATUS_Idle) {
          // Back off along the target-to-unit direction to 110% of the
          // minimum range, so arriving inside the band again is unlikely.
          const Wm3::Vec3f gunPos = mTarget.GetTargetPosGun(false);
          const Wm3::Vec3f here = unit->GetPosition();
          Wm3::Vec3f backOff{here.x - gunPos.x, here.y - gunPos.y, here.z - gunPos.z};
          (void)VecSetLength(&backOff, minRadius * 1.1f);

          const Wm3::Vec3f anchor = mTarget.GetTargetPosGun(false);
          Wm3::Vec3f destination{anchor.x + backOff.x, anchor.y + backOff.y, anchor.z + backOff.z};

          gpg::Rect2f skirt{};
          (void)unit->PrepareMove(0, &destination, &skirt, unit->ArmyRef->UseWholeMap());
          navigator->SetGoal(SNavGoal{unit->GetFootprint().ToCellPos(destination)});
        }
        return 1;
      }

      if (groundDistance <= maxRadius) {
        // In the band: stop moving and make sure a round is loaded.
        if (unit->IsMobile() && navigator) {
          navigator->AbortMove();
        }

        if (!mWeapon->CheckSilo()) {
          CAiSiloBuildImpl* const silo = unit->AiSiloBuild;
          if (!silo) {
            return -1;
          }

          const auto siloType = static_cast<ESiloType>(mIsNuclear);
          if (!silo->SiloIsBusy(siloType)) {
            if (!silo->SiloIsFull(siloType)) {
              // Nothing loaded and nothing building: queue a round, and give
              // up if the silo will not take the order.
              if (!unit->AiSiloBuild->SiloAddBuild(siloType)) {
                return -1;
              }
            } else {
              // Full but CheckSilo said no: fall through to firing.
              mTaskState = TASKSTATE_Starting;
              return 0;
            }
          }

          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        mTaskState = TASKSTATE_Starting;
        return 0;
      }

      // Out of range: close on the target.
      if (!unit->IsMobile() || !navigator) {
        return -1;
      }

      if (navigator->GetStatus() == AINAVSTATUS_Idle) {
        Wm3::Vec3f destination = mTarget.GetTargetPosGun(false);
        gpg::Rect2f skirt{};
        (void)unit->PrepareMove(0, &destination, &skirt, unit->ArmyRef->UseWholeMap());
        navigator->SetGoal(SNavGoal{unit->GetFootprint().ToCellPos(destination)});
      }
      return 1;
    }

    case TASKSTATE_Waiting:
      // Waiting on the silo to finish building the round.
      if (mWeapon->CheckSilo()) {
        mTaskState = NextTaskState(mTaskState);
      }
      return 10;

    case TASKSTATE_Starting:
      // Fire once, as soon as the unit is free.
      if (!unit->IsUnitState(UNITSTATE_Busy)) {
        if (mIsNuclear == 1) {
          (void)unit->RunScript("OnNukeLaunched");
        }
        mWeapon->SetTarget(&mTarget);
        mWeapon->Fire();
        mTaskState = NextTaskState(mTaskState);
      }
      return 3;

    case TASKSTATE_Processing:
      // The shot marks the unit busy; that transition ends the firing step.
      if (unit->IsUnitState(UNITSTATE_Busy)) {
        mTaskState = NextTaskState(mTaskState);
      }
      return 3;

    case TASKSTATE_Complete:
      return unit->IsUnitState(UNITSTATE_Busy) ? 3 : -1;

    default:
      gpg::HandleAssertFailure(
        "Reached the supposably unreachable.",
        910,
        "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitCommands.cpp"
      );
      return -1;
    }
  }

  /**
   * Address: 0x0060D430 (FUN_0060D430, Moho::CUnitFireAtTask::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall sub_60D430(Moho::CUnitFireAtTask *this@<ecx>, gpg::ReadArchive *archive@<eax>);
   *
   * What it does:
   * Loads fire-at-task state from an archive in binary lane order:
   *   1. base `CCommandTask` subobject (by reflected type).
   *   2. `mDispatch` at +0x30, read as a tracked `CCommandTask*` pointer
   *      (`IAiCommandDispatchImpl` derives from `CCommandTask`).
   *   3. `mTarget` at +0x34 (by reflected type).
   *   4. `mWeapon` at +0x54, read as a tracked pointer.
   *   5. `mIsNuclear` at +0x58, read through the `ESiloType` reflected type.
   */
  void CUnitFireAtTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    CCommandTask* dispatchAsCommandTask = nullptr;
    archive->ReadPointer_CCommandTask(&dispatchAsCommandTask, &ownerRef);
    mDispatch = static_cast<IAiCommandDispatchImpl*>(dispatchAsCommandTask);

    archive->Read(CachedCAiTargetType(), &mTarget, ownerRef);
    archive->ReadPointer_UnitWeapon(&mWeapon, &ownerRef);
    archive->Read(CachedESiloTypeType(), &mIsNuclear, ownerRef);
  }

  /**
   * Address: 0x0060D510 (FUN_0060D510, Moho::CUnitFireAtTask::MemberSerialize)
   *
   * IDA signature:
   * void __usercall sub_60D510(Moho::CUnitFireAtTask *this@<eax>, gpg::WriteArchive *archive@<edi>);
   *
   * What it does:
   * Writes fire-at-task state to an archive in the same binary lane order as
   * `MemberDeserialize`: base `CCommandTask` subobject, `mDispatch` (as an
   * unowned tracked `CCommandTask*` pointer), `mTarget` (by reflected type),
   * `mWeapon` (as an unowned tracked pointer), then `mIsNuclear` (through the
   * `ESiloType` reflected type).
   */
  void CUnitFireAtTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef dispatchRef{};
    (void)gpg::RRef_CCommandTask(&dispatchRef, static_cast<CCommandTask*>(mDispatch));
    gpg::WriteRawPointer(archive, dispatchRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedCAiTargetType(), &mTarget, ownerRef);

    gpg::RRef weaponRef{};
    (void)gpg::RRef_UnitWeapon(&weaponRef, mWeapon);
    gpg::WriteRawPointer(archive, weaponRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedESiloTypeType(), &mIsNuclear, ownerRef);
  }

  namespace
  {
    // Address: 0x00BD06B0 (FUN_00BD06B0, register_CUnitFireAtTaskSerializer)
    // -- MSVC's own compiler-generated dynamic initializer for this global
    // runs the real `gpg::SerSaveLoadHelper<CUnitFireAtTask>` ctor chain
    // (self-links into `sNewHelpers`, binds `mLoadCallback`/`mSaveCallback`
    // to the template's `Deserialize`/`Serialize` -- the real compiled
    // bodies at 0x0060B100/0x0060B110, which tail-call
    // `CUnitFireAtTask::MemberDeserialize`/`MemberSerialize` above -- then
    // installs first the base template's vtable, then this derived class's
    // own; the intermediate base-vtable write is elided by the compiler
    // since it is immediately overwritten) and registers the atexit dtor
    // (0x00BF9CF0, ResetLinks()-shaped unlink-then-self-link body).
    // `FUN_0060B150` and `FUN_0060B180` are duplicate-emission twins of that
    // exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
    // addresses); they have no distinct source-level body of their own.
    CUnitFireAtTaskSerializer gCUnitFireAtTaskSerializer;

    struct CUnitFireAtTaskSerializerBootstrap
    {
      CUnitFireAtTaskSerializerBootstrap()
      {
        register_CUnitFireAtTaskSerializer();
      }
    };

    CUnitFireAtTaskSerializerBootstrap gCUnitFireAtTaskSerializerBootstrap;
  } // namespace

  /**
   * Address: 0x00BD06B0 (FUN_00BD06B0, register_CUnitFireAtTaskSerializer)
   *
   * What it does:
   * Forces this translation unit's global `CUnitFireAtTaskSerializer`
   * instance to link into the reflection bootstrap sequence. See the Doxygen
   * comment on the declaration (CUnitFireAtTask.h) and on
   * `gCUnitFireAtTaskSerializer` above for why this function's body has no
   * field-setting logic of its own.
   */
  void register_CUnitFireAtTaskSerializer()
  {
    (void)gCUnitFireAtTaskSerializer;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0060CE10 (FUN_0060CE10, gpg::RRef_CUnitFireAtTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFireAtTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFireAtTask(gpg::RRef* const outRef, moho::CUnitFireAtTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitFireAtTaskType());
    return outRef;
  }

  /**
   * Address: 0x0060C800 (FUN_0060C800)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFireAtTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFireAtTaskRef(gpg::RRef* const outRef, moho::CUnitFireAtTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitFireAtTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
