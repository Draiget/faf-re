#include "moho/unit/tasks/CUnitGetBuiltTask.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    constexpr const char* kAiUnitCommandsPath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitCommands.cpp";
  }

  /**
   * Address: 0x0060A4D0 (FUN_0060A4D0, Moho::CUnitGetBuiltTask::TaskTick)
   *
   * What it does:
   * Tracks build completion for the owner unit and completes when the unit is
   * mobile and attached to a parent transporter/entity.
   */
  int CUnitGetBuiltTask::Execute()
  {
    if (mTaskState == TASKSTATE_Preparing) {
      if (mUnit->IsBeingBuilt()) {
        return 1;
      }

      if (!mUnit->IsMobile()) {
        return -1;
      }

      mTaskState = TASKSTATE_Waiting;
    } else if (mTaskState != TASKSTATE_Waiting) {
      gpg::HandleAssertFailure("Reached the supposably unreachable.", 557, kAiUnitCommandsPath);
    }

    return (mUnit->mAttachInfo.GetAttachTargetEntity() != nullptr) ? 1 : -1;
  }

  /**
   * Address: 0x0060A550 (FUN_0060A550, Moho::CUnitGetBuiltTask::CUnitGetBuiltTask)
   *
   * What it does:
   * Runs the detached `CCommandTask` base constructor and leaves the derived
   * task with its own vftable installed by the compiler.
   */
  CUnitGetBuiltTask::CUnitGetBuiltTask()
    : CCommandTask()
  {}

  /**
   * Address: 0x0060A810 (FUN_0060A810, Moho::CUnitGetBuildTask::CUnitGetBuildTask)
   *
   * What it does:
   * Constructs one built-task child lane from parent command-dispatch context.
   */
  CUnitGetBuiltTask::CUnitGetBuiltTask(CCommandTask* const parent)
    : CCommandTask(parent)
  {}

  /**
   * Address: 0x0060A570 (FUN_0060A570, scalar deleting destructor thunk)
   *
   * What it does:
   * Runs `CCommandTask` teardown for the built-task lane; there is no extra
   * derived state to release.
   */
  CUnitGetBuiltTask::~CUnitGetBuiltTask() = default;
} // namespace moho

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitGetBuiltTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitGetBuiltTask));
    }
    return cached;
  }

  /**
   * VFTABLE: 0x00E202FC (`??_7CUnitGetBuiltTaskSerializer@Moho@@6B@`)
   *
   * Demangled: gpg::SerSaveLoadHelper<class moho::CUnitGetBuiltTask> (IDA
   * infers `Moho::CUnitGetBuiltTaskSerializer`). The binary global is 0x14
   * bytes (vtable + inherited link pair + load/save callback lanes),
   * matching every other `SerHelperBase`-derived serializer in this
   * codebase.
   */
  struct CUnitGetBuiltTaskSerializer : public gpg::SerHelperBase
  {
    /**
     * Address: 0x0060BAE0 (FUN_0060BAE0, Moho::CUnitGetBuiltTaskSerializer::Init,
     * vtable slot 0)
     *
     * What it does:
     * Lazily resolves `CUnitGetBuiltTask` RTTI and installs this helper's
     * load/save callback pair onto the reflected type descriptor.
     */
    void Init() override;

    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(CUnitGetBuiltTaskSerializer, mSerLoadFunc) == 0x0C,
    "CUnitGetBuiltTaskSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitGetBuiltTaskSerializer, mSerSaveFunc) == 0x10,
    "CUnitGetBuiltTaskSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitGetBuiltTaskSerializer) == 0x14,
    "CUnitGetBuiltTaskSerializer size must be 0x14"
  );

  void CUnitGetBuiltTaskSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitGetBuiltTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  CUnitGetBuiltTaskSerializer gCUnitGetBuiltTaskSerializer{};

  /**
   * Address: 0x0060A7B0 (FUN_0060A7B0)
   *
   * What it does:
   * Unlinks `CUnitGetBuiltTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  void UnlinkCUnitGetBuiltTaskSerializerNodePrimary()
  {
    gCUnitGetBuiltTaskSerializer.ResetLinks();
  }

  /**
   * Address: 0x0060A7E0 (FUN_0060A7E0)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitGetBuiltTaskSerializer` helper storage. No in-binary caller was
   * recovered for this address (distinct from the primary lane above); kept
   * as a thin address-anchored wrapper rather than dropped.
   */
  [[maybe_unused]] void UnlinkCUnitGetBuiltTaskSerializerNodeSecondary()
  {
    gCUnitGetBuiltTaskSerializer.ResetLinks();
  }

  // CUnitGetBuiltTask adds no fields beyond CCommandTask (see the trivial
  // forwarding constructors above), so the binary serializes it purely as
  // its CCommandTask base -- both facades below read/write through the
  // cached CCommandTask reflection type rather than a per-class member
  // Deserialize/Serialize.
  [[nodiscard]] gpg::RType* CachedCCommandTaskTypeForGetBuiltTask()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0060A700 (FUN_0060A700, Moho::CUnitGetBuiltTaskSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `CUnitGetBuiltTask`. Reads the
   * object's `CCommandTask` base lane directly through the cached
   * `CCommandTask` reflection type (the derived class adds no fields);
   * `version` is unused by the binary tail call.
   */
  void DeserializeCUnitGetBuiltTaskSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(
      CachedCCommandTaskTypeForGetBuiltTask(),
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(objectPtr)),
      owner
    );
  }

  /**
   * Address: 0x0060A740 (FUN_0060A740, Moho::CUnitGetBuiltTaskSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `CUnitGetBuiltTask`. Writes the
   * object's `CCommandTask` base lane directly through the cached
   * `CCommandTask` reflection type (the derived class adds no fields);
   * `version` is unused by the binary tail call.
   */
  void SerializeCUnitGetBuiltTaskSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(
      CachedCCommandTaskTypeForGetBuiltTask(),
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(objectPtr)),
      owner
    );
  }

  /**
   * Address: 0x00BF9BD0 (FUN_00BF9BD0, Moho::CUnitGetBuiltTaskSerializer::~CUnitGetBuiltTaskSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `CUnitGetBuiltTaskSerializer` helper
   * node, matching the sibling unlink lanes used across other serializer
   * registrars.
   */
  void cleanup_CUnitGetBuiltTaskSerializer_atexit()
  {
    UnlinkCUnitGetBuiltTaskSerializerNodePrimary();
  }

  /**
   * Address: 0x00BD05F0 (FUN_00BD05F0, register_CUnitGetBuiltTaskSerializer,
   * dynamic initializer for the global `CUnitGetBuiltTaskSerializer`
   * singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
   * splices it into the process-global `sNewHelpers` pending list; this was
   * previously modeled as a manual self-link here), binds the load/save
   * callback lanes, and installs process-exit cleanup via `atexit`.
   */
  void register_CUnitGetBuiltTaskSerializer()
  {
    gCUnitGetBuiltTaskSerializer.mSerLoadFunc = &DeserializeCUnitGetBuiltTaskSerializerCallback;
    gCUnitGetBuiltTaskSerializer.mSerSaveFunc = &SerializeCUnitGetBuiltTaskSerializerCallback;
    (void)std::atexit(&cleanup_CUnitGetBuiltTaskSerializer_atexit);
  }

  struct CUnitGetBuiltTaskSerializerStartupBootstrap
  {
    CUnitGetBuiltTaskSerializerStartupBootstrap()
    {
      register_CUnitGetBuiltTaskSerializer();
    }
  };

  [[maybe_unused]] CUnitGetBuiltTaskSerializerStartupBootstrap gCUnitGetBuiltTaskSerializerStartupBootstrap;
} // namespace
