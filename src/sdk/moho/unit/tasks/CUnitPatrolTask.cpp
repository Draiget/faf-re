#include "moho/unit/tasks/CUnitPatrolTask.h"
#include "moho/unit/tasks/CUnitPatrolTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitPatrolTaskType()
  {
    gpg::RType* type = moho::CUnitPatrolTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitPatrolTask));
      moho::CUnitPatrolTask::sType = type;
    }
    return type;
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
  gpg::RType* CUnitPatrolTask::sType = nullptr;

  /**
   * Address: 0x0061B0B0 (FUN_0061B0B0, Moho::CUnitPatrolTask::CUnitPatrolTask default ctor)
   *
   * What it does:
   * Default-constructs one patrol-task with zeroed payload storage.
   *
   * The binary body publishes the `CUnitPatrolTask` and embedded
   * `Listener<ECommandEvent>` / `Listener<EFormationdStatus>` vtables, self-
   * links the two listener intrusive nodes (offsets 56-60 / 72-76) and the
   * action-listener nodes near offset 200, then zero-fills the remaining
   * payload bytes. Those vtables and intrusive-list lanes are not modeled
   * in the current opaque `mPadding[0xF0]` class layout, so this body only
   * zero-initializes the padding. The truncated default-init is
   * SerConstruct-path-safe: the freshly-constructed object is immediately
   * fed to the archive `Read` chain which overwrites payload fields with
   * real data before any virtual call is dispatched. A future class-layout
   * recovery pass should expand `mPadding` into typed fields and restore
   * the listener/vtable setup.
   */
  CUnitPatrolTask::CUnitPatrolTask() noexcept
    : mPadding{}
  {
  }

  /**
   * Address: 0x0061C480 (FUN_0061C480, Moho::CUnitPatrolTask::operator new)
   *
   * What it does:
   * Allocates one patrol-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitPatrolTask* CUnitPatrolTask::Create(
    CCommandTask* const dispatchTask,
    const void* const goalPayload,
    const bool inFormation
  )
  {
    void* const storage = ::operator new(sizeof(CUnitPatrolTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitPatrolTask(dispatchTask, goalPayload, nullptr, inFormation);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x0061C4E0 (FUN_0061C4E0, Moho::CUnitPatrolTask::operator new `_0` overload)
   * Mangled: ??2CUnitPatrolTask@Moho@@QAE@@Z_0
   *
   * What it does:
   * Formation-instance allocation overload used by
   * `IAiCommandDispatchImpl::DispatchTask` when an existing
   * `IFormationInstance` must be bound to the new patrol task.
   */
  CUnitPatrolTask* CUnitPatrolTask::CreateWithFormation(
    CCommandTask* const dispatchTask,
    const void* const goalPayload,
    IFormationInstance* const formationInstance
  )
  {
    void* const storage = ::operator new(sizeof(CUnitPatrolTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitPatrolTask(dispatchTask, goalPayload, formationInstance, false);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  struct CUnitPatrolFormationListenerRuntimeView
  {
    std::uint8_t reserved00_3C[0x3D]{};
    std::uint8_t needsListenerResync = 0; // +0x3D
  };
  static_assert(
    offsetof(CUnitPatrolFormationListenerRuntimeView, needsListenerResync) == 0x3D,
    "CUnitPatrolFormationListenerRuntimeView::needsListenerResync offset must be 0x3D"
  );

  /**
   * Address: 0x0061C470 (FUN_0061C470)
   *
   * What it does:
   * Decrements one formation-listener countdown lane and marks listener-resync
   * state when this call consumes the last pending count.
   */
  [[maybe_unused]] int CUnitPatrolTaskConsumeFormationListenerCountdown(
    CUnitPatrolFormationListenerRuntimeView* const listenerRuntime,
    const int pendingCount
  ) noexcept
  {
    const int result = pendingCount - 1;
    if (pendingCount == 1 && listenerRuntime != nullptr) {
      listenerRuntime->needsListenerResync = 1;
    }
    return result;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061CCA0 (FUN_0061CCA0, gpg::RRef_CUnitPatrolTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitPatrolTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitPatrolTask(gpg::RRef* const outRef, moho::CUnitPatrolTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitPatrolTaskType());
    return outRef;
  }

  /**
   * Address: 0x0061CBF0 (FUN_0061CBF0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitPatrolTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitPatrolTaskRef(gpg::RRef* const outRef, moho::CUnitPatrolTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitPatrolTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitPatrolTaskSerializer{};

  /**
   * Address: 0x0061ADF0 (FUN_0061ADF0)
   *
   * What it does:
   * Unlinks `CUnitPatrolTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitPatrolTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitPatrolTaskSerializer);
  }

  /**
   * Address: 0x0061AE20 (FUN_0061AE20)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitPatrolTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitPatrolTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitPatrolTaskSerializer);
  }

  struct SerConstructHelperView
  {
    void* mVftable;
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(SerConstructHelperView, mConstructCallback) == 0x0C,
    "SerConstructHelperView::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerConstructHelperView, mDeleteCallback) == 0x10,
    "SerConstructHelperView::mDeleteCallback offset must be 0x10"
  );

  /**
   * Address: 0x0061C660 (FUN_0061C660, gpg::SerConstructHelper<Moho::CUnitPatrolTask>::Init)
   *
   * IDA signature:
   * void __thiscall sub_61C660(SerConstructHelperView *this);
   *
   * What it does:
   * Virtual-method body installed in both the
   * `Moho::CUnitPatrolTaskConstruct` and
   * `gpg::SerConstructHelper<Moho::CUnitPatrolTask>` vtables. Lazily resolves
   * the `CUnitPatrolTask` reflection descriptor, asserts the construct
   * callback slot is empty, and publishes this helper's construct/delete
   * callbacks to the descriptor.
   *
   * Notes:
   * Mirrors the binary's single `!type->mSerConstructFunc` assert (no separate
   * delete-slot assert); intentionally diverges from the broader
   * `RegisterConstructCallbacks` helper used in other subsystems.
   */
  [[maybe_unused]] gpg::RType::construct_func_t InitCUnitPatrolTaskConstructHelper(
    const SerConstructHelperView& helper
  )
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = CachedCUnitPatrolTaskType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = helper.mConstructCallback;
    type->deleteFunc_ = helper.mDeleteCallback;
    return helper.mConstructCallback;
  }

  /**
   * Address: 0x0061AD10 (FUN_0061AD10, Moho::CUnitPatrolTaskConstruct::Construct)
   *
   * What it does:
   * Allocates one `CUnitPatrolTask` instance via `operator new(0xF0u)`,
   * default-constructs it, wraps the result in a typed `gpg::RRef_CUnitPatrolTask`,
   * and publishes the payload as an unowned construct result through
   * `gpg::SerConstructResult::SetUnowned`. Invoked by the reflection
   * subsystem during archive replay when a patrol-task instance must be
   * materialized before its fields are streamed in.
   */
  void ConstructCUnitPatrolTaskSerializerCallback(void* const constructResultStorage)
  {
    auto* const result = static_cast<gpg::SerConstructResult*>(constructResultStorage);
    if (result == nullptr) {
      return;
    }

    auto* const task = new (std::nothrow) moho::CUnitPatrolTask{};
    gpg::RRef taskRef{};
    (void)gpg::RRef_CUnitPatrolTask(&taskRef, task);
    result->SetUnowned(taskRef, 0u);
  }

  /**
   * Address: 0x0061ADC0 (FUN_0061ADC0, Moho::CUnitPatrolTaskConstruct::Deconstruct)
   *
   * What it does:
   * Releases one heap-owned `CUnitPatrolTask` instance via the standard
   * scalar `delete` expression; mirrors the binary's reflection-side
   * destructor lane that fires when the construct result is discarded.
   */
  void DestructCUnitPatrolTaskSerializerCallback(void* const taskStorage)
  {
    delete static_cast<moho::CUnitPatrolTask*>(taskStorage);
  }

  /**
   * Static-init driver that installs `ConstructCUnitPatrolTaskSerializerCallback`
   * and `DestructCUnitPatrolTaskSerializerCallback` into the cached
   * `CUnitPatrolTask` reflection descriptor's lifecycle slots. The binary
   * registers the equivalent helper via a static-init-time
   * `SerConstructHelper<CUnitPatrolTask>` global; in modern source the same
   * effect is achieved by a file-scope dummy whose ctor invokes
   * `InitCUnitPatrolTaskConstructHelper` once at load time. This is the
   * source-level invocation chain that makes
   * `InitCUnitPatrolTaskConstructHelper` (and the inner pair of
   * Construct/Destruct callbacks) non-orphan.
   */
  struct CUnitPatrolTaskConstructHelperRegistrar
  {
    CUnitPatrolTaskConstructHelperRegistrar() noexcept
    {
      // Ensure the CUnitPatrolTask reflection descriptor is pre-registered
      // before we publish lifecycle callbacks into it. The binary defers
      // this through its `SerConstructHelper<CUnitPatrolTask>` global ctor
      // chain; in the modern build we call `preregister_CUnitPatrolTaskTypeInfo`
      // explicitly to make the order TU-static-init-safe.
      (void)moho::preregister_CUnitPatrolTaskTypeInfo();

      SerConstructHelperView helper{};
      helper.mVftable = nullptr;
      helper.mNext = nullptr;
      helper.mPrev = nullptr;
      helper.mConstructCallback = &ConstructCUnitPatrolTaskSerializerCallback;
      helper.mDeleteCallback = &DestructCUnitPatrolTaskSerializerCallback;
      (void)InitCUnitPatrolTaskConstructHelper(helper);
    }
  };

  [[maybe_unused]] const CUnitPatrolTaskConstructHelperRegistrar gCUnitPatrolTaskConstructHelperRegistrar{};
} // namespace
