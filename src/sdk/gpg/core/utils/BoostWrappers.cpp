#include "BoostWrappers.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <new>

#include <boost/ptr_container/exception.hpp>

namespace boost
{
  namespace
  {
    struct SpCountedBaseRuntimeView
    {
      void* vftable;
      volatile LONG useCount;
      volatile LONG weakCount;
    };

    static_assert(sizeof(SpCountedBaseRuntimeView) == 0x0C, "SpCountedBaseRuntimeView size must be 0x0C");

    [[nodiscard]] inline SpCountedBaseRuntimeView* AsRuntimeView(detail::sp_counted_base* const control) noexcept
    {
      return reinterpret_cast<SpCountedBaseRuntimeView*>(control);
    }

    template <typename OutPairT, typename SourcePairT>
    SharedCountPair* AssignWeakPairFromSharedCore(OutPairT* const outPair, const SourcePairT* const sourcePair) noexcept
    {
      outPair->px = sourcePair->px;

      detail::sp_counted_base* const sourceControl = sourcePair->pi;
      if (sourceControl != outPair->pi) {
        if (sourceControl != nullptr) {
          sourceControl->add_ref_copy();
        }
        if (outPair->pi != nullptr) {
          outPair->pi->weak_release();
        }
        outPair->pi = sourceControl;
      }

      return outPair;
    }

    template <typename OutPairT, typename SourcePairT>
    SharedCountPair* AssignSharedPairRetainCore(OutPairT* const outPair, const SourcePairT* const sourcePair) noexcept
    {
      outPair->px = sourcePair->px;
      outPair->pi = sourcePair->pi;
      if (outPair->pi != nullptr) {
        outPair->pi->add_ref_copy();
      }
      return outPair;
    }
  } // namespace

  /**
   * Address: 0x0043D940 (FUN_0043D940)
   * Address: 0x0043EED0 (FUN_0043EED0)
   * Address: 0x0043F2E0 (FUN_0043F2E0)
   * Address: 0x004438C0 (FUN_004438C0)
   *
   * What it does:
   * Copies one `(px,pi)` pair and rebinds control ownership by retaining the
   * incoming `pi` then weak-releasing the previous `pi`.
   */
  SharedCountPair* AssignWeakPairFromShared(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignWeakPairFromSharedCore(outPair, sourcePair);
  }

  /**
   * Address: 0x004414F0 (FUN_004414F0)
   * Address: 0x0043F7E0 (FUN_0043F7E0)
   * Address: 0x0043FCF0 (FUN_0043FCF0)
   *
   * What it does:
   * Executes the same weak-owner pair rebind as `AssignWeakPairFromShared`,
   * but receives arguments in `(source, destination)` order.
   */
  SharedCountPair* AssignWeakPairFromSharedReversed(
    const SharedCountPair* const sourcePair,
    SharedCountPair* const outPair
  ) noexcept
  {
    return AssignWeakPairFromSharedCore(outPair, sourcePair);
  }

  /**
   * Address: 0x0043DCF0 (FUN_0043DCF0)
 * Address: 0x0043F500 (FUN_0043F500)
 * Address: 0x0043F8E0 (FUN_0043F8E0)
 * Address: 0x0043FD90 (FUN_0043FD90)
 * Address: 0x00446A80 (FUN_00446A80)
 * Address: 0x004456E0 (FUN_004456E0)
 * Address: 0x00445860 (FUN_00445860)
 * Address: 0x004459A0 (FUN_004459A0)
 * Address: 0x004459C0 (FUN_004459C0)
 * Address: 0x004459E0 (FUN_004459E0)
 * Address: 0x00446150 (FUN_00446150)
 * Address: 0x004462F0 (FUN_004462F0)
 *
 * What it does:
 * Copies one `(px,pi)` pair and retains one shared control-block reference.
 */
  SharedCountPair* AssignSharedPairRetain(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignSharedPairRetainCore(outPair, sourcePair);
  }

  /**
   * Address: 0x0043E3B0 (FUN_0043E3B0)
   *
   * What it does:
   * Duplicate codegen lane of `AssignSharedPairRetain`.
   */
  SharedCountPair* AssignSharedPairRetainAlias(
    SharedCountPair* const outPair,
    const SharedCountPair* const sourcePair
  ) noexcept
  {
    return AssignSharedPairRetainCore(outPair, sourcePair);
  }

  /**
   * Address: 0x00446F30 (FUN_00446F30)
   *
   * What it does:
   * Attempts to acquire one shared-owner reference only when the current
   * use-count is non-zero.
   */
  bool SpCountedBaseAddRefLock(detail::sp_counted_base* const control) noexcept
  {
    return control != nullptr && control->add_ref_lock();
  }

  /**
   * Address: 0x00446F70 (FUN_00446F70)
   *
   * What it does:
   * Atomically increments one weak-count lane and returns the previous value.
   */
  std::int32_t SpCountedBaseWeakAddRef(detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return 0;
    }

    SpCountedBaseRuntimeView* const runtime = AsRuntimeView(control);
    return static_cast<std::int32_t>(InterlockedExchangeAdd(&runtime->weakCount, 1));
  }

  /**
   * Address: 0x00446F80 (FUN_00446F80)
   *
   * What it does:
   * Returns one shared-owner use-count lane.
   */
  std::int32_t SpCountedBaseUseCount(const detail::sp_counted_base* const control) noexcept
  {
    if (control == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(control->use_count());
  }

  /**
   * Address: 0x00446FB0 (FUN_00446FB0)
   *
   * What it does:
   * Increments one weak-count lane and returns the same control pointer.
   */
  detail::sp_counted_base* SpCountedBaseWeakAddRefReturn(detail::sp_counted_base* const control) noexcept
  {
    SpCountedBaseWeakAddRef(control);
    return control;
  }

  /**
   * Address: 0x00446FC0 (FUN_00446FC0)
   *
   * What it does:
   * Releases one weak-owner reference from one control-pointer slot.
   */
  detail::sp_counted_base* SpCountedBaseWeakReleaseFromSlot(detail::sp_counted_base** const controlSlot) noexcept
  {
    if (controlSlot == nullptr) {
      return nullptr;
    }

    detail::sp_counted_base* const control = *controlSlot;
    if (control != nullptr) {
      control->weak_release();
    }
    return control;
  }

  /**
   * Address: 0x00446FE0 (FUN_00446FE0)
   *
   * What it does:
   * Rebinds one weak control-pointer slot by weak-retaining the incoming
   * source control and weak-releasing the previously bound control.
   */
  detail::sp_counted_base** SpCountedBaseWeakAssignSlot(
    detail::sp_counted_base** const targetControlSlot,
    detail::sp_counted_base* const* const sourceControlSlot
  ) noexcept
  {
    if (targetControlSlot == nullptr) {
      return nullptr;
    }

    detail::sp_counted_base* const incomingControl =
      sourceControlSlot != nullptr ? *sourceControlSlot : nullptr;
    if (incomingControl != nullptr) {
      SpCountedBaseWeakAddRef(incomingControl);
    }

    if (*targetControlSlot != nullptr) {
      (*targetControlSlot)->weak_release();
    }

    *targetControlSlot = incomingControl;
    return targetControlSlot;
  }

  /**
   * Address: 0x00447020 (FUN_00447020)
   *
   * What it does:
   * Returns shared-owner use-count from one control-pointer slot, or zero when
   * no control block is present.
   */
  std::int32_t SpCountedBaseUseCountFromSlotOrZero(detail::sp_counted_base* const* const controlSlot) noexcept
  {
    if (controlSlot == nullptr || *controlSlot == nullptr) {
      return 0;
    }
    return SpCountedBaseUseCount(*controlSlot);
  }

  /**
   * Address: 0x00447030 (FUN_00447030)
   *
   * What it does:
   * Constructs/rebinds one weak control-pointer slot from one shared slot and
   * throws `boost::bad_weak_ptr` when the shared owner is absent or lock fails.
   */
  detail::sp_counted_base** SpCountedBaseWeakConstructFromSharedOrThrow(
    detail::sp_counted_base** const outWeakControlSlot,
    detail::sp_counted_base* const* const sourceSharedControlSlot
  )
  {
    if (outWeakControlSlot == nullptr) {
      throw boost::bad_weak_ptr();
    }

    detail::sp_counted_base* const sourceControl =
      sourceSharedControlSlot != nullptr ? *sourceSharedControlSlot : nullptr;
    *outWeakControlSlot = sourceControl;

    if (sourceControl == nullptr || !SpCountedBaseAddRefLock(sourceControl)) {
      throw boost::bad_weak_ptr();
    }

    return outWeakControlSlot;
  }

  /**
   * Address: 0x004470A0 (FUN_004470A0)
   *
   * What it does:
   * Constructs one `boost::bad_weak_ptr` exception object in caller-provided
   * storage.
   */
  boost::bad_weak_ptr* ConstructBadWeakPtr(boost::bad_weak_ptr* const outException)
  {
    return ::new (static_cast<void*>(outException)) boost::bad_weak_ptr();
  }

  /**
   * Address: 0x004470D0 (FUN_004470D0)
   *
   * What it does:
   * Runs one `boost::bad_weak_ptr` deleting-destructor lane controlled by
   * the low bit of `deleteFlag`.
   */
  boost::bad_weak_ptr* DestructBadWeakPtr(
    boost::bad_weak_ptr* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    exceptionObject->~bad_weak_ptr();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }

  /**
   * Address: 0x0049C140 (FUN_0049C140)
   *
   * What it does:
   * Copy-constructs one `boost::bad_pointer` exception into caller-provided
   * storage, preserving the legacy pointer-container exception chain.
   */
  boost::bad_pointer* ConstructBadPointerFromCopy(
    boost::bad_pointer* const outException,
    const boost::bad_pointer& sourceException
  )
  {
    return ::new (static_cast<void*>(outException)) boost::bad_pointer(sourceException);
  }

  /**
   * Address: 0x0049C170 (FUN_0049C170)
   *
   * What it does:
   * Copy-constructs one `boost::bad_ptr_container_operation` exception into
   * caller-provided storage.
   */
  boost::bad_ptr_container_operation* ConstructBadPtrContainerOperationFromCopy(
    boost::bad_ptr_container_operation* const outException,
    const boost::bad_ptr_container_operation& sourceException
  )
  {
    return ::new (static_cast<void*>(outException)) boost::bad_ptr_container_operation(sourceException);
  }

  namespace
  {
    struct BadPtrContainerOperationRuntimeView
    {
      void* vftable;
      std::uint32_t stdExceptionWhat;
      std::uint32_t stdExceptionDoFree;
      const char* message;
    };

    static_assert(
      offsetof(BadPtrContainerOperationRuntimeView, message) == 0x0C,
      "BadPtrContainerOperationRuntimeView::message offset must be 0x0C"
    );
  } // namespace

  /**
   * Address: 0x00491350 (FUN_00491350)
   *
   * What it does:
   * Returns the pointer-container exception message lane used by both
   * `boost::bad_ptr_container_operation` and `boost::bad_pointer`.
   */
  const char* GetBadPtrContainerMessage(const boost::bad_ptr_container_operation* const exceptionObject) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    const auto* const view = reinterpret_cast<const BadPtrContainerOperationRuntimeView*>(exceptionObject);
    return view->message;
  }

  /**
   * Address: 0x00491360 (FUN_00491360)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `boost::bad_ptr_container_operation`,
   * forwarding through `std::exception` teardown and optional operator delete.
   */
  boost::bad_ptr_container_operation* DestructBadPtrContainerOperation(
    boost::bad_ptr_container_operation* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    static_cast<std::exception*>(exceptionObject)->~exception();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }

  /**
   * Address: 0x004913B0 (FUN_004913B0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `boost::bad_pointer`,
   * forwarding through `std::exception` teardown and optional operator delete.
   */
  boost::bad_pointer* DestructBadPointer(
    boost::bad_pointer* const exceptionObject,
    const unsigned char deleteFlag
  ) noexcept
  {
    if (exceptionObject == nullptr) {
      return nullptr;
    }

    static_cast<std::exception*>(exceptionObject)->~exception();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(exceptionObject));
    }
    return exceptionObject;
  }
} // namespace boost
