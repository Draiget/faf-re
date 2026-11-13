#pragma once
#include <memory>

namespace gpg::core
{
  /**
   * Supersedes the binary's `boost::thread_specific_ptr<T>` construction
   * machinery for `LogContext::tss` (`ContextStack` in the original boost
   * naming): `boost::detail::tss_adapter_ContextStack::tss_adapter_ContextStack`
   * (0x00936B30), `boost::function1_ContextStack` (0x00937950, the cleanup-
   * function wrapper boost's tss_adapter stores), and `boost::
   * thread_specific_ptr_ContextStack::thread_specific_ptr_ContextStack`
   * (0x009379F0) are all real, compiled-in boost template instantiations
   * for this exact slot, but none has a corresponding call here: a C++
   * `thread_local` slot replaces boost's TLS-slot allocation, keeping its
   * behaviour (a value per thread, deleted when the thread ends). `TssPtr`'s own
   * trivial `constexpr` default constructor is the modern equivalent of
   * what those three addresses did in the original binary; the boost
   * cleanup callback they registered is superseded by `ThreadStateTssDeleter`
   * (`Logging.h`), already cited against the matching runtime addresses
   * there (0x00936CC0/0x00936FD0).
   * Address: 0x00935DB0 (FUN_00935DB0 -- `boost::detail::function::void_function_invoker1<void (*)(void*), void,
   * void*>::invoke` for that `boost::function1` cleanup wrapper: loads the stored function pointer and calls it with
   * the one argument; reached through the wrapper's vtable, no direct callers. Formerly `InvokeUnaryCdeclThunkRuntime`
   * in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.) Address: 0x00936180 (FUN_00936180 -- the same
   * `boost::function1` wrapper's functor manager (clone / destroy / type query of the stored function pointer); caller
   * 0x00936B30 (`tss_adapter` constructor). Was tagged external_dependency; it is an engine-instantiated boost template
   * like its siblings above.)
   *
   * Each `TssPtr<T, Deleter>` type has one slot per thread, so the engine keeps one object per type (it has one,
   * `LogContext::tss`). The slot is allocated once per thread and never freed: `LogContext`'s destructor runs from
   * an atexit handler after the main thread's `thread_local` destructors and still reads it, and finds it empty.
   * When a thread ends, its value is deleted with `Deleter`.
   */
  template <class T, class Deleter = std::default_delete<T>>
  class TssPtr
  {
  public:
    using element_type = T;
    using deleter_type = Deleter;

    constexpr TssPtr() noexcept = default;

    /** Deletes the current thread's value, if any. */
    ~TssPtr() noexcept
    {
      reset(nullptr);
    }

    TssPtr(const TssPtr&) = delete;
    TssPtr& operator=(const TssPtr&) = delete;

    /** The current thread's value (may be null). */
    T* get() const noexcept
    {
      return Slot();
    }

    /** Replaces the current thread's value and deletes the previous one with `Deleter`. */
    void reset(
      T* const value = nullptr
    ) noexcept
    {
      T*& slot = Slot();
      T* const previous = slot;
      slot = value;
      if (previous != nullptr && previous != value) {
        Deleter{}(previous);
      }
    }

    T& operator*() const
    {
      return *get();
    }
    T* operator->() const
    {
      return get();
    }

  private:
    /** The current thread's slot; never freed, see the class comment. */
    static T*& Storage() noexcept
    {
      static thread_local T** const slot = new T*(nullptr);
      return *slot;
    }

    /** Deletes the thread's value when the thread ends; the slot stays, empty. */
    struct ThreadExit
    {
      ~ThreadExit() noexcept
      {
        T*& slot = Storage();
        T* const value = slot;
        slot = nullptr;
        if (value != nullptr) {
          Deleter{}(value);
        }
      }
    };

    static T*& Slot() noexcept
    {
      static thread_local ThreadExit threadExit;
      (void)threadExit;
      return Storage();
    }
  };
} // namespace gpg::core
