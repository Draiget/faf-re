#pragma once

#include <new>
#include <type_traits>

/**
 * Storage owner for the engine's static `RType` descriptor singletons.
 *
 * Every `<T>TypeInfo` descriptor in the binary lives in a fixed `.data` slot
 * (e.g. `stru_10B1EB8` for `CUnitLoadUnitsTypeInfo`) that a CRT static
 * initializer constructs in place and never destroys: the descriptor must
 * outlive every consumer that resolves it through `gpg::LookupRType`, so it
 * deliberately has no atexit teardown. Reproducing that lifetime in C++
 * requires raw storage plus placement new, which is why the mechanics live
 * here instead of being restated in each descriptor's translation unit.
 *
 * This type is the single owner of that unsafe knowledge. Descriptor files
 * should declare one `StaticTypeInfoStorage<T>` at namespace scope and call
 * `Ensure()`; they must not open-code `alignas` byte arrays, placement new,
 * or the pointer cast out of those bytes.
 *
 * Not thread-safe by design: the binary constructs these from the single-
 * threaded CRT initializer walk before any consumer runs, and adding a guard
 * would introduce a lock the original never took.
 */
namespace gpg
{
  template <class TTypeInfo>
  class StaticTypeInfoStorage
  {
  public:
    /**
     * Constructs the descriptor on first call and returns it. Later calls
     * return the same object, which is what makes it safe for both the
     * `.CRT$XCL` provider hook and any lazily-running bootstrap object to
     * call the same provider function.
     */
    [[nodiscard]] TTypeInfo& Ensure() noexcept
    {
      if (!mConstructed) {
        ::new (static_cast<void*>(mBytes)) TTypeInfo();
        mConstructed = true;
      }

      return Ref();
    }

    /**
     * Returns the descriptor without constructing it. Callers must have
     * already gone through `Ensure()`; reading unconstructed storage is
     * undefined behavior.
     */
    [[nodiscard]] TTypeInfo& Ref() noexcept
    {
      // The bytes hold a live TTypeInfo once Ensure() has run; this is the
      // one place in the codebase allowed to reconstitute the pointer.
      return *std::launder(reinterpret_cast<TTypeInfo*>(mBytes));
    }

    [[nodiscard]] bool IsConstructed() const noexcept
    {
      return mConstructed;
    }

  private:
    alignas(TTypeInfo) unsigned char mBytes[sizeof(TTypeInfo)]{};
    bool mConstructed{false};
  };
} // namespace gpg
