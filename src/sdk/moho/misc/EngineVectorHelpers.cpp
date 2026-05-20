#include "moho/misc/EngineVectorHelpers.h"

#include <new>

#include "moho/unit/core/Unit.h"

namespace moho
{
  /**
   * Address: 0x00560A90 (FUN_00560A90, msvc8::vector<unsigned int>::vector(const vector&))
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated
   * `msvc8::vector<std::uint32_t>` copy operation. The source-level invocation
   * here (`destination = source`) forces the compiler to emit the templated
   * copy-assignment/copy-ctor body out-of-line for `T = std::uint32_t`,
   * preserving the 2007 MSVC8 per-`T` symbol shape.
   *
   * Callers default-construct the destination then invoke this helper to
   * deep-copy contents from `source`.
   */
  void AssignCopyVectorUint32(msvc8::vector<std::uint32_t>& destination,
                              const msvc8::vector<std::uint32_t>& source)
  {
    destination = source;
  }

  /**
   * Address: 0x0057E550 (FUN_0057E550, func_FastvecUnitToStdVec)
   *
   * What it does:
   * Per-T named helper that captures the engine-instantiated conversion body
   * `gpg::fastvector<Moho::Unit*>` → `std::vector<Moho::Unit*>`. Initializes
   * the destination triplet to empty, then if the source range contains
   * elements, reserves capacity and bulk-inserts the source pointers in order.
   */
  void CopyFastvectorUnitToStdVector(const gpg::fastvector<Unit*>& source,
                                     std::vector<Unit*>& destination)
  {
    destination.clear();

    if (source.start_ == nullptr || source.end_ == nullptr) {
      return;
    }

    const auto count = static_cast<std::size_t>(source.end_ - source.start_);
    if (count == 0u) {
      return;
    }

    destination.reserve(count);
    destination.insert(destination.end(), source.start_, source.end_);
  }
} // namespace moho
