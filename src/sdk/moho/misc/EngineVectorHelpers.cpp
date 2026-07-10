#include "moho/misc/EngineVectorHelpers.h"

#include <new>

#include "moho/render/RCamManager.h"
#include "moho/net/CGpgNetInterface.h"
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

  /**
   * Address: 0x007AE840 (FUN_007AE840, msvc8::vector<Moho::CameraImpl*>::vector(const vector&))
   *
   * What it does:
   * Per-T named helper binding the engine-instantiated
   * `msvc8::vector<Moho::CameraImpl*>` copy operation. Forwards to the
   * compiler-emitted copy-assignment body which carries the same
   * default-zero + allocate + range-copy semantics the binary's
   * out-of-line copy-ctor encoded.
   */
  void CopyConstructVectorOfCameraImplPtr(msvc8::vector<CameraImpl*>& destination,
                                          const msvc8::vector<CameraImpl*>& source)
  {
    destination = source;
  }

  /**
   * Address: 0x007AFD10 (FUN_007AFD10, msvc8::vector<Moho::CameraImpl*>::_Insert_n)
   *
   * What it does:
   * Per-T named helper binding the engine-instantiated
   * `msvc8::vector<CameraImpl*>` grow/insert lane. Forwards to the modeled
   * `msvc8::vector<CameraImpl*>::insert(pos, count, value)` which carries the
   * same capacity-check / 1.5x-grow / head+tail-move / gap-fill semantics the
   * binary's out-of-line `_Insert_n` body encoded for the 4-byte pointer element.
   */
  void InsertNCopiesCameraImplPtrVector(msvc8::vector<CameraImpl*>& storage,
                                        CameraImpl** const insertPosition,
                                        const unsigned int insertCount,
                                        CameraImpl* const fillValue)
  {
    if (insertCount == 0u) {
      return;
    }

    const auto offset = static_cast<std::size_t>(insertPosition - storage.begin());
    storage.insert(storage.begin() + offset, static_cast<std::size_t>(insertCount), fillValue);
  }

  /**
   * Address: 0x007AE990 (FUN_007AE990, msvc8::vector<Moho::CameraImpl*>::push_back)
   *
   * What it does:
   * Per-T push_back-shape helper for `msvc8::vector<CameraImpl*>`, mirroring the
   * MSVC8 inlined append shape: when the reserved capacity is exhausted the
   * append reaches the canonical `_Insert_n` slow-path
   * (`InsertNCopiesCameraImplPtrVector`, FUN_007AFD10); otherwise a fast-path
   * in-place store through the modeled `push_back`. This is the shape
   * `Moho::RCamManager::CreateCamera` open-codes around `mCams.push_back(camera)`.
   */
  void AppendCameraImplPtr(msvc8::vector<CameraImpl*>& storage, CameraImpl* const value)
  {
    if (storage.size() == storage.capacity()) {
      InsertNCopiesCameraImplPtrVector(storage, storage.end(), 1u, value);
    } else {
      storage.push_back(value);
    }
  }

  /**
   * Address: 0x007BAFE0 (FUN_007BAFE0, msvc8::vector<Moho::SNetCommandArg>::vector(const vector&))
   *
   * What it does:
   * Per-T named helper binding the engine-instantiated
   * `msvc8::vector<Moho::SNetCommandArg>` copy operation. Forwards to the
   * compiler-emitted copy-assignment body which carries the same
   * default-zero + allocate + element-copy semantics the binary's
   * out-of-line copy-ctor encoded.
   */
  void CopyConstructVectorOfSNetCommandArg(msvc8::vector<SNetCommandArg>& destination,
                                           const msvc8::vector<SNetCommandArg>& source)
  {
    destination = source;
  }
} // namespace moho
