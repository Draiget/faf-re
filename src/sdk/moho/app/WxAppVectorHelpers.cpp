#include "moho/app/WxAppVectorHelpers.h"

#include <cstddef>

#include "moho/app/WxRuntimeTypes.h"

namespace moho
{
  /**
   * Address: 0x004F7F50 (FUN_004F7F50, msvc8_vector_CWinLogLine_insert_pos_value)
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated single-element
   * `msvc8::vector<moho::CWinLogLine>::insert` body. Forwarding through
   * `push_back` preserves the appendage semantics observed at the only
   * binary call site (insert-at-end), which forces the compiler to emit
   * the templated grow/insert chain out-of-line for `T = CWinLogLine` —
   * keeping the 2007 MSVC8 per-`T` symbol shape.
   */
  CWinLogLine* InsertVectorWinLogLineAtEnd(
    msvc8::vector<CWinLogLine>& vec,
    const CWinLogLine& value)
  {
    // Route through the per-`T` `_Insert_n` helper so both per-T emissions
    // (FUN_004F7F50 outer insert + FUN_004F88B0 grow-and-insert) are forced
    // out-of-line — mirroring the binary's `insert -> _Insert_n` chain.
    CWinLogLine* const tail =
      vec.empty() ? nullptr : vec.data() + vec.size();
    GrowAndInsertOneVectorWinLogLine(vec, tail, value);
    if (vec.empty()) {
      return nullptr;
    }
    return vec.data() + (vec.size() - 1u);
  }

  /**
   * Address: 0x004F88B0 (FUN_004F88B0, msvc8_vector_CWinLogLine_Insert_n_pos_one_value)
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated MSVC8 slow-path
   * body for inserting a single `CWinLogLine` with potential reallocation.
   * Delegates to `InsertVectorWinLogLineAtEnd` so the templated grow-on-
   * insert chain is forced to emit out-of-line for `T = CWinLogLine`.
   */
  void GrowAndInsertOneVectorWinLogLine(
    msvc8::vector<CWinLogLine>& vec,
    CWinLogLine* const insertAt,
    const CWinLogLine& value)
  {
    const std::size_t oldCount = vec.size();
    const bool atEnd = (insertAt == nullptr) || vec.empty() ||
                       insertAt >= vec.data() + oldCount;
    std::size_t insertIndex = oldCount;
    if (!atEnd) {
      insertIndex = static_cast<std::size_t>(insertAt - vec.data());
    }

    vec.push_back(value);
    CWinLogLine* const storage = vec.data();
    if (storage == nullptr) {
      return;
    }
    for (std::size_t i = vec.size() - 1u; i > insertIndex; --i) {
      storage[i] = storage[i - 1u];
    }
    storage[insertIndex] = value;
  }

  /**
   * Address: 0x004FA880 (FUN_004FA880, msvc8_vector_CWinLogLine_insert_pos_first_last)
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated range-insert
   * body. Appends `[first, last)` onto `destination`. Because the only
   * observed call site is an append (`pos == end()`), forwarding through
   * `push_back` per element preserves observable behavior while forcing
   * the templated emission to bind for `T = CWinLogLine`.
   */
  void AppendVectorWinLogLineRange(
    msvc8::vector<CWinLogLine>& destination,
    const CWinLogLine* const first,
    const CWinLogLine* const last)
  {
    if (first == nullptr || last == nullptr || first >= last) {
      return;
    }
    // Route through the per-`T` single-element helper so the range-insert
    // emission FUN_004FA880 is reachable via the same engine `T` chain that
    // the binary used.
    for (const CWinLogLine* cursor = first; cursor != last; ++cursor) {
      (void)InsertVectorWinLogLineAtEnd(destination, *cursor);
    }
  }

  /**
   * Address: 0x004F8CA0 (FUN_004F8CA0, msvc8_vector_ManagedWindowSlot_insert_managedWindows)
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated single-element
   * insert body for the `managedWindows` global vector. Inserts one
   * `ManagedWindowSlot` value at the requested position with grow-on-
   * reallocation semantics.
   */
  ManagedWindowSlot* InsertManagedWindowSlotIntoWindowsVector(
    ManagedWindowSlot* const insertAt,
    const ManagedWindowSlot& value)
  {
    auto& vec = moho::managedWindows;
    const ManagedWindowSlot* const begin = vec.data();
    const std::size_t count = vec.size();

    std::size_t insertIndex = count;
    if (begin != nullptr && count != 0u && insertAt != nullptr) {
      if (insertAt >= begin && insertAt <= begin + count) {
        insertIndex = static_cast<std::size_t>(insertAt - begin);
      }
    }

    vec.push_back(value);
    ManagedWindowSlot* const storage = vec.data();
    if (storage == nullptr) {
      return nullptr;
    }
    for (std::size_t i = vec.size() - 1u; i > insertIndex; --i) {
      storage[i] = storage[i - 1u];
    }
    storage[insertIndex] = value;
    return storage + insertIndex;
  }

  /**
   * Address: 0x004F9050 (FUN_004F9050, msvc8_vector_ManagedWindowSlot_insert_managedFrames)
   *
   * What it does:
   * Per-T named helper that wraps the engine-instantiated single-element
   * insert body for the `managedFrames` global vector. Inserts one
   * `ManagedWindowSlot` value at the requested position with grow-on-
   * reallocation semantics. Mirrors the `managedWindows` body — MSVC8
   * emitted a distinct symbol per global because the optimizer specialized
   * the storage-reference loads.
   */
  ManagedWindowSlot* InsertManagedWindowSlotIntoFramesVector(
    ManagedWindowSlot* const insertAt,
    const ManagedWindowSlot& value)
  {
    auto& vec = moho::managedFrames;
    const ManagedWindowSlot* const begin = vec.data();
    const std::size_t count = vec.size();

    std::size_t insertIndex = count;
    if (begin != nullptr && count != 0u && insertAt != nullptr) {
      if (insertAt >= begin && insertAt <= begin + count) {
        insertIndex = static_cast<std::size_t>(insertAt - begin);
      }
    }

    vec.push_back(value);
    ManagedWindowSlot* const storage = vec.data();
    if (storage == nullptr) {
      return nullptr;
    }
    for (std::size_t i = vec.size() - 1u; i > insertIndex; --i) {
      storage[i] = storage[i - 1u];
    }
    storage[insertIndex] = value;
    return storage + insertIndex;
  }
} // namespace moho
