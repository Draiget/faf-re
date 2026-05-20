#pragma once

#include <cstddef>

#include "legacy/containers/Vector.h"

namespace moho
{
  struct CWinLogLine;
  struct ManagedWindowSlot;

  /**
   * Per-type named wrappers around `msvc8::vector<T>` template emissions for
   * wx-app subsystem engine types (`moho::CWinLogLine`,
   * `moho::ManagedWindowSlot`).
   *
   * MSVC8 emitted one distinct out-of-line body per `vector<T>::*` operation
   * the engine source instantiated. Modern compilers may inline
   * `vec.push_back(x)` when the body is tiny, eliding the out-of-line symbol.
   * To preserve the binary's 1:1 symbol shape (one named function per engine
   * `T`), wx-app callers route through these per-type wrappers; the compiler
   * must emit each wrapper as a real, externally-visible out-of-line body.
   *
   * Each wrapper has the exact 2007 semantics: forward to the corresponding
   * `msvc8::vector<T>::*` operation, which dispatches to the fast-path or
   * slow-path inside the templated body.
   */

  /**
   * Address: 0x004F7F50 (FUN_004F7F50, msvc8_vector_CWinLogLine_insert_pos_value)
   *
   * IDA signature:
   * _DWORD *__userpurge sub_4F7F50@<eax>(
   *   int a1@<edi>, _DWORD *a2, int a3, int a4);
   *
   * What it does:
   * Engine-instantiated body of `msvc8::vector<moho::CWinLogLine>::insert`
   * (the `(pos, value)` overload). Inserts one `CWinLogLine` (size 0x28) at
   * the requested position, growing storage via the MSVC8 slow-path
   * (`_Insert_n`) when capacity is reached, then returns the rebased
   * iterator pointing at the inserted slot.
   *
   * Caller: `moho::CWinLogTarget::AppendPendingLine` (0x004F6F40) — the
   * `mPendingLines` accumulator that receives one record per log line.
   */
  CWinLogLine* InsertVectorWinLogLineAtEnd(
    msvc8::vector<CWinLogLine>& vec,
    const CWinLogLine& value);

  /**
   * Address: 0x004F88B0 (FUN_004F88B0, msvc8_vector_CWinLogLine_Insert_n_pos_one_value)
   *
   * IDA signature:
   * void __cdecl __noreturn sub_4F88B0(_DWORD *a1, int a2, int *a3);
   *
   * What it does:
   * Engine-instantiated MSVC8 slow-path body for inserting one
   * `CWinLogLine` at a requested position with capacity-growth rebalance.
   * Allocates fresh storage when the active range has reached `_Myend`,
   * shifts the tail, places the new value, and updates the triplet.
   *
   * Caller (transitive): `moho::CWinLogTarget::AppendPendingLine` via
   * `InsertVectorWinLogLineAtEnd` (FUN_004F7F50).
   */
  void GrowAndInsertOneVectorWinLogLine(
    msvc8::vector<CWinLogLine>& vec,
    CWinLogLine* insertAt,
    const CWinLogLine& value);

  /**
   * Address: 0x004FA880 (FUN_004FA880, msvc8_vector_CWinLogLine_insert_pos_first_last)
   *
   * IDA signature:
   * void __stdcall __noreturn sub_4FA880(
   *   int *a1, int a2, int a3, int a4, int a5);
   *
   * What it does:
   * Engine-instantiated range-insert body for `msvc8::vector<CWinLogLine>`.
   * Inserts `[first, last)` at the requested position, allocating new
   * storage when the existing capacity cannot fit the additional count and
   * preserving relative ordering of pre-existing tail records.
   *
   * Caller: `moho::CWinLogTarget::MergePendingLines` (0x004F6A50) — appends
   * the pending-line range onto the committed-line vector after enforcing
   * the 10,000-line cap.
   */
  void AppendVectorWinLogLineRange(
    msvc8::vector<CWinLogLine>& destination,
    const CWinLogLine* first,
    const CWinLogLine* last);

  /**
   * Address: 0x004F8CA0 (FUN_004F8CA0, msvc8_vector_ManagedWindowSlot_insert_managedWindows)
   *
   * IDA signature:
   * int **__cdecl sub_4F8CA0(_DWORD **a3, int ***a2);
   *
   * What it does:
   * Engine-instantiated single-element insert body for the
   * `moho::managedWindows` global. Inserts one `ManagedWindowSlot` at the
   * requested position; when storage must grow, allocates fresh memory and
   * relocates the existing slots, otherwise shifts the tail in place.
   *
   * Caller: `moho::WWinManagedDialog::RegisterManagedOwnerSlot` (via
   * `InsertManagedWindowSlotIntoWindows` at 0x004F80F0).
   */
  ManagedWindowSlot* InsertManagedWindowSlotIntoWindowsVector(
    ManagedWindowSlot* insertAt,
    const ManagedWindowSlot& value);

  /**
   * Address: 0x004F9050 (FUN_004F9050, msvc8_vector_ManagedWindowSlot_insert_managedFrames)
   *
   * IDA signature:
   * void __stdcall __noreturn sub_4F9050(int a1, _DWORD **a2);
   *
   * What it does:
   * Engine-instantiated single-element insert body for the
   * `moho::managedFrames` global. Inserts one `ManagedWindowSlot` at the
   * requested position; when storage must grow, allocates fresh memory and
   * relocates the existing slots, otherwise shifts the tail in place.
   *
   * Caller: `moho::WWinManagedFrame::RegisterManagedOwnerSlot` (via
   * `InsertManagedWindowSlotIntoFrames` at 0x004F8240).
   */
  ManagedWindowSlot* InsertManagedWindowSlotIntoFramesVector(
    ManagedWindowSlot* insertAt,
    const ManagedWindowSlot& value);
} // namespace moho
