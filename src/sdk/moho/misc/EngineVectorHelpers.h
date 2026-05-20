#pragma once

#include <cstdint>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"

/**
 * Per-type named wrappers around `msvc8::vector<T>` template emissions for
 * engine-instantiated types.
 *
 * MSVC8 emitted a distinct out-of-line body for each `vector<T>::*` operation
 * the engine source instantiated. Modern compilers may inline `vec.push_back(x)`
 * or `vec = other` when the call site is local and the body is tiny, eliding
 * the out-of-line symbol. To preserve the binary's 1:1 symbol shape (one named
 * function per engine `T`), callers route through these per-type wrappers; the
 * compiler must emit each wrapper as a real, externally-visible out-of-line
 * body.
 *
 * Each wrapper has the exact 2007 semantics: forward to the corresponding
 * `msvc8::vector<T>::*` operation, which dispatches to the fast-path or
 * slow-path inside the templated body.
 */

namespace moho
{
  // Forward decl for the unit type used in the fastvector→std::vector helper.
  class Unit;
  class CameraImpl;
  struct SNetCommandArg;


  /**
   * Address: 0x00547750 (FUN_00547750)
   *
   * IDA signature:
   * int __usercall sub_547750@<eax>(std::vector_ResourceDeposit *a1@<eax>, Moho::ResourceDeposit *a2@<ebx>);
   *
   * What it does:
   * Engine-instantiated body of `msvc8::vector<Moho::ResourceDeposit>::push_back`.
   * Appends one `ResourceDeposit` (size 0x14) at `_Mylast`, growing the storage
   * via the MSVC8 slow-path insert helper when the active range has reached
   * `_Myend`; otherwise placement-constructs the new element at the tail.
   *
   * Caller: Moho::CSimResources::AddDeposit (0x00545F10).
   */
  template <class T>
  void PushBackVector(msvc8::vector<T>& vec, const T& item)
  {
    vec.push_back(item);
  }

  /**
   * Address: 0x00560A90 (FUN_00560A90, msvc8::vector<unsigned int>::vector(const vector&))
   *
   * IDA signature:
   * _DWORD *__thiscall sub_560A90(_DWORD *this, _DWORD *a2);
   *
   * What it does:
   * Engine-instantiated copy-constructor body of `msvc8::vector<uint32_t>`.
   * Initializes the destination triplet to empty, then if the source contains
   * elements, allocates fresh storage (`operator new(uint)`) and copies the
   * source `[_Myfirst, _Mylast)` into the destination's storage, updating
   * `_Mylast` to the new end and `_Myend` to one-past-allocation.
   *
   * Caller: Moho::SSTIArmyVariableData::SSTIArmyVariableData copy-ctor
   * (0x0055FF80) — triggered by member-wise copy of
   * `mRuntimeWordVectorWithMeta.mWords` in the initializer list.
   *
   * This per-T named free helper produces the bound out-of-line symbol so
   * the linker keeps the MSVC8 body shape (one symbol per engine `T`).
   * Callers invoke this helper after default-constructing `destination` to
   * deep-copy the source contents into the destination vector.
   */
  void AssignCopyVectorUint32(msvc8::vector<std::uint32_t>& destination,
                              const msvc8::vector<std::uint32_t>& source);

  /**
   * Address: 0x0057E550 (FUN_0057E550, func_FastvecUnitToStdVec)
   *
   * IDA signature:
   * std::vector_Unit *__thiscall func_FastvecUnitToStdVec(
   *     gpg::fastvector_Unit *this, std::vector_Unit *a2);
   *
   * What it does:
   * Engine helper that snapshots a `gpg::fastvector<Moho::Unit*>` lane into a
   * fresh `std::vector<Moho::Unit*>`. Initializes the destination triplet to
   * empty, then if the source is non-empty allocates fresh storage sized to
   * the source's element count and bulk-copies the pointer range
   * `[start_, end_)` into it.
   *
   * Caller: Moho::FindAvailableFactory (0x0057AC30) — the entry-point
   * snapshot of the candidate list before the buildability scan.
   */
  void CopyFastvectorUnitToStdVector(const gpg::fastvector<Unit*>& source,
                                     std::vector<Unit*>& destination);

  /**
   * Address: 0x007AE840 (FUN_007AE840, msvc8::vector<Moho::CameraImpl*>::vector(const vector&))
   *
   * What it does:
   * Engine-instantiated copy-construction body for
   * `msvc8::vector<Moho::CameraImpl*>`. Default-zeros the destination triplet
   * then, if the source has any elements, allocates fresh dword storage,
   * copies the pointer range `[src._Myfirst, src._Mylast)` into the
   * destination, and updates `_Mylast`/`_Myend`.
   *
   * Bound to `Moho::RCamManager::GetAllCameras` (FUN_007AAB60) which returns
   * the camera vector by value. NRVO may elide the natural `return mCams;`
   * copy-ctor — wiring through this per-T named helper preserves the MSVC8
   * 1:1 symbol shape.
   */
  void CopyConstructVectorOfCameraImplPtr(msvc8::vector<CameraImpl*>& destination,
                                          const msvc8::vector<CameraImpl*>& source);

  /**
   * Address: 0x007BAFE0 (FUN_007BAFE0, msvc8::vector<Moho::SNetCommandArg>::vector(const vector&))
   *
   * What it does:
   * Engine-instantiated copy-construction body for
   * `msvc8::vector<Moho::SNetCommandArg>`. Default-zeros the destination
   * triplet then, if the source has any elements, allocates fresh storage,
   * copy-constructs each `SNetCommandArg` element into the destination, and
   * updates `_Mylast`/`_Myend`.
   *
   * Bound to `Moho::SNetCommand::SNetCommand(const SNetCommand&)`
   * (FUN_007BCE70) which copies the queued-command argument vector. Wiring
   * through this per-T named helper preserves the MSVC8 1:1 symbol shape
   * even when the compiler elides the inline copy-ctor body.
   */
  void CopyConstructVectorOfSNetCommandArg(msvc8::vector<SNetCommandArg>& destination,
                                           const msvc8::vector<SNetCommandArg>& source);
} // namespace moho
