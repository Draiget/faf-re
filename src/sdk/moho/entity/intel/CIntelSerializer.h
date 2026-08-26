#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E36214
   * COL:  0x00E8FC14
   *
   * Demangled: gpg::SerSaveLoadHelper<Moho::CIntel>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CIntelSerializer@Moho'`): `FUN_00BDCBE0` (real,
   * `__xc_a`-reachable) vs. a dead zero-xref duplicate at `FUN_0076E6D0`
   * (previously mis-modeled as `InitializeCIntelSerializerHelper()`). The
   * real `Init()` body (`FUN_0076E810`, found via the class's own vtable
   * slot-0 data xref) demangles as `gpg::SerSaveLoadHelper_CIntel::Init`,
   * but `CIntel` exposes `ReadArchive`/`WriteArchive` rather than the
   * template's expected `MemberDeserialize`/`MemberSerialize` names, so
   * this stays a direct `SerHelperBase` derivative rather than a
   * `gpg::SerSaveLoadHelper<CIntel>` alias (matching the precedent of
   * `Rect2iSerializer`/`Rect2fSerializer` staying concrete).
   */
  class CIntelSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDCBE0 (FUN_00BDCBE0, dynamic initializer for the global
     * `CIntelSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Plain unlink atexit target, modeled as
     * the compiler's implicit static-destructor registration.
     */
    CIntelSerializer();

    /**
     * Address: 0x00C01DF0 (FUN_00C01DF0, atexit target registered by the
     * real ctor above)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_0076E700`/
     * `FUN_0076E730` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed; distinct from the ctor-side
     * dead duplicate `FUN_0076E6D0` above), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneBH` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~CIntelSerializer();

    /**
     * Address: 0x0076E810 (FUN_0076E810, gpg::SerSaveLoadHelper_CIntel::Init)
     *
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `CIntel`.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CIntelSerializer, mLoadCallback) == 0x0C, "CIntelSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelSerializer, mSaveCallback) == 0x10, "CIntelSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelSerializer) == 0x14, "CIntelSerializer size must be 0x14");
} // namespace moho
