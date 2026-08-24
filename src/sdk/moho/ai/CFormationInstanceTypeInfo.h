#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFormationInstance;

  /**
   * Owns reflected metadata for `CFormationInstance`, the un-AI-specialized
   * formation-instance base. `CAiFormationInstanceTypeInfo::Init`
   * (`CAiFormationInstanceTypeInfo.cpp`) resolves this type by name
   * ("CFormationInstance") and registers it as `CAiFormationInstance`'s
   * reflected base.
   *
   * VFTABLE: 0x00E19104
   */
  class CFormationInstanceTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0056A720 (FUN_0056A720, ctor lane)
     *
     * What it does:
     * Preregisters the `CFormationInstance` RTTI descriptor during startup.
     * In the binary this constructor body is inlined directly into the
     * `.CRT$XCL` provider wrapper (`register_CFormationInstanceTypeInfo`,
     * 0x00BCAC20) that constructs the file-scope singleton, rather than
     * being emitted as a standalone `__thiscall` symbol.
     */
    CFormationInstanceTypeInfo();

    /**
     * Address: 0x0056A7B0 (FUN_0056A7B0, Moho::CFormationInstanceTypeInfo::dtr)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes
     * (`bases_`, `fields_`) and restores the `gpg::RObject` vftable.
     * Defaulted in source: the compiler-generated `~RType()` reproduces this
     * behavior, matching `SPointVectorTypeInfo::~SPointVectorTypeInfo()`'s
     * identical emission shape (`SPointVector.h`) for the same base-layout
     * reason. Vtable-confirmed: `??_7CFormationInstanceTypeInfo@Moho@@6B@+0x8`
     * writes this address; that vtable is constructed by this class's own
     * constructor (0x0056A720), which is invoked from
     * `register_CFormationInstanceTypeInfo` (0x00BCAC20, recovered,
     * `CFormationInstanceTypeInfo.cpp`) and so writes its vptr on construction.
     */
    ~CFormationInstanceTypeInfo() override = default;

    /**
     * Address: 0x0056A7A0 (FUN_0056A7A0, Moho::CFormationInstanceTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `CFormationInstance`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0056A780 (FUN_0056A780, Moho::CFormationInstanceTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected width to `sizeof(CFormationInstance)`, adds
     * `IFormationInstance` as the reflected base at offset `+0x00`
     * (matching `CFormationInstance : public IFormationInstance`), and
     * finalizes the type metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(CFormationInstanceTypeInfo) == 0x64, "CFormationInstanceTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCAC20 (FUN_00BCAC20, register_CFormationInstanceTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CFormationInstanceTypeInfo` singleton and
   * installs process-exit cleanup. Dispatched from `.CRT$XCL` (`__xc_a`);
   * the binary has exactly one call site and no reentry guard, so the
   * recovered singleton storage is constructed unconditionally here.
   */
  void register_CFormationInstanceTypeInfo();
} // namespace moho
