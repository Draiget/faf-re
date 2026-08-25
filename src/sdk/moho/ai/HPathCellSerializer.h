#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E35B1C (`??_7HPathCellSerializer@Moho@@6B@`)
   * Also installed as: 0x00E35B24 (`??_7?$SerSaveLoadHelper@UHPathCell@Moho@@@gpg@@6B@`)
   *
   * Demangled: gpg::SerSaveLoadHelper<struct Moho::HPathCell>
   *
   * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
   * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
   * load/save callback lanes@0x0C-0x13. Total 0x14 bytes, matching every
   * sibling `SerHelperBase`-derived serializer in this codebase
   * (`CUnitCarrierRetrieveSerializerHelper`, `SPathNeighborSerializer`, ...).
   *
   * Investigation note (2026-08-25): this class replaces a prior
   * `InstallMohoHPathCellSerializerCallbacks` free function in
   * `ArchiveSerialization.cpp` that cited this same address (0x007632D0) but
   * with a fabricated `gpg::REF_FindTypeNamed("Moho::HPathCell")`-by-string
   * body. The raw disassembly at 0x007632D0 does not call
   * `REF_FindTypeNamed` at all -- it reads a cached static
   * `Moho::HPathCell::sType`, resolves via `gpg::LookupRType(typeid(HPathCell))`
   * on a miss, and binds `this->mLoadCallback`/`this->mSaveCallback`
   * (offsets +0x0C/+0x10) into the resolved type's `serLoadFunc_`/
   * `serSaveFunc_` slots -- exactly the `Init()`-override shape below.
   * See decomp/recovery/reports/by-source/src/sdk/gpg/core/containers/ArchiveSerialization.cpp.reconstruction.md.
   */
  class HPathCellSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC630 (FUN_00BDC630, register_HPathCellSerializer,
     * dynamic initializer for the global `HPathCellSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the deserialize/serialize callback fields and installs
     * process-exit cleanup via `atexit`.
     */
    HPathCellSerializer();

    /**
     * Address: 0x007632D0 (FUN_007632D0, gpg::SerSaveLoadHelper<Moho::HPathCell>::Init)
     *
     * What it does:
     * Resolves `HPathCell` RTTI and installs this helper's load/save
     * callbacks into the reflected type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
  static_assert(offsetof(HPathCellSerializer, mLoadCallback) == 0x0C, "HPathCellSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(HPathCellSerializer, mSaveCallback) == 0x10, "HPathCellSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(HPathCellSerializer) == 0x14, "HPathCellSerializer size must be 0x14");
} // namespace moho
