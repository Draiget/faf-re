#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CSimResources;

  /**
   * VFTABLE: 0x00E171E4
   * COL: 0x00E6B64C
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CSimResourcesSerializer@Moho'`): `FUN_00BC96D0` (real,
   * `__xc_a`-reachable) vs. a dead zero-xref duplicate at `FUN_00546C20`
   * (same field writes, no `atexit` call, confirmed via raw asm never live).
   * Confirmed via raw asm: the real ctor default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_00546B80`/`FUN_00546BD0`, installs the `CSimResourcesSerializer`
   * vtable, and pushes the real mangled destructor
   * `??1CSimResourcesSerializer@Moho@@QAE@@Z` (`FUN_00BF42C0`, confirmed
   * unlink-then-self-link shape matching `SerHelperBase::ResetLinks()`) as
   * its `atexit` target -- no eager `RegisterSerializeFunctions`/`Init()`
   * call exists in the real ctor. Two more zero-xref duplicate emissions of
   * that same unlink logic (`FUN_00546C50`, `FUN_00546C80`, formerly
   * `CleanupCSimResourcesSerializerHelperNodePrimary/Secondary`) are dead
   * ICF twins, sha256-identical to the real destructor.
   */
  class CSimResourcesSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC96D0 (FUN_00BC96D0, dynamic initializer for the global
     * `CSimResourcesSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CSimResourcesSerializer();

    /**
     * Address: 0x00BF42C0 (FUN_00BF42C0, Moho::CSimResourcesSerializer::~CSimResourcesSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSimResourcesSerializer();

    /**
     * Address: 0x00546B80 (FUN_00546B80, Moho::CSimResourcesSerializer::Deserialize)
     *
     * What it does:
     * Deserializes the `CSimResources::deposits_` vector from archive state.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00546BD0 (FUN_00546BD0, Moho::CSimResourcesSerializer::Serialize)
     *
     * What it does:
     * Serializes the `CSimResources::deposits_` vector to archive state.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
     *
     * What it does:
     * Binds `CSimResources` load/save serializer callbacks into RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CSimResourcesSerializer, mDeserialize) == 0x0C,
    "CSimResourcesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mSerialize) == 0x10,
    "CSimResourcesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CSimResourcesSerializer) == 0x14, "CSimResourcesSerializer size must be 0x14");
} // namespace moho
