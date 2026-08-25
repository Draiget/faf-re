#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/Unit.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * RTTI Class Hierarchy Descriptor shows this class's base chain running
   * through `.?AU?$SerConstructHelper@VUnit@Moho@@@gpg@@` before
   * `gpg::SerHelperBase` -- the construct/delete template family (see
   * `CUnitCommandConstruct` for the sibling `CUnitCommand` instantiation).
   * Kept as a concrete `SerHelperBase`-derived class, same precedent.
   */
  class UnitConstruct final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6B20 (FUN_00BD6B20, register_UnitConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    UnitConstruct();

    /**
     * Address: 0x00BFDA00 (FUN_00BFDA00, Moho::UnitConstruct::~UnitConstruct)
     *
     * What it does:
     * Unlinks `UnitConstruct` helper links and rewires self-links.
     */
    ~UnitConstruct();

    /**
     * Address: 0x006AD3A0 (FUN_006AD3A0, Moho::UnitConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `Unit::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006B1010 (FUN_006B1010, Moho::UnitConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `Unit`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x006AE9A0 (FUN_006AE9A0, Moho::UnitConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Unit`.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeconstructCallback;  // +0x10
  };

  static_assert(offsetof(UnitConstruct, mConstructCallback) == 0x0C, "UnitConstruct::mConstructCallback offset must be 0x0C");
  static_assert(
    offsetof(UnitConstruct, mDeconstructCallback) == 0x10, "UnitConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(UnitConstruct) == 0x14, "UnitConstruct size must be 0x14");

  /**
   * RTTI Class Hierarchy Descriptor shows this class's base chain running
   * through `.?AU?$SerSaveLoadHelper@VUnit@Moho@@@gpg@@` before
   * `gpg::SerHelperBase` (same pattern observed on every
   * `PrimitiveSerHelper<T,int>` instantiation this session). Not converted
   * to a naked `gpg::SerSaveLoadHelper<Unit>` alias: `Unit` does not expose
   * a `MemberDeserialize`/`MemberSerialize` pair matching that template's
   * generic forwarding signature (`Unit::MemberDeserialize`/
   * `MemberSerialize` take extra owner/version threading the template
   * doesn't forward). Same situation already documented for
   * `Rect2iSerializer`/`SSTIUnitConstantDataSerializer` above: stays a
   * concrete `SerHelperBase`-derived class with its own
   * `Deserialize`/`Serialize`.
   */
  class UnitSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6B60 (FUN_00BD6B60, register_UnitSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    UnitSerializer();

    /**
     * Address: 0x00BFDA30 (FUN_00BFDA30, Moho::UnitSerializer::~UnitSerializer)
     *
     * What it does:
     * Unlinks `UnitSerializer` helper links and rewires self-links.
     */
    ~UnitSerializer();

    /**
     * Address: 0x006AD470 (FUN_006AD470, Moho::UnitSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load callback into `Unit::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006AD490 (FUN_006AD490, Moho::UnitSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save callback into `Unit::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006AEA20 (FUN_006AEA20, gpg::SerSaveLoadHelper<Moho::Unit>::Init lane)
     *
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `Unit`. Previously
     * mis-cited in `ArchiveSerialization.cpp` as a generic
     * `InstallSerSaveLoadHelperCallbacksByTypeName` dispatch (same
     * mis-citation family already caught this session for several other
     * classes); real body caches on `Unit::sType` directly, reached here
     * through the already-established `Unit::StaticGetClass()` accessor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(UnitSerializer, mDeserialize) == 0x0C, "UnitSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(UnitSerializer, mSerialize) == 0x10, "UnitSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UnitSerializer) == 0x14, "UnitSerializer size must be 0x14");
} // namespace moho
