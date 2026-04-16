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
  class UnitConstruct
  {
  public:
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
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(offsetof(UnitConstruct, mHelperNext) == 0x04, "UnitConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitConstruct, mHelperPrev) == 0x08, "UnitConstruct::mHelperPrev offset must be 0x08");
  static_assert(offsetof(UnitConstruct, mConstructCallback) == 0x0C, "UnitConstruct::mConstructCallback offset must be 0x0C");
  static_assert(
    offsetof(UnitConstruct, mDeconstructCallback) == 0x10, "UnitConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(UnitConstruct) == 0x14, "UnitConstruct size must be 0x14");

  class UnitSerializer
  {
  public:
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
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `Unit`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(UnitSerializer, mHelperNext) == 0x04, "UnitSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitSerializer, mHelperPrev) == 0x08, "UnitSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(UnitSerializer, mDeserialize) == 0x0C, "UnitSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(UnitSerializer, mSerialize) == 0x10, "UnitSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UnitSerializer) == 0x14, "UnitSerializer size must be 0x14");

  /**
   * Address: 0x00BFDA00 (FUN_00BFDA00, cleanup_UnitConstruct)
   *
   * What it does:
   * Unlinks `UnitConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitConstruct();

  /**
   * Address: 0x00BFDA30 (FUN_00BFDA30, cleanup_UnitSerializer)
   *
   * What it does:
   * Unlinks `UnitSerializer` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitSerializer();

  /**
   * Address: 0x00BD6B20 (FUN_00BD6B20, register_UnitConstruct)
   *
   * What it does:
   * Initializes and registers `UnitConstruct` startup helper.
   */
  void register_UnitConstruct();

  /**
   * Address: 0x00BD6B60 (FUN_00BD6B60, register_UnitSerializer)
   *
   * What it does:
   * Initializes and registers `UnitSerializer` startup helper.
   */
  void register_UnitSerializer();
} // namespace moho
