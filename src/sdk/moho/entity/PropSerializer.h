#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class Prop;

  /**
   * VFTABLE: 0x00E2F4C4
   * COL: 0x00E8D924
   */
  class SPropPriorityInfoSerializer
  {
  public:
    /**
     * Address: 0x006F9BE0 (FUN_006F9BE0, Moho::SPropPriorityInfoSerializer::Deserialize)
     *
     * What it does:
     * Reads `{priority,boundedTick}` lanes from the archive into `SPropPriorityInfo`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006F9C10 (FUN_006F9C10, Moho::SPropPriorityInfoSerializer::Serialize)
     *
     * What it does:
     * Writes `{priority,boundedTick}` lanes for `SPropPriorityInfo`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006FA8C0 (FUN_006FA8C0, sub_6FA8C0)
     *
     * What it does:
     * Binds `SPropPriorityInfo` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SPropPriorityInfoSerializer, mHelperLinks) == 0x04,
    "SPropPriorityInfoSerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(SPropPriorityInfoSerializer, mDeserialize) == 0x0C,
    "SPropPriorityInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SPropPriorityInfoSerializer, mSerialize) == 0x10,
    "SPropPriorityInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SPropPriorityInfoSerializer) == 0x14, "SPropPriorityInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BFF140 (FUN_00BFF140, sub_BFF140)
   *
   * What it does:
   * Unlinks the SPropPriorityInfo serializer helper node and rewires it as a
   * self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_SPropPriorityInfoSerializer();

  /**
   * Address: 0x00BD9840 (FUN_00BD9840, register_SPropPriorityInfoSerializer)
   *
   * What it does:
   * Initializes and registers the serializer callbacks for `SPropPriorityInfo`.
   */
  void register_SPropPriorityInfoSerializer();

  /**
   * VFTABLE: 0x00E2F4F4
   * COL: 0x00E8D8B4
   */
  class PropSerializer
  {
  public:
    /**
     * Address: 0x006FA760 (FUN_006FA760, Moho::PropSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load into `Prop::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006FA780 (FUN_006FA780, Moho::PropSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save into `Prop::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006FAA60 (FUN_006FAA60, sub_6FAA60)
     *
     * What it does:
     * Binds `Prop` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(PropSerializer, mHelperLinks) == 0x04, "PropSerializer::mHelperLinks offset must be 0x04");
  static_assert(offsetof(PropSerializer, mDeserialize) == 0x0C, "PropSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(PropSerializer, mSerialize) == 0x10, "PropSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(PropSerializer) == 0x14, "PropSerializer size must be 0x14");

  /**
   * Address: 0x00BFF230 (FUN_00BFF230, Moho::PropSerializer::~PropSerializer)
   *
   * What it does:
   * Unlinks the Prop serializer helper node and rewires it as a self-linked
   * singleton.
   */
  gpg::SerHelperBase* cleanup_PropSerializer();

  /**
   * Address: 0x00BD9910 (FUN_00BD9910, register_PropSerializer)
   *
   * What it does:
   * Initializes and registers the serializer callbacks for `Prop`.
   */
  void register_PropSerializer();
} // namespace moho


