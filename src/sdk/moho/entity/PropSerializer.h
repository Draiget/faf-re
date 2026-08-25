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
  class SPropPriorityInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD9840 (FUN_00BD9840, dynamic initializer for the global
     * `SPropPriorityInfoSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Plain unlink atexit target,
     * modeled as the compiler's implicit static-destructor registration.
     */
    SPropPriorityInfoSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPropPriorityInfoSerializer();

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
     * Address: 0x006FA8C0 (FUN_006FA8C0, gpg::SerSaveLoadHelper_SPropPriorityInfo::Init)
     *
     * What it does:
     * Binds `SPropPriorityInfo` RTTI load/save callbacks. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
   * VFTABLE: 0x00E2F4F4
   * COL: 0x00E8D8B4
   */
  class PropSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD9910 (FUN_00BD9910, dynamic initializer for the global
     * `PropSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    PropSerializer();

    /**
     * Address: 0x00BFF230 (FUN_00BFF230, Moho::PropSerializer::~PropSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~PropSerializer();

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
     * Address: 0x006FAA60 (FUN_006FAA60, gpg::SerSaveLoadHelper_Prop::Init)
     *
     * What it does:
     * Binds `Prop` RTTI load/save callbacks. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(PropSerializer, mDeserialize) == 0x0C, "PropSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(PropSerializer, mSerialize) == 0x10, "PropSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(PropSerializer) == 0x14, "PropSerializer size must be 0x14");
} // namespace moho
