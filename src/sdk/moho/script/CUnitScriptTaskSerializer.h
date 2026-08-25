#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E20C98
   * COL: 0x00E79F40
   *
   * RTTI (`dumps/rtti_dump_all.hpp`) shows the real inheritance chain as
   * `SerHelperBase -> SerSaveLoadHelper<CUnitScriptTask> -> CUnitScriptTaskSerializer`
   * (every base at `mdisp=0`, single inheritance) -- but
   * `CUnitScriptTask::MemberDeserialize`/`MemberSerialize` are `static`
   * methods with a non-standard `(archive, task, version)`/`(task, archive,
   * version)` signature, not the instance-method shape the generic template
   * forwards to, so this class fully overrides `Init()`/`Deserialize`/
   * `Serialize`. Modeled as directly inheriting `SerHelperBase` (same
   * prior-art judgment as `Rect2iSerializer`/`Rect2fSerializer` and
   * `SCoordsVec2Serializer`): the intermediate template level adds zero
   * data or behavior this class doesn't already fully override.
   */
  class CUnitScriptTaskSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD19A0 (FUN_00BD19A0, dynamic initializer for the global
     * `CUnitScriptTaskSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitScriptTaskSerializer();

    /**
     * Address: 0x00BFA470 (FUN_00BFA470, Moho::CUnitScriptTaskSerializer::~CUnitScriptTaskSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The real ctor
     * pushes this mangled destructor symbol as its atexit target.
     */
    ~CUnitScriptTaskSerializer();

    /**
     * Address: 0x00622EA0 (FUN_00622EA0, Moho::CUnitScriptTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitScriptTask::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00622EC0 (FUN_00622EC0, Moho::CUnitScriptTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitScriptTask::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00623BB0 (FUN_00623BB0) -- shared vtable slot 0 target for
     * both `??_7CUnitScriptTaskSerializer@Moho@@6B@` and the
     * `SerSaveLoadHelper<CUnitScriptTask>` intermediate vtable.
     *
     * What it does:
     * Binds load/save serializer callbacks into CUnitScriptTask RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CUnitScriptTaskSerializer, mLoadCallback) == 0x0C,
    "CUnitScriptTaskSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitScriptTaskSerializer, mSaveCallback) == 0x10,
    "CUnitScriptTaskSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitScriptTaskSerializer) == 0x14, "CUnitScriptTaskSerializer size must be 0x14");
} // namespace moho
