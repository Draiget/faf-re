#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1EB24
   * COL: 0x00E756B0
   *
   * RTTI Class Hierarchy Descriptor shows this class's base chain running
   * through `.?AU?$SerSaveLoadHelper@VCAcquireTargetTask@Moho@@@gpg@@`
   * before `gpg::SerHelperBase` (same pattern observed on every
   * `PrimitiveSerHelper<T,int>` instantiation this session). The real ctor
   * binds `mDeserialize`/`mSerialize` directly to
   * `CAcquireTargetTask::MemberDeserialize`/`MemberSerialize` -- no separate
   * per-class forwarding wrapper exists (the decompiler's
   * `Moho::CAcquireTargetTaskSerializer::Deserialize` label on the assigned
   * value is a display artifact of the cast target, not a distinct
   * function; no such address exists in the functions table). Kept as a
   * concrete `SerHelperBase`-derived class rather than a naked
   * `gpg::SerSaveLoadHelper<CAcquireTargetTask>` alias, matching the
   * `Rect2iSerializer`-style precedent, since it binds the callbacks
   * directly in its own ctor instead of through the template's generic
   * `Deserialize`/`Serialize` static forwarders.
   */
  class CAcquireTargetTaskSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCE930 (FUN_00BCE930, register_CAcquireTargetTaskSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields directly to
     * `CAcquireTargetTask::MemberDeserialize`/`MemberSerialize`.
     */
    CAcquireTargetTaskSerializer();

    /**
     * Address: 0x00BF84C0 (FUN_00BF84C0, Moho::CAcquireTargetTaskSerializer::~CAcquireTargetTaskSerializer)
     *
     * What it does:
     * Unlinks the serializer helper from the intrusive helper list.
     */
    ~CAcquireTargetTaskSerializer();

    /**
     * Address: 0x005DC190 (FUN_005DC190)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CAcquireTargetTask` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mDeserialize) == 0x0C,
    "CAcquireTargetTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mSerialize) == 0x10,
    "CAcquireTargetTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CAcquireTargetTaskSerializer) == 0x14, "CAcquireTargetTaskSerializer size must be 0x14");
} // namespace moho
