#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E311D8
   */
  class CArmyStatItemSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA120 (FUN_00BDA120, dynamic initializer for the global
     * `CArmyStatItemSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target is a plain
     * unlink thunk, not a mangled destructor, so it is modeled as the
     * compiler's implicit static-destructor registration rather than an
     * explicit call.
     */
    CArmyStatItemSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CArmyStatItemSerializer();

    /**
     * Address: 0x0070B770 (FUN_0070B770, sub_70B770)
     *
     * What it does:
     * Reflection load callback that deserializes `CArmyStatItem` fields.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070B780 (FUN_0070B780, sub_70B780)
     *
     * What it does:
     * Reflection save callback that serializes `CArmyStatItem` fields.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070EEE0 (FUN_0070EEE0, gpg::SerSaveLoadHelper_CArmyStatItem::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyStatItem RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CArmyStatItemSerializer, mLoadCallback) == 0x0C,
    "CArmyStatItemSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatItemSerializer, mSaveCallback) == 0x10,
    "CArmyStatItemSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatItemSerializer) == 0x14, "CArmyStatItemSerializer size must be 0x14");
} // namespace moho
