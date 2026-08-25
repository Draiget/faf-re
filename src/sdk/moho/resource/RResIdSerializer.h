#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct RResId;

  /**
   * VFTABLE: 0x00E073BC
   * COL: 0x00E61E9C
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='RResIdSerializer@Moho'`): `FUN_00BC5A80` (real, sole
   * writer, `__xc_a`-reachable). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_004A9690`/`FUN_004A96B0`, installs the `RResIdSerializer` vtable,
   * and pushes the real mangled destructor
   * `??1RResIdSerializer@Moho@@QAE@@Z` (`FUN_00BF04C0`, confirmed
   * unlink-then-self-link shape matching `SerHelperBase::ResetLinks()`) as
   * its `atexit` target -- no eager `RegisterSerializeFunctions`/`Init()`
   * call exists in the real ctor. Two zero-xref duplicate emissions of that
   * same unlink logic (`FUN_004A9700`, `FUN_004A9730`, formerly
   * `ResetRResIdSerializerLinksVariant1/2`) are dead ICF twins,
   * sha256-identical to the real destructor.
   *
   * `nullsub_693` (`FUN_004A9680`, a single-byte `retn` stub) was previously
   * attached to this file with no real connection to `RResIdSerializer` --
   * it decompiles to nothing but a bare return, has zero callers/xrefs, and
   * shares no evidence with any function here. IDA pad-byte
   * misclassification; removed from this file (marked `skip`).
   */
  class RResIdSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5A80 (FUN_00BC5A80, dynamic initializer for the global
     * `RResIdSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    RResIdSerializer();

    /**
     * Address: 0x00BF04C0 (FUN_00BF04C0, Moho::RResIdSerializer::~RResIdSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~RResIdSerializer();

    /**
     * Address: 0x004A9690 (FUN_004A9690, Moho::RResIdSerializer::Deserialize)
     *
     * What it does:
     * Loads one reflected `RResId` filename string from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A96B0 (FUN_004A96B0, Moho::RResIdSerializer::Serialize)
     *
     * What it does:
     * Saves one reflected `RResId` filename string to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A9790 (FUN_004A9790, gpg::SerSaveLoadHelper<Moho::RResId>::Init)
     *
     * What it does:
     * Binds `RResId` serializer load/save callbacks into reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(RResIdSerializer, mDeserialize) == 0x0C, "RResIdSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(RResIdSerializer, mSerialize) == 0x10, "RResIdSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(RResIdSerializer) == 0x14, "RResIdSerializer size must be 0x14");
} // namespace moho

