#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * RTTI (`vtable_writers` class_name `CScriptObjectSerializer@Moho`)
   * confirms this is a standalone `gpg::SerHelperBase`-derived class, not a
   * `SerSaveLoadHelper<CScriptObject>` template instantiation, even though
   * its `Deserialize`/`Serialize` bodies behaviorally match that template's
   * generic `T::MemberDeserialize`/`T::MemberSerialize` forwarding shape.
   */
  class CScriptObjectSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC6080 (FUN_00BC6080, dynamic initializer for the global
     * `CScriptObjectSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CScriptObjectSerializer();

    /**
     * Address: 0x00BF0980 (FUN_00BF0980, Moho::CScriptObjectSerializer::~CScriptObjectSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The real ctor
     * pushes this mangled destructor symbol as its atexit target.
     */
    ~CScriptObjectSerializer();

    /**
     * Address: 0x004C79E0 (FUN_004C79E0, Moho::CScriptObjectSerializer::Deserialize)
     *
     * What it does:
     * Serializer load callback forwarding directly into
     * `CScriptObject::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004C79F0 (FUN_004C79F0, Moho::CScriptObjectSerializer::Serialize)
     *
     * What it does:
     * Serializer save callback forwarding directly into
     * `CScriptObject::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004C7D50 (FUN_004C7D50, Moho::CScriptObjectSerializer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CScriptObject RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CScriptObjectSerializer, mLoadCallback) == 0x0C,
    "CScriptObjectSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CScriptObjectSerializer, mSaveCallback) == 0x10,
    "CScriptObjectSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CScriptObjectSerializer) == 0x14, "CScriptObjectSerializer size must be 0x14");
} // namespace moho
