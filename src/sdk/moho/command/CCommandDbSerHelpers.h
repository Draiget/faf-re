#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CCommandDb;

  class CCommandDBSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8C60 (FUN_00BD8C60, dynamic initializer for the global
     * `CCommandDBSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CCommandDBSaveConstruct@Moho@@6B@` -- no eager `Init()` call
     * exists here. The ctor's atexit target (0x00BFE9A0) is a plain unlink
     * thunk, not a mangled destructor symbol, so it is modeled as the
     * compiler's implicit static-destructor registration for a global with
     * a non-trivial destructor rather than an explicit `atexit` call --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    CCommandDBSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CCommandDBSaveConstruct();

    /**
     * Address: 0x006E1040 (FUN_006E1040, sub_6E1040)
     *
     * What it does:
     * Serializes the owning `Sim` pointer for `CCommandDb` as an unowned tracked pointer.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x006E1B20 (FUN_006E1B20, Moho::CCommandDBSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds `CCommandDb` save-construct-args callback into the reflected RTTI slot.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CCommandDBSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CCommandDBSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CCommandDBSaveConstruct) == 0x10, "CCommandDBSaveConstruct size must be 0x10");

  class CCommandDBConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8C90 (FUN_00BD8C90, dynamic initializer for the global
     * `CCommandDBConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. The ctor's atexit target
     * (0x00BFE9D0) is a plain unlink thunk, not a mangled destructor
     * symbol, so it is modeled as the compiler's implicit
     * static-destructor registration rather than an explicit `atexit`
     * call.
     */
    CCommandDBConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CCommandDBConstruct();

    /**
     * Address: 0x006E1220 (FUN_006E1220, sub_6E1220)
     *
     * What it does:
     * Reads the owning `Sim` pointer, allocates `CCommandDb`, and returns it as unowned.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006E1BA0 (FUN_006E1BA0, Moho::CCommandDBConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds `CCommandDb` construct/delete callbacks into the reflected RTTI slot.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;  // +0x0C
    gpg::RType::delete_func_t mDeconstructCallback;    // +0x10
  };

  static_assert(
    offsetof(CCommandDBConstruct, mConstructCallback) == 0x0C, "CCommandDBConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CCommandDBConstruct, mDeconstructCallback) == 0x10, "CCommandDBConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(CCommandDBConstruct) == 0x14, "CCommandDBConstruct size must be 0x14");

  class CCommandDBSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8CD0 (FUN_00BD8CD0, dynamic initializer for the global
     * `CCommandDBSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CCommandDBSerializer();

    /**
     * Address: 0x00BFEA00 (FUN_00BFEA00, Moho::CCommandDBSerializer::~CCommandDBSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The real ctor
     * pushes this mangled destructor symbol as its atexit target, so it is
     * the compiler's own implicit static-destructor registration.
     */
    ~CCommandDBSerializer();

    /**
     * Address: 0x006E12E0 (FUN_006E12E0, Moho::CCommandDBSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load into `CCommandDb::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E12F0 (FUN_006E12F0, Moho::CCommandDBSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save into `CCommandDb::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E1C20 (FUN_006E1C20, Moho::CCommandDBSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `CCommandDb` load/save callbacks into the reflected RTTI slot.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(CCommandDBSerializer, mDeserialize) == 0x0C, "CCommandDBSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CCommandDBSerializer, mSerialize) == 0x10, "CCommandDBSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CCommandDBSerializer) == 0x14, "CCommandDBSerializer size must be 0x14");
} // namespace moho
