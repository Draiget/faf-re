#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
}

namespace moho
{
  /**
   * Resolvable sound variable descriptor.
   *
   * Binary shape recovered from FUN_004E02B0/FUN_004E0330:
   * - +0x00: resolved runtime variable id (0xFFFF = unresolved/invalid)
   * - +0x02: resolve-attempt flag (set by DoResolve)
   * - +0x04: variable name (MSVC8 string)
   */
  class CSndVar
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x004E02B0 (FUN_004E02B0)
     *
     * gpg::StrArg name
     *
     * What it does:
     * Initializes variable id/flags and stores the variable name token.
     */
    explicit CSndVar(const char* name);

    /**
     * Address: 0x004E0330 (FUN_004E0330)
     *
     * What it does:
     * Releases name storage and resets the instance to unresolved state.
     */
    ~CSndVar();

    /**
     * Address: 0x004E0390 (FUN_004E0390)
     *
     * What it does:
     * Lazily resolves the named global sound variable id and caches the result.
     */
    bool DoResolve() const;

  public:
    mutable std::uint16_t mState;   // +0x00
    mutable std::uint8_t mResolved; // +0x02
    std::uint8_t mReserved03;       // +0x03
    msvc8::string mName;            // +0x04
  };

  /**
   * Address: 0x004DF390 (FUN_004DF390, func_NewCSndVar)
   *
   * What it does:
   * Returns one interned `CSndVar` for the supplied variable name, creating a
   * new descriptor on first use.
   */
  CSndVar* SND_FindOrCreateVariable(const msvc8::string& variableName);

  static_assert(offsetof(CSndVar, mState) == 0x00, "CSndVar::mState offset must be 0x00");
  static_assert(offsetof(CSndVar, mResolved) == 0x02, "CSndVar::mResolved offset must be 0x02");
  static_assert(offsetof(CSndVar, mName) == 0x04, "CSndVar::mName offset must be 0x04");
  static_assert(sizeof(CSndVar) == 0x20, "CSndVar size must be 0x20");

  /**
   * VFTABLE: 0x00E0BA48
   *
   * Demangled: gpg::SerConstructHelper<class Moho::CSndVar>
   *
   * What it does:
   * Reflection construct/delete helper for `CSndVar`: `Construct` interns a
   * `CSndVar` from its archived name; `Deconstruct` destroys a heap-owned one.
   */
  class CSndVarConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC6960 (FUN_00BC6960, dynamic initializer for the global
     * `CSndVarConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the construct/delete callback fields.
     */
    CSndVarConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSndVarConstruct();

    /**
     * Address: 0x004E0560 (FUN_004E0560, Moho::CSndVarConstruct::Construct)
     *
     * What it does:
     * Reads one variable-name construct arg, interns/creates the matching
     * `CSndVar`, and returns it as an owned reflection result.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x004E4BD0 (FUN_004E4BD0, Moho::CSndVarConstruct::Deconstruct)
     *
     * What it does:
     * Destroys one reflected `CSndVar` object allocated by the construct
     * callback.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x004E1D30 (FUN_004E1D30, gpg::SerConstructHelper<Moho::CSndVar>::Init)
     *
     * What it does:
     * Installs construct/delete callbacks into `CSndVar` RTTI. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

  static_assert(
    offsetof(CSndVarConstruct, mConstructCallback) == 0x0C, "CSndVarConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSndVarConstruct, mDeleteCallback) == 0x10, "CSndVarConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CSndVarConstruct) == 0x14, "CSndVarConstruct size must be 0x14");

  /**
   * VFTABLE: 0x00E0BA38
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::CSndVar>
   *
   * What it does:
   * Reflection save-construct-args helper for `CSndVar`: serializes the
   * live descriptor's name into its construct-arg payload.
   */
  class CSndVarSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC6930 (FUN_00BC6930, dynamic initializer for the global
     * `CSndVarSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    CSndVarSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CSndVarSaveConstruct();

    /**
     * Address: 0x004E0430 (FUN_004E0430, Moho::CSndVarSaveConstruct::SaveConstructArgs)
     *
     * What it does:
     * Serializes one live `CSndVar` descriptor's name into its
     * construct-arg payload.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x004E1CB0 (FUN_004E1CB0, gpg::SerSaveConstructHelper<Moho::CSndVar>::Init)
     *
     * What it does:
     * Binds the save-construct-args callback lane into `CSndVar` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CSndVarSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CSndVarSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CSndVarSaveConstruct) == 0x10, "CSndVarSaveConstruct size must be 0x10");
} // namespace moho
