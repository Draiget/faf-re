#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class RRef;
} // namespace gpg

namespace moho
{
  /**
   * Demangled: gpg::SerConstructHelper<class Moho::REmitterBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `REmitterBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   *
   * Unlike its sibling blueprint construct helpers, this class's real
   * destructor is independently named in the binary
   * (`??1REmitterBlueprintConstruct@Moho@@QAE@@Z`, 0x00BF25F0) rather than an
   * anonymous `sub_XXXXXX` -- the compiler specialized the unlink body to the
   * one known global instance (its only caller is this class's own `atexit`
   * registration), but it is still a genuine member destructor at the source
   * level, so it is declared as one here instead of a free-function
   * `Cleanup...()` helper.
   */
  class REmitterBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8100 (FUN_00BC8100, dynamic initializer for the global
     * `REmitterBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the construct/delete callback fields. Registers this class's
     * real destructor as process-exit cleanup (compiler-emitted; see class
     * doxygen).
     */
    REmitterBlueprintConstruct();

    /**
     * Address: 0x00BF25F0 (FUN_00BF25F0, Moho::REmitterBlueprintConstruct::~REmitterBlueprintConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     *
     * ICF twins: 0x0050FDE0 (FUN_0050FDE0) and 0x0050FE10 (FUN_0050FE10) are
     * byte-identical duplicates hardcoded to this same global's link fields,
     * confirmed zero independent callers via the callgraph index -- dead
     * linker-emitted copies, not separate binary behavior.
     */
    ~REmitterBlueprintConstruct();

    /**
     * Address: 0x00510600 (FUN_00510600, gpg::SerConstructHelper<Moho::REmitterBlueprint>::Init)
     *
     * What it does:
     * Lazily resolves the `REmitterBlueprint` reflection descriptor, asserts
     * the construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(REmitterBlueprintConstruct, mConstructCallback) == 0x0C,
    "REmitterBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(REmitterBlueprintConstruct, mDeleteCallback) == 0x10,
    "REmitterBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(REmitterBlueprintConstruct) == 0x14, "REmitterBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x0050FE40 (FUN_0050FE40)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves emitter
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_REmitterBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x005110A0 (FUN_005110A0)
   *
   * What it does:
   * Deletes one constructed `REmitterBlueprint`.
   */
  void Delete_REmitterBlueprint(void* objectPtr);
} // namespace moho
