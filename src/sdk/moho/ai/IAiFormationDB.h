// Reconstructed from FA binary evidence (vtable + callsites + decomp).
#pragma once

#include <cstdint>

#include "gpg/core/containers/String.h"

namespace moho
{
  class CAiFormationInstance;

  /**
   * Formation script bucket type used by `/lua/formations.lua`.
   * Evidence: `FUN_00575A30`, `FUN_00575BD0`, `FUN_00575DB0`.
   */
  enum class EFormationType : std::int32_t
  {
    Surface = 0,
    Air = 1,
  };

  /**
   * VFTABLE: 0x00E1B45C
   * COL:  0x00E70BD8
   */
  class IAiFormationDB
  {
  public:
    /**
     * Address: 0x0059A3D0 (FUN_0059A3D0)
     *
     * What it does:
     * Base deleting-destructor thunk for formation DB interface.
     */
    virtual ~IAiFormationDB();

    /**
     * Address: 0x0059C0C0 (FUN_0059C0C0)
     * Mangled: ?GetScriptName@CAiFormationDBImpl@Moho@@UAEPBDHW4EFormationType@2@@Z
     *
     * What it does:
     * Returns the script-name string for a formation script index/type.
     */
    virtual const char* GetScriptName(int scriptIndex, EFormationType formationType) = 0;

    /**
     * Address: 0x0059C0F0 (FUN_0059C0F0)
     * Mangled: ?GetScriptIndex@CAiFormationDBImpl@Moho@@UAEHPBDW4EFormationType@2@@Z
     *
     * What it does:
     * Resolves a formation script name into its zero-based index.
     */
    virtual int GetScriptIndex(gpg::StrArg scriptName, EFormationType formationType) = 0;

    /**
     * Address: 0x0059C060 (FUN_0059C060)
     * Mangled: ?RemoveFormation@CAiFormationDBImpl@Moho@@UAEXPAVCAiFormationInstance@2@@Z
     *
     * What it does:
     * Removes one formation-instance pointer from the DB storage.
     */
    virtual void RemoveFormation(CAiFormationInstance* formation) = 0;

    /**
     * Address: 0x0059C030 (FUN_0059C030)
     * Mangled: ?Update@CAiFormationDBImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Advances all live formation instances for the current sim tick.
     */
    virtual void Update() = 0;

    /**
     * Address: 0x0059C120 (FUN_0059C120)
     * Mangled:
     * ?NewFormation@CAiFormationDBImpl@Moho@@UAEPAVCAiFormationInstance@2@HPBDPAV?$fastvector_n@V?$weak_ptr@VUnit@Moho@@@boost@@$09@gpg@@MMMMM@Z
     *
     * What it does:
     * Allocates/builds a new formation instance and appends it to this DB.
     */
    virtual CAiFormationInstance* NewFormation(
      int scriptIndex, const char* scriptName, void* unitWeakSet, int arg4, int arg5, int arg6, int arg7, int arg8
    ) = 0;
  };

  static_assert(sizeof(IAiFormationDB) == 0x04, "IAiFormationDB size must be 0x04");
} // namespace moho
