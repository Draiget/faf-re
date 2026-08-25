#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E35ABC
   * COL: 0x00E8EF78
   */
  class CSimSoundManagerSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC590 (FUN_00BDC590, dynamic initializer for the global
     * `CSimSoundManagerSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly (IDA's own inferred name for this address is literally
     * `register_CSimSoundManagerSerializer`): calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CSimSoundManagerSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here. Previously this global was declared with plain `{}`
     * aggregate init and this constructor was never invoked anywhere in
     * the recovered source, so the helper was never spliced into
     * `sNewHelpers` and its `Init()` never ran.
     */
    CSimSoundManagerSerializer();

    /**
     * Address: 0x00762440 (FUN_00762440)
     *
     * What it does:
     * Reflection load callback wrapper for `CSimSoundManager`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00762450 (FUN_00762450)
     *
     * What it does:
     * Reflection save callback wrapper for `CSimSoundManager`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00761E90 (FUN_00761E90, gpg::SerSaveLoadHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CSimSoundManager` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CSimSoundManagerSerializer, mLoadCallback) == 0x0C,
    "CSimSoundManagerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimSoundManagerSerializer, mSaveCallback) == 0x10,
    "CSimSoundManagerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CSimSoundManagerSerializer) == 0x14, "CSimSoundManagerSerializer size must be 0x14");
} // namespace moho
