#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2410C
   * COL: 0x00E7E594
   *
   * Reflection TypeInfo descriptor for `moho::CEfxEmitter`.
   * Inherits `gpg::RType` and registers lifetime/reflection
   * callbacks for the emitter effect type.
   */
  class CEfxEmitterTypeInfo final : public gpg::RType
  {
  public:
    /**
       * Address: 0x0065DFE0 (FUN_0065DFE0)
     * Mangled: ??0CEfxEmitterTypeInfo@Moho@@QAE@@Z
     *
     * What it does:
     * Constructs and preregisters RTTI ownership for `CEfxEmitter`.
     */
    CEfxEmitterTypeInfo();

    /**
     * Address: 0x0065E090 (FUN_0065E090, Moho::CEfxEmitterTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `CEfxEmitterTypeInfo`.
     */
    ~CEfxEmitterTypeInfo() override;

    /**
     * Address: 0x0065E080 (FUN_0065E080, Moho::CEfxEmitterTypeInfo::GetName)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0065E040 (FUN_0065E040, Moho::CEfxEmitterTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0065F790 (Moho::CEfxEmitterTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0065F830 (Moho::CEfxEmitterTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0065F810 (Moho::CEfxEmitterTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0065F8A0 (Moho::CEfxEmitterTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x0065F9A0 (Moho::CEfxEmitterTypeInfo::AddBase_CEffectImpl)
     */
    static void AddBase_CEffectImpl(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CEfxEmitterTypeInfo) == 0x64, "CEfxEmitterTypeInfo size must be 0x64");

  /**
    * Alias of FUN_0065DFE0 (non-canonical helper lane).
   *
   * What it does:
   * Constructs and preregisters startup RTTI metadata for `moho::CEfxEmitter`.
   */
  gpg::RType* register_CEfxEmitterTypeInfo_00();

  /**
   * Address: 0x00BFBD50 (FUN_00BFBD50)
   *
   * What it does:
   * Tears down startup-owned `CEfxEmitterTypeInfo` reflection storage.
   */
  void cleanup_CEfxEmitterTypeInfo();

  /**
   * Address: 0x00BD42F0 (FUN_00BD42F0)
   *
   * What it does:
   * Registers `CEfxEmitter` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEfxEmitterTypeInfo_AtExit();
} // namespace moho
