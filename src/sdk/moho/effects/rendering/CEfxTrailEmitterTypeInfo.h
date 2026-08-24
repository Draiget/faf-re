#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEfxTrailEmitterTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00671F80 (FUN_00671F80, Moho::CEfxTrailEmitterTypeInfo::dtr)
     */
    ~CEfxTrailEmitterTypeInfo() override;

    /**
     * Address: 0x00671F70 (FUN_00671F70, Moho::CEfxTrailEmitterTypeInfo::GetName)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00671F30 (FUN_00671F30, Moho::CEfxTrailEmitterTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00672380 (FUN_00672380, Moho::CEfxTrailEmitterTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00672410 (FUN_00672410, Moho::CEfxTrailEmitterTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006723F0 (FUN_006723F0, Moho::CEfxTrailEmitterTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00672480 (FUN_00672480, Moho::CEfxTrailEmitterTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00672490 (FUN_00672490, Moho::CEfxTrailEmitterTypeInfo::AddBase_CEffectImpl)
     */
    static void AddBase_CEffectImpl(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CEfxTrailEmitterTypeInfo) == 0x64, "CEfxTrailEmitterTypeInfo size must be 0x64");

  /**
   * Address: 0x00671ED0 (FUN_00671ED0)
   *
   * What it does:
   * Constructs and preregisters startup RTTI metadata for `moho::CEfxTrailEmitter`.
   */
  gpg::RType* register_CEfxTrailEmitterTypeInfo_00();

  /**
   * Address: 0x00BFC1F0 (FUN_00BFC1F0)
   *
   * What it does:
   * Tears down startup-owned `CEfxTrailEmitterTypeInfo` reflection storage.
   */
  void cleanup_CEfxTrailEmitterTypeInfo();

  /**
   * Address: 0x00BD4950 (FUN_00BD4950)
   *
   * What it does:
   * Registers `CEfxTrailEmitter` RTTI bootstrap and installs process-exit
   * cleanup.
   */
  int register_CEfxTrailEmitterTypeInfo_AtExit();
} // namespace moho
