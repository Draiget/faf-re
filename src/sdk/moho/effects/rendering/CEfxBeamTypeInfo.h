#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEfxBeamTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00655EB0 (FUN_00655EB0, Moho::CEfxBeamTypeInfo::dtr)
     */
    ~CEfxBeamTypeInfo() override;

    /**
     * Address: 0x00655EA0 (FUN_00655EA0, Moho::CEfxBeamTypeInfo::GetName)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00655E60 (FUN_00655E60, Moho::CEfxBeamTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00658320 (Moho::CEfxBeamTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006583C0 (Moho::CEfxBeamTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006583A0 (Moho::CEfxBeamTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00658430 (Moho::CEfxBeamTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00658570 (Moho::CEfxBeamTypeInfo::AddBase_CEffectImpl)
     */
    static void AddBase_CEffectImpl(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CEfxBeamTypeInfo) == 0x64, "CEfxBeamTypeInfo size must be 0x64");

  /**
   * Address: 0x00655E00 (FUN_00655E00)
   *
   * What it does:
   * Constructs and preregisters startup RTTI metadata for `moho::CEfxBeam`.
   */
  gpg::RType* register_CEfxBeamTypeInfo_00();

  /**
   * Address: 0x00BFB8B0 (FUN_00BFB8B0)
   *
   * What it does:
   * Tears down startup-owned `CEfxBeamTypeInfo` reflection storage.
   */
  void cleanup_CEfxBeamTypeInfo();

  /**
   * Address: 0x00BD3F30 (FUN_00BD3F30)
   *
   * What it does:
   * Registers `CEfxBeam` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEfxBeamTypeInfo_AtExit();
} // namespace moho
