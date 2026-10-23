#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E171B4
   * COL: 0x00E6B6E4
   */
  class CSimResourcesTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00546A20 (FUN_00546A20, Moho::CSimResourcesTypeInfo::CSimResourcesTypeInfo)
     *
     * What it does:
     * Initializes the base reflection type state and preregisters RTTI
     * ownership for `CSimResources`.
     */
    CSimResourcesTypeInfo();

    /**
     * Address: 0x00546AD0 (FUN_00546AD0, Moho::CSimResourcesTypeInfo::dtr)
     * Slot: 2
     */
    ~CSimResourcesTypeInfo() override;

    /**
     * Address: 0x00546AC0 (FUN_00546AC0, Moho::CSimResourcesTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `CSimResources`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00546A80 (FUN_00546A80, Moho::CSimResourcesTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `CSimResources` reflection size metadata and binds typed
     * new/construct/delete/destruct callbacks before finalization.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005487E0 (FUN_005487E0, Moho::CSimResourcesTypeInfo::AddBase_ISimResources)
     *
     * What it does:
     * Registers `ISimResources` as reflection base metadata at offset `0`.
     */
    static void AddBase_ISimResources(gpg::RType* typeInfo);

    /**
     * Address: 0x005484A0 (FUN_005484A0, Moho::CSimResourcesTypeInfo::NewRef)
     *
     * What it does:
     * Allocates + default-constructs one `CSimResources` and returns its typed
     * reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00548530 (FUN_00548530, Moho::CSimResourcesTypeInfo::CtrRef)
     *
     * What it does:
     * Default-constructs one `CSimResources` in caller-provided storage and
     * returns its typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectPtr);

    /**
     * Address: 0x00548510 (FUN_00548510, Moho::CSimResourcesTypeInfo::Delete)
     *
     * What it does:
     * Deletes one `CSimResources` object through its virtual deleting
     * destructor.
     */
    static void Delete(void* objectPtr);

    /**
     * Address: 0x005485A0 (FUN_005485A0, Moho::CSimResourcesTypeInfo::Destruct)
     *
     * What it does:
     * Runs `CSimResources` non-deleting destructor on in-place storage.
     */
    static void Destruct(void* objectPtr);
  };

  /**
   * Address: 0x00BC96B0 (FUN_00BC96B0, register_CSimResourcesTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CSimResourcesTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_CSimResourcesTypeInfo();

  static_assert(sizeof(CSimResourcesTypeInfo) == 0x64, "CSimResourcesTypeInfo size must be 0x64");
} // namespace moho
