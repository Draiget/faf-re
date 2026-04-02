#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E361E4
   * COL:  0x00E8FCAC
   */
  class CIntelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0076E550 (FUN_0076E550, Moho::CIntelTypeInfo::CIntelTypeInfo)
     *
     * What it does:
     * Constructs `CIntel` type-info storage and preregisters its RTTI mapping.
     */
    CIntelTypeInfo();

    /**
     * Address: 0x0076E600 (FUN_0076E600, Moho::CIntelTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk for CIntelTypeInfo.
     */
    ~CIntelTypeInfo() override;

    /**
     * Address: 0x0076E5F0 (FUN_0076E5F0, Moho::CIntelTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type label for CIntel.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0076E5B0 (FUN_0076E5B0, Moho::CIntelTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets CIntel size metadata, binds CIntel ref/delete callbacks, and
     * finalizes reflection registration for the type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0076E8B0 (FUN_0076E8B0, Moho::CIntelTypeInfo::NewRef)
     *
     * What it does:
     * Allocates a new CIntel object, default-constructs it, and returns a
     * typed reflection reference.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0076E950 (FUN_0076E950, Moho::CIntelTypeInfo::CtrRef)
     *
     * What it does:
     * Default-constructs a CIntel object in provided storage and returns a
     * typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectPtr);

    /**
     * Address: 0x0076E920 (FUN_0076E920, Moho::CIntelTypeInfo::Delete)
     *
     * What it does:
     * Destroys CIntel-owned intel handles and frees object storage.
     */
    static void Delete(void* objectPtr);

    /**
     * Address: 0x0076E9C0 (FUN_0076E9C0, Moho::CIntelTypeInfo::Destruct)
     *
     * What it does:
     * Destroys CIntel-owned intel handles without freeing object storage.
     */
    static void Destruct(void* objectPtr);
  };

  static_assert(sizeof(CIntelTypeInfo) == 0x64, "CIntelTypeInfo size must be 0x64");

  /**
   * Address: 0x00C01D90 (FUN_00C01D90, cleanup_CIntelTypeInfo)
   *
   * What it does:
   * Runs process-exit teardown for startup `CIntelTypeInfo` storage.
   */
  void cleanup_CIntelTypeInfo();

  /**
   * Address: 0x00BDCBC0 (FUN_00BDCBC0, register_CIntelTypeInfo)
   *
   * What it does:
   * Builds startup `CIntelTypeInfo` storage and installs process-exit cleanup.
   */
  void register_CIntelTypeInfo();
} // namespace moho
