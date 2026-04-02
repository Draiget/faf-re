#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EmitterTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
     */
    ~EmitterTypeTypeInfo() override;

    /**
     * Address: 0x0065DF30 (FUN_0065DF30)
     *
     * What it does:
     * Returns the reflection type name literal for EmitterType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0065DF10 (FUN_0065DF10)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EmitterTypeTypeInfo) == 0x78, "EmitterTypeTypeInfo size must be 0x78");

  /**
   * VFTABLE: 0x00E2416C
   * COL: 0x00E7E4A8
   */
  class EmitterTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0065EE50 (FUN_0065EE50, gpg::PrimitiveSerHelper<moho::EmitterType,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EmitterType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EmitterTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EmitterTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EmitterTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EmitterTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EmitterTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "EmitterTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EmitterTypePrimitiveSerializer, mSerialize) == 0x10,
    "EmitterTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EmitterTypePrimitiveSerializer) == 0x14, "EmitterTypePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x0065DEB0 (FUN_0065DEB0, register_EmitterTypeTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::EmitterType`.
   */
  gpg::RType* register_EmitterTypeTypeInfo_00();

  /**
   * Address: 0x00BFBD10 (FUN_00BFBD10, cleanup_EmitterTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EmitterTypeTypeInfo` reflection storage.
   */
  void cleanup_EmitterTypeTypeInfo();

  /**
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo_AtExit)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_EmitterTypeTypeInfo_AtExit();

  /**
   * Address: 0x00BFBD20 (FUN_00BFBD20, cleanup_EmitterTypePrimitiveSerializer)
   *
   * What it does:
   * Unlinks startup `EmitterType` primitive serializer helper node.
   */
  gpg::SerHelperBase* cleanup_EmitterTypePrimitiveSerializer();

  /**
   * Address: 0x00BD42B0 (FUN_00BD42B0, register_EmitterTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `EmitterType` and installs
   * process-exit cleanup.
   */
  int register_EmitterTypePrimitiveSerializer();
} // namespace moho
