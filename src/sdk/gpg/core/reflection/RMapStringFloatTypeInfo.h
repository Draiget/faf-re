#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  /**
   * Reflection descriptor for `std::map<std::string,float>`.
   *
   * VFTABLE: `gpg::RMapType<std::string,float>`
   * COL: from startup lane around `FUN_006B16B0`.
   */
  class RMapStringFloatTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006AE290 (FUN_006AE290, gpg::RMapType_string_float::GetName)
     *
     * What it does:
     * Builds/caches the lexical map type label from runtime key/value RTTI
     * names and returns `"map<key,value>"`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006AF250 (FUN_006AF250, gpg::RMapType_string_float::SerLoad)
     *
     * What it does:
     * Clears destination map storage, then reads `count` key/value pairs and
     * inserts them into `std::map<std::string,float>`.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006AF390 (FUN_006AF390, gpg::RMapType_string_float::SerSave)
     *
     * What it does:
     * Writes map size and serializes each key/value pair in map-order.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006AE350 (FUN_006AE350, gpg::RMapType_string_float::Init)
     *
     * What it does:
     * Initializes reflected size/version metadata and binds map serializer
     * callbacks.
     */
    void Init() override;
  };

  static_assert(sizeof(RMapStringFloatTypeInfo) == 0x64, "RMapStringFloatTypeInfo size must be 0x64");

  /**
   * Address: 0x006B16B0 (FUN_006B16B0, register_MapStringFloat_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `std::map<std::string,float>`.
   */
  [[nodiscard]] gpg::RType* register_MapStringFloat_Type_00();

  /**
   * Address: 0x00BFDBE0 (FUN_00BFDBE0, cleanup_MapStringFloat_Type)
   *
   * What it does:
   * Tears down startup-owned `std::map<std::string,float>` RTTI storage.
   */
  void cleanup_MapStringFloat_Type();

  /**
   * Address: 0x00BD6BC0 (FUN_00BD6BC0, register_MapStringFloat_Type_AtExit)
   *
   * What it does:
   * Registers `std::map<std::string,float>` RTTI and installs process-exit
   * cleanup.
   */
  int register_MapStringFloat_Type_AtExit();
} // namespace gpg
