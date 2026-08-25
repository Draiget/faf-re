#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA54
   * COL:  0x00E73F44
   */
  class ReconBlipConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDCA0 (FUN_00BCDCA0, dynamic initializer for the global
     * `ReconBlipConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    ReconBlipConstruct();

    /**
     * Address: 0x00BF7900 (FUN_00BF7900, Moho::ReconBlipConstruct::~ReconBlipConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~ReconBlipConstruct();

    /**
     * Address: 0x005BFBC0 (FUN_005BFBC0, Moho::ReconBlipConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `ReconBlip::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005C9070 (FUN_005C9070, Moho::ReconBlipConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed object through its deleting-destructor vtable
     * entry when the pointer is non-null.
     */
    static void DeleteConstructedObject(void* objectPtr);

    /**
     * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into ReconBlip RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(ReconBlipConstruct, mConstructCallback) == 0x0C,
    "ReconBlipConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mDeleteCallback) == 0x10, "ReconBlipConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipConstruct) == 0x14, "ReconBlipConstruct size must be 0x14");
} // namespace moho
