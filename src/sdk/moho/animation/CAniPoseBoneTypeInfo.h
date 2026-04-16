#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniPose.h"

namespace moho
{
  class CAniPoseBoneTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0054BB50 (FUN_0054BB50, scalar deleting destructor thunk)
     */
    ~CAniPoseBoneTypeInfo() override;

    /**
     * Address: 0x0054BB40 (FUN_0054BB40, Moho::CAniPoseBoneTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0054BB20 (FUN_0054BB20, Moho::CAniPoseBoneTypeInfo::Init)
     *
     * What it does:
     * Initializes reflection metadata for `CAniPoseBone` (`sizeof = 0x4C`).
     */
    void Init() override;
  };

  static_assert(sizeof(CAniPoseBoneTypeInfo) == 0x64, "CAniPoseBoneTypeInfo size must be 0x64");

  /**
   * Address: 0x0054BAC0 (FUN_0054BAC0, preregister_CAniPoseBoneTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `CAniPoseBone`.
   */
  [[nodiscard]] gpg::RType* preregister_CAniPoseBoneTypeInfo();

  /**
   * Address: 0x00BF4640 (FUN_00BF4640, cleanup_CAniPoseBoneTypeInfo)
   *
   * What it does:
   * Releases startup-owned `CAniPoseBoneTypeInfo` field/base metadata storage.
   */
  void cleanup_CAniPoseBoneTypeInfo();

  /**
   * Address: 0x00BC99A0 (FUN_00BC99A0, register_CAniPoseBoneTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `CAniPoseBone` RTTI and installs process-exit cleanup.
   */
  int register_CAniPoseBoneTypeInfoAtexit();

  /**
   * Address: 0x0054E370 (FUN_0054E370, preregister_FastVectorCAniPoseBoneType)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for
   * `gpg::fastvector<CAniPoseBone>`.
   */
  [[nodiscard]] gpg::RType* preregister_FastVectorCAniPoseBoneType();

  /**
   * Address: 0x00BF4700 (FUN_00BF4700, cleanup_FastVectorCAniPoseBoneType)
   *
   * What it does:
   * Releases startup-owned `fastvector<CAniPoseBone>` reflection metadata.
   */
  void cleanup_FastVectorCAniPoseBoneType();

  /**
   * Address: 0x00BC9A00 (FUN_00BC9A00, register_FastVectorCAniPoseBoneTypeAtexit)
   *
   * What it does:
   * Preregisters `fastvector<CAniPoseBone>` RTTI and installs process-exit
   * cleanup.
   */
  int register_FastVectorCAniPoseBoneTypeAtexit();
} // namespace moho

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::CAniPoseBone> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0054E440 (FUN_0054E440, scalar deleting destructor thunk)
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x0054C680 (FUN_0054C680, gpg::RFastVectorType_CAniPoseBone::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0054C740 (FUN_0054C740, gpg::RFastVectorType_CAniPoseBone::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0054C7D0 (FUN_0054C7D0, gpg::RFastVectorType_CAniPoseBone::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0054C720 (FUN_0054C720, gpg::RFastVectorType_CAniPoseBone::Init)
     *
     * What it does:
     * Initializes reflected fast-vector size/version and serializer callbacks.
     */
    void Init() override;

    /**
     * Address: 0x0054C880 (FUN_0054C880, gpg::RFastVectorType_CAniPoseBone::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0054C7E0 (FUN_0054C7E0, gpg::RFastVectorType_CAniPoseBone::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0054C800 (FUN_0054C800, gpg::RFastVectorType_CAniPoseBone::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<moho::CAniPoseBone>) == 0x68, "RFastVectorType<CAniPoseBone> size must be 0x68");
} // namespace gpg
