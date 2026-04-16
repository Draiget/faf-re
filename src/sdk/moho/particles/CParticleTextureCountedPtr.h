#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/CountedObject.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CParticleTexture;
  template <class T>
  class RCountedPtrType;

  /**
   * What it does:
   * Models one intrusive counted-pointer lane to `CParticleTexture` used by
   * world beam/particle payload serialization.
   */
  using CountedPtr_CParticleTexture = CountedPtr<CParticleTexture>;

  static_assert(sizeof(CountedPtr_CParticleTexture) == 0x04, "CountedPtr_CParticleTexture size must be 0x04");
  static_assert(
    offsetof(CountedPtr_CParticleTexture, tex) == 0x00,
    "CountedPtr_CParticleTexture::tex offset must be 0x00"
  );

  template <>
  class RCountedPtrType<moho::CParticleTexture> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
       * Address: 0x0065AAD0 (FUN_0065AAD0)
     */
    RCountedPtrType();
    /**
     * Address: 0x0065AC80 (FUN_0065AC80, Moho::RCountedPtrType_CParticleTexture::dtr)
     */
    ~RCountedPtrType() override;

    /**
      * Alias of FUN_0065AAD0 (non-canonical helper lane).
     */
    [[nodiscard]] const char* GetName() const override;
    /**
     * Address: 0x00659C80 (FUN_00659C80, Moho::RCountedPtrType_CParticleTexture::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    /**
     * Address: 0x00659E00 (FUN_00659E00, Moho::RCountedPtrType_CParticleTexture::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    /**
     * Address: 0x00659E10 (FUN_00659E10, Moho::RCountedPtrType_CParticleTexture::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;
    /**
     * Address: 0x00659C60 (FUN_00659C60, Moho::RCountedPtrType_CParticleTexture::Init)
     */
    void Init() override;
    /**
     * Address: 0x00659E30 (FUN_00659E30, Moho::RCountedPtrType_CParticleTexture::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    /**
     * Address: 0x00659E20 (FUN_00659E20, Moho::RCountedPtrType_CParticleTexture::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0065A430 (FUN_0065A430, Moho::RCountedPtrType_CParticleTexture::SerLoad)
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    /**
     * Address: 0x0065A490 (FUN_0065A490, Moho::RCountedPtrType_CParticleTexture::SerSave)
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  static_assert(sizeof(RCountedPtrType<moho::CParticleTexture>) == 0x68, "RCountedPtrType<CParticleTexture> size must be 0x68");

  /**
   * Address: 0x004954E0 (FUN_004954E0, sub_4954E0)
   *
   * What it does:
   * Returns the raw particle-texture pointer lane from one counted-pointer
   * wrapper.
   */
  [[nodiscard]] CParticleTexture* GetCountedParticleTextureRawPointer(const CountedPtr_CParticleTexture& countedTexture
  ) noexcept;

  /**
   * Address: 0x004954B0 (FUN_004954B0, sub_4954B0)
   *
   * What it does:
   * Releases one counted particle-texture pointer lane and clears it.
   */
  void ResetCountedParticleTexturePtr(CountedPtr_CParticleTexture& countedTexture) noexcept;

  /**
   * Address: 0x004954F0 (FUN_004954F0, sub_4954F0)
   *
   * What it does:
   * Rebinds one counted particle-texture pointer lane while preserving
   * intrusive reference-count semantics.
   */
  CountedPtr_CParticleTexture* AssignCountedParticleTexturePtr(
    CountedPtr_CParticleTexture* target,
    CParticleTexture* texture
  ) noexcept;

  /**
    * Alias of FUN_0065AAD0 (non-canonical helper lane).
   */
  gpg::RType* preregister_CountedPtrCParticleTextureType();

  /**
   * Address: 0x00BFBBD0 (FUN_00BFBBD0, cleanup_CountedPtrCParticleTextureType)
   */
  void cleanup_CountedPtrCParticleTextureType();

  /**
   * Address: 0x00BD4140 (FUN_00BD4140, register_CountedPtrCParticleTextureTypeAtexit)
   */
  int register_CountedPtrCParticleTextureTypeAtexit();

  /**
   * Address: 0x0065AB40 (FUN_0065AB40, preregister_FastVectorCountedPtrCParticleTextureType)
   */
  gpg::RType* preregister_FastVectorCountedPtrCParticleTextureType();

  /**
   * Address: 0x00BFBB70 (FUN_00BFBB70, cleanup_FastVectorCountedPtrCParticleTextureType)
   */
  void cleanup_FastVectorCountedPtrCParticleTextureType();

  /**
   * Address: 0x00BD4160 (FUN_00BD4160, register_FastVectorCountedPtrCParticleTextureTypeAtexit)
   */
  int register_FastVectorCountedPtrCParticleTextureTypeAtexit();
} // namespace moho
