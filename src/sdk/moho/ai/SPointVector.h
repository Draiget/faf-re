#pragma once

#include <cstddef>

#include "Wm3Vector3.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  template <class T>
  class RVectorType;
  class ReadArchive;
  class WriteArchive;
  struct SerHelperBase;
  class RRef;
} // namespace gpg

namespace moho
{
  class SPointVectorTypeInfo;

  struct SPointVector
  {
    static gpg::RType* sType;

    /**
     * Address: 0x0050CF10 (FUN_0050CF10, Moho::SPointVector::MemberDeserialize)
     *
     * What it does:
     * Reads both `Vector3<float>` lanes for `SPointVector` from the archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0050CF90 (FUN_0050CF90, Moho::SPointVector::MemberSerialize)
     *
     * What it does:
     * Writes both `Vector3<float>` lanes for `SPointVector` into the archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    Wm3::Vector3<float> point;  // +0x00
    Wm3::Vector3<float> vector; // +0x0C
  };

  static_assert(offsetof(SPointVector, point) == 0x00, "SPointVector::point offset must be 0x00");
  static_assert(offsetof(SPointVector, vector) == 0x0C, "SPointVector::vector offset must be 0x0C");
  static_assert(sizeof(SPointVector) == 0x18, "SPointVector size must be 0x18");

  /**
   * Owns reflected metadata for `SPointVector`.
   */
  class SPointVectorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050C220 (FUN_0050C220, Moho::SPointVectorTypeInfo::SPointVectorTypeInfo)
     *
     * What it does:
     * Preregisters the `SPointVector` RTTI descriptor during startup.
     */
    SPointVectorTypeInfo();

    /**
     * Address: 0x0050C2B0 (FUN_0050C2B0, Moho::SPointVectorTypeInfo::dtr)
     *
     * What it does:
     * Releases the `SPointVector` reflection descriptor lanes.
     */
    ~SPointVectorTypeInfo() override;

    /**
     * Address: 0x0050C2A0 (FUN_0050C2A0, Moho::SPointVectorTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SPointVector`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050C280 (FUN_0050C280, Moho::SPointVectorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected width and finalizes the `SPointVector` type metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(SPointVectorTypeInfo) == 0x64, "SPointVectorTypeInfo size must be 0x64");

  /**
   * Serializer helper lane for `SPointVector`.
   */
  class SPointVectorSerializer
  {
  public:
    /**
     * Address: 0x0050C360 (FUN_0050C360, Moho::SPointVectorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load requests into `SPointVector::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, SPointVector* value);

    /**
     * Address: 0x0050C370 (FUN_0050C370, Moho::SPointVectorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save requests into `SPointVector::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, SPointVector* value);

    /**
     * What it does:
     * Binds the `SPointVector` serializer callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(SPointVectorSerializer, mHelperNext) == 0x04, "SPointVectorSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SPointVectorSerializer, mHelperPrev) == 0x08, "SPointVectorSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SPointVectorSerializer, mLoadCallback) == 0x0C, "SPointVectorSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(SPointVectorSerializer, mSaveCallback) == 0x10, "SPointVectorSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(SPointVectorSerializer) == 0x14, "SPointVectorSerializer size must be 0x14");

  /**
   * Address: 0x00BC7E00 (FUN_00BC7E00, register_SPointVectorSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `SPointVector` and installs process-exit
   * cleanup.
   */
  void register_SPointVectorSerializer();

  /**
   * Address: 0x00BC7DE0 (FUN_00BC7DE0, register_SPointVectorTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `SPointVectorTypeInfo` descriptor and installs
   * process-exit cleanup.
   */
  int register_SPointVectorTypeInfo();

  /**
   * Address: 0x005825A0 (FUN_005825A0, register_SPointVectorVectorType)
   *
   * What it does:
   * Constructs/preregisters RTTI for `msvc8::vector<moho::SPointVector>`.
   */
  [[nodiscard]] gpg::RType* register_SPointVectorVectorType();

  /**
   * Address: 0x00BCB470 (FUN_00BCB470, register_SPointVectorVectorType_AtExit)
   *
   * What it does:
   * Registers `vector<SPointVector>` reflection and installs process-exit
   * cleanup via `atexit`.
   */
  int register_SPointVectorVectorType_AtExit();
} // namespace moho

namespace gpg
{
  /**
   * Reflection/indexing adapter for `msvc8::vector<moho::SPointVector>`.
   */
  template <>
  class RVectorType<moho::SPointVector> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0057DF60 (FUN_0057DF60, gpg::RVectorType_SPointVector::GetName)
     *
     * What it does:
     * Lazily builds and caches the reflected type label
     * `vector<SPointVector>`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0057E020 (FUN_0057E020, gpg::RVectorType_SPointVector::GetLexical)
     *
     * What it does:
     * Returns the base lexical text plus `size=<count>` for one reflected
     * `vector<SPointVector>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0057E0B0 (FUN_0057E0B0, gpg::RVectorType_SPointVector::IsIndexed)
     *
     * What it does:
     * Exposes the `RIndexed` subobject for `vector<SPointVector>`.
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0057E000 (FUN_0057E000, gpg::RVectorType_SPointVector::Init)
     *
     * What it does:
     * Initializes `vector<SPointVector>` reflection metadata and serializer
     * callback lanes.
     */
    void Init() override;

    /**
     * Address: 0x0057F2D0 (FUN_0057F2D0, gpg::RVectorType_SPointVector::SerLoad)
     *
     * What it does:
     * Loads one `vector<SPointVector>` payload from archive and replaces the
     * destination storage.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0057F400 (FUN_0057F400, gpg::RVectorType_SPointVector::SerSave)
     *
     * What it does:
     * Saves one `vector<SPointVector>` payload to archive element-by-element.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0057E160 (FUN_0057E160, gpg::RVectorType_SPointVector::SubscriptIndex)
     *
     * What it does:
     * Returns one reflected element reference at index `ind`.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0057E0C0 (FUN_0057E0C0, gpg::RVectorType_SPointVector::GetCount)
     *
     * What it does:
     * Returns element count for one reflected `vector<SPointVector>` payload.
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0057E0F0 (FUN_0057E0F0, gpg::RVectorType_SPointVector::SetCount)
     *
     * What it does:
     * Resizes one reflected `vector<SPointVector>` payload using zero
     * `SPointVector` fill for growth lanes.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType<moho::SPointVector>) == 0x68, "RVectorType<SPointVector> size must be 0x68");
} // namespace gpg
