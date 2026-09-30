#include "moho/animation/IAniManipulator.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniPose.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  class SAniManipBindingTypeInfo final : public gpg::RType
  {
  public:
    ~SAniManipBindingTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  static_assert(sizeof(SAniManipBindingTypeInfo) == 0x64, "SAniManipBindingTypeInfo size must be 0x64");
  /**
   * Address: 0x0063B270 (FUN_0063B270, preregister_SAniManipBindingTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `SAniManipBinding`.
   */
  gpg::RType* preregister_SAniManipBindingTypeInfo();

  /**
   * Address: 0x00BD2BA0 (FUN_00BD2BA0, register_SAniManipBindingTypeInfo)
   *
   * What it does:
   * Preregisters `SAniManipBinding` RTTI.
   */
  void register_SAniManipBindingTypeInfo();

  /**
   * Address: 0x0063D0E0 (FUN_0063D0E0, preregister_FastVectorSAniManipBindingType)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `gpg::fastvector<SAniManipBinding>`.
   */
  gpg::RType* preregister_FastVectorSAniManipBindingType();

  /**
   * Address: 0x00BD2CC0 (FUN_00BD2CC0, register_FastVectorSAniManipBindingType)
   *
   * What it does:
   * Preregisters `fastvector<SAniManipBinding>` RTTI.
   */
  void register_FastVectorSAniManipBindingType();
} // namespace moho

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::SAniManipBinding> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0063D1B0 (FUN_0063D1B0, gpg::RFastVectorType_SAniManipBinding::dtr)
     */
    ~RFastVectorType() override;

    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SAniManipBinding>) == 0x68,
    "RFastVectorType<SAniManipBinding> size must be 0x68"
  );
} // namespace gpg

namespace
{
  using SAniManipBindingTypeInfo = moho::SAniManipBindingTypeInfo;
  using FastVectorSAniManipBindingType = gpg::RFastVectorType<moho::SAniManipBinding>;

  /**
   * Address: 0x00BFAD30 (FUN_00BFAD30, atexit destructor of the SAniManipBindingTypeInfo object)
   */
  [[nodiscard]] SAniManipBindingTypeInfo* AcquireSAniManipBindingTypeInfo()
  {
    static SAniManipBindingTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BFAE80 (FUN_00BFAE80, atexit destructor of the FastVectorSAniManipBindingType object)
   */
  [[nodiscard]] FastVectorSAniManipBindingType* AcquireFastVectorSAniManipBindingType()
  {
    static FastVectorSAniManipBindingType sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* CachedSAniManipBindingType()
  {
    if (!moho::SAniManipBinding::sType) {
      moho::SAniManipBinding::sType = gpg::LookupRType(typeid(moho::SAniManipBinding));
    }
    return moho::SAniManipBinding::sType;
  }

  struct SAniManipBindingRuntimeInlineView
  {
    moho::SAniManipBinding* begin = nullptr;
    moho::SAniManipBinding* end = nullptr;
    moho::SAniManipBinding* capacityEnd = nullptr;
    moho::SAniManipBinding* inlineStorage = nullptr;
  };
  static_assert(
    sizeof(SAniManipBindingRuntimeInlineView) == 0x10,
    "SAniManipBindingRuntimeInlineView size must be 0x10"
  );

  /**
   * Address: 0x0063C780 (FUN_0063C780)
   *
   * What it does:
   * Initializes one inline fastvector-style runtime view where `begin=end` at
   * the inline storage base and capacity spans two `SAniManipBinding` lanes.
   */
  [[maybe_unused]] SAniManipBindingRuntimeInlineView*
  InitializeSAniManipBindingRuntimeInlineView(
    SAniManipBindingRuntimeInlineView* const outView,
    moho::SAniManipBinding* const inlineStorageBase
  ) noexcept
  {
    outView->begin = inlineStorageBase;
    outView->end = inlineStorageBase;
    outView->capacityEnd = inlineStorageBase + 2;
    outView->inlineStorage = inlineStorageBase;
    return outView;
  }

  /**
   * Address: 0x0063C7A0 (FUN_0063C7A0, gpg::RFastVectorType_SAniManipBinding::SerLoad)
   *
   * What it does:
   * Loads a `fastvector<SAniManipBinding>` runtime view and deserializes each element.
   */
  void LoadFastVectorSAniManipBinding(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    auto& vec = *reinterpret_cast<gpg::fastvector<moho::SAniManipBinding>*>(objectPtr);
    moho::SAniManipBinding fill{};
    vec.Resize(static_cast<std::size_t>(count), fill);

    gpg::RType* const elementType = CachedSAniManipBindingType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &vec[i], owner);
    }
  }

  /**
   * Address: 0x0063C830 (FUN_0063C830, gpg::RFastVectorType_SAniManipBinding::SerSave)
   *
   * What it does:
   * Saves a `fastvector<SAniManipBinding>` runtime view and serializes each element.
   */
  void SaveFastVectorSAniManipBinding(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& vec = *reinterpret_cast<gpg::fastvector<moho::SAniManipBinding>*>(objectPtr);
    const unsigned int count = static_cast<unsigned int>(vec.size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSAniManipBindingType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &vec[i], owner);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* SAniManipBinding::sType = nullptr;

  /**
   * Address: 0x0063B300 (FUN_0063B300, Moho::SAniManipBindingTypeInfo::dtr)
   */
  SAniManipBindingTypeInfo::~SAniManipBindingTypeInfo() = default;

  /**
   * Address: 0x0063B2F0 (FUN_0063B2F0, Moho::SAniManipBindingTypeInfo::GetName)
   */
  const char* SAniManipBindingTypeInfo::GetName() const
  {
    return "SAniManipBinding";
  }

  /**
   * Address: 0x0063B2D0 (FUN_0063B2D0, Moho::SAniManipBindingTypeInfo::Init)
   */
  void SAniManipBindingTypeInfo::Init()
  {
    size_ = sizeof(SAniManipBinding);
    gpg::RType::Init();
    version_ = 2;
    Finish();
  }

  /**
   * Address: 0x0063B270 (FUN_0063B270, preregister_SAniManipBindingTypeInfo)
   */
  gpg::RType* preregister_SAniManipBindingTypeInfo()
  {
    SAniManipBindingTypeInfo* const typeInfo = AcquireSAniManipBindingTypeInfo();
    gpg::PreRegisterRType(typeid(SAniManipBinding), typeInfo);
    SAniManipBinding::sType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BD2BA0 (FUN_00BD2BA0, register_SAniManipBindingTypeInfo)
   */
  void register_SAniManipBindingTypeInfo()
  {
    (void)preregister_SAniManipBindingTypeInfo();
  }

} // namespace moho

namespace gpg
{
  RFastVectorType<moho::SAniManipBinding>::~RFastVectorType() = default;

  /**
   * Address: 0x0063C320 (FUN_0063C320, gpg::RFastVectorType_SAniManipBinding::GetName)
   * Address: 0x00BFAE50 (FUN_00BFAE50, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `fastvector<SAniManipBinding>` once and returns it.
   */
  const char* RFastVectorType<moho::SAniManipBinding>::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("fastvector<%s>", CachedSAniManipBindingType()->GetName());
    return sName.c_str();
  }

  /**
   * Address: 0x0063C3E0 (FUN_0063C3E0, gpg::RFastVectorType_SAniManipBinding::GetLexical)
   */
  msvc8::string RFastVectorType<moho::SAniManipBinding>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0063C470 (FUN_0063C470, gpg::RFastVectorType_SAniManipBinding::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::SAniManipBinding>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0063C3C0 (FUN_0063C3C0, gpg::RFastVectorType_SAniManipBinding::Init)
   */
  void RFastVectorType<moho::SAniManipBinding>::Init()
  {
    static_assert(sizeof(gpg::core::FastVectorInline<moho::SAniManipBinding>) == 0x10, "gpg::core::FastVectorInline<moho::SAniManipBinding> is 0x10 bytes on x86");
    size_ = sizeof(gpg::core::FastVectorInline<moho::SAniManipBinding>);
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorSAniManipBinding;
    serSaveFunc_ = &SaveFastVectorSAniManipBinding;
  }

  gpg::RRef RFastVectorType<moho::SAniManipBinding>::SubscriptIndex(void* obj, const int ind) const
  {
    gpg::RRef out{};
    out.mType = CachedSAniManipBindingType();
    out.mObj = nullptr;
    if (!obj || ind < 0) {
      return out;
    }

    auto& vec = *static_cast<gpg::fastvector<moho::SAniManipBinding>*>(obj);
    if (vec.Data() == nullptr || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    out.mObj = vec.Data() + ind;
    return out;
  }

  size_t RFastVectorType<moho::SAniManipBinding>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    auto& vec = *static_cast<gpg::fastvector<moho::SAniManipBinding>*>(obj);
    if (vec.Data() == nullptr) {
      return 0u;
    }

    return vec.size();
  }

  void RFastVectorType<moho::SAniManipBinding>::SetCount(void* obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& vec = *static_cast<gpg::fastvector<moho::SAniManipBinding>*>(obj);
    moho::SAniManipBinding fill{};
    vec.Resize(static_cast<std::size_t>(count), fill);
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0063D0E0 (FUN_0063D0E0, preregister_FastVectorSAniManipBindingType)
   */
  gpg::RType* preregister_FastVectorSAniManipBindingType()
  {
    FastVectorSAniManipBindingType* const typeInfo = AcquireFastVectorSAniManipBindingType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<SAniManipBinding>), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BD2CC0 (FUN_00BD2CC0, register_FastVectorSAniManipBindingType)
   */
  void register_FastVectorSAniManipBindingType()
  {
    (void)preregister_FastVectorSAniManipBindingType();
  }
} // namespace moho

namespace
{
  struct SAniManipBindingReflectionBootstrap
  {
    SAniManipBindingReflectionBootstrap()
    {
      moho::register_SAniManipBindingTypeInfo();
      moho::register_FastVectorSAniManipBindingType();
    }
  };

  [[maybe_unused]] SAniManipBindingReflectionBootstrap gSAniManipBindingReflectionBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SAniManipBindingTypeInfo_c664d9, moho::preregister_SAniManipBindingTypeInfo)
GPG_PREREGISTER_INIT(preregister_FastVectorSAniManipBindingType_c664d9, moho::preregister_FastVectorSAniManipBindingType)
GPG_PREREGISTER_INIT(register_FastVectorSAniManipBindingType_c664d9, moho::register_FastVectorSAniManipBindingType)

namespace moho
{
  /**
   * Address: 0x0063CCA0 (FUN_0063CCA0, sub_63CCA0)
   *
   * IDA signature:
   * int __usercall sub_63CCA0@<eax>(int a1@<eax>, gpg::ReadArchive *a2@<ecx>, int a3);
   *
   * What it does:
   * Deserializes one `SAniManipBinding` payload (one `int` bone index plus a
   * pair of `ushort`/`short` halves combined into the 32-bit flag word). When
   * loading a pre-version-2 archive, also drains and discards a legacy
   * `CAniPose*` pointer slot that older snapshots wrote ahead of the fields.
   */
  void SAniManipBinding::MemberDeserialize(gpg::ReadArchive* const archive, const int version, const gpg::RRef&)
  {
    if (version < 2) {
      moho::CAniPose* discardedAniPose = nullptr;
      const gpg::RRef nullOwner{};
      archive->ReadPointer(&discardedAniPose, &nullOwner);
    }

    archive->ReadInt(&mBoneIndex);
    unsigned short lowFlags = 0;
    short highFlags = 0;
    archive->ReadUShort(&lowFlags);
    archive->ReadShort(&highFlags);

    const std::uint32_t combined =
      static_cast<std::uint32_t>(lowFlags)
      | (static_cast<std::uint32_t>(static_cast<std::uint16_t>(highFlags)) << 16);
    mFlags = static_cast<std::int32_t>(combined);
  }

  /**
   * Address: 0x0063CD00 (FUN_0063CD00)
   *
   * What it does:
   * Serializes one `SAniManipBinding`, preserving the version-1 raw-pointer
   * compatibility lane when older archive versions are requested.
   */
  void SAniManipBinding::MemberSerialize(gpg::WriteArchive* const archive, const int version, const gpg::RRef&) const
  {
    if (version < 2) {
      const gpg::RRef nullRef{};
      const gpg::RRef nullOwner{};
      gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

    archive->WriteInt(mBoneIndex);
    const std::uint32_t rawFlags = static_cast<std::uint32_t>(mFlags);
    archive->WriteUShort(static_cast<unsigned short>(rawFlags & 0xFFFFu));
    archive->WriteShort(static_cast<short>((rawFlags >> 16) & 0xFFFFu));
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SAniManipBinding>`, vtable 0x00E21F14.
   *
   * Address: 0x00BD2BC0 (FUN_00BD2BC0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFAD90 (FUN_00BFAD90 -- the global's destructor.)
   * Address: 0x0063C2B0 (FUN_0063C2B0 -- `Init`.)
   * Address: 0x0063B3B0 (FUN_0063B3B0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0063B3D0 (FUN_0063B3D0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SAniManipBindingSerializer : gpg::SerSaveLoadHelper<SAniManipBinding>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B28C8 -- process-global `SAniManipBindingSerializer` singleton.
  moho::SAniManipBindingSerializer gSAniManipBindingSerializer;
} // namespace
