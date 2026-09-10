#include "moho/sim/SDelayedSubVizInfoReflection.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using DelayedSubVizVector = msvc8::vector<moho::SDelayedSubVizInfo>;
  using DelayedSubVizVectorType = gpg::RVectorType<moho::SDelayedSubVizInfo>;

  alignas(DelayedSubVizVectorType) unsigned char gDelayedSubVizVectorTypeStorage[sizeof(DelayedSubVizVectorType)];
  bool gDelayedSubVizVectorTypeConstructed = false;

  msvc8::string gDelayedSubVizVectorTypeName;
  bool gDelayedSubVizVectorTypeNameCleanupRegistered = false;

  // Address: 0x00BC78E0 (FUN_00BC78E0, register_SDelayedSubVizInfoSerializer)
  // -- MSVC's own compiler-generated dynamic initializer for this global; see
  // gpg::SerSaveLoadHelper<T>'s class-level comment in Reflection.h (same
  // shape already established for gpg::PrimitiveSerHelper<T,IntType>).
  moho::SDelayedSubVizInfoSerializer gSDelayedSubVizInfoSerializer;
  [[nodiscard]] DelayedSubVizVectorType* AcquireDelayedSubVizVectorType();

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  /**
   * Address: 0x00508270 (FUN_00508270, delayed-sub-viz RTTI cache resolve)
   */
  [[nodiscard]] gpg::RType* ResolveSDelayedSubVizInfoType()
  {
    gpg::RType* type = moho::SDelayedSubVizInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SDelayedSubVizInfo));
      moho::SDelayedSubVizInfo::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00508290 (FUN_00508290, intel-grid RTTI cache resolve)
   *
   * Orphan: zero xrefs at this address in the IDA export (xrefs_total: 0),
   * zero callers in the callgraph index, and `moho::CIntelGrid` is not
   * referenced anywhere else in this file -- `SDelayedSubVizInfo` (this
   * file's own subject, `{mLastPos, mRadius, mTicksTilUpdate}`) has no
   * `CIntelGrid`-typed field. A separate, real, actively-used
   * `ResolveCIntelGridType()` exists in
   * `moho/ai/CAiReconDBImplSerializer.cpp` (its own anonymous-namespace
   * copy, called 9x serializing `CAiReconDBImpl`'s grid members) and
   * `CIntelGrid.cpp` has its own third copy under the name
   * `CachedIntelGridType()` (used by `RRef_CIntelGrid`/`MakeCIntelGridRef`)
   * -- both are distinct, independently-evidenced functions at different
   * addresses, not ODR conflicts with this one. No caller for this specific
   * copy has been found.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveCIntelGridType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelGrid));
    }
    return cached;
  }

  /**
   * Address: 0x00508DE0 (FUN_00508DE0, delayed-sub-viz vector-type construct/register)
   */
  [[nodiscard]] gpg::RType* ConstructAndRegisterDelayedSubVizVectorType()
  {
    DelayedSubVizVectorType* const type = AcquireDelayedSubVizVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<moho::SDelayedSubVizInfo>), type);
    return type;
  }

  /**
   * Address: 0x00508B30 (FUN_00508B30, delayed-sub-viz typed read helper)
   */
  gpg::ReadArchive* ReadDelayedSubVizInfoViaRTypeVariant1(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    if (archive && object && elementType) {
      archive->Read(elementType, object, ownerRef ? *ownerRef : gpg::RRef{});
    }
    return archive;
  }

  /**
   * Address: 0x00508E90 (FUN_00508E90, delayed-sub-viz typed read helper duplicate)
   */
  void ReadDelayedSubVizInfoViaRTypeVariant2(
    gpg::ReadArchive* const archive, void* const object, const gpg::RRef* const ownerRef
  )
  {
    (void)ReadDelayedSubVizInfoViaRTypeVariant1(archive, object, ownerRef);
  }

  /**
   * Address: 0x00508BA0 (FUN_00508BA0, delayed-sub-viz typed write helper)
   */
  gpg::WriteArchive* WriteDelayedSubVizInfoViaRTypeVariant1(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef* const ownerRef
  )
  {
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    if (archive && object && elementType) {
      archive->Write(elementType, object, ownerRef ? *ownerRef : gpg::RRef{});
    }
    return archive;
  }

  /**
   * Address: 0x00508EC0 (FUN_00508EC0, delayed-sub-viz typed write helper duplicate)
   */
  void WriteDelayedSubVizInfoViaRTypeVariant2(
    gpg::WriteArchive* const archive, const void* const object, const gpg::RRef* const ownerRef
  )
  {
    (void)WriteDelayedSubVizInfoViaRTypeVariant1(archive, object, ownerRef);
  }

  /**
   * Address: 0x00508AD0 (FUN_00508AD0, delayed-sub-viz RRef fill helper)
   */
  gpg::RRef* FillDelayedSubVizRef(
    moho::SDelayedSubVizInfo* const value, gpg::RRef* const outRef
  )
  {
    return gpg::RRef_SDelayedSubVizInfo(outRef, value);
  }

  [[nodiscard]] DelayedSubVizVectorType* AcquireDelayedSubVizVectorType()
  {
    if (!gDelayedSubVizVectorTypeConstructed) {
      new (gDelayedSubVizVectorTypeStorage) DelayedSubVizVectorType();
      gDelayedSubVizVectorTypeConstructed = true;
    }
    return reinterpret_cast<DelayedSubVizVectorType*>(gDelayedSubVizVectorTypeStorage);
  }

  [[nodiscard]] DelayedSubVizVectorType* PeekDelayedSubVizVectorType() noexcept
  {
    if (!gDelayedSubVizVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<DelayedSubVizVectorType*>(gDelayedSubVizVectorTypeStorage);
  }

  /**
   * Address: 0x00BF1E80 (FUN_00BF1E80, delayed-sub-viz vector name cleanup)
   *
   * What it does:
   * Releases cached `vector<SDelayedSubVizInfo>` type-name storage.
   */
  void cleanup_SDelayedSubVizInfoVectorTypeName()
  {
    gDelayedSubVizVectorTypeName = msvc8::string{};
    gDelayedSubVizVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x005080C0 (FUN_005080C0, gpg::RVectorType_SDelayedSubVizInfo::SerLoad)
   *
   * What it does:
   * Loads delayed-sub-viz vector elements from archive and replaces destination
   * storage.
   */
  void LoadSDelayedSubVizInfoVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const out = reinterpret_cast<DelayedSubVizVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(out != nullptr);
    if (!archive || !out) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    DelayedSubVizVector loaded{};
    loaded.reserve(static_cast<std::size_t>(count));
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();

    for (unsigned int i = 0; i < count; ++i) {
      moho::SDelayedSubVizInfo element{};
      if (elementType) {
        (void)ReadDelayedSubVizInfoViaRTypeVariant1(archive, &element, &owner);
      } else {
        element.MemberDeserialize(archive);
      }
      loaded.push_back(element);
    }

    *out = loaded;
  }

  /**
   * Address: 0x005081B0 (FUN_005081B0, gpg::RVectorType_SDelayedSubVizInfo::SerSave)
   *
   * What it does:
   * Saves delayed-sub-viz vector payload to archive element-by-element.
   */
  void SaveSDelayedSubVizInfoVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const source = reinterpret_cast<const DelayedSubVizVector*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(source != nullptr);
    if (!archive || !source) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(source->size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveSDelayedSubVizInfoType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    for (unsigned int i = 0; i < count; ++i) {
      const moho::SDelayedSubVizInfo& element = (*source)[static_cast<std::size_t>(i)];
      if (elementType) {
        (void)WriteDelayedSubVizInfoViaRTypeVariant1(archive, &element, &owner);
      } else {
        element.MemberSerialize(archive);
      }
    }
  }

  /**
   * What it does:
   * Destroys delayed-sub-viz vector type storage lanes at process exit.
   */
  void cleanup_SDelayedSubVizInfoVectorType()
  {
    DelayedSubVizVectorType* const type = PeekDelayedSubVizVectorType();
    if (!type) {
      return;
    }

    type->~DelayedSubVizVectorType();
    gDelayedSubVizVectorTypeConstructed = false;
  }

  struct SDelayedSubVizInfoReflectionBootstrap
  {
    SDelayedSubVizInfoReflectionBootstrap()
    {
      (void)moho::preregister_SDelayedSubVizInfoTypeInfo();
      moho::register_SDelayedSubVizInfoSerializer();
      (void)moho::register_SDelayedSubVizInfoVectorType_AtExit();
    }
  };

  SDelayedSubVizInfoReflectionBootstrap gSDelayedSubVizInfoReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00506FC0 (FUN_00506FC0 -- the implicit destructor of this type
   * (frees `fields_`/`bases_`, restores `RObject`'s vtable); no source line.
   * Zero callers, unreachable. Formerly transcribed as
   * `cleanup_SDelayedSubVizInfoTypeInfoRTypeBase`, removed 2026-09-10.)
   */
  class SDelayedSubVizInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SDelayedSubVizInfo";
    }

    void Init() override
    {
      size_ = sizeof(SDelayedSubVizInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x00506ED0 (FUN_00506ED0, preregister_SDelayedSubVizInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for `SDelayedSubVizInfo`.
   */
  gpg::RType* preregister_SDelayedSubVizInfoTypeInfo()
  {
    static SDelayedSubVizInfoTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SDelayedSubVizInfo), &typeInfo);
    return &typeInfo;
  }

  gpg::RType* SDelayedSubVizInfo::sType = nullptr;

  gpg::RType* SDelayedSubVizInfo::StaticGetClass()
  {
    return ResolveSDelayedSubVizInfoType();
  }

  /**
   * Address: 0x005088F0 (FUN_005088F0, Moho::SDelayedSubVizInfo::MemberDeserialize)
   */
  void SDelayedSubVizInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const vector3Type = ResolveVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3Type, &mLastPos, ownerRef);
    archive->ReadFloat(&mRadius);
    archive->ReadInt(&mTicksTilUpdate);
  }

  /**
   * Address: 0x00508950 (FUN_00508950, Moho::SDelayedSubVizInfo::MemberSerialize)
   */
  void SDelayedSubVizInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    gpg::RType* const vector3Type = ResolveVector3fType();
    gpg::RRef ownerRef{};
    archive->Write(vector3Type, &mLastPos, ownerRef);
    archive->WriteFloat(mRadius);
    archive->WriteInt(mTicksTilUpdate);
  }

  /**
   * Address: 0x00BC78E0 (FUN_00BC78E0, register_SDelayedSubVizInfoSerializer)
   *
   * What it does:
   * Forces this translation unit's global `SDelayedSubVizInfoSerializer`
   * instance to link into the reflection bootstrap sequence. The real
   * ctor/vtable-install/atexit-dtor-registration sequence this address
   * decompiles to is MSVC's own compiler-generated dynamic initializer for
   * `gSDelayedSubVizInfoSerializer` (see the Doxygen comment on that global
   * above), not hand-written source. `Deserialize`/`Serialize`/`Init()`
   * (0x00507010 / 0x00507020 / 0x00507CC0) are now
   * `gpg::SerSaveLoadHelper<SDelayedSubVizInfo>`'s own template bodies
   * (Reflection.h); `Init()` caches its `RType*` on
   * `SDelayedSubVizInfo::sType`, same slot `ResolveSDelayedSubVizInfoType()`
   * above already uses.
   */
  void register_SDelayedSubVizInfoSerializer()
  {
    (void)gSDelayedSubVizInfoSerializer;
  }

  gpg::RType* register_SDelayedSubVizInfoVectorType()
  {
    return ConstructAndRegisterDelayedSubVizVectorType();
  }

  /**
   * Address: 0x00BC79F0 (FUN_00BC79F0, register_SDelayedSubVizInfoVectorType_AtExit)
   */
  int register_SDelayedSubVizInfoVectorType_AtExit()
  {
    (void)register_SDelayedSubVizInfoVectorType();
    return std::atexit(&cleanup_SDelayedSubVizInfoVectorType);
  }
} // namespace moho

/**
 * Address: 0x00509410 (FUN_00509410, gpg::RRef_SDelayedSubVizInfo)
 */
gpg::RRef* gpg::RRef_SDelayedSubVizInfo(gpg::RRef* const outRef, moho::SDelayedSubVizInfo* const value)
{
  if (!outRef) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = moho::SDelayedSubVizInfo::StaticGetClass();
  return outRef;
}

/**
 * Address: 0x00507AA0 (FUN_00507AA0, gpg::RVectorType_SDelayedSubVizInfo::GetName)
 */
const char* gpg::RVectorType<moho::SDelayedSubVizInfo>::GetName() const
{
  if (gDelayedSubVizVectorTypeName.empty()) {
    const gpg::RType* const elementType = moho::SDelayedSubVizInfo::StaticGetClass();
    const char* const elementName = elementType ? elementType->GetName() : "SDelayedSubVizInfo";
    gDelayedSubVizVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SDelayedSubVizInfo");

    if (!gDelayedSubVizVectorTypeNameCleanupRegistered) {
      gDelayedSubVizVectorTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_SDelayedSubVizInfoVectorTypeName);
    }
  }

  return gDelayedSubVizVectorTypeName.c_str();
}

/**
 * Address: 0x00507B60 (FUN_00507B60, gpg::RVectorType_SDelayedSubVizInfo::GetLexical)
 */
msvc8::string gpg::RVectorType<moho::SDelayedSubVizInfo>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00507BF0 (FUN_00507BF0, gpg::RVectorType_SDelayedSubVizInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType<moho::SDelayedSubVizInfo>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00507B40 (FUN_00507B40, gpg::RVectorType_SDelayedSubVizInfo::Init)
 */
void gpg::RVectorType<moho::SDelayedSubVizInfo>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadSDelayedSubVizInfoVector;
  serSaveFunc_ = &SaveSDelayedSubVizInfoVector;
}

/**
 * Address: 0x00507C50 (FUN_00507C50, gpg::RVectorType_SDelayedSubVizInfo::SubscriptIndex)
 */
gpg::RRef gpg::RVectorType<moho::SDelayedSubVizInfo>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<DelayedSubVizVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  gpg::RRef_SDelayedSubVizInfo(&out, nullptr);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SDelayedSubVizInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00507C00 (FUN_00507C00, gpg::RVectorType_SDelayedSubVizInfo::GetCount)
 */
size_t gpg::RVectorType<moho::SDelayedSubVizInfo>::GetCount(void* const obj) const
{
  if (!obj) {
    return 0u;
  }

  return (*static_cast<const DelayedSubVizVector*>(obj)).size();
}

/**
 * Address: 0x00507C30 (FUN_00507C30, gpg::RVectorType_SDelayedSubVizInfo::SetCount)
 */
void gpg::RVectorType<moho::SDelayedSubVizInfo>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<DelayedSubVizVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  const moho::SDelayedSubVizInfo zeroFill{};
  storage->resize(static_cast<std::size_t>(count), zeroFill);
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SDelayedSubVizInfoTypeInfo_b03a7d, moho::preregister_SDelayedSubVizInfoTypeInfo)
GPG_PREREGISTER_INIT(register_SDelayedSubVizInfoVectorType_b03a7d, moho::register_SDelayedSubVizInfoVectorType)

GPG_PREREGISTER_INIT(ConstructAndRegisterDelayedSubVizVectorType_b03a7d, ConstructAndRegisterDelayedSubVizVectorType)
