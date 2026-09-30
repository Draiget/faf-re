#include "moho/render/CDecalTypes.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/RListType.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/entity/CTextureScroller.h"

namespace
{
  /**
   * Address: 0x0077B940 (FUN_0077B940)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `SDecalInfo`.
   */
  [[nodiscard]] gpg::RType* CachedSDecalInfoType()
  {
    gpg::RType* type = moho::SDecalInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SDecalInfo));
      moho::SDecalInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return type;
  }

  [[nodiscard]] gpg::ReadArchive* ReadReflectedSDecalInfoPayload(
    gpg::ReadArchive* const archive,
    void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Read(CachedSDecalInfoType(), payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  [[nodiscard]] gpg::WriteArchive* WriteReflectedSDecalInfoPayload(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Write(CachedSDecalInfoType(), payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  /**
   * Address: 0x0077D9D0 (FUN_0077D9D0)
   *
   * What it does:
   * Deserializes one reflected `SDecalInfo` payload lane and returns the
   * archive for callback chaining.
   */
  [[maybe_unused]] gpg::ReadArchive* DeserializeSDecalInfoReflectedPayloadA(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    return ReadReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DA10 (FUN_0077DA10)
   *
   * What it does:
   * Serializes one reflected `SDecalInfo` payload lane and returns the archive
   * for callback chaining.
   */
  [[maybe_unused]] gpg::WriteArchive* SerializeSDecalInfoReflectedPayloadA(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    return WriteReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DF80 (FUN_0077DF80)
   *
   * What it does:
   * Secondary deserializer entrypoint for one reflected `SDecalInfo` payload
   * lane.
   */
  [[maybe_unused]] void DeserializeSDecalInfoReflectedPayloadB(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * Address: 0x0077DFB0 (FUN_0077DFB0)
   *
   * What it does:
   * Secondary serializer entrypoint for one reflected `SDecalInfo` payload
   * lane.
   */
  [[maybe_unused]] void SerializeSDecalInfoReflectedPayloadB(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    (void)WriteReflectedSDecalInfoPayload(archive, payload, ownerRef);
  }

  /**
   * VFTABLE: 0x00E37368
   *
   * Demangled: gpg::SerSaveLoadHelper<struct Moho::SDecalInfo>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer: 0x00BDD820 (__xc_a-reachable;
   *    dead zero-xref COMDAT duplicates: 0x0077A6A0, and the mangled
   *    ??0SDecalInfoSerializer@Moho@@QAE@@Z body at 0x00778E40)
   *  - dtor: 0x00C02820 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x0077A6D0
   *  - Deserialize(): 0x00778E10
   *  - Serialize(): 0x00778E20
   *
   * NOTE: prior recovery had mis-cited the ctor address as 0x0077A6A0 (a
   * zero-xref dead duplicate) and had never identified 0x00BDD820 at all.
   * `ArchiveSerialization.cpp`'s `InstallMohoSDecalInfoSerializerCallbacks`
   * coincidentally cites this same Init() address (0x0077A6D0) via the
   * generic by-type-name `InstallSerSaveLoadHelperCallbacksByTypeName`
   * dispatch, but that whole citation family is already flagged elsewhere in
   * this codebase as unreliable (the real body does a typeid/RTTI-pointer
   * `LookupRType`, not a by-name string lookup); left untouched here.
   */
  struct SDecalInfoSerializer : gpg::SerSaveLoadHelper<moho::SDecalInfo>
  {};

  // Address: 0x00BDD820 (dynamic initializer for the global
  // `SDecalInfoSerializer` singleton, __xc_a-reachable) -- MSVC's own
  // compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<SDecalInfo>` ctor and registers the real
  // destructor (0x00C02820) via `atexit`.
  SDecalInfoSerializer gSDecalInfoSerializer;

  /**
   * Address: 0x0077E940 (FUN_0077E940)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` lane, including string members and trailing
   * scalar/object lanes, then returns the destination lane.
   */
  [[nodiscard]] moho::SDecalInfo* CopyAssignSDecalInfoLane(
    moho::SDecalInfo* const destination,
    const moho::SDecalInfo* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->mPos = source->mPos;
    destination->mSize = source->mSize;
    destination->mRot = source->mRot;
    destination->mTexName1 = source->mTexName1;
    destination->mTexName2 = source->mTexName2;
    destination->mIsSplat = source->mIsSplat;
    destination->mPad5D[0] = source->mPad5D[0];
    destination->mPad5D[1] = source->mPad5D[1];
    destination->mPad5D[2] = source->mPad5D[2];
    destination->mLODParam = source->mLODParam;
    destination->mStartTick = source->mStartTick;
    destination->mType = source->mType;
    destination->mObj = source->mObj;
    destination->mArmy = source->mArmy;
    destination->mFidelity = source->mFidelity;
    return destination;
  }

  /**
   * Address: 0x0077E7E0 (FUN_0077E7E0)
   * Address: 0x0077DA80 (FUN_0077DA80)
   *
   * What it does:
   * Assign-copies one contiguous `[destinationBegin, destinationEnd)` range
   * from one fixed `SDecalInfo` prototype lane.
   */
  [[maybe_unused]] moho::SDecalInfo* CopyAssignSDecalInfoRangeFromPrototype(
    moho::SDecalInfo* destinationBegin,
    moho::SDecalInfo* const destinationEnd,
    const moho::SDecalInfo* const prototype
  )
  {
    while (destinationBegin != destinationEnd) {
      (void)CopyAssignSDecalInfoLane(destinationBegin, prototype);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0077E830 (FUN_0077E830)
   * Address: 0x0077F340 (FUN_0077F340)
   * Address: 0x0077DAB0 (FUN_0077DAB0)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` range backward, returning the destination
   * begin lane after copy-backward completes.
   */
  [[maybe_unused]] moho::SDecalInfo* CopyAssignSDecalInfoRangeBackward(
    const moho::SDecalInfo* sourceEnd,
    moho::SDecalInfo* destinationEnd,
    const moho::SDecalInfo* const sourceBegin
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      (void)CopyAssignSDecalInfoLane(destinationEnd, sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0077F3A0 (FUN_0077F3A0)
   * Address: 0x0077E8E0 (FUN_0077E8E0, inlined stride-0x90 forward-assign lane)
   *
   * What it does:
   * Assign-copies one `SDecalInfo` forward range and returns one-past the last
   * assigned destination lane. The binary emits an additional specialized
   * forward-assign lane at `0x0077E8E0` for `msvc8::vector<SDecalInfo>`'s
   * operator= reuse path, where the fastcall/register-assignment shape
   * inlines the stride-`sizeof(SDecalInfo)=0x90` loop over a pre-sized
   * destination range; semantically identical to this canonical helper, so
   * this single typed definition services every callsite in the TU.
   */
  [[nodiscard]] moho::SDecalInfo* CopyAssignSDecalInfoRangeForward(
    moho::SDecalInfo* destinationBegin,
    const moho::SDecalInfo* sourceBegin,
    const moho::SDecalInfo* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      (void)CopyAssignSDecalInfoLane(destinationBegin, sourceBegin);
      ++destinationBegin;
      ++sourceBegin;
    }
    return destinationBegin;
  }

  // `DestroySDecalInfoRange`/`DestroySDecalInfoRangeThiscallAdapter`
  // (0x00741420)/`ClearSDecalInfoVectorUsedRange` (0x0077E2D0) formerly
  // lived here as free functions with no source-level caller anywhere in
  // `src/sdk/**` (`DestroySDecalInfoRangeThiscallAdapter` was
  // `[[maybe_unused]]`; `ClearSDecalInfoVectorUsedRange` was defined but
  // never called at all) -- a RULE ONE per-type duplicate of the canonical
  // `msvc8::vector<Moho::SDecalInfo>::destroy_range`/`clear` template
  // instantiations. Removed in favor of the real citations on those
  // template members in `legacy/containers/Vector.h`, the same fix already
  // applied once in this exact file for the sibling `uninit_copy_n` adapter
  // `FUN_0077DA50` ("previously mis-cited as having its canonical body in
  // CDecalTypes.cpp").

} // namespace

/**
 * Address: 0x0077DF00 (FUN_0077DF00, preregister_RListType_SDecalInfo)
 * Address: 0x00C029A0 (FUN_00C029A0, atexit destructor of the list type object)
 *
 * What it does:
 * Constructs the `gpg::RListType<moho::SDecalInfo>` static, which
 * preregisters it for `typeid(msvc8::list<moho::SDecalInfo>)`, and returns
 * it.
 *
 * `RListType<SDecalInfo>`, vtable 0x00E373A8:
 *
 * Address: 0x0077DFE0 (FUN_0077DFE0 -- the implicit scalar deleting destructor.)
 * Address: 0x0077A760 (FUN_0077A760 -- `GetName`.)
 * Address: 0x00C02970 (FUN_00C02970 -- the atexit destructor of `GetName`'s name string.)
 * Address: 0x0077A820 (FUN_0077A820 -- `GetLexical`.)
 * Address: 0x0077A800 (FUN_0077A800 -- `Init`.)
 * Address: 0x0077B260 (FUN_0077B260 -- `SerLoad`; each entry read owned by `*ownerRef` at 0x0077B369.)
 * Address: 0x0077B420 (FUN_0077B420 -- `SerSave`; each entry written owned by `*ownerRef` at 0x0077B460.)
 */
[[nodiscard]] gpg::RType* preregister_RListType_SDecalInfo()
{
  static gpg::RListType<moho::SDecalInfo> sInstance;
  return &sInstance;
}

namespace moho
{
  gpg::RType* SDecalInfo::sType = nullptr;

  /**
   * Address: 0x007786B0 (FUN_007786B0)
   *
   * What it does:
   * Constructs one `SDecalInfo` object in preallocated storage and returns the
   * constructed object lane.
   */
  [[maybe_unused]] SDecalInfo* ConstructSDecalInfoInPlace(SDecalInfo* const storage)
  {
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) SDecalInfo();
  }

  [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresent(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) SDecalInfo(*source);
  }

  /**
   * Address: 0x0077D360 (FUN_0077D360)
   *
   * What it does:
   * Primary adapter lane for nullable `SDecalInfo` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresentPrimary(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    return CopyConstructSDecalInfoIfPresent(destination, source);
  }

  /**
   * Address: 0x0077DCC0 (FUN_0077DCC0)
   *
   * What it does:
   * Secondary adapter lane for nullable `SDecalInfo` copy-construction into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] SDecalInfo* CopyConstructSDecalInfoIfPresentSecondary(
    SDecalInfo* const destination,
    const SDecalInfo* const source
  )
  {
    return CopyConstructSDecalInfoIfPresent(destination, source);
  }

  /**
   * Address: 0x00742360 (FUN_00742360, Moho::SDecalInfo::~SDecalInfo)
   *
   * What it does:
   * Releases one decal-info payload. The compiler-synthesized teardown
   * first destroys the trailing string `mType` (deallocating when its
   * capacity slot at `+0x80` exceeds the SSO threshold of 0x10) and then
   * runs the eh-vector destructor lane for the two texture-name strings
   * at `+0x24`/`+0x40` (count=2, stride=0x1C) which destroys `mTexName2`
   * followed by `mTexName1` in reverse declaration order. Aligned
   * `Wm3::Vec3f` lanes are trivially destructible and need no teardown.
   *
   * The explicit definition reifies the compiler-synthesized destructor
   * that lives at `0x00742360` in the shipped binary so that the
   * `msvc8::vector<SDecalInfo>` teardown path (`destroy_range<SDecalInfo>`,
   * `legacy/containers/Vector.h`, address-cited 0x00742090 and siblings)
   * binds to a named, address-annotated symbol rather than an implicit
   * lane.
   */
  SDecalInfo::~SDecalInfo() = default;

  /**
   * Address: 0x00778B60 (FUN_00778B60, SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Initializes one default decal payload with empty textures/type and
   * default fidelity.
   */
  SDecalInfo::SDecalInfo()
    : mPos{}
    , mSize{}
    , mRot{}
    , mTexName1()
    , mTexName2()
    , mIsSplat(0)
    , mPad5D{0, 0, 0}
    , mLODParam(0.0f)
    , mStartTick(0)
    , mType()
    , mObj(0)
    , mArmy(0)
    , mFidelity(1)
  {}

  /**
   * Address: 0x0066D210 (FUN_0066D210, Moho::SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Copies position/size/rotation + texture/type strings and seeds runtime
   * decal metadata fields.
   */
  SDecalInfo::SDecalInfo(
    const Wm3::Vec3f& size,
    const Wm3::Vec3f& position,
    const Wm3::Vec3f& rotation,
    const msvc8::string& textureNamePrimary,
    const msvc8::string& textureNameSecondary,
    const bool isSplat,
    const float lodParam,
    const std::uint32_t startTick,
    const msvc8::string& typeName,
    const std::uint32_t armyIndex,
    const std::uint32_t fidelity
  )
    : mPos(position)
    , mSize(size)
    , mRot(rotation)
    , mTexName1(textureNamePrimary)
    , mTexName2(textureNameSecondary)
    , mIsSplat(isSplat ? 1u : 0u)
    , mPad5D{0, 0, 0}
    , mLODParam(lodParam)
    , mStartTick(startTick)
    , mType(typeName)
    , mObj(0)
    , mArmy(armyIndex)
    , mFidelity(fidelity)
  {}

  /**
   * Address: 0x0077D470 (FUN_0077D470, Moho::SDecalInfo::MemberDeserialize)
   *
   * What it does:
   * Loads decal position/size/rotation vectors plus texture/type lanes and
   * runtime metadata fields from archive payload.
   */
  void SDecalInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const vector3fType = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3fType, &mPos, ownerRef);
    archive->Read(vector3fType, &mSize, ownerRef);
    archive->Read(vector3fType, &mRot, ownerRef);

    archive->ReadString(&mTexName1);
    archive->ReadString(&mTexName2);

    bool isSplat = false;
    archive->ReadBool(&isSplat);
    mIsSplat = isSplat ? 1u : 0u;

    archive->ReadFloat(&mLODParam);
    archive->ReadUInt(&mStartTick);
    archive->ReadString(&mType);

    std::int32_t objectId = 0;
    std::int32_t armyIndex = 0;
    std::int32_t fidelity = 0;
    archive->ReadInt(&objectId);
    archive->ReadInt(&armyIndex);
    archive->ReadInt(&fidelity);
    mObj = static_cast<std::uint32_t>(objectId);
    mArmy = static_cast<std::uint32_t>(armyIndex);
    mFidelity = static_cast<std::uint32_t>(fidelity);
  }

  /**
   * Address: 0x0077D5A0 (FUN_0077D5A0)
   *
   * What it does:
   * Saves decal position/size/rotation vectors plus texture/type lanes and
   * runtime metadata fields to archive payload.
   */
  void SDecalInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    gpg::RType* const vector3fType = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Write(vector3fType, &mPos, ownerRef);
    archive->Write(vector3fType, &mSize, ownerRef);
    archive->Write(vector3fType, &mRot, ownerRef);

    archive->WriteString(const_cast<msvc8::string*>(&mTexName1));
    archive->WriteString(const_cast<msvc8::string*>(&mTexName2));
    archive->WriteBool(mIsSplat != 0u);
    archive->WriteFloat(mLODParam);
    archive->WriteUInt(mStartTick);
    archive->WriteString(const_cast<msvc8::string*>(&mType));
    archive->WriteInt(static_cast<int>(mObj));
    archive->WriteInt(static_cast<int>(mArmy));
    archive->WriteInt(static_cast<int>(mFidelity));
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RListType_SDecalInfo_874f42, preregister_RListType_SDecalInfo)
