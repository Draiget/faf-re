#include "moho/entity/CTextureScroller.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/VTransform.h"
#include "moho/ui/EScrollTypeTypeInfo.h"

namespace
{
  enum class TextureScrollerMode : std::int32_t
  {
    None = 0,
    PingPong = 1,
    Manual = 2,
    Thread = 3,
  };

  struct EntityTextureRuntimeView
  {
    std::uint8_t mPad0000_009B[0x9C];
    moho::VTransform mCurTransform;  // +0x9C
    moho::VTransform mLastTransform; // +0xB8
    std::uint8_t mPad00D4_00F7[0x24];
    Wm3::Vector2f mScroll1; // +0xF8
    Wm3::Vector2f mScroll2; // +0x100
  };

  static_assert(offsetof(EntityTextureRuntimeView, mCurTransform) == 0x9C, "EntityTextureRuntimeView::mCurTransform offset must be 0x9C");
  static_assert(offsetof(EntityTextureRuntimeView, mLastTransform) == 0xB8, "EntityTextureRuntimeView::mLastTransform offset must be 0xB8");
  static_assert(offsetof(EntityTextureRuntimeView, mScroll1) == 0xF8, "EntityTextureRuntimeView::mScroll1 offset must be 0xF8");
  static_assert(offsetof(EntityTextureRuntimeView, mScroll2) == 0x100, "EntityTextureRuntimeView::mScroll2 offset must be 0x100");

  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  // Forward declaration: defined further down in this namespace; used by
  // SScrollerSerializer::Init() below.
  [[nodiscard]] gpg::RType* CachedScrollerType();

  /**
   * Demangled: gpg::SerSaveLoadHelper<class Moho::SScroller> (Init() body
   * confirmed at FUN_00777EC0, see below; matches the shared
   * `InstallSerSaveLoadHelperCallbacksByTypeName` template's expansion for
   * "Moho::SScroller" in gpg/core/containers/ArchiveSerialization.cpp).
   *
   * NOTE: no citation in this TU identifies a constructor that binds
   * `mLoadCallback`/`mSaveCallback` for this specific helper -- both load/save
   * fields stay null, matching this file's pre-existing (already-uncalled)
   * state. `CTextureScroller::MemberDeserialize` / `MemberSerialize` bypass
   * this generic per-type dispatch entirely and call
   * `DeserializeSScrollerConfigPayload` / `SerializeSScrollerConfigPayload`
   * directly, so this helper may simply be unused at runtime.
   */
  class SScrollerSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00777EC0 (FUN_00777EC0, InstallMohoSScrollerSerializerCallbacks
     * instantiation of the shared `InstallSerSaveLoadHelperCallbacksByTypeName`
     * template in gpg/core/containers/ArchiveSerialization.cpp)
     *
     * What it does:
     * Resolves `SScroller` reflected type metadata and publishes this
     * helper's (currently null) load/save callback lanes to it.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
  static_assert(
    offsetof(SScrollerSerializer, mLoadCallback) == 0x0C, "SScrollerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SScrollerSerializer, mSaveCallback) == 0x10, "SScrollerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SScrollerSerializer) == 0x14, "SScrollerSerializer size must be 0x14");

  void SScrollerSerializer::Init()
  {
    gpg::RType* const type = CachedScrollerType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  SScrollerSerializer gSScrollerSerializerHelper;

  /**
   * Address: 0x007774D0 (FUN_007774D0)
   *
   * What it does:
   * Unlinks `SScrollerSerializer` helper node from the intrusive helper list
   * and restores self-links.
   */
  [[maybe_unused]] void UnlinkSScrollerSerializerNodeVariantA() noexcept
  {
    gSScrollerSerializerHelper.ResetLinks();
  }

  /**
   * Address: 0x00777500 (FUN_00777500)
   *
   * What it does:
   * Duplicate unlink/reset lane for the `SScrollerSerializer` helper node.
   */
  [[maybe_unused]] void UnlinkSScrollerSerializerNodeVariantB() noexcept
  {
    gSScrollerSerializerHelper.ResetLinks();
  }

  [[nodiscard]] EntityTextureRuntimeView& AccessEntityTextureRuntime(moho::Entity& entity) noexcept
  {
    return *reinterpret_cast<EntityTextureRuntimeView*>(&entity);
  }

  [[nodiscard]] gpg::RType* CachedScrollerType()
  {
    if (moho::SScroller::sType == nullptr) {
      moho::SScroller::sType = gpg::LookupRType(typeid(moho::SScroller));
    }
    return moho::SScroller::sType;
  }

  [[nodiscard]] gpg::RType* CachedEScrollType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::EScrollType));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::Entity));
    }
    return cached;
  }

  [[nodiscard]] gpg::ReadArchive* ReadReflectedPayload(
    gpg::ReadArchive* const archive,
    gpg::RType* const type,
    void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Read(type, payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  [[nodiscard]] gpg::WriteArchive* WriteReflectedPayload(
    gpg::WriteArchive* const archive,
    gpg::RType* const type,
    const void* const payload,
    const gpg::RRef* const ownerRef = nullptr
  )
  {
    gpg::RRef nullOwner{};
    archive->Write(type, payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  /**
   * Address: 0x00776FF0 (FUN_00776FF0)
   *
   * What it does:
   * Deserializes one reflected `Entity` payload lane with a null-owner
   * fallback.
   */
  [[maybe_unused]] void DeserializeEntityReflectedPayloadA(gpg::ReadArchive* const archive, void* const payload)
  {
    (void)ReadReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x00777030 (FUN_00777030)
   *
   * What it does:
   * Serializes one reflected `Entity` payload lane with a null-owner fallback.
   */
  [[maybe_unused]] void SerializeEntityReflectedPayloadA(gpg::WriteArchive* const archive, const void* const payload)
  {
    (void)WriteReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x007770A0 (FUN_007770A0)
   *
   * What it does:
   * Secondary deserializer entrypoint for one reflected `Entity` payload lane.
   */
  [[maybe_unused]] void DeserializeEntityReflectedPayloadB(gpg::ReadArchive* const archive, void* const payload)
  {
    (void)ReadReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x007770E0 (FUN_007770E0)
   *
   * What it does:
   * Secondary serializer entrypoint for one reflected `Entity` payload lane.
   */
  [[maybe_unused]] void SerializeEntityReflectedPayloadB(gpg::WriteArchive* const archive, const void* const payload)
  {
    (void)WriteReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x00777120 (FUN_00777120)
   *
   * What it does:
   * Deserializes one reflected `Entity` payload lane using swapped callback
   * argument order.
   */
  [[maybe_unused]] void DeserializeEntityReflectedPayloadSwappedArgs(void* const payload, gpg::ReadArchive* const archive)
  {
    (void)ReadReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x00777160 (FUN_00777160)
   *
   * What it does:
   * Serializes one reflected `Entity` payload lane using swapped callback
   * argument order.
   */
  [[maybe_unused]] void SerializeEntityReflectedPayloadSwappedArgs(const void* const payload, gpg::WriteArchive* const archive)
  {
    (void)WriteReflectedPayload(archive, CachedEntityType(), payload);
  }

  /**
   * Address: 0x00778370 (FUN_00778370)
   *
   * What it does:
   * Deserializes one reflected `EScrollType` lane and returns the archive for
   * callback chaining.
   */
  [[maybe_unused]] gpg::ReadArchive* DeserializeEScrollTypeReflectedPayloadA(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    return ReadReflectedPayload(archive, CachedEScrollType(), payload, ownerRef);
  }

  /**
   * Address: 0x007783B0 (FUN_007783B0)
   *
   * What it does:
   * Serializes one reflected `EScrollType` lane and returns the archive for
   * callback chaining.
   */
  [[maybe_unused]] gpg::WriteArchive* SerializeEScrollTypeReflectedPayloadA(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    return WriteReflectedPayload(archive, CachedEScrollType(), payload, ownerRef);
  }

  /**
   * Address: 0x00778410 (FUN_00778410)
   *
   * What it does:
   * Secondary deserializer entrypoint for one reflected `EScrollType` lane.
   */
  [[maybe_unused]] void DeserializeEScrollTypeReflectedPayloadB(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadReflectedPayload(archive, CachedEScrollType(), payload, ownerRef);
  }

  /**
   * Address: 0x00778440 (FUN_00778440)
   *
   * What it does:
   * Secondary serializer entrypoint for one reflected `EScrollType` lane.
   */
  [[maybe_unused]] void SerializeEScrollTypeReflectedPayloadB(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    (void)WriteReflectedPayload(archive, CachedEScrollType(), payload, ownerRef);
  }

  /**
   * Address: 0x007785F0 (FUN_007785F0)
   *
   * What it does:
   * Serializes one reflected `SScroller` payload lane and returns the archive
   * for callback chaining.
   */
  [[maybe_unused]] gpg::WriteArchive* SerializeSScrollerReflectedPayloadA(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    return WriteReflectedPayload(archive, CachedScrollerType(), payload, ownerRef);
  }

  /**
   * Address: 0x00778630 (FUN_00778630)
   *
   * What it does:
   * Deserializes one reflected `SScroller` payload lane.
   */
  [[maybe_unused]] void DeserializeSScrollerReflectedPayload(
    gpg::ReadArchive* const archive,
    void* const payload,
    gpg::RRef* const ownerRef
  )
  {
    (void)ReadReflectedPayload(archive, CachedScrollerType(), payload, ownerRef);
  }

  /**
   * Address: 0x00778660 (FUN_00778660)
   *
   * What it does:
   * Secondary serializer entrypoint for one reflected `SScroller` payload
   * lane.
   */
  [[maybe_unused]] void SerializeSScrollerReflectedPayloadB(
    gpg::WriteArchive* const archive,
    const void* const payload,
    const gpg::RRef* const ownerRef
  )
  {
    (void)WriteReflectedPayload(archive, CachedScrollerType(), payload, ownerRef);
  }

  /**
   * Address: 0x00778170 (FUN_00778170)
   *
   * What it does:
   * Deserializes one `SScroller` payload by loading its reflected
   * `EScrollType` lane followed by all ten float lanes in binary order.
   */
  [[nodiscard]] gpg::ReadArchive* DeserializeSScrollerConfigPayload(
    moho::SScroller* const payload,
    gpg::ReadArchive* const archive
  )
  {
    if (archive == nullptr || payload == nullptr) {
      return archive;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedEScrollType(), &payload->mType, ownerRef);
    archive->ReadFloat(&payload->mFloat04);
    archive->ReadFloat(&payload->mFloat08);
    archive->ReadFloat(&payload->mFloat0C);
    archive->ReadFloat(&payload->mFloat10);
    archive->ReadFloat(&payload->mScroll1.x);
    archive->ReadFloat(&payload->mScroll1.y);
    archive->ReadFloat(&payload->mScroll2.x);
    archive->ReadFloat(&payload->mScroll2.y);
    archive->ReadFloat(&payload->mFloat24);
    archive->ReadFloat(&payload->mFloat28);
    return archive;
  }

  /**
   * Address: 0x00778240 (FUN_00778240)
   *
   * What it does:
   * Serializes one `SScroller` payload by writing its reflected
   * `EScrollType` lane followed by all ten float lanes in binary order.
   */
  void SerializeSScrollerConfigPayload(
    const moho::SScroller& payload,
    gpg::WriteArchive* const archive
  )
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedEScrollType(), &payload.mType, ownerRef);
    archive->WriteFloat(payload.mFloat04);
    archive->WriteFloat(payload.mFloat08);
    archive->WriteFloat(payload.mFloat0C);
    archive->WriteFloat(payload.mFloat10);
    archive->WriteFloat(payload.mScroll1.x);
    archive->WriteFloat(payload.mScroll1.y);
    archive->WriteFloat(payload.mScroll2.x);
    archive->WriteFloat(payload.mScroll2.y);
    archive->WriteFloat(payload.mFloat24);
    archive->WriteFloat(payload.mFloat28);
  }

  /**
   * Address: 0x007785B0 (FUN_007785B0)
   *
   * What it does:
   * Deserializes one reflected `SScroller` payload lane and returns the input
   * archive pointer for callback chaining.
   */
  [[maybe_unused]] gpg::ReadArchive*
  DeserializeScrollerPayload(gpg::ReadArchive* const archive, void* const payload, gpg::RRef* const ownerRef)
  {
    if (archive == nullptr || payload == nullptr) {
      return archive;
    }

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);

    const gpg::RRef nullOwner{};
    archive->Read(scrollerType, payload, ownerRef ? *ownerRef : nullOwner);
    return archive;
  }

  [[nodiscard]] gpg::RRef MakeTextureScrollerRef(moho::CTextureScroller* const object) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = moho::CTextureScroller::StaticGetClass();
    return ref;
  }

  /**
   * Address: 0x00777FC0 (FUN_00777FC0, inferred callback target from FUN_00777F30)
   *
   * What it does:
   * Allocates one `CTextureScroller` and returns a typed reflected reference.
   */
  gpg::RRef NewTextureScrollerRef()
  {
    auto* const object = new (std::nothrow) moho::CTextureScroller(nullptr);
    return MakeTextureScrollerRef(object);
  }

  /**
   * Address: 0x00778120 (FUN_00778120, Moho::CTextureScrollerTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CTextureScroller` in caller-provided storage and
   * returns a typed reflected reference.
   */
  gpg::RRef CtrTextureScrollerRef(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<moho::CTextureScroller*>(objectPtr);
    if (object != nullptr) {
      new (object) moho::CTextureScroller(nullptr);
    }
    return MakeTextureScrollerRef(object);
  }

  /**
   * Address: 0x00778100 (FUN_00778100, Moho::CTextureScrollerTypeInfo::Delete)
   *
   * What it does:
   * Releases storage for one `CTextureScroller` object pointer.
   */
  void DeleteTextureScrollerObject(void* const objectPtr)
  {
    if (objectPtr != nullptr) {
      operator delete(objectPtr);
    }
  }

  /**
   * Address: 0x00778160 (FUN_00778160, Moho::CTextureScrollerTypeInfo::Destruct)
   *
   * What it does:
   * No-op destruct callback lane used by legacy texture-scroller type-info.
   */
  void DestructTextureScrollerObject(void* const)
  {}

  // NOTE: 0x00777F30 (the "assign lifecycle callbacks" shape) had zero code
  // callers and zero data xrefs in the callgraph index (verified,
  // NO_CALLSITE_EVIDENCE/UNREACHED) -- the real CTextureScrollerTypeInfo::Init
  // (0x00777590) writes its four lifecycle-callback fields inline (confirmed
  // via decompile), matching the shared gpg::BindRTypeLifecycleCallbacks
  // helper's other ~40 citations (Reflection.h), not a call to a separate
  // function. The local AssignTextureScrollerTypeLifecycleCallbacks duplicate
  // that carried this false citation has been removed; Init calls the shared
  // helper directly with the four callbacks below.

  /**
   * Address: 0x00778690 (FUN_00778690)
   *
   * What it does:
   * Computes cosine/sine for one angle and writes them to output lanes.
   */
  [[maybe_unused]] float* ComputeSinAndCosToOutputLanes(
    const float angle,
    float* const outSin,
    float* const outCos
  ) noexcept
  {
    *outCos = std::cos(angle);
    *outSin = std::sin(angle);
    return outSin;
  }
} // namespace

namespace moho
{
  gpg::RType* SScroller::sType = nullptr;
  gpg::RType* CTextureScroller::sType = nullptr;

  /**
   * Address: 0x00683190 (FUN_00683190)
   *
   * What it does:
   * Returns cached reflected type metadata for `CTextureScroller`,
   * resolving it through RTTI lookup on first use.
   */
  gpg::RType* CTextureScroller::StaticGetClass()
  {
    gpg::RType* type = sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CTextureScroller));
      sType = type;
    }

    return type;
  }

  /**
   * Address: 0x00777530 (FUN_00777530, ctor lane)
   */
  CTextureScrollerTypeInfo::CTextureScrollerTypeInfo()
  {
    gpg::PreRegisterRType(typeid(CTextureScroller), this);
  }

  /**
   * Address: 0x007775D0 (FUN_007775D0, Moho::CTextureScrollerTypeInfo::GetName)
   */
  const char* CTextureScrollerTypeInfo::GetName() const
  {
    return "CTextureScroller";
  }

  /**
   * Address: 0x00777590 (FUN_00777590, Moho::CTextureScrollerTypeInfo::Init)
   */
  void CTextureScrollerTypeInfo::Init()
  {
    size_ = sizeof(CTextureScroller);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &NewTextureScrollerRef,
      &CtrTextureScrollerRef,
      &DeleteTextureScrollerObject,
      &DestructTextureScrollerObject
    );
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00676B50 (FUN_00676B50, Moho::SScroller::SScroller defaults lane)
   *
   * What it does:
   * Seeds one scroller payload with mode `None`, zero timing/scroll lanes,
   * and unit scale factors for both UV channels.
   */
  void SScroller::InitializeDefaults() noexcept
  {
    mType = static_cast<std::int32_t>(TextureScrollerMode::None);
    mFloat04 = 0.0f;
    mFloat08 = 0.0f;
    mFloat0C = 0.0f;
    mFloat10 = 0.0f;
    mScroll1.x = 0.0f;
    mScroll1.y = 0.0f;
    mScroll2.x = 0.0f;
    mScroll2.y = 0.0f;
    mFloat24 = 1.0f;
    mFloat28 = 1.0f;
  }

  /**
   * Address: 0x00676BA0 (FUN_00676BA0, ??0CTextureScroller@Moho@@QAE@@Z)
   *
   * Moho::Entity *
   *
   * IDA signature:
   * Moho::CTextureScroller * __usercall
   *   Moho::CTextureScroller::CTextureScroller@<eax>(
   *     Moho::CTextureScroller *this@<eax>, Moho::Entity *owner@<ecx>);
   *
   * What it does:
   * Binds one owning entity pointer and seeds one default "none" scroller
   * payload with zero direction/speed lanes.
   */
  CTextureScroller::CTextureScroller(Entity* const owner)
    : mEntity(owner)
  {
    mScroller.InitializeDefaults();

    mDir[0] = 0u;
    mDir[1] = 0u;
    mPad32[0] = 0u;
    mPad32[1] = 0u;
    mSpeed[0] = 0;
    mSpeed[1] = 0;
  }

  /**
   * Address: 0x00777730 (FUN_00777730, Moho::CTextureScroller::Tick)
   *
   * What it does:
   * Advances one texture-scroll lane according to configured mode:
   * ping-pong stepping, manual UV drift, or motion-derived UV projection.
   */
  void CTextureScroller::Tick()
  {
    if (mEntity == nullptr) {
      return;
    }

    EntityTextureRuntimeView& entityRuntime = AccessEntityTextureRuntime(*mEntity);
    switch (static_cast<TextureScrollerMode>(mScroller.mType)) {
    case TextureScrollerMode::PingPong: {
      bool changed = false;

      for (std::int32_t axis = 0; axis < 2; ++axis) {
        --mSpeed[axis];
        if (mSpeed[axis] > 0) {
          continue;
        }

        changed = true;
        const bool wasForward = mDir[axis] != 0u;
        mDir[axis] = static_cast<std::uint8_t>(!wasForward);

        float phaseDuration = 0.0f;
        if (axis == 0) {
          phaseDuration = wasForward ? mScroller.mFloat08 : mScroller.mFloat04;
        } else {
          phaseDuration = wasForward ? mScroller.mFloat10 : mScroller.mFloat0C;
        }

        mSpeed[axis] = static_cast<std::int32_t>(std::floor(phaseDuration * 10.0f));
      }

      if (!changed) {
        return;
      }

      const float scrollX = (mDir[0] != 0u) ? mScroller.mScroll1.x : mScroller.mScroll2.x;
      const float scrollY = (mDir[1] != 0u) ? mScroller.mScroll1.y : mScroller.mScroll2.y;
      entityRuntime.mScroll1.x = scrollX;
      entityRuntime.mScroll1.y = scrollY;
      entityRuntime.mScroll2.x = scrollX;
      entityRuntime.mScroll2.y = scrollY;
      return;
    }

    case TextureScrollerMode::Manual: {
      const float currentX = entityRuntime.mScroll2.x;
      const float currentY = entityRuntime.mScroll2.y;
      entityRuntime.mScroll1.x = currentX;
      entityRuntime.mScroll1.y = currentY;
      entityRuntime.mScroll2.x = currentX + mScroller.mFloat04;
      entityRuntime.mScroll2.y = currentY + mScroller.mFloat08;
      return;
    }

    case TextureScrollerMode::Thread: {
      if (!Wm3::Vector3f::Compare(&entityRuntime.mCurTransform.pos_, &entityRuntime.mLastTransform.pos_)) {
        return;
      }

      const VTransform curTransform(entityRuntime.mCurTransform);
      const VTransform lastTransform(entityRuntime.mLastTransform);

      const auto& cur = curTransform.orient_;
      const auto& last = lastTransform.orient_;
      const float offset = mScroller.mFloat24;

      // Column 0 of the rotation matrix - the local X axis - scalar-first:
      // (1-2(y*y+z*z), 2(xy+wz), 2(xz-wy)). The previous spelling had every
      // lane rotated one place, leaving a `w*w` diagonal term behind.
      const float curAxisX = 1.0f - (((cur.z * cur.z) + (cur.y * cur.y)) * 2.0f);
      const float curAxisY = ((cur.y * cur.x) + (cur.z * cur.w)) * 2.0f;
      const float curAxisZ = ((cur.z * cur.x) - (cur.y * cur.w)) * 2.0f;

      const float lastAxisX = 1.0f - (((last.z * last.z) + (last.y * last.y)) * 2.0f);
      const float lastAxisY = ((last.z * last.w) + (last.y * last.x)) * 2.0f;
      const float lastAxisZ = ((last.z * last.x) - (last.y * last.w)) * 2.0f;

      const float leadDeltaX =
        (curTransform.pos_.x + (curAxisX * offset)) - (lastTransform.pos_.x + (lastAxisX * offset));
      const float leadDeltaY =
        (curTransform.pos_.y + (curAxisY * offset)) - (lastTransform.pos_.y + (lastAxisY * offset));
      const float leadDeltaZ =
        (curTransform.pos_.z + (curAxisZ * offset)) - (lastTransform.pos_.z + (lastAxisZ * offset));

      const float trailDeltaX =
        (curTransform.pos_.x - (curAxisX * offset)) - (lastTransform.pos_.x - (lastAxisX * offset));
      const float trailDeltaY =
        (curTransform.pos_.y - (curAxisY * offset)) - (lastTransform.pos_.y - (lastAxisY * offset));
      const float trailDeltaZ =
        (curTransform.pos_.z - (curAxisZ * offset)) - (lastTransform.pos_.z - (lastAxisZ * offset));

      const float avgBasisX =
        ((((cur.z * cur.x) + (cur.w * cur.y)) * 2.0f) + (((last.z * last.x) + (last.w * last.y)) * 2.0f)) * 0.5f;
      const float avgBasisY =
        ((1.0f - (((cur.x * cur.x) + (cur.y * cur.y)) * 2.0f)) + (1.0f - (((last.x * last.x) + (last.y * last.y)) * 2.0f))) * 0.5f;
      const float avgBasisZ =
        ((((cur.y * cur.z) - (cur.w * cur.x)) * 2.0f) + (((last.y * last.z) - (last.w * last.x)) * 2.0f)) * 0.5f;

      const float scrollScale = mScroller.mFloat28;
      const float scrollDeltaX = ((avgBasisY * leadDeltaZ) + (avgBasisZ * leadDeltaY) + (avgBasisX * leadDeltaX)) * scrollScale;
      const float scrollDeltaY = ((avgBasisX * trailDeltaX) + (avgBasisY * trailDeltaZ) + (avgBasisZ * trailDeltaY)) * scrollScale;

      const float currentX = entityRuntime.mScroll2.x;
      const float currentY = entityRuntime.mScroll2.y;
      entityRuntime.mScroll1.x = currentX;
      entityRuntime.mScroll1.y = currentY;
      entityRuntime.mScroll2.x = currentX + scrollDeltaX;
      entityRuntime.mScroll2.y = currentY + scrollDeltaY;
      return;
    }

    default:
      return;
    }
  }

  /**
   * Address: 0x00778470 (FUN_00778470, Moho::CTextureScroller::MemberDeserialize)
   *
   * What it does:
   * Deserializes owner entity pointer, scroller configuration payload, then
   * reads direction/speed lanes.
   */
  void CTextureScroller::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_Entity(&mEntity, &nullOwner);

    (void)DeserializeSScrollerConfigPayload(&mScroller, archive);

    bool dir0 = false;
    bool dir1 = false;
    archive->ReadBool(&dir0);
    archive->ReadBool(&dir1);
    mDir[0] = static_cast<std::uint8_t>(dir0 ? 1u : 0u);
    mDir[1] = static_cast<std::uint8_t>(dir1 ? 1u : 0u);

    archive->ReadInt(&mSpeed[0]);
    archive->ReadInt(&mSpeed[1]);
  }

  // Addresses 0x00778320/0x007783F0 (the "ThunkA"/"ThunkB" load-lane
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // `DeserializeCTextureScrollerSerializerCallback` below (wired into
  // `CTextureScrollerSerializer`'s ctor) already forwards into
  // `CTextureScroller::MemberDeserialize` and is the real, atexit-registered
  // body.

  /**
   * Address: 0x00778510 (FUN_00778510, Moho::CTextureScroller::MemberSerialize)
   *
   * What it does:
   * Serializes owner entity pointer, scroller configuration payload, then
   * emits direction/speed lanes.
   */
  void CTextureScroller::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RRef entityRef{};
    gpg::RRef_Entity(&entityRef, mEntity);
    gpg::WriteRawPointer(archive, entityRef, gpg::TrackedPointerState::Unowned, nullOwner);

    SerializeSScrollerConfigPayload(mScroller, archive);

    archive->WriteBool(mDir[0] != 0u);
    archive->WriteBool(mDir[1] != 0u);
    archive->WriteInt(mSpeed[0]);
    archive->WriteInt(mSpeed[1]);
  }

  // Addresses 0x00778330/0x00778400 (the "ThunkA"/"ThunkB" save-lane
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // `SerializeCTextureScrollerSerializerCallback` below (wired into
  // `CTextureScrollerSerializer`'s ctor) already forwards into
  // `CTextureScroller::MemberSerialize` and is the real, atexit-registered
  // body.
} // namespace moho

namespace
{
  // Forward declarations: CTextureScrollerSerializer's constructor binds
  // these as its load/save callback pointers; bodies defined below.
  void DeserializeCTextureScrollerSerializerCallback(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  void SerializeCTextureScrollerSerializerCallback(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  void cleanup_CTextureScrollerSerializer_atexit();

  /**
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CTextureScroller>
   */
  class CTextureScrollerSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDD750 (FUN_00BDD750, register_CTextureScrollerSerializer)
     *
     * What it does:
     * Binds this helper's load/save callback lanes and registers process-exit
     * cleanup. Base-class construction (`gpg::SerHelperBase::SerHelperBase`)
     * self-links this node and splices it into the pending `sNewHelpers`
     * list.
     */
    CTextureScrollerSerializer();

    /**
     * Address: 0x00777F80 (FUN_00777F80, gpg::SerSaveLoadHelper_CTextureScroller::Init)
     *
     * What it does:
     * Resolves reflected type metadata for `CTextureScroller` and installs
     * this helper's load/save callback lanes.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback = nullptr;
    gpg::RType::save_func_t mSaveCallback = nullptr;
  };
  static_assert(
    offsetof(CTextureScrollerSerializer, mLoadCallback) == 0x0C,
    "CTextureScrollerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CTextureScrollerSerializer, mSaveCallback) == 0x10,
    "CTextureScrollerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CTextureScrollerSerializer) == 0x14, "CTextureScrollerSerializer size must be 0x14");

  CTextureScrollerSerializer::CTextureScrollerSerializer()
    : mLoadCallback(&DeserializeCTextureScrollerSerializerCallback)
    , mSaveCallback(&SerializeCTextureScrollerSerializerCallback)
  {
    (void)std::atexit(&cleanup_CTextureScrollerSerializer_atexit);
  }

  void CTextureScrollerSerializer::Init()
  {
    gpg::RType* type = moho::CTextureScroller::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CTextureScroller));
      moho::CTextureScroller::sType = type;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
    }
    type->serLoadFunc_ = mLoadCallback;

    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
    }
    type->serSaveFunc_ = mSaveCallback;
  }

  CTextureScrollerSerializer gCTextureScrollerSerializer;

  void DeserializeCTextureScrollerSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<moho::CTextureScroller*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  void SerializeCTextureScrollerSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<const moho::CTextureScroller*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
  }

  void cleanup_CTextureScrollerSerializer_atexit()
  {
    gCTextureScrollerSerializer.ResetLinks();
  }
} // namespace

namespace
{
  alignas(moho::CTextureScrollerTypeInfo)
  unsigned char gCTextureScrollerTypeInfoStorage[sizeof(moho::CTextureScrollerTypeInfo)] = {};
  bool gCTextureScrollerTypeInfoConstructed = false;

  [[nodiscard]] moho::CTextureScrollerTypeInfo* AcquireCTextureScrollerTypeInfo()
  {
    if (!gCTextureScrollerTypeInfoConstructed) {
      new (gCTextureScrollerTypeInfoStorage) moho::CTextureScrollerTypeInfo();
      gCTextureScrollerTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CTextureScrollerTypeInfo*>(gCTextureScrollerTypeInfoStorage);
  }

  /**
   * Address: 0x00C02710 (FUN_00C02710, cleanup_CTextureScrollerTypeInfo)
   *
   * What it does:
   * Tears down static `CTextureScrollerTypeInfo` storage at process exit.
   */
  void cleanup_CTextureScrollerTypeInfo()
  {
    if (!gCTextureScrollerTypeInfoConstructed) {
      return;
    }

    AcquireCTextureScrollerTypeInfo()->~CTextureScrollerTypeInfo();
    gCTextureScrollerTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDD730 (FUN_00BDD730, register_CTextureScrollerTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CTextureScrollerTypeInfo` singleton and
   * installs process-exit cleanup. Dispatched from `.CRT$XCL` (`__xc_a`); the
   * binary has exactly one call site and no reentry guard, matching the
   * guarded-singleton idiom used throughout this reflection family.
   */
  void register_CTextureScrollerTypeInfo()
  {
    (void)AcquireCTextureScrollerTypeInfo();
    (void)std::atexit(&cleanup_CTextureScrollerTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CTextureScrollerTypeInfo_6b8f21, moho::register_CTextureScrollerTypeInfo)
