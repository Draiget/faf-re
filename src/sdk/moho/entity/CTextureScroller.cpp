#include "moho/entity/CTextureScroller.h"

#include <cmath>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
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

  gpg::SerSaveLoadHelperListRuntime gSScrollerSerializerHelper{};

  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  struct SerSaveLoadHelperInitRuntimeView
  {
    void* mVTable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoadCallback = nullptr; // +0x0C
    gpg::RType::save_func_t mSaveCallback = nullptr; // +0x10
  };
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperInitRuntimeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperInitRuntimeView::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mLoadCallback) == 0x0C,
    "SerSaveLoadHelperInitRuntimeView::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mSaveCallback) == 0x10,
    "SerSaveLoadHelperInitRuntimeView::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerSaveLoadHelperInitRuntimeView) == 0x14,
    "SerSaveLoadHelperInitRuntimeView size must be 0x14"
  );

  /**
   * Address: 0x007774D0 (FUN_007774D0, SerSaveLoadHelper<SScroller>::unlink lane A)
   *
   * What it does:
   * Unlinks `SScrollerSerializer` helper node from the intrusive helper list
   * and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSScrollerSerializerNodeVariantA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSScrollerSerializerHelper);
  }

  /**
   * Address: 0x00777500 (FUN_00777500, SerSaveLoadHelper<SScroller>::unlink lane B)
   *
   * What it does:
   * Duplicate unlink/reset lane for the `SScrollerSerializer` helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSScrollerSerializerNodeVariantB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSScrollerSerializerHelper);
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
  [[maybe_unused]] gpg::RRef NewTextureScrollerRef()
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
  [[maybe_unused]] gpg::RRef CtrTextureScrollerRef(void* const objectPtr)
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
  [[maybe_unused]] void DeleteTextureScrollerObject(void* const objectPtr)
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
  [[maybe_unused]] void DestructTextureScrollerObject(void* const)
  {}

  /**
   * Address: 0x00777F30 (FUN_00777F30)
   *
   * What it does:
   * Assigns texture-scroller lifecycle callbacks to reflected type-info slots.
   */
  [[maybe_unused]] gpg::RType* AssignTextureScrollerTypeLifecycleCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &NewTextureScrollerRef;
    typeInfo->ctorRefFunc_ = &CtrTextureScrollerRef;
    typeInfo->deleteFunc_ = &DeleteTextureScrollerObject;
    typeInfo->dtrFunc_ = &DestructTextureScrollerObject;
    return typeInfo;
  }

  /**
   * Address: 0x00777F80 (FUN_00777F80, gpg::SerSaveLoadHelper_CTextureScroller::Init)
   *
   * What it does:
   * Resolves reflected type metadata for `CTextureScroller`, installs
   * serializer callbacks from helper storage, and returns the load callback.
   */
  [[nodiscard]] gpg::RType::load_func_t InstallTextureScrollerSerializerCallbacks(
    SerSaveLoadHelperInitRuntimeView* const helper
  )
  {
    gpg::RType* type = moho::CTextureScroller::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CTextureScroller));
      moho::CTextureScroller::sType = type;
    }

    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
    }

    const bool saveWasNull = type->serSaveFunc_ == nullptr;
    const gpg::RType::load_func_t loadCallback = helper->mLoadCallback;
    type->serLoadFunc_ = loadCallback;

    if (!saveWasNull) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
    }

    type->serSaveFunc_ = helper->mSaveCallback;
    return loadCallback;
  }

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

      const float curAxisX = 1.0f - (((cur.w * cur.w) + (cur.z * cur.z)) * 2.0f);
      const float curAxisY = ((cur.z * cur.y) + (cur.w * cur.x)) * 2.0f;
      const float curAxisZ = ((cur.w * cur.y) - (cur.z * cur.x)) * 2.0f;

      const float lastAxisX = 1.0f - (((last.w * last.w) + (last.z * last.z)) * 2.0f);
      const float lastAxisY = ((last.w * last.x) + (last.z * last.y)) * 2.0f;
      const float lastAxisZ = ((last.w * last.y) - (last.z * last.x)) * 2.0f;

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
        ((1.0f - (((cur.y * cur.y) + (cur.z * cur.z)) * 2.0f)) + (1.0f - (((last.y * last.y) + (last.z * last.z)) * 2.0f))) * 0.5f;
      const float avgBasisZ =
        ((((cur.w * cur.z) - (cur.y * cur.x)) * 2.0f) + (((last.w * last.z) - (last.x * last.y)) * 2.0f)) * 0.5f;

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

  /**
   * Address: 0x00778320 (FUN_00778320)
   *
   * What it does:
   * Tail-thunk alias that forwards texture-scroller load lanes into
   * `CTextureScroller::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCTextureScrollerThunkA(
    CTextureScroller* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x007783F0 (FUN_007783F0)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards texture-scroller load lanes into
   * `CTextureScroller::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCTextureScrollerThunkB(
    CTextureScroller* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberDeserialize(archive);
    }
  }

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

  /**
   * Address: 0x00778330 (FUN_00778330)
   *
   * What it does:
   * Tail-thunk alias that forwards texture-scroller save lanes into
   * `CTextureScroller::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCTextureScrollerThunkA(
    const CTextureScroller* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00778400 (FUN_00778400)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards texture-scroller save lanes into
   * `CTextureScroller::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCTextureScrollerThunkB(
    const CTextureScroller* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberSerialize(archive);
    }
  }
} // namespace moho
