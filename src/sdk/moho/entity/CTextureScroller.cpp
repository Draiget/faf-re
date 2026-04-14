#include "moho/entity/CTextureScroller.h"

#include <cmath>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/VTransform.h"

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
} // namespace

namespace moho
{
  gpg::RType* SScroller::sType = nullptr;

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
    mScroller.mType = static_cast<std::int32_t>(TextureScrollerMode::None);
    mScroller.mFloat04 = 0.0f;
    mScroller.mFloat08 = 0.0f;
    mScroller.mFloat0C = 0.0f;
    mScroller.mFloat10 = 0.0f;
    mScroller.mScroll1.x = 0.0f;
    mScroller.mScroll1.y = 0.0f;
    mScroller.mScroll2.x = 0.0f;
    mScroller.mScroll2.y = 0.0f;
    mScroller.mFloat24 = 1.0f;
    mScroller.mFloat28 = 1.0f;

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

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);
    archive->Read(scrollerType, &mScroller, nullOwner);

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

    gpg::RType* const scrollerType = CachedScrollerType();
    GPG_ASSERT(scrollerType != nullptr);
    archive->Write(scrollerType, &mScroller, nullOwner);

    archive->WriteBool(mDir[0] != 0u);
    archive->WriteBool(mDir[1] != 0u);
    archive->WriteInt(mSpeed[0]);
    archive->WriteInt(mSpeed[1]);
  }
} // namespace moho
