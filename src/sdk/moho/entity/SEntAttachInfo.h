#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Entity;

  /**
   * Address owner: Entity::mAttachInfo at +0x18C
   *
   * What it does:
   * Stores current parent-attach linkage and local attach transform.
   *
   * Notes from 0x00679680:
   * - first 8 bytes are `WeakPtr<Entity>` intrusive link state.
   * - owner slot stores encoded pointer to owner's weak-link head slot.
   * - second dword links this node into owner weak-chain.
   * - Bone indices default to -1 when detached.
   * - Orientation defaults to identity (w=1), relative position defaults to zero.
   */
  struct SEntAttachInfo
  {
    inline static gpg::RType* sType = nullptr;

    WeakPtr<Entity> mAttachTargetWeak; // +0x00

    std::int32_t mParentBoneIndex; // +0x08
    std::int32_t mChildBoneIndex;  // +0x0C
    float mRelativeOrientX;        // +0x10
    float mRelativeOrientY;        // +0x14
    float mRelativeOrientZ;        // +0x18
    float mRelativeOrientW;        // +0x1C
    float mRelativePosX;           // +0x20
    float mRelativePosY;           // +0x24
    float mRelativePosZ;           // +0x28

    [[nodiscard]] WeakPtr<Entity>& TargetWeakLink() noexcept
    {
      return mAttachTargetWeak;
    }

    [[nodiscard]] const WeakPtr<Entity>& TargetWeakLink() const noexcept
    {
      return mAttachTargetWeak;
    }

    [[nodiscard]] SEntAttachInfo*& NextAttachInfo() noexcept
    {
      return reinterpret_cast<SEntAttachInfo*&>(mAttachTargetWeak.nextInOwner);
    }

    [[nodiscard]] const SEntAttachInfo* NextAttachInfo() const noexcept
    {
      return reinterpret_cast<const SEntAttachInfo*>(mAttachTargetWeak.nextInOwner);
    }

    [[nodiscard]] bool HasAttachTarget() const noexcept
    {
      return TargetWeakLink().HasValue();
    }

    [[nodiscard]] Entity* GetAttachTargetEntity() const noexcept
    {
      return TargetWeakLink().GetObjectPtr();
    }

    [[nodiscard]] static SEntAttachInfo MakeDetached() noexcept
    {
      SEntAttachInfo info{};
      info.mAttachTargetWeak.ownerLinkSlot = nullptr;
      info.mAttachTargetWeak.nextInOwner = nullptr;
      info.mParentBoneIndex = -1;
      info.mChildBoneIndex = -1;
      info.mRelativeOrientX = 0.0f;
      info.mRelativeOrientY = 0.0f;
      info.mRelativeOrientZ = 0.0f;
      info.mRelativeOrientW = 1.0f;
      info.mRelativePosX = 0.0f;
      info.mRelativePosY = 0.0f;
      info.mRelativePosZ = 0.0f;
      return info;
    }

    /**
     * Address: 0x0067ED40 (FUN_0067ED40, Moho::SEntAttachInfo::MemberDeserialize)
     *
     * What it does:
     * Deserializes weak-parent linkage, bone indices, and relative attach transform payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0067EDD0 (FUN_0067EDD0, Moho::SEntAttachInfo::MemberSerialize)
     *
     * What it does:
     * Serializes weak-parent linkage, bone indices, and relative attach transform payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(sizeof(SEntAttachInfo) == 0x2C, "SEntAttachInfo size must be 0x2C");
  static_assert(
    offsetof(SEntAttachInfo, mAttachTargetWeak) == 0x00, "SEntAttachInfo::mAttachTargetWeak offset must be 0x00"
  );
  static_assert(
    offsetof(SEntAttachInfo, mParentBoneIndex) == 0x08, "SEntAttachInfo::mParentBoneIndex offset must be 0x08"
  );
  static_assert(
    offsetof(SEntAttachInfo, mChildBoneIndex) == 0x0C, "SEntAttachInfo::mChildBoneIndex offset must be 0x0C"
  );
  static_assert(
    offsetof(SEntAttachInfo, mRelativeOrientW) == 0x1C, "SEntAttachInfo::mRelativeOrientW offset must be 0x1C"
  );
  static_assert(offsetof(SEntAttachInfo, mRelativePosX) == 0x20, "SEntAttachInfo::mRelativePosX offset must be 0x20");
} // namespace moho
