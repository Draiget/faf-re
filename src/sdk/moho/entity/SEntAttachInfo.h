#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/render/camera/VTransform.h"

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
   *
   * +0x10 is one `VTransform`: the serializer (0x0067ED40 / 0x0067EDD0) moves it
   * through `VTransform`'s RType, and 0x005E3B50 copies it from a `VTransform`.
   */
  struct SEntAttachInfo
  {
    inline static gpg::RType* sType = nullptr;

    WeakPtr<Entity> mAttachTargetWeak; // +0x00

    std::int32_t mParentBoneIndex;  // +0x08
    std::int32_t mChildBoneIndex;   // +0x0C
    VTransform mRelativeTransform;  // +0x10

    /**
     * What it does:
     * Detached: no target, both bones -1, identity relative transform. Inlined
     * wherever an attach info is embedded (Entity ctors 0x006779E0/0x00678160,
     * CEffectImpl ctors 0x00659090/0x00659190, CEfxBeam ctor 0x006547C0).
     */
    SEntAttachInfo() noexcept
      : mParentBoneIndex(-1)
      , mChildBoneIndex(-1)
    {}

    /**
     * Address: 0x005E3B50 (FUN_005E3B50)
     *
     * What it does:
     * Links to `parent`'s weak chain (`parent ? parent + 4 : 0`, push-front),
     * stores both bone indices and copies `relativeTransform`. This in EAX,
     * parent in EDX, transform in ECX, the two bones on the stack, `ret 8`.
     * Callers: `CAiTransportImpl::TransportAddToStorage` (0x005E7C72),
     * `cfunc_EntityAttachToL` (0x0068BF44), `cfunc_EntityAttachBoneToL`
     * (0x0068C1E6), each with a default-constructed (identity) transform.
     */
    SEntAttachInfo(
      Entity* const parent,
      const std::int32_t childBoneIndex,
      const std::int32_t parentBoneIndex,
      const VTransform& relativeTransform
    ) noexcept
      : mAttachTargetWeak(parent)
      , mParentBoneIndex(parentBoneIndex)
      , mChildBoneIndex(childBoneIndex)
      , mRelativeTransform(relativeTransform)
    {}

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
    offsetof(SEntAttachInfo, mRelativeTransform) == 0x10, "SEntAttachInfo::mRelativeTransform offset must be 0x10"
  );
} // namespace moho
