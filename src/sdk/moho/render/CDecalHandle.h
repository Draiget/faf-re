#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/render/CDecalTypes.h"
#include "moho/script/CScriptObject.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E372F4
   * COL: 0x00E91714
   */
  class CDecalHandle : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x007788B0 (FUN_007788B0, Moho::CDecalHandle::GetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for `CDecalHandle`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

    /**
     * Address: 0x007788F0 (FUN_007788F0, Moho::CDecalHandle::CDecalHandle)
     *
     * What it does:
     * Initializes CScriptObject base state, resets intrusive-list links, and
     * zeroes runtime decal-visibility bookkeeping.
     */
    CDecalHandle();

    /**
     * Address: 0x00778980 (FUN_00778980, Moho::CDecalHandle::CDecalHandle)
     *
     * What it does:
     * Binds one script-visible decal-handle object, copies decal payload, and
     * seeds per-handle visibility/runtime tick lanes.
     */
    CDecalHandle(
      LuaPlus::LuaState* state,
      std::uint32_t objectId,
      const SDecalInfo& info,
      std::uint32_t createdAtTick
    );

    /**
     * Address: 0x0077F1E0 (FUN_0077F1E0, Moho::CDecalHandle::MemberDeserialize)
     *
     * What it does:
     * Deserializes base script-object lanes, decal payload, army visibility,
     * and creation tick from the archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0077F280 (FUN_0077F280, Moho::CDecalHandle::MemberSerialize)
     *
     * What it does:
     * Serializes base script-object lanes, decal payload, army visibility, and
     * creation tick into the archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x007788B0 (FUN_007788B0, Moho::CDecalHandle::GetClass)
     * Slot: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x007788D0 (FUN_007788D0, Moho::CDecalHandle::GetDerivedObjectRef)
     * Slot: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00778B40 (FUN_00778B40, Moho::CDecalHandle::dtr)
     * Address: 0x00778C10 (FUN_00778C10, Moho::CDecalHandle::~CDecalHandle body)
     * Slot: 2
     */
    ~CDecalHandle() override;

    [[nodiscard]]
    static CDecalHandle* FromListNode(CDecalHandleListNode* node) noexcept;

    [[nodiscard]]
    static const CDecalHandle* FromListNode(const CDecalHandleListNode* node) noexcept;

  public:
    CDecalHandleListNode mListNode;       // +0x34
    SDecalInfo mInfo;                     // +0x3C
    std::uint32_t mArmyVisibilityFlags;   // +0xCC
    std::uint8_t mVisibleInFocus;         // +0xD0
    std::uint8_t mPadD1[0x03];
    std::uint32_t mCreatedAtTick;         // +0xD4
  };

  template <>
  class CScrLuaMetatableFactory<CDecalHandle> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CDecalHandle>) == 0x08,
    "CScrLuaMetatableFactory<CDecalHandle> size must be 0x08"
  );

  /**
   * Address: 0x0077D450 (FUN_0077D450, func_CreateCDecalHandleObject)
   *
   * What it does:
   * Returns cached `CDecalHandle` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_CreateCDecalHandleObject(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * VFTABLE: 0x00E267D4
   * COL: 0x00E7F224
   */
  using CDecalHandleDestroy_LuaFuncDef = ::moho::CScrLuaBinder;

  static_assert(offsetof(CDecalHandle, mListNode) == 0x34, "CDecalHandle::mListNode offset must be 0x34");
  static_assert(offsetof(CDecalHandle, mInfo) == 0x3C, "CDecalHandle::mInfo offset must be 0x3C");
  static_assert(
    offsetof(CDecalHandle, mArmyVisibilityFlags) == 0xCC, "CDecalHandle::mArmyVisibilityFlags offset must be 0xCC"
  );
  static_assert(offsetof(CDecalHandle, mVisibleInFocus) == 0xD0, "CDecalHandle::mVisibleInFocus offset must be 0xD0");
  static_assert(offsetof(CDecalHandle, mCreatedAtTick) == 0xD4, "CDecalHandle::mCreatedAtTick offset must be 0xD4");
  static_assert(sizeof(CDecalHandle) == 0xD8, "CDecalHandle size must be 0xD8");
} // namespace moho
