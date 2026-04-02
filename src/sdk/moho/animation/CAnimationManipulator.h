#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/containers/BitStorage32.h"
#include "moho/lua/CScrLuaBinderFwd.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  class Unit;

  using SAniManipBitStorage = SBitStorage32;

  struct SAniManipOwnerLink
  {
    SAniManipOwnerLink** mPrevSlot; // +0x00
    SAniManipOwnerLink* mNext;      // +0x04
  };

  static_assert(sizeof(SAniManipOwnerLink) == 0x08, "SAniManipOwnerLink size must be 0x08");

  class CAnimationManipulator : public IAniManipulator
  {
  public:
    using AnimationResourceRef = boost::SharedPtrRaw<void>;

    /**
     * Address: 0x0063F380 (FUN_0063F380, ??0CAnimationManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds IAniManipulator base state and initializes owner-link, bone-mask,
     * animation-resource, playback-rate, and runtime flags.
     */
    CAnimationManipulator();

    /**
     * Address: 0x0063F440 (FUN_0063F440, scalar deleting destructor thunk)
     * Address: 0x0063F8D0 (FUN_0063F8D0, ??1CAnimationManipulator@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0 (primary CTaskEvent/CScriptEvent view)
     */
    ~CAnimationManipulator() override;

    /**
     * Address: 0x0063EEE0 (FUN_0063EEE0, ?GetClass@CAnimationManipulator@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0063EF00 (FUN_0063EF00, ?GetDerivedObjectRef@CAnimationManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0063FDD0 (FUN_0063FDD0, CAnimationManipulator::ManipulatorUpdate)
     *
     * VFTable SLOT: 1 (primary CTaskEvent/CScriptEvent view)
     */
    bool ManipulatorUpdate() override;

    /**
     * Address: 0x0063F9E0 (FUN_0063F9E0)
     */
    void SetAnimationFraction(float fraction);

    /**
     * Address: 0x0063FA90 (FUN_0063FA90)
     */
    void SetAnimationTime(float timeSeconds);

    /**
     * Address: 0x0063FB10 (FUN_0063FB10)
     */
    bool UpdateTriggeredState();

    /**
     * Address: 0x0063FBA0 (FUN_0063FBA0)
     */
    void SetAnimationResource(const AnimationResourceRef& resource, bool looping);

    /**
     * Address: 0x006412C0 (FUN_006412C0)
     */
    void SetBoneEnabled(std::int32_t boneIndex, bool includeDescendants, bool enabled);

    [[nodiscard]] float GetRate() const noexcept;
    void SetRate(float rate);
    [[nodiscard]] float GetAnimationFraction() const;
    [[nodiscard]] float GetAnimationTime() const noexcept;
    [[nodiscard]] float GetAnimationDuration() const;
    void SetOverwriteMode(bool enabled) noexcept;
    void SetDisableOnSignal(bool enabled) noexcept;
    void SetDirectionalAnim(bool enabled) noexcept;

    void InitializeBoneMask(std::uint32_t boneCount);

  public:
    static gpg::RType* sType;

    SAniManipOwnerLink mOwnerLink;      // +0x80
    SAniManipBitStorage mBoneMask;      // +0x88
    AnimationResourceRef mAnimationRef; // +0x9C
    float mRate;                        // +0xA4
    float mAnimationTime;               // +0xA8
    float mLastFramePosition;           // +0xAC
    bool mLooping;                      // +0xB0
    bool mFrameChanged;                 // +0xB1
    bool mIgnoreMotionScaling;          // +0xB2
    bool mOverwriteMode;                // +0xB3
    bool mDisableOnSignal;              // +0xB4
    bool mDirectionalAnim;              // +0xB5
    std::uint8_t mReservedB6[2]{};      // +0xB6
  };

  using CAnimationManipulatorPlayAnim_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetRate_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetRate_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationFraction_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetAnimationFraction_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationTime_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetAnimationTime_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorGetAnimationDuration_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetBoneEnabled_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetOverwriteMode_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetDisableOnSignal_LuaFuncDef = ::moho::CScrLuaBinder;
  using CAnimationManipulatorSetDirectionalAnim_LuaFuncDef = ::moho::CScrLuaBinder;

  class CAnimationManipulatorConstruct
  {
  public:
    /**
     * Address: 0x0063F220 (FUN_0063F220, Moho::CAnimationManipulatorConstruct::Construct)
     *
     * What it does:
     * Allocates one `CAnimationManipulator`, runs constructor setup, and
     * returns an unowned reflected reference through `SerConstructResult`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00642340 (FUN_00642340, Moho::CAnimationManipulatorConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `CAnimationManipulator`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00641E70 (FUN_00641E70, sub_641E70)
     * Slot: 0
     *
     * What it does:
     * Installs serialization-construct and delete callbacks into
     * CAnimationManipulator RTTI descriptor.
     */
    virtual void RegisterConstructFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CAnimationManipulatorSerializer
  {
  public:
    /**
     * Address: 0x0063F2C0 (FUN_0063F2C0, Moho::CAnimationManipulatorSerializer::Deserialize)
     *
     * What it does:
     * Loads `CAnimationManipulator` serialization payload (base IAniManipulator
     * lane, goal-link lane, bit-mask lane, shared animation resource, and
     * playback/flag scalars) into an existing object.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0063F2D0 (FUN_0063F2D0, Moho::CAnimationManipulatorSerializer::Serialize)
     *
     * What it does:
     * Saves `CAnimationManipulator` serialization payload (base IAniManipulator
     * lane, goal-link lane, bit-mask lane, shared animation resource, and
     * playback/flag scalars) from an existing object.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00641EF0 (FUN_00641EF0, sub_641EF0)
     * Slot: 0
     *
     * What it does:
     * Installs CAnimationManipulator load/save callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CAnimationManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0063F0E0 (FUN_0063F0E0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CAnimationManipulatorTypeInfo() override;

    /**
     * Address: 0x0063F0D0 (FUN_0063F0D0, ?GetName@CAnimationManipulatorTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0063F0A0 (FUN_0063F0A0, ?Init@CAnimationManipulatorTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAnimationManipulator`
     * (`sizeof = 0xB8`) and registers `IAniManipulator` as base metadata.
     */
    void Init() override;
  };

  static_assert(
    offsetof(CAnimationManipulator, mOwnerLink) == 0x80, "CAnimationManipulator::mOwnerLink offset must be 0x80"
  );
  static_assert(
    offsetof(CAnimationManipulator, mBoneMask) == 0x88, "CAnimationManipulator::mBoneMask offset must be 0x88"
  );
  static_assert(
    offsetof(CAnimationManipulator, mAnimationRef) == 0x9C, "CAnimationManipulator::mAnimationRef offset must be 0x9C"
  );
  static_assert(offsetof(CAnimationManipulator, mRate) == 0xA4, "CAnimationManipulator::mRate offset must be 0xA4");
  static_assert(
    offsetof(CAnimationManipulator, mAnimationTime) == 0xA8, "CAnimationManipulator::mAnimationTime offset must be 0xA8"
  );
  static_assert(
    offsetof(CAnimationManipulator, mLastFramePosition) == 0xAC,
    "CAnimationManipulator::mLastFramePosition offset must be 0xAC"
  );
  static_assert(
    offsetof(CAnimationManipulator, mLooping) == 0xB0, "CAnimationManipulator::mLooping offset must be 0xB0"
  );
  static_assert(
    offsetof(CAnimationManipulator, mOverwriteMode) == 0xB3, "CAnimationManipulator::mOverwriteMode offset must be 0xB3"
  );
  static_assert(
    offsetof(CAnimationManipulator, mDisableOnSignal) == 0xB4,
    "CAnimationManipulator::mDisableOnSignal offset must be 0xB4"
  );
  static_assert(
    offsetof(CAnimationManipulator, mDirectionalAnim) == 0xB5,
    "CAnimationManipulator::mDirectionalAnim offset must be 0xB5"
  );
  static_assert(sizeof(CAnimationManipulator) == 0xB8, "CAnimationManipulator size must be 0xB8");
  static_assert(sizeof(CAnimationManipulatorConstruct) == 0x14, "CAnimationManipulatorConstruct size must be 0x14");
  static_assert(sizeof(CAnimationManipulatorSerializer) == 0x14, "CAnimationManipulatorSerializer size must be 0x14");
  static_assert(sizeof(CAnimationManipulatorTypeInfo) == 0x64, "CAnimationManipulatorTypeInfo size must be 0x64");
} // namespace moho
