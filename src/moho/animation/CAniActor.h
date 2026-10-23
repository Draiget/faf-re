#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/containers/TDatList.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

namespace LuaPlus
{
  class LuaStackObject;
} // namespace LuaPlus

namespace moho
{
  class CAniPose;
  class CAniSkel;
  class IAniManipulator;
  class VTransform;

  class CAniActor
  {
  public:
    CAniActor() = default;

    /**
     * Address: 0x0063A8F0 (FUN_0063A8F0, ??0CAniActor@Moho@@QAE@ABV?$shared_ptr@VCAniPose@Moho@@@boost@@0@Z)
     *
     * What it does:
     * Copies both pose handles (current pose first: the binary takes it in ECX
     * and stores it at +0x00) and self-links the manipulator list head.
     */
    CAniActor(const boost::shared_ptr<CAniPose>& pose, const boost::shared_ptr<CAniPose>& priorPose);

    /**
     * Address: 0x0063A930 (FUN_0063A930, ??1CAniActor@Moho@@QAE@XZ)
     *
     * What it does:
     * Deletes all linked manipulators, unlinks the actor list head, and
     * releases pose shared-pointer ownership lanes.
     */
    ~CAniActor();

    /**
     * Address: 0x0063B030 (FUN_0063B030, Moho::CAniActor::MemberConstruct)
     *
     * What it does:
     * Allocates one `CAniActor` and publishes it as an unowned serialization
     * construct result.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x0063E200 (FUN_0063E200, sub_63E200)
     *
     * What it does:
     * Loads pose pointers and owned manipulator chain from archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0063E2A0 (FUN_0063E2A0, sub_63E2A0)
     *
     * What it does:
     * Saves pose pointers and owned manipulator chain to archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005E3CF0 (FUN_005E3CF0, ?GetSkeleton@CAniActor@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns the current skeleton handle from the actor-owned pose object.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

    /**
     * Address: 0x005BDD50 (FUN_005BDD50, ?GetPoseShared@CAniActor@Moho@@QBE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared-ptr handle to this actor's current pose.
     */
    [[nodiscard]]
    boost::shared_ptr<CAniPose> GetPoseShared() const;

    /**
     * Address: 0x005BDD70 (FUN_005BDD70, ?GetPriorPoseShared@CAniActor@Moho@@QBE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared-ptr handle to this actor's prior pose.
     */
    [[nodiscard]]
    boost::shared_ptr<CAniPose> GetPriorPoseShared() const;

    /**
     * Address: 0x0063AA20 (FUN_0063AA20)
     *
     * What it does:
     * Replaces both pose handles; `Unit::SetPoses` calls it.
     */
    void AssignPoses(const boost::shared_ptr<CAniPose>& pose, const boost::shared_ptr<CAniPose>& priorPose) noexcept;

    /**
     * Address: 0x0063AA80 (FUN_0063AA80, ?UpdateManipulators@CAniActor@Moho@@QAEXABVVTransform@2@@Z)
     *
     * IDA signature:
     * void __thiscall Moho::CAniActor::UpdateManipulators(Moho::CAniActor *this, struct Moho::VTransform *a2);
     *
     * What it does:
     * Advances this actor one animation step: retires the current pose into
     * `mPriorPose`, installs a fresh copy of it as `mPose`, rebuilds that copy's
     * bone transforms under `worldTransform`, then runs every enabled
     * manipulator in precedence order.
     */
    void UpdateManipulators(const VTransform& worldTransform);

    /**
     * Address: 0x0063AD40 (FUN_0063AD40, Moho::CAniActor::ResolveBoneIndex)
     *
     * What it does:
     * Resolves one Lua bone selector (index/name/nil) into a validated bone
     * index for this actor's current skeleton.
     */
    [[nodiscard]] int ResolveBoneIndex(LuaPlus::LuaStackObject& boneArg);

    /**
     * Address: 0x0063AB50 (FUN_0063AB50, Moho::CAniActor::EnableBoneIndex)
     *
     * What it does:
     * Enables/disables all manipulator watch-bone bindings that target one
     * exact bone index.
     */
    void EnableBoneIndex(bool enabled, int index);

    /**
     * Address: 0x0063ABC0 (FUN_0063ABC0, Moho::CAniActor::EnableBoneString)
     *
     * What it does:
     * Enables/disables the first wildcard-matching watch-bone binding per
     * manipulator.
     */
    void EnableBoneString(const char* boneName, bool enabled);

    /**
     * Address: 0x0063AC00 (FUN_0063AC00, Moho::CAniActor::KillManipulatorByBoneIndex)
     *
     * What it does:
     * Deletes each manipulator whose watch-bone list contains `index`.
     */
    void KillManipulatorByBoneIndex(int index);

    /**
     * Address: 0x0063AC50 (FUN_0063AC50, Moho::CAniActor::KillManipulatorsByBonePattern)
     *
     * What it does:
     * Deletes each manipulator that has at least one watch bone whose skeleton
     * name wildcard-matches `bonePattern`.
     */
    void KillManipulatorsByBonePattern(const char* bonePattern);

    /**
     * Address: 0x0063ACA0 (FUN_0063ACA0, Moho::CAniActor::KillManipulator)
     *
     * What it does:
     * Deletes the exact manipulator instance when that object is linked in this
     * actor's precedence list.
     */
    void KillManipulator(IAniManipulator* manipulator);

  public:
    static gpg::RType* sType;

    boost::shared_ptr<CAniPose> mPose;                         // +0x00
    boost::shared_ptr<CAniPose> mPriorPose;                    // +0x08
    TDatList<IAniManipulator, void> mManipulatorsByPrecedence; // +0x10
  };

  /**
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CAniActor>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_CAniActorSerializer`):
   *    0x00BD2B60 (__xc_a-reachable; dead zero-xref COMDAT duplicate:
   *    0x0063C1E0)
   *  - dtor: 0x00BFAD00 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x0063C210
   *  - Deserialize(): 0x0063B0A0
   *  - Serialize(): 0x0063B0C0
   */
  struct CAniActorSerializer : gpg::SerSaveLoadHelper<CAniActor>
  {};

  class CAniActorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0063A770 (FUN_0063A770, ??0CAniActorTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Preregisters `CAniActor` RTTI ownership for lazy type lookup.
     */
    CAniActorTypeInfo();

    /**
     * Address: 0x0063A800 (FUN_0063A800, Moho::CAniActorTypeInfo::dtr)
     *
     * VFTable SLOT: 2
     */
    ~CAniActorTypeInfo() override;

    /**
     * Address: 0x0063A7F0 (FUN_0063A7F0, Moho::CAniActorTypeInfo::GetName)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0063A7D0 (FUN_0063A7D0, Moho::CAniActorTypeInfo::Init)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BD2B00 (FUN_00BD2B00, register_CAniActorTypeInfo)
   *
   * What it does:
   * Constructs the static `CAniActorTypeInfo` object.
   */
  void register_CAniActorTypeInfo();

  /**
   * Address: 0x00BD2B60 (FUN_00BD2B60, register_CAniActorSerializer)
   *
   * What it does:
   * Forces this translation unit's global `CAniActorSerializer` instance to
   * link into the reflection bootstrap sequence. The ctor/vtable-install/
   * atexit-dtor-registration sequence this address decompiles to is MSVC's
   * own compiler-generated dynamic initializer for that global, not
   * hand-written source -- see `gpg::SerSaveLoadHelper<T>` in Reflection.h.
   */
  void register_CAniActorSerializer();

  static_assert(offsetof(CAniActor, mPose) == 0x00, "CAniActor::mPose offset must be 0x00");
  static_assert(offsetof(CAniActor, mPriorPose) == 0x08, "CAniActor::mPriorPose offset must be 0x08");
  static_assert(
    offsetof(CAniActor, mManipulatorsByPrecedence) == 0x10,
    "CAniActor::mManipulatorsByPrecedence offset must be 0x10"
  );
  static_assert(sizeof(CAniActor) == 0x18, "CAniActor size must be 0x18");
  static_assert(sizeof(CAniActorTypeInfo) == 0x64, "CAniActorTypeInfo size must be 0x64");
} // namespace moho
