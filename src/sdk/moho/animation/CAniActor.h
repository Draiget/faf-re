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
     * Initializes actor pose handles from `{priorPose, pose}` and self-links
     * the manipulator intrusive list head.
     */
    CAniActor(const boost::SharedPtrRaw<CAniPose>& priorPose, const boost::SharedPtrRaw<CAniPose>& pose);

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
    static void MemberConstruct(gpg::SerConstructResult* result);

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
     * Replaces both `mPose` and `mPriorPose` raw shared-ptr lanes in one call,
     * retaining new control blocks and releasing prior ones. Out-of-line
     * helper emitted for callers (e.g. `Unit::SetPoses`) that assign both
     * pose lanes together; preserves VC8 ordering (use_count_++ before
     * release() on the swapped-out partner).
     */
    void AssignPoses(
      const boost::SharedPtrRaw<CAniPose>& pose,
      const boost::SharedPtrRaw<CAniPose>& priorPose
    ) noexcept;

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

    boost::SharedPtrRaw<CAniPose> mPose;                       // +0x00
    boost::SharedPtrRaw<CAniPose> mPriorPose;                  // +0x08
    TDatList<IAniManipulator, void> mManipulatorsByPrecedence; // +0x10
  };

  class CAniActorConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD2B20 (FUN_00BD2B20, dynamic initializer for the global
     * `CAniActorConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CAniActorConstruct();

    /**
     * Address: 0x00BFACD0 (FUN_00BFACD0, Moho::CAniActorConstruct::~CAniActorConstruct)
     */
    ~CAniActorConstruct();

    /**
     * Address: 0x0063B020 (FUN_0063B020, Moho::CAniActorConstruct::Construct)
     *
     * What it does:
     * Dispatches construct callback flow into `CAniActor::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0063CAB0 (FUN_0063CAB0, Moho::CAniActorConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting teardown for one constructed `CAniActor`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0063C190 (FUN_0063C190, Moho::CAniActorConstruct::Init)
     *
     * What it does:
     * Installs construct/delete callbacks into `CAniActor` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mSerConstructFunc; // +0x0C
    gpg::RType::delete_func_t mDeleteFunc;           // +0x10
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
  using CAniActorSerializer = gpg::SerSaveLoadHelper<CAniActor>;

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
   * Constructs startup-owned `CAniActorTypeInfo` and installs process-exit cleanup.
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
  static_assert(
    offsetof(CAniActorConstruct, mSerConstructFunc) == 0x0C,
    "CAniActorConstruct::mSerConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CAniActorConstruct, mDeleteFunc) == 0x10, "CAniActorConstruct::mDeleteFunc offset must be 0x10"
  );
  static_assert(sizeof(CAniActorConstruct) == 0x14, "CAniActorConstruct size must be 0x14");
  static_assert(sizeof(CAniActorTypeInfo) == 0x64, "CAniActorTypeInfo size must be 0x64");
} // namespace moho
