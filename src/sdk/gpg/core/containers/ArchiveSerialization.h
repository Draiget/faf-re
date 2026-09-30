#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"

namespace boost
{
  template <class T>
  struct SharedPtrRaw;
} // namespace boost

namespace moho
{
  class StatItem;
  template <class T>
  class Stats;
  class Sim;
  class CAniSkel;
  class CAniPose;
  class CIntelGrid;
  class ISimResources;
  class LaunchInfoBase;
  class RScaResource;
  class RScmResource;
  struct STrigger;
  struct SSessionSaveData;
} // namespace moho

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RRef;
  class RType;

  /**
   * Strict weak ordering for reflected references.
   *
   * The binary compares the reflected type lane first and only falls back to
   * the underlying object pointer when the type lanes match.
   */
  struct RRefCompare
  {
    /**
     * Address: 0x0094F730 (FUN_0094F730, gpg::RRefCompare::operator())
     *
     * What it does:
     * Orders two reflected references lexicographically by reflected type lane
     * and then by object pointer lane.
     */
    [[nodiscard]] bool operator()(const RRef& lhs, const RRef& rhs) const noexcept;
  };
  static_assert(sizeof(RRefCompare) == 0x1, "RRefCompare size must be 0x1");

  /**
   * Address context:
   * - 0x00953CA0 (WriteArchive::Write)
   * - 0x00953DA0 (ReadArchive::Read)
   * - 0x00953720 (ReadArchive::ReadRawPointer)
   * - 0x00953320 (WriteArchive::WriteRawPointer)
   */
  enum class ArchiveToken : int
  {
    ObjectTerminator = 0,
    NewObjectToken = 1,
    NullPointerToken = 2,
    ExistingPointerToken = 3,
    ObjectStart = 4,

    // Compatibility aliases used by existing recovered call sites.
    NewObject = NewObjectToken,
    NullPointer = NullPointerToken,
    ExistingPointer = ExistingPointerToken,
  };

  /**
   * Address context:
   * - 0x00953320 (WriteArchive::WriteRawPointer)
   * - 0x00953720 (ReadArchive::ReadRawPointer)
   */
  enum class TrackedPointerState : int
  {
    Reserved = 0,
    Unowned = 1,
    Owned = 2,
    Shared = 3,
  };

  /**
   * One entry in the archive's pointer-tracking table
   * (`ReadArchive::mTrackedPtrs`, at +0x14 of the archive).
   *
   * The original field names survive in an assert string the binary still
   * carries: 0x00884CE6 pushes "ptrinfo.mObj.GetRType()->mDelete" alongside
   * the source path "c:\work\rts\main\code\src\libs\gpgcore/reflection/
   * serializat...". So `{object, type}` was one embedded `RRef mObj`, and
   * +0x08 is a `boost::shared_ptr<void>`: 0x00953720 copies an entry into the
   * table with `shared_count::operator=` (0x00422A70) on +0x0C, and the
   * construct result it copied from releases its own count as it dies
   * (0x0094F5A0). `{object, type}` stays flat because `RRef` is defined in
   * Reflection.h, which includes this header.
   *
   * The trailing three fields are ordered from four independent functions,
   * because a duplicate of this layout in ReadArchive.cpp had disagreed with
   * it and nothing was checking:
   *   0x00953B30 (`TrackPointer`) builds one on the stack - [+0x08]=0,
   *     [+0x0C]=0, [+0x10]=2 (`Owned`) - then runs the full
   *     `sp_counted_base::release()` on [+0x0C] as the temporary dies.
   *   0x00950EA0 copy-constructs n slots from one source - +0x00, +0x04 and
   *     +0x08 plain, +0x0C `add_ref_copy()`, +0x10 plain, stride 0x14.
   *   0x009506F0 copy-assigns a range - +0x0C takes the whole
   *     add-ref-new / release-old / store dance, +0x08 and +0x10 plain.
   *   0x00884C90 gates promote-to-shared on `cmp [edi+0x10], 1` (`Unowned`)
   *     and writes 3 (`Shared`), and assigns a fresh `shared_ptr<void>` to
   *     `this+0x08`.
   * `ReadArchive::EndSection` (0x00952BD0) agrees from a fifth site: it tests
   * `cmp dword ptr [eax+esi+10h], 1` to pick the entries it may delete.
   *
   * Address: 0x0094F5A0 (FUN_0094F5A0 -- the implicit destructor, which releases `sharedPtr`'s count; `ReadRawPointer`
   * 0x00953720 runs it on the construct result. Formerly `ReleaseTrackedPointerSharedControl` in
   * gpg/core/containers/ArchiveSerialization.cpp.)
   */
  struct TrackedPointerInfo
  {
    void* object = nullptr;                                    // +0x00
    RType* type = nullptr;                                     // +0x04
    boost::shared_ptr<void> sharedPtr;                         // +0x08
    TrackedPointerState state = TrackedPointerState::Reserved;  // +0x10
  };
  static_assert(offsetof(TrackedPointerInfo, sharedPtr) == 0x08, "TrackedPointerInfo::sharedPtr offset must be 0x08");
  static_assert(offsetof(TrackedPointerInfo, state) == 0x10, "TrackedPointerInfo::state offset must be 0x10");
  static_assert(sizeof(TrackedPointerInfo) == 0x14, "TrackedPointerInfo size must be 0x14");

  /**
   * What a type's construct hook (`RType::serConstructFunc_`) hands back to
   * `ReadArchive` when it builds an object from the stream: the tracked
   * pointer the object becomes, and whether its members are still to be read.
   * `ReadArchive` makes one per pointer on the stack, reserved and with member
   * loading on (0x00953720), asserts the hook left it reserved no longer
   * (`"constructResult.mInfo.mState != RESERVED"`, serialization.cpp line
   * 156), copies `mInfo` into its tracked-pointer table and reads the members
   * only when `mLoadMembers` is still set.
   */
  class SerConstructResult
  {
  public:
    /**
     * Address: 0x0094F5E0 (FUN_0094F5E0, gpg::SerConstructResult::SetOwned)
     *
     * What it does:
     * Marks load-construct result ownership as `OWNED` and stores the
     * constructed reflected reference.
     */
    void SetOwned(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F630 (FUN_0094F630, gpg::SerConstructResult::SetUnowned)
     *
     * What it does:
     * Marks load-construct result ownership as `UNOWNED` and stores the
     * constructed reflected reference.
     */
    void SetUnowned(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F680 (FUN_0094F680, gpg::SerConstructResult::SetShared)
     * Mangled: ?SetShared@SerConstructResult@gpg@@QAEXABVRRef@2@I@Z_0
     *
     * What it does:
     * Marks load-construct result ownership as `SHARED` and stores one
     * reflected reference directly.
     */
    void SetShared(const RRef& ref, unsigned int flags);

    /**
     * Address: 0x0094F6D0 (FUN_0094F6D0, gpg::SerConstructResult::SetShared)
     *
     * What it does:
     * Marks load-construct result ownership as `SHARED`, retains the shared
     * control block, and stores the reflected reference.
     */
    void SetShared(const boost::shared_ptr<void>& object, RType* type, unsigned int flags);

    TrackedPointerInfo mInfo{};  // +0x00
    bool mLoadMembers = true;    // +0x14
  };
  static_assert(offsetof(SerConstructResult, mLoadMembers) == 0x14, "SerConstructResult::mLoadMembers offset must be 0x14");
  static_assert(sizeof(SerConstructResult) == 0x18, "SerConstructResult size must be 0x18");

  /**
   * What a type's save-construct hook (`RType::serSaveConstructArgsFunc_`)
   * reports to `WriteArchive` after writing the arguments its construct hook
   * will need: how the pointer is owned, and whether the members still follow.
   * `WriteRawPointer` 0x00953320 starts it reserved with member writing on and
   * asserts the hook set an ownership (`"saveConstructArgsResult.mOwnership !=
   * RESERVED"`, serialization.cpp line 319).
   */
  class SerSaveConstructArgsResult
  {
  public:
    /**
     * Address: 0x0094F750 (FUN_0094F750, gpg::SerSaveConstructArgsResult::SetOwned)
     *
     * What it does:
     * Marks save-construct ownership as `OWNED` from the reserved state.
     */
    void SetOwned(unsigned int flags);

    /**
     * Address: 0x0094F790 (FUN_0094F790, gpg::SerSaveConstructArgsResult::SetUnowned)
     *
     * What it does:
     * Marks save-construct ownership as `UNOWNED` from the reserved state.
     */
    void SetUnowned(unsigned int flags);

    /**
     * Address: 0x0094F7D0 (FUN_0094F7D0, gpg::SerSaveConstructArgsResult::SetShared)
     *
     * What it does:
     * Marks save-construct ownership as `SHARED` from the reserved state.
     */
    void SetShared(unsigned int flags);

    TrackedPointerState mOwnership = TrackedPointerState::Reserved;  // +0x00
    bool mWriteMembers = true;                                      // +0x04
  };
  static_assert(
    offsetof(SerSaveConstructArgsResult, mWriteMembers) == 0x04, "SerSaveConstructArgsResult::mWriteMembers offset must be 0x04"
  );
  static_assert(sizeof(SerSaveConstructArgsResult) == 0x08, "SerSaveConstructArgsResult size must be 0x08");

  struct TypeHandle
  {
    RType* type = nullptr;
    int version = 0;
  };
  static_assert(sizeof(TypeHandle) == 0x08, "TypeHandle size must be 0x08");

  /**
   * Address: 0x00953720 (FUN_00953720)
   *
   * What it does:
   * Reads pointer token payload and resolves one tracked-pointer table lane.
   */
  TrackedPointerInfo& ReadRawPointer(ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x00953320 (FUN_00953320)
   *
   * What it does:
   * Writes tracked-pointer token payload and serializes newly seen pointees.
   */
  void WriteRawPointer(WriteArchive* archive, const RRef& objectRef, TrackedPointerState state, const RRef& ownerRef);

  /**
   * Address: 0x0094FEC0 (FUN_0094FEC0)
   *
   * What it does:
   * Wraps an ArchiveToken object in reflection reference form.
   */
  RRef RRef_ArchiveToken(ArchiveToken* token);

  /**
   * Address: 0x00756130 (FUN_00756130, sub_756130)
   *
   * What it does:
   * Wrapper that materializes one temporary `RRef_Sim` and copies its
   * object/type lanes into the destination ref.
   */
  RRef* AssignSimRef(RRef* outRef, moho::Sim* value);

  /**
   * Address: 0x0055D590 (FUN_0055D590, gpg::RFastVectorType_UnitWeaponInfo::SerSave)
   *
   * What it does:
   * Writes one contiguous `fastvector<UnitWeaponInfo>` payload as element count
   * plus each reflected lane in order. Declared here so the
   * `RFastVectorType<Moho::UnitWeaponInfo>` descriptor
   * (FastVectorUIntReflection.cpp) can bind it into `serSaveFunc_`, which is
   * the binary's only reference to this body.
   */
  void SaveFastVectorUnitWeaponInfo(WriteArchive* archive, int objectPtr, int version, RRef* ownerRef);

  /**
   * Address: 0x005C5860 (FUN_005C5860)
   *
   * What it does:
   * Writes one contiguous `vector<SPerArmyReconInfo>` payload by saving the
   * element count and each reflected lane in order. Declared here so
   * `SPerArmyReconInfoVectorTypeRuntime::Init` (ReconBlipTypeInfo.cpp) can
   * bind it into `serSaveFunc_`.
   */
  void SaveVectorSPerArmyReconInfo(WriteArchive* archive, int objectPtr, int version, RRef* ownerRef);

  /**
   * Address: 0x005C5700 (FUN_005C5700)
   *
   * What it does:
   * Reads one contiguous `vector<SPerArmyReconInfo>` payload by reading the
   * element count and that many reflected lanes into a fresh temporary
   * vector, which replaces the destination vector's storage. Declared here
   * so `SPerArmyReconInfoVectorTypeRuntime::Init` (ReconBlipTypeInfo.cpp)
   * can bind it into `serLoadFunc_`.
   */
  void LoadVectorSPerArmyReconInfo(ReadArchive* archive, int objectPtr, int version, RRef* ownerRef);
} // namespace gpg
