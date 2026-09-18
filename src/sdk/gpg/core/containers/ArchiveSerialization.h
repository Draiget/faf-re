#pragma once

#include <cstddef>

namespace boost
{
  template <class T>
  struct SharedPtrRaw;

  namespace detail
  {
    class sp_counted_base;
  } // namespace detail
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
   * `{sharedObject, sharedControl}` was one `boost::shared_ptr<void>` whose
   * copy/assign/destroy the emissions below are. The flat spelling kept here
   * is what every recovered call site already reads; regrouping them into the
   * two real sub-objects is a separate pass.
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
   *     and writes 3 (`Shared`), and hands `this+0x08` to the shared-pointer
   *     constructor as its `this`.
   * `ReadArchive::EndSection` (0x00952BD0) agrees from a fifth site: it tests
   * `cmp dword ptr [eax+esi+10h], 1` to pick the entries it may delete.
   */
  struct TrackedPointerInfo
  {
    void* object = nullptr;                                    // +0x00
    RType* type = nullptr;                                     // +0x04
    void* sharedObject = nullptr;                              // +0x08
    boost::detail::sp_counted_base* sharedControl = nullptr;    // +0x0C
    TrackedPointerState state = TrackedPointerState::Reserved;  // +0x10
  };
  static_assert(
    offsetof(TrackedPointerInfo, sharedObject) == 0x08, "TrackedPointerInfo::sharedObject offset must be 0x08"
  );
  static_assert(
    offsetof(TrackedPointerInfo, sharedControl) == 0x0C, "TrackedPointerInfo::sharedControl offset must be 0x0C"
  );
  static_assert(offsetof(TrackedPointerInfo, state) == 0x10, "TrackedPointerInfo::state offset must be 0x10");
  static_assert(sizeof(TrackedPointerInfo) == 0x14, "TrackedPointerInfo size must be 0x14");

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
   * Address: 0x00884C90 (FUN_00884C90)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<LaunchInfoBase>` with
   * archive ownership-state transitions (`UNOWNED -> SHARED`) and type checking.
   */
  void
  ReadPointerShared_LaunchInfoBase(boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x008843F0 (FUN_008843F0)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<SSessionSaveData>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void ReadPointerShared_SSessionSaveData(
    boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* archive, const RRef& ownerRef
  );

  /**
   * Address: 0x0055F990 (FUN_0055F990)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<CAniPose>`, promotes
   * unowned lanes to shared ownership, and validates pointee type.
   */
  void
  ReadPointerShared_CAniPose(boost::SharedPtrRaw<moho::CAniPose>& outPointer, ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x0054FF20 (FUN_0054FF20)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<CAniSkel>`, promotes
   * unowned lanes to shared ownership, and validates pointee type.
   */
  void
  ReadPointerShared_CAniSkel(boost::SharedPtrRaw<moho::CAniSkel>& outPointer, ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x0055F780 (FUN_0055F780)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<Stats<StatItem>>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void ReadPointerShared_Stats_StatItem(
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>>& outPointer, ReadArchive* archive, const RRef& ownerRef
  );

  /**
   * Address: 0x00757900 (FUN_00757900)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<ISimResources>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void ReadPointerShared_ISimResources(
    boost::SharedPtrRaw<moho::ISimResources>& outPointer, ReadArchive* archive, const RRef& ownerRef
  );

  /**
   * Address: 0x00551CC0 (FUN_00551CC0)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<CIntelGrid>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void
  ReadPointerShared_CIntelGrid(boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x005CE220 (FUN_005CE220, gpg::ReadArchive::ReadPointerShared_CIntelGrid2)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<CIntelGrid>` for the
   * legacy CIntelPosHandle serializer lane, promoting unowned entries to shared
   * ownership and validating pointee type.
   */
  void
  ReadPointerShared_CIntelGrid2(boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* archive, const RRef& ownerRef);

  /**
   * Address: 0x00642F60 (FUN_00642F60, gpg::ReadArchive::ReadPointerShared_RScaResource)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<RScaResource>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void ReadPointerShared_RScaResource(
    boost::SharedPtrRaw<moho::RScaResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
  );

  /**
   * Address: 0x0055A5D0 (FUN_0055A5D0)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<RScmResource>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void ReadPointerShared_RScmResource(
    boost::SharedPtrRaw<moho::RScmResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
  );

  /**
   * Address: 0x007142F0 (FUN_007142F0)
   *
   * What it does:
   * Reads one tracked pointer lane as `boost::shared_ptr<STrigger>`,
   * promotes unowned lanes to shared ownership, and validates pointee type.
   */
  void
  ReadPointerShared_STrigger(boost::SharedPtrRaw<moho::STrigger>& outPointer, ReadArchive* archive, const RRef& ownerRef);

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
