#pragma once

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

  struct TrackedPointerInfo
  {
    void* object = nullptr;
    RType* type = nullptr;
    TrackedPointerState state = TrackedPointerState::Reserved;
    void* sharedObject = nullptr;
    boost::detail::sp_counted_base* sharedControl = nullptr;
  };
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
} // namespace gpg
