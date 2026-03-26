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
  class LaunchInfoBase;
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
    NullPointer = 1,
    ExistingPointer = 2,
    NewObject = 3,
    ObjectStart = 4,
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
} // namespace gpg
