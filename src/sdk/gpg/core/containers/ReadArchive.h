// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a reconstruction target; keep address docs in sync with recovered bodies.
#pragma once

#include <cstddef>
#include <cstdio>

#include "ArchiveSerialization.h"
#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace msvc8
{
  struct string;
}

namespace gpg
{
  class RIndexed;
  class RRef;
  class RType;

  /**
   * VFTABLE: 0x00D48D14
   * COL:  0x00E53B84
   */
  class ReadArchive
  {
  public:
    /**
     * Address: 0x00953700 (FUN_00953700)
     * Demangled: gpg::ReadArchive::dtr
     *
     * What it does:
     * Destroys read-archive bookkeeping state.
     */
    virtual ~ReadArchive();

    /**
     * Address: 0x00A82547
     * Slot: 1
     * Demangled: _purecall
     */
    virtual void ReadBytes(char*, size_t) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     * Demangled: _purecall
     */
    virtual void ReadString(msvc8::string*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual void ReadFloat(float*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 4
     * Demangled: _purecall
     */
    virtual void ReadUInt64(unsigned __int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual void ReadInt64(__int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual void ReadULong(unsigned long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void ReadLong(long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void ReadUInt(unsigned int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     */
    virtual void ReadInt(int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void ReadUShort(unsigned short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 11
     * Demangled: _purecall
     */
    virtual void ReadShort(short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual void ReadUByte(unsigned __int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 13
     * Demangled: _purecall
     */
    virtual void ReadByte(__int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 14
     * Demangled: _purecall
     */
    virtual void ReadBool(bool*) = 0;

    /**
     * Address: 0x00952BD0 (FUN_00952BD0)
     * Slot: 15
     * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
     *
     * What it does:
     * Releases tracked pointer/type-handle section state.
     */
    virtual void EndSection(bool);

    /**
     * Address: 0x00A82547
     * Slot: 16
     * Demangled: _purecall
     */
    virtual int NextMarker() = 0;

    /**
     * Address: 0x00953DA0 (FUN_00953DA0)
     * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const
     * &)
     *
     * What it does:
     * Reads one typed object payload using reflection serializer callbacks.
     */
    void Read(const gpg::RType* type, void* object, const gpg::RRef& ownerRef);

    /**
     * Address: 0x00952F10 (FUN_00952F10)
     * Demangled: gpg::ReadArchive::ReadTypeHandle
     *
     * What it does:
     * Reads or resolves reflected type/version handle from archive token stream.
     */
    TypeHandle ReadTypeHandle();

  protected:
    msvc8::vector<TypeHandle> mTypeHandles;
    msvc8::vector<TrackedPointerInfo> mTrackedPtrs;
    TrackedPointerInfo mNullTrackedPointer;

    friend TrackedPointerInfo& ReadRawPointer(ReadArchive* archive, const RRef& ownerRef);
    friend void
    ReadPointerShared_LaunchInfoBase(boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_SSessionSaveData(
      boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
  };
  static_assert(sizeof(ReadArchive) == 0x38, "ReadArchive size must be 0x38");

  /**
   * Address: 0x009048B0 (FUN_009048B0)
   * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
   *
   * What it does:
   * Creates one file-backed concrete `ReadArchive` for save/load serializers.
   */
  ReadArchive* CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file);
} // namespace gpg
