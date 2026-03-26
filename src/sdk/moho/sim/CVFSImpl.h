#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CVirtualFileSystem.h"

namespace moho
{
  class CZipFile;

  struct SVFSMountPoint
  {
    msvc8::string mDir;        // +0x00
    msvc8::string mMountpoint; // +0x1C
    CZipFile* mZipHandle;      // +0x38
  };

  static_assert(offsetof(SVFSMountPoint, mDir) == 0x00, "SVFSMountPoint::mDir offset must be 0x00");
  static_assert(offsetof(SVFSMountPoint, mMountpoint) == 0x1C, "SVFSMountPoint::mMountpoint offset must be 0x1C");
  static_assert(offsetof(SVFSMountPoint, mZipHandle) == 0x38, "SVFSMountPoint::mZipHandle offset must be 0x38");
  static_assert(sizeof(SVFSMountPoint) == 0x3C, "SVFSMountPoint size must be 0x3C");

  /**
   * VFTABLE: 0x00E03560
   * COL: 0x00E5FFD4
   */
  class CVFSImpl : public CVirtualFileSystem
  {
  public:
    /**
     * Address: 0x004662F0 (FUN_004662F0, Moho::CVFSImpl::dtr)
     * Address: 0x00466320 (FUN_00466320, Moho::CVFSImpl::~CVFSImpl)
     * Slot: 0
     */
    ~CVFSImpl() override;

    /**
     * Address: 0x00466A20 (FUN_00466A20, Moho::CVFSImpl::FindFile)
     * Slot: 1
     *
     * std::string *,gpg::StrArg,Moho::SDiskFileInfo *
     *
     * What it does:
     * Resolves one mounted path to an on-disk/zip-backed path and writes the
     * first match to `outPath`.
     */
    msvc8::string* FindFile(msvc8::string* outPath, gpg::StrArg sourcePath, SDiskFileInfo* outInfo) override;

    /**
     * Address: 0x00466C60 (FUN_00466C60, Moho::CVFSImpl::ToMountedPath)
     * Slot: 2
     *
     * std::string *,gpg::StrArg
     *
     * What it does:
     * Converts one real path under mounted directories into mounted VFS path
     * form.
     */
    msvc8::string* ToMountedPath(msvc8::string* outPath, gpg::StrArg sourcePath) override;

    /**
     * Address: 0x00466E50 (FUN_00466E50, Moho::CVFSImpl::GetFileInfo)
     * Slot: 3
     *
     * gpg::StrArg,Moho::SDiskFileInfo *
     *
     * What it does:
     * Resolves metadata for one mounted path through the file wait-handle set.
     */
    bool GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo) override;

    /**
     * Address: 0x00467020 (FUN_00467020, Moho::CVFSImpl::Func3)
     * Slot: 4
     */
    void EnumerateFiles(
      gpg::StrArg mountPrefix,
      gpg::StrArg queryPath,
      bool allowPrefixWildcard,
      msvc8::vector<msvc8::string>* outPaths
    ) override = 0;

    /**
     * Address: 0x00467900 (FUN_00467900, Moho::CVFSImpl::Func4)
     * Slot: 5
     */
    void EnumerateChildren(gpg::StrArg mountPrefix, msvc8::vector<msvc8::string>* outPaths) override = 0;

  public:
    msvc8::vector<SVFSMountPoint> mMountpoints; // +0x04
  };

  static_assert(offsetof(CVFSImpl, mMountpoints) == 0x04, "CVFSImpl::mMountpoints offset must be 0x04");
  static_assert(sizeof(CVFSImpl) == 0x14, "CVFSImpl size must be 0x14");
} // namespace moho
