#pragma once

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  struct SDiskFileInfo;

  class CVirtualFileSystem
  {
  public:
    /**
     * Address: 0x004661D0 (FUN_004661D0, scalar deleting thunk)
     *
     * What it does:
     * Releases virtual file-system implementations through the abstract vtable.
     */
    virtual ~CVirtualFileSystem();

    /**
     * Address: 0x00466A20 (FUN_00466A20, Moho::CVFSImpl::FindFile)
     * Slot: 1
     *
     * What it does:
     * Resolves one mounted path and fills disk metadata for the first matching entry.
     */
    virtual msvc8::string* FindFile(msvc8::string* outPath, gpg::StrArg sourcePath, SDiskFileInfo* outInfo) = 0;

    /**
     * Address: 0x00466C60 (FUN_00466C60, Moho::CVFSImpl::ToMountedPath)
     * Slot: 2
     *
     * What it does:
     * Maps an on-disk path to its mounted virtual-file-system path.
     */
    virtual msvc8::string* ToMountedPath(msvc8::string* outPath, gpg::StrArg sourcePath) = 0;

    /**
     * Address: 0x00466E50 (FUN_00466E50, Moho::CVFSImpl::GetFileInfo)
     * Slot: 3
     *
     * What it does:
     * Returns metadata for one mounted file path.
     */
    virtual bool GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo) = 0;

    /**
     * Address: 0x00467020 (FUN_00467020, Moho::CVFSImpl::Func3)
     * Slot: 4
     *
     * What it does:
     * Enumerates files under one mounted prefix and appends normalized results.
     */
    virtual void EnumerateFiles(
      gpg::StrArg mountPrefix,
      gpg::StrArg queryPath,
      bool allowPrefixWildcard,
      msvc8::vector<msvc8::string>* outPaths
    ) = 0;

    /**
     * Address: 0x00467900 (FUN_00467900, Moho::CVFSImpl::Func4)
     * Slot: 5
     *
     * What it does:
     * Enumerates child path entries under one mounted prefix.
     */
    virtual void EnumerateChildren(gpg::StrArg mountPrefix, msvc8::vector<msvc8::string>* outPaths) = 0;
  };
} // namespace moho
