#pragma once

#include <cstddef>
#include <filesystem>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CVirtualFileSystem.h"

namespace moho
{
  struct SFileWaitHandle;

  struct SVFSMountPoint
  {
    /**
     * Address: 0x004661F0 (FUN_004661F0, sub_4661F0)
     *
     * What it does:
     * Initializes one mount-point lane with empty directory state, `/` mount
     * root, and no mounted zip handle.
     */
    SVFSMountPoint();

    /**
     * Address: 0x004577D0 (FUN_004577D0, Moho::SVFSMountPoint::SVFSMountPoint)
     *
     * char *,char *
     *
     * What it does:
     * Initializes one mount-point lane from explicit directory/mountpoint text
     * tokens and clears mounted-zip ownership.
     */
    SVFSMountPoint(gpg::StrArg dir, gpg::StrArg mountpoint);

    SVFSMountPoint(const SVFSMountPoint& other);
    SVFSMountPoint(SVFSMountPoint&& other) noexcept;

    /**
     * Address: 0x004698D0 (FUN_004698D0, sub_4698D0)
     *
     * Moho::SVFSMountPoint const&
     *
     * What it does:
     * Copies directory + mountpoint strings and transfers zip-handle ownership
     * with correct retain/release semantics.
     */
    SVFSMountPoint& operator=(const SVFSMountPoint& other);
    SVFSMountPoint& operator=(SVFSMountPoint&& other) noexcept;

    /**
     * Address: 0x00466970 (FUN_00466970, sub_466970)
     *
     * What it does:
     * Releases mountpoint-owned zip-handle reference and clears owned strings.
     */
    ~SVFSMountPoint();

    msvc8::string mDir;        // +0x00
    msvc8::string mMountpoint; // +0x1C
    SFileWaitHandle* mZipHandle; // +0x38
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
     * Address: 0x00466250 (FUN_00466250, ??0CVFSImpl@Moho@@QAE@@Z)
     *
     * std::vector<Moho::SVFSMountPoint> const &,boost::filesystem::basic_path<std::string,boost::filesystem::path_traits> const &
     *
     * What it does:
     * Initializes VFS mountpoint storage and expands configured mount lanes.
     */
    CVFSImpl(const msvc8::vector<SVFSMountPoint>& mountpoints, const std::filesystem::path& launchDir);

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
     *
     * What it does:
     * Enumerates mounted files that match `queryPath` under `mountPrefix`,
     * traversing zip-backed and directory-backed lanes, then sorts and
     * de-duplicates the output list.
     */
    void EnumerateFiles(
      gpg::StrArg mountPrefix,
      gpg::StrArg queryPath,
      bool allowPrefixWildcard,
      msvc8::vector<msvc8::string>* outPaths
    ) override;

    /**
     * Address: 0x00467900 (FUN_00467900, Moho::CVFSImpl::Func4)
     * Slot: 5
     *
     * What it does:
     * Enumerates child mounted directories beneath `mountPrefix`, then sorts
     * and de-duplicates the output list.
     */
    void EnumerateChildren(gpg::StrArg mountPrefix, msvc8::vector<msvc8::string>* outPaths) override;

  private:
    /**
     * Address: 0x00466370 (FUN_00466370, Moho::CVFSImpl::AddMountPoint)
     *
     * What it does:
     * Resolves one configured mount source to concrete search-path candidates
     * and forwards each candidate to `AddSearchPath`.
     */
    void AddMountPoint(const SVFSMountPoint& mountPoint, const std::filesystem::path& launchDir);

    /**
     * Address: 0x004666A0 (FUN_004666A0, Moho::CVFSImpl::AddSearchPath)
     *
     * What it does:
     * Registers one resolved directory/zip search path under the source
     * mountpoint root, optionally enables disk-watch registration for
     * directory lanes, and mounts zip handles when needed.
     */
    void AddSearchPath(const SVFSMountPoint& mountPoint, const msvc8::string& resolvedPath, bool isDirectory);

  public:
    msvc8::vector<SVFSMountPoint> mMountpoints; // +0x04
  };

  /**
   * Address: 0x00467F90 (FUN_00467F90, ?VFS_Create@Moho@@...)
   *
   * What it does:
   * Allocates and returns one concrete `CVFSImpl` instance as the
   * `CVirtualFileSystem` interface.
   */
  [[nodiscard]] CVirtualFileSystem* VFS_Create(
    const msvc8::vector<SVFSMountPoint>& mountpoints,
    const std::filesystem::path& launchDir
  );

  static_assert(offsetof(CVFSImpl, mMountpoints) == 0x04, "CVFSImpl::mMountpoints offset must be 0x04");
  static_assert(sizeof(CVFSImpl) == 0x14, "CVFSImpl size must be 0x14");
} // namespace moho
