#include "moho/sim/CVFSImpl.h"

#include <algorithm>
#include <cstddef>

#include "gpg/core/containers/String.h"
#include "moho/misc/FileWaitHandleSet.h"

namespace
{
  [[nodiscard]] const char* SafePathArg(const gpg::StrArg sourcePath)
  {
    return sourcePath != nullptr ? sourcePath : "";
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00466320 (FUN_00466320, Moho::CVFSImpl::~CVFSImpl)
   */
  CVFSImpl::~CVFSImpl() = default;

  /**
   * Address: 0x00466A20 (FUN_00466A20, Moho::CVFSImpl::FindFile)
   *
   * std::string *,gpg::StrArg,Moho::SDiskFileInfo *
   *
   * What it does:
   * Resolves a mounted path to on-disk/zip-backed path and stores the first
   * matching real path into `outPath`.
   */
  msvc8::string* CVFSImpl::FindFile(msvc8::string* const outPath, const gpg::StrArg sourcePath, SDiskFileInfo* const outInfo)
  {
    if (outPath == nullptr) {
      return nullptr;
    }

    const msvc8::string loweredPath = gpg::STR_ToLower(SafePathArg(sourcePath));
    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      if (!gpg::STR_StartsWith(loweredPath.c_str(), mountpoint.mMountpoint.c_str())) {
        continue;
      }

      const std::size_t mountpointSize = mountpoint.mMountpoint.size();
      const std::size_t suffixStart =
        mountpointSize == 0 ? 0u : std::min(loweredPath.size(), mountpointSize - 1u);
      msvc8::string diskPath = mountpoint.mDir + (loweredPath.c_str() + suffixStart);
      for (std::size_t index = mountpoint.mDir.size(); index < diskPath.size(); ++index) {
        if (diskPath[index] == '/') {
          diskPath[index] = '\\';
        }
      }

      FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet != nullptr &&
          waitHandleSet->GetFileInfo(diskPath.c_str(), outInfo, mountpoint.mZipHandle != nullptr)) {
        outPath->assign_owned(diskPath.view());
        return outPath;
      }
    }

    outPath->clear();
    return outPath;
  }

  /**
   * Address: 0x00466C60 (FUN_00466C60, Moho::CVFSImpl::ToMountedPath)
   *
   * std::string *,gpg::StrArg
   *
   * What it does:
   * Maps one on-disk path under mounted directories back to VFS mountpoint form.
   */
  msvc8::string* CVFSImpl::ToMountedPath(msvc8::string* const outPath, const gpg::StrArg sourcePath)
  {
    if (outPath == nullptr) {
      return nullptr;
    }

    const msvc8::string loweredPath = gpg::STR_ToLower(SafePathArg(sourcePath));
    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      if (!gpg::STR_StartsWith(loweredPath.c_str(), mountpoint.mDir.c_str())) {
        continue;
      }

      const std::size_t dirSize = mountpoint.mDir.size();
      if (loweredPath.size() <= dirSize || loweredPath[dirSize] != '\\') {
        continue;
      }

      msvc8::string mountedPath = mountpoint.mMountpoint + (loweredPath.c_str() + dirSize + 1u);
      for (std::size_t index = mountpoint.mMountpoint.size(); index < mountedPath.size(); ++index) {
        if (mountedPath[index] == '\\') {
          mountedPath[index] = '/';
        }
      }
      outPath->assign_owned(mountedPath.view());
      return outPath;
    }

    outPath->clear();
    return outPath;
  }

  /**
   * Address: 0x00466E50 (FUN_00466E50, Moho::CVFSImpl::GetFileInfo)
   *
   * gpg::StrArg,Moho::SDiskFileInfo *
   *
   * What it does:
   * Resolves metadata for one mounted path via wait-handle set lookup.
   */
  bool CVFSImpl::GetFileInfo(const gpg::StrArg sourcePath, SDiskFileInfo* const outInfo)
  {
    const msvc8::string loweredPath = gpg::STR_ToLower(SafePathArg(sourcePath));
    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      if (!gpg::STR_StartsWith(loweredPath.c_str(), mountpoint.mMountpoint.c_str())) {
        continue;
      }

      const std::size_t mountpointSize = mountpoint.mMountpoint.size();
      const std::size_t suffixStart =
        mountpointSize == 0 ? 0u : std::min(loweredPath.size(), mountpointSize - 1u);
      const msvc8::string diskPath = mountpoint.mDir + (loweredPath.c_str() + suffixStart);

      FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet != nullptr &&
          waitHandleSet->GetFileInfo(diskPath.c_str(), outInfo, mountpoint.mZipHandle != nullptr)) {
        return true;
      }
    }

    return false;
  }
} // namespace moho
