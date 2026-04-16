#include "moho/sim/CVFSImpl.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <new>
#include <string_view>
#include <utility>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/CZipFile.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  [[nodiscard]] const char* SafePathArg(const gpg::StrArg sourcePath)
  {
    return sourcePath != nullptr ? sourcePath : "";
  }

  [[nodiscard]] bool ContainsWildcardCharacters(const msvc8::string& pathPattern)
  {
    return pathPattern.find('*') != msvc8::string::npos || pathPattern.find('?') != msvc8::string::npos;
  }

  [[nodiscard]] msvc8::string ParentDirectoryFromPattern(const msvc8::string& canonicalPattern)
  {
    const std::string_view patternView = canonicalPattern.view();
    const std::size_t splitIndex = patternView.find_last_of("\\/");
    if (splitIndex == std::string_view::npos) {
      return msvc8::string(".");
    }
    if (splitIndex == 0u) {
      return msvc8::string("\\");
    }
    return canonicalPattern.substr(0u, splitIndex);
  }

  struct SearchPathCandidate
  {
    msvc8::string mResolvedPath{};
    bool mIsDirectory = false;
  };
  static_assert(
    offsetof(SearchPathCandidate, mResolvedPath) == 0x00, "SearchPathCandidate::mResolvedPath offset must be 0x00"
  );
  static_assert(
    offsetof(SearchPathCandidate, mIsDirectory) == 0x1C, "SearchPathCandidate::mIsDirectory offset must be 0x1C"
  );
  static_assert(sizeof(SearchPathCandidate) == 0x20, "SearchPathCandidate size must be 0x20");

  /**
   * Address: 0x004699A0 (FUN_004699A0, sub_4699A0)
   *
   * What it does:
   * Destroys one search-candidate string lane and resets it to empty SSO
   * state.
   */
  [[maybe_unused]] void DestroySearchPathCandidate(SearchPathCandidate& candidate)
  {
    candidate.mResolvedPath.tidy(true, 0U);
  }

  /**
   * Address: 0x004697E0 (FUN_004697E0, sub_4697E0)
   *
   * What it does:
   * Destroys one contiguous search-candidate range by resetting each string
   * payload lane.
   */
  [[maybe_unused]] void DestroySearchPathCandidateRange(SearchPathCandidate* begin, SearchPathCandidate* end)
  {
    for (SearchPathCandidate* current = begin; current != end; ++current) {
      DestroySearchPathCandidate(*current);
    }
  }

  [[nodiscard]] std::vector<SearchPathCandidate> CollectSearchPathCandidates(const msvc8::string& canonicalPattern)
  {
    std::vector<SearchPathCandidate> candidates{};
    if (canonicalPattern.empty()) {
      return candidates;
    }

    if (!ContainsWildcardCharacters(canonicalPattern)) {
      const DWORD attributes = ::GetFileAttributesA(canonicalPattern.c_str());
      if (attributes == INVALID_FILE_ATTRIBUTES) {
        return candidates;
      }

      SearchPathCandidate candidate{};
      candidate.mResolvedPath.assign_owned(canonicalPattern.view());
      candidate.mIsDirectory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      candidates.push_back(std::move(candidate));
      return candidates;
    }

    WIN32_FIND_DATAA findData{};
    HANDLE findHandle = ::FindFirstFileA(canonicalPattern.c_str(), &findData);
    if (findHandle == INVALID_HANDLE_VALUE) {
      return candidates;
    }

    const msvc8::string parentDirectory = ParentDirectoryFromPattern(canonicalPattern);
    do {
      if (std::strcmp(findData.cFileName, ".") == 0 || std::strcmp(findData.cFileName, "..") == 0) {
        continue;
      }

      msvc8::string candidatePath = parentDirectory;
      if (!candidatePath.empty()) {
        const char tail = candidatePath[candidatePath.size() - 1];
        if (tail != '\\' && tail != '/') {
          (void)candidatePath.push_back('\\');
        }
      }
      (void)candidatePath.append(findData.cFileName, std::strlen(findData.cFileName));

      msvc8::string canonicalCandidate{};
      gpg::STR_CanonizeFilename(&canonicalCandidate, candidatePath.c_str());
      if (canonicalCandidate.empty()) {
        continue;
      }

      SearchPathCandidate candidate{};
      candidate.mResolvedPath.assign_owned(canonicalCandidate.view());
      candidate.mIsDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      candidates.push_back(std::move(candidate));
    } while (::FindNextFileA(findHandle, &findData) != FALSE);

    (void)::FindClose(findHandle);
    return candidates;
  }

  [[nodiscard]] msvc8::string CanonicalizeJoinedMountPath(
    const std::filesystem::path& launchDir, const msvc8::string& sourcePath
  )
  {
    if (sourcePath.empty()) {
      return {};
    }

    std::filesystem::path resolvedPath(sourcePath.c_str());
    if (!resolvedPath.is_absolute() && !launchDir.empty()) {
      resolvedPath = launchDir / resolvedPath;
    }

    msvc8::string canonicalPath{};
    const std::string resolvedUtf8 = resolvedPath.string();
    gpg::STR_CanonizeFilename(&canonicalPath, resolvedUtf8.c_str());
    return canonicalPath;
  }

  void SortAndUniquePaths(msvc8::vector<msvc8::string>& paths)
  {
    std::sort(paths.begin(), paths.end(), [](const msvc8::string& lhs, const msvc8::string& rhs) {
      return lhs.view() < rhs.view();
    });

    const auto uniqueEnd = std::unique(paths.begin(), paths.end(), [](const msvc8::string& lhs, const msvc8::string& rhs) {
      return lhs.view() == rhs.view();
    });
    paths.erase(uniqueEnd, paths.end());
  }

  /**
    * Alias of FUN_0046AE90 (non-canonical helper lane).
    * Alias of FUN_0046B4B0 (non-canonical helper lane).
    * Alias of FUN_0046BA60 (non-canonical helper lane).
   *
   * What it does:
   * Compares search-path candidate string lanes using reverse path-component
   * order (leaf-first), then applies directory-flag tiebreak ordering.
   */
  [[nodiscard]] bool SearchPathCandidateLess(const SearchPathCandidate& lhs, const SearchPathCandidate& rhs)
  {
    if (moho::PATH_ReverseComponentLess(lhs.mResolvedPath, rhs.mResolvedPath)) {
      return true;
    }
    if (moho::PATH_ReverseComponentLess(rhs.mResolvedPath, lhs.mResolvedPath)) {
      return false;
    }
    return static_cast<unsigned int>(lhs.mIsDirectory) < static_cast<unsigned int>(rhs.mIsDirectory);
  }

  /**
   * Address: 0x00467380 (FUN_00467380, sub_467380)
   *
   * What it does:
   * Enumerates zip-entry file matches under one relative prefix and appends
   * mounted paths that satisfy wildcard constraints.
   */
  void EnumerateZipFiles(
    moho::CZipFile* const zipFile,
    const char* const relativePrefix,
    const msvc8::string& mountedRoot,
    const char* const wildcardPattern,
    const bool recursive,
    msvc8::vector<msvc8::string>& outPaths
  )
  {
    if (zipFile == nullptr || relativePrefix == nullptr || wildcardPattern == nullptr) {
      return;
    }

    const std::size_t prefixLength = std::strlen(relativePrefix);
    const std::size_t entryCount = zipFile->mEntries.size();
    for (std::size_t entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
      msvc8::string entryPath = gpg::STR_ToLower(zipFile->GetEntryName(static_cast<std::uint32_t>(entryIndex)).c_str());
      gpg::STR_Replace(entryPath, "\\", "/", -1);

      if (!gpg::STR_StartsWith(entryPath.c_str(), relativePrefix)) {
        continue;
      }

      const char* const relativeTail = entryPath.c_str() + prefixLength;
      const char* const leafSlash = std::strrchr(relativeTail, '/');
      if (leafSlash != nullptr) {
        if (!recursive || !gpg::STR_MatchWildcard(leafSlash + 1, wildcardPattern)) {
          continue;
        }
      } else if (!gpg::STR_MatchWildcard(relativeTail, wildcardPattern)) {
        continue;
      }

      msvc8::string mountedPath = mountedRoot;
      (void)mountedPath.append(entryPath.c_str(), entryPath.size());
      outPaths.push_back(std::move(mountedPath));
    }
  }

  /**
   * Address: 0x00467BA0 (FUN_00467BA0, sub_467BA0)
   *
   * What it does:
   * Enumerates immediate child directories from zip entries under one relative
   * prefix and appends mounted child paths.
   */
  void EnumerateZipChildren(
    moho::CZipFile* const zipFile,
    const char* const relativePrefix,
    const msvc8::string& mountedRoot,
    msvc8::vector<msvc8::string>& outPaths
  )
  {
    if (zipFile == nullptr || relativePrefix == nullptr) {
      return;
    }

    const std::size_t prefixLength = std::strlen(relativePrefix);
    const std::size_t entryCount = zipFile->mEntries.size();
    for (std::size_t entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
      msvc8::string entryPath = gpg::STR_ToLower(zipFile->GetEntryName(static_cast<std::uint32_t>(entryIndex)).c_str());
      gpg::STR_Replace(entryPath, "\\", "/", -1);

      if (!gpg::STR_StartsWith(entryPath.c_str(), relativePrefix)) {
        continue;
      }

      const char* const firstSlash = std::strchr(entryPath.c_str() + prefixLength, '/');
      if (firstSlash == nullptr) {
        continue;
      }

      const std::size_t childLength =
        static_cast<std::size_t>(firstSlash - entryPath.c_str());
      msvc8::string childPath = entryPath.substr(0u, childLength);

      msvc8::string mountedPath = mountedRoot;
      (void)mountedPath.append(childPath.c_str(), childPath.size());
      if (outPaths.empty() || outPaths.back().view() != mountedPath.view()) {
        outPaths.push_back(std::move(mountedPath));
      }
    }
  }

  /**
   * Address: 0x004675D0 (FUN_004675D0, sub_4675D0)
   *
   * What it does:
   * Enumerates disk-backed mounted files recursively (when enabled) and appends
   * wildcard-matching mounted paths.
   */
  void EnumerateDirectoryFiles(
    const msvc8::string& diskDirectory,
    const msvc8::string& mountedDirectory,
    const char* const wildcardPattern,
    const bool recursive,
    msvc8::vector<msvc8::string>& outPaths
  )
  {
    if (wildcardPattern == nullptr) {
      return;
    }

    msvc8::string searchPattern = diskDirectory;
    (void)searchPattern.append("\\*.*", 4u);

    WIN32_FIND_DATAA findData{};
    HANDLE findHandle = ::FindFirstFileA(searchPattern.c_str(), &findData);
    if (findHandle == INVALID_HANDLE_VALUE) {
      return;
    }

    do {
      msvc8::string loweredName = gpg::STR_ToLower(findData.cFileName);
      const bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u;
      if (isDirectory) {
        if (!recursive || std::strcmp(findData.cFileName, ".") == 0 || std::strcmp(findData.cFileName, "..") == 0) {
          continue;
        }

        msvc8::string childMountedDirectory = mountedDirectory;
        (void)childMountedDirectory.append(loweredName.c_str(), loweredName.size());
        (void)childMountedDirectory.push_back('/');

        msvc8::string childDiskDirectory = diskDirectory;
        (void)childDiskDirectory.push_back('\\');
        (void)childDiskDirectory.append(findData.cFileName, std::strlen(findData.cFileName));
        EnumerateDirectoryFiles(childDiskDirectory, childMountedDirectory, wildcardPattern, true, outPaths);
        continue;
      }

      if (!gpg::STR_MatchWildcard(loweredName.c_str(), wildcardPattern)) {
        continue;
      }

      msvc8::string mountedPath = mountedDirectory;
      (void)mountedPath.append(loweredName.c_str(), loweredName.size());
      outPaths.push_back(std::move(mountedPath));
    } while (::FindNextFileA(findHandle, &findData) != FALSE);

    (void)::FindClose(findHandle);
  }

  /**
   * Address: 0x00467E00 (FUN_00467E00, sub_467E00)
   *
   * What it does:
   * Enumerates immediate child directories from one disk-backed mount root and
   * appends normalized mounted paths.
   */
  void EnumerateDirectoryChildren(
    const msvc8::string& diskDirectory,
    const msvc8::string& mountedDirectory,
    msvc8::vector<msvc8::string>& outPaths
  )
  {
    msvc8::string searchPattern = diskDirectory;
    (void)searchPattern.append("\\*.*", 4u);

    WIN32_FIND_DATAA findData{};
    HANDLE findHandle = ::FindFirstFileA(searchPattern.c_str(), &findData);
    if (findHandle == INVALID_HANDLE_VALUE) {
      return;
    }

    do {
      const bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u;
      if (!isDirectory || std::strcmp(findData.cFileName, ".") == 0 || std::strcmp(findData.cFileName, "..") == 0) {
        continue;
      }

      msvc8::string loweredName = gpg::STR_ToLower(findData.cFileName);
      msvc8::string mountedPath = mountedDirectory;
      (void)mountedPath.append(loweredName.c_str(), loweredName.size());
      outPaths.push_back(std::move(mountedPath));
    } while (::FindNextFileA(findHandle, &findData) != FALSE);

    (void)::FindClose(findHandle);
  }

  void RetainMountedZipHandle(moho::SFileWaitHandle* const handle)
  {
    if (handle != nullptr) {
      (void)::InterlockedExchangeAdd(&handle->mLock, 1);
    }
  }

  void ReleaseMountedZipHandle(moho::SFileWaitHandle* const handle)
  {
    if (handle == nullptr) {
      return;
    }

    if (::InterlockedExchangeAdd(&handle->mLock, -1) == 1) {
      moho::FILE_EnsureWaitHandleSet();
      if (moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet(); waitHandleSet != nullptr) {
        waitHandleSet->RemoveEntry(handle);
      }
    }
  }

  /**
   * Address: 0x00469930 (FUN_00469930, sub_469930)
   *
   * What it does:
   * Copy-constructs one mount-point element into provided storage when
   * destination storage is non-null.
   */
  [[maybe_unused]] moho::SVFSMountPoint* ConstructMountPointCopyIfPresent(
    const moho::SVFSMountPoint& source, moho::SVFSMountPoint* destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }
    return new (destination) moho::SVFSMountPoint(source);
  }

  /**
   * Address: 0x0046A3F0 (FUN_0046A3F0, sub_46A3F0)
   *
   * What it does:
   * Copies one mount-point range backward, preserving intrusive zip-handle
   * retain/release ownership via typed assignment.
   */
  [[maybe_unused]] moho::SVFSMountPoint* CopyMountPointRangeBackward(
    moho::SVFSMountPoint* destinationEnd,
    const moho::SVFSMountPoint* sourceEnd,
    const moho::SVFSMountPoint* sourceBegin
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0046A4B0 (FUN_0046A4B0, sub_46A4B0)
   *
   * What it does:
   * Copies one search-candidate range backward for string + directory-flag
   * elements.
   */
  [[maybe_unused]] SearchPathCandidate* CopySearchPathCandidateRangeBackward(
    SearchPathCandidate* destinationEnd,
    const SearchPathCandidate* sourceEnd,
    const SearchPathCandidate* sourceBegin
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      destinationEnd->mResolvedPath.reset_and_assign(sourceEnd->mResolvedPath);
      destinationEnd->mIsDirectory = sourceEnd->mIsDirectory;
    }
    return destinationEnd;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004661F0 (FUN_004661F0, sub_4661F0)
   */
  SVFSMountPoint::SVFSMountPoint()
    : mDir()
    , mMountpoint("/", 1u)
    , mZipHandle(nullptr)
  {
  }

  /**
   * Address: 0x004577D0 (FUN_004577D0, Moho::SVFSMountPoint::SVFSMountPoint)
   *
   * char *,char *
   *
   * What it does:
   * Initializes one mount-point lane from explicit directory/mountpoint text
   * tokens and clears mounted-zip ownership.
   */
  SVFSMountPoint::SVFSMountPoint(const gpg::StrArg dir, const gpg::StrArg mountpoint)
    : mDir(dir != nullptr ? dir : "", dir != nullptr ? std::strlen(dir) : 0u)
    , mMountpoint(mountpoint != nullptr ? mountpoint : "", mountpoint != nullptr ? std::strlen(mountpoint) : 0u)
    , mZipHandle(nullptr)
  {
  }

  SVFSMountPoint::SVFSMountPoint(const SVFSMountPoint& other)
    : mDir()
    , mMountpoint()
    , mZipHandle(other.mZipHandle)
  {
    mDir.reset_and_assign(other.mDir);
    mMountpoint.reset_and_assign(other.mMountpoint);
    RetainMountedZipHandle(mZipHandle);
  }

  SVFSMountPoint::SVFSMountPoint(SVFSMountPoint&& other) noexcept
    : mDir(std::move(other.mDir))
    , mMountpoint(std::move(other.mMountpoint))
    , mZipHandle(other.mZipHandle)
  {
    other.mZipHandle = nullptr;
  }

  /**
   * Address: 0x004698D0 (FUN_004698D0, sub_4698D0)
   *
   * What it does:
   * Copies mountpoint directory/root strings and transfers zip-handle
   * ownership with retain/release semantics.
   */
  SVFSMountPoint& SVFSMountPoint::operator=(const SVFSMountPoint& other)
  {
    SFileWaitHandle* const nextHandle = other.mZipHandle;
    RetainMountedZipHandle(nextHandle);
    ReleaseMountedZipHandle(mZipHandle);

    mDir.reset_and_assign(other.mDir);
    mMountpoint.reset_and_assign(other.mMountpoint);
    mZipHandle = nextHandle;
    return *this;
  }

  SVFSMountPoint& SVFSMountPoint::operator=(SVFSMountPoint&& other) noexcept
  {
    if (this == &other) {
      return *this;
    }

    ReleaseMountedZipHandle(mZipHandle);
    mDir = std::move(other.mDir);
    mMountpoint = std::move(other.mMountpoint);
    mZipHandle = other.mZipHandle;
    other.mZipHandle = nullptr;
    return *this;
  }

  /**
   * Address: 0x00466970 (FUN_00466970, sub_466970)
   */
  SVFSMountPoint::~SVFSMountPoint()
  {
    ReleaseMountedZipHandle(mZipHandle);
    mZipHandle = nullptr;
  }

  /**
   * Address: 0x00466250 (FUN_00466250, ??0CVFSImpl@Moho@@QAE@@Z)
   *
   * std::vector<Moho::SVFSMountPoint> const &,boost::filesystem::basic_path<std::string,boost::filesystem::path_traits> const &
   *
   * What it does:
   * Initializes mountpoint storage and expands the configured mount lanes.
   */
  CVFSImpl::CVFSImpl(const msvc8::vector<SVFSMountPoint>& mountpoints, const std::filesystem::path& launchDir)
    : mMountpoints()
  {
    for (const SVFSMountPoint& mountpoint : mountpoints) {
      AddMountPoint(mountpoint, launchDir);
    }
  }

  /**
   * Address: 0x004662F0 (FUN_004662F0, Moho::CVFSImpl::dtr)
   * Address: 0x00466320 (FUN_00466320, Moho::CVFSImpl::~CVFSImpl)
   */
  CVFSImpl::~CVFSImpl()
  {
    mMountpoints.clear();
  }

  /**
   * Address: 0x00466370 (FUN_00466370, Moho::CVFSImpl::AddMountPoint)
   *
   * What it does:
   * Resolves one configured mount source path (including wildcard expansion)
   * and forwards concrete candidates to `AddSearchPath`.
   */
  void CVFSImpl::AddMountPoint(const SVFSMountPoint& mountPoint, const std::filesystem::path& launchDir)
  {
    const msvc8::string canonicalPattern = CanonicalizeJoinedMountPath(launchDir, mountPoint.mDir);
    if (canonicalPattern.empty()) {
      return;
    }

    std::vector<SearchPathCandidate> searchCandidates = CollectSearchPathCandidates(canonicalPattern);
    std::sort(searchCandidates.begin(), searchCandidates.end(), SearchPathCandidateLess);
    for (const SearchPathCandidate& candidate : searchCandidates) {
      AddSearchPath(mountPoint, candidate.mResolvedPath, candidate.mIsDirectory);
    }
  }

  /**
   * Address: 0x004666A0 (FUN_004666A0, Moho::CVFSImpl::AddSearchPath)
   *
   * What it does:
   * Converts one resolved path into a mounted VFS entry; directories are
   * mounted directly and files are mounted through `DISK_MountZipFile`.
   */
  void CVFSImpl::AddSearchPath(
    const SVFSMountPoint& mountPoint, const msvc8::string& resolvedPath, const bool isDirectory
  )
  {
    msvc8::string canonicalPath{};
    gpg::STR_CanonizeFilename(&canonicalPath, resolvedPath.c_str());
    if (canonicalPath.empty()) {
      return;
    }

    SVFSMountPoint mountedPath{};
    mountedPath.mDir = gpg::STR_ToLower(canonicalPath.c_str());
    mountedPath.mMountpoint = gpg::STR_ToLower(mountPoint.mMountpoint.c_str());
    if (mountedPath.mMountpoint.empty() || mountedPath.mMountpoint[mountedPath.mMountpoint.size() - 1] != '/') {
      (void)mountedPath.mMountpoint.push_back('/');
    }

    gpg::Logf("DISK: AddSearchPath: '%s', mounted as '%s'", mountedPath.mDir.c_str(), mountedPath.mMountpoint.c_str());

    if (isDirectory) {
      if (CFG_GetArgOption("/EnableDiskWatch", 0u, nullptr)) {
        (void)DISK_AddWatchDirectory(mountedPath.mDir.c_str());
      }
      mMountpoints.push_back(std::move(mountedPath));
      return;
    }

    mountedPath.mZipHandle = DISK_MountZipFile(mountedPath.mDir.c_str());
    if (mountedPath.mZipHandle == nullptr) {
      gpg::Warnf("Search path element \"%s\" is not a valid .zip file.", mountedPath.mDir.c_str());
      return;
    }

    mMountpoints.push_back(std::move(mountedPath));
  }

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

  /**
   * Address: 0x00467020 (FUN_00467020, Moho::CVFSImpl::Func3)
   *
   * gpg::StrArg,gpg::StrArg,bool,std::vector<std::string> *
   *
   * What it does:
   * Enumerates mounted file paths under one prefix from both zip and directory
   * sources, applies wildcard filtering, then sorts and de-duplicates output.
   */
  void CVFSImpl::EnumerateFiles(
    const gpg::StrArg mountPrefix,
    const gpg::StrArg queryPath,
    const bool allowPrefixWildcard,
    msvc8::vector<msvc8::string>* const outPaths
  )
  {
    if (outPaths == nullptr) {
      return;
    }

    msvc8::string normalizedPrefix = gpg::STR_ToLower(SafePathArg(mountPrefix));
    if (normalizedPrefix.empty() || normalizedPrefix[normalizedPrefix.size() - 1u] != '/') {
      (void)normalizedPrefix.push_back('/');
    }
    const msvc8::string wildcardPattern = gpg::STR_ToLower(SafePathArg(queryPath));

    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      const bool prefixContainsMount =
        gpg::STR_StartsWith(normalizedPrefix.c_str(), mountpoint.mMountpoint.c_str());
      const bool mountContainsPrefix =
        allowPrefixWildcard && gpg::STR_StartsWith(mountpoint.mMountpoint.c_str(), normalizedPrefix.c_str());
      if (!prefixContainsMount && !mountContainsPrefix) {
        continue;
      }

      const std::size_t sharedPrefixLen = std::min(normalizedPrefix.size(), mountpoint.mMountpoint.size());
      const char* const relativePrefix = normalizedPrefix.c_str() + sharedPrefixLen;

      if (mountpoint.mZipHandle != nullptr) {
        EnumerateZipFiles(
          mountpoint.mZipHandle->mZipFile,
          relativePrefix,
          mountpoint.mMountpoint,
          wildcardPattern.c_str(),
          allowPrefixWildcard,
          *outPaths
        );
        continue;
      }

      msvc8::string mountedDirectory = mountpoint.mMountpoint;
      (void)mountedDirectory.append(relativePrefix, std::strlen(relativePrefix));

      msvc8::string diskDirectory = mountpoint.mDir;
      if (sharedPrefixLen > 0u) {
        const char* const diskSuffix = normalizedPrefix.c_str() + (sharedPrefixLen - 1u);
        (void)diskDirectory.append(diskSuffix, std::strlen(diskSuffix));
      }
      EnumerateDirectoryFiles(
        diskDirectory,
        mountedDirectory,
        wildcardPattern.c_str(),
        allowPrefixWildcard,
        *outPaths
      );
    }

    SortAndUniquePaths(*outPaths);
  }

  /**
   * Address: 0x00467900 (FUN_00467900, Moho::CVFSImpl::Func4)
   *
   * gpg::StrArg,std::vector<std::string> *
   *
   * What it does:
   * Enumerates child directory paths under one mounted prefix from zip and
   * directory search roots, then sorts and de-duplicates output.
   */
  void CVFSImpl::EnumerateChildren(const gpg::StrArg mountPrefix, msvc8::vector<msvc8::string>* const outPaths)
  {
    if (outPaths == nullptr) {
      return;
    }

    msvc8::string normalizedPrefix = gpg::STR_ToLower(SafePathArg(mountPrefix));
    if (normalizedPrefix.empty() || normalizedPrefix[normalizedPrefix.size() - 1u] != '/') {
      (void)normalizedPrefix.push_back('/');
    }

    for (const SVFSMountPoint& mountpoint : mMountpoints) {
      if (!gpg::STR_StartsWith(normalizedPrefix.c_str(), mountpoint.mMountpoint.c_str())) {
        continue;
      }

      const std::size_t mountPrefixLen = mountpoint.mMountpoint.size();
      const char* const relativePrefix = normalizedPrefix.c_str() + mountPrefixLen;
      if (mountpoint.mZipHandle != nullptr) {
        EnumerateZipChildren(mountpoint.mZipHandle->mZipFile, relativePrefix, mountpoint.mMountpoint, *outPaths);
        continue;
      }

      msvc8::string mountedDirectory = mountpoint.mMountpoint;
      (void)mountedDirectory.append(relativePrefix, std::strlen(relativePrefix));

      msvc8::string diskDirectory = mountpoint.mDir;
      if (mountPrefixLen > 0u) {
        const char* const diskSuffix = normalizedPrefix.c_str() + (mountPrefixLen - 1u);
        (void)diskDirectory.append(diskSuffix, std::strlen(diskSuffix));
      }
      EnumerateDirectoryChildren(diskDirectory, mountedDirectory, *outPaths);
    }

    SortAndUniquePaths(*outPaths);
  }

  /**
   * Address: 0x00467F90 (FUN_00467F90, ?VFS_Create@Moho@@...)
   *
   * What it does:
   * Creates one `CVFSImpl` and returns it through the base VFS interface.
   */
  CVirtualFileSystem* VFS_Create(
    const msvc8::vector<SVFSMountPoint>& mountpoints,
    const std::filesystem::path& launchDir
  )
  {
    return new CVFSImpl(mountpoints, launchDir);
  }
} // namespace moho
