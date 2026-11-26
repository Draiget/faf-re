#include "moho/misc/FafLuaOverrides.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "gpg/core/algorithms/SHA256.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CVFSImpl.h"

namespace
{
  [[nodiscard]] bool IsHexDigest(
    const std::string_view text
  )
  {
    return text.size() == 64 && std::all_of(text.begin(), text.end(), [](const char c) {
      return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
  }

  [[nodiscard]] std::string ToLowerAscii(
    std::string_view text
  )
  {
    std::string lowered(text);
    for (char& c : lowered) {
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      }
    }
    return lowered;
  }

  /** The next space-separated word of `rest`, which keeps what follows it. */
  [[nodiscard]] std::string_view NextWord(
    std::string_view& rest
  )
  {
    const std::size_t start = rest.find_first_not_of(" \t");
    if (start == std::string_view::npos) {
      rest = {};
      return {};
    }
    rest.remove_prefix(start);
    const std::size_t end = rest.find_first_of(" \t");
    const std::string_view word = rest.substr(0, end);
    rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end);
    return word;
  }
} // namespace

std::vector<moho::SFafLuaManifestEntry> moho::FAFLUA_ParseManifest(
  const std::string_view text,
  std::vector<std::string>* const problems
)
{
  std::vector<SFafLuaManifestEntry> entries;
  std::size_t lineStart = 0;
  for (std::size_t lineNumber = 1; lineStart <= text.size(); ++lineNumber) {
    std::size_t lineEnd = text.find('\n', lineStart);
    if (lineEnd == std::string_view::npos) {
      lineEnd = text.size();
    }
    std::string_view line = text.substr(lineStart, lineEnd - lineStart);
    lineStart = lineEnd + 1;
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }

    std::string_view rest = line;
    const std::string_view digest = NextWord(rest);
    if (digest.empty() || digest.front() == '#') {
      continue;
    }
    const std::string_view mountedPath = NextWord(rest);
    const std::string_view entry = NextWord(rest);
    const std::string loweredDigest = ToLowerAscii(digest);
    if (!IsHexDigest(loweredDigest) || mountedPath.size() < 2 || mountedPath.front() != '/' || entry.empty()) {
      if (problems != nullptr) {
        problems->push_back("manifest.txt line " + std::to_string(lineNumber) + " is not <sha256> /<path> <entry>");
      }
      continue;
    }
    const std::size_t notesStart = rest.find_first_not_of(" \t");
    entries.push_back(
      SFafLuaManifestEntry{
        loweredDigest,
        ToLowerAscii(mountedPath),
        std::string(entry),
        notesStart == std::string_view::npos ? std::string{} : std::string(rest.substr(notesStart)),
      }
    );
  }
  return entries;
}

bool moho::FAFLUA_IsReplaceablePath(
  const std::string_view loweredMountedPath
)
{
  // UI Lua only: nothing the simulation loads, so a player with these files plays the same game as
  // one without. No "..", no backslash, so the path can't climb out of these folders.
  if (
    loweredMountedPath.find("..") != std::string_view::npos || loweredMountedPath.find('\\') != std::string_view::npos
  ) {
    return false;
  }
  if (loweredMountedPath.size() < 5 || loweredMountedPath.substr(loweredMountedPath.size() - 4) != ".lua") {
    return false;
  }
  return loweredMountedPath.starts_with("/lua/ui/") || loweredMountedPath.starts_with("/lua/keymap/");
}

std::string moho::FAFLUA_DigestHex(
  const void* const data,
  const std::size_t size
)
{
  gpg::SHA256 hasher;
  hasher.Update(data, size);
  const gpg::SHA256::Digest digest = hasher.Snapshot();
  static constexpr char kHex[] = "0123456789abcdef";
  std::string text;
  text.reserve(digest.size() * 2);
  for (const std::uint8_t byte : digest) {
    text.push_back(kHex[byte >> 4]);
    text.push_back(kHex[byte & 0x0F]);
  }
  return text;
}

void moho::FAFLUA_Apply(
  CVFSImpl& vfs,
  const std::filesystem::path& executableDirectory
)
{
  const std::filesystem::path archivePath = executableDirectory / kFafLuaArchiveName;
  std::error_code error;
  if (!std::filesystem::is_regular_file(archivePath, error)) {
    return;
  }
  if (CFG_GetArgOption("/nofaflua", 0u, nullptr)) {
    gpg::Logf("FAF Lua: %s not used (/nofaflua)", kFafLuaArchiveName);
    return;
  }

  // The archive is mounted under the path FindFile would give for it, so its entries are looked up
  // like those of any mounted zip (FWaitHandleSet::GetFileInfo, DISK_OpenFileRead).
  fa::string archive{};
  gpg::STR_CanonizeFilename(&archive, gpg::STR_WideToUtf8(archivePath.wstring().c_str()).c_str());
  SFileWaitHandle* const handle = DISK_MountZipFile(archive.c_str());
  if (handle == nullptr) {
    gpg::Warnf("FAF Lua: %s is not a valid zip archive; FAF's own files are used", archive.c_str());
    return;
  }
  const std::string archivePrefix = std::string(archive.view()) + "\\";
  const auto entryDiskPath = [&archivePrefix](const std::string& entry) {
    std::string path = archivePrefix + ToLowerAscii(entry);
    std::replace(path.begin() + static_cast<std::ptrdiff_t>(archivePrefix.size()), path.end(), '/', '\\');
    return path;
  };

  const gpg::MemBuffer<char> manifestFile = DISK_ReadFile(entryDiskPath("manifest.txt").c_str());
  if (manifestFile.mBegin == nullptr) {
    gpg::Warnf("FAF Lua: %s has no manifest.txt; FAF's own files are used", archive.c_str());
    vfs.SetFileReplacements(handle, {});
    return;
  }
  std::vector<std::string> problems;
  const std::vector<SFafLuaManifestEntry> entries = FAFLUA_ParseManifest(
    std::string_view(manifestFile.mBegin, static_cast<std::size_t>(manifestFile.mEnd - manifestFile.mBegin)), &problems
  );
  for (const std::string& problem : problems) {
    gpg::Warnf("FAF Lua: %s", problem.c_str());
  }

  // One FAF file, read and hashed once, can have several entries (one per FAF version).
  std::map<std::string, std::vector<const SFafLuaManifestEntry*>> byPath;
  for (const SFafLuaManifestEntry& entry : entries) {
    if (!FAFLUA_IsReplaceablePath(entry.mMountedPath)) {
      gpg::Warnf(
        "FAF Lua: %s can't be replaced (only UI Lua under /lua/ui/ and /lua/keymap/)", entry.mMountedPath.c_str()
      );
      continue;
    }
    byPath[entry.mMountedPath].push_back(&entry);
  }

  FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
  std::vector<CVFSImpl::SFileReplacement> replacements;
  std::size_t kept = 0;
  for (const auto& [mountedPath, candidates] : byPath) {
    fa::string fafDiskPath{};
    (void)vfs.FindFile(&fafDiskPath, mountedPath.c_str(), nullptr);
    if (fafDiskPath.empty()) {
      gpg::Logf("FAF Lua: %s kept out: the game files have no such file", mountedPath.c_str());
      ++kept;
      continue;
    }
    const gpg::MemBuffer<char> fafFile = DISK_ReadFile(fafDiskPath.c_str());
    const std::string digest = FAFLUA_DigestHex(
      fafFile.mBegin, fafFile.mBegin == nullptr ? 0u : static_cast<std::size_t>(fafFile.mEnd - fafFile.mBegin)
    );
    const auto match = std::find_if(candidates.begin(), candidates.end(), [&digest](const SFafLuaManifestEntry* entry) {
      return entry->mBaseDigest == digest;
    });
    if (match == candidates.end()) {
      gpg::Logf(
        "FAF Lua: %s kept as FAF has it: FAF's file (%s, sha256 %.12s) is not the one the replacement was made for",
        mountedPath.c_str(),
        fafDiskPath.c_str(),
        digest.c_str()
      );
      ++kept;
      continue;
    }
    const std::string diskPath = entryDiskPath((*match)->mEntry);
    if (waitHandleSet == nullptr || !waitHandleSet->GetFileInfo(diskPath.c_str(), nullptr, true)) {
      gpg::Warnf("FAF Lua: %s lists %s, which it doesn't hold", archive.c_str(), (*match)->mEntry.c_str());
      ++kept;
      continue;
    }
    gpg::Logf("FAF Lua: %s replaced from %s (%s)", mountedPath.c_str(), kFafLuaArchiveName, (*match)->mNotes.c_str());
    replacements.push_back(CVFSImpl::SFileReplacement{fa::string(mountedPath.c_str()), fa::string(diskPath.c_str())});
  }
  gpg::Logf("FAF Lua: %zu files replaced, %zu kept as FAF has them", replacements.size(), kept);
  vfs.SetFileReplacements(handle, std::move(replacements));
}
