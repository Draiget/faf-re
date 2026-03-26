#include "moho/misc/CSaveGameRequestImpl.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <cstdio>

#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/serialization/SaveGameFileHeader.h"
#include "moho/serialization/SSavedGameHeader.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"

namespace
{
  using SaveGameFileHeader = moho::SSaveGameFileHeader;

  constexpr std::size_t kUtf16HeaderTextCopyLimit = 2047;

  [[nodiscard]] msvc8::string MakeTempSavePath(const msvc8::string& basePath)
  {
    return basePath + ".NEW";
  }

  template <std::size_t N>
  void CopyWideStringTruncated(wchar_t (&outBuffer)[N], const std::wstring& source)
  {
    const std::size_t maxCopy = (std::min)(N - 1, kUtf16HeaderTextCopyLimit);
    const std::size_t charCount = (std::min)(source.size(), maxCopy);
    std::fill(std::begin(outBuffer), std::end(outBuffer), L'\0');
    if (charCount != 0) {
      std::copy_n(source.data(), charCount, outBuffer);
    }
  }

  [[nodiscard]] std::wstring Utf8ToWide(const msvc8::string& source)
  {
    return gpg::STR_Utf8ToWide(source.c_str());
  }

  [[nodiscard]] bool WriteExact(std::FILE* const file, const void* const data, const std::size_t byteCount)
  {
    if (!file) {
      return false;
    }
    if (byteCount == 0) {
      return true;
    }
    return std::fwrite(data, byteCount, 1, file) == 1;
  }

  [[nodiscard]] bool RewriteSaveHeader(std::FILE* const file, const SaveGameFileHeader& header)
  {
    if (!file) {
      return false;
    }
    if (std::fseek(file, 0, SEEK_SET) != 0) {
      return false;
    }
    return WriteExact(file, &header, sizeof(header));
  }

  [[nodiscard]] gpg::MemBuffer<const char> TryLoadPreviewBytes()
  {
    gpg::MemBuffer<const char> preview = gpg::LoadFileToMemBuffer("/coderes/engine/boxart_neutral.png");
    if (preview.begin() != nullptr) {
      return preview;
    }
    return gpg::LoadFileToMemBuffer("coderes/engine/boxart_neutral.png");
  }

  void FillFileHeaderTextFields(
    SaveGameFileHeader& outHeader, const msvc8::string& appNameUtf8, const msvc8::string& sessionNameUtf8
  )
  {
    CopyWideStringTruncated(outHeader.mAppNameUtf16, Utf8ToWide(appNameUtf8));
    CopyWideStringTruncated(outHeader.mSessionNameUtf16, Utf8ToWide(sessionNameUtf8));
  }

  void FillFileHeaderGameIdFields(SaveGameFileHeader& outHeader)
  {
    outHeader.mGameIdPart1 = moho::APP_GetGameIdPart(0);
    outHeader.mGameIdPart2 = moho::APP_GetGameIdPart(1);
    outHeader.mGameIdPart3 = moho::APP_GetGameIdPart(2);
    outHeader.mGameIdPart4 = moho::APP_GetGameIdPart(3);
  }

  [[nodiscard]] moho::SSavedGameHeader BuildSavedGameHeader(const moho::CWldSession* const session)
  {
    moho::SSavedGameHeader header{};
    if (!session) {
      return header;
    }

    header.mMapName = session->mMapName;
    header.mFocusArmy = session->FocusArmy;
    header.mArmyInfo.clear();
    header.mArmyInfo.reserve(session->userArmies.size());

    for (const moho::UserArmy* const userArmy : session->userArmies) {
      moho::SSavedGameArmyInfo armyInfo{};
      if (userArmy) {
        armyInfo.mPlayerName = userArmy->mPlayerName;
      }
      header.mArmyInfo.push_back(armyInfo);
    }

    const char* const scenarioInfoText = session->mScenarioInfo.GetString();
    if (scenarioInfoText != nullptr) {
      header.mScenarioInfoText.assign_owned(scenarioInfoText);
    }

    header.mLaunchInfo = boost::SharedPtrRawFromSharedRetained(session->mLaunchInfo);
    return header;
  }

  [[nodiscard]] bool MoveTempFileIntoSavePath(const msvc8::string& tempPath, const msvc8::string& targetPath)
  {
    const std::wstring wideTargetPath = gpg::STR_Utf8ToWide(targetPath.c_str());
    const std::wstring wideTempPath = gpg::STR_Utf8ToWide(tempPath.c_str());
    return ::MoveFileExW(wideTempPath.c_str(), wideTargetPath.c_str(), MOVEFILE_REPLACE_EXISTING) != FALSE;
  }

  [[nodiscard]] bool DeleteTempFile(const msvc8::string& tempPath)
  {
    const std::wstring wideTempPath = gpg::STR_Utf8ToWide(tempPath.c_str());
    return ::DeleteFileW(wideTempPath.c_str()) != FALSE;
  }
} // namespace

namespace moho
{
  void SFileStarCloser::operator()(std::FILE* const file) const noexcept
  {
    if (file) {
      std::fclose(file);
    }
  }

  /**
   * Address: 0x00880F00 (FUN_00880F00)
   *
   * gpg::StrArg,gpg::StrArg,LuaPlus::LuaObject const &
   *
   * What it does:
   * Initializes one save request object, opens `<savePath>.NEW`, writes the
   * placeholder file header block, and serializes `SSavedGameHeader`.
   */
  CSaveGameRequestImpl::CSaveGameRequestImpl(
    const gpg::StrArg savePath, const gpg::StrArg sessionName, const LuaPlus::LuaObject& completionCallback
  )
    : mSavePath(savePath != nullptr ? savePath : "")
    , mSessionName(sessionName != nullptr ? sessionName : "")
    , mCompletionCallback(completionCallback)
    , mFile()
    , mArchive(nullptr)
  {
    const msvc8::string tempPath = MakeTempSavePath(mSavePath);
    const std::wstring wideTempPath = gpg::STR_Utf8ToWide(tempPath.c_str());
    std::FILE* file = nullptr;
    if (_wfopen_s(&file, wideTempPath.c_str(), L"wb") != 0) {
      file = nullptr;
    }
    mFile.reset(file, moho::SFileStarCloser{});

    if (!file) {
      const msvc8::string message = gpg::STR_Printf("Error opening %s for write", tempPath.c_str());
      throw gpg::SerializationError(message.c_str());
    }

    std::array<std::uint8_t, moho::kSaveGameFileHeaderSize> blankHeader{};
    if (!WriteExact(file, blankHeader.data(), blankHeader.size())) {
      throw gpg::SerializationError("Error writing savegame header.");
    }

    std::unique_ptr<gpg::WriteArchive> archive(gpg::CreateBinaryWriteArchive(mFile));
    const SSavedGameHeader header = BuildSavedGameHeader(WLD_GetActiveSession());
    const gpg::RRef ownerRef{nullptr, nullptr};
    archive->Write(SSavedGameHeader::StaticGetClass(), &header, ownerRef);
    archive->EndSection(false);
    mArchive = archive.release();
  }

  /**
   * Address: 0x008819E0 (FUN_008819E0)
   *
   * What it does:
   * Releases active write archive, shared file handle, and callback/string fields.
   */
  CSaveGameRequestImpl::~CSaveGameRequestImpl()
  {
    delete mArchive;
    mArchive = nullptr;
    mFile.reset();
  }

  /**
   * Address: 0x00880EF0 (FUN_00880EF0)
   *
   * What it does:
   * Returns the write archive that receives serialized sim data.
   */
  gpg::WriteArchive* CSaveGameRequestImpl::GetArchive()
  {
    return mArchive;
  }

  /**
   * Address: 0x008813A0 (FUN_008813A0)
   *
   * What it does:
   * Finalizes save output, writes fixed file header payload, and dispatches
   * completion callback state.
   */
  void CSaveGameRequestImpl::Save(const SSaveGameDispatchData& data)
  {
    delete mArchive;
    mArchive = nullptr;

    bool completedSuccessfully = data.useSuggestedName;
    msvc8::string completionText = data.saveName;
    const msvc8::string tempPath = MakeTempSavePath(mSavePath);

    if (completedSuccessfully) {
      SaveGameFileHeader fileHeader{};
      FillFileHeaderGameIdFields(fileHeader);
      FillFileHeaderTextFields(fileHeader, APP_GetProductName(), mSessionName);

      std::FILE* const file = mFile.get();
      const gpg::MemBuffer<const char> previewBytes = TryLoadPreviewBytes();
      if (file != nullptr && previewBytes.begin() != nullptr) {
        const long previewStreamOffset = std::ftell(file);
        if (previewStreamOffset >= 0 && previewBytes.Size() <= std::numeric_limits<std::uint32_t>::max()) {
          const std::int64_t relativeOffset =
            static_cast<std::int64_t>(previewStreamOffset) - moho::kSaveGameFileHeaderSize;
          fileHeader.mPreviewOffsetLow = static_cast<std::int32_t>(relativeOffset & 0xFFFFFFFFLL);
          fileHeader.mPreviewOffsetHigh = static_cast<std::int32_t>((relativeOffset >> 32) & 0xFFFFFFFFLL);
          fileHeader.mPreviewByteSize = static_cast<std::uint32_t>(previewBytes.Size());
          if (!WriteExact(file, previewBytes.begin(), previewBytes.Size())) {
            completedSuccessfully = false;
          }
        }
      }

      if (!RewriteSaveHeader(file, fileHeader)) {
        completedSuccessfully = false;
        completionText = gpg::STR_Printf("IO error writing header");
      }

      mFile.reset();
      if (completedSuccessfully && !MoveTempFileIntoSavePath(tempPath, mSavePath)) {
        completedSuccessfully = false;
        gpg::Logf(
          "SAVE: MoveFileEx(\"%s\", \"%s\", MOVEFILE_REPLACE_EXISTING) failed.", tempPath.c_str(), mSavePath.c_str()
        );
      }
    }

    if (!completedSuccessfully) {
      mFile.reset();
      if (!DeleteTempFile(tempPath)) {
        gpg::Logf("SAVE: DeleteFile(\"%s\") failed.", tempPath.c_str());
      }
    }

    try {
      LuaPlus::LuaFunction<void> onCompletion(mCompletionCallback);
      onCompletion(completedSuccessfully, completionText);
    } catch (const std::exception& ex) {
      gpg::Warnf("SaveRequest's OnCompletion() method failed: %s", ex.what());
    } catch (...) {
      gpg::Warnf("SaveRequest's OnCompletion() method failed: %s", "unknown exception");
    }

    delete this;
  }
} // namespace moho
