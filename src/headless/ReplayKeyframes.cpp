#include "headless/ReplayKeyframes.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <vector>

#include <zlib.h>

#include "boost/shared_ptr.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/ISaveRequest.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimKeyframe.h"

namespace faf::headless
{
  namespace
  {
    using Clock = std::chrono::steady_clock;

    /** Engine addition: see `gpg::CreateFastBinaryWriteArchive`. The file's format is the same. */
    bool save_FastKeyframeArchive = true;
    moho::TConVar<bool> gTConVar_save_FastKeyframeArchive(
      "save_FastKeyframeArchive",
      "A replay keyframe's save looks up pointers in a hash index and writes through a memory buffer (1, the default), "
      "or as a saved game does (0). Same file format.",
      &save_FastKeyframeArchive
    );

    /**
     * One keyframe. The sim's thread calls `GetArchive` between beats and saves the sim into
     * it (`CSimDriver::PreparePendingSaveRequestLocked`); `CSimDriver::Dispatch` then calls
     * `Save` on the main thread, which hands the result back and deletes the request, as
     * `CSaveGameRequestImpl::Save` does.
     */
    class CKeyframeRequest final : public moho::ISaveRequest
    {
    public:
      CKeyframeRequest(CReplayKeyframes& owner, std::string path, const moho::Sim* const sim)
        : mOwner(owner)
        , mPath(std::move(path))
        , mSim(sim)
      {}

      gpg::WriteArchive* GetArchive() override
      {
        mStart = Clock::now();
        mBeat = mSim != nullptr ? mSim->mCurBeat : 0u;
        // A retail-format save changes the sim (see gSimExactArchive); a keyframe must not.
        moho::gSimExactSaveCount.fetch_add(1u);
        moho::gSimExactArchive.store(true);
        std::FILE* file = nullptr;
        if (fopen_s(&file, mPath.c_str(), "wb") != 0 || file == nullptr) {
          // `Sim::SaveState` writes through the archive it is given; the driver catches the throw.
          throw std::runtime_error("cannot write " + mPath);
        }
        mFile = boost::shared_ptr<std::FILE>(file, moho::SFileStarCloser{});
        if (mSim != nullptr) {
          moho::SSimKeyframeHeader header{};
          moho::SIM_CaptureKeyframeHeader(*mSim, header);
          if (!moho::SIM_WriteKeyframeHeader(file, header)) {
            throw std::runtime_error("cannot write " + mPath);
          }
        }
        mArchive = save_FastKeyframeArchive ? gpg::CreateFastBinaryWriteArchive(mFile) : gpg::CreateBinaryWriteArchive(mFile);
        return mArchive;
      }

      void Save(const moho::SSaveGameDispatchData& data) override
      {
        const double seconds = std::chrono::duration<double>(Clock::now() - mStart).count();
        delete mArchive;
        mArchive = nullptr;
        mFile.reset();
        mOwner.OnSaved(mBeat, mPath, seconds, data.useSuggestedName, data.saveName.c_str());
        delete this;
      }

    private:
      ~CKeyframeRequest()
      {
        delete mArchive;
      }

      CReplayKeyframes& mOwner;
      std::string mPath;
      const moho::Sim* mSim;
      std::uint32_t mBeat = 0;
      Clock::time_point mStart{};
      boost::shared_ptr<std::FILE> mFile;
      gpg::WriteArchive* mArchive = nullptr;
    };

    [[nodiscard]] bool ReadWholeFile(const std::string& path, std::vector<unsigned char>& bytes)
    {
      std::FILE* file = nullptr;
      if (fopen_s(&file, path.c_str(), "rb") != 0 || file == nullptr) {
        return false;
      }
      std::fseek(file, 0, SEEK_END);
      const long size = std::ftell(file);
      std::fseek(file, 0, SEEK_SET);
      bytes.resize(size > 0 ? static_cast<std::size_t>(size) : 0u);
      const bool read = bytes.empty() || std::fread(bytes.data(), bytes.size(), 1u, file) == 1u;
      std::fclose(file);
      return read;
    }
  } // namespace

  CReplayKeyframes::CReplayKeyframes(
    std::string directory, const int everyBeats, const bool keep, std::string label,
    std::map<int, std::string>* const index
  )
    : mDirectory(std::move(directory))
    , mLabel(std::move(label))
    , mEveryBeats(everyBeats)
    , mKeep(keep)
    , mNextBeat(index != nullptr && !index->empty() ? index->rbegin()->first + everyBeats : everyBeats)
    , mIndex(index)
  {
    std::error_code ignored;
    std::filesystem::create_directories(mDirectory, ignored);
  }

  void CReplayKeyframes::OnBeat(moho::ISTIDriver& driver, const moho::Sim* const sim, const int beat)
  {
    if (mPending || beat < mNextBeat) {
      return;
    }
    mPending = true;
    mNextBeat = beat + mEveryBeats;
    // The label in the name keeps parallel runs sharing a folder apart.
    const std::string name = mLabel + "_keyframe_" + std::to_string(beat) + ".bin";
    driver.RequestSaveGame(new CKeyframeRequest(*this, (std::filesystem::path(mDirectory) / name).string(), sim));
  }

  void CReplayKeyframes::OnSaved(
    const std::uint32_t beat, const std::string& path, const double saveSeconds, const bool succeeded,
    const std::string& error
  )
  {
    mPending = false;
    std::vector<unsigned char> bytes;
    if (!succeeded || !ReadWholeFile(path, bytes) || bytes.empty()) {
      ++mFailures;
      std::printf(
        "[%s] KEYFRAME-FAILED beat %u: %s\n", mLabel.c_str(), beat, succeeded ? "empty file" : error.c_str()
      );
      std::fflush(stdout);
      return;
    }

    gpg::MD5Context md5{};
    md5.Reset();
    md5.Update(bytes.data(), bytes.size());

    const Clock::time_point packStart = Clock::now();
    uLongf packedSize = moho::SIM_KeyframePackBound(static_cast<uLong>(bytes.size()));
    std::vector<unsigned char> packed(packedSize);
    const bool packedOk =
      compress2(packed.data(), &packedSize, bytes.data(), static_cast<uLong>(bytes.size()), 1) == Z_OK;
    const double packSeconds = std::chrono::duration<double>(Clock::now() - packStart).count();

    ++mCount;
    mLargestRaw = std::max<std::uint64_t>(mLargestRaw, bytes.size());
    if (packedOk) {
      mLargestPacked = std::max<std::uint64_t>(mLargestPacked, packedSize);
      mTotalPacked += packedSize;
    }
    mLongestSave = std::max(mLongestSave, saveSeconds);
    mTotalSave += saveSeconds;
    mTotalPack += packSeconds;

    std::printf(
      "[%s] keyframe beat %u: %zu bytes, zlib-1 %lu bytes in %.0f ms, saved within %.0f ms, md5 %s\n",
      mLabel.c_str(),
      beat,
      bytes.size(),
      packedOk ? static_cast<unsigned long>(packedSize) : 0ul,
      packSeconds * 1000.0,
      saveSeconds * 1000.0,
      md5.Digest().ToString().c_str()
    );
    std::fflush(stdout);

    if (mIndex != nullptr) {
      (*mIndex)[static_cast<int>(beat)] = path;
    }

    if (!mKeep) {
      std::error_code ignored;
      std::filesystem::remove(path, ignored);
    }
  }

  std::string CReplayKeyframes::Summary() const
  {
    char line[320];
    std::snprintf(
      line,
      sizeof(line),
      "keyframes: %d taken, %d failed, largest %.1f MB raw / %.1f MB zlib-1, all zlib-1 %.1f MB, "
      "save at most %.0f ms (mean %.0f), zlib mean %.0f ms",
      mCount,
      mFailures,
      static_cast<double>(mLargestRaw) / 1048576.0,
      static_cast<double>(mLargestPacked) / 1048576.0,
      static_cast<double>(mTotalPacked) / 1048576.0,
      mLongestSave * 1000.0,
      mCount > 0 ? mTotalSave * 1000.0 / mCount : 0.0,
      mCount > 0 ? mTotalPack * 1000.0 / mCount : 0.0
    );
    return line;
  }
} // namespace faf::headless
