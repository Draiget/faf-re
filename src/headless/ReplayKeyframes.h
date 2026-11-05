#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>

// Engine addition (headless `--keyframe-every`, replay rewind): the sim saved between beats
// through the driver's save request (`ISTIDriver::RequestSaveGame`), the path a saved game takes,
// into a file. Each keyframe reports its beat, its size raw and with zlib, its MD5 and how long it
// took. The run's checksums tell whether taking keyframes changes the game; the MD5s tell whether
// two runs (or two players) save the same beat to the same bytes.

namespace moho
{
  class ISTIDriver;
  class Sim;
} // namespace moho

namespace faf::headless
{
  class CReplayKeyframes
  {
  public:
    /**
     * Every `everyBeats` beats into `directory`; the files are deleted after measuring unless `keep`.
     * With `index`: each saved file is added under the beat it restores, and nothing is saved before
     * the next beat due after the newest one already there.
     */
    CReplayKeyframes(
      std::string directory, int everyBeats, bool keep, std::string label, std::map<int, std::string>* index = nullptr
    );

    CReplayKeyframes(const CReplayKeyframes&) = delete;
    CReplayKeyframes& operator=(const CReplayKeyframes&) = delete;

    /** Main thread, after a beat's sync packet: asks for the next keyframe once it is due. */
    void OnBeat(moho::ISTIDriver& driver, const moho::Sim* sim, int beat);

    /** One line: count, sizes, times, failures. */
    [[nodiscard]] std::string Summary() const;
    [[nodiscard]] int Failures() const noexcept { return mFailures; }
    [[nodiscard]] bool Pending() const noexcept { return mPending; }

    /** For the replay viewer's hidden process: each file gets its name only once complete, and nothing is measured. */
    void SetPreparing(const bool preparing) noexcept { mPreparing = preparing; }
    /** Before any keyframe: the first comes at this beat. A later session of a `--seek` run goes on from what it has. */
    void SetFirstBeat(const int beat) noexcept
    {
      if (mIndex == nullptr || mIndex->empty()) {
        mNextBeat = beat;
      }
    }
    [[nodiscard]] bool IsPreparing() const noexcept { return mPreparing; }

    // Called by the request.
    void OnPrepared(std::uint32_t beat, double saveSeconds);
    void OnSaved(
      std::uint32_t beat, const std::string& path, double saveSeconds, bool succeeded, const std::string& error
    );

  private:
    bool mPreparing = false;
    std::string mDirectory;
    std::string mLabel;
    int mEveryBeats;
    bool mKeep;
    int mNextBeat;
    std::map<int, std::string>* mIndex;
    bool mPending = false;

    int mCount = 0;
    int mFailures = 0;
    std::uint64_t mLargestRaw = 0;
    std::uint64_t mLargestPacked = 0;
    std::uint64_t mTotalPacked = 0;
    double mLongestSave = 0.0;
    double mTotalSave = 0.0;
    double mTotalPack = 0.0;
  };
} // namespace faf::headless
