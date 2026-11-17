#pragma once

// FAF Studio's performance timing (perf.lua): while on, the time each section of the editor's frame takes, summed over
// five seconds and reported as one line (the app logs it, so the Log panel shows it too). No engine types: tested on
// its own (tests/editor/RoundNineTests.cpp).

#include <chrono>
#include <map>
#include <string>

namespace faf::editor
{
  class EdPerf
  {
  public:
    /** The editor's one timer (View > Performance timing, `/perf`). */
    static EdPerf& Get();

    [[nodiscard]] bool On() const noexcept
    {
      return mOn;
    }
    /** On or off; either way the counts start again. */
    void SetOn(bool on);

    /** A section's time this frame (milliseconds), added to its sum. */
    void Add(const std::string& section, double ms);
    /**
     * Ends a frame of `frameSeconds`; once `period` seconds of frames were counted, true with the report (the sections
     * by their share, the most first: milliseconds a frame and the slowest frame's), and the counts start again.
     */
    bool EndFrame(double frameSeconds, std::string& report, double period = 5.0);

    /** Times its own life into a section while the timer is on. */
    class Scope
    {
    public:
      explicit Scope(const char* section);
      ~Scope();
      Scope(const Scope&) = delete;
      Scope& operator=(const Scope&) = delete;

    private:
      const char* mSection = nullptr;
      std::chrono::steady_clock::time_point mStart;
    };

  private:
    struct Section
    {
      double total = 0.0;
      double worst = 0.0;
      double thisFrame = 0.0;
    };
    std::map<std::string, Section> mSections;
    bool mOn = false;
    double mElapsed = 0.0;
    int mFrames = 0;
  };
} // namespace faf::editor
