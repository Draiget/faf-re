#include "CD3DDevice.h"

#include <Windows.h>

#include <cstdint>
#include <cstring>

#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"

namespace
{
  moho::StatItem* sEngineStatFrameTime = nullptr;
  moho::StatItem* sEngineStatFrameFps = nullptr;

  float sDeltaFrame = 0.0f;
  float sWeightedFrameRate = 0.0f;
  std::int32_t sCurGameTick = 0;

  [[nodiscard]] std::int32_t FloatToBits(const float value) noexcept
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return static_cast<std::int32_t>(bits);
  }

  void PublishFloatStat(moho::StatItem* item, const float value)
  {
    if (item == nullptr) {
      return;
    }

    volatile long* const counter = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
    const long nextBits = static_cast<long>(FloatToBits(value));

    long observed = 0;
    do {
      observed = ::InterlockedCompareExchange(counter, 0, 0);
    } while (::InterlockedCompareExchange(counter, nextBits, observed) != observed);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0042DBE0 (FUN_0042DBE0)
   *
   * What it does:
   * Owns the deleting-destructor entrypoint for the D3D device wrapper.
   */
  CD3DDevice::~CD3DDevice() = default;

  /**
   * Address: 0x007FA2C0 (FUN_007FA2C0, Moho::REN_Frame)
   *
   * int gameTick, float simDeltaSeconds, float frameSeconds
   *
   * What it does:
   * Updates render timing globals and publishes `Frame_Time` / `Frame_FPS`
   * stat counters.
   */
  void REN_Frame(const int gameTick, const float simDeltaSeconds, const float frameSeconds)
  {
    sDeltaFrame = simDeltaSeconds;

    const float weightedFrameSeconds = (sWeightedFrameRate * 0.9f) + (frameSeconds * 0.1f);
    const float frameTimeMs = weightedFrameSeconds * 1000.0f;
    const float frameFps = 1.0f / weightedFrameSeconds;

    sCurGameTick = gameTick;
    sWeightedFrameRate = weightedFrameSeconds;

    if (sEngineStatFrameTime == nullptr) {
      if (EngineStats* const engineStats = GetEngineStats(); engineStats != nullptr) {
        sEngineStatFrameTime = engineStats->GetItem3("Frame_Time");
        if (sEngineStatFrameTime != nullptr) {
          (void)sEngineStatFrameTime->Release(0);
        }
      }
    }
    PublishFloatStat(sEngineStatFrameTime, frameTimeMs);

    if (sEngineStatFrameFps == nullptr) {
      if (EngineStats* const engineStats = GetEngineStats(); engineStats != nullptr) {
        sEngineStatFrameFps = engineStats->GetItem3("Frame_FPS");
        if (sEngineStatFrameFps != nullptr) {
          (void)sEngineStatFrameFps->Release(0);
        }
      }
    }
    PublishFloatStat(sEngineStatFrameFps, frameFps);
  }
} // namespace moho
