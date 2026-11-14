#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "moho/audio/AudioEngine.h"

namespace moho
{
  /**
   * Engine addition, not in the shipped binary: the cue `AudioEngine::Play` hands out on Windows,
   * so the engine can rebuild XACT when the sound output changes (AudioEngine.cpp, "output
   * recovery"). Every holder (`HSound`, the loop and handle lists of `CUserSoundManager`) keeps
   * this object; the XACT cue behind it is destroyed with the old engine (`Detach`) and prepared
   * again from the rebuilt sound bank (`Restore`), played again when the game had played it.
   *
   * While it has no XACT cue it answers as the cue would: playing when the game played it and
   * didn't stop it, so the game neither reaps it nor starts it twice. `Abandon` reports it
   * stopped, for a cue that can't come back. All calls run on the thread that plays sounds.
   *
   * The registry is a set of pointers: its order only decides which cue is prepared again first
   * after a rebuild, which nothing in the sim or the game's sound logic can see.
   */
  class RecoverableCue final : public IXACTCue
  {
  public:
    // XACT_CUESTATE_* (xact.h).
    static constexpr std::int32_t kPrepared = 0x04;
    static constexpr std::int32_t kPlaying = 0x08;
    static constexpr std::int32_t kStopping = 0x10;
    static constexpr std::int32_t kStopped = 0x20;

    /**
     * Wraps `cue`, made from cue `cueIndex` of sound bank `bankId`; `played` is false for a cue
     * from `Prepare`. The cue adds itself to `registry` and leaves it in `Destroy`, both under
     * `registryLock` when there is one.
     */
    RecoverableCue(
      std::set<RecoverableCue*>& registry,
      std::mutex* const registryLock,
      IXACTCue* const cue,
      const std::uint16_t bankId,
      const std::uint16_t cueIndex,
      const bool played
    )
      : mRegistry(&registry)
      , mRegistryLock(registryLock)
      , mCue(cue)
      , mBankId(bankId)
      , mCueIndex(cueIndex)
      , mPlayRequested(played)
    {
      if (mRegistryLock != nullptr) {
        const std::lock_guard<std::mutex> guard(*mRegistryLock);
        registry.insert(this);
      } else {
        registry.insert(this);
      }
    }

    RecoverableCue(const RecoverableCue&) = delete;
    RecoverableCue& operator=(const RecoverableCue&) = delete;

    std::int32_t __stdcall Play() override
    {
      if (mStopped) {
        return 0;
      }
      const std::int32_t result = mCue != nullptr ? mCue->Play() : 0;
      if (result >= 0) {
        mPlayRequested = true;
      }
      return result;
    }

    void __stdcall Stop(
      const std::int32_t stopFlags
    ) override
    {
      mStopped = true;
      mPlayRequested = false;
      if (mCue != nullptr) {
        mCue->Stop(stopFlags);
      }
    }

    std::int32_t __stdcall GetState(
      std::int32_t* const outState
    ) override
    {
      if (outState == nullptr) {
        return static_cast<std::int32_t>(0x80004003u); // E_POINTER
      }
      if (mCue != nullptr) {
        return mCue->GetState(outState);
      }
      *outState = mStopped ? kStopped : (mPlayRequested ? kPlaying : kPrepared);
      return 0;
    }

    std::int32_t __stdcall Destroy() override
    {
      const std::int32_t result = mCue != nullptr ? mCue->Destroy() : 0;
      mCue = nullptr;
      if (mRegistryLock != nullptr) {
        const std::lock_guard<std::mutex> guard(*mRegistryLock);
        if (mRegistry != nullptr) {
          mRegistry->erase(this);
        }
      } else if (mRegistry != nullptr) {
        mRegistry->erase(this);
      }
      delete this;
      return result;
    }

    // Slots the engine never calls (AudioEngine.h); passed on for completeness.
    void __stdcall Reserved10() override
    {
      if (mCue != nullptr) {
        mCue->Reserved10();
      }
    }
    void __stdcall Reserved14() override
    {
      if (mCue != nullptr) {
        mCue->Reserved14();
      }
    }
    void __stdcall Reserved18() override
    {
      if (mCue != nullptr) {
        mCue->Reserved18();
      }
    }
    void __stdcall Reserved1C() override
    {
      if (mCue != nullptr) {
        mCue->Reserved1C();
      }
    }

    // The next 3D update sets the matrix again, for the new output's channels.
    std::int32_t __stdcall SetMatrixCoefficients(
      const std::uint32_t srcChannelCount,
      const std::uint32_t dstChannelCount,
      const float* const matrixCoefficients
    ) override
    {
      return mCue != nullptr ? mCue->SetMatrixCoefficients(srcChannelCount, dstChannelCount, matrixCoefficients) : 0;
    }

    std::uint16_t __stdcall GetVariableIndex(
      const char* const variableName
    ) override
    {
      if (variableName == nullptr) {
        return kInvalidVariable;
      }
      if (mCue != nullptr) {
        const std::uint16_t index = mCue->GetVariableIndex(variableName);
        mVariableIndices[variableName] = index;
        return index;
      }
      const auto found = mVariableIndices.find(variableName);
      return found != mVariableIndices.end() ? found->second : kInvalidVariable;
    }

    std::int32_t __stdcall SetVariable(
      const std::uint16_t variableIndex,
      const float value
    ) override
    {
      const std::int32_t result = mCue != nullptr ? mCue->SetVariable(variableIndex, value) : 0;
      if (result >= 0 && variableIndex != kInvalidVariable) {
        mVariables[variableIndex] = value;
      }
      return result;
    }

    /**
     * Destroys the XACT cue, before its engine goes. A cue that had stopped, or was stopping,
     * stays stopped. With `final` (its engine is destroyed for good) it also leaves the registry,
     * which dies with that engine, and reports stopped from then on.
     */
    void Detach(
      const bool final = false
    )
    {
      if (mCue != nullptr) {
        std::int32_t state = 0;
        if (mCue->GetState(&state) >= 0 && (state & (kStopping | kStopped)) != 0) {
          mStopped = true;
          mPlayRequested = false;
        }
        (void)mCue->Destroy();
        mCue = nullptr;
      }
      if (final) {
        // Called with the registry's lock held, by the engine that owns the registry.
        Abandon();
        mRegistry = nullptr;
        mRegistryLock = nullptr;
      }
    }

    /**
     * Makes the cue again from `bank`, the rebuilt sound bank of `BankId()`, sets its variables
     * and plays it when the game had played it. Returns false while it can't (no bank yet, or a
     * streaming wave bank still being prepared), to be tried again on a later frame; true when
     * there is nothing to restore.
     */
    bool Restore(
      IXACTSoundBank* const bank
    )
    {
      if (mCue != nullptr || mStopped) {
        return true;
      }
      if (bank == nullptr) {
        return false;
      }
      IXACTCue* replacement = nullptr;
      if (bank->Prepare(mCueIndex, 0u, 0u, &replacement) < 0 || replacement == nullptr) {
        return false;
      }
      for (const auto& [index, value] : mVariables) {
        (void)replacement->SetVariable(index, value);
      }
      if (mPlayRequested && replacement->Play() < 0) {
        (void)replacement->Destroy();
        return false;
      }
      mCue = replacement;
      return true;
    }

    /** Gives up on a cue `Restore` couldn't make again: the game sees it stopped. */
    void Abandon()
    {
      mStopped = true;
      mPlayRequested = false;
    }

    [[nodiscard]] std::uint16_t BankId() const
    {
      return mBankId;
    }

    [[nodiscard]] bool HasCue() const
    {
      return mCue != nullptr;
    }

  private:
    static constexpr std::uint16_t kInvalidVariable = 0xFFFFu; // XACTVARIABLEINDEX_INVALID

    ~RecoverableCue() = default;

    std::set<RecoverableCue*>* mRegistry;
    std::mutex* mRegistryLock;
    IXACTCue* mCue;
    std::uint16_t mBankId;
    std::uint16_t mCueIndex;
    bool mPlayRequested;
    bool mStopped = false;
    std::map<std::uint16_t, float> mVariables;
    std::map<std::string, std::uint16_t> mVariableIndices;
  };
} // namespace moho
