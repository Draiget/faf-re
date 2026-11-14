#pragma once

#include "moho/audio/AudioEngine.h"

#include <map>
#include <set>
#include <string>

namespace moho
{
  // FAF addition: callers retain this handle while XACT and its cues are rebuilt.
  // All operations run on the audio/UI thread, like the original cue calls.
  class RecoverableCue final : public IXACTCue
  {
  public:
    RecoverableCue(std::set<RecoverableCue*>& registry, IXACTCue* cue,
                   std::uint16_t bank, std::uint16_t index, bool prepared, bool* restorePending = nullptr)
      : mRegistry(&registry), mCue(cue), mBank(bank), mIndex(index),
        mState(prepared ? XACT_CUESTATE_PREPARED : XACT_CUESTATE_PLAYING),
        mPlayRequested(!prepared), mRestorePending(restorePending)
    {
      registry.insert(this);
    }

    std::int32_t __stdcall Play() override
    {
      const auto result = mCue ? mCue->Play() : 0;
      if (result >= 0) { mState = XACT_CUESTATE_PLAYING; mPlayRequested = true; }
      if (!mCue && mRestorePending) *mRestorePending = true;
      return result;
    }

    void __stdcall Stop(std::int32_t flags) override
    {
      mState = XACT_CUESTATE_STOPPED;
      mPlayRequested = false;
      if (mCue) mCue->Stop(flags);
    }

    std::int32_t __stdcall GetState(std::int32_t* state) override
    {
      if (!state) return E_POINTER;
      if (mCue) {
        const auto result = mCue->GetState(state);
        if (result >= 0) {
          mState = *state;
          if (mState & (XACT_CUESTATE_STOPPED | XACT_CUESTATE_STOPPING)) mPlayRequested = false;
          return result;
        }
      }
      *state = mState;
      return 0;
    }

    std::int32_t __stdcall Destroy() override
    {
      const auto result = mCue ? mCue->Destroy() : 0;
      if (mRegistry) mRegistry->erase(this);
      delete this;
      return result;
    }

    void __stdcall Reserved10() override { if (mCue) mCue->Reserved10(); }
    void __stdcall Reserved14() override { if (mCue) mCue->Reserved14(); }
    void __stdcall Reserved18() override { if (mCue) mCue->Reserved18(); }
    void __stdcall Reserved1C() override { if (mCue) mCue->Reserved1C(); }

    std::int32_t __stdcall SetMatrixCoefficients(std::uint32_t src, std::uint32_t dst,
                                               const float* matrix) override
    {
      // The next spatial update recomputes the matrix for the new channel layout.
      return mCue ? mCue->SetMatrixCoefficients(src, dst, matrix) : 0;
    }

    std::uint16_t __stdcall GetVariableIndex(const char* name) override
    {
      if (mCue) {
        const auto index = mCue->GetVariableIndex(name);
        mVariableIndices[name] = index;
        return index;
      }
      const auto found = mVariableIndices.find(name);
      return found == mVariableIndices.end() ? 0xFFFFu : found->second;
    }

    std::int32_t __stdcall SetVariable(std::uint16_t index, float value) override
    {
      const auto result = mCue ? mCue->SetVariable(index, value) : 0;
      if (result >= 0 && index != 0xFFFFu) mVariables[index] = value;
      return result;
    }

    void Detach(bool shutdown = false)
    {
      if (mCue) {
        std::int32_t state = mState;
        if (mCue->GetState(&state) >= 0) mState = state;
        if (mState & (XACT_CUESTATE_STOPPED | XACT_CUESTATE_STOPPING)) mPlayRequested = false;
        mCue->Destroy();
        mCue = nullptr;
      }
      if (shutdown) {
        mState = XACT_CUESTATE_STOPPED;
        mPlayRequested = false;
        mRegistry = nullptr;
        mRestorePending = nullptr;
      }
    }

    bool Restore(IXACTSoundBank* bank)
    {
      if (mCue || (mState & (XACT_CUESTATE_STOPPED | XACT_CUESTATE_STOPPING))) return true;
      if (!bank) return false;
      IXACTCue* replacement = nullptr;
      if (bank->Prepare(mIndex, 0, 0, &replacement) < 0 || !replacement) return false;
      mCue = replacement;
      for (const auto& [index, value] : mVariables) mCue->SetVariable(index, value);
      if (mPlayRequested) {
        if (mCue->Play() < 0) {
          mCue->Destroy();
          mCue = nullptr;
          return false;
        }
      }
      return true;
    }

    std::uint16_t Bank() const { return mBank; }

  private:
    std::set<RecoverableCue*>* mRegistry;
    IXACTCue* mCue;
    std::uint16_t mBank;
    std::uint16_t mIndex;
    std::int32_t mState;
    bool mPlayRequested;
    bool* mRestorePending;
    std::map<std::uint16_t, float> mVariables;
    std::map<std::string, std::uint16_t> mVariableIndices;
  };
}
