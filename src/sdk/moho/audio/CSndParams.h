#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/audio/CSndVar.h"

namespace moho
{
  class AudioEngine;

  /**
   * Parsed bank/cue playback descriptor used by user-side audio playback.
   *
   * Layout recovered from FUN_004E0740 callsites and field access in
   * CUserSoundManager methods.
   */
  class CSndParams
  {
  public:
    /**
     * Address: 0x004E0740 (FUN_004E0740)
     *
     * boost::shared_ptr<Moho::AudioEngine> const&, msvc8::string const&,
     * msvc8::string const&, Moho::CSndVar*, Moho::CSndVar*
     *
     * What it does:
     * Stores bank/cue strings, optional variable selectors, and captures
     * engine ownership for later playback.
     */
    CSndParams(
      const boost::shared_ptr<AudioEngine>& engine,
      const msvc8::string& bankName,
      const msvc8::string& cueName,
      CSndVar* lodCutoffVar,
      CSndVar* rpcLoopVar
    );

    /**
     * Address: 0x004E0820 (FUN_004E0820)
     *
     * boost::shared_ptr<Moho::AudioEngine>* outEngine
     *
     * What it does:
     * Copies/returns the retained playback engine handle for this cue set.
     */
    boost::shared_ptr<AudioEngine>* GetEngine(boost::shared_ptr<AudioEngine>* outEngine) const;

  public:
    msvc8::string mBank;                    // +0x00
    msvc8::string mCue;                     // +0x1C
    CSndVar* mLodCutoff;                    // +0x38
    CSndVar* mRpcLoopVariable;              // +0x3C
    std::uint32_t mResolvePolicy;           // +0x40
    std::uint16_t mBankId;                  // +0x44
    std::uint16_t mCueId;                   // +0x46
    boost::shared_ptr<AudioEngine> mEngine; // +0x48
  };

  static_assert(offsetof(CSndParams, mBank) == 0x00, "CSndParams::mBank offset must be 0x00");
  static_assert(offsetof(CSndParams, mCue) == 0x1C, "CSndParams::mCue offset must be 0x1C");
  static_assert(offsetof(CSndParams, mLodCutoff) == 0x38, "CSndParams::mLodCutoff offset must be 0x38");
  static_assert(offsetof(CSndParams, mRpcLoopVariable) == 0x3C, "CSndParams::mRpcLoopVariable offset must be 0x3C");
  static_assert(offsetof(CSndParams, mResolvePolicy) == 0x40, "CSndParams::mResolvePolicy offset must be 0x40");
  static_assert(offsetof(CSndParams, mBankId) == 0x44, "CSndParams::mBankId offset must be 0x44");
  static_assert(offsetof(CSndParams, mCueId) == 0x46, "CSndParams::mCueId offset must be 0x46");
  static_assert(offsetof(CSndParams, mEngine) == 0x48, "CSndParams::mEngine offset must be 0x48");
  static_assert(sizeof(CSndParams) == 0x50, "CSndParams size must be 0x50");
} // namespace moho
