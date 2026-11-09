// Part of Sim.cpp, included there: Sim accessors, checksums and resume.

/**
 * Address: 0x00746820 (FUN_00746820, ?GetParticleBuffer@Sim@Moho@@QAEPAUSParticleBuffer@2@XZ)
 *
 * What it does:
 * Returns the shared particle buffer, allocating and binding it lazily on
 * first use.
 */
SParticleBuffer* Sim::GetParticleBuffer()
{
  // Engine addition (sim_ParallelEffects): an effect tick on a sim worker appends to its chunk's
  // buffer, which CEffectManagerImpl::TickParallel then commits here in list order.
  if (SParticleBuffer* const chunkBuffer = EffectTickChunkParticleBuffer(); chunkBuffer != nullptr) {
    return chunkBuffer;
  }

  if (!mParticleBuffer) {
    (void)AssignSharedParticleBufferFromRaw(&mParticleBuffer, new SParticleBuffer());
  }

  return mParticleBuffer.get();
}

/**
 * Address: 0x0062CBD0 (FUN_0062CBD0, ?CenterOfMap@Sim@Moho@@QBE?AV?$Vector3@M@Wm3@@XZ)
 *
 * What it does:
 * Computes the center of the current map in terrain grid coordinates from
 * the backing heightfield dimensions and returns a zero-elevation vector.
 */
Wm3::Vec3f Sim::CenterOfMap() const
{
  const CHeightField* const field = mMapData->GetHeightField();

  Wm3::Vec3f center{};
  center.x = static_cast<float>(field->width - 1) * 0.5f;
  center.y = 0.0f;
  center.z = static_cast<float>(field->height - 1) * 0.5f;
  return center;
}

LuaPlus::LuaState* Sim::GetLuaState() const noexcept
{
  return mLuaState;
}

/**
 * Address: 0x00747180 (FUN_00747180, Moho::Sim::CheatsEnabled)
 *
 * What it does:
 * Logs the attempt, tracks its command source, hashes the enabled flag,
 * and returns whether the current simulation permits cheats.
 */
bool Sim::CheatsEnabled()
{
  if (mCheatsEnabled) {
    if (IsSimReportCheatsEnabled()) {
      gpg::Warnf("%s is cheating!", GetCurrentCommandSourceName());
    }
  } else {
    gpg::Warnf("%s is trying to cheat!", GetCurrentCommandSourceName());
  }

  if (IsSimDebugCheatsEnabled()) {
    // 0x00747230/0x0074723D refer to the same array after stack-argument pushes.
    std::uintptr_t frames[16]{};
    fa::string callstackText{};
    const int frameCount = GetCallStackFrames(frames);
    FormatCallStack(&callstackText, frameCount, frames);
    Logf("%s", callstackText.c_str());
  }

  if (mCurCommandSource != kInvalidCommandSource) {
    const int cheaterSource = static_cast<int>(mCurCommandSource);
    const auto it = std::find(mCheaters.begin(), mCheaters.end(), cheaterSource);
    if (it == mCheaters.end()) {
      mCheaters.push_back(cheaterSource);
    }
  }

  mContext.Update(&mCheatsEnabled, 1u);
  return mCheatsEnabled;
}

/**
 * Address: 0x00747320 (FUN_00747320, ?OkayToMessWith@Sim@Moho@@QAE_NPAVSimArmy@2@@Z)
 *
 * What it does:
 * Validates whether current command source may issue actions on one army, with
 * cheat fallback when source authorization fails.
 */
bool Sim::OkayToMessWith(SimArmy* army)
{
  auto* armyImpl = static_cast<CArmyImpl*>(army);
  if (!armyImpl) {
    return CheatsEnabled();
  }

  if (armyImpl->mVarDat.mIsOutOfGame) {
    return false;
  }

  const uint32_t sourceId = static_cast<uint32_t>(mCurCommandSource);
  if (sourceId != kInvalidCommandSource && armyImpl->mVarDat.mValidCommandSources.Contains(sourceId)) {
    return true;
  }

  return CheatsEnabled();
}

/**
 * Address: 0x00747360 (FUN_00747360, ?OkayToMessWith@Sim@Moho@@QAE_NPAVEntity@2@@Z)
 *
 * What it does:
 * Resolves entity owner army and delegates permission checks to army-level policy.
 */
bool Sim::OkayToMessWith(Entity* entity)
{
  return OkayToMessWith(entity ? static_cast<SimArmy*>(entity->ArmyRef) : nullptr);
}

/**
 * Address: 0x007473B0 (FUN_007473B0, ?OkayToMessWith@Sim@Moho@@QAE_NPAVCUnitCommand@2@@Z)
 *
 * What it does:
 * Checks each command unit-set entry against command-source permissions and
 * requires cheats for unusable or unauthorized entries.
 */
bool Sim::OkayToMessWith(CUnitCommand* cmd)
{
  if (!cmd) {
    return false;
  }

  Entity** unitSetIt = cmd->mUnitSet.mVec.begin();
  Entity** unitSetEnd = cmd->mUnitSet.mVec.end();
  if (unitSetIt == unitSetEnd) {
    return true;
  }

  while (unitSetIt != unitSetEnd) {
    Unit* const unit = static_cast<Unit*>(*unitSetIt);
    if (unit == nullptr) {
      if (!CheatsEnabled()) {
        return false;
      }
      ++unitSetIt;
      continue;
    }

    Entity* entity = unit;
    if (!OkayToMessWith(entity)) {
      return false;
    }

    ++unitSetIt;
  }

  return true;
}

/**
 * Address: 0x00743120 (FUN_00743120, Moho::SDesyncInfo::SDesyncInfo)
 *
 * What it does:
 * Initializes one desync entry from beat/army metadata and both checksum
 * digest payloads.
 */
SDesyncInfo::SDesyncInfo(const std::int32_t beatValue, const std::int32_t armyValue, const gpg::MD5Digest& expectedHash, const gpg::MD5Digest& remoteHash)
  : beat(beatValue)
  , army(armyValue)
  , hash1(expectedHash)
  , hash2(remoteHash)
{}

/**
 * Address: 0x007487C0 (FUN_007487C0, ?VerifyChecksum@Sim@Moho@@UAEXABVMD5Digest@gpg@@H@Z)
 *
 * What it does:
 * Validates one remote beat checksum against the local rolling hash ring,
 * records a desync entry on mismatch, and clears the cached desync log list.
 */
void Sim::VerifyChecksum(const gpg::MD5Digest& checksum, const CSeqNo beat)
{
  if (mCurCommandSource == kInvalidCommandSource) {
    return;
  }

  const int oldestBeat = static_cast<int>(mCurBeat) - 128;
  if (beat < oldestBeat) {
    Logf(
      "Ignoring verify of beat %d because that was %d beats ago and we only have data for %d beats.",
      beat,
      static_cast<int>(mCurBeat) - beat,
      128
    );
    return;
  }

  if (beat >= static_cast<int>(mCurBeat)) {
    Logf("Ignoring verify of beat %d because it is in the future.", beat);
    return;
  }

  gpg::MD5Digest* expected = &mSimHashes[beat & 0x7F];

  // Engine addition (issue #216): every compared report, matching or not, so a dump shows who
  // agrees with whom.
  if (CDesyncRecorder* const recorder = CDesyncRecorder::For(this)) {
    recorder->NoteChecksum(*this, beat, mCurCommandSource, checksum, *expected);
  }

  if (std::memcmp(expected, &checksum, sizeof(gpg::MD5Digest)) == 0) {
    return;
  }

  const SDesyncInfo desync(beat, mCurCommandSource, *expected, checksum);
  mDesyncs.push_back(desync);

  const fa::string incomingHash = checksum.ToString();
  const fa::string simHash = expected->ToString();

  gpg::Warnf(
    "Checksum for beat %d mismatched: %s (sim) != %s (%s).",
    beat,
    simHash.c_str(),
    incomingHash.c_str(),
    GetCurrentCommandSourceName()
  );

  mIsDesyncFree = false;
  mDesyncLogLines.clear();
}

/**
 * Address: 0x00748960 (FUN_00748960, ?RequestPause@Sim@Moho@@UAEXXZ)
 */
void Sim::RequestPause()
{
  if (mPausedByCommandSource != -1) {
    return;
  }

  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return;
  }

  // Three-way, not two: only a timeout budget of exactly zero refuses the
  // pause. A negative budget means unlimited, and pauses without spending
  // anything -- which is what every local player has, since SessionStartup
  // seeds `mTimeouts = -1`.
  //
  //   0x00748985  test edx, edx
  //   0x00748987  jz   locret_74899A       ; == 0, refuse
  //   0x00748989  jle  short loc_74898E    ; <  0, skip the decrement
  //   0x0074898B  add  dword ptr [eax], -1 ; >  0, spend one
  //   0x0074898E  mov  [ecx+8E0h], eax     ; both surviving paths pause
  int& timeouts = mCommandSources[mCurCommandSource].mTimeouts;
  if (timeouts == 0) {
    return;
  }

  if (timeouts > 0) {
    --timeouts;
  }
  mPausedByCommandSource = mCurCommandSource;
}

/**
 * Address: 0x007489A0 (FUN_007489A0, ?Resume@Sim@Moho@@UAEXXZ)
 */
void Sim::Resume()
{
  if (mCurCommandSource != kInvalidCommandSource) {
    mPausedByCommandSource = -1;
  }
}

/**
 * Address: 0x007489C0 (FUN_007489C0, ?SingleStep@Sim@Moho@@UAEXXZ)
 */
void Sim::SingleStep()
{
  if (mPausedByCommandSource != -1 && mCurCommandSource != kInvalidCommandSource) {
    mSingleStep = true;
  }
}
