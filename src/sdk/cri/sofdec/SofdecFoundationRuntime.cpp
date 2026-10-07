#include "moho/audio/SofdecRuntime.h"

#include <array>
#include <algorithm>
#include <bit>
#include <cstdarg>
#include <cstdlib>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mmintrin.h>
#include <xmmintrin.h>
#include <process.h>

#include "platform/MmxOnX64.h"

#ifndef CINTERFACE
#define CINTERFACE
#endif
#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>

using moho::SjChunkRange;

struct XeficQueuedFileEntry
{
  HANDLE fileHandle = nullptr; // +0x00
  std::int32_t fileSizeBytes = 0; // +0x04
  std::int32_t cacheState = 0; // +0x08
  XeficQueuedFileEntry* next = nullptr; // +0x0C
  const char* relativePath = nullptr; // +0x10
};

static_assert(offsetof(XeficQueuedFileEntry, fileHandle) == 0x00, "XeficQueuedFileEntry::fileHandle offset must be 0x00");
static_assert(offsetof(XeficQueuedFileEntry, fileSizeBytes) == 0x04, "XeficQueuedFileEntry::fileSizeBytes offset must be 0x04");
static_assert(offsetof(XeficQueuedFileEntry, cacheState) == 0x08, "XeficQueuedFileEntry::cacheState offset must be 0x08");
static_assert(offsetof(XeficQueuedFileEntry, next) == 0x0C, "XeficQueuedFileEntry::next offset must be 0x0C");
static_assert(offsetof(XeficQueuedFileEntry, relativePath) == 0x10, "XeficQueuedFileEntry::relativePath offset must be 0x10");
static_assert(sizeof(XeficQueuedFileEntry) == 0x14, "XeficQueuedFileEntry size must be 0x14");

struct XeficObject
{
  std::int32_t used = 0; // +0x00
  std::int32_t state = 0; // +0x04
  std::int32_t stateSignal = 0; // +0x08
  std::int32_t hasHeapAllocation = 0; // +0x0C
  HANDLE heapHandle = nullptr; // +0x10
  std::int32_t hasWork = 0; // +0x14
  void* workBuffer = nullptr; // +0x18
  std::int32_t workBufferBytes = 0; // +0x1C
  std::int32_t usedWorkBytes = 0; // +0x20
  const char* pathPrefix = nullptr; // +0x24
  std::int32_t pathPrefixLength = 0; // +0x28
  std::int32_t pathEnumerationMode = 0; // +0x2C
  std::int32_t queuedEntryCount = 0; // +0x30
  XeficQueuedFileEntry* queueHead = nullptr; // +0x34
  XeficQueuedFileEntry* queueCursor = nullptr; // +0x38
  void* stateResetGuard = nullptr; // +0x3C
  std::uint8_t mUnknown40[0x4]{}; // +0x40
};

static_assert(offsetof(XeficObject, used) == 0x00, "XeficObject::used offset must be 0x00");
static_assert(offsetof(XeficObject, state) == 0x04, "XeficObject::state offset must be 0x04");
static_assert(offsetof(XeficObject, stateSignal) == 0x08, "XeficObject::stateSignal offset must be 0x08");
static_assert(offsetof(XeficObject, hasHeapAllocation) == 0x0C, "XeficObject::hasHeapAllocation offset must be 0x0C");
static_assert(offsetof(XeficObject, heapHandle) == 0x10, "XeficObject::heapHandle offset must be 0x10");
static_assert(offsetof(XeficObject, hasWork) == 0x14, "XeficObject::hasWork offset must be 0x14");
static_assert(offsetof(XeficObject, workBuffer) == 0x18, "XeficObject::workBuffer offset must be 0x18");
static_assert(offsetof(XeficObject, workBufferBytes) == 0x1C, "XeficObject::workBufferBytes offset must be 0x1C");
static_assert(offsetof(XeficObject, usedWorkBytes) == 0x20, "XeficObject::usedWorkBytes offset must be 0x20");
static_assert(offsetof(XeficObject, pathPrefix) == 0x24, "XeficObject::pathPrefix offset must be 0x24");
static_assert(offsetof(XeficObject, pathPrefixLength) == 0x28, "XeficObject::pathPrefixLength offset must be 0x28");
static_assert(
  offsetof(XeficObject, pathEnumerationMode) == 0x2C, "XeficObject::pathEnumerationMode offset must be 0x2C"
);
static_assert(offsetof(XeficObject, queuedEntryCount) == 0x30, "XeficObject::queuedEntryCount offset must be 0x30");
static_assert(offsetof(XeficObject, queueHead) == 0x34, "XeficObject::queueHead offset must be 0x34");
static_assert(offsetof(XeficObject, queueCursor) == 0x38, "XeficObject::queueCursor offset must be 0x38");
static_assert(offsetof(XeficObject, stateResetGuard) == 0x3C, "XeficObject::stateResetGuard offset must be 0x3C");
static_assert(sizeof(XeficObject) == 0x44, "XeficObject size must be 0x44");

struct XeciObject
{
  std::uint8_t used = 0; // +0x00
  std::int8_t state = 0; // +0x01
  std::uint8_t mUnknown02[0x2]{}; // +0x02
  void* readBufferPtr = nullptr; // +0x04
  std::uint32_t readChunkSizeBytes = 0; // +0x08
  std::int32_t mUnknown0C = 0; // +0x0C
  std::uint32_t fileSizeLow = 0; // +0x10
  std::int32_t fileSizeHigh = 0; // +0x14
  std::uint32_t transferChunkCount = 0; // +0x18
  std::int32_t currentChunkIndex = 0; // +0x1C
  std::uint32_t transferCountLow = 0; // +0x20
  std::uint32_t transferCountHigh = 0; // +0x24
  std::int32_t readChunkCount = 0; // +0x28
  std::int32_t fileHandleOwnedExternally = 0; // +0x2C
  HANDLE fileHandle = nullptr; // +0x30
  OVERLAPPED overlapped{}; // +0x34
  std::int32_t readOffsetLow = 0; // +0x48
  std::int32_t readOffsetHigh = 0; // +0x4C
  std::uint32_t transferSizeBytes = 0; // +0x50
  std::int32_t wantsRead = 0; // +0x54
  std::int32_t wantsUpdate = 0; // +0x58
  std::int32_t updateLockFlag = 0; // +0x5C
  char fileName[MAX_PATH]{}; // +0x60
  std::uint8_t mUnknown164[0x4]{}; // +0x164
};

static_assert(offsetof(XeciObject, used) == 0x00, "XeciObject::used offset must be 0x00");
static_assert(offsetof(XeciObject, state) == 0x01, "XeciObject::state offset must be 0x01");
static_assert(offsetof(XeciObject, readBufferPtr) == 0x04, "XeciObject::readBufferPtr offset must be 0x04");
static_assert(
  offsetof(XeciObject, readChunkSizeBytes) == 0x08, "XeciObject::readChunkSizeBytes offset must be 0x08"
);
static_assert(offsetof(XeciObject, fileSizeLow) == 0x10, "XeciObject::fileSizeLow offset must be 0x10");
static_assert(offsetof(XeciObject, fileSizeHigh) == 0x14, "XeciObject::fileSizeHigh offset must be 0x14");
static_assert(
  offsetof(XeciObject, transferChunkCount) == 0x18, "XeciObject::transferChunkCount offset must be 0x18"
);
static_assert(
  offsetof(XeciObject, currentChunkIndex) == 0x1C, "XeciObject::currentChunkIndex offset must be 0x1C"
);
static_assert(
  offsetof(XeciObject, transferCountLow) == 0x20, "XeciObject::transferCountLow offset must be 0x20"
);
static_assert(
  offsetof(XeciObject, transferCountHigh) == 0x24, "XeciObject::transferCountHigh offset must be 0x24"
);
static_assert(offsetof(XeciObject, readChunkCount) == 0x28, "XeciObject::readChunkCount offset must be 0x28");
static_assert(
  offsetof(XeciObject, fileHandleOwnedExternally) == 0x2C,
  "XeciObject::fileHandleOwnedExternally offset must be 0x2C"
);
static_assert(offsetof(XeciObject, fileHandle) == 0x30, "XeciObject::fileHandle offset must be 0x30");
static_assert(offsetof(XeciObject, overlapped) == 0x34, "XeciObject::overlapped offset must be 0x34");
static_assert(offsetof(XeciObject, readOffsetLow) == 0x48, "XeciObject::readOffsetLow offset must be 0x48");
static_assert(offsetof(XeciObject, readOffsetHigh) == 0x4C, "XeciObject::readOffsetHigh offset must be 0x4C");
static_assert(
  offsetof(XeciObject, transferSizeBytes) == 0x50, "XeciObject::transferSizeBytes offset must be 0x50"
);
static_assert(offsetof(XeciObject, wantsRead) == 0x54, "XeciObject::wantsRead offset must be 0x54");
static_assert(offsetof(XeciObject, wantsUpdate) == 0x58, "XeciObject::wantsUpdate offset must be 0x58");
static_assert(offsetof(XeciObject, updateLockFlag) == 0x5C, "XeciObject::updateLockFlag offset must be 0x5C");
static_assert(offsetof(XeciObject, fileName) == 0x60, "XeciObject::fileName offset must be 0x60");
static_assert(sizeof(XeciObject) == 0x168, "XeciObject size must be 0x168");

struct MfciHandle
{
  std::uint8_t used = 0; // +0x00
  std::uint8_t state = 0; // +0x01
  std::uint8_t mUnknown02[0x2]{}; // +0x02
  std::int32_t sectorSizeBytes = 0; // +0x04
  std::int32_t fileSizeBytes = 0; // +0x08
  std::int32_t sectorCount = 0; // +0x0C
  std::int32_t sectorCursor = 0; // +0x10
  std::int32_t transferredBytes = 0; // +0x14
  std::int32_t transferredSectors = 0; // +0x18
  char addressAndSizeText[0x1C]{}; // +0x1C
};

static_assert(offsetof(MfciHandle, used) == 0x00, "MfciHandle::used offset must be 0x00");
static_assert(offsetof(MfciHandle, state) == 0x01, "MfciHandle::state offset must be 0x01");
static_assert(offsetof(MfciHandle, sectorSizeBytes) == 0x04, "MfciHandle::sectorSizeBytes offset must be 0x04");
static_assert(offsetof(MfciHandle, fileSizeBytes) == 0x08, "MfciHandle::fileSizeBytes offset must be 0x08");
static_assert(offsetof(MfciHandle, sectorCount) == 0x0C, "MfciHandle::sectorCount offset must be 0x0C");
static_assert(offsetof(MfciHandle, sectorCursor) == 0x10, "MfciHandle::sectorCursor offset must be 0x10");
static_assert(offsetof(MfciHandle, transferredBytes) == 0x14, "MfciHandle::transferredBytes offset must be 0x14");
static_assert(offsetof(MfciHandle, transferredSectors) == 0x18, "MfciHandle::transferredSectors offset must be 0x18");
static_assert(offsetof(MfciHandle, addressAndSizeText) == 0x1C, "MfciHandle::addressAndSizeText offset must be 0x1C");
static_assert(sizeof(MfciHandle) == 0x38, "MfciHandle size must be 0x38");

[[nodiscard]] MfciHandle* AsMfciHandle(const SofdecAddressWord handleAddress)
{
  return reinterpret_cast<MfciHandle*>(static_cast<std::uintptr_t>(handleAddress));
}

[[nodiscard]] const MfciHandle* AsMfciHandleConst(const SofdecAddressWord handleAddress)
{
  return reinterpret_cast<const MfciHandle*>(static_cast<std::uintptr_t>(handleAddress));
}

[[nodiscard]] SofdecAddressWord MfciHandleToAddress(const MfciHandle* const handle)
{
  return static_cast<SofdecAddressWord>(reinterpret_cast<std::uintptr_t>(handle));
}

struct AdxStreamJoinEncoderState
{
  std::uint8_t used = 0; // +0x00
  std::uint8_t executionStage = 0; // +0x01
  std::uint8_t inputChannelCountCompact = 0; // +0x02
  std::uint8_t endCodePending = 0; // +0x03
  moho::SofdecSjSupplyHandle* inputSjHandles[2]{}; // +0x04
  moho::SofdecSjSupplyHandle* outputSjHandle = nullptr; // +0x0C
  std::uint8_t mUnknown10[0x18]{}; // +0x10
  std::int32_t streamDataOffset = 0; // +0x28
  std::int32_t encodedDataBytes = 0; // +0x2C
  std::int32_t encodedSamplePosition = 0; // +0x30
  std::int32_t totalSampleCountLimit = 0; // +0x34
  std::int32_t mUnknown38 = 0; // +0x38
  std::int32_t totalSampleCount = 0; // +0x3C
  std::int32_t totalSampleCountLimitMirror = 0; // +0x40
  std::int32_t blockSampleCount = 0; // +0x44
  std::int32_t headerInfoSizeBytes = 0; // +0x48
  std::int32_t headerCodecType = 0; // +0x4C
  std::int32_t blockLengthBytes = 0; // +0x50
  std::int32_t outputBitsPerSample = 0; // +0x54
  std::int32_t channelCount = 0; // +0x58
  std::int32_t predictorSampleRate = 0; // +0x5C
  std::int32_t totalSampleCountMirror = 0; // +0x60
  std::int32_t predictorPreset = 0; // +0x64
  std::int32_t loopInsertedSampleCount = 0; // +0x68
  std::int32_t loopCount = 0; // +0x6C
  std::int32_t loopStartSamplePosition = 0; // +0x70
  std::int32_t loopStartByteOffset = 0; // +0x74
  std::int32_t loopEndSamplePosition = 0; // +0x78
  std::int32_t loopEndByteOffset = 0; // +0x7C
  std::int32_t predictorFilterHandles[2]{}; // +0x80
  std::uint8_t predictorHistoryWindow[0x240]{}; // +0x88
  std::uint8_t stagedPredictorWindow[0x8]{}; // +0x2C8
  std::int16_t extKey0 = 0; // +0x2D0
  std::int16_t extKeyMultiplier = 0; // +0x2D2
  std::int16_t extKeyAdder = 0; // +0x2D4
  std::uint8_t hasAinfInfo = 0; // +0x2D6
  std::uint8_t ainfDataIdBytes[0x10]{}; // +0x2D7
  std::int16_t ainfOutputVolume = 0; // +0x2E8
  std::int16_t ainfOutputPanByChannel[2]{}; // +0x2EA
  std::uint8_t commonInfoEnabled = 0; // +0x2EE
  std::uint8_t mUnknown2EF = 0; // +0x2EF
  std::int32_t commonInfoDataOffset = 0; // +0x2F0
  std::int32_t commonInfoDataBytes = 0; // +0x2F4
};

static_assert(offsetof(AdxStreamJoinEncoderState, used) == 0x00, "AdxStreamJoinEncoderState::used offset must be 0x00");
static_assert(
  offsetof(AdxStreamJoinEncoderState, executionStage) == 0x01,
  "AdxStreamJoinEncoderState::executionStage offset must be 0x01"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, inputChannelCountCompact) == 0x02,
  "AdxStreamJoinEncoderState::inputChannelCountCompact offset must be 0x02"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, endCodePending) == 0x03,
  "AdxStreamJoinEncoderState::endCodePending offset must be 0x03"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, inputSjHandles) == 0x04,
  "AdxStreamJoinEncoderState::inputSjHandles offset must be 0x04"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, outputSjHandle) == 0x0C,
  "AdxStreamJoinEncoderState::outputSjHandle offset must be 0x0C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, streamDataOffset) == 0x28,
  "AdxStreamJoinEncoderState::streamDataOffset offset must be 0x28"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, encodedDataBytes) == 0x2C,
  "AdxStreamJoinEncoderState::encodedDataBytes offset must be 0x2C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, encodedSamplePosition) == 0x30,
  "AdxStreamJoinEncoderState::encodedSamplePosition offset must be 0x30"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, totalSampleCountLimit) == 0x34,
  "AdxStreamJoinEncoderState::totalSampleCountLimit offset must be 0x34"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, totalSampleCount) == 0x3C,
  "AdxStreamJoinEncoderState::totalSampleCount offset must be 0x3C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, totalSampleCountLimitMirror) == 0x40,
  "AdxStreamJoinEncoderState::totalSampleCountLimitMirror offset must be 0x40"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, blockSampleCount) == 0x44,
  "AdxStreamJoinEncoderState::blockSampleCount offset must be 0x44"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, headerInfoSizeBytes) == 0x48,
  "AdxStreamJoinEncoderState::headerInfoSizeBytes offset must be 0x48"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, headerCodecType) == 0x4C,
  "AdxStreamJoinEncoderState::headerCodecType offset must be 0x4C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, blockLengthBytes) == 0x50,
  "AdxStreamJoinEncoderState::blockLengthBytes offset must be 0x50"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, outputBitsPerSample) == 0x54,
  "AdxStreamJoinEncoderState::outputBitsPerSample offset must be 0x54"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, channelCount) == 0x58,
  "AdxStreamJoinEncoderState::channelCount offset must be 0x58"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, predictorSampleRate) == 0x5C,
  "AdxStreamJoinEncoderState::predictorSampleRate offset must be 0x5C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, totalSampleCountMirror) == 0x60,
  "AdxStreamJoinEncoderState::totalSampleCountMirror offset must be 0x60"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, predictorPreset) == 0x64,
  "AdxStreamJoinEncoderState::predictorPreset offset must be 0x64"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopInsertedSampleCount) == 0x68,
  "AdxStreamJoinEncoderState::loopInsertedSampleCount offset must be 0x68"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopCount) == 0x6C,
  "AdxStreamJoinEncoderState::loopCount offset must be 0x6C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopStartSamplePosition) == 0x70,
  "AdxStreamJoinEncoderState::loopStartSamplePosition offset must be 0x70"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopStartByteOffset) == 0x74,
  "AdxStreamJoinEncoderState::loopStartByteOffset offset must be 0x74"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopEndSamplePosition) == 0x78,
  "AdxStreamJoinEncoderState::loopEndSamplePosition offset must be 0x78"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, loopEndByteOffset) == 0x7C,
  "AdxStreamJoinEncoderState::loopEndByteOffset offset must be 0x7C"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, predictorFilterHandles) == 0x80,
  "AdxStreamJoinEncoderState::predictorFilterHandles offset must be 0x80"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, predictorHistoryWindow) == 0x88,
  "AdxStreamJoinEncoderState::predictorHistoryWindow offset must be 0x88"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, stagedPredictorWindow) == 0x2C8,
  "AdxStreamJoinEncoderState::stagedPredictorWindow offset must be 0x2C8"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, extKey0) == 0x2D0,
  "AdxStreamJoinEncoderState::extKey0 offset must be 0x2D0"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, extKeyMultiplier) == 0x2D2,
  "AdxStreamJoinEncoderState::extKeyMultiplier offset must be 0x2D2"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, extKeyAdder) == 0x2D4,
  "AdxStreamJoinEncoderState::extKeyAdder offset must be 0x2D4"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, hasAinfInfo) == 0x2D6,
  "AdxStreamJoinEncoderState::hasAinfInfo offset must be 0x2D6"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, ainfDataIdBytes) == 0x2D7,
  "AdxStreamJoinEncoderState::ainfDataIdBytes offset must be 0x2D7"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, ainfOutputVolume) == 0x2E8,
  "AdxStreamJoinEncoderState::ainfOutputVolume offset must be 0x2E8"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, ainfOutputPanByChannel) == 0x2EA,
  "AdxStreamJoinEncoderState::ainfOutputPanByChannel offset must be 0x2EA"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, commonInfoEnabled) == 0x2EE,
  "AdxStreamJoinEncoderState::commonInfoEnabled offset must be 0x2EE"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, commonInfoDataOffset) == 0x2F0,
  "AdxStreamJoinEncoderState::commonInfoDataOffset offset must be 0x2F0"
);
static_assert(
  offsetof(AdxStreamJoinEncoderState, commonInfoDataBytes) == 0x2F4,
  "AdxStreamJoinEncoderState::commonInfoDataBytes offset must be 0x2F4"
);
static_assert(sizeof(AdxStreamJoinEncoderState) == 0x2F8, "AdxStreamJoinEncoderState size must be 0x2F8");

struct AdxsjeIirFilterState
{
  std::uint8_t used = 0; // +0x00
  std::uint8_t mUnknown01 = 0; // +0x01
  std::uint8_t mUnknown02[0x2]{}; // +0x02
  std::int16_t coefficient0 = 0; // +0x04
  std::int16_t coefficient1 = 0; // +0x06
  std::int16_t delay0 = 0; // +0x08
  std::int16_t delay1 = 0; // +0x0A
};

static_assert(offsetof(AdxsjeIirFilterState, used) == 0x00, "AdxsjeIirFilterState::used offset must be 0x00");
static_assert(
  offsetof(AdxsjeIirFilterState, coefficient0) == 0x04,
  "AdxsjeIirFilterState::coefficient0 offset must be 0x04"
);
static_assert(
  offsetof(AdxsjeIirFilterState, coefficient1) == 0x06,
  "AdxsjeIirFilterState::coefficient1 offset must be 0x06"
);
static_assert(offsetof(AdxsjeIirFilterState, delay0) == 0x08, "AdxsjeIirFilterState::delay0 offset must be 0x08");
static_assert(offsetof(AdxsjeIirFilterState, delay1) == 0x0A, "AdxsjeIirFilterState::delay1 offset must be 0x0A");
static_assert(sizeof(AdxsjeIirFilterState) == 0x0C, "AdxsjeIirFilterState size must be 0x0C");

struct AdxsjePredictorFilterState
{
  std::uint8_t used = 0; // +0x00
  std::uint8_t mUnknown01 = 0; // +0x01
  std::uint8_t mUnknown02[0x2]{}; // +0x02
  std::int16_t coefficient0 = 0; // +0x04
  std::int16_t coefficient1 = 0; // +0x06
  std::int16_t delay0 = 0; // +0x08
  std::int16_t delay1 = 0; // +0x0A
  std::uint8_t mUnknown0C[0x8]{}; // +0x0C
  std::int32_t blockSampleCount = 0; // +0x14
  std::int16_t residualSignals[0x20]{}; // +0x18
  std::int8_t quantizedResidualSignals[0x20]{}; // +0x58
  std::int32_t peakAbsResidual = 0; // +0x78
  std::int16_t gainStep = 0; // +0x7C
  std::uint8_t mUnknown7E[0x2]{}; // +0x7E
  double residualScale = 0.0; // +0x80
  SofdecAddressWord iirFilterHandle = 0; // +0x88
  std::uint8_t mUnknown8C[0x4]{}; // +0x8C
};

static_assert(offsetof(AdxsjePredictorFilterState, used) == 0x00, "AdxsjePredictorFilterState::used offset must be 0x00");
static_assert(
  offsetof(AdxsjePredictorFilterState, coefficient0) == 0x04,
  "AdxsjePredictorFilterState::coefficient0 offset must be 0x04"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, coefficient1) == 0x06,
  "AdxsjePredictorFilterState::coefficient1 offset must be 0x06"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, delay0) == 0x08,
  "AdxsjePredictorFilterState::delay0 offset must be 0x08"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, delay1) == 0x0A,
  "AdxsjePredictorFilterState::delay1 offset must be 0x0A"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, blockSampleCount) == 0x14,
  "AdxsjePredictorFilterState::blockSampleCount offset must be 0x14"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, residualSignals) == 0x18,
  "AdxsjePredictorFilterState::residualSignals offset must be 0x18"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, quantizedResidualSignals) == 0x58,
  "AdxsjePredictorFilterState::quantizedResidualSignals offset must be 0x58"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, peakAbsResidual) == 0x78,
  "AdxsjePredictorFilterState::peakAbsResidual offset must be 0x78"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, gainStep) == 0x7C,
  "AdxsjePredictorFilterState::gainStep offset must be 0x7C"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, residualScale) == 0x80,
  "AdxsjePredictorFilterState::residualScale offset must be 0x80"
);
static_assert(
  offsetof(AdxsjePredictorFilterState, iirFilterHandle) == 0x88,
  "AdxsjePredictorFilterState::iirFilterHandle offset must be 0x88"
);
static_assert(sizeof(AdxsjePredictorFilterState) == 0x90, "AdxsjePredictorFilterState size must be 0x90");

constexpr std::int32_t kAdxsjePredictorFilterSlotCount = 16;
constexpr std::size_t kAdxsjeObjectCount = 8;
constexpr std::size_t kAdxsjdObjectCount = 32;
constexpr std::int16_t kAdxsjeVersion = 0x0100;
constexpr const char* kAdxsjeVersionString = "ADXENC.DLL Ver.1.10 Feb 28 2005";

struct XeficCacheBuildSizeContext
{
  std::uint8_t mUnknown00[0x1C]{}; // +0x00
  std::int32_t accumulatedWorkBytes = 0; // +0x1C
  std::uint8_t mUnknown20[0x08]{}; // +0x20
  std::int32_t pathPrefixLength = 0; // +0x28
};

static_assert(
  offsetof(XeficCacheBuildSizeContext, accumulatedWorkBytes) == 0x1C,
  "XeficCacheBuildSizeContext::accumulatedWorkBytes offset must be 0x1C"
);
static_assert(
  offsetof(XeficCacheBuildSizeContext, pathPrefixLength) == 0x28,
  "XeficCacheBuildSizeContext::pathPrefixLength offset must be 0x28"
);
static_assert(sizeof(XeficCacheBuildSizeContext) == 0x2C, "XeficCacheBuildSizeContext size must be 0x2C");

struct XefindFoundFileInfo
{
  const char* path = nullptr; // +0x00
  std::uint32_t fileSizeHigh = 0; // +0x04
  std::uint32_t fileSizeLow = 0; // +0x08
};

static_assert(offsetof(XefindFoundFileInfo, path) == 0x00, "XefindFoundFileInfo::path offset must be 0x00");
static_assert(offsetof(XefindFoundFileInfo, fileSizeHigh) == 0x04, "XefindFoundFileInfo::fileSizeHigh offset must be 0x04");
static_assert(offsetof(XefindFoundFileInfo, fileSizeLow) == 0x08, "XefindFoundFileInfo::fileSizeLow offset must be 0x08");
static_assert(sizeof(XefindFoundFileInfo) == 0x0C, "XefindFoundFileInfo size must be 0x0C");

using XefindVisitCallback = std::int32_t(__cdecl*)(const XefindFoundFileInfo* foundFile, void* callbackContext);
using XeficOpenResultProbeCallback =
  void(__cdecl*)(const char* filePath, std::int32_t fileSizeBytes, HANDLE fileHandle, std::int32_t callbackContext);
using XeficObjectCleanupCallback = void(__cdecl*)(XeficObject* object);

using XeficQueueVisitor = int(__cdecl*)(XeficQueuedFileEntry* queueEntry, std::int32_t contextValue);

struct M2aBitstreamState
{
  std::uint8_t mUnknown00[0x0C]{};
  std::uint32_t bitEndPosition = 0; // +0x0C
  std::uint32_t bitPosition = 0; // +0x10
  std::uint32_t overrunCount = 0; // +0x14
};

static_assert(offsetof(M2aBitstreamState, bitEndPosition) == 0x0C, "M2aBitstreamState::bitEndPosition offset must be 0x0C");
static_assert(offsetof(M2aBitstreamState, bitPosition) == 0x10, "M2aBitstreamState::bitPosition offset must be 0x10");
static_assert(offsetof(M2aBitstreamState, overrunCount) == 0x14, "M2aBitstreamState::overrunCount offset must be 0x14");

struct MparbdDecoderState
{
  std::uint8_t mUnknown00[0x3514]{};
  SofdecAddressWord bitReaderHandlePrimary = 0; // +0x3514
  SofdecAddressWord bitReaderHandleSecondary = 0; // +0x3518
  std::uint8_t mUnknown351C[0x18]{};
  MparbdDecoderState* nextNewer = nullptr; // +0x3534
  MparbdDecoderState* previousOlder = nullptr; // +0x3538
};

static_assert(
  offsetof(MparbdDecoderState, bitReaderHandlePrimary) == 0x3514,
  "MparbdDecoderState::bitReaderHandlePrimary offset must be 0x3514"
);
static_assert(
  offsetof(MparbdDecoderState, bitReaderHandleSecondary) == 0x3518,
  "MparbdDecoderState::bitReaderHandleSecondary offset must be 0x3518"
);
static_assert(
  offsetof(MparbdDecoderState, nextNewer) == 0x3534,
  "MparbdDecoderState::nextNewer offset must be 0x3534"
);
static_assert(
  offsetof(MparbdDecoderState, previousOlder) == 0x3538,
  "MparbdDecoderState::previousOlder offset must be 0x3538"
);
static_assert(sizeof(MparbdDecoderState) == 0x353C, "MparbdDecoderState size must be 0x353C");

struct MparbfBuffer
{
  std::uint8_t* data = nullptr; // +0x00
  std::uint32_t capacityBytes = 0; // +0x04
  std::uint32_t readOffsetBytes = 0; // +0x08
  std::uint32_t dataBytes = 0; // +0x0C
  std::uint32_t writeOffsetBytes = 0; // +0x10
  std::uint32_t freeBytes = 0; // +0x14
};

static_assert(offsetof(MparbfBuffer, data) == 0x00, "MparbfBuffer::data offset must be 0x00");
static_assert(
  offsetof(MparbfBuffer, capacityBytes) == 0x04,
  "MparbfBuffer::capacityBytes offset must be 0x04"
);
static_assert(
  offsetof(MparbfBuffer, readOffsetBytes) == 0x08,
  "MparbfBuffer::readOffsetBytes offset must be 0x08"
);
static_assert(
  offsetof(MparbfBuffer, dataBytes) == 0x0C,
  "MparbfBuffer::dataBytes offset must be 0x0C"
);
static_assert(
  offsetof(MparbfBuffer, writeOffsetBytes) == 0x10,
  "MparbfBuffer::writeOffsetBytes offset must be 0x10"
);
static_assert(
  offsetof(MparbfBuffer, freeBytes) == 0x14,
  "MparbfBuffer::freeBytes offset must be 0x14"
);
static_assert(sizeof(MparbfBuffer) == 0x18, "MparbfBuffer size must be 0x18");

struct SfxaHandle
{
  using LuminanceTableBuilderCallback = std::int32_t(__cdecl*)(std::int32_t laneA, std::int32_t laneB, std::int32_t laneC, SofdecAddressWord laneD);
  using AlphaTableBuilderCallback = std::int32_t(__cdecl*)(SofdecAddressWord destinationAddress, std::int32_t alpha0, std::int32_t alpha1, std::int32_t alpha2);

  std::int32_t used = 0; // +0x00
  std::int32_t needsLumiTableUpdate = 0; // +0x04
  std::int32_t luminancePivot = 0; // +0x08
  std::int32_t luminanceMin = 0; // +0x0C
  std::int32_t luminanceMax = 0; // +0x10
  std::int8_t alpha0 = 0; // +0x14
  std::int8_t alpha1 = 0; // +0x15
  std::int8_t alpha2 = 0; // +0x16
  std::uint8_t mUnknown17 = 0; // +0x17
  LuminanceTableBuilderCallback luminanceBuilder = nullptr; // +0x18
  AlphaTableBuilderCallback alpha3110Builder = nullptr; // +0x1C
  AlphaTableBuilderCallback alpha3211Builder = nullptr; // +0x20
};

static_assert(offsetof(SfxaHandle, used) == 0x00, "SfxaHandle::used offset must be 0x00");
static_assert(
  offsetof(SfxaHandle, needsLumiTableUpdate) == 0x04,
  "SfxaHandle::needsLumiTableUpdate offset must be 0x04"
);
static_assert(offsetof(SfxaHandle, luminancePivot) == 0x08, "SfxaHandle::luminancePivot offset must be 0x08");
static_assert(offsetof(SfxaHandle, luminanceMin) == 0x0C, "SfxaHandle::luminanceMin offset must be 0x0C");
static_assert(offsetof(SfxaHandle, luminanceMax) == 0x10, "SfxaHandle::luminanceMax offset must be 0x10");
static_assert(offsetof(SfxaHandle, alpha0) == 0x14, "SfxaHandle::alpha0 offset must be 0x14");
static_assert(offsetof(SfxaHandle, alpha1) == 0x15, "SfxaHandle::alpha1 offset must be 0x15");
static_assert(offsetof(SfxaHandle, alpha2) == 0x16, "SfxaHandle::alpha2 offset must be 0x16");
static_assert(
  offsetof(SfxaHandle, luminanceBuilder) == 0x18,
  "SfxaHandle::luminanceBuilder offset must be 0x18"
);
static_assert(
  offsetof(SfxaHandle, alpha3110Builder) == 0x1C,
  "SfxaHandle::alpha3110Builder offset must be 0x1C"
);
static_assert(
  offsetof(SfxaHandle, alpha3211Builder) == 0x20,
  "SfxaHandle::alpha3211Builder offset must be 0x20"
);
static_assert(sizeof(SfxaHandle) == 0x24, "SfxaHandle size must be 0x24");

struct SfxaLibWork
{
  std::int32_t cur = 0; // +0x00
  std::int32_t last = 0; // +0x04
  std::array<SfxaHandle, 32> objects{}; // +0x08
};

static_assert(offsetof(SfxaLibWork, cur) == 0x00, "SfxaLibWork::cur offset must be 0x00");
static_assert(offsetof(SfxaLibWork, last) == 0x04, "SfxaLibWork::last offset must be 0x04");
static_assert(offsetof(SfxaLibWork, objects) == 0x08, "SfxaLibWork::objects offset must be 0x08");
static_assert(sizeof(SfxaLibWork) == 0x488, "SfxaLibWork size must be 0x488");

struct SfbufInitLayoutConfig
{
  std::int32_t mUnknown00 = 0; // +0x00
  SofdecAddressWord baseBufferAddress = 0; // +0x04
  std::array<std::int32_t, 8> laneBufferSizes{}; // +0x08
  std::int32_t lane0ExtraModuloDivisor = 0; // +0x28
};

static_assert(
  offsetof(SfbufInitLayoutConfig, baseBufferAddress) == 0x04,
  "SfbufInitLayoutConfig::baseBufferAddress offset must be 0x04"
);
static_assert(
  offsetof(SfbufInitLayoutConfig, laneBufferSizes) == 0x08,
  "SfbufInitLayoutConfig::laneBufferSizes offset must be 0x08"
);
static_assert(
  offsetof(SfbufInitLayoutConfig, lane0ExtraModuloDivisor) == 0x28,
  "SfbufInitLayoutConfig::lane0ExtraModuloDivisor offset must be 0x28"
);
static_assert(sizeof(SfbufInitLayoutConfig) == 0x2C, "SfbufInitLayoutConfig size must be 0x2C");

struct SfbufSjCreateState
{
  SofdecAddressWord ownerTag = 0; // +0x00
  moho::SofdecSjRingBufferHandle* sjHandle = nullptr; // +0x04
  SofdecAddressWord sourceBufferAddress = 0; // +0x08
  SofdecAddressWord sourceBufferBytes = 0; // +0x0C
  SofdecAddressWord extraBufferBytes = 0; // +0x10
  SofdecAddressWord mUnknown14 = 0; // +0x14
};

static_assert(offsetof(SfbufSjCreateState, sjHandle) == 0x04, "SfbufSjCreateState::sjHandle offset must be 0x04");
static_assert(
  offsetof(SfbufSjCreateState, sourceBufferAddress) == 0x08,
  "SfbufSjCreateState::sourceBufferAddress offset must be 0x08"
);
static_assert(
  offsetof(SfbufSjCreateState, sourceBufferBytes) == 0x0C,
  "SfbufSjCreateState::sourceBufferBytes offset must be 0x0C"
);
static_assert(
  offsetof(SfbufSjCreateState, extraBufferBytes) == 0x10,
  "SfbufSjCreateState::extraBufferBytes offset must be 0x10"
);
static_assert(sizeof(SfbufSjCreateState) == 0x18, "SfbufSjCreateState size must be 0x18");


struct SfbufUochDescriptor
{
  SofdecAddressWord word0 = 0; // +0x00
  SofdecAddressWord word1 = 0; // +0x04
  SofdecAddressWord word2 = 0; // +0x08
  SofdecAddressWord word3 = 0; // +0x0C
};

static_assert(offsetof(SfbufUochDescriptor, word0) == 0x00, "SfbufUochDescriptor::word0 offset must be 0x00");
static_assert(offsetof(SfbufUochDescriptor, word1) == 0x04, "SfbufUochDescriptor::word1 offset must be 0x04");
static_assert(offsetof(SfbufUochDescriptor, word2) == 0x08, "SfbufUochDescriptor::word2 offset must be 0x08");
static_assert(offsetof(SfbufUochDescriptor, word3) == 0x0C, "SfbufUochDescriptor::word3 offset must be 0x0C");
static_assert(sizeof(SfbufUochDescriptor) == 0x10, "SfbufUochDescriptor size must be 0x10");

struct SfbufRingCursorSnapshot
{
  moho::SjChunkRange firstChunk{}; // +0x00
  moho::SjChunkRange secondChunk{}; // +0x08
  std::array<std::int32_t, 3> reservedWords{}; // +0x10
};

static_assert(
  offsetof(SfbufRingCursorSnapshot, firstChunk) == 0x00,
  "SfbufRingCursorSnapshot::firstChunk offset must be 0x00"
);
static_assert(
  offsetof(SfbufRingCursorSnapshot, secondChunk) == 0x08,
  "SfbufRingCursorSnapshot::secondChunk offset must be 0x08"
);
static_assert(
  offsetof(SfbufRingCursorSnapshot, reservedWords) == 0x10,
  "SfbufRingCursorSnapshot::reservedWords offset must be 0x10"
);
static_assert(sizeof(SfbufRingCursorSnapshot) == 0x1C, "SfbufRingCursorSnapshot size must be 0x1C");

struct SfbufSupplyStateWindow
{
  SofdecAddressWord sourceBufferAddress = 0; // +0x00
  SofdecAddressWord ringHandleAddress = 0; // +0x04
  SofdecAddressWord ownerLaneAddress = 0; // +0x08
  SofdecAddressWord queuedDataBytes = 0; // +0x0C
  SofdecAddressWord laneParam20 = 0; // +0x10
  SofdecAddressWord laneParam24 = 0; // +0x14
  SofdecAddressWord delimiterPrimaryAddress = 0; // +0x18
  SofdecAddressWord delimiterSecondaryAddress = 0; // +0x1C
};

static_assert(
  offsetof(SfbufSupplyStateWindow, ringHandleAddress) == 0x04,
  "SfbufSupplyStateWindow::ringHandleAddress offset must be 0x04"
);
static_assert(
  offsetof(SfbufSupplyStateWindow, delimiterPrimaryAddress) == 0x18,
  "SfbufSupplyStateWindow::delimiterPrimaryAddress offset must be 0x18"
);
static_assert(
  offsetof(SfbufSupplyStateWindow, delimiterSecondaryAddress) == 0x1C,
  "SfbufSupplyStateWindow::delimiterSecondaryAddress offset must be 0x1C"
);
static_assert(sizeof(SfbufSupplyStateWindow) == 0x20, "SfbufSupplyStateWindow size must be 0x20");


struct SfbufAringLaneState
{
  SofdecAddressWord transferParam0 = 0; // +0x00
  SofdecAddressWord sampleMode = 0; // +0x04
  SofdecAddressWord transferParam2 = 0; // +0x08
  SofdecAddressWord primarySampleBaseAddress = 0; // +0x0C
  SofdecAddressWord secondarySampleBaseAddress = 0; // +0x10
  SofdecAddressWord ringCapacitySamples = 0; // +0x14
  SofdecAddressWord writeCursorSamples = 0; // +0x18
  SofdecAddressWord readCursorSamples = 0; // +0x1C
  SofdecAddressWord writeTotalSamples = 0; // +0x20
  SofdecAddressWord readTotalSamples = 0; // +0x24
  SofdecAddressWord mUnknown28 = 0; // +0x28
  SofdecAddressWord mUnknown2C = 0; // +0x2C
  SofdecAddressWord mUnknown30 = 0; // +0x30
  SofdecAddressWord transferHandleAddress = 0; // +0x34
};

static_assert(
  offsetof(SfbufAringLaneState, transferParam0) == 0x00,
  "SfbufAringLaneState::transferParam0 offset must be 0x00"
);
static_assert(
  offsetof(SfbufAringLaneState, sampleMode) == 0x04,
  "SfbufAringLaneState::sampleMode offset must be 0x04"
);
static_assert(
  offsetof(SfbufAringLaneState, transferParam2) == 0x08,
  "SfbufAringLaneState::transferParam2 offset must be 0x08"
);
static_assert(
  offsetof(SfbufAringLaneState, primarySampleBaseAddress) == 0x0C,
  "SfbufAringLaneState::primarySampleBaseAddress offset must be 0x0C"
);
static_assert(
  offsetof(SfbufAringLaneState, secondarySampleBaseAddress) == 0x10,
  "SfbufAringLaneState::secondarySampleBaseAddress offset must be 0x10"
);
static_assert(
  offsetof(SfbufAringLaneState, ringCapacitySamples) == 0x14,
  "SfbufAringLaneState::ringCapacitySamples offset must be 0x14"
);
static_assert(
  offsetof(SfbufAringLaneState, writeCursorSamples) == 0x18,
  "SfbufAringLaneState::writeCursorSamples offset must be 0x18"
);
static_assert(
  offsetof(SfbufAringLaneState, readCursorSamples) == 0x1C,
  "SfbufAringLaneState::readCursorSamples offset must be 0x1C"
);
static_assert(
  offsetof(SfbufAringLaneState, writeTotalSamples) == 0x20,
  "SfbufAringLaneState::writeTotalSamples offset must be 0x20"
);
static_assert(
  offsetof(SfbufAringLaneState, readTotalSamples) == 0x24,
  "SfbufAringLaneState::readTotalSamples offset must be 0x24"
);
static_assert(
  offsetof(SfbufAringLaneState, transferHandleAddress) == 0x34,
  "SfbufAringLaneState::transferHandleAddress offset must be 0x34"
);
static_assert(sizeof(SfbufAringLaneState) == 0x38, "SfbufAringLaneState size must be 0x38");

struct SfbufAringTransferSnapshot
{
  std::int32_t transferParam0 = 0; // +0x00
  std::int32_t sampleMode = 0; // +0x04
  std::int32_t transferParam2 = 0; // +0x08
  std::int32_t chunkSampleCount = 0; // +0x0C
  std::int32_t wrapCursorSample = 0; // +0x10
  SofdecAddressWord primaryChunkAddress = 0; // +0x14
  SofdecAddressWord secondaryChunkAddress = 0; // +0x18
  SofdecAddressWord primaryWrapAddress = 0; // +0x1C
  SofdecAddressWord secondaryWrapAddress = 0; // +0x20
  std::int32_t writeTotalSamples = 0; // +0x24
  std::int32_t readTotalSamples = 0; // +0x28
};

static_assert(
  offsetof(SfbufAringTransferSnapshot, transferParam0) == 0x00,
  "SfbufAringTransferSnapshot::transferParam0 offset must be 0x00"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, sampleMode) == 0x04,
  "SfbufAringTransferSnapshot::sampleMode offset must be 0x04"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, transferParam2) == 0x08,
  "SfbufAringTransferSnapshot::transferParam2 offset must be 0x08"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, chunkSampleCount) == 0x0C,
  "SfbufAringTransferSnapshot::chunkSampleCount offset must be 0x0C"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, primaryChunkAddress) == 0x14,
  "SfbufAringTransferSnapshot::primaryChunkAddress offset must be 0x14"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, secondaryChunkAddress) == 0x18,
  "SfbufAringTransferSnapshot::secondaryChunkAddress offset must be 0x18"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, writeTotalSamples) == 0x24,
  "SfbufAringTransferSnapshot::writeTotalSamples offset must be 0x24"
);
static_assert(
  offsetof(SfbufAringTransferSnapshot, readTotalSamples) == 0x28,
  "SfbufAringTransferSnapshot::readTotalSamples offset must be 0x28"
);
static_assert(sizeof(SfbufAringTransferSnapshot) == 0x2C, "SfbufAringTransferSnapshot size must be 0x2C");


/**
 * Per-stream entry point of a transfer strategy.
 *
 * The eight strategy descriptors in the binary are plain C tables whose slots
 * hold functions with per-family signatures - `SFMEM_GetWrite` takes an out
 * cursor where `SFVOM_GetWrite` does not, `SFUO_Create` takes a handle where
 * `SFMEM_Create` takes none. The original C source therefore declared one
 * generic pointer type for those slots; only the lifecycle pair below is
 * uniform across every family.
 */
using SftrnEntryCallback =
  std::int32_t(__cdecl*)(std::int32_t arg0, std::int32_t arg1, std::int32_t arg2, std::int32_t arg3);

/** Init/Finish are `Sint32 (*)(void)` in all eight strategies. */
using SftrnLifecycleCallback = std::int32_t(__cdecl*)();

/**
 * One SFD transfer strategy (SFMEM / SFMPS / SFMPV / SFVOM / SFM2TS / SFADXT /
 * SFAOAP / SFUO).
 *
 * Evidence: the eight descriptor blocks at 0x00D7F49C, 0x00D7F4D4, 0x00D7F50C,
 * 0x00D7F544, 0x00D7F57C, 0x00D7F5D4, 0x00D7F670 and 0x00D7F6B8 are spaced
 * 0x38 apart, and the IDA symbol at every one of the 14 slots agrees on the
 * slot role across all eight families (`_SF*_Init`, `_SF*_Finish`,
 * `_SF*_ExecServer`, ... `_SF*_Seek`).
 */
struct SofdecTransferStrategy
{
  SftrnLifecycleCallback init = nullptr; // +0x00
  SftrnLifecycleCallback finish = nullptr; // +0x04
  SftrnEntryCallback execServer = nullptr; // +0x08
  SftrnEntryCallback create = nullptr; // +0x0C
  SftrnEntryCallback destroy = nullptr; // +0x10
  SftrnEntryCallback requestStop = nullptr; // +0x14
  SftrnEntryCallback start = nullptr; // +0x18
  SftrnEntryCallback stop = nullptr; // +0x1C
  SftrnEntryCallback pause = nullptr; // +0x20
  SftrnEntryCallback getWrite = nullptr; // +0x24
  SftrnEntryCallback addWrite = nullptr; // +0x28
  SftrnEntryCallback getRead = nullptr; // +0x2C
  SftrnEntryCallback addRead = nullptr; // +0x30
  SftrnEntryCallback seek = nullptr; // +0x34
};

static_assert(offsetof(SofdecTransferStrategy, execServer) == 0x08, "SofdecTransferStrategy::execServer offset must be 0x08");
static_assert(offsetof(SofdecTransferStrategy, seek) == 0x34, "SofdecTransferStrategy::seek offset must be 0x34");
static_assert(sizeof(SofdecTransferStrategy) == 0x38, "SofdecTransferStrategy size must be 0x38");

/**
 * Null-terminated strategy list copied wholesale by `SFTRN_Init`.
 *
 * Evidence: the list head sits at 0x00D7F3D0 and is exactly 0x3C bytes - the
 * next static, `mwsfd_initsfdpara`, begins at 0x00D7F40C and its `callbacks`
 * field points back at 0x00D7F3D0.
 */
struct SftrnEntryList
{
  std::array<SofdecTransferStrategy*, 15> entries{};
};

static_assert(sizeof(SftrnEntryList) == 0x3C, "SftrnEntryList size must be 0x3C");


/// The create template's transfer-strategy table: one strategy pointer per
/// lane, tested for presence. Word-sized so it indexes like the table it is.
struct SftrnBuildConfig
{
  SofdecAddressWord mUnknown00 = 0; // +0x00
  SofdecAddressWord hasSystemLane = 0; // +0x04
  SofdecAddressWord hasAudioLane = 0; // +0x08
  SofdecAddressWord hasVideoLane = 0; // +0x0C
  SofdecAddressWord hasAudioExtendedLane = 0; // +0x10
  SofdecAddressWord hasVideoExtendedLane = 0; // +0x14
  std::array<SofdecAddressWord, 2> mUnknown18{}; // +0x18
  SofdecAddressWord hasUserLane = 0; // +0x20
};

static_assert(offsetof(SftrnBuildConfig, hasSystemLane) == 0x04, "SftrnBuildConfig::hasSystemLane offset must be 0x04");
static_assert(offsetof(SftrnBuildConfig, hasAudioLane) == 0x08, "SftrnBuildConfig::hasAudioLane offset must be 0x08");
static_assert(offsetof(SftrnBuildConfig, hasVideoLane) == 0x0C, "SftrnBuildConfig::hasVideoLane offset must be 0x0C");
static_assert(
  offsetof(SftrnBuildConfig, hasAudioExtendedLane) == 0x10,
  "SftrnBuildConfig::hasAudioExtendedLane offset must be 0x10"
);
static_assert(
  offsetof(SftrnBuildConfig, hasVideoExtendedLane) == 0x14,
  "SftrnBuildConfig::hasVideoExtendedLane offset must be 0x14"
);
static_assert(offsetof(SftrnBuildConfig, hasUserLane) == 0x20, "SftrnBuildConfig::hasUserLane offset must be 0x20");

using SfplyPictureCountCallback =
  std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t callbackContext, moho::SfplyPictureCount* pictureCounts);






/// The SFBUF lane SFPLY's readiness checks query (`workctrl + 0x1320 + lane * 0x74`
/// in the binary: the lane's join handle and ring window span).
[[nodiscard]] static const moho::SfbufLane*
SfplyGetDataLaneDescriptor(const moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t laneIndex)
{
  return &workctrlSubobj->bufferState.lanes[static_cast<std::size_t>(laneIndex)];
}

[[nodiscard]] static std::int32_t SfplyQueryLaneReadyBytes(const moho::SfbufLane* const lane)
{
  auto* const sj = reinterpret_cast<moho::SofdecSjSupplyHandle*>(lane->supplyJoinAddress);
  return sj->dispatchTable->queryAvailableBytes(sj, 1);
}

static bool SfbufContainsAddress(const moho::SjChunkRange& chunkRange, const SofdecAddressWord candidateAddress)
{
  const SofdecAddressWord chunkStart = static_cast<SofdecAddressWord>(chunkRange.bufferAddress);
  const SofdecAddressWord chunkEnd = chunkStart + chunkRange.byteCount;
  return (candidateAddress >= chunkStart) && (candidateAddress < chunkEnd);
}

static std::int32_t SfbufAringScaledAddress(
  const std::int32_t sampleMode,
  const SofdecAddressWord baseAddress,
  const std::int32_t sampleOffset
)
{
  if (sampleMode > 8) {
    return baseAddress + (sampleOffset * 2);
  }
  return baseAddress + sampleOffset;
}

using MparbdErrorCallback = std::int32_t(__cdecl*)(const char* functionName, std::int32_t sourceLine, const char* message, std::int32_t callbackContext);
using MparbdUserMallocCallback = std::int32_t(__cdecl*)(std::int32_t allocationBytes, void** outPointer);
using MparbdUserFreeCallback = void(__cdecl*)(void** pointerAddress);
struct M2asjdIoStream
{
  virtual void Reserved00() = 0;
  virtual void Reserved04() = 0;
  virtual void Reserved08() = 0;
  /**
   * Slot 3 (+0x0C) - tears the stream joint down.
   *
   * Evidence: the M2A decoder teardown in `SofdecAdxXeficRuntime.cpp` calls
   * this slot with no arguments beyond the object, on the failure path next to
   * `HEAPMNG_Destroy` and again when releasing `stagingStream`.
   */
  virtual void Destroy() = 0;
  virtual void Reserved10() = 0;
  virtual void Reset() = 0;
  virtual void AcquireChunk(std::int32_t lane, std::int32_t requestedBytes, SjChunkRange* outChunk) = 0;
  virtual void ReturnChunk(std::int32_t lane, const SjChunkRange* chunk) = 0;
  virtual void CommitChunk(std::int32_t lane, const SjChunkRange* chunk) = 0;
  virtual std::int32_t QueryAvailableBytes(std::int32_t lane) = 0;
};

struct AdxampState
{
  std::uint8_t used = 0; // +0x00
  std::uint8_t executionState = 0; // +0x01
  std::int8_t outputChannelCount = 0; // +0x02
  std::uint8_t mUnknown03 = 0; // +0x03
  M2asjdIoStream* inputStreams[2]{}; // +0x04
  M2asjdIoStream* outputStreams[2]{}; // +0x0C
  std::int32_t extractedSamplesByLane[2]{}; // +0x14
  std::int32_t activeLaneCount = 0; // +0x1C
  std::int32_t sampleRate = 0; // +0x20
  float frameLength = 0.0f; // +0x24
  float framePeriod = 0.0f; // +0x28
  std::int32_t extractIterationCount = 0; // +0x2C
};

static_assert(offsetof(AdxampState, used) == 0x00, "AdxampState::used offset must be 0x00");
static_assert(
  offsetof(AdxampState, executionState) == 0x01, "AdxampState::executionState offset must be 0x01"
);
static_assert(
  offsetof(AdxampState, outputChannelCount) == 0x02,
  "AdxampState::outputChannelCount offset must be 0x02"
);
static_assert(
  offsetof(AdxampState, inputStreams) == 0x04, "AdxampState::inputStreams offset must be 0x04"
);
static_assert(
  offsetof(AdxampState, outputStreams) == 0x0C, "AdxampState::outputStreams offset must be 0x0C"
);
static_assert(
  offsetof(AdxampState, extractedSamplesByLane) == 0x14,
  "AdxampState::extractedSamplesByLane offset must be 0x14"
);
static_assert(
  offsetof(AdxampState, activeLaneCount) == 0x1C, "AdxampState::activeLaneCount offset must be 0x1C"
);
static_assert(
  offsetof(AdxampState, sampleRate) == 0x20, "AdxampState::sampleRate offset must be 0x20"
);
static_assert(
  offsetof(AdxampState, frameLength) == 0x24, "AdxampState::frameLength offset must be 0x24"
);
static_assert(
  offsetof(AdxampState, framePeriod) == 0x28, "AdxampState::framePeriod offset must be 0x28"
);
static_assert(
  offsetof(AdxampState, extractIterationCount) == 0x2C,
  "AdxampState::extractIterationCount offset must be 0x2C"
);
static_assert(sizeof(AdxampState) == 0x30, "AdxampState size must be 0x30");

struct M2asjdDecoderState
{
  std::int32_t slotState = 0; // +0x00
  std::int32_t runState = 0; // +0x04
  void* heapManagerHandle = nullptr; // +0x08
  std::int32_t heapManagerOwner = 0; // +0x0C
  std::int32_t ioContextValue = 0; // +0x10
  M2aDecoderContext* decoderContext = nullptr; // +0x14
  M2asjdIoStream* sourceStream = nullptr; // +0x18
  M2asjdIoStream* outputStreams[6]{}; // +0x1C
  M2asjdIoStream* stagingStream = nullptr; // +0x34
  std::uint8_t* stagingBuffer = nullptr; // +0x38
  std::int32_t decodedByteCount = 0; // +0x3C
  std::int32_t decodedSampleCount = 0; // +0x40
  std::int32_t lastOutputFrameCount = 0; // +0x44
  std::int32_t downmixMode = 0; // +0x48
  std::int32_t termSupplyFlag = 0; // +0x4C
  M2asjdDecoderState* nextNewer = nullptr; // +0x50
  M2asjdDecoderState* nextOlder = nullptr; // +0x54
};

static_assert(offsetof(M2asjdDecoderState, runState) == 0x04, "M2asjdDecoderState::runState offset must be 0x04");
static_assert(
  offsetof(M2asjdDecoderState, decoderContext) == 0x14, "M2asjdDecoderState::decoderContext offset must be 0x14"
);
static_assert(offsetof(M2asjdDecoderState, sourceStream) == 0x18, "M2asjdDecoderState::sourceStream offset must be 0x18");
static_assert(
  offsetof(M2asjdDecoderState, outputStreams) == 0x1C, "M2asjdDecoderState::outputStreams offset must be 0x1C"
);
static_assert(
  offsetof(M2asjdDecoderState, stagingStream) == 0x34, "M2asjdDecoderState::stagingStream offset must be 0x34"
);
static_assert(
  offsetof(M2asjdDecoderState, decodedByteCount) == 0x3C, "M2asjdDecoderState::decodedByteCount offset must be 0x3C"
);
static_assert(
  offsetof(M2asjdDecoderState, decodedSampleCount) == 0x40, "M2asjdDecoderState::decodedSampleCount offset must be 0x40"
);
static_assert(
  offsetof(M2asjdDecoderState, lastOutputFrameCount) == 0x44,
  "M2asjdDecoderState::lastOutputFrameCount offset must be 0x44"
);
static_assert(
  offsetof(M2asjdDecoderState, downmixMode) == 0x48, "M2asjdDecoderState::downmixMode offset must be 0x48"
);
static_assert(
  offsetof(M2asjdDecoderState, termSupplyFlag) == 0x4C, "M2asjdDecoderState::termSupplyFlag offset must be 0x4C"
);
static_assert(offsetof(M2asjdDecoderState, nextNewer) == 0x50, "M2asjdDecoderState::nextNewer offset must be 0x50");
static_assert(offsetof(M2asjdDecoderState, nextOlder) == 0x54, "M2asjdDecoderState::nextOlder offset must be 0x54");
static_assert(sizeof(M2asjdDecoderState) == 0x58, "M2asjdDecoderState size must be 0x58");

struct MpasjdDecoderState
{
  std::int32_t slotState = 0; // +0x00
  std::int32_t runState = 0; // +0x04
  void* heapManagerHandle = nullptr; // +0x08
  std::int32_t heapManagerOwner = 0; // +0x0C
  MparbdDecoderState* decoderContext = nullptr; // +0x10
  std::int8_t* interleaveBuffer = nullptr; // +0x14
  M2asjdIoStream* sourceStream = nullptr; // +0x18
  M2asjdIoStream* outputStreams[2]{}; // +0x1C
  std::int32_t decodedByteCount = 0; // +0x24
  std::int32_t decodedSampleCount = 0; // +0x28
  std::int32_t termSupplyFlag = 0; // +0x2C
  MpasjdDecoderState* nextNewer = nullptr; // +0x30
  MpasjdDecoderState* nextOlder = nullptr; // +0x34
};

static_assert(
  offsetof(MpasjdDecoderState, decoderContext) == 0x10,
  "MpasjdDecoderState::decoderContext offset must be 0x10"
);
static_assert(
  offsetof(MpasjdDecoderState, sourceStream) == 0x18,
  "MpasjdDecoderState::sourceStream offset must be 0x18"
);
static_assert(
  offsetof(MpasjdDecoderState, outputStreams) == 0x1C,
  "MpasjdDecoderState::outputStreams offset must be 0x1C"
);
static_assert(
  offsetof(MpasjdDecoderState, decodedByteCount) == 0x24,
  "MpasjdDecoderState::decodedByteCount offset must be 0x24"
);
static_assert(
  offsetof(MpasjdDecoderState, decodedSampleCount) == 0x28,
  "MpasjdDecoderState::decodedSampleCount offset must be 0x28"
);
static_assert(
  offsetof(MpasjdDecoderState, termSupplyFlag) == 0x2C,
  "MpasjdDecoderState::termSupplyFlag offset must be 0x2C"
);
static_assert(
  offsetof(MpasjdDecoderState, nextNewer) == 0x30,
  "MpasjdDecoderState::nextNewer offset must be 0x30"
);
static_assert(
  offsetof(MpasjdDecoderState, nextOlder) == 0x34,
  "MpasjdDecoderState::nextOlder offset must be 0x34"
);
static_assert(sizeof(MpasjdDecoderState) == 0x38, "MpasjdDecoderState size must be 0x38");

using M2asjdErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* errorMessage);
using M2asjdDecodeCallback =
  std::int32_t(__cdecl*)(std::int32_t callbackObject, M2asjdDecoderState* decoder, std::int32_t callbackContext, std::int32_t producedBytes);
using MpasjdDecodeCallback =
  std::int32_t(__cdecl*)(std::int32_t callbackObject, MpasjdDecoderState* decoder, std::int32_t consumedBytes, std::int32_t producedBytes);

struct MwsfdRawPlaybackInfo
{
  std::uint8_t mUnknown00[0x04]{};
  std::int32_t dropFrameAccumulator = 0; // +0x04
  std::uint8_t mUnknown08[0x08]{};
  std::int32_t skipEmptyBFrameCount = 0; // +0x10
  std::uint8_t mUnknown14[0x10]{};
  std::int32_t noSupplyFrameCount = 0; // +0x24
  std::uint8_t mUnknown28[0x80]{};
};

static_assert(
  offsetof(MwsfdRawPlaybackInfo, dropFrameAccumulator) == 0x04,
  "MwsfdRawPlaybackInfo::dropFrameAccumulator offset must be 0x04"
);
static_assert(
  offsetof(MwsfdRawPlaybackInfo, skipEmptyBFrameCount) == 0x10,
  "MwsfdRawPlaybackInfo::skipEmptyBFrameCount offset must be 0x10"
);
static_assert(
  offsetof(MwsfdRawPlaybackInfo, noSupplyFrameCount) == 0x24,
  "MwsfdRawPlaybackInfo::noSupplyFrameCount offset must be 0x24"
);
static_assert(sizeof(MwsfdRawPlaybackInfo) == 0xA8, "MwsfdRawPlaybackInfo size must be 0xA8");

struct MwsfdRawTimerInfo
{
  std::uint8_t mUnknown00[0xDC]{};
  std::int32_t timerEndSample = 0; // +0xDC
};

static_assert(offsetof(MwsfdRawTimerInfo, timerEndSample) == 0xDC, "MwsfdRawTimerInfo::timerEndSample offset must be 0xDC");
static_assert(sizeof(MwsfdRawTimerInfo) == 0xE0, "MwsfdRawTimerInfo size must be 0xE0");

struct MwsfdPlaybackInfoSummary
{
  std::int32_t dropFrameCount = 0; // +0x00
  std::int32_t skipDecodeCount = 0; // +0x04
  std::int32_t skipDisplayCount = 0; // +0x08
  std::int32_t skipEmptyBCount = 0; // +0x0C
  std::int32_t noSupplyCount = 0; // +0x10
  std::int32_t timerSample = 0; // +0x14
};

static_assert(offsetof(MwsfdPlaybackInfoSummary, dropFrameCount) == 0x00, "MwsfdPlaybackInfoSummary::dropFrameCount offset must be 0x00");
static_assert(
  offsetof(MwsfdPlaybackInfoSummary, skipDecodeCount) == 0x04,
  "MwsfdPlaybackInfoSummary::skipDecodeCount offset must be 0x04"
);
static_assert(
  offsetof(MwsfdPlaybackInfoSummary, skipDisplayCount) == 0x08,
  "MwsfdPlaybackInfoSummary::skipDisplayCount offset must be 0x08"
);
static_assert(offsetof(MwsfdPlaybackInfoSummary, skipEmptyBCount) == 0x0C, "MwsfdPlaybackInfoSummary::skipEmptyBCount offset must be 0x0C");
static_assert(offsetof(MwsfdPlaybackInfoSummary, noSupplyCount) == 0x10, "MwsfdPlaybackInfoSummary::noSupplyCount offset must be 0x10");
static_assert(offsetof(MwsfdPlaybackInfoSummary, timerSample) == 0x14, "MwsfdPlaybackInfoSummary::timerSample offset must be 0x14");
static_assert(sizeof(MwsfdPlaybackInfoSummary) == 0x18, "MwsfdPlaybackInfoSummary size must be 0x18");

using CvFsUserErrorBridgeFn = void(__cdecl*)(SofdecAddressWord errorObjectAddress, const char* message);
using CvFsRegisterUserErrorFn = void(__cdecl*)(CvFsUserErrorBridgeFn bridgeCallback, SofdecAddressWord errorObjectAddress);
using CvFsDeviceOpenFn = std::int32_t(__cdecl*)(char* fileName, std::int32_t openMode, std::int32_t openFlags);
using CvFsCloseBridgeFn = void(__cdecl*)(SofdecAddressWord handleAddress);
using CvFsSeekBridgeFn = std::int32_t(__cdecl*)(SofdecAddressWord handleAddress, std::int32_t seekOffset, std::int32_t seekOrigin);
using CvFsGetStatBridgeFn = std::int32_t(__cdecl*)(SofdecAddressWord handleAddress);
using CvFsNoArgOperationFn = std::int32_t(__cdecl*)();
using CvFsHandleOperationFn = std::int32_t(__cdecl*)(SofdecAddressWord handleAddress);
using CvFsHandleReadWriteFn = std::int32_t(__cdecl*)(SofdecAddressWord handleAddress, SofdecAddressWord bufferAddress, std::int32_t byteCount);
using CvFsGetMaxByteRateFn = std::int32_t(__cdecl*)(SofdecAddressWord handleAddress);
using CvFsPathOperationFn = std::int32_t(__cdecl*)(char* filePath);
using CvFsPathArgOperationFn = std::int32_t(__cdecl*)(char* filePath, std::int32_t optionArg);
using CvFsLoadDirInfoFn = std::int32_t(__cdecl*)(char* fileName, std::int32_t optionArg0, std::int32_t optionArg1);
using CvFsDeviceOptionFn = std::int32_t(
  __cdecl*
)(void* optionBuffer, std::int32_t optionCode, std::int32_t optionArg0, std::int32_t optionArg1);

struct CvFsDeviceInterface
{
  CvFsNoArgOperationFn execServer = nullptr; // +0x00
  CvFsRegisterUserErrorFn registerUserErrorBridge = nullptr; // +0x04
  CvFsPathOperationFn getFileSize = nullptr; // +0x08
  CvFsNoArgOperationFn getFreeSize = nullptr; // +0x0C
  CvFsDeviceOpenFn openFile = nullptr; // +0x10
  CvFsCloseBridgeFn closeFile = nullptr; // +0x14
  CvFsSeekBridgeFn seekFile = nullptr; // +0x18
  CvFsHandleOperationFn tellPosition = nullptr; // +0x1C
  CvFsHandleReadWriteFn requestRead = nullptr; // +0x20
  CvFsHandleReadWriteFn requestWrite = nullptr; // +0x24
  CvFsHandleOperationFn stopTransfer = nullptr; // +0x28
  CvFsGetStatBridgeFn getStat = nullptr; // +0x2C
  CvFsHandleOperationFn getSectorLength = nullptr; // +0x30
  CvFsHandleOperationFn setSectorLength = nullptr; // +0x34
  CvFsHandleOperationFn getTransferCount = nullptr; // +0x38
  CvFsPathOperationFn changeDir = nullptr; // +0x3C
  CvFsPathOperationFn isFileExists = nullptr; // +0x40
  CvFsNoArgOperationFn getNumFiles = nullptr; // +0x44
  CvFsLoadDirInfoFn loadDirInfo = nullptr; // +0x48
  CvFsGetMaxByteRateFn getMaxByteRate = nullptr; // +0x4C
  CvFsPathOperationFn makeDir = nullptr; // +0x50
  CvFsPathOperationFn removeDir = nullptr; // +0x54
  CvFsPathOperationFn deleteFile = nullptr; // +0x58
  CvFsPathArgOperationFn getFileSizeEx = nullptr; // +0x5C
  CvFsDeviceOptionFn option = nullptr; // +0x60
  CvFsDeviceOptionFn option2 = nullptr; // +0x64
};

static_assert(
  offsetof(CvFsDeviceInterface, execServer) == 0x00,
  "CvFsDeviceInterface::execServer offset must be 0x00"
);
static_assert(
  offsetof(CvFsDeviceInterface, registerUserErrorBridge) == 0x04,
  "CvFsDeviceInterface::registerUserErrorBridge offset must be 0x04"
);
static_assert(offsetof(CvFsDeviceInterface, getFileSize) == 0x08, "CvFsDeviceInterface::getFileSize offset must be 0x08");
static_assert(offsetof(CvFsDeviceInterface, getFreeSize) == 0x0C, "CvFsDeviceInterface::getFreeSize offset must be 0x0C");
static_assert(offsetof(CvFsDeviceInterface, openFile) == 0x10, "CvFsDeviceInterface::openFile offset must be 0x10");
static_assert(
  offsetof(CvFsDeviceInterface, closeFile) == 0x14, "CvFsDeviceInterface::closeFile offset must be 0x14"
);
static_assert(offsetof(CvFsDeviceInterface, seekFile) == 0x18, "CvFsDeviceInterface::seekFile offset must be 0x18");
static_assert(offsetof(CvFsDeviceInterface, tellPosition) == 0x1C, "CvFsDeviceInterface::tellPosition offset must be 0x1C");
static_assert(offsetof(CvFsDeviceInterface, requestRead) == 0x20, "CvFsDeviceInterface::requestRead offset must be 0x20");
static_assert(offsetof(CvFsDeviceInterface, requestWrite) == 0x24, "CvFsDeviceInterface::requestWrite offset must be 0x24");
static_assert(offsetof(CvFsDeviceInterface, stopTransfer) == 0x28, "CvFsDeviceInterface::stopTransfer offset must be 0x28");
static_assert(offsetof(CvFsDeviceInterface, getStat) == 0x2C, "CvFsDeviceInterface::getStat offset must be 0x2C");
static_assert(offsetof(CvFsDeviceInterface, getSectorLength) == 0x30, "CvFsDeviceInterface::getSectorLength offset must be 0x30");
static_assert(offsetof(CvFsDeviceInterface, setSectorLength) == 0x34, "CvFsDeviceInterface::setSectorLength offset must be 0x34");
static_assert(offsetof(CvFsDeviceInterface, getTransferCount) == 0x38, "CvFsDeviceInterface::getTransferCount offset must be 0x38");
static_assert(offsetof(CvFsDeviceInterface, changeDir) == 0x3C, "CvFsDeviceInterface::changeDir offset must be 0x3C");
static_assert(offsetof(CvFsDeviceInterface, isFileExists) == 0x40, "CvFsDeviceInterface::isFileExists offset must be 0x40");
static_assert(offsetof(CvFsDeviceInterface, getNumFiles) == 0x44, "CvFsDeviceInterface::getNumFiles offset must be 0x44");
static_assert(offsetof(CvFsDeviceInterface, loadDirInfo) == 0x48, "CvFsDeviceInterface::loadDirInfo offset must be 0x48");
static_assert(
  offsetof(CvFsDeviceInterface, getMaxByteRate) == 0x4C,
  "CvFsDeviceInterface::getMaxByteRate offset must be 0x4C"
);
static_assert(offsetof(CvFsDeviceInterface, makeDir) == 0x50, "CvFsDeviceInterface::makeDir offset must be 0x50");
static_assert(
  offsetof(CvFsDeviceInterface, removeDir) == 0x54,
  "CvFsDeviceInterface::removeDir offset must be 0x54"
);
static_assert(
  offsetof(CvFsDeviceInterface, deleteFile) == 0x58,
  "CvFsDeviceInterface::deleteFile offset must be 0x58"
);
static_assert(offsetof(CvFsDeviceInterface, getFileSizeEx) == 0x5C, "CvFsDeviceInterface::getFileSizeEx offset must be 0x5C");
static_assert(offsetof(CvFsDeviceInterface, option) == 0x60, "CvFsDeviceInterface::option offset must be 0x60");
static_assert(offsetof(CvFsDeviceInterface, option2) == 0x64, "CvFsDeviceInterface::option2 offset must be 0x64");
static_assert(sizeof(CvFsDeviceInterface) == 0x68, "CvFsDeviceInterface size must be 0x68");

struct CvFsHandle
{
  CvFsDeviceInterface* interfaceView = nullptr; // +0x00
  SofdecAddressWord handleAddress = 0; // +0x04
};

static_assert(offsetof(CvFsHandle, interfaceView) == 0x00, "CvFsHandle::interfaceView offset must be 0x00");
static_assert(offsetof(CvFsHandle, handleAddress) == 0x04, "CvFsHandle::handleAddress offset must be 0x04");
static_assert(sizeof(CvFsHandle) == 0x08, "CvFsHandle size must be 0x08");

struct CvFsDeviceSlot
{
  CvFsDeviceInterface* interfaceView = nullptr; // +0x00
  std::array<char, 12> deviceName{}; // +0x04
};

static_assert(offsetof(CvFsDeviceSlot, interfaceView) == 0x00, "CvFsDeviceSlot::interfaceView offset must be 0x00");
static_assert(offsetof(CvFsDeviceSlot, deviceName) == 0x04, "CvFsDeviceSlot::deviceName offset must be 0x04");
static_assert(sizeof(CvFsDeviceSlot) == 0x10, "CvFsDeviceSlot size must be 0x10");

extern "C"
{
  int ADX_DecodeInfo(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outHeaderIdentity,
    std::int8_t* outHeaderType,
    std::int8_t* outSampleBits,
    std::int8_t* outChannels,
    std::int8_t* outBlockBytes,
    std::int32_t* outBlockSamples,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSamples
  );
  int ADX_DecodeInfoExVer(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outEncryptionMode,
    std::int32_t* outVersion
  );
  int ADX_DecodeInfoExADPCM2(const std::uint8_t* sourceBytes, std::int32_t sourceLength, std::int16_t* outCoefficientIndex);
  int ADX_DecodeInfoExIdly(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int16_t* outDelay0,
    std::int16_t* outDelay1
  );
  int ADX_DecodeInfoExLoop(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outInsertedSamples,
    std::int16_t* outLoopCount,
    std::uint16_t* outLoopType,
    std::int32_t* outLoopStartSample,
    std::int32_t* outLoopStartOffset,
    std::int32_t* outLoopEndSample,
    std::int32_t* outLoopEndOffset
  );
  int ADX_DecodeInfoAinf(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outAinfLength,
    std::uint8_t* outDataIdBytes,
    std::int16_t* outDefaultVolume,
    std::int16_t* outDefaultPanByChannel
  );
  int ADX_DecodeInfoExLoopEncTime(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int16_t* outLoopEnabled,
    std::int32_t* outLoopStartEncodedSamples,
    std::int32_t* outLoopEndEncodedSamples
  );
  int ADX_DecodeFooter(const std::uint8_t* sourceBytes, std::int32_t sourceLength, std::int16_t* outFooterBytes);

  int ADXERR_CallErrFunc1_(const char* message);
  int ADXERR_CallErrFunc2_(const char* prefix, const char* message);
  void ADXERR_ItoA2(std::int32_t highWord, std::int32_t lowWord, char* outText, std::int32_t outBytes);
  std::int32_t ADXERR_Init();
  std::int32_t ADXERR_Finish();
  void ADXERR_EntryErrFunc(moho::AdxmErrorCallback callbackFunction, std::int32_t callbackObject);
  void SVM_SetCbErr(moho::AdxmErrorCallback callback, std::int32_t callbackParam);
  std::int32_t MWSFLIB_SetErrCode(std::int32_t errorCode);
  std::int32_t MWSFSVM_Error(const char* message, ...);
  std::int32_t MWSFSVM_EntryIdVfunc(
    std::int32_t laneId,
    SofdecAddressWord callbackAddress,
    std::int32_t callbackObject,
    const char* callbackName
  );
  std::int32_t MWSFSVM_EntryMainFunc(SofdecAddressWord callbackAddress, std::int32_t callbackObject, const char* callbackName);
  std::int32_t MWSFSVM_EntryIdleFunc(SofdecAddressWord callbackAddress, std::int32_t callbackObject, const char* callbackName);
  BOOL MWSFSVM_TestAndSet(std::int32_t* signalLane);
  BOOL SVM_TestAndSet(std::int32_t* signalLane);
  void __cdecl MWSFSVR_VsyncThrdProc();
  void __cdecl MWSFSVR_MainThrdProc();
  void __cdecl MWSFSVR_IdleThrdProc();
  void MWSFSVR_SetMwsfdSvrFlg(std::int32_t enabled);
  std::int32_t mwsflib_LscErrFunc(std::int32_t callbackObject, const char* message);
  void mwsflib_InitLibWork(moho::MwsfdInitPrm* initParams);
  std::int32_t mwsflib_SetDefCond(const float* startupConditionValue);
  void MWSFLIB_SetSeekFlg(std::int32_t enabled);
  std::int32_t MWSFLIB_GetSeekFlg();
  SofdecAddressWord MWSFD_SetCond(
    moho::MwsfdPlaybackStateSubobj* ply,
    std::int32_t conditionId,
    std::int32_t conditionValue
  );
  std::int32_t mwPlySfdFinish();
  std::int32_t SFD_Finish();
  std::int32_t SFD_Destroy(void* sfdHandle);
  std::int32_t SFD_IsVersionCompatible(const char* versionText, std::int32_t versionTag);
  std::int32_t SFD_Init(moho::MwsfdInitSfdParams* initParams);
  std::int32_t SFD_SetErrFn(SofdecAddressWord errorObjectAddress, SofdecAddressWord callbackAddress, std::int32_t callbackObject);
  std::int32_t SFD_GetErrInf(SofdecAddressWord errorObjectAddress, void* outErrInfo);
  std::int32_t SFD_Stop(void* sfdHandle);
  std::int32_t SFD_IsSvrWait();
  std::int32_t SFD_GetIdFrm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outFrameId, void** outFrame);
  std::int32_t SFD_GetFrm(SofdecAddressWord sfdHandleAddress, void** outFrame);
  void SFD_RelFrm(SofdecAddressWord sfdHandleAddress, void* frameAddress);
  std::int32_t SFD_IsNextFrmReady(SofdecAddressWord sfdHandleAddress);
  SofdecAddressWord mwPlyGetSfdHn(moho::MwsfdPlaybackStateSubobj* ply);
  void* MWSFSFX_GetSfxHn(const moho::MwsfdPlaybackStateSubobj* ply);
  void SFX_SetOutBufSize(void* sfxHandle, std::int32_t outputPitch, std::int32_t outputHeight);
  void SFX_SetUnitWidth(void* sfxHandle, std::int32_t unitWidth);
  std::int32_t SFX_GetCompoMode(void* sfxHandle);
  std::int32_t SFD_GetHnStat(void* sfdHandle);
  std::int32_t SFD_SetConcatPlay(void* sfdHandle);
  std::int32_t SFD_GetTime(void* sfdHandle, std::int32_t* outTime, std::int32_t* outScale);
  std::int32_t SFD_SetPicUsrBuf(
    void* sfdHandle,
    SofdecAddressWord bufferAddress,
    std::int32_t frameSlotCount,
    std::int32_t bytesPerFrame
  );
  std::int32_t MWSFD_GetUsePicUsr();
  std::int32_t SFD_SetOutVol(void* sfdHandle, std::int32_t volumeLevel);
  std::int32_t SFD_GetOutVol(void* sfdHandle);
  std::int32_t SFD_SetOutPan(void* sfdHandle, std::int32_t laneIndex, std::int32_t panLevel);
  std::int32_t SFD_GetOutPan(void* sfdHandle, std::int32_t laneIndex);
  std::int32_t SFD_GetPlyInf(SofdecAddressWord sfdHandleAddress, void* outPlyInfo);
  std::int32_t SFD_GetTmrInf(SofdecAddressWord sfdHandleAddress, void* outTimerInfo);
  std::int32_t MWSST_GetStat(moho::MwsstStreamStateSubobj* streamState);
  std::int32_t MWSST_Stop(moho::MwsstStreamStateSubobj* streamState);
  void MWSST_Destroy(moho::MwsstStreamStateSubobj* streamState);
  void MWSST_Pause(moho::MwsstStreamStateSubobj* streamState, std::int32_t paused);
  std::int32_t UTY_CmpTime(
    std::int32_t leftTime,
    std::int32_t timeUnit,
    std::int32_t rightTime,
    std::int32_t currentTime
  );
  std::int32_t SFD_SetUsrSj(SofdecAddressWord sfdHandleAddress, std::int32_t mode, SofdecAddressWord arg0, SofdecAddressWord arg1);
  SofdecAddressWord SFX_SetTagInf(void* sfxHandle, SofdecAddressWord tagDataAddress, std::int32_t tagDataLength);
  void MWSFTAG_DestroyAinfSj(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFTAG_UpdateTagInf(moho::MwsfdPlaybackStateSubobj* ply);
  void MWSFSFX_Destroy(void* sfxHandle);
  std::int32_t MWSTM_Destroy(void* streamHandle);
  std::int32_t MWSTM_GetStat(void* streamHandle);
  std::int32_t MWSTM_SetFileRange(
    void* streamHandle,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  std::int32_t MWSTM_ReqStart(void* streamHandle);
  void mwsfcre_AllFree(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfcre_GetMallocCnt(moho::MwsfdPlaybackStateSubobj* ply);
  void* mwsfcre_OrgMalloc(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t size);
  void* mwsfcre_UsrMalloc(std::int32_t size);
  void mwsfcre_IncMallocCnt(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFD_IsEnableHndl(moho::MwsfdPlaybackStateSubobj* ply);
  void mwsffrm_SetFrmApi(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t type);
  void mwsffrm_CheckAinf(moho::MwsfdPlaybackStateSubobj* ply, const moho::MwsfdFrameInfo* frameInfo);
  void mwl_convFrmInfFromSFD(SofdecAddressWord playbackAddress, SofdecAddressWord sfdFrameAddress, SofdecAddressWord outFrameInfoAddress);
  void mwsffrm_SaveFrmDetail(SofdecAddressWord playbackAddress, SofdecAddressWord sfdFrameAddress);
  std::int32_t mwPlyIsNextFrmReady(moho::MwsfdPlaybackStateSubobj* ply);
  void MWSFCRE_DestroySfd(char* sfdHandleAddress);
  SofdecAddressWord MWSFCRE_SetSupplySj(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFD_GetReqSvrBdrLib();
  void mwSfdStartFnameSub(
    moho::MwsfdPlaybackStateSubobj* ply,
    const char* fname,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  void mwply_StartFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);
  std::int32_t MWSFPLY_ReqStartFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);
  void MWSFSEE_StartFnameSub1();
  void MWSFSEE_StartFnameSub2();
  void MWSFPLY_RecordFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);
  void MWSFPLY_ReqStartFnameRange(
    moho::MwsfdPlaybackStateSubobj* ply,
    const char* fname,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  std::int32_t LSC_EntryFname(void* lscHandle, const char* fname);
  std::int32_t LSC_GetNumStm(void* lscHandle);
  std::int32_t LSC_GetStat(void* lscHandle);
  void LSC_SetLpFlg(void* lscHandle, std::int32_t enabled);
  void lsc_Start(void* lscHandle);
  std::int32_t lsc_GetStmId(void* lscHandle, std::int32_t streamIndex);
  const char* lsc_GetStmFname(void* lscHandle, std::int32_t streamId);
  std::int32_t lsc_GetStmStat(void* lscHandle, std::int32_t streamId);
  std::int32_t lsc_GetStmRdSct(void* lscHandle, std::int32_t streamId);
  std::int32_t lsc_SetFlowLimit(void* lscHandle, std::int32_t flowLimit);
  std::int32_t lsc_EntryFileRange(
    void* lscHandle,
    const char* fname,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  std::int32_t ADXF_GetFnameRangeEx(
    SofdecAddressWord afsHandle,
    std::int32_t fileIndex,
    char* outFileName,
    std::int32_t* outStartOffset,
    std::int32_t* outRangeStart,
    std::int32_t* outRangeEnd
  );
  const char* ADXF_GetFnameFromPt(SofdecAddressWord afsHandle);
  std::int32_t SFD_ExecOne(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_IsHnSvrWait(SofdecAddressWord sfdHandleAddress);
  void mwPlySfdStart(moho::MwsfdPlaybackStateSubobj* ply);
  void mwPlyPause(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t paused);
  void mwPlyLinkStm(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t linkMode);
  bool MWSTM_IsFsStatErr(SofdecAddressWord streamHandleAddress);
  bool MWSFLSC_IsFsStatErr(void* lscHandle);
  std::int32_t MWSFSVR_SetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);
  std::int32_t MWSFSVR_GetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFSVR_SetHnSfdSvrFlg(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);
  void mwPlyEntryAfs(moho::MwsfdPlaybackStateSubobj* ply, SofdecAddressWord afsHandle, std::int32_t fileIndex);
  void mwPlyReleaseSeamless(moho::MwsfdPlaybackStateSubobj* ply);
  void mwPlyEntryFnameRange(
    moho::MwsfdPlaybackStateSubobj* ply,
    const char* fname,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  std::int32_t MWSFD_StartInternalSj(
    moho::MwsfdPlaybackStateSubobj* ply,
    moho::SofdecSjRingBufferHandle* ringBufferHandle
  );
  void MWSFPLY_SetFlowLimit(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwlSfdSleepDecSvr(moho::MwsfdPlaybackStateSubobj* ply);
  void mwsfsvr_StartPlayback(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfsvr_StartStream(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwlSfdExecDecSvrPrep(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwlSfdExecDecSvrPlaying(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfd_CheckFsErr(moho::MwsfdPlaybackStateSubobj* ply);
  void mwsfsvr_CheckSupply();
  std::int32_t mwPlyChkSupply(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t sfply_TermSupply(SofdecAddressWord sfdHandleAddress);
  std::int32_t mwSfdExecDecSvrHndl(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfd_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* ply);
  void mwPlyEntryFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);
  void mwPlySetSeamlessLp(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);
  void mwPlyStartSeamless(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwply_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* ply);
  void MWSTM_ReqStop(void* streamHandle);
  void lsc_Stop(void* lscHandle);
  void adxt_StopWithoutLsc(void* adxtRuntime);
  void ADXT_StopWithoutLsc(void* adxtRuntime);
  void ADXT_Stop(void* adxtRuntime);
