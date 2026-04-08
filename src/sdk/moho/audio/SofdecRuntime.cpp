#include "moho/audio/SofdecRuntime.h"

#include <array>
#include <bit>
#include <cstdarg>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mmintrin.h>
#include <process.h>

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
  std::uint8_t mUnknown0C[0x8]{}; // +0x0C
  std::int32_t hasWork = 0; // +0x14
  std::uint8_t mUnknown18[0xC]{}; // +0x18
  const char* pathPrefix = nullptr; // +0x24
  std::uint8_t mUnknown28[0x8]{}; // +0x28
  std::int32_t queuedEntryCount = 0; // +0x30
  XeficQueuedFileEntry* queueHead = nullptr; // +0x34
  XeficQueuedFileEntry* queueCursor = nullptr; // +0x38
  void* stateResetGuard = nullptr; // +0x3C
  std::uint8_t mUnknown40[0x4]{}; // +0x40
};

static_assert(offsetof(XeficObject, used) == 0x00, "XeficObject::used offset must be 0x00");
static_assert(offsetof(XeficObject, state) == 0x04, "XeficObject::state offset must be 0x04");
static_assert(offsetof(XeficObject, stateSignal) == 0x08, "XeficObject::stateSignal offset must be 0x08");
static_assert(offsetof(XeficObject, hasWork) == 0x14, "XeficObject::hasWork offset must be 0x14");
static_assert(offsetof(XeficObject, pathPrefix) == 0x24, "XeficObject::pathPrefix offset must be 0x24");
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

using XeficQueueVisitor = int(__cdecl*)(XeficQueuedFileEntry* queueEntry, std::int32_t contextValue);

struct M2aChannelPairLocation
{
  std::int32_t channelPairType = 0; // +0x00
  std::int32_t channelClass = 0; // +0x04
  std::int32_t locationClass = 0; // +0x08
};

static_assert(offsetof(M2aChannelPairLocation, channelPairType) == 0x00, "M2aChannelPairLocation::channelPairType offset must be 0x00");
static_assert(offsetof(M2aChannelPairLocation, channelClass) == 0x04, "M2aChannelPairLocation::channelClass offset must be 0x04");
static_assert(offsetof(M2aChannelPairLocation, locationClass) == 0x08, "M2aChannelPairLocation::locationClass offset must be 0x08");
static_assert(sizeof(M2aChannelPairLocation) == 0x0C, "M2aChannelPairLocation size must be 0x0C");

struct M2aDecoderContext
{
  std::uint8_t mUnknown00[0x24]{};
  std::int32_t bitstreamHandle = 0; // +0x24
  std::int32_t activeElementIndex = 0; // +0x28
  std::int32_t activeWindowGroupIndex = 0; // +0x2C
  std::uint8_t mUnknown30[0x38]{};
  std::int32_t locationCountClass0 = 0; // +0x68
  std::int32_t locationCountClass1 = 0; // +0x6C
  std::int32_t locationCountClass3 = 0; // +0x70
  std::int32_t locationCountClass4 = 0; // +0x74
  std::int32_t locationCountClass5 = 0; // +0x78
  std::int32_t locationCountClass6 = 0; // +0x7C
  std::int32_t locationCountClass7 = 0; // +0x80
  std::uint8_t mUnknown84[0x08]{};
  const std::int32_t* scalefactorBandWidthsLong = nullptr; // +0x8C
  const std::int32_t* scalefactorBandWidthsShort = nullptr; // +0x90
  std::uint8_t mUnknown94[0x04]{};
  void* pceMap = nullptr; // +0x98
  M2aChannelPairLocation* channelPairLocationEntries[128]{}; // +0x9C
  void* m2aIcsInfoTable[16]{}; // +0x29C
  std::uint8_t mUnknown2DC[0x3C0]{};
  void* m2aPrimaryStateTable[16]{}; // +0x69C
  void* m2aSecondaryStateTable[16]{}; // +0x6DC
};

static_assert(offsetof(M2aDecoderContext, bitstreamHandle) == 0x24, "M2aDecoderContext::bitstreamHandle offset must be 0x24");
static_assert(offsetof(M2aDecoderContext, activeElementIndex) == 0x28, "M2aDecoderContext::activeElementIndex offset must be 0x28");
static_assert(
  offsetof(M2aDecoderContext, activeWindowGroupIndex) == 0x2C,
  "M2aDecoderContext::activeWindowGroupIndex offset must be 0x2C"
);
static_assert(
  offsetof(M2aDecoderContext, scalefactorBandWidthsLong) == 0x8C,
  "M2aDecoderContext::scalefactorBandWidthsLong offset must be 0x8C"
);
static_assert(
  offsetof(M2aDecoderContext, scalefactorBandWidthsShort) == 0x90,
  "M2aDecoderContext::scalefactorBandWidthsShort offset must be 0x90"
);
static_assert(offsetof(M2aDecoderContext, pceMap) == 0x98, "M2aDecoderContext::pceMap offset must be 0x98");
static_assert(
  offsetof(M2aDecoderContext, channelPairLocationEntries) == 0x9C,
  "M2aDecoderContext::channelPairLocationEntries offset must be 0x9C"
);
static_assert(
  offsetof(M2aDecoderContext, m2aIcsInfoTable) == 0x29C, "M2aDecoderContext::m2aIcsInfoTable offset must be 0x29C"
);
static_assert(
  offsetof(M2aDecoderContext, m2aPrimaryStateTable) == 0x69C,
  "M2aDecoderContext::m2aPrimaryStateTable offset must be 0x69C"
);
static_assert(
  offsetof(M2aDecoderContext, m2aSecondaryStateTable) == 0x6DC,
  "M2aDecoderContext::m2aSecondaryStateTable offset must be 0x6DC"
);

struct M2aBitstreamRuntimeView
{
  std::uint8_t mUnknown00[0x0C]{};
  std::uint32_t bitEndPosition = 0; // +0x0C
  std::uint32_t bitPosition = 0; // +0x10
  std::uint32_t overrunCount = 0; // +0x14
};

static_assert(offsetof(M2aBitstreamRuntimeView, bitEndPosition) == 0x0C, "M2aBitstreamRuntimeView::bitEndPosition offset must be 0x0C");
static_assert(offsetof(M2aBitstreamRuntimeView, bitPosition) == 0x10, "M2aBitstreamRuntimeView::bitPosition offset must be 0x10");
static_assert(offsetof(M2aBitstreamRuntimeView, overrunCount) == 0x14, "M2aBitstreamRuntimeView::overrunCount offset must be 0x14");

struct MparbdDecoderState
{
  std::uint8_t mUnknown00[0x3514]{};
  std::int32_t bitReaderHandlePrimary = 0; // +0x3514
  std::int32_t bitReaderHandleSecondary = 0; // +0x3518
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

struct MparbfRuntimeBuffer
{
  std::uint8_t* data = nullptr; // +0x00
  std::uint32_t capacityBytes = 0; // +0x04
  std::uint32_t readOffsetBytes = 0; // +0x08
  std::uint32_t dataBytes = 0; // +0x0C
  std::uint32_t writeOffsetBytes = 0; // +0x10
  std::uint32_t freeBytes = 0; // +0x14
};

static_assert(offsetof(MparbfRuntimeBuffer, data) == 0x00, "MparbfRuntimeBuffer::data offset must be 0x00");
static_assert(
  offsetof(MparbfRuntimeBuffer, capacityBytes) == 0x04,
  "MparbfRuntimeBuffer::capacityBytes offset must be 0x04"
);
static_assert(
  offsetof(MparbfRuntimeBuffer, readOffsetBytes) == 0x08,
  "MparbfRuntimeBuffer::readOffsetBytes offset must be 0x08"
);
static_assert(
  offsetof(MparbfRuntimeBuffer, dataBytes) == 0x0C,
  "MparbfRuntimeBuffer::dataBytes offset must be 0x0C"
);
static_assert(
  offsetof(MparbfRuntimeBuffer, writeOffsetBytes) == 0x10,
  "MparbfRuntimeBuffer::writeOffsetBytes offset must be 0x10"
);
static_assert(
  offsetof(MparbfRuntimeBuffer, freeBytes) == 0x14,
  "MparbfRuntimeBuffer::freeBytes offset must be 0x14"
);
static_assert(sizeof(MparbfRuntimeBuffer) == 0x18, "MparbfRuntimeBuffer size must be 0x18");

struct SfxaRuntimeHandleView
{
  using LuminanceTableBuilderCallback = std::int32_t(__cdecl*)(std::int32_t laneA, std::int32_t laneB, std::int32_t laneC, std::int32_t laneD);
  using AlphaTableBuilderCallback = std::int32_t(__cdecl*)(std::int32_t destinationAddress, std::int32_t alpha0, std::int32_t alpha1, std::int32_t alpha2);

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

static_assert(offsetof(SfxaRuntimeHandleView, used) == 0x00, "SfxaRuntimeHandleView::used offset must be 0x00");
static_assert(
  offsetof(SfxaRuntimeHandleView, needsLumiTableUpdate) == 0x04,
  "SfxaRuntimeHandleView::needsLumiTableUpdate offset must be 0x04"
);
static_assert(offsetof(SfxaRuntimeHandleView, luminancePivot) == 0x08, "SfxaRuntimeHandleView::luminancePivot offset must be 0x08");
static_assert(offsetof(SfxaRuntimeHandleView, luminanceMin) == 0x0C, "SfxaRuntimeHandleView::luminanceMin offset must be 0x0C");
static_assert(offsetof(SfxaRuntimeHandleView, luminanceMax) == 0x10, "SfxaRuntimeHandleView::luminanceMax offset must be 0x10");
static_assert(offsetof(SfxaRuntimeHandleView, alpha0) == 0x14, "SfxaRuntimeHandleView::alpha0 offset must be 0x14");
static_assert(offsetof(SfxaRuntimeHandleView, alpha1) == 0x15, "SfxaRuntimeHandleView::alpha1 offset must be 0x15");
static_assert(offsetof(SfxaRuntimeHandleView, alpha2) == 0x16, "SfxaRuntimeHandleView::alpha2 offset must be 0x16");
static_assert(
  offsetof(SfxaRuntimeHandleView, luminanceBuilder) == 0x18,
  "SfxaRuntimeHandleView::luminanceBuilder offset must be 0x18"
);
static_assert(
  offsetof(SfxaRuntimeHandleView, alpha3110Builder) == 0x1C,
  "SfxaRuntimeHandleView::alpha3110Builder offset must be 0x1C"
);
static_assert(
  offsetof(SfxaRuntimeHandleView, alpha3211Builder) == 0x20,
  "SfxaRuntimeHandleView::alpha3211Builder offset must be 0x20"
);
static_assert(sizeof(SfxaRuntimeHandleView) == 0x24, "SfxaRuntimeHandleView size must be 0x24");

struct SfxaLibWorkView
{
  std::int32_t cur = 0; // +0x00
  std::int32_t last = 0; // +0x04
  std::array<SfxaRuntimeHandleView, 32> objects{}; // +0x08
};

static_assert(offsetof(SfxaLibWorkView, cur) == 0x00, "SfxaLibWorkView::cur offset must be 0x00");
static_assert(offsetof(SfxaLibWorkView, last) == 0x04, "SfxaLibWorkView::last offset must be 0x04");
static_assert(offsetof(SfxaLibWorkView, objects) == 0x08, "SfxaLibWorkView::objects offset must be 0x08");
static_assert(sizeof(SfxaLibWorkView) == 0x488, "SfxaLibWorkView size must be 0x488");

struct SfbufInitLayoutConfigView
{
  std::int32_t mUnknown00 = 0; // +0x00
  std::int32_t baseBufferAddress = 0; // +0x04
  std::array<std::int32_t, 8> laneBufferSizes{}; // +0x08
  std::int32_t lane0ExtraModuloDivisor = 0; // +0x28
};

static_assert(
  offsetof(SfbufInitLayoutConfigView, baseBufferAddress) == 0x04,
  "SfbufInitLayoutConfigView::baseBufferAddress offset must be 0x04"
);
static_assert(
  offsetof(SfbufInitLayoutConfigView, laneBufferSizes) == 0x08,
  "SfbufInitLayoutConfigView::laneBufferSizes offset must be 0x08"
);
static_assert(
  offsetof(SfbufInitLayoutConfigView, lane0ExtraModuloDivisor) == 0x28,
  "SfbufInitLayoutConfigView::lane0ExtraModuloDivisor offset must be 0x28"
);
static_assert(sizeof(SfbufInitLayoutConfigView) == 0x2C, "SfbufInitLayoutConfigView size must be 0x2C");

struct SfbufSjCreateStateView
{
  std::int32_t ownerTag = 0; // +0x00
  moho::SofdecSjRingBufferHandle* sjHandle = nullptr; // +0x04
  std::int32_t sourceBufferAddress = 0; // +0x08
  std::int32_t sourceBufferBytes = 0; // +0x0C
  std::int32_t extraBufferBytes = 0; // +0x10
  std::int32_t mUnknown14 = 0; // +0x14
};

static_assert(offsetof(SfbufSjCreateStateView, sjHandle) == 0x04, "SfbufSjCreateStateView::sjHandle offset must be 0x04");
static_assert(
  offsetof(SfbufSjCreateStateView, sourceBufferAddress) == 0x08,
  "SfbufSjCreateStateView::sourceBufferAddress offset must be 0x08"
);
static_assert(
  offsetof(SfbufSjCreateStateView, sourceBufferBytes) == 0x0C,
  "SfbufSjCreateStateView::sourceBufferBytes offset must be 0x0C"
);
static_assert(
  offsetof(SfbufSjCreateStateView, extraBufferBytes) == 0x10,
  "SfbufSjCreateStateView::extraBufferBytes offset must be 0x10"
);
static_assert(sizeof(SfbufSjCreateStateView) == 0x18, "SfbufSjCreateStateView size must be 0x18");

struct SfbufSupplyLaneView
{
  std::int32_t laneType = 0; // +0x00
  std::int32_t isSetup = 0; // +0x04
  std::int32_t prepFlag = 0; // +0x08
  std::int32_t termFlag = 0; // +0x0C
  std::int32_t sourceBufferAddress = 0; // +0x10
  std::int32_t sourceBufferBytes = 0; // +0x14
  std::int32_t laneParam18 = 0; // +0x18
  std::int32_t queuedDataBytes = 0; // +0x1C
  std::int32_t laneParam20 = 0; // +0x20
  std::int32_t laneParam24 = 0; // +0x24
  std::int32_t delimiterPrimaryAddress = 0; // +0x28
  std::int32_t delimiterSecondaryAddress = 0; // +0x2C
  std::int32_t writeTotalBytes = 0; // +0x30
  std::int32_t readTotalBytes = 0; // +0x34
  std::int32_t laneParam38 = 0; // +0x38
  std::int32_t laneParam3C = 0; // +0x3C
  std::uint8_t mUnknown40[0x0C]{}; // +0x40
  std::int32_t runtimeState0 = 0; // +0x4C
  std::int32_t runtimeState1 = 0; // +0x50
  std::uint8_t mUnknown54[0x20]{}; // +0x54
};

static_assert(offsetof(SfbufSupplyLaneView, laneType) == 0x00, "SfbufSupplyLaneView::laneType offset must be 0x00");
static_assert(offsetof(SfbufSupplyLaneView, isSetup) == 0x04, "SfbufSupplyLaneView::isSetup offset must be 0x04");
static_assert(offsetof(SfbufSupplyLaneView, prepFlag) == 0x08, "SfbufSupplyLaneView::prepFlag offset must be 0x08");
static_assert(offsetof(SfbufSupplyLaneView, termFlag) == 0x0C, "SfbufSupplyLaneView::termFlag offset must be 0x0C");
static_assert(
  offsetof(SfbufSupplyLaneView, sourceBufferAddress) == 0x10,
  "SfbufSupplyLaneView::sourceBufferAddress offset must be 0x10"
);
static_assert(
  offsetof(SfbufSupplyLaneView, sourceBufferBytes) == 0x14,
  "SfbufSupplyLaneView::sourceBufferBytes offset must be 0x14"
);
static_assert(
  offsetof(SfbufSupplyLaneView, queuedDataBytes) == 0x1C,
  "SfbufSupplyLaneView::queuedDataBytes offset must be 0x1C"
);
static_assert(
  offsetof(SfbufSupplyLaneView, delimiterPrimaryAddress) == 0x28,
  "SfbufSupplyLaneView::delimiterPrimaryAddress offset must be 0x28"
);
static_assert(
  offsetof(SfbufSupplyLaneView, delimiterSecondaryAddress) == 0x2C,
  "SfbufSupplyLaneView::delimiterSecondaryAddress offset must be 0x2C"
);
static_assert(
  offsetof(SfbufSupplyLaneView, writeTotalBytes) == 0x30,
  "SfbufSupplyLaneView::writeTotalBytes offset must be 0x30"
);
static_assert(
  offsetof(SfbufSupplyLaneView, readTotalBytes) == 0x34,
  "SfbufSupplyLaneView::readTotalBytes offset must be 0x34"
);
static_assert(
  offsetof(SfbufSupplyLaneView, runtimeState0) == 0x4C,
  "SfbufSupplyLaneView::runtimeState0 offset must be 0x4C"
);
static_assert(
  offsetof(SfbufSupplyLaneView, runtimeState1) == 0x50,
  "SfbufSupplyLaneView::runtimeState1 offset must be 0x50"
);
static_assert(sizeof(SfbufSupplyLaneView) == 0x74, "SfbufSupplyLaneView size must be 0x74");

struct SfbufUochDescriptorView
{
  std::int32_t word0 = 0; // +0x00
  std::int32_t word1 = 0; // +0x04
  std::int32_t word2 = 0; // +0x08
  std::int32_t word3 = 0; // +0x0C
};

static_assert(offsetof(SfbufUochDescriptorView, word0) == 0x00, "SfbufUochDescriptorView::word0 offset must be 0x00");
static_assert(offsetof(SfbufUochDescriptorView, word1) == 0x04, "SfbufUochDescriptorView::word1 offset must be 0x04");
static_assert(offsetof(SfbufUochDescriptorView, word2) == 0x08, "SfbufUochDescriptorView::word2 offset must be 0x08");
static_assert(offsetof(SfbufUochDescriptorView, word3) == 0x0C, "SfbufUochDescriptorView::word3 offset must be 0x0C");
static_assert(sizeof(SfbufUochDescriptorView) == 0x10, "SfbufUochDescriptorView size must be 0x10");

struct SfbufRingCursorSnapshotView
{
  moho::SjChunkRange firstChunk{}; // +0x00
  moho::SjChunkRange secondChunk{}; // +0x08
  std::array<std::int32_t, 3> reservedWords{}; // +0x10
};

static_assert(
  offsetof(SfbufRingCursorSnapshotView, firstChunk) == 0x00,
  "SfbufRingCursorSnapshotView::firstChunk offset must be 0x00"
);
static_assert(
  offsetof(SfbufRingCursorSnapshotView, secondChunk) == 0x08,
  "SfbufRingCursorSnapshotView::secondChunk offset must be 0x08"
);
static_assert(
  offsetof(SfbufRingCursorSnapshotView, reservedWords) == 0x10,
  "SfbufRingCursorSnapshotView::reservedWords offset must be 0x10"
);
static_assert(sizeof(SfbufRingCursorSnapshotView) == 0x1C, "SfbufRingCursorSnapshotView size must be 0x1C");

struct SfbufSupplyStateWindowView
{
  std::int32_t sourceBufferAddress = 0; // +0x00
  std::int32_t ringHandleAddress = 0; // +0x04
  std::int32_t ownerLaneAddress = 0; // +0x08
  std::int32_t queuedDataBytes = 0; // +0x0C
  std::int32_t laneParam20 = 0; // +0x10
  std::int32_t laneParam24 = 0; // +0x14
  std::int32_t delimiterPrimaryAddress = 0; // +0x18
  std::int32_t delimiterSecondaryAddress = 0; // +0x1C
};

static_assert(
  offsetof(SfbufSupplyStateWindowView, ringHandleAddress) == 0x04,
  "SfbufSupplyStateWindowView::ringHandleAddress offset must be 0x04"
);
static_assert(
  offsetof(SfbufSupplyStateWindowView, delimiterPrimaryAddress) == 0x18,
  "SfbufSupplyStateWindowView::delimiterPrimaryAddress offset must be 0x18"
);
static_assert(
  offsetof(SfbufSupplyStateWindowView, delimiterSecondaryAddress) == 0x1C,
  "SfbufSupplyStateWindowView::delimiterSecondaryAddress offset must be 0x1C"
);
static_assert(sizeof(SfbufSupplyStateWindowView) == 0x20, "SfbufSupplyStateWindowView size must be 0x20");

struct SfbufRuntimeStatusView
{
  std::uint8_t mUnknown00[0x44]{};
  std::int32_t dirtyFlag = 0; // +0x44
};

static_assert(offsetof(SfbufRuntimeStatusView, dirtyFlag) == 0x44, "SfbufRuntimeStatusView::dirtyFlag offset must be 0x44");

struct SfbufAringLaneStateView
{
  std::int32_t transferParam0 = 0; // +0x00
  std::int32_t sampleMode = 0; // +0x04
  std::int32_t transferParam2 = 0; // +0x08
  std::int32_t primarySampleBaseAddress = 0; // +0x0C
  std::int32_t secondarySampleBaseAddress = 0; // +0x10
  std::int32_t ringCapacitySamples = 0; // +0x14
  std::int32_t writeCursorSamples = 0; // +0x18
  std::int32_t readCursorSamples = 0; // +0x1C
  std::int32_t writeTotalSamples = 0; // +0x20
  std::int32_t readTotalSamples = 0; // +0x24
  std::int32_t mUnknown28 = 0; // +0x28
  std::int32_t mUnknown2C = 0; // +0x2C
  std::int32_t mUnknown30 = 0; // +0x30
  std::int32_t transferHandleAddress = 0; // +0x34
};

static_assert(
  offsetof(SfbufAringLaneStateView, transferParam0) == 0x00,
  "SfbufAringLaneStateView::transferParam0 offset must be 0x00"
);
static_assert(
  offsetof(SfbufAringLaneStateView, sampleMode) == 0x04,
  "SfbufAringLaneStateView::sampleMode offset must be 0x04"
);
static_assert(
  offsetof(SfbufAringLaneStateView, transferParam2) == 0x08,
  "SfbufAringLaneStateView::transferParam2 offset must be 0x08"
);
static_assert(
  offsetof(SfbufAringLaneStateView, primarySampleBaseAddress) == 0x0C,
  "SfbufAringLaneStateView::primarySampleBaseAddress offset must be 0x0C"
);
static_assert(
  offsetof(SfbufAringLaneStateView, secondarySampleBaseAddress) == 0x10,
  "SfbufAringLaneStateView::secondarySampleBaseAddress offset must be 0x10"
);
static_assert(
  offsetof(SfbufAringLaneStateView, ringCapacitySamples) == 0x14,
  "SfbufAringLaneStateView::ringCapacitySamples offset must be 0x14"
);
static_assert(
  offsetof(SfbufAringLaneStateView, writeCursorSamples) == 0x18,
  "SfbufAringLaneStateView::writeCursorSamples offset must be 0x18"
);
static_assert(
  offsetof(SfbufAringLaneStateView, readCursorSamples) == 0x1C,
  "SfbufAringLaneStateView::readCursorSamples offset must be 0x1C"
);
static_assert(
  offsetof(SfbufAringLaneStateView, writeTotalSamples) == 0x20,
  "SfbufAringLaneStateView::writeTotalSamples offset must be 0x20"
);
static_assert(
  offsetof(SfbufAringLaneStateView, readTotalSamples) == 0x24,
  "SfbufAringLaneStateView::readTotalSamples offset must be 0x24"
);
static_assert(
  offsetof(SfbufAringLaneStateView, transferHandleAddress) == 0x34,
  "SfbufAringLaneStateView::transferHandleAddress offset must be 0x34"
);
static_assert(sizeof(SfbufAringLaneStateView) == 0x38, "SfbufAringLaneStateView size must be 0x38");

struct SfbufAringTransferSnapshotView
{
  std::int32_t transferParam0 = 0; // +0x00
  std::int32_t sampleMode = 0; // +0x04
  std::int32_t transferParam2 = 0; // +0x08
  std::int32_t chunkSampleCount = 0; // +0x0C
  std::int32_t wrapCursorSample = 0; // +0x10
  std::int32_t primaryChunkAddress = 0; // +0x14
  std::int32_t secondaryChunkAddress = 0; // +0x18
  std::int32_t primaryWrapAddress = 0; // +0x1C
  std::int32_t secondaryWrapAddress = 0; // +0x20
  std::int32_t writeTotalSamples = 0; // +0x24
  std::int32_t readTotalSamples = 0; // +0x28
};

static_assert(
  offsetof(SfbufAringTransferSnapshotView, transferParam0) == 0x00,
  "SfbufAringTransferSnapshotView::transferParam0 offset must be 0x00"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, sampleMode) == 0x04,
  "SfbufAringTransferSnapshotView::sampleMode offset must be 0x04"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, transferParam2) == 0x08,
  "SfbufAringTransferSnapshotView::transferParam2 offset must be 0x08"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, chunkSampleCount) == 0x0C,
  "SfbufAringTransferSnapshotView::chunkSampleCount offset must be 0x0C"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, primaryChunkAddress) == 0x14,
  "SfbufAringTransferSnapshotView::primaryChunkAddress offset must be 0x14"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, secondaryChunkAddress) == 0x18,
  "SfbufAringTransferSnapshotView::secondaryChunkAddress offset must be 0x18"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, writeTotalSamples) == 0x24,
  "SfbufAringTransferSnapshotView::writeTotalSamples offset must be 0x24"
);
static_assert(
  offsetof(SfbufAringTransferSnapshotView, readTotalSamples) == 0x28,
  "SfbufAringTransferSnapshotView::readTotalSamples offset must be 0x28"
);
static_assert(sizeof(SfbufAringTransferSnapshotView) == 0x2C, "SfbufAringTransferSnapshotView size must be 0x2C");

struct SfbufRuntimeHandleView
{
  std::uint8_t mUnknown00[0x1310]{}; // +0x00
  std::array<SfbufSupplyLaneView, 8> lanes{}; // +0x1310
};

static_assert(offsetof(SfbufRuntimeHandleView, lanes) == 0x1310, "SfbufRuntimeHandleView::lanes offset must be 0x1310");

using SftrnEntryCallback =
  std::int32_t(__cdecl*)(std::int32_t arg0, std::int32_t arg1, std::int32_t arg2, std::int32_t arg3);

struct SftrnEntryDispatchView
{
  std::array<SftrnEntryCallback, 2> entryCallbacks{};
};

static_assert(sizeof(SftrnEntryDispatchView) == 0x8, "SftrnEntryDispatchView size must be 0x8");

struct SftrnEntryListView
{
  std::array<SftrnEntryDispatchView*, 15> entries{};
};

static_assert(sizeof(SftrnEntryListView) == 0x3C, "SftrnEntryListView size must be 0x3C");

struct SftrnTransferDataLaneView
{
  std::int32_t prepFlag = 0; // +0x00
  std::int32_t termFlag = 0; // +0x04
  std::int32_t setupState = 0; // +0x08
  std::int32_t transferDescriptorAddress = 0; // +0x0C
  std::int32_t sourceLaneIndex = 0; // +0x10
  std::int32_t targetLaneIndex0 = 0; // +0x14
  std::int32_t targetLaneIndex1 = 0; // +0x18
  std::int32_t targetLaneIndex2 = 0; // +0x1C
  std::int32_t transferEndState = 0; // +0x20
  std::uint8_t mUnknown24[0x20]{}; // +0x24
};

static_assert(
  offsetof(SftrnTransferDataLaneView, prepFlag) == 0x00,
  "SftrnTransferDataLaneView::prepFlag offset must be 0x00"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, termFlag) == 0x04,
  "SftrnTransferDataLaneView::termFlag offset must be 0x04"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, setupState) == 0x08,
  "SftrnTransferDataLaneView::setupState offset must be 0x08"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, transferDescriptorAddress) == 0x0C,
  "SftrnTransferDataLaneView::transferDescriptorAddress offset must be 0x0C"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, sourceLaneIndex) == 0x10,
  "SftrnTransferDataLaneView::sourceLaneIndex offset must be 0x10"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, targetLaneIndex0) == 0x14,
  "SftrnTransferDataLaneView::targetLaneIndex0 offset must be 0x14"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, targetLaneIndex1) == 0x18,
  "SftrnTransferDataLaneView::targetLaneIndex1 offset must be 0x18"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, targetLaneIndex2) == 0x1C,
  "SftrnTransferDataLaneView::targetLaneIndex2 offset must be 0x1C"
);
static_assert(
  offsetof(SftrnTransferDataLaneView, transferEndState) == 0x20,
  "SftrnTransferDataLaneView::transferEndState offset must be 0x20"
);
static_assert(sizeof(SftrnTransferDataLaneView) == 0x44, "SftrnTransferDataLaneView size must be 0x44");

struct SftrnTransferRuntimeView
{
  std::uint8_t mUnknown00[0x1F30]{}; // +0x00
  std::array<SftrnTransferDataLaneView, 9> transferLanes{}; // +0x1F30
};

static_assert(
  offsetof(SftrnTransferRuntimeView, transferLanes) == 0x1F30,
  "SftrnTransferRuntimeView::transferLanes offset must be 0x1F30"
);

struct SftrnBuildConfigView
{
  std::int32_t mUnknown00 = 0; // +0x00
  std::int32_t hasSystemLane = 0; // +0x04
  std::int32_t hasAudioLane = 0; // +0x08
  std::int32_t hasVideoLane = 0; // +0x0C
  std::int32_t hasAudioExtendedLane = 0; // +0x10
  std::int32_t hasVideoExtendedLane = 0; // +0x14
  std::uint8_t mUnknown18[0x8]{}; // +0x18
  std::int32_t hasUserLane = 0; // +0x20
};

static_assert(offsetof(SftrnBuildConfigView, hasSystemLane) == 0x04, "SftrnBuildConfigView::hasSystemLane offset must be 0x04");
static_assert(offsetof(SftrnBuildConfigView, hasAudioLane) == 0x08, "SftrnBuildConfigView::hasAudioLane offset must be 0x08");
static_assert(offsetof(SftrnBuildConfigView, hasVideoLane) == 0x0C, "SftrnBuildConfigView::hasVideoLane offset must be 0x0C");
static_assert(
  offsetof(SftrnBuildConfigView, hasAudioExtendedLane) == 0x10,
  "SftrnBuildConfigView::hasAudioExtendedLane offset must be 0x10"
);
static_assert(
  offsetof(SftrnBuildConfigView, hasVideoExtendedLane) == 0x14,
  "SftrnBuildConfigView::hasVideoExtendedLane offset must be 0x14"
);
static_assert(offsetof(SftrnBuildConfigView, hasUserLane) == 0x20, "SftrnBuildConfigView::hasUserLane offset must be 0x20");

struct SftrnWorkctrlStateView
{
  std::uint8_t mUnknown00[0xBB0]{}; // +0x00
  std::int32_t audioConditionState = 0; // +0xBB0
  std::int32_t videoConditionState = 0; // +0xBB4
};

static_assert(
  offsetof(SftrnWorkctrlStateView, audioConditionState) == 0xBB0,
  "SftrnWorkctrlStateView::audioConditionState offset must be 0xBB0"
);
static_assert(
  offsetof(SftrnWorkctrlStateView, videoConditionState) == 0xBB4,
  "SftrnWorkctrlStateView::videoConditionState offset must be 0xBB4"
);

struct SfsetConditionStateView
{
  std::uint8_t mUnknown00[0xA0C]{}; // +0x00
  std::array<std::int32_t, 256> setConditions{}; // +0xA0C (at least condition IDs up to 0x48 are observed)
};

static_assert(
  offsetof(SfsetConditionStateView, setConditions) == 0xA0C,
  "SfsetConditionStateView::setConditions offset must be 0xA0C"
);

struct SfplyPictureCountView
{
  std::int32_t decodedPictureCount = 0; // +0x00
  std::int32_t skippedPictureCount = 0; // +0x04
};

static_assert(
  offsetof(SfplyPictureCountView, decodedPictureCount) == 0x00,
  "SfplyPictureCountView::decodedPictureCount offset must be 0x00"
);
static_assert(
  offsetof(SfplyPictureCountView, skippedPictureCount) == 0x04,
  "SfplyPictureCountView::skippedPictureCount offset must be 0x04"
);
static_assert(sizeof(SfplyPictureCountView) == 0x08, "SfplyPictureCountView size must be 0x08");

using SfplyPictureCountCallback =
  std::int32_t(__cdecl*)(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t callbackContext, SfplyPictureCountView* pictureCounts);

struct SfplyFileHeaderLaneView
{
  std::uint8_t mUnknown00[0x78]{}; // +0x00
  std::uint8_t fileHeaderState[1]{}; // +0x78
};

static_assert(
  offsetof(SfplyFileHeaderLaneView, fileHeaderState) == 0x78,
  "SfplyFileHeaderLaneView::fileHeaderState offset must be 0x78"
);

struct SfplyRuntimeStateView
{
  std::uint8_t mUnknown00[0x44]{}; // +0x00
  std::int32_t serverWaitFlag = 0; // +0x44
  std::int32_t statusLane = 0; // +0x48
  std::int32_t phaseLane = 0; // +0x4C
  std::int32_t startupGateFlag = 0; // +0x50
  std::uint8_t mUnknown54[0x8FC]{}; // +0x54
  SfplyPictureCountView pictureCounts{}; // +0x950
  std::uint8_t mUnknown958[0x18]{}; // +0x958
  std::int32_t bpaActiveFlag = 0; // +0x970
  std::int32_t bpaToggleCount = 0; // +0x974
  std::int32_t videoLaneReadyFlag = 0; // +0x978
  std::uint8_t mUnknown97C[0x90]{}; // +0x97C
  std::array<std::int32_t, 256> setConditions{}; // +0xA0C
  std::uint8_t mUnknownE0C[0x1A8]{}; // +0xE0C
  std::int32_t bpaWindowTicks = 0; // +0xFB4
  std::int32_t bpaTickRate = 0; // +0xFB8
  std::uint8_t mUnknownFBC[0x24]{}; // +0xFBC
  std::int32_t startSyncBypassFlag = 0; // +0xFE0
  std::uint8_t mUnknownFE4[0x18]{}; // +0xFE4
  std::int32_t startSyncCurrentTicks = 0; // +0xFFC
};

static_assert(
  offsetof(SfplyRuntimeStateView, serverWaitFlag) == 0x44, "SfplyRuntimeStateView::serverWaitFlag offset must be 0x44"
);
static_assert(offsetof(SfplyRuntimeStateView, statusLane) == 0x48, "SfplyRuntimeStateView::statusLane offset must be 0x48");
static_assert(offsetof(SfplyRuntimeStateView, phaseLane) == 0x4C, "SfplyRuntimeStateView::phaseLane offset must be 0x4C");
static_assert(
  offsetof(SfplyRuntimeStateView, startupGateFlag) == 0x50, "SfplyRuntimeStateView::startupGateFlag offset must be 0x50"
);
static_assert(
  offsetof(SfplyRuntimeStateView, pictureCounts) == 0x950, "SfplyRuntimeStateView::pictureCounts offset must be 0x950"
);
static_assert(
  offsetof(SfplyRuntimeStateView, bpaActiveFlag) == 0x970, "SfplyRuntimeStateView::bpaActiveFlag offset must be 0x970"
);
static_assert(
  offsetof(SfplyRuntimeStateView, bpaToggleCount) == 0x974, "SfplyRuntimeStateView::bpaToggleCount offset must be 0x974"
);
static_assert(
  offsetof(SfplyRuntimeStateView, videoLaneReadyFlag) == 0x978,
  "SfplyRuntimeStateView::videoLaneReadyFlag offset must be 0x978"
);
static_assert(
  offsetof(SfplyRuntimeStateView, setConditions) == 0xA0C, "SfplyRuntimeStateView::setConditions offset must be 0xA0C"
);
static_assert(
  offsetof(SfplyRuntimeStateView, bpaWindowTicks) == 0xFB4, "SfplyRuntimeStateView::bpaWindowTicks offset must be 0xFB4"
);
static_assert(
  offsetof(SfplyRuntimeStateView, bpaTickRate) == 0xFB8, "SfplyRuntimeStateView::bpaTickRate offset must be 0xFB8"
);
static_assert(
  offsetof(SfplyRuntimeStateView, startSyncBypassFlag) == 0xFE0,
  "SfplyRuntimeStateView::startSyncBypassFlag offset must be 0xFE0"
);
static_assert(
  offsetof(SfplyRuntimeStateView, startSyncCurrentTicks) == 0xFFC,
  "SfplyRuntimeStateView::startSyncCurrentTicks offset must be 0xFFC"
);

struct SfplyDataLaneReaderVtable
{
  std::uint8_t mUnknown00[0x24]{};
  std::int32_t(__cdecl* queryAvailableBytes)(void* laneReader, std::int32_t queryMode) = nullptr; // +0x24
};

static_assert(
  offsetof(SfplyDataLaneReaderVtable, queryAvailableBytes) == 0x24,
  "SfplyDataLaneReaderVtable::queryAvailableBytes offset must be 0x24"
);

struct SfplyDataLaneReader
{
  SfplyDataLaneReaderVtable* dispatchTable = nullptr; // +0x00
};

struct SfplyDataLaneDescriptor
{
  std::uint8_t mUnknown00[0x04]{};
  SfplyDataLaneReader* laneReader = nullptr; // +0x04
  std::uint8_t mUnknown08[0x04]{};
  std::int32_t readyThresholdBytes = 0; // +0x0C
  std::uint8_t mUnknown10[0x64]{};
};

static_assert(
  offsetof(SfplyDataLaneDescriptor, laneReader) == 0x04, "SfplyDataLaneDescriptor::laneReader offset must be 0x04"
);
static_assert(
  offsetof(SfplyDataLaneDescriptor, readyThresholdBytes) == 0x0C,
  "SfplyDataLaneDescriptor::readyThresholdBytes offset must be 0x0C"
);
static_assert(sizeof(SfplyDataLaneDescriptor) == 0x74, "SfplyDataLaneDescriptor size must be 0x74");

struct SfplyDataReadinessIndexView
{
  std::uint8_t mUnknown00[0x1FC8]{};
  std::int32_t activeVideoLaneIndex = 0; // +0x1FC8
  std::uint8_t mUnknown1FCC[0x40]{};
  std::int32_t activeAudioLaneIndex = 0; // +0x200C
};

static_assert(
  offsetof(SfplyDataReadinessIndexView, activeVideoLaneIndex) == 0x1FC8,
  "SfplyDataReadinessIndexView::activeVideoLaneIndex offset must be 0x1FC8"
);
static_assert(
  offsetof(SfplyDataReadinessIndexView, activeAudioLaneIndex) == 0x200C,
  "SfplyDataReadinessIndexView::activeAudioLaneIndex offset must be 0x200C"
);

struct SfplyEndTimeView
{
  std::uint8_t mUnknown00[0xA5C]{};
  std::int32_t endTimeMajor = 0; // +0xA5C
  std::int32_t endTimeMinor = 0; // +0xA60
};

static_assert(offsetof(SfplyEndTimeView, endTimeMajor) == 0xA5C, "SfplyEndTimeView::endTimeMajor offset must be 0xA5C");
static_assert(offsetof(SfplyEndTimeView, endTimeMinor) == 0xA60, "SfplyEndTimeView::endTimeMinor offset must be 0xA60");

[[nodiscard]] static SfplyDataLaneDescriptor*
SfplyGetDataLaneDescriptor(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t laneIndex)
{
  constexpr std::int32_t kLaneTableOffset = 0x1320;
  auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(workctrlSubobj);
  return reinterpret_cast<SfplyDataLaneDescriptor*>(
    runtimeBytes + kLaneTableOffset + (laneIndex * static_cast<std::int32_t>(sizeof(SfplyDataLaneDescriptor)))
  );
}

[[nodiscard]] static const SfplyDataLaneDescriptor*
SfplyGetDataLaneDescriptor(const moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t laneIndex)
{
  constexpr std::int32_t kLaneTableOffset = 0x1320;
  const auto* const runtimeBytes = reinterpret_cast<const std::uint8_t*>(workctrlSubobj);
  return reinterpret_cast<const SfplyDataLaneDescriptor*>(
    runtimeBytes + kLaneTableOffset + (laneIndex * static_cast<std::int32_t>(sizeof(SfplyDataLaneDescriptor)))
  );
}

[[nodiscard]] static std::int32_t SfplyQueryLaneReadyBytes(const SfplyDataLaneDescriptor* const laneDescriptor)
{
  return laneDescriptor->laneReader->dispatchTable->queryAvailableBytes(laneDescriptor->laneReader, 1);
}

static bool SfbufContainsAddress(const moho::SjChunkRange& chunkRange, const std::uint32_t candidateAddress)
{
  const std::uint32_t chunkStart = static_cast<std::uint32_t>(chunkRange.bufferAddress);
  const std::uint32_t chunkEnd = chunkStart + static_cast<std::uint32_t>(chunkRange.byteCount);
  return (candidateAddress >= chunkStart) && (candidateAddress < chunkEnd);
}

static std::int32_t SfbufAringScaledAddress(
  const std::int32_t sampleMode,
  const std::int32_t baseAddress,
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
  virtual void Reserved0C() = 0;
  virtual void Reserved10() = 0;
  virtual void Reset() = 0;
  virtual void AcquireChunk(std::int32_t lane, std::int32_t requestedBytes, SjChunkRange* outChunk) = 0;
  virtual void ReturnChunk(std::int32_t lane, const SjChunkRange* chunk) = 0;
  virtual void CommitChunk(std::int32_t lane, const SjChunkRange* chunk) = 0;
  virtual std::int32_t QueryAvailableBytes(std::int32_t lane) = 0;
};

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

using M2asjdErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* errorMessage);
using M2asjdDecodeCallback =
  std::int32_t(__cdecl*)(std::int32_t callbackObject, M2asjdDecoderState* decoder, std::int32_t callbackContext, std::int32_t producedBytes);

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

using CvFsUserErrorBridgeFn = void(__cdecl*)(std::int32_t errorObjectAddress, const char* message);
using CvFsRegisterUserErrorFn = void(__cdecl*)(CvFsUserErrorBridgeFn bridgeCallback, std::int32_t errorObjectAddress);
using CvFsDeviceOpenFn = std::int32_t(__cdecl*)(char* fileName, std::int32_t openMode, std::int32_t openFlags);
using CvFsCloseBridgeFn = void(__cdecl*)(std::int32_t handleAddress);
using CvFsDeviceOptionFn = std::int32_t(
  __cdecl*
)(void* optionBuffer, std::int32_t optionCode, std::int32_t optionArg0, std::int32_t optionArg1);

struct CvFsDeviceInterfaceView
{
  void* mUnknown00 = nullptr;
  CvFsRegisterUserErrorFn registerUserErrorBridge = nullptr; // +0x04
  void* mUnknown08 = nullptr; // +0x08
  void* mUnknown0C = nullptr; // +0x0C
  CvFsDeviceOpenFn openFile = nullptr; // +0x10
  CvFsCloseBridgeFn closeFile = nullptr; // +0x14
  std::uint8_t mUnknown18[0x48]{}; // +0x18
  CvFsDeviceOptionFn option = nullptr; // +0x60
};

static_assert(
  offsetof(CvFsDeviceInterfaceView, registerUserErrorBridge) == 0x04,
  "CvFsDeviceInterfaceView::registerUserErrorBridge offset must be 0x04"
);
static_assert(offsetof(CvFsDeviceInterfaceView, openFile) == 0x10, "CvFsDeviceInterfaceView::openFile offset must be 0x10");
static_assert(
  offsetof(CvFsDeviceInterfaceView, closeFile) == 0x14, "CvFsDeviceInterfaceView::closeFile offset must be 0x14"
);
static_assert(offsetof(CvFsDeviceInterfaceView, option) == 0x60, "CvFsDeviceInterfaceView::option offset must be 0x60");
static_assert(sizeof(CvFsDeviceInterfaceView) == 0x64, "CvFsDeviceInterfaceView size must be 0x64");

struct CvFsHandleView
{
  CvFsDeviceInterfaceView* interfaceView = nullptr; // +0x00
  std::int32_t handleAddress = 0; // +0x04
};

static_assert(offsetof(CvFsHandleView, interfaceView) == 0x00, "CvFsHandleView::interfaceView offset must be 0x00");
static_assert(offsetof(CvFsHandleView, handleAddress) == 0x04, "CvFsHandleView::handleAddress offset must be 0x04");
static_assert(sizeof(CvFsHandleView) == 0x08, "CvFsHandleView size must be 0x08");

struct CvFsDeviceSlot
{
  CvFsDeviceInterfaceView* interfaceView = nullptr; // +0x00
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

  void ADXPD_Init();
  void ADXPD_Finish();
  void* ADXPD_Create();
  void ADXPD_Destroy(void* adxPacketDecoder);
  void ADXPD_GetDly(void* adxPacketDecoder, std::int16_t* outDelay0, std::int16_t* outDelay1);
  std::int16_t ADXPD_GetExtPrm(
    void* adxPacketDecoder,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  );
  void* ADXPD_SetDly(void* adxPacketDecoder, const std::int16_t* delay0, const std::int16_t* delay1);
  void* ADXPD_SetExtPrm(void* adxPacketDecoder, std::int16_t key0, std::int16_t keyMultiplier, std::int16_t keyAdder);
  std::int32_t ADXPD_SetCoef(void* adxPacketDecoder, std::int32_t sampleRate, std::int16_t coefficientIndex);
  std::int32_t __cdecl ADXPD_EntryMono(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  );
  std::int32_t __cdecl ADXPD_EntryPl2(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  );
  std::int32_t __cdecl ADXPD_EntrySte(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  );
  void* ADXPD_Start(void* adxPacketDecoder);
  void* ADXPD_Stop(void* adxPacketDecoder);
  void* ADXPD_Reset(void* adxPacketDecoder);
  std::int32_t ADXPD_GetNumBlk(void* adxPacketDecoder);
  std::int32_t ADXPD_GetStat(void* adxPacketDecoder);
  void __cdecl ADXPD_ExecHndl(std::int32_t handleAddress);

  int ADXERR_CallErrFunc1_(const char* message);
  int ADXERR_CallErrFunc2_(const char* prefix, const char* message);
  void ADXERR_ItoA2(std::int32_t highWord, std::int32_t lowWord, char* outText, std::int32_t outBytes);
  std::int32_t MWSFLIB_SetErrCode(std::int32_t errorCode);
  std::int32_t MWSFSVM_Error(const char* message, ...);
  std::int32_t MWSFSVM_EntryIdVfunc(
    std::int32_t laneId,
    std::int32_t callbackAddress,
    std::int32_t callbackObject,
    const char* callbackName
  );
  std::int32_t MWSFSVM_EntryMainFunc(std::int32_t callbackAddress, std::int32_t callbackObject, const char* callbackName);
  std::int32_t MWSFSVM_EntryIdleFunc(std::int32_t callbackAddress, std::int32_t callbackObject, const char* callbackName);
  BOOL MWSFSVM_TestAndSet(std::int32_t* signalLane);
  BOOL SVM_TestAndSet(std::int32_t* signalLane);
  void __cdecl MWSFSVR_VsyncThrdProc();
  void __cdecl MWSFSVR_MainThrdProc();
  void __cdecl MWSFSVR_IdleThrdProc();
  void MWSFSVR_SetMwsfdSvrFlg(std::int32_t enabled);
  void mwsflib_LscErrFunc(std::int32_t callbackObject, const char* message);
  void mwsflib_InitLibWork(moho::MwsfdInitPrm* initParams);
  std::int32_t mwsflib_SetDefCond(const float* startupConditionValue);
  void MWSFLIB_SetSeekFlg(std::int32_t enabled);
  std::int32_t MWSFLIB_GetSeekFlg();
  std::int32_t MWSFD_SetCond(std::int32_t laneId, std::int32_t conditionId, std::int32_t value);
  std::int32_t mwPlySfdFinish();
  std::int32_t SFD_Finish();
  std::int32_t SFD_Destroy(void* sfdHandle);
  std::int32_t SFD_IsVersionCompatible(const char* versionText, std::int32_t versionTag);
  std::int32_t SFD_Init(moho::MwsfdInitSfdParams* initParams);
  std::int32_t SFD_SetErrFn(std::int32_t errorObjectAddress, std::int32_t callbackAddress, std::int32_t callbackObject);
  std::int32_t SFD_GetErrInf(std::int32_t errorObjectAddress, void* outErrInfo);
  std::int32_t SFD_Stop(void* sfdHandle);
  std::int32_t SFD_IsSvrWait();
  void SFD_GetFrm(std::int32_t sfdHandleAddress, void** outFrame);
  void SFD_RelFrm(std::int32_t sfdHandleAddress, void* frameAddress);
  std::int32_t SFD_IsNextFrmReady(std::int32_t sfdHandleAddress);
  std::int32_t mwPlyGetSfdHn(moho::MwsfdPlaybackStateSubobj* ply);
  void* MWSFSFX_GetSfxHn(const moho::MwsfdPlaybackStateSubobj* ply);
  void SFX_SetOutBufSize(void* sfxHandle, std::int32_t outputPitch, std::int32_t outputHeight);
  void SFX_SetUnitWidth(void* sfxHandle, std::int32_t unitWidth);
  std::int32_t SFX_GetCompoMode(void* sfxHandle);
  std::int32_t SFD_GetHnStat(void* sfdHandle);
  std::int32_t SFD_SetConcatPlay(void* sfdHandle);
  std::int32_t SFD_GetTime(void* sfdHandle, std::int32_t* outTime, std::int32_t* outScale);
  std::int32_t SFD_SetPicUsrBuf(
    void* sfdHandle,
    std::int32_t bufferAddress,
    std::int32_t frameSlotCount,
    std::int32_t bytesPerFrame
  );
  std::int32_t MWSFD_GetUsePicUsr();
  std::int32_t SFD_SetOutVol(void* sfdHandle, std::int32_t volumeLevel);
  std::int32_t SFD_GetOutVol(void* sfdHandle);
  std::int32_t SFD_SetOutPan(void* sfdHandle, std::int32_t laneIndex, std::int32_t panLevel);
  std::int32_t SFD_GetOutPan(void* sfdHandle, std::int32_t laneIndex);
  std::int32_t SFD_GetPlyInf(std::int32_t sfdHandleAddress, void* outPlyInfo);
  std::int32_t SFD_GetTmrInf(std::int32_t sfdHandleAddress, void* outTimerInfo);
  std::int32_t MWSST_GetStat(moho::MwsstStreamStateSubobj* streamState);
  void MWSST_Stop(moho::MwsstStreamStateSubobj* streamState);
  void MWSST_Destroy(moho::MwsstStreamStateSubobj* streamState);
  std::int32_t MWSST_Pause(moho::MwsstStreamStateSubobj* streamState, std::int32_t paused);
  std::int32_t UTY_CmpTime(
    std::int32_t leftTime,
    std::int32_t timeUnit,
    std::int32_t rightTime,
    std::int32_t currentTime
  );
  std::int32_t SFD_SetUsrSj(std::int32_t sfdHandleAddress, std::int32_t mode, std::int32_t arg0, std::int32_t arg1);
  std::int32_t SFX_SetTagInf(void* sfxHandle, std::int32_t tagDataAddress, std::int32_t tagDataLength);
  void MWSFTAG_DestroyAinfSj(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFTAG_UpdateTagInf(moho::MwsfdPlaybackStateSubobj* ply);
  void MWSFSFX_Destroy(void* sfxHandle);
  void MWSTM_Destroy(void* streamHandle);
  std::int32_t MWSTM_GetStat(void* streamHandle);
  void MWSTM_SetFileRange(
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
  std::int32_t mwsffrm_CheckAinf(std::int32_t playbackAddress, std::int32_t frameInfoAddress);
  void mwl_convFrmInfFromSFD(std::int32_t playbackAddress, std::int32_t sfdFrameAddress, std::int32_t outFrameInfoAddress);
  void mwsffrm_SaveFrmDetail(std::int32_t playbackAddress, std::int32_t sfdFrameAddress);
  std::int32_t mwPlyIsNextFrmReady(moho::MwsfdPlaybackStateSubobj* ply);
  void MWSFCRE_DestroySfd(char* sfdHandleAddress);
  std::int32_t MWSFCRE_SetSupplySj(moho::MwsfdPlaybackStateSubobj* ply);
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
    std::int32_t afsHandle,
    std::int32_t fileIndex,
    char* outFileName,
    std::int32_t* outStartOffset,
    std::int32_t* outRangeStart,
    std::int32_t* outRangeEnd
  );
  const char* ADXF_GetFnameFromPt(std::int32_t afsHandle);
  std::int32_t SFD_ExecOne(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_IsHnSvrWait(std::int32_t sfdHandleAddress);
  void mwPlySfdStart(moho::MwsfdPlaybackStateSubobj* ply);
  void mwPlyPause(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t paused);
  void mwPlyLinkStm(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t linkMode);
  bool MWSTM_IsFsStatErr(std::int32_t streamHandleAddress);
  bool MWSFLSC_IsFsStatErr(void* lscHandle);
  std::int32_t MWSFSVR_SetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);
  std::int32_t MWSFSVR_GetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t MWSFSVR_SetHnSfdSvrFlg(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);
  void mwPlyEntryAfs(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t afsHandle, std::int32_t fileIndex);
  void mwPlyReleaseSeamless(moho::MwsfdPlaybackStateSubobj* ply);
  void mwPlyEntryFnameRange(
    moho::MwsfdPlaybackStateSubobj* ply,
    const char* fname,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  void MWSFD_StartInternalSj(moho::MwsfdPlaybackStateSubobj* ply, moho::SofdecSjRingBufferHandle* ringBufferHandle);
  void MWSFPLY_SetFlowLimit(moho::MwsfdPlaybackStateSubobj* ply);
  void mwlSfdSleepDecSvr(moho::MwsfdPlaybackStateSubobj* ply);
  void mwsfsvr_StartPlayback(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfsvr_StartStream(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwlSfdExecDecSvrPrep(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwlSfdExecDecSvrPlaying(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t mwsfd_CheckFsErr(moho::MwsfdPlaybackStateSubobj* ply);
  void mwsfsvr_CheckSupply();
  std::int32_t mwPlyChkSupply(moho::MwsfdPlaybackStateSubobj* ply);
  std::int32_t sfply_TermSupply(std::int32_t sfdHandleAddress);
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
  void adxt_StartSj(void* adxtRuntime, void* sourceJoinHandle);
  /**
   * Address: 0x00B1ABF0 (FUN_00B1ABF0, _adxt_RcvrReplay)
   *
   * What it does:
   * Recovers one ADXT replay lane after stream/decode errors by stopping active
   * decode transfer, resetting channel lanes, restarting stream read from
   * sector 0, and re-entering SJ decode start.
   */
  void adxt_RcvrReplay(void* adxtRuntime);
  /**
   * Address: 0x00B1ACA0 (FUN_00B1ACA0, _ADXT_ExecErrChk)
   *
   * What it does:
   * Runs one ADXT error-check tick and dispatches configured stop/recover
   * actions for decode, transport, and stream-status fault lanes.
   */
  void ADXT_ExecErrChk(void* adxtRuntime);

  /**
   * Address: 0x00B0D090 (FUN_00B0D090, _adxt_start_sj)
   *
   * What it does:
   * Starts ADXT decode from one SJ input object, resets playback timing lanes,
   * and starts optional channel-expansion lane when present.
   */
  std::int32_t adxt_start_sj(void* adxtRuntime, void* sourceJoinHandle);

  /**
   * Address: 0x00B0D130 (FUN_00B0D130, _adxt_start_stm)
   *
   * What it does:
   * Rebinds ADXT stream file range and starts stream + SJ decode chain for one
   * runtime object.
   */
  std::int32_t adxt_start_stm(
    void* adxtRuntime,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );

  std::int32_t ADXT_SetLnkSw(void* adxtRuntime, std::int32_t enabled);
  std::int32_t SFTRN_IsSetup(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t transferLaneType);
  std::int32_t SFTRN_CallTrtTrif(
    std::int32_t sfbufHandleAddress,
    std::int32_t transferHandleAddress,
    std::int32_t trifCommandId,
    std::int32_t arg0,
    std::int32_t arg1
  );
  std::int32_t sftrn_ConnBufTrn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBuf0(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufV(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufA(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufU(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_BuildUsr(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfset_IsCondValid(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId, std::int32_t value);
  std::int32_t SFSET_SetCond(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId, std::int32_t value);
  std::int32_t SFSET_GetCond(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId);
  std::int32_t SFXINF_GetStmInf(moho::SfxStreamState* streamState, const char* tagName);
  void CFT_Ycc420plnToArgb8888Init();

  /**
   * Address: 0x00AEE730 (FUN_00AEE730, _CFT_Ycc420plnToArgb8888IntInit)
   *
   * What it does:
   * Builds CRI CFT integer YUV->ARGB conversion lookup tables for red/blue/
   * green lanes and one packed intermediate lane.
   */
  void CFT_Ycc420plnToArgb8888IntInit();
  void CFT_Ycc420plnToArgb8888PrgInit();
  void CFT_Ycc420plnToRgb565Init();
  void CFT_Ycc420plnToRgb555Init();
  std::int32_t createBitcutClipTable32_555(std::int32_t* table, std::int8_t componentBits, std::int8_t bitShift);
  void createBitcut5GradPtnDitherClipTable32_555(
    std::int32_t* table,
    std::int8_t componentBits,
    std::int8_t bitShift,
    std::int32_t ditherPatternIndex
  );
  std::int32_t createBitcutClipTable32_565(std::int32_t* table, std::int8_t componentBits, std::int8_t bitShift);
  void createBitcut5GradPtnDitherClipTable32_565(
    std::int32_t* table,
    std::int8_t componentBits,
    std::int8_t bitShift,
    std::int32_t ditherPatternIndex
  );
  void SUD_Init();
  std::int32_t SUD_Finish();
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  std::int32_t sfbuf_InitSjUuid();
  void sfbuf_SetSupSj(
    std::int32_t* supplyLaneWords,
    const std::int32_t* createdSjStateWords,
    std::int32_t ownerAddress,
    std::int32_t ownershipMode
  );
  std::int32_t sfbuf_RingGetSub(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outCursor, std::int32_t laneMode);
  std::int32_t sfbuf_RingAddSub(
    std::int32_t sfbufHandleAddress,
    std::int32_t ringIndex,
    std::int32_t advanceCount,
    std::int32_t laneMode
  );
  std::uint32_t sfbuf_ResetConti(std::int32_t* supplyStateWords);
  std::int32_t sfbuf_PeekChunk(
    std::int32_t ringHandleAddress,
    std::int32_t laneMode,
    moho::SjChunkRange* outFirstChunk,
    moho::SjChunkRange* outSecondChunk
  );
  std::int32_t sfbuf_MoveChunk(std::int32_t ringHandleAddress, std::int32_t laneMode, std::int32_t requestedBytes);
  std::int32_t SFX_DecideTableAlph3(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState);
  void SFX_MakeTable(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState, std::int32_t tableMode);
  void sfxcnv_ExecCnvFrmByCbFunc(
    moho::SfxCallbackFrameContext* conversionState,
    moho::SfxStreamState* streamState,
    std::int32_t callbackArg,
    std::int32_t useLookupTable
  );
  void sfxcnv_ExecFullAlphaByCbFunc(
    moho::SfxCallbackFrameContext* conversionState,
    moho::SfxStreamState* streamState,
    std::int32_t callbackArg
  );
  void SFXLIB_Error(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState, const char* message);
  std::int32_t ADXT_IsInitialized();
  void ADXFIC_Finish();
  char* ADXPC_GetVersion();
  void cvFsFinish();
  char* xeCiFinish();
  void xeCiInit();

  /**
   * Address: 0x00B110F0 (FUN_00B110F0, xedir_new_handle)
   *
   * What it does:
   * Returns the first free XECI object lane from the fixed global pool.
   */
  XeciObject* xedir_new_handle();

  /**
   * Address: 0x00B111C0 (FUN_00B111C0, _xeCiOpen)
   *
   * What it does:
   * Opens one XECI stream object and initializes transfer geometry.
   */
  XeciObject* __cdecl xeCiOpen(const char* fileName, std::int32_t openMode, std::int32_t readWriteFlag);

  /**
   * Address: 0x00B11440 (FUN_00B11440, _xeCiReqRead)
   *
   * What it does:
   * Arms one chunked XECI read request and validates DMA/alignment constraints.
   */
  std::int32_t __cdecl xeCiReqRead(XeciObject* object, std::int32_t requestedChunkCount, void* readBuffer);

  /**
   * Address: 0x00B118B0 (FUN_00B118B0, _xeci_create_func)
   *
   * What it does:
   * Opens one file handle for XECI reads, honoring the current read-mode lane.
   */
  HANDLE __cdecl xeci_create_func(LPCSTR fileName);

  /**
   * Address: 0x00B11A90 (FUN_00B11A90, _xeDirSetRootDir)
   *
   * What it does:
   * Resolves and stores one CVFS root directory path and appends a trailing
   * `\\` separator when missing.
   */
  std::int32_t xeDirSetRootDir(const char* rootDirectory);
  std::int32_t cvFsEntryErrFunc(std::int32_t errorCallbackAddress, std::int32_t errorObjectAddress);
  std::int32_t cvFsSetDefDev(const char* deviceName);
  std::int32_t cvFsError_(const char* message);
  void cvFsCallUsrErrFn(std::int32_t errorObjectAddress, const char* message);

  /**
   * Address: 0x00B11F40 (FUN_00B11F40, _addDevice)
   *
   * What it does:
   * Registers one CVFS device interface in the fixed device table.
   */
  CvFsDeviceInterfaceView* addDevice(const char* deviceName, void* (__cdecl* deviceFactory)());

  /**
   * Address: 0x00B11FB0 (FUN_00B11FB0, _getDevice)
   *
   * What it does:
   * Resolves one CVFS device name prefix to its registered interface.
   */
  CvFsDeviceInterfaceView* getDevice(const char* deviceName);

  /**
   * Address: 0x00B12040 (FUN_00B12040, _cvFsDelDev)
   *
   * What it does:
   * Clears one CVFS device-table slot by device-name prefix.
   */
  std::int32_t cvFsDelDev(const char* deviceName);

  /**
   * Address: 0x00B12160 (FUN_00B12160, _cvFsOpen)
   *
   * What it does:
   * Opens one CVFS handle through the selected device interface.
   */
  extern "C" CvFsHandleView* cvFsOpen(char* fileName, std::int32_t openMode, std::int32_t openFlags);

  /**
   * Address: 0x00B12290 (FUN_00B12290, _variousProc)
   *
   * What it does:
   * Resolves effective device + rewritten path for CVFS open operations.
   */
  CvFsDeviceInterfaceView* variousProc(char* deviceName, char* filePath, const char* originalPath);

  /**
   * Address: 0x00B12300 (FUN_00B12300, _allocCvFsHn)
   *
   * What it does:
   * Returns one free entry from the fixed CVFS handle pool.
   */
  CvFsHandleView* allocCvFsHn();

  /**
   * Address: 0x00B12350 (FUN_00B12350, _getDevName)
   *
   * What it does:
   * Splits device prefix (`DEV:`) and relative path from one CVFS file name.
   */
  void getDevName(char* outDeviceName, char* outFilePath, const char* fileName);

  /**
   * Address: 0x00B12400 (FUN_00B12400, _getDefDev)
   *
   * What it does:
   * Copies configured default device name into caller buffer.
   */
  char getDefDev(char* outDeviceName);

  /**
   * Address: 0x00B13320 (FUN_00B13320, _cvFsSetDefVol)
   *
   * What it does:
   * Dispatches default-volume option request to one CVFS device.
   */
  void cvFsSetDefVol(char* deviceName, std::int32_t volumeName);

  /**
   * Address: 0x00B133B0 (FUN_00B133B0, _isNeedDevName)
   *
   * What it does:
   * Queries whether one CVFS device requires explicit device-prefix paths.
   */
  std::int32_t isNeedDevName(char* deviceName);

  /**
   * Address: 0x00B133E0 (FUN_00B133E0, _addDevName)
   *
   * What it does:
   * Prefixes `DEV:` onto one path when the target device requires it.
   */
  std::int32_t addDevName(char* deviceName, char* filePath);

  void* mfCiGetInterface();
  void* xeCiGetInterface();
  void adxt_detach_ahx();
  void adxt_detach_mpa(void* adxtRuntime);
  void adxt_detach_m2a(void* adxtRuntime);
  void adxt_Stop(void* adxtRuntime);
  void ADXSJD_Stop(std::int32_t sjdHandle);
  void ADXSJD_SetInSj(std::int32_t sjdHandle, void* sourceJoinHandle);
  std::int32_t ADXSJD_Start(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetLnkSw(std::int32_t sjdHandle, std::int32_t enabled);
  std::int32_t ADXSJD_GetStat(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetDecNumSmpl(std::int32_t sjdHandle);
  std::int32_t ADXAMP_Start(void* channelExpandHandle);
  void ADXAMP_Stop(void* channelExpandHandle);
  void CRIERR_CallErr(const char* message);
  void j__ADXRNA_Stop(std::int32_t rnaHandle);
  void j__ADXRNA_SetTransSw(std::int32_t rnaHandle, std::int32_t enabled);
  void j__ADXRNA_SetPlaySw(std::int32_t rnaHandle, std::int32_t enabled);
  void ADXRNA_Destroy(std::int32_t rnaHandle);
  void ADXSJD_Destroy(std::int32_t sjdHandle);
  void* adxf_AllocAdxFs();
  void* ADXSTM_Create(std::int32_t mode, std::int32_t reserveSectors);
  void ADXSTM_EntryEosFunc(std::int32_t streamHandleAddress, std::int32_t callbackAddress, std::int32_t callbackContext);
  void ADXSTM_StopNw(void* streamHandle);
  void ADXSTM_ReleaseFileNw(void* streamHandle);
  void ADXSTM_BindFileNw(
    void* streamHandle,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  void ADXSTM_SetEos(void* streamHandle, std::int32_t eosSector);
  void ADXSTM_SetBufSize(void* streamHandle, std::int32_t minBufferSectors, std::int32_t maxBufferSectors);
  void ADXSTM_SetReqRdSize(void* streamHandle, std::int32_t requestedSectors);
  void ADXSTM_SetPause(void* streamHandle, std::int32_t paused);
  void ADXSTM_SetSj(void* streamHandle, void* sourceJoinObject);
  void ADXSTM_Seek(void* streamHandle, std::int32_t sectorOffset);
  void ADXSTM_Start(void* streamHandle);
  void ADXSTM_Start2(void* streamHandle, std::int32_t sectorCount);
  std::int32_t ADXSTM_GetStat(void* streamHandle);
  std::int32_t ADXSTM_Tell(void* streamHandle);
  void ADXSTM_Stop(void* streamHandle);
  void ADXSTM_Destroy(void* streamHandle);
  std::int32_t LSC_CallErrFunc_(const char* format, ...);
  void LSC_Destroy(void* lscHandle);
  void ADXAMP_Destroy(void* channelExpandHandle);
  int ADX_DecodeSteFloatAsMono(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t decodeScale,
    float scaleFactor
  );
  int ADX_DecodeSteFloatAsSte(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t decodeScale,
    float scaleFactor
  );

  int HEAPMNG_Allocate(int heapManagerHandle, SIZE_T byteCount, int* outPointer);
  int HEAPMNG_Free(int heapManagerHandle, int pointerValue);

  void SJCRS_Init();
  std::int32_t SJCRS_Finish();

  /**
   * Address: 0x00B0C340 (FUN_00B0C340, _SVM_CallErr)
   *
   * What it does:
   * Formats one SVM error message and dispatches it through registered
   * SVM error-callback lane.
   */
  void SVM_CallErr(const char* format, ...);

  /**
   * Address: 0x00B0C1E0 (FUN_00B0C1E0, _svm_lock)
   *
   * What it does:
   * Executes one configured SVM lock callback and updates lock nesting/type
   * state.
   */
  void svm_lock(std::int32_t lockType);

  /**
   * Address: 0x00B0C230 (FUN_00B0C230, _svm_unlock)
   *
   * What it does:
   * Executes one configured SVM unlock callback and validates lock-type
   * symmetry when leaving the outermost lock level.
   */
  void svm_unlock(std::int32_t lockType);

  /**
   * Address: 0x00B0C1D0 (FUN_00B0C1D0, _SVM_Lock)
   *
   * What it does:
   * Enters SVM lock lane using default lock-type token `1`.
   */
  void SVM_Lock();

  /**
   * Address: 0x00B0C220 (FUN_00B0C220, _SVM_Unlock)
   *
   * What it does:
   * Leaves SVM lock lane using default lock-type token `1`.
   */
  void SVM_Unlock();
  int M2ABSR_Read(std::int32_t bitstreamHandle, std::int32_t bitCount, void* outBits);
  int M2ABSR_Tell(std::int32_t bitstreamHandle, std::int32_t* outBitPosition);
  int M2ABSR_Seek(std::int32_t bitstreamHandle, std::int32_t bitPosition, std::int32_t origin);
  int M2ABSR_Overruns(std::int32_t bitstreamHandle, std::int32_t* outOverrunFlag);
  int M2ABSR_AlignToByteBoundary(std::int32_t bitstreamHandle);
  int M2ABSR_Initialize();
  int M2ABSR_Finalize();
  int M2ABSR_Create(std::int32_t heapManagerHandle, std::int32_t** outBitstream);
  int M2ABSR_Destroy(std::int32_t* bitstreamHandle);
  int M2ABSR_Reset(std::uint32_t* bitstreamState);
  int M2ABSR_SetBuffer(std::uint32_t* bitstreamState, std::int32_t sourceBuffer, std::int32_t sourceBytes);
  int M2ABSR_IsEndOfBuffer(std::int32_t bitstreamHandle, std::int32_t* outIsEnd);
  int M2AHUFFMAN_Initialize();
  int M2AHUFFMAN_Finalize();
  int M2AIMDCT_Initialize();
  int M2AIMDCT_Finalize();
  std::int32_t M2ADEC_Initialize();
  std::int32_t M2ADEC_Finalize();

  std::int32_t __cdecl M2ADEC_Reset(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_GetStatus(M2aDecoderContext* context, std::int32_t* outStatus);
  std::int32_t __cdecl M2ADEC_GetErrorCode(M2aDecoderContext* context, std::int32_t* outErrorCode);
  std::int32_t __cdecl M2ADEC_Start(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_Stop(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_Process(
    M2aDecoderContext* context,
    std::int32_t sourceAddress,
    std::int32_t sourceBytes,
    std::int32_t* outConsumedBytes
  );
  std::int32_t __cdecl M2ADEC_GetPendingSupply(M2aDecoderContext* context, std::int32_t* outPendingSupply);
  std::int32_t __cdecl M2ADEC_BeginFlush(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_GetNumFramesDecoded(M2aDecoderContext* context, std::int32_t* outFrameCount);
  std::int32_t __cdecl M2ADEC_GetNumSamplesDecoded(M2aDecoderContext* context, std::int32_t* outSampleCount);
  std::int32_t __cdecl M2ADEC_GetProfile(M2aDecoderContext* context, std::int32_t* outProfile);
  std::int32_t __cdecl M2ADEC_GetFrequency(M2aDecoderContext* context, std::int32_t* outFrequency);
  std::int32_t __cdecl M2ADEC_GetNumChannels(M2aDecoderContext* context, std::int32_t* outChannelCount);
  std::int32_t __cdecl M2ADEC_GetChannelConfiguration(M2aDecoderContext* context, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl M2ADEC_GetPcm(M2aDecoderContext* context, std::int32_t channelIndex, std::int32_t destinationAddress);
  std::int32_t __cdecl M2ADEC_GetDownmixedPcm(
    M2aDecoderContext* context,
    std::int32_t outputChannelIndex,
    std::int32_t destinationAddress
  );
  std::int32_t __cdecl M2ADEC_GetSurroundPcm(
    M2aDecoderContext* context,
    std::int32_t outputChannelIndex,
    std::int32_t destinationAddress
  );
  HANDLE __cdecl m2adec_malloc(std::int32_t heapManagerHandle, SIZE_T byteCount);
  HANDLE __cdecl m2adec_free(std::int32_t heapManagerHandle, LPVOID memoryBlock);
  std::int32_t __cdecl m2adec_decode_header(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_header_type(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outHeaderType
  );
  std::int32_t __cdecl m2adec_get_adif_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_fixed_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_variable_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_crc_check(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_elements(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_sce(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_cpe(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_sce_initialize(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_cpe_initialize(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_ics(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ics_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ms_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ms_info8(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_pcm(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_dse(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_fil(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_pce(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_specify_location(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_find_sync_offset(void* state, std::int32_t* outOffset);
  std::int32_t __cdecl m2adec_convert_to_pcm16(float* sourceSamples, std::int32_t destinationAddress);

  int __cdecl mpabdr_Init();
  int __cdecl mpabdr_Finish();
  int __cdecl MPARBF_SetUsrMallocFunc(std::int32_t allocatorFunctionAddress);
  int __cdecl MPARBF_SetUsrFreeFunc(std::int32_t freeFunctionAddress);
  int __cdecl MPARBF_Create(std::int32_t bufferBytes, std::int32_t* outHandle);
  int __cdecl MPARBF_Destroy(std::int32_t* handleAddress);
  int __cdecl MPARBF_Reset(std::int32_t handleAddress);
  int __cdecl MPARBF_GetDataSize(std::int32_t bitReaderHandle, std::uint32_t* outDataBytes);
  int __cdecl MPARBF_GetFreeSize(std::int32_t bitReaderHandle, std::uint32_t* outFreeBytes);
  int __cdecl MPARBF_ReadData(
    std::int32_t bitReaderHandle,
    char* destinationBytes,
    std::uint32_t byteCount,
    std::uint32_t* outReadBytes
  );
  int __cdecl MPARBF_WriteData(
    std::int32_t bitReaderHandle,
    std::int32_t sourceAddress,
    std::uint32_t byteCount,
    std::uint32_t* outWrittenBytes
  );
  int __cdecl MPARBF_ReturnData(
    std::int32_t bitReaderHandle,
    std::uint32_t returnBytes,
    std::uint32_t* outReturnedBytes
  );
  std::int32_t __cdecl mparbd_Create(MparbdDecoderState** outDecoder);
  std::int32_t __cdecl mparbd_Destroy(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_Reset(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_ExecHndl(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_start_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_prep_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_dechdr_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_decsmpl_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_decend_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPARBD_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  );
  std::int32_t __cdecl mparbd_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  );
  std::int32_t __cdecl MPARBD_GetNumByteDcd(MparbdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl MPARBD_GetSfreq(MparbdDecoderState* decoder, std::int32_t* outSampleRate);
  std::int32_t __cdecl MPARBD_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl mparbd_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl MPARBD_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl mparbd_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl MPARBD_TermSupply(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_TermSupply(MparbdDecoderState* decoder);
  std::int32_t __cdecl mpadcd_GetHdrInfo(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_GetBitAllocInfo(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_GetScfInfo(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_GetSmpl(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_DequantizeSmpl(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_GetPcmSmpl(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_SkipToNextFrm(std::uint32_t* state);
  void* M2AIMDCT_GetWindow(std::int32_t windowSequence, std::int32_t windowShape);
  int M2AIMDCT_TransformShort(float* spectralData, void* previousWindow, void* currentWindow, float* overlapBuffer);
  int M2AIMDCT_TransformLong(float* spectralData, void* previousWindow, void* currentWindow, float* overlapBuffer);
  /**
   * Address: 0x00B255A0 (_m2adec_copy)
   *
   * What it does:
   * Copies one M2A runtime buffer lane and returns copied byte count.
   */
  std::uint32_t m2adec_copy(void* destination, const void* source, std::size_t byteCount);
  std::int32_t __cdecl m2adec_clear(void* destination, std::uint32_t byteCount);
  int M2AHUFFMAN_GetCodebook(int index, std::uintptr_t* outCodebook);
  int M2AHUFFMAN_Decode(int codebookHandle, int bitstreamHandle);
  int M2AHUFFMAN_Unpack(
    std::uint32_t* codebook,
    int packedValue,
    std::int32_t* outValues,
    std::int32_t* outDimension,
    int bitstreamHandle
  );
  int M2AHUFFMAN_GetEscValue(int valuesHandle, int bitstreamHandle);
  extern float m2adec_tns_decode_table[];
  extern std::int32_t m2adec_frequency_table[];
  extern std::int32_t m2adec_num_spectra_per_sfb[];
  extern std::int32_t m2adec_num_spectra_per_sfb8[];
  using XeciErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* errorMessage, std::int32_t errorCode);
  using XeciReadFileCallback = BOOL(
    __cdecl*
  )(HANDLE fileHandle, LPVOID buffer, DWORD bytesToRead, LPDWORD outBytesRead, LPOVERLAPPED overlapped);
  using XeciOpenProbeCallback =
    HANDLE(__cdecl*)(const char* fileName, std::int32_t* outFileSizeLow, std::int32_t* outFileSizeHigh);
  using XeciPathFileSizeProbeCallback = std::int32_t(__cdecl*)(const char* fileName);
  using XeciServerIdleCallback = void(__cdecl*)(std::int32_t callbackObject);

  char* __cdecl xeDirAppendRootDir(char* outputPath, const char* relativeOrAbsolutePath);
  std::int64_t __cdecl xeci_GetFileSizeResolved(const char* fileName);
  std::int32_t __cdecl xeCiGetFileSize(const char* fileName);
  std::int32_t __cdecl xeCiOptionFunc(const void* optionTarget, std::int32_t optionCode);
  std::int32_t __cdecl xeCiSeek(XeciObject* object, std::int32_t offset, std::int32_t originMode);
  std::int32_t __cdecl xeCiTell(const XeciObject* object);
  std::int32_t __cdecl xeCiGetStat(const XeciObject* object);
  std::int32_t __cdecl xeCiGetSctLen(const XeciObject* object);
  std::uint64_t __cdecl xeci_GetFileSizeFromPath(const char* fileName);
  char* __cdecl xeDirAppendRootDirThunk(char* outputPath, const char* relativeOrAbsolutePath);
  std::int32_t __cdecl xeCiGetFileSizeLower(const char* fileName);

  std::int64_t __cdecl xeCiGetFileSizeByHndl(const XeciObject* object);
  BOOL __cdecl xeci_obj_read_from_file(XeciObject* object);
  void __cdecl xeci_obj_update(XeciObject* object);
  std::int32_t __cdecl xeci_has_active_transfer();
  void __cdecl xeCiExecServer();
  HANDLE __cdecl xeci_obj_init(XeciObject* object);
  std::int32_t __cdecl xeci_obj_overlap_cleanup(XeciObject* object);
  std::int32_t __cdecl xeCiGetNumTr(const XeciObject* object);
  void __cdecl xeci_obj_cleanup(XeciObject* object);
  void __cdecl xeci_obj_handle_cleanup(HANDLE objectHandle);
  std::uint64_t __cdecl xeUtyGetFileSizeEx(HANDLE fileHandle);
  std::uint64_t __cdecl xeCiGetNumTrUpper(const XeciObject* object);
  std::int32_t __cdecl xeCiGetNumTrLower(const XeciObject* object);
  std::int32_t __cdecl xeCiGetFileSizeUpper(const XeciObject* object);

  void __cdecl xeci_set_read_mode(
    std::int32_t unusedOptionA,
    std::int32_t unusedOptionB,
    std::int32_t unusedOptionC,
    std::int32_t readMode
  );
  void __cdecl xeci_request_async_abort();
  void wxCiLock_init();
  void wxCiLock_destroy();
  std::int32_t wxCiLock();
  void wxCiUnLock();
  std::int32_t wxCiLock_get_count();
  DWORD xeci_get_chunk_size();
  DWORD __cdecl xeci_set_chunk_size(DWORD chunkSizeBytes);
  BOOL __cdecl xeci_read_file(
    HANDLE fileHandle,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  );
  BOOL __cdecl xeci_read_amt_from_file(
    HANDLE fileHandle,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  );
  void __cdecl xeci_lock();
  void __cdecl xeci_unlock();
  std::int32_t xeci_lock_count();
  void __cdecl xeci_lock_n(std::int32_t lockCount);
  std::int32_t __cdecl xeci_obj_update_overlapped(XeciObject* object);
  BOOL SofdecSetTrueThunk(std::int32_t* signalLane);

  /**
   * Address: 0x00B11B50 (xeci_error)
   *
   * What it does:
   * Forwards one XECI error message through `xeci_assert`.
   */
  int __cdecl xeci_error(std::int32_t callbackObject, const char* errorMessage);
  std::int32_t __cdecl M2ASJD_SetCbErr(M2asjdErrorCallback callback, std::int32_t callbackObject);
  std::int32_t __cdecl M2ASJD_Init();
  std::int32_t __cdecl M2ASJD_Finish();
  std::int32_t __cdecl m2asjd_SetCbDcd(M2asjdDecodeCallback decodeCallback, std::int32_t callbackObject);
  std::int32_t __cdecl m2asjd_default_callback(std::int32_t callbackObject, const char* errorMessage);
  std::int32_t __cdecl m2asjd_Init();
  std::int32_t __cdecl m2asjd_Finish();
  std::int32_t __cdecl M2ASJD_SetCbDcd(M2asjdDecodeCallback decodeCallback, std::int32_t callbackObject);
  std::int32_t __cdecl M2ASJD_Reset(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Reset(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_Start(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Start(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_Stop(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Stop(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_GetStat(M2asjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl m2asjd_GetStat(M2asjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl M2ASJD_GetNumChannels(M2asjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl m2asjd_GetNumChannels(M2asjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl M2ASJD_GetChannelConfig(M2asjdDecoderState* decoder, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl m2asjd_GetChannelConfig(M2asjdDecoderState* decoder, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl M2ASJD_GetFrequency(M2asjdDecoderState* decoder, std::int32_t* outFrequency);
  std::int32_t __cdecl m2asjd_GetFrequency(M2asjdDecoderState* decoder, std::int32_t* outFrequency);
  std::int32_t __cdecl M2ASJD_GetNumBits(M2asjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl m2asjd_GetNumBits(M2asjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl M2ASJD_GetNumSmplsDcd(M2asjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl m2asjd_GetNumSmplsDcd(M2asjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl M2ASJD_GetNumBytesDcd(M2asjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl m2asjd_GetNumBytesDcd(M2asjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl M2ASJD_GetDownmixMode(M2asjdDecoderState* decoder, std::int32_t* outDownmixMode);
  std::int32_t __cdecl m2asjd_GetDownmixMode(M2asjdDecoderState* decoder, std::int32_t* outDownmixMode);
  std::int32_t __cdecl M2ASJD_SetDownmixMode(M2asjdDecoderState* decoder, std::int32_t downmixMode);
  std::int32_t __cdecl m2asjd_SetDownmixMode(M2asjdDecoderState* decoder, std::int32_t downmixMode);
  std::int32_t __cdecl M2ASJD_TermSupply(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_TermSupply(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_ExecServer();
  std::int32_t __cdecl M2ASJD_ExecHndl(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_ExecServer();
  std::int32_t __cdecl m2asjd_ExecHndl(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_input_proc(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_proc(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_stereo(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_surround(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_adx(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Destroy(M2asjdDecoderState* decoder);
  SjChunkRange* __cdecl SJ_SplitChunk(
    const SjChunkRange* sourceChunk,
    std::int32_t splitBytes,
    SjChunkRange* outHeadChunk,
    SjChunkRange* outTailChunk
  );
  std::int32_t __cdecl sub_B1F9D0(XeficObject* object);
  XeficQueuedFileEntry* __cdecl xefic_obj_pop(XeficObject* object);
  DWORD __stdcall xeci_thread_server(LPVOID threadParameter);

  std::uint8_t* adxb_ResetAinf(moho::AdxBitstreamDecoderState* decoder);
  int ADXB_CheckSpsd(const std::uint8_t* headerBytes);
  int ADXB_CheckWav(const std::uint8_t* headerBytes);
  int ADXB_CheckAiff(const std::uint8_t* headerBytes);
  int ADXB_CheckAu(const std::uint8_t* headerBytes);
  int ADXB_CheckMpa(const std::uint8_t* headerBytes);
  int ADXB_CheckM2a(const std::uint8_t* headerBytes);

  int ADXB_DecodeHeaderSpsd(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderWav(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderAiff(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderAu(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderMpa(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderM2a(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  std::int32_t __cdecl ADXB_ExecOneWav(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneSpsd(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAiff(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAu(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAhx(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneMpa(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneM2a(std::int32_t decoderAddress);
  struct SflibErrorInfo;
  struct SflibLibWorkRuntime;
  using SflibErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, std::int32_t errorCode);
  std::int32_t SFHDS_Init();
  std::int32_t SFHDS_Finish();
  std::int32_t SFPLY_Init();
  std::int32_t sfply_ChkCondDfl();
  std::int32_t sfply_StatStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatPrep(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_FixAvPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustSyncMode(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatStby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsStartSync(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ChkBpa(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsBpaOn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsBpaOff(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_VbIn();
  void SFD_VbOut();
  std::int32_t sfply_ExecOneSub(std::int32_t workctrlAddress);
  std::int32_t sfply_TrExecServer(std::int32_t workctrlAddress);
  std::int32_t SFSEE_ExecServer(std::int32_t workctrlAddress);
  std::int32_t SFSEE_FixAvPlay(std::int32_t workctrlAddress, std::int32_t condition5State, std::int32_t condition6State);
  std::int32_t sfply_ExecOne(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ChkFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsEtime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsStagnant(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsPlayTimeAutoStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_Fin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  moho::SofdecSfdWorkctrlSubobj* sfply_Create(const moho::SfplyCreateParams* createParams, std::int32_t createContext);
  std::int32_t sfply_ChkCrePara(const moho::SfplyCreateParams* createParams);
  std::int32_t sfply_SearchFreeHn();
  std::int32_t sfply_InitMvInf(moho::SfplyMovieInfo* movieInfo);
  std::int32_t sfply_InitPlyInf(moho::SfplyPlaybackInfo* playbackInfo);
  moho::SfplyFlowCount* sfply_InitFlowCnt(moho::SfplyFlowCount* flowCount);
  std::int32_t sfply_InitTmrInf(moho::SfplyTimerInfo* timerInfo);
  std::int32_t SFPLY_AddDecPic(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t decodedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t SFPLY_AddSkipPic(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t skippedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t sfply_TrCreate(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_TrDestroy(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_Start(void* sfdHandle);
  std::int32_t sfply_Start(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_TrStart(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_Stop(void* sfdHandle);
  std::int32_t SFPLY_Stop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFPLY_SetResetFlg(std::int32_t enabled);
  std::int32_t SFPLY_GetResetFlg();
  std::int32_t sfply_TrStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ResetHn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  moho::SofdecSfdWorkctrlSubobj* sfply_InitHn(const moho::SfplyCreateParams* createParams, std::int32_t createContext);
  std::int32_t sfply_IsAnyoneTerm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_EnoughViData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_EnoughAiData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  void SFPLY_MeasureFps(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFPL2_Pause(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t paused);
  std::int32_t SFPL2_Standby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFHDS_FinishFhd(void* fileHeaderState);
  void SFBUF_DestroySj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFTMR_InitTsum(void* timerSummary);
  std::int32_t SFTIM_VbIn();
  void SFTIM_GetTime(std::int32_t workctrlAddress, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  std::int32_t SFTIM_GetTimeSub(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFTIM_IsStagnant(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_CmpTime(
    std::int32_t lhsIntegerPart,
    std::int32_t lhsFractionalPart,
    std::int32_t rhsIntegerPart,
    std::int32_t rhsFractionalPart
  );
  std::int32_t UTY_IsTmrVoid();
  std::int32_t UTY_MulDiv(std::int32_t lhs, std::int32_t rhs, std::int32_t divisor);
  void ADXCRS_Lock();
  void ADXCRS_Unlock();
  std::int32_t sflib_InitLibWork(const moho::MwsfdInitSfdParams* initParams);
  void sflib_InitBaseLib();
  void sflib_InitSub();
  void sflib_InitCs();
  SflibErrorInfo* sflib_InitErr(SflibErrorInfo* errInfo);
  SflibErrorInfo*
  sflib_SetErrFnSub(SflibErrorInfo* errInfo, SflibErrorCallback callback, std::int32_t callbackObject);
  SflibLibWorkRuntime* sflib_InitResetPara(SflibLibWorkRuntime* libWork);
  void SFTIM_Init(void* timerState, std::int32_t versionTag);
  void SFTIM_Finish(void* timerState);
  void sflib_FinishCs();
  std::int32_t sflib_FinishSub();
  std::int32_t sflib_FinishBaseLib();
  extern std::int32_t(__cdecl* ahxsetsjifunc)(void* ahxDecoderHandle);
  extern void(__cdecl* ahxsetdecsmplfunc)(void* ahxDecoderHandle, std::int32_t maxDecodeSamples);
  extern std::int32_t(__cdecl* ahxexecfunc)();
  extern std::int32_t(__cdecl* ahxtermsupplyfunc)(void* ahxDecoderHandle);
  extern std::int32_t adxt_q12_mix_table[];

  extern void(__cdecl* ahxsetextfunc)(void* ahxDecoderHandle, const std::int16_t* extParams);
  extern M2asjdDecodeCallback m2asjd_dcd_func;
  extern std::int32_t m2asjd_dcd_obj;
  extern M2asjdDecoderState* m2asjd_entry;
  extern LONG m2asjd_init_count;
  extern CRITICAL_SECTION m2asjd_crs;
  extern CRITICAL_SECTION mpasjd_crs;
  extern M2asjdErrorCallback m2asjd_err_func;
  extern std::int32_t m2asjd_err_obj;
  extern CRITICAL_SECTION xefic_lock_obj;
  extern XeficObject xefic_crs[16];
  extern void(__cdecl* xefic_work_complete_callback)(XeficObject* object);
  extern HANDLE xeci_thread;
  extern std::int32_t xeci_is_done;
  extern std::int32_t xeci_old_thread_prio;
  extern XeciErrorCallback xeci_err_func;
  extern std::int32_t xeci_err_obj;
  extern XeciOpenProbeCallback xeci_open_probe_callback;
  extern XeciReadFileCallback wxCiLock_fn;
  extern LONG wxCiLock_inited;
  extern std::int32_t wxCiLock_count;
  extern CRITICAL_SECTION wxCiLock_obj;
  extern std::int32_t xeci_read_file_mode;
  extern std::int32_t xeci_obj_currently_reading;
  extern std::int32_t xeci_async_abort_requested;
  extern DWORD xeci_chunk_size;
  extern char wxfic_cache_file[0x140];
  extern XeciObject xedir_work[80];
  extern std::array<char, MAX_PATH> gXeDirRootDirectory;
  extern moho::AdxmErrorCallback crierr_callback_func;
  extern std::int32_t crierr_callback_obj;
  extern char crierr_err_msg[0x100];
  extern std::int32_t mwsfd_init_flag;

  std::int16_t adxb_def_k0 = 0;
  std::int16_t adxb_def_km = 0;
  std::int16_t adxb_def_ka = 0;
  std::int32_t adxb_dec_err_mode = 0;
  std::int32_t adx_decode_output_mono_flag = 0;
  std::int32_t adxt_output_mono_flag = 0;
  std::int32_t skg_init_count = 0;
  moho::AdxBitstreamDecoderState adxb_obj[32]{};
  moho::AdxrnaTimingState adxrna_timing_pool[32]{};
  std::int32_t(__cdecl* adxrna_GetTime)() = nullptr;
  using AdxtCodecStopCallback = void(__cdecl*)(void* runtimeHandle);
  AdxtCodecStopCallback mpastopfunc = nullptr;
  AdxtCodecStopCallback m2astopfunc = nullptr;
  extern std::int16_t skg_prim_tbl[1024];
  MparbdErrorCallback mparbd_err_func = nullptr;
  std::int32_t mparbd_err_param = 0;
  MparbdUserMallocCallback mparbd_malloc_func = nullptr;
  MparbdUserFreeCallback mparbd_free_func = nullptr;
  MparbdUserMallocCallback mparbf_malloc_func = nullptr;
  MparbdUserFreeCallback mparbf_free_func = nullptr;
  HANDLE m2adec_global_heap = nullptr;
  std::int32_t mparbd_init_count = 0;
  MparbdDecoderState* mparbd_entry = nullptr;
  M2asjdDecodeCallback m2asjd_dcd_func = nullptr;
  std::int32_t m2asjd_dcd_obj = 0;
  M2asjdDecoderState* m2asjd_entry = nullptr;
  LONG m2asjd_init_count = 0;
  CRITICAL_SECTION m2asjd_crs{};
  CRITICAL_SECTION mpasjd_crs{};
  M2asjdErrorCallback m2asjd_err_func = nullptr;
  std::int32_t m2asjd_err_obj = 0;
  XeciErrorCallback xeci_err_func = nullptr;
  std::int32_t xeci_err_obj = 0;
  XeciOpenProbeCallback xeci_open_probe_callback = nullptr;
  XeciPathFileSizeProbeCallback xeci_file_size_probe_callback = nullptr;
  XeciServerIdleCallback xeci_server_idle_callback = nullptr;
  XeciReadFileCallback wxCiLock_fn = nullptr;
  LONG wxCiLock_inited = 0;
  std::int32_t wxCiLock_count = 0;
  CRITICAL_SECTION wxCiLock_obj{};
  std::int32_t xeci_read_file_mode = 0;
  std::int32_t xeci_obj_currently_reading = 0;
  std::int32_t xeci_async_abort_requested = 0;
  DWORD xeci_chunk_size = 0x8000u;
  char wxfic_cache_file[0x140]{};
  XeciObject xedir_work[80]{};
  float m2asjd_downmix_table[4] = {0.5f, 0.35355338f, 0.25f, 0.0f};
  float m2asjd_downmix_buffer[1024]{};

  std::int32_t gSofdecSjRingBufferInitCount = 0;
  std::int32_t gSofdecSjMemoryInitCount = 0;
  std::int32_t gSofdecSjUnifyInitCount = 0;
  moho::SofdecSjRingBufferHandle gSofdecSjRingBufferPool[0x300]{};
  moho::SofdecSjMemoryHandle gSofdecSjMemoryPool[0x60]{};
  moho::SofdecSjUnifyHandle gSofdecSjUnifyPool[0xC0]{};
  std::int32_t gSofdecSjRingBufferVtableTag = 0;
  std::int32_t gSofdecSjMemoryVtableTag = 0;
  std::int32_t gSofdecSjUnifyVtableTag = 0;
  std::int32_t gSofdecSjRingBufferUuidTag = 0;
  std::int32_t gSofdecSjMemoryUuidTag = 0;
  std::int32_t gSofdecSjUnifyUuidTag = 0;
  std::int32_t gSfbufSjRingBufferUuid = 0;
  std::int32_t gSfbufSjMemoryUuid = 0;
  std::int32_t gAdxpcDvdErrorReportingEnabled = 0;
  moho::SofdecSoundPort gSofdecSoundPortPool[32]{};
  IDirectSound* gSofdecDirectSound = nullptr;
  IDirectSoundBuffer* gSofdecRestoreProbeBuffer = nullptr;
  std::int32_t gSofdecDirectSoundVersionTag = 0;
  std::int32_t gSofdecMonoRoutingMode = 0;
  std::int32_t gSofdecOpenPortCount = 0;
  std::int32_t gSofdecFrequencyMode = 0;
  std::int32_t gSofdecGlobalFocusMode = 0;
  std::int32_t gSofdecBufferPlacementMode = 0;
  std::uint32_t gSofdecPortBufferBytesPerChannel = 0x10000u;
  std::int32_t gSofdecSoundPortVtable1Tag = 0;
  std::int32_t gSofdecSoundPortVtable2Tag = 0;
  moho::MwsfdLibWork gMwsfdLibWork{};

  struct SflibErrorInfo
  {
    SflibErrorCallback callback = nullptr; // +0x00
    std::int32_t callbackObject = 0; // +0x04
    std::int32_t firstErrorCode = 0; // +0x08
    std::int32_t reserved0 = 0; // +0x0C
    std::int32_t reserved1 = 0; // +0x10
  };

  static_assert(offsetof(SflibErrorInfo, callback) == 0x00, "SflibErrorInfo::callback offset must be 0x00");
  static_assert(
    offsetof(SflibErrorInfo, callbackObject) == 0x04, "SflibErrorInfo::callbackObject offset must be 0x04"
  );
  static_assert(
    offsetof(SflibErrorInfo, firstErrorCode) == 0x08, "SflibErrorInfo::firstErrorCode offset must be 0x08"
  );
  static_assert(sizeof(SflibErrorInfo) == 0x14, "SflibErrorInfo size must be 0x14");

  struct SflibTransferInitRuntimeView
  {
    std::uint8_t mUnknown00[0x3C]{};
    std::int32_t resetParameter = 0; // +0x3C
    std::int32_t adxtHandle = 0; // +0x40
  };

  static_assert(
    offsetof(SflibTransferInitRuntimeView, resetParameter) == 0x3C,
    "SflibTransferInitRuntimeView::resetParameter offset must be 0x3C"
  );
  static_assert(
    offsetof(SflibTransferInitRuntimeView, adxtHandle) == 0x40,
    "SflibTransferInitRuntimeView::adxtHandle offset must be 0x40"
  );
  static_assert(sizeof(SflibTransferInitRuntimeView) == 0x44, "SflibTransferInitRuntimeView size must be 0x44");

  struct SflibLibWorkRuntime
  {
    std::array<std::uint32_t, 0x64> defaultConditions{}; // +0x000
    moho::MwsfdInitSfdParams initParams{}; // +0x190
    std::int32_t initState = 0; // +0x198
    SflibErrorInfo errInfo{}; // +0x19C
    std::uint8_t timeState[0x0C]{}; // +0x1B0
    std::uint8_t sfbufState[0x04]{}; // +0x1BC
    SflibTransferInitRuntimeView transferInitState{}; // +0x1C0
    std::array<void*, 32> objectHandles{}; // +0x204
    std::int32_t versionTag = 0; // +0x284
  };

  static_assert(
    offsetof(SflibLibWorkRuntime, defaultConditions) == 0x000,
    "SflibLibWorkRuntime::defaultConditions offset must be 0x000"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, initParams) == 0x190,
    "SflibLibWorkRuntime::initParams offset must be 0x190"
  );
  static_assert(offsetof(SflibLibWorkRuntime, initState) == 0x198, "SflibLibWorkRuntime::initState offset must be 0x198");
  static_assert(offsetof(SflibLibWorkRuntime, errInfo) == 0x19C, "SflibLibWorkRuntime::errInfo offset must be 0x19C");
  static_assert(
    offsetof(SflibLibWorkRuntime, timeState) == 0x1B0,
    "SflibLibWorkRuntime::timeState offset must be 0x1B0"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, sfbufState) == 0x1BC,
    "SflibLibWorkRuntime::sfbufState offset must be 0x1BC"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) == 0x1C0,
    "SflibLibWorkRuntime::transferInitState offset must be 0x1C0"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) + offsetof(SflibTransferInitRuntimeView, resetParameter) == 0x1FC,
    "SflibLibWorkRuntime::resetParameter offset must be 0x1FC"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) + offsetof(SflibTransferInitRuntimeView, adxtHandle) == 0x200,
    "SflibLibWorkRuntime::adxtHandle offset must be 0x200"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, objectHandles) == 0x204,
    "SflibLibWorkRuntime::objectHandles offset must be 0x204"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, versionTag) == 0x284,
    "SflibLibWorkRuntime::versionTag offset must be 0x284"
  );
  static_assert(sizeof(SflibLibWorkRuntime) == 0x288, "SflibLibWorkRuntime size must be 0x288");

  struct SflibErrorOwnerRuntimeView
  {
    std::uint8_t mUnknown00[0x48]{};
    std::int32_t handleState = 0; // +0x48
    std::uint8_t mUnknown4C[0x9AC]{};
    SflibErrorInfo errInfo{}; // +0x9F8
  };

  static_assert(
    offsetof(SflibErrorOwnerRuntimeView, handleState) == 0x48,
    "SflibErrorOwnerRuntimeView::handleState offset must be 0x48"
  );
  static_assert(
    offsetof(SflibErrorOwnerRuntimeView, errInfo) == 0x9F8,
    "SflibErrorOwnerRuntimeView::errInfo offset must be 0x9F8"
  );

  SflibLibWorkRuntime gSflibLibWork{};
  moho::MwsfdInitSfdParams gMwsfdInitSfdParams{};
  std::int32_t gMwsfdLastMwsfdHandle = 0;
  std::int32_t gMwsfdLastSfdHandle = 0;
  moho::MwsfdPlaybackStateSubobj* mwsfd_hn_last = nullptr;
  std::int32_t SFPLY_recordgetfrm = 0;
  moho::SofdecSfdWorkctrlSubobj* gSfdDebugLastHandle = nullptr;
  std::int32_t gMwsfdErrorCount = 0;
  std::int32_t gMwsfdErrorCodeHistory[16]{};
  char gMwsfdErrorString[0x100]{};
  const char* gMwsfdBackendErrorText = "";
  const char* gCriVerstrPtrSfd = "";
  const char* gCriVerstrPtrCft = "";
  SfxaLibWorkView gSfxaLibWork{};
  const char* gCftcomFunctionName = nullptr;
  std::int32_t gCftcomOptimizeSpeed = 0;
  std::int32_t gUtySseSupportState = -1;
  std::array<std::int16_t, 0x10000> yuv_to_tmp{};
  std::array<std::uint32_t, 0x10000> yuv_to_r{};
  std::array<std::uint8_t, 0x10000> yuv_to_b{};
  std::array<std::uint16_t, 0x40000> tmp_to_g{};
  constexpr double kCftFixedPointScale = 65536.0;
  constexpr std::array<std::int32_t, 4> kCftDitherPatternWeights = {3, 1, 2, 4};
  std::array<std::int32_t, 0x100> y_to_y2_555{};
  std::array<std::int32_t, 0x100> cr_to_r_555{};
  std::array<std::int32_t, 0x100> cb_to_g_555{};
  std::array<std::int32_t, 0x100> cr_to_g_555{};
  std::array<std::int32_t, 0x100> cb_to_b_555{};
  std::array<std::int32_t, 0x300> r_to_pix_555{};
  std::array<std::int32_t, 0x300> g_to_pix_555{};
  std::array<std::int32_t, 0x300> b_to_pix_555{};
  std::array<std::int32_t, 0xC00> r_to_pix32_dither_555{};
  std::array<std::int32_t, 0xC00> g_to_pix32_dither_555{};
  std::array<std::int32_t, 0xC00> b_to_pix32_dither_555{};
  std::array<std::int32_t, 0x100> y_to_y2_565{};
  std::array<std::int32_t, 0x100> cr_to_r_565{};
  std::array<std::int32_t, 0x100> cb_to_g_565{};
  std::array<std::int32_t, 0x100> cr_to_g_565{};
  std::array<std::int32_t, 0x100> cb_to_b_565{};
  std::array<std::int32_t, 0x300> r_to_pix_565{};
  std::array<std::int32_t, 0x300> g_to_pix_565{};
  std::array<std::int32_t, 0x300> b_to_pix_565{};
  std::array<std::int32_t, 0xC00> r_to_pix32_dither_565{};
  std::array<std::int32_t, 0xC00> g_to_pix32_dither_565{};
  std::array<std::int32_t, 0xC00> b_to_pix32_dither_565{};

  using SofdecFrameReadCallback = std::uint32_t(__cdecl*)();
  SofdecFrameReadCallback gSofdecFrameReadCallback = nullptr;
  std::int32_t gSofdecSignalLane2 = 0;
  std::int32_t gAdxmInterval2 = 0;
  std::int32_t gSofdecScreenHeight2 = 0;
  std::int32_t gSofdecScanlineOffset = 0;
  std::int32_t gAdxmTimerSwitchState = 0;
  std::int32_t gAdxmTimerSwitchSignal = 0;
  MMRESULT gAdxmMultimediaTimerId = 0;
  LPTIMECALLBACK gAdxmMultimediaTimerCallback = nullptr;
  HANDLE gAdxmSyncEventHandle = nullptr;
  std::int64_t gAdxmPerformanceFrequency = 0;
  LARGE_INTEGER gAdxmLastSyncCounter{};
  LARGE_INTEGER gAdxmProbeCounter{};
  std::int32_t gAdxmInterval1 = 0;

  using SofdecTestAndSetOverride = BOOL(__cdecl*)(std::int32_t*);
  SofdecTestAndSetOverride gSofdecTestAndSetOverride = nullptr;

  using SvmLockCallback = void(__cdecl*)(std::int32_t callbackObject);
  using SvmErrorCallback = std::int32_t(__cdecl*)(std::uint32_t callbackObject, const char* message);

  struct SvmCallbackBinding
  {
    SvmLockCallback fn = nullptr;
    std::int32_t callbackObject = 0;
  };

  struct SvmErrorCallbackBinding
  {
    SvmErrorCallback fn = nullptr;
    std::int32_t callbackObject = 0;
  };

  SvmCallbackBinding gSvmLockCallback{};
  SvmCallbackBinding gSvmUnlockCallback{};
  SvmErrorCallbackBinding gSvmErrorCallback{};
  std::int32_t gSvmLockLevel = 0;
  std::int32_t gSvmLockingType = 0;
  char gSvmErrorBuffer[0x80]{};
  using SvmServerCallbackFn = std::int32_t(__cdecl*)(std::int32_t callbackObject);
  struct SvmServerCallbackSlot
  {
    SvmServerCallbackFn callbackFn = nullptr;
    std::int32_t callbackObject = 0;
    const char* callbackName = nullptr;
  };
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackFn) == 0x00, "SvmServerCallbackSlot::callbackFn offset must be 0x00"
  );
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackObject) == 0x04,
    "SvmServerCallbackSlot::callbackObject offset must be 0x04"
  );
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackName) == 0x08,
    "SvmServerCallbackSlot::callbackName offset must be 0x08"
  );
  static_assert(sizeof(SvmServerCallbackSlot) == 0x0C, "SvmServerCallbackSlot size must be 0x0C");
  std::array<SvmServerCallbackSlot, 48> gSvmServerCallbackTable{};
  std::int32_t gMwsfsvmVintSlotId = 0;
  std::int32_t gMwsfsvmVsyncSlotId = 0;
  std::int32_t gMwsfsvmIdleSlotId = 0;
  std::int32_t gMwsfsvmMainSlotId = 0;

  using AdxbExpandSamplePairCallback =
    void(__cdecl*)(moho::AdxBitstreamDecoderState* decoder, std::int32_t sampleValue, const std::int16_t* leftSample, const std::int16_t* rightSample);

  void(__cdecl* ADXB_OnStopPostProcess)(moho::AdxBitstreamDecoderState* decoder) = nullptr;
  AdxbExpandSamplePairCallback ADXB_OnExpandSamplePair = nullptr;
}

namespace
{
  constexpr std::int32_t kSofdecSoundPortPoolSize = 32;
  constexpr DWORD kSofdecPrimaryBufferFlagsLegacy = 0x10080u;
  constexpr DWORD kSofdecPrimaryBufferFlagsDx8 = 0x10280u;
  constexpr DWORD kSofdecPrimaryBufferFlagsAlt = 0x100A0u;
  constexpr std::int32_t kSofdecLegacyDx8CapabilityTag = 0x800;
  constexpr std::int32_t kSofdecLegacyDx7CapabilityTag = 0x700;
  constexpr std::int32_t kSofdecPlaybackPollDivisor = 1500;
  constexpr char kSofdecErrChannelCountRange[] = "E1221:Illigal parameter(MAXNCH) in mwSndOpenPort().";
  constexpr char kSofdecErrNoFreeSoundPort[] = "E1222:Not enough instance(MWSND) in mwSndOpenPort().";
  constexpr char kSofdecErrCreateBuffer[] = "E1223:Cannot create DirectSoundBuffer in mwSndOpenPort().";
  constexpr char kSofdecErrNullPrimaryBuffer[] = "E1225:dsb(member in handle) is NULL";
  constexpr char kSofdecErrPlayFailed[] = "E1226:IDirectSoundBuffer_Play return error.";
  constexpr char kSofdecErrSetCurrentPositionFailed[] = "E1227:IDirectSoundBuffer_SetCurrentPosition return error.";
  constexpr char kSofdecErrSetFrequencyFailed[] = "E1228:IDirectSoundBuffer_SetFrequency return error.";
  constexpr char kSofdecErrCreatePlaybackFailed[] = "E1229:IDirectSoundBuffer_CreateSoundBuffer return error.";
  constexpr char kSofdecErrStopFailed[] = "E1229:IDirectSoundBuffer_Stop return error.";
  constexpr char kSofdecErrDirectSoundMissing[] = "E2003100700:DirectSound Object is NULL.";
  constexpr char kSofdecErrSetVolumeFailed[] = "E1230:IDirectSoundBuffer_SetVolume return error in mwSndSetVol";
  constexpr char kSofdecErrSetPanFailed[] = "E1232:IDirectSoundBuffer_SetPan return error in mwSndSetBalance";
  constexpr char kSofdecErrLockFailed[] = "E1234:IDirectSoundBuffer_Lock return error in mwSndGetData";
  constexpr char kSofdecErrUnlockFailed[] = "E1235:IDirectSoundBuffer_Unlock return error in mwSndGetData";
  constexpr char kSofdecErrControlSetFrequencyFailed[] = "E1236:IDirectSoundBuffer_SetFrequency return error in mwSndSetControl";
  constexpr char kCvFsDeviceMf[] = "MF";
  constexpr char kCvFsDeviceWx[] = "WX";
  constexpr char kCvFsErrAddDevInvalidDeviceName[] = "cvFsAddDev #1:illegal device name";
  constexpr char kCvFsErrAddDevInvalidInterfaceFn[] = "cvFsAddDev #2:illegal I/F func name";
  constexpr char kCvFsErrAddDevFailed[] = "cvFsAddDev #3:failed added a device";
  constexpr char kCvFsErrDelDevInvalidDeviceName[] = "cvFsDelDev #1:illegal device name";
  constexpr char kCvFsErrSetDefDevInvalidDeviceName[] = "cvFsSetDefDev #1:illegal device name";
  constexpr char kCvFsErrSetDefDevUnknownDeviceName[] = "cvFsSetDefDev #2:unknown device name";
  constexpr char kCvFsErrCloseHandle[] = "cvFsClose #1:handle error";
  constexpr char kCvFsErrCloseVtable[] = "cvFsClose #2:vtbl error";
  constexpr char kCvFsErrOpenIllegalFileName[] = "cvFsOpen #1:illegal file name";
  constexpr char kCvFsErrOpenHandleAllocFailed[] = "cvFsOpen #3:failed handle alloced";
  constexpr char kCvFsErrOpenDeviceNotFound[] = "cvFsOpen #4:device not found";
  constexpr char kCvFsErrOpenVtableError[] = "cvFsOpen #5:vtbl error";
  constexpr char kCvFsErrOpenFailed[] = "cvFsOpen #6:open failed";
  constexpr char kCvFsErrSetDefVolInvalidDeviceName[] = "cvFsSetDefVol #1:illegal device name";
  constexpr char kCvFsErrSetDefVolInvalidVolumeName[] = "cvFsSetDefVol #2:illegal volume name";
  constexpr char kCvFsErrSetDefVolDeviceNotFound[] = "cvFsSetDefVol #3:device not found";
  constexpr std::int32_t kSvmServerTypeCount = 8;
  constexpr std::int32_t kSvmServerSlotsPerType = 6;
  constexpr char kSvmUnknownServerCallbackName[] = "Unknown";
  constexpr char kSvmErrSetCbSvrTooManyServerFuncs[] = "1051001:SVM_SetCbSvr:too many server functions";
  constexpr char kSvmErrDelCbSvrIllegalId[] = "1051002:SVM_DelCbSvr:illegal id";
  constexpr char kSvmErrSetCbSvrIllegalSvType[] = "1071205:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrDelCbSvrIllegalSvType[] = "1071206:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrSetCbSvrIdIllegalId[] = "1071201:SVM_SetCbSvrId:illegal id";
  constexpr char kSvmErrSetCbSvrIdIllegalSvType[] = "1071202:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrSetCbSvrIdOverwrite[] = "2100801:SVM_SetCbSvrId:over write callback function";
  constexpr char kSvmErrExecSvrFuncIdIllegalId[] = "1071301:SVM_ExecSvrFuncId:illegal id";
  constexpr char kSvmErrExecSvrFuncIdIllegalSvType[] = "1071302:SVM_ExecSvrFuncId:illegal svtype";
  constexpr char kSvmErrUnlockTypeMismatch[] = "2103102:SVM:svm_unlock:lock type miss match.(type org=%d, type now=%d)";
  constexpr char kMwlRnaStartTransNullSjMessage[] = "E1212:mwlRnaStartTrans rna->sj=NULL";
  constexpr char kAdxrnaIllegalParameterMessage[] = "E1205:Illegal parameter (MWRNA=NULL)";
  constexpr char kMwsfdRequiredVersion[] = "1.958";
  constexpr std::int32_t kMwsfdRequiredVersionTag = 0x3640;
  constexpr char kCriSfdVersionString[] = "\nCRI SFD/PC Ver.1.958 Build:Feb 28 2005 21:33:54\n";
  constexpr std::int32_t kMwsfdErrInitFailed = -301;
  constexpr std::int32_t kMwsfdErrSetErrFnFailed = -303;
  constexpr std::int32_t kMwsfdFileTypeMpv = 2;
  constexpr char kMwsfdErrIncompatibleVersion[] = "E011081 mwPlySfdInit: Not compatible SFD Version.";
  constexpr char kMwsfdErrStartFnameInvalidHandle[] = "E1122601: mwPlyStartFname: handle is invalid.";
  constexpr char kMwsfdErrStartFnameNullFileName[] = "E10915C: mwPlyStartFname: fname is NULL.";
  constexpr char kMwsfdErrInvalidHandle[] = "E1122630: mwPlyStartFnameLp: handle is invalid.";
  constexpr char kMwsfdErrNullFileName[] = "E10915A: mwPlyStartFnameLp: fname is NULL.";
  constexpr char kMwsfdErrConcatPlayFailed[] = "E99072103 mwPlyStartXX: can't link stream";
  constexpr char kMwsfdErrStopFailed[] = "E2003 mwSfdStop:can't stop SFD";
  constexpr char kMwsfdErrStartMemInvalidHandle[] = "E1122610 mwPlyStartMem: handle is invalid.";
  constexpr char kMwsfdErrStartMemUnsupportedMpv[] =
    "E4111701 mwPlyStartMem: can't play file type MPV. Use memory file system(MFS).";
  constexpr char kMwsfdErrStartSjInvalidHandle[] = "E1122609 mwPlyStartSj: handle is invalid.";
  constexpr char kMwsfdErrStartStreamReqStartFailedFmt[] = "E211141 MWSTM_ReqStart: can't start '%s'";
  constexpr char kMwsfdErrFileNameTooLong[] = "E211121: filename is longer.";
  constexpr char kMwsfdErrEntryFnameInvalidHandle[] = "E1122633: mwPlyEntryFname: handle is invalid.";
  constexpr char kMwsfdErrEntryFnameNullFileName[] = "E10915B: mwPlyEntryFname: fname is NULL.";
  constexpr char kMwsfdErrEntryFnameCannotEntryFmt[] = "E204021: mwPlyEntryFname: Can't entry file'%s'";
  constexpr char kMwsfdErrGetTimeInvalidHandle[] = "E1122603 mwPlyGetTime; handle is invalid.";
  constexpr char kMwsfdErrGetTimeFailed[] = "E2006 mwPlyGetTime; can't get time";
  constexpr char kMwsfdErrStartSeamlessInvalidHandle[] = "E1122634: mwPlyStartSeamless: handle is invalid.";
  constexpr char kMwsfdErrLinkStmInvalidHandle[] = "E1122642: mwPlyLinkStm: handle is invalid.";
  constexpr char kMwsfdErrLinkStmConcatPlayFailed[] = "E99072101 mwPlyLinkStm: can't link stream";
  constexpr char kMwsfdErrSetLpFlagInvalidHandle[] = "E1122641: mwPlySetLpFlg: handle is invalid.";
  constexpr char kMwsfdErrReleaseLpInvalidHandle[] = "E1122631: mwPlyReleaseLp: handle is invalid.";
  constexpr char kMwsfdErrReleaseSeamlessInvalidHandle[] = "E1122635: mwPlyReleaseSeamless: handle is invalid.";
  constexpr char kMwsfdErrStartAfsLpInvalidHandle[] = "E1122632: mwPlyStartAfsLp: handle is invalid.";
  constexpr char kMwsfdErrEntryAfsInvalidHandle[] = "E1122636: mwPlyEntryAfs: handle is invalid.";
  constexpr char kMwsfdErrEntryAfsCannotEntryFmt[] = "E008311 mwPlyEntryAfs: can't entry pid=%d fid=%d";
  constexpr char kMwsfdErrEntryFnameRangeInvalidHandle[] = "E407023: mwPlyEntryFnameRange: handle is invalid.";
  constexpr char kMwsfdErrStartFnameRangeLpInvalidHandle[] = "E407024: mwPlyStartFnameRangeLp: handle is invalid.";
  constexpr char kMwsfdErrGetCurFrmInvalidHandle[] = "E1122614: mwPlyGetCurFrm: handle is invalid.";
  constexpr char kMwsfdErrRelCurFrmInvalidHandle[] = "E1122615: mwPlyRelCurFrm: handle is invalid.";
  constexpr char kMwsfdErrStopInvalidHandle[] = "E1122602 mwSfdStop: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipDispInvalidHandle[] = "E202231: mwPlyGetNumSkipDisp: handle is invalid.";
  constexpr char kMwsfdErrGetSfdHandleInvalidHandle[] = "E1122640: mwPlyGetSfdHn: handle is invalid.";
  constexpr char kMwsfdErrGetNumDropFrmInvalidHandle[] = "E202232: mwPlyGetNumDropFrm: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipDecInvalidHandle[] = "E1122619: mwPlyGetNumSkipDec: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipEmptyBInvalidHandle[] = "E1122623: mwPlyGetNumSkipEmptyB: handle is invalid.";
  constexpr char kMwsfdErrGetPlyInfInvalidHandle[] = "E202191: mwPlyGetPlyInf: handle is invalid.";
  constexpr char kMwsfdErrForgotFree[] = "E2053005: forgot free.";
  constexpr char kMwsfdErrInvalidStreamIndexFmt[] = "E10821B : Invalid value of stm_no : %d";
  constexpr char kMwsfdErrGetSlFnameInvalidHandle[] = "E1122637: mwPlyGetSlFname: handle is invalid.";
  constexpr char kMwsfdErrGetCompoModeInvalidHandle[] = "E2011915: mwPlyFxGetCompoMode: handle is invalid.";
  constexpr char kMwsfdErrGetStatInvalidHandle[] = "W2004 mwPlyGetStat: handle is invalid";
  constexpr char kMwsfdErrExecSvrNullHandle[] = "E1071901 mwPlyExecSvrHndl: NULL handle.";
  constexpr char kMwsfdErrExecSvrPlayingTermFailed[] = "E99072102 mwlSfdExecDecSvrPlaying: can't term";
  constexpr char kMwsfdErrGetSyncModeInvalidHandle[] = "E2010802: mwPlyGetSyncMode: handle is invalid.";
  constexpr char kMwsfdErrGetSyncModeInvalidMode[] = "E2010803: mwPlyGetSyncMode: mode is invalid.";
  constexpr char kMwsfdErrSetOutBufSizeInvalidHandle[] = "E306091 MWSFSFX_SetOutBufSize: invalid handle";
  constexpr char kMwsfdErrMallocCountOver[] = "E2053001 MWSFD_Malloc: cnt over.";
  constexpr std::int32_t kMwsfdErrCodeInvalidHandle = -12;
  constexpr char kMwsfcreErrAttachPicUsrBufInternal[] = "E02120501: Internal Error: mwsfcre_AttachPicUsrBuf().";
  constexpr char kMwsfcreErrAttachPicUsrBufShort[] = "E02120502: mwsfcre_AttachPicUsrBuf(): usrdatbuf is short.";
  constexpr char kAdxfErrCreateNoHandles[] = "E04041201:not enough ADXF handle (adxf_CreateAdxFs)";
  constexpr char kAdxfErrCreateCannotCreateStream[] = "E02111001:can't create stm handle (adxf_CreateAdxFs)";
  constexpr std::int32_t kSflibErrInvalidHandleSetErrFn = static_cast<std::int32_t>(0xFF000101u);
  constexpr std::int32_t kSflibErrInvalidHandleGetErrInf = static_cast<std::int32_t>(0xFF000102u);
  constexpr std::int32_t kSflibErrDefaultConditionMissing = static_cast<std::int32_t>(0xFF000201u);
  constexpr std::int32_t kSflibErrCreateMissingWorkArea = static_cast<std::int32_t>(0xFF000204u);
  constexpr std::int32_t kSflibErrCreateWorkSizeTooSmall = static_cast<std::int32_t>(0xFF000205u);
  constexpr std::int32_t kSflibErrCreateNoFreeHandle = static_cast<std::int32_t>(0xFF000206u);
  constexpr std::int32_t kSflibErrInvalidHandleDestroy = static_cast<std::int32_t>(0xFF000131u);
  constexpr std::int32_t kSflibErrInvalidHandleStart = static_cast<std::int32_t>(0xFF000132u);
  constexpr std::int32_t kSflibErrInvalidHandleStop = static_cast<std::int32_t>(0xFF000133u);
  constexpr std::int32_t kSflibErrInvalidHandleGetCond = static_cast<std::int32_t>(0xFF000113u);
  constexpr std::int32_t kSflibErrInvalidHandleExecOne = static_cast<std::int32_t>(0xFF000138u);
  constexpr std::int32_t kSflibErrInvalidHandleTermSupply = static_cast<std::int32_t>(0xFF000135u);
  constexpr std::int32_t kAdxstmStatusFilesystemError = 4;
  constexpr char kCriCftVersionString[] = "\nCRI CFT/PC Ver.1.72 Build:Feb 28 2005 21:33:29\n";
  constexpr std::array<std::uint32_t, 0x64> kSfplyDefaultConditions = {
    0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0x00000001u, 0x00000000u, 0x00000001u,
    0x00000000u, 0x00000001u, 0xFFFFFFFDu, 0x00000001u, 0xFFFFFFFCu, 0x00000001u, 0x00000000u, 0x00000003u,
    0x00001000u, 0x00000000u, 0x00000001u, 0x0000003Cu, 0x00000001u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0x00000000u,
    0xFFFF8AD0u, 0xFFFFC950u, 0x00001F40u, 0x0000EA24u, 0x00000FA0u, 0x00000FA0u, 0x00000029u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000005u, 0x00000000u, 0x00000005u, 0x022291E0u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x7FFFFFFFu, 0x00000000u, 0x00000000u, 0x00000001u, 0x0000000Au, 0x0000412Bu,
    0x00030D40u, 0x00000000u, 0x00000000u, 0x00000001u, 0x000104ACu, 0x00020958u, 0x0007D000u, 0x00000001u,
    0x00000001u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u,
    0x00000001u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x5A5A5A5Au, 0x00000000u, 0x00000000u,
  };
  constexpr char kSfxTagCompo[] = "COMPO";
  constexpr char kSfxErrUnsupportedCompo[] = "E4111902: sfxcnv_ChkCompoByCbFunc : compo is not support.";
  constexpr std::int32_t kSfxCompoModeHalfAlpha = 17;
  constexpr std::int32_t kSfxCompoModeFullAlpha = 33;
  constexpr std::int32_t kSfxCompoModeLookup = 49;
  constexpr std::int32_t kSfxCompoModeDynamicA = 65;
  constexpr std::int32_t kSfxCompoModeDynamicB = 81;
  constexpr std::int32_t kSfxCompoModeDynamicC = 97;
  constexpr std::int32_t kSfxCompoModeDirect = 257;
  constexpr std::int32_t kSfxCompoModeForcedLookup = 4097;
  constexpr std::int32_t kSfxCompoTableFullAlpha = 1;
  constexpr std::int32_t kSfxCompoTableLookup = 2;
  constexpr std::int32_t kSfxCompoTableForced = 21;
  constexpr std::int32_t kMwsfdErrorHistoryMaxIndex = 15;
  constexpr std::int32_t kMwsfdErrFramePoolSize = -16773355;
  constexpr std::int32_t kMwsfdErrRelFrameDoubleRelease = -16773345;
  constexpr std::int32_t kMwsfdErrMaxWidthHeightSmallMin = -16773353;
  constexpr std::int32_t kMwsfdErrMaxWidthHeightSmallMax = -16773352;
  constexpr std::int32_t kMwsfdErrReadBufferSmallA = -16773348;
  constexpr std::int32_t kMwsfdErrLibraryMessage = -16776143;
  constexpr std::int32_t kMwsfdErrReadBufferSmallB = -16776184;
  constexpr std::int32_t kMwsfdErrReadBufferSmallC = -16776180;
  constexpr std::int32_t kMwsfdErrAdxtHandleLimit = -16774140;
  constexpr std::int32_t kMwsfdErrDataLowerBound = -3;
  constexpr std::int32_t kMwsfdErrDataUpperBound = -2;
  constexpr char kMwsfdFmtSfdError[] = "SFD ERROR(%08X)";
  constexpr char kMwsfdFmtSfdErrorWithText[] = "SFD ERROR(%08X): %s";
  constexpr char kMwsfdFmtDataError[] = "DATA ERROR(%08X)";
  constexpr char kMwsfdMsgFramePoolSize[] =
    "SFD ERROR(%08X): Frame pool size is incorrect. Set positive integer to 'nfrm_pool_wk' of creation parameter.";
  constexpr char kMwsfdMsgRelFrameDoubleRelease[] =
    "SFD ERROR(%08X): mwPlyRelFrm() was called twice to the same frame ID.";
  constexpr char kMwsfdMsgMaxWidthHeightSmall[] =
    "SFD ERROR(%08X): 'max_width, max_height' of creation parameter is small. Increase this value.";
  constexpr char kMwsfdMsgReadBufferSmall[] =
    "SFD ERROR(%08X): Read buffer is small. Increase 'max_bps' of creation parameter.";
  constexpr char kMwsfdMsgAdxtHandleLimit[] =
    "SFD ERROR(%08X): Number of ADXT handles exceeds its maximum number. MWPLY handle uses one ADXT handle(stereo) for MWSFD_FTYPE_SFD.";
  constexpr std::int32_t kSofdecMinMillibel = -10000;
  constexpr std::int32_t kSofdecMaxMillibel = 0;
  constexpr std::int32_t kSofdecBalanceIndexMin = -15;
  constexpr std::int32_t kSofdecBalanceIndexMax = 15;
  constexpr std::int32_t kSofdecFrequencyMinHz = 100;
  constexpr std::int32_t kSofdecFrequencyMaxHz = 100000;

  constexpr std::array<std::int32_t, 31> kSofdecBalancePanTable = {
    -10000,
    -7356,
    -5411,
    -3981,
    -2928,
    -2154,
    -1584,
    -1165,
    -857,
    -630,
    -464,
    -341,
    -251,
    -184,
    -135,
    0,
    135,
    184,
    251,
    341,
    464,
    630,
    857,
    1165,
    1584,
    2154,
    2928,
    3981,
    5411,
    7356,
    10000,
  };

  constexpr std::array<std::int32_t, 31> kSofdecSpatialPanTable = {
    -10000,
    -2561,
    -1957,
    -1600,
    -1345,
    -1144,
    -976,
    -831,
    -702,
    -586,
    -477,
    -375,
    -278,
    -183,
    -91,
    0,
    91,
    183,
    278,
    375,
    477,
    586,
    702,
    831,
    976,
    1144,
    1345,
    1600,
    1957,
    2561,
    10000,
  };

  constexpr std::array<std::int32_t, 31> kSofdecSpatialVolumeOffsetTable = {
    0,
    -1,
    -5,
    -11,
    -19,
    -30,
    -44,
    -60,
    -79,
    -100,
    -125,
    -153,
    -184,
    -219,
    -258,
    -301,
    -258,
    -219,
    -184,
    -153,
    -125,
    -100,
    -79,
    -60,
    -44,
    -30,
    -19,
    -11,
    -5,
    -1,
    0,
  };

  [[nodiscard]] std::int32_t SofdecClampMillibel(const std::int32_t value)
  {
    if (value > kSofdecMaxMillibel) {
      return kSofdecMaxMillibel;
    }
    if (value < kSofdecMinMillibel) {
      return kSofdecMinMillibel;
    }
    return value;
  }

  [[nodiscard]] std::int32_t SofdecLookupBalancePanMillibel(const std::int32_t balanceIndex)
  {
    return kSofdecBalancePanTable[static_cast<std::size_t>(balanceIndex - kSofdecBalanceIndexMin)];
  }

  [[nodiscard]] std::int32_t SofdecLookupSpatialPanMillibel(const std::int32_t spatialIndex)
  {
    return kSofdecSpatialPanTable[static_cast<std::size_t>(spatialIndex - kSofdecBalanceIndexMin)];
  }

  [[nodiscard]] std::int32_t SofdecLookupSpatialVolumeOffsetMillibel(const std::int32_t spatialIndex)
  {
    return kSofdecSpatialVolumeOffsetTable[static_cast<std::size_t>(spatialIndex - kSofdecBalanceIndexMin)];
  }

  void SofdecPollBufferPlaybackState(IDirectSoundBuffer* const soundBuffer, const bool waitForPlayingState)
  {
    LARGE_INTEGER startCounter{};
    QueryPerformanceCounter(&startCounter);

    DWORD status = 0;
    soundBuffer->lpVtbl->GetStatus(soundBuffer, &status);

    while (((status & DSBSTATUS_PLAYING) != 0) != waitForPlayingState) {
      LARGE_INTEGER frequency{};
      QueryPerformanceFrequency(&frequency);
      frequency.QuadPart /= kSofdecPlaybackPollDivisor;

      LARGE_INTEGER currentCounter{};
      QueryPerformanceCounter(&currentCounter);

      if ((currentCounter.QuadPart - startCounter.QuadPart) > frequency.QuadPart) {
        break;
      }
      if (currentCounter.QuadPart <= startCounter.QuadPart) {
        break;
      }

      soundBuffer->lpVtbl->GetStatus(soundBuffer, &status);
    }
  }

  constexpr std::int32_t kM2aMaxBandsLong = 49;
  constexpr std::int32_t kM2aMaxBandsShort = 14;
  constexpr std::int32_t kM2aShortWindowCount = 8;
  constexpr std::int32_t kM2aTnsCoefficientLaneCount = 32;
  constexpr std::int32_t kM2aIcsMaxSfbIndex = 140;
  constexpr std::int32_t kM2aIcsWindowSequenceIndex = 122;
  constexpr std::int32_t kM2aIcsWindowShapeIndex = 123;
  constexpr std::int32_t kM2aIcsIntensityScaleBaseIndex = 114;
  constexpr std::int32_t kM2aContextStatusIndex = 1;
  constexpr std::int32_t kM2aContextErrorCodeIndex = 2;
  constexpr std::int32_t kM2aContextHeapManagerIndex = 5;
  constexpr std::int32_t kM2aContextAudioObjectTypeIndex = 19;
  constexpr std::int32_t kM2aContextSampleRateIndex = 20;
  constexpr std::int32_t kM2aContextSampleRateTableIndex = 21;
  constexpr std::int32_t kM2aContextDecodedChannelCountIndex = 23;
  constexpr std::int32_t kM2aContextDecodeCountInitializedIndex = 33;
  constexpr std::int32_t kM2aContextScalefactorBandLongPtrIndex = 35;
  constexpr std::int32_t kM2aContextScalefactorBandShortPtrIndex = 36;
  constexpr std::int32_t kM2aContextPceMapIndex = 38;
  constexpr std::int32_t kM2aContextLocationEntryBaseIndex = 39;
  constexpr std::int32_t kM2aContextLocationAllocBaseIndex = 156;
  constexpr std::int32_t kM2aContextIcsTableBaseIndex = 167;
  constexpr std::int32_t kM2aContextSecondaryIcsTableBaseIndex = 183;
  constexpr std::int32_t kM2aContextPrimaryStateBaseIndex = 423;
  constexpr std::int32_t kM2aContextSecondaryStateBaseIndex = 439;
  constexpr std::int32_t kM2aContextElementIndex = 10;
  constexpr std::int32_t kM2aContextWindowGroupIndex = 11;
  constexpr std::int32_t kM2aContextLocationEntryCountIndex = 88;
  constexpr double kM2aIntensityPowBase = 0.5;
  constexpr double kM2aIntensityPowScale = 0.25;
  constexpr std::size_t kM2aLocationEntrySize = 0x0Cu;
  constexpr std::size_t kM2aIcsInfoSize = 0x234u;
  constexpr std::size_t kM2aDecodeStateSize = 0x88ECu;
  constexpr std::size_t kM2aDecoderContextSize = 0xA9Cu;
  constexpr std::size_t kM2aScratchMappingBytes = 0x34u;
  constexpr std::size_t kM2aPceMapBytes = 0x2B8u;
  constexpr std::int32_t kM2aLocationEntryCapacity = 128;
  constexpr std::int32_t kM2aDecoderSlotCount = 256;
  constexpr std::int32_t kM2aContextScratchMappingIndex = 37;
  constexpr std::int32_t kM2aContextInputBufferIndex = 6;
  constexpr std::int32_t kM2aContextInputByteCountIndex = 7;
  constexpr std::int32_t kM2aContextInputBitRemainderIndex = 8;
  constexpr std::int32_t kM2aContextElementCounterIndex = 12;
  constexpr std::int32_t kM2aContextElementCounterLimitIndex = 13;
  constexpr std::int32_t kM2aContextFrameCounterIndex = 14;
  constexpr std::int32_t kM2aContextPendingSupplyIndex = 15;
  constexpr std::int32_t kM2aContextEndModeIndex = 16;
  constexpr std::int32_t kM2aContextHeaderTypeIndex = 17;
  constexpr std::int32_t kM2aContextBitstreamHandleIndex = 9;
  constexpr std::int32_t kM2aContextAdtsFrameLengthIndex = 12;
  constexpr std::int32_t kM2aContextAdtsRawBlockCountIndex = 13;
  constexpr std::int32_t kM2aContextChannelConfigurationIndex = 24;
  constexpr std::int32_t kM2aContextLayoutInitializedIndex = 34;
  constexpr std::int32_t kM2aPceMixdownTableIndex = 171;
  constexpr std::int32_t kM2aPceSurroundMixdownEnabledIndex = 172;
  constexpr std::int32_t kM2aElementIdEnd = 7;
  constexpr std::int32_t kM2aMainProfile = 1;
  constexpr std::int32_t kM2aDecodeStateOutputReadySamplesIndex = 8762;
  constexpr std::ptrdiff_t kM2aDecodeStatePcmWindowOffset = 0x78E4;
  constexpr std::int32_t kM2aPcmWindowSampleCount = 1024;
  constexpr float kM2aCenterDownmixScale = 0.70710677f;
  constexpr float kM2aMonoDownmixScale = 0.5f;
  constexpr std::uint32_t kM2aDownmixBufferBytes =
    static_cast<std::uint32_t>(kM2aPcmWindowSampleCount * sizeof(float));

  struct AdxbRuntimeView
  {
    std::int16_t slotState = 0; // +0x00
    std::int16_t initState = 0; // +0x02
    std::int32_t runState = 0; // +0x04
    void* adxPacketDecoder = nullptr; // +0x08
    std::int8_t headerType = 0; // +0x0C
    std::int8_t sourceSampleBits = 0; // +0x0D
    std::int8_t sourceChannels = 0; // +0x0E
    std::int8_t sourceBlockBytes = 0; // +0x0F
    std::int32_t sourceBlockSamples = 0; // +0x10
    std::int32_t sampleRate = 0; // +0x14
    std::int32_t totalSampleCount = 0; // +0x18
    std::int16_t adpcmCoefficientIndex = 0; // +0x1C
    std::uint8_t mUnknown1E[0x2]{}; // +0x1E
    std::int32_t loopInsertedSamples = 0; // +0x20
    std::int16_t loopCount = 0; // +0x24
    std::uint16_t loopType = 0; // +0x26
    std::int32_t loopStartSample = 0; // +0x28
    std::int32_t loopStartOffset = 0; // +0x2C
    std::int32_t loopEndSample = 0; // +0x30
    std::int32_t loopEndOffset = 0; // +0x34
    void* pcmBufferTag = nullptr; // +0x38
    std::int16_t* pcmBuffer0 = nullptr; // +0x3C
    std::int32_t pcmBufferSampleLimit = 0; // +0x40
    std::int32_t pcmBufferSecondChannelOffset = 0; // +0x44
    char* sourceWordStream = nullptr; // +0x48
    std::int32_t sourceWordLimit = 0; // +0x4C
    std::int32_t outputChannels = 0; // +0x50
    std::int32_t outputBlockBytes = 0; // +0x54
    std::int32_t outputBlockSamples = 0; // +0x58
    std::int16_t* outputWordStream0 = nullptr; // +0x5C
    std::int32_t outputWordLimit = 0; // +0x60
    std::int32_t outputSecondChannelOffset = 0; // +0x64
    std::int32_t entryWriteStartWordIndex = 0; // +0x68
    std::int32_t entryWriteUsedWordCount = 0; // +0x6C
    std::int32_t entryWriteCapacityWords = 0; // +0x70
    std::int32_t callbackLane3 = 0; // +0x74
    void(__cdecl* entryGetWriteFunc)(std::int32_t, std::int32_t*, std::int32_t*, std::int32_t*) = nullptr; // +0x78
    std::int32_t entryGetWriteContext = 0; // +0x7C
    std::int32_t(__cdecl* entryAddWriteFunc)(std::int32_t, std::int32_t, std::int32_t) = nullptr; // +0x80
    std::int32_t entryAddWriteContext = 0; // +0x84
    std::int32_t entrySubmittedBytes = 0; // +0x88
    std::int32_t entryCommittedBytes = 0; // +0x8C
    std::int32_t producedSampleCount = 0; // +0x90
    std::int32_t producedByteCount = 0; // +0x94
    std::int16_t format = 0; // +0x98
    std::int16_t preferredFormat = 0; // +0x9A
    std::int16_t outputSamplePacking = 0; // +0x9C
    std::uint8_t mUnknown9E[0x2]{}; // +0x9E
    std::uint8_t mUnknownA0[0x14]{}; // +0xA0
    void* ahxDecoderHandle = nullptr; // +0xB4
    std::int32_t ahxMaxDecodeSamples = 0; // +0xB8
    std::int32_t ahxMaxDecodeBlocks = 0; // +0xBC
    std::uint8_t mUnknownC0[0x34]{}; // +0xC0
    std::int32_t channelExpandHandle = 0; // +0xF4
    std::uint8_t mUnknownF8[0x8]{}; // +0xF8
    std::int32_t decodeCallbackConsumedBytes = 0; // +0x100
    std::uint8_t mUnknown104[0x4]{}; // +0x104
    std::int32_t(__cdecl* decodeCallback)(std::int32_t callbackContext, std::int32_t producedDelta, std::int32_t producedBytes) = nullptr; // +0x108
    std::int32_t decodeCallbackContext = 0; // +0x10C
  };

  static_assert(offsetof(AdxbRuntimeView, runState) == 0x04, "AdxbRuntimeView::runState offset must be 0x04");
  static_assert(offsetof(AdxbRuntimeView, adxPacketDecoder) == 0x08, "AdxbRuntimeView::adxPacketDecoder offset must be 0x08");
  static_assert(offsetof(AdxbRuntimeView, sourceChannels) == 0x0E, "AdxbRuntimeView::sourceChannels offset must be 0x0E");
  static_assert(offsetof(AdxbRuntimeView, sourceWordStream) == 0x48, "AdxbRuntimeView::sourceWordStream offset must be 0x48");
  static_assert(offsetof(AdxbRuntimeView, outputChannels) == 0x50, "AdxbRuntimeView::outputChannels offset must be 0x50");
  static_assert(offsetof(AdxbRuntimeView, outputWordStream0) == 0x5C, "AdxbRuntimeView::outputWordStream0 offset must be 0x5C");
  static_assert(
    offsetof(AdxbRuntimeView, entryGetWriteFunc) == 0x78, "AdxbRuntimeView::entryGetWriteFunc offset must be 0x78"
  );
  static_assert(
    offsetof(AdxbRuntimeView, entryAddWriteFunc) == 0x80, "AdxbRuntimeView::entryAddWriteFunc offset must be 0x80"
  );
  static_assert(
    offsetof(AdxbRuntimeView, producedSampleCount) == 0x90, "AdxbRuntimeView::producedSampleCount offset must be 0x90"
  );
  static_assert(
    offsetof(AdxbRuntimeView, producedByteCount) == 0x94, "AdxbRuntimeView::producedByteCount offset must be 0x94"
  );
  static_assert(
    offsetof(AdxbRuntimeView, channelExpandHandle) == 0xF4,
    "AdxbRuntimeView::channelExpandHandle offset must be 0xF4"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxDecoderHandle) == 0xB4,
    "AdxbRuntimeView::ahxDecoderHandle offset must be 0xB4"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxMaxDecodeSamples) == 0xB8,
    "AdxbRuntimeView::ahxMaxDecodeSamples offset must be 0xB8"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxMaxDecodeBlocks) == 0xBC,
    "AdxbRuntimeView::ahxMaxDecodeBlocks offset must be 0xBC"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallbackConsumedBytes) == 0x100,
    "AdxbRuntimeView::decodeCallbackConsumedBytes offset must be 0x100"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallback) == 0x108, "AdxbRuntimeView::decodeCallback offset must be 0x108"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallbackContext) == 0x10C,
    "AdxbRuntimeView::decodeCallbackContext offset must be 0x10C"
  );
  static_assert(sizeof(AdxbRuntimeView) == 0x110, "AdxbRuntimeView size must be 0x110");

  struct AdxPacketDecodeSampleView
  {
    std::uint8_t mUnknown00[0x10]{}; // +0x00
    std::int32_t sourceChannels = 0; // +0x10
    std::uint8_t mUnknown14[0x0C]{}; // +0x14
    std::uint8_t* primaryOutputBytes = nullptr; // +0x20
    std::uint8_t* secondaryOutputBytes = nullptr; // +0x24
  };

  static_assert(
    offsetof(AdxPacketDecodeSampleView, sourceChannels) == 0x10,
    "AdxPacketDecodeSampleView::sourceChannels offset must be 0x10"
  );
  static_assert(
    offsetof(AdxPacketDecodeSampleView, primaryOutputBytes) == 0x20,
    "AdxPacketDecodeSampleView::primaryOutputBytes offset must be 0x20"
  );
  static_assert(
    offsetof(AdxPacketDecodeSampleView, secondaryOutputBytes) == 0x24,
    "AdxPacketDecodeSampleView::secondaryOutputBytes offset must be 0x24"
  );

  struct AdxtDolbyRuntimeState
  {
    void* workBufferBase = nullptr; // +0x00
    std::int32_t workBufferBytes = 0; // +0x04
    std::int32_t* historyLaneA = nullptr; // +0x08
    std::int32_t* historyLaneB = nullptr; // +0x0C
    std::int32_t sampleRate = 0; // +0x10
    std::int32_t historyWriteIndex = 0; // +0x14
    std::int32_t historyWindowLength = 0; // +0x18
    std::int32_t mixTableIndexA = 0; // +0x1C
    std::int32_t mixTableIndexB = 0; // +0x20
    std::int32_t mixTableIndexC = 0; // +0x24
    std::int32_t mixTableIndexD = 0; // +0x28
  };

  static_assert(
    offsetof(AdxtDolbyRuntimeState, workBufferBase) == 0x00,
    "AdxtDolbyRuntimeState::workBufferBase offset must be 0x00"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, workBufferBytes) == 0x04,
    "AdxtDolbyRuntimeState::workBufferBytes offset must be 0x04"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyLaneA) == 0x08,
    "AdxtDolbyRuntimeState::historyLaneA offset must be 0x08"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyLaneB) == 0x0C,
    "AdxtDolbyRuntimeState::historyLaneB offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, sampleRate) == 0x10, "AdxtDolbyRuntimeState::sampleRate offset must be 0x10"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyWriteIndex) == 0x14,
    "AdxtDolbyRuntimeState::historyWriteIndex offset must be 0x14"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyWindowLength) == 0x18,
    "AdxtDolbyRuntimeState::historyWindowLength offset must be 0x18"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexA) == 0x1C,
    "AdxtDolbyRuntimeState::mixTableIndexA offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexB) == 0x20,
    "AdxtDolbyRuntimeState::mixTableIndexB offset must be 0x20"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexC) == 0x24,
    "AdxtDolbyRuntimeState::mixTableIndexC offset must be 0x24"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexD) == 0x28,
    "AdxtDolbyRuntimeState::mixTableIndexD offset must be 0x28"
  );
  static_assert(sizeof(AdxtDolbyRuntimeState) == 0x2C, "AdxtDolbyRuntimeState size must be 0x2C");

  struct AdxtDestroyableHandle
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Destroy() = 0; // +0x14
  };

  struct AdxtStreamJoinHandle
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void OnSeamlessStart() = 0; // +0x14
    virtual void Reserved18() = 0;
    virtual void Reserved1C() = 0;
    virtual void Reserved20() = 0;
    virtual std::int32_t QueryDecodeBacklog(std::int32_t lane) = 0; // +0x24
  };

  struct AdxtRuntimeState
  {
    std::uint8_t used = 0; // +0x00
    std::uint8_t mUnknown01 = 0; // +0x01
    std::uint8_t mUnknown02 = 0; // +0x02
    std::int8_t maxChannelCount = 0; // +0x03
    std::int32_t sjdHandle = 0; // +0x04
    void* streamHandle = nullptr; // +0x08
    std::int32_t rnaHandle = 0; // +0x0C
    AdxtDestroyableHandle* sourceRingHandle = nullptr; // +0x10
    AdxtStreamJoinHandle* streamJoinInputHandle = nullptr; // +0x14
    std::uint8_t mUnknown18[0x24]{}; // +0x18
    std::int16_t streamBufferSectorLimitHint = 0; // +0x3C
    std::int16_t seamlessFlowSectorHint = 0; // +0x3E
    std::uint8_t mUnknown40[0x0C]{}; // +0x40
    std::int32_t streamStartScratchWord = 0; // +0x4C
    std::uint8_t mUnknown50[0x21]{}; // +0x50
    std::uint8_t streamStartLatchByte = 0; // +0x71
    std::uint8_t mUnknown72[0x02]{}; // +0x72
    void* channelExpandHandle = nullptr; // +0x74
    std::uint8_t mUnknown78[0x10]{}; // +0x78
    std::int32_t linkReadCursor = 0; // +0x88
    std::int32_t streamEndSector = 0; // +0x8C
    std::int32_t streamLoopStartSample = 0; // +0x90
    void* linkControlHandle = nullptr; // +0x94
    std::uint8_t linkSwitchRequested = 0; // +0x98
    std::uint8_t mUnknown99[0x03]{}; // +0x99
    std::int32_t playbackTimeBaseFrames = 0; // +0x9C
    std::int32_t playbackTimeVsyncAnchor = 0; // +0xA0
    std::int32_t playbackTimeDeltaFrames = 0; // +0xA4
    std::uint8_t linkSwitchActive = 0; // +0xA8
    std::uint8_t mUnknownA9[0x17]{}; // +0xA9
    std::int32_t streamDecodeWindowState = 0; // +0xC0

    [[nodiscard]] AdxtDestroyableHandle*& SourceChannelRingLane(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x18 + (lane * sizeof(void*)));
    }

    [[nodiscard]] AdxtDestroyableHandle*& AuxReleaseLaneA(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x78 + (lane * sizeof(void*)));
    }

    [[nodiscard]] AdxtDestroyableHandle*& AuxReleaseLaneB(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x80 + (lane * sizeof(void*)));
    }

    [[nodiscard]] void*& SeamlessLscHandle()
    {
      return linkControlHandle;
    }

    [[nodiscard]] const void* SeamlessLscHandle() const
    {
      return linkControlHandle;
    }

    [[nodiscard]] char*& SeamlessAfsNameBuffer()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<char**>(base + 0xAC);
    }

    [[nodiscard]] std::int16_t& SeamlessFlowSectorHint()
    {
      return seamlessFlowSectorHint;
    }

    [[nodiscard]] std::int16_t& StreamBufferSectorLimitHint()
    {
      return streamBufferSectorLimitHint;
    }

    [[nodiscard]] std::int32_t& ErrorCheckFrameWindow()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int32_t*>(base + 0x38);
    }

    [[nodiscard]] std::int16_t& ErrorStateCode()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x60);
    }

    [[nodiscard]] std::int32_t& LastDecodedSampleCount()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int32_t*>(base + 0x64);
    }

    [[nodiscard]] std::int16_t& DecodeStallCounter()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x68);
    }

    [[nodiscard]] std::int16_t& RecoveryWatchdogCounter()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x6A);
    }

    [[nodiscard]] std::uint8_t& ErrorRecoveryMode()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x6D);
    }

    [[nodiscard]] std::uint8_t& ErrorCheckSuppressedFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x72);
    }

    [[nodiscard]] std::int32_t& StreamStartScratchWord()
    {
      return streamStartScratchWord;
    }

    [[nodiscard]] std::uint8_t& StreamStartLatchByte()
    {
      return streamStartLatchByte;
    }

    [[nodiscard]] std::int32_t& StreamEndSector()
    {
      return streamEndSector;
    }

    [[nodiscard]] std::int32_t& StreamLoopStartSample()
    {
      return streamLoopStartSample;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeBaseFrames()
    {
      return playbackTimeBaseFrames;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeVsyncAnchor()
    {
      return playbackTimeVsyncAnchor;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeDeltaFrames()
    {
      return playbackTimeDeltaFrames;
    }

    [[nodiscard]] std::int32_t& StreamDecodeWindowState()
    {
      return streamDecodeWindowState;
    }
  };

  static_assert(offsetof(AdxtRuntimeState, used) == 0x00, "AdxtRuntimeState::used offset must be 0x00");
  static_assert(
    offsetof(AdxtRuntimeState, maxChannelCount) == 0x03, "AdxtRuntimeState::maxChannelCount offset must be 0x03"
  );
  static_assert(offsetof(AdxtRuntimeState, sjdHandle) == 0x04, "AdxtRuntimeState::sjdHandle offset must be 0x04");
  static_assert(offsetof(AdxtRuntimeState, streamHandle) == 0x08, "AdxtRuntimeState::streamHandle offset must be 0x08");
  static_assert(offsetof(AdxtRuntimeState, rnaHandle) == 0x0C, "AdxtRuntimeState::rnaHandle offset must be 0x0C");
  static_assert(
    offsetof(AdxtRuntimeState, sourceRingHandle) == 0x10, "AdxtRuntimeState::sourceRingHandle offset must be 0x10"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamJoinInputHandle) == 0x14,
    "AdxtRuntimeState::streamJoinInputHandle offset must be 0x14"
  );
  static_assert(
    offsetof(AdxtRuntimeState, mUnknown18) == 0x18, "AdxtRuntimeState::mUnknown18 offset must be 0x18"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamBufferSectorLimitHint) == 0x3C,
    "AdxtRuntimeState::streamBufferSectorLimitHint offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, seamlessFlowSectorHint) == 0x3E,
    "AdxtRuntimeState::seamlessFlowSectorHint offset must be 0x3E"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamStartScratchWord) == 0x4C,
    "AdxtRuntimeState::streamStartScratchWord offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamStartLatchByte) == 0x71,
    "AdxtRuntimeState::streamStartLatchByte offset must be 0x71"
  );
  static_assert(
    offsetof(AdxtRuntimeState, channelExpandHandle) == 0x74,
    "AdxtRuntimeState::channelExpandHandle offset must be 0x74"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkReadCursor) == 0x88, "AdxtRuntimeState::linkReadCursor offset must be 0x88"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamEndSector) == 0x8C, "AdxtRuntimeState::streamEndSector offset must be 0x8C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamLoopStartSample) == 0x90,
    "AdxtRuntimeState::streamLoopStartSample offset must be 0x90"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkControlHandle) == 0x94,
    "AdxtRuntimeState::linkControlHandle offset must be 0x94"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkSwitchRequested) == 0x98,
    "AdxtRuntimeState::linkSwitchRequested offset must be 0x98"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeBaseFrames) == 0x9C,
    "AdxtRuntimeState::playbackTimeBaseFrames offset must be 0x9C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeVsyncAnchor) == 0xA0,
    "AdxtRuntimeState::playbackTimeVsyncAnchor offset must be 0xA0"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeDeltaFrames) == 0xA4,
    "AdxtRuntimeState::playbackTimeDeltaFrames offset must be 0xA4"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkSwitchActive) == 0xA8,
    "AdxtRuntimeState::linkSwitchActive offset must be 0xA8"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamDecodeWindowState) == 0xC0,
    "AdxtRuntimeState::streamDecodeWindowState offset must be 0xC0"
  );
  static_assert(sizeof(AdxtRuntimeState) == 0xC4, "AdxtRuntimeState size must be 0xC4");

  struct MwsfdPicUserBufferDescriptor
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t bufferBytes = 0; // +0x04
    std::int32_t bytesPerFrame = 0; // +0x08
  };

  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bufferAddress) == 0x00,
    "MwsfdPicUserBufferDescriptor::bufferAddress offset must be 0x00"
  );
  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bufferBytes) == 0x04,
    "MwsfdPicUserBufferDescriptor::bufferBytes offset must be 0x04"
  );
  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bytesPerFrame) == 0x08,
    "MwsfdPicUserBufferDescriptor::bytesPerFrame offset must be 0x08"
  );
  static_assert(sizeof(MwsfdPicUserBufferDescriptor) == 0x0C, "MwsfdPicUserBufferDescriptor size must be 0x0C");

  struct MwsfdPlaybackPicUserView
  {
    std::uint8_t mUnknown00[0x178]{};
    MwsfdPicUserBufferDescriptor* picUserBuffer = nullptr; // +0x178
  };

  static_assert(
    offsetof(MwsfdPlaybackPicUserView, picUserBuffer) == 0x178,
    "MwsfdPlaybackPicUserView::picUserBuffer offset must be 0x178"
  );

  struct AdxfRuntimeHandleView
  {
    std::uint8_t used = 0; // +0x00
    std::uint8_t status = 0; // +0x01
    std::uint8_t sjFlag = 0; // +0x02
    std::uint8_t stopWithoutNetworkFlag = 0; // +0x03
    void* streamHandle = nullptr; // +0x04
    std::int32_t boundAfsHandle = 0; // +0x08
    std::int32_t fileSectorCount = 0; // +0x0C
    std::int32_t mUnknown10 = 0; // +0x10
    std::int32_t readStartSector = 0; // +0x14
    std::int32_t requestSectorStart = 0; // +0x18
    std::int32_t requestSectorCount = 0; // +0x1C
    void* requestBuffer = nullptr; // +0x20
    std::uint8_t mUnknown24[0x08]{}; // +0x24
    std::int32_t requestedReadSizeSectors = 0; // +0x2C
    std::int32_t fileStartSector = 0; // +0x30
  };

  static_assert(offsetof(AdxfRuntimeHandleView, used) == 0x00, "AdxfRuntimeHandleView::used offset must be 0x00");
  static_assert(
    offsetof(AdxfRuntimeHandleView, status) == 0x01,
    "AdxfRuntimeHandleView::status offset must be 0x01"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, sjFlag) == 0x02,
    "AdxfRuntimeHandleView::sjFlag offset must be 0x02"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, stopWithoutNetworkFlag) == 0x03,
    "AdxfRuntimeHandleView::stopWithoutNetworkFlag offset must be 0x03"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, streamHandle) == 0x04,
    "AdxfRuntimeHandleView::streamHandle offset must be 0x04"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, boundAfsHandle) == 0x08,
    "AdxfRuntimeHandleView::boundAfsHandle offset must be 0x08"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, readStartSector) == 0x14,
    "AdxfRuntimeHandleView::readStartSector offset must be 0x14"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestSectorStart) == 0x18,
    "AdxfRuntimeHandleView::requestSectorStart offset must be 0x18"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestSectorCount) == 0x1C,
    "AdxfRuntimeHandleView::requestSectorCount offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestBuffer) == 0x20,
    "AdxfRuntimeHandleView::requestBuffer offset must be 0x20"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestedReadSizeSectors) == 0x2C,
    "AdxfRuntimeHandleView::requestedReadSizeSectors offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, fileStartSector) == 0x30,
    "AdxfRuntimeHandleView::fileStartSector offset must be 0x30"
  );

  struct AdxsjdRuntimeView
  {
    std::uint8_t mUnknown00 = 0; // +0x00
    std::uint8_t streamFormatClass = 0; // +0x01
    std::uint8_t mUnknown02[0x2]{}; // +0x02
    moho::AdxBitstreamDecoderState* adxbHandle = nullptr; // +0x04
  };

  static_assert(
    offsetof(AdxsjdRuntimeView, streamFormatClass) == 0x01,
    "AdxsjdRuntimeView::streamFormatClass offset must be 0x01"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, adxbHandle) == 0x04,
    "AdxsjdRuntimeView::adxbHandle offset must be 0x04"
  );

  struct AdxrnaPanDispatchTable
  {
    std::uintptr_t mUnknown00[15]{}; // +0x00
    std::int32_t(__cdecl* setOutputPan)(void* outputOwner, std::int32_t channelIndex, std::int32_t panLevel) = nullptr;
  };

  static_assert(
    offsetof(AdxrnaPanDispatchTable, setOutputPan) == 0x3C,
    "AdxrnaPanDispatchTable::setOutputPan offset must be 0x3C"
  );

  struct AdxrnaOutputRuntimeView
  {
    AdxrnaPanDispatchTable* dispatchTable = nullptr; // +0x00
  };

  struct AdxrnaRuntimeView
  {
    std::uint8_t mUnknown00[0x3]{}; // +0x00
    std::uint8_t channelCount = 0; // +0x03
    std::uint8_t mUnknown04[0x34]{}; // +0x04
    AdxrnaOutputRuntimeView* outputRuntime = nullptr; // +0x38
    std::uint8_t mUnknown3C[0x28]{}; // +0x3C
    std::int32_t outputPanByChannel[16]{}; // +0x64
  };

  static_assert(offsetof(AdxrnaRuntimeView, channelCount) == 0x03, "AdxrnaRuntimeView::channelCount offset must be 0x03");
  static_assert(
    offsetof(AdxrnaRuntimeView, outputRuntime) == 0x38,
    "AdxrnaRuntimeView::outputRuntime offset must be 0x38"
  );
  static_assert(
    offsetof(AdxrnaRuntimeView, outputPanByChannel) == 0x64,
    "AdxrnaRuntimeView::outputPanByChannel offset must be 0x64"
  );

  struct AdxrnaPlaySwitchRuntimeView
  {
    std::uint8_t mUnknown00 = 0; // +0x00
    std::uint8_t stateFlags = 0; // +0x01
    std::uint8_t mUnknown02[0x92]{}; // +0x02
    std::int32_t playSwitch = 0; // +0x94
    std::uint8_t mUnknown98[0x4]{}; // +0x98
    std::int32_t stopTransitionPending = 0; // +0x9C
  };

  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, stateFlags) == 0x01,
    "AdxrnaPlaySwitchRuntimeView::stateFlags offset must be 0x01"
  );
  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, playSwitch) == 0x94,
    "AdxrnaPlaySwitchRuntimeView::playSwitch offset must be 0x94"
  );
  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, stopTransitionPending) == 0x9C,
    "AdxrnaPlaySwitchRuntimeView::stopTransitionPending offset must be 0x9C"
  );

  struct AdxtPanCacheRuntimeView
  {
    std::uint8_t mUnknown00[0x42]{}; // +0x00
    std::int16_t requestedPanByChannel[16]{}; // +0x42
  };

  static_assert(
    offsetof(AdxtPanCacheRuntimeView, requestedPanByChannel) == 0x42,
    "AdxtPanCacheRuntimeView::requestedPanByChannel offset must be 0x42"
  );

  using SofdecReportCallback = std::int32_t(__cdecl*)(std::int32_t callbackContext, const char* message);
  using AdxtDestroyCallback = std::int32_t(__cdecl*)();

  SofdecReportCallback gSofdecReportCallback = nullptr;
  std::int32_t gSofdecReportCallbackContext = 0;
  std::int32_t gSofdecDolbyAttachRefCount = 0;
  AdxtDestroyCallback gAdxtDestroyCallback = nullptr;
  std::int32_t gAdxtVsyncCount = 0;
  std::int32_t gAdxtStreamEosSector = 0x7FFFFFFF;

  [[nodiscard]] std::uint8_t* AlignPointerTo4Bytes(std::uint8_t* pointer)
  {
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    const auto misalignment = static_cast<std::uint32_t>(address & 0x3u);
    if (misalignment == 0) {
      return pointer;
    }
    return pointer + (4u - misalignment);
  }

  [[nodiscard]] AdxbRuntimeView* AsAdxbRuntimeView(moho::AdxBitstreamDecoderState* const decoder)
  {
    return reinterpret_cast<AdxbRuntimeView*>(decoder);
  }

  [[nodiscard]] const AdxbRuntimeView* AsAdxbRuntimeView(const moho::AdxBitstreamDecoderState* const decoder)
  {
    return reinterpret_cast<const AdxbRuntimeView*>(decoder);
  }

  [[nodiscard]] AdxsjdRuntimeView* AsAdxsjdRuntimeView(const std::int32_t sjdHandle)
  {
    return reinterpret_cast<AdxsjdRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sjdHandle)));
  }

  [[nodiscard]] AdxrnaRuntimeView* AsAdxrnaRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle)));
  }

  [[nodiscard]] AdxrnaPlaySwitchRuntimeView* AsAdxrnaPlaySwitchRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaPlaySwitchRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle))
    );
  }

  [[nodiscard]] std::int32_t ClampAdxrnaPanLevel(std::int32_t panLevel)
  {
    if (panLevel < -15) {
      return -15;
    }
    if (panLevel > 15) {
      return 15;
    }
    return panLevel;
  }

  [[nodiscard]] std::int16_t ResolveAdxsjdDefaultPanLane(
    const std::int32_t sjdHandle,
    const std::int32_t channelIndex
  )
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    if (
      ADXB_GetAinfLen(sjdRuntime->adxbHandle) > 0
      && (sjdRuntime->streamFormatClass == 2u || sjdRuntime->streamFormatClass == 3u)
    ) {
      return ADXB_GetDefPan(sjdRuntime->adxbHandle, channelIndex);
    }
    return -128;
  }

  [[nodiscard]] std::int32_t ResolveAdxsjdChannelCount(const std::int32_t sjdHandle)
  {
    return ADXB_GetNumChan(AsAdxsjdRuntimeView(sjdHandle)->adxbHandle);
  }

  std::int32_t SetAdxrnaOutputPan(const std::int32_t rnaHandle, const std::int32_t channelIndex, const std::int32_t panLevel)
  {
    auto* const rnaRuntime = AsAdxrnaRuntimeView(rnaHandle);
    if (rnaRuntime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxrnaIllegalParameterMessage);
    }

    if (channelIndex < 0 || channelIndex >= static_cast<std::int32_t>(rnaRuntime->channelCount)) {
      return 0;
    }

    const std::int32_t clampedPan = ClampAdxrnaPanLevel(panLevel);
    const std::int32_t result =
      rnaRuntime->outputRuntime->dispatchTable->setOutputPan(rnaRuntime->outputRuntime, channelIndex, clampedPan);
    rnaRuntime->outputPanByChannel[channelIndex] = clampedPan;
    return result;
  }

  struct MwlRnaRuntimeView
  {
    std::uint8_t mUnknown00 = 0; // +0x00
    std::uint8_t mTransferActive = 0; // +0x01
    std::uint8_t mTransferEnabled = 0; // +0x02
    std::uint8_t channelCount = 0; // +0x03
    std::uint32_t mUnknown04 = 0; // +0x04
    std::int32_t bitsPerSample = 0; // +0x08
    std::uint8_t mUnknown0C[0x14]{}; // +0x0C
    void* channelSjHandle0 = nullptr; // +0x20
    void* channelSjHandle1 = nullptr; // +0x24
    std::int32_t transferCapacityBytes = 0; // +0x28
    std::int32_t transferWriteCursor = 0; // +0x2C
    std::uint32_t mUnknown30 = 0; // +0x30
    std::int32_t transferConsumedBytes = 0; // +0x34
    void* transferCallbackOwner = nullptr; // +0x38
    std::int32_t lastTransferUnits = 0; // +0x3C
    std::uint8_t mUnknown40[0x1C]{}; // +0x40
    std::int32_t transferIssuedFlag = 0; // +0x5C
  };

  static_assert(offsetof(MwlRnaRuntimeView, channelCount) == 0x03, "MwlRnaRuntimeView::channelCount offset must be 0x03");
  static_assert(
    offsetof(MwlRnaRuntimeView, bitsPerSample) == 0x08,
    "MwlRnaRuntimeView::bitsPerSample offset must be 0x08"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, channelSjHandle0) == 0x20,
    "MwlRnaRuntimeView::channelSjHandle0 offset must be 0x20"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, channelSjHandle1) == 0x24,
    "MwlRnaRuntimeView::channelSjHandle1 offset must be 0x24"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferCapacityBytes) == 0x28,
    "MwlRnaRuntimeView::transferCapacityBytes offset must be 0x28"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferWriteCursor) == 0x2C,
    "MwlRnaRuntimeView::transferWriteCursor offset must be 0x2C"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferConsumedBytes) == 0x34,
    "MwlRnaRuntimeView::transferConsumedBytes offset must be 0x34"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferCallbackOwner) == 0x38,
    "MwlRnaRuntimeView::transferCallbackOwner offset must be 0x38"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, lastTransferUnits) == 0x3C,
    "MwlRnaRuntimeView::lastTransferUnits offset must be 0x3C"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferIssuedFlag) == 0x5C,
    "MwlRnaRuntimeView::transferIssuedFlag offset must be 0x5C"
  );

  struct SjRuntimeChunkView
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t byteCount = 0; // +0x04
  };

  static_assert(offsetof(SjRuntimeChunkView, bufferAddress) == 0x00, "SjRuntimeChunkView::bufferAddress offset must be 0x00");
  static_assert(offsetof(SjRuntimeChunkView, byteCount) == 0x04, "SjRuntimeChunkView::byteCount offset must be 0x04");
  static_assert(sizeof(SjRuntimeChunkView) == 0x08, "SjRuntimeChunkView size must be 0x08");

  using SjAcquireChunkFn = void(__cdecl*)(void* handle, std::int32_t lane, std::int32_t requestedBytes, SjRuntimeChunkView* outChunk);
  using SjSubmitChunkFn = void(__cdecl*)(void* handle, std::int32_t lane, SjRuntimeChunkView* chunk);
  using RnaTransferDispatchFn =
    void(__cdecl*)(void* callbackOwner, std::int32_t channelIndex, std::int32_t startUnit, std::int32_t sourceAddress, std::int32_t transferUnits);

  [[nodiscard]] SjAcquireChunkFn ResolveSjAcquireChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjAcquireChunkFn>(vtable[6]); // +0x18
  }

  [[nodiscard]] SjSubmitChunkFn ResolveSjSubmitChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjSubmitChunkFn>(vtable[7]); // +0x1C
  }

  [[nodiscard]] SjSubmitChunkFn ResolveSjReturnChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjSubmitChunkFn>(vtable[8]); // +0x20
  }

  [[nodiscard]] RnaTransferDispatchFn ResolveRnaTransferDispatchFn(void* const callbackOwner)
  {
    auto** const vtable = *reinterpret_cast<void***>(callbackOwner);
    return reinterpret_cast<RnaTransferDispatchFn>(vtable[21]); // +0x54
  }

  std::int32_t gMwlRnaChunkScratch0 = 0;
  std::int32_t gMwlRnaChunkScratch1 = 0;

  /**
   * Address: 0x00B15330 (FUN_00B15330, sub_B15330)
   *
   * What it does:
   * Dispatches one RNA transfer callback chunk and marks transfer-issued lane.
   */
  std::int32_t mwlRnaDispatchTransferChunk(
    MwlRnaRuntimeView* const runtime,
    const std::int32_t channelIndex,
    const std::int32_t startUnit,
    const std::int32_t sourceAddress,
    const std::int32_t transferUnits
  )
  {
    if (transferUnits <= 0) {
      return 0;
    }

    ResolveRnaTransferDispatchFn(runtime->transferCallbackOwner)(
      runtime->transferCallbackOwner,
      channelIndex,
      startUnit,
      sourceAddress,
      transferUnits
    );
    runtime->transferIssuedFlag = 1;
    return transferUnits;
  }

  /**
   * Address: 0x00B15160 (FUN_00B15160, mwlRnaStartTrans)
   *
   * What it does:
   * Pulls per-channel source chunks, computes aligned transferable unit count,
   * dispatches transfer callback lanes, then returns split chunks to SJ lanes.
   */
  std::int32_t mwlRnaStartTrans(MwlRnaRuntimeView* const runtime)
  {
    if (runtime == nullptr || runtime->bitsPerSample <= 0) {
      return 0;
    }

    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    if (channelCount <= 0) {
      return 0;
    }

    const std::int32_t unitStride = 8 * (32 / runtime->bitsPerSample);
    const std::int32_t availableTransferBytes = runtime->transferCapacityBytes - runtime->transferConsumedBytes;
    const std::int32_t maxTransferUnits = unitStride * (availableTransferBytes / unitStride);

    std::array<SjRuntimeChunkView, 2> sourceChunks{};
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
      if (sjHandle == nullptr) {
        CRIERR_CallErr(kMwlRnaStartTransNullSjMessage);
      }

      ResolveSjAcquireChunkFn(sjHandle)(
        sjHandle,
        1,
        (maxTransferUnits * runtime->bitsPerSample) / 8,
        &sourceChunks[static_cast<std::size_t>(channelIndex)]
      );
    }

    std::int32_t availableChunkBytes = sourceChunks[0].byteCount;
    if (channelCount != 1 && sourceChunks[0].byteCount >= sourceChunks[1].byteCount) {
      availableChunkBytes = sourceChunks[1].byteCount;
    }

    std::int32_t transferUnits = 8 * (availableChunkBytes / runtime->bitsPerSample);
    if (transferUnits >= maxTransferUnits) {
      transferUnits = maxTransferUnits;
    }

    const std::int32_t transferRoomBytes = runtime->transferCapacityBytes - runtime->transferWriteCursor;
    if (transferUnits >= transferRoomBytes) {
      transferUnits = transferRoomBytes;
    }

    transferUnits = unitStride * (transferUnits / unitStride);
    if (transferUnits > 0) {
      std::int32_t transferredUnits = 0;
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
        gMwlRnaChunkScratch0 = 0;
        transferredUnits = mwlRnaDispatchTransferChunk(
          runtime,
          channelIndex,
          runtime->transferWriteCursor,
          sourceChunks[static_cast<std::size_t>(channelIndex)].bufferAddress,
          transferUnits
        );
        gMwlRnaChunkScratch1 = 0;

        SjRuntimeChunkView headChunk{};
        SjRuntimeChunkView tailChunk{};
        SJ_SplitChunk(
          reinterpret_cast<moho::SjChunkRange*>(&sourceChunks[static_cast<std::size_t>(channelIndex)]),
          (transferredUnits * runtime->bitsPerSample) / 8,
          reinterpret_cast<moho::SjChunkRange*>(&headChunk),
          reinterpret_cast<moho::SjChunkRange*>(&tailChunk)
        );
        ResolveSjReturnChunkFn(sjHandle)(sjHandle, 0, &headChunk);
        ResolveSjSubmitChunkFn(sjHandle)(sjHandle, 1, &tailChunk);
      }

      runtime->lastTransferUnits = transferredUnits;
      return transferredUnits;
    }

    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
      if (sjHandle == nullptr) {
        CRIERR_CallErr(kMwlRnaStartTransNullSjMessage);
      }

      ResolveSjSubmitChunkFn(sjHandle)(sjHandle, 1, &sourceChunks[static_cast<std::size_t>(channelIndex)]);
    }

    return 0;
  }

  [[nodiscard]] std::int32_t M2aGetCurrentSlotIndex(const M2aDecoderContext* context)
  {
    return context->activeElementIndex + (context->activeWindowGroupIndex << 5);
  }

  [[nodiscard]] std::int32_t* M2aContextWords(M2aDecoderContext* context)
  {
    return reinterpret_cast<std::int32_t*>(context);
  }

  [[nodiscard]] const std::int32_t* M2aContextWords(const M2aDecoderContext* context)
  {
    return reinterpret_cast<const std::int32_t*>(context);
  }

  template <typename T>
  [[nodiscard]] T* M2aWordToPtr(const std::int32_t addressWord)
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(addressWord)));
  }

  [[nodiscard]] std::int32_t M2aPtrToWord(const void* pointer)
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(pointer));
  }

  [[nodiscard]] void* M2aAllocFromHeap(const std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    int allocatedPointer = 0;
    if (heapManagerHandle != 0 && HEAPMNG_Allocate(heapManagerHandle, byteCount, &allocatedPointer) >= 0) {
      return M2aWordToPtr<void>(allocatedPointer);
    }
    return nullptr;
  }

  [[nodiscard]] std::int32_t M2aGetHeapManagerHandle(const M2aDecoderContext* context)
  {
    return M2aContextWords(context)[kM2aContextHeapManagerIndex];
  }

  void M2aInitializeIcsWindowPointers(std::int32_t* const icsInfo)
  {
    auto* sectionCodebookLane = reinterpret_cast<std::uint8_t*>(icsInfo + 2);
    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      icsInfo[114 + windowIndex] = M2aPtrToWord(sectionCodebookLane);
      sectionCodebookLane += 56;
    }
  }

  void M2aInitializeDecodeStateWindowPointers(std::int32_t* const decodeState)
  {
    auto* sectionCodebookLane = reinterpret_cast<std::uint8_t*>(decodeState + 114);
    auto* spectralBase = reinterpret_cast<std::uint8_t*>(decodeState + 1568);

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      decodeState[234 + windowIndex] = M2aPtrToWord(sectionCodebookLane);
      decodeState[226 + windowIndex] = M2aPtrToWord(sectionCodebookLane - 448);
      decodeState[3616 + windowIndex] = M2aPtrToWord(spectralBase - 4096);
      decodeState[3624 + windowIndex] = M2aPtrToWord(spectralBase);
      decodeState[3632 + windowIndex] = M2aPtrToWord(spectralBase + 4096);

      sectionCodebookLane += 56;
      spectralBase += 512;
    }
  }

  [[nodiscard]] std::int32_t* M2aGetIcsInfoLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextIcsTableBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetPrimaryStateLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPrimaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetSecondaryStateLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextSecondaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetPrimaryStateBySlot(const M2aDecoderContext* context, const std::int32_t slotIndex)
  {
    if (slotIndex < 0 || slotIndex >= 16) {
      return nullptr;
    }

    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPrimaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetSecondaryStateBySlot(const M2aDecoderContext* context, const std::int32_t slotIndex)
  {
    if (slotIndex < 0 || slotIndex >= 16) {
      return nullptr;
    }

    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextSecondaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] float* M2aGetDecodeStatePcmWindow(std::int32_t* const decodeState)
  {
    if (decodeState == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + kM2aDecodeStatePcmWindowOffset);
  }

  [[nodiscard]] const float* M2aGetDecodeStatePcmWindow(const std::int32_t* const decodeState)
  {
    if (decodeState == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<const float*>(reinterpret_cast<const std::uint8_t*>(decodeState) + kM2aDecodeStatePcmWindowOffset);
  }

  [[nodiscard]] bool M2aHasReadyPcmWindow(const std::int32_t* const decodeState)
  {
    return decodeState != nullptr &&
           decodeState[kM2aDecodeStateOutputReadySamplesIndex] >= kM2aPcmWindowSampleCount;
  }

  void M2aAccumulateScaledPcmWindow(float* destination, const float* source, const float scale)
  {
    for (std::int32_t sampleIndex = 0; sampleIndex < kM2aPcmWindowSampleCount; ++sampleIndex) {
      destination[sampleIndex] += source[sampleIndex] * scale;
    }
  }

  void M2aAccumulatePairedPcmWindow(float* destination, const float* leftSource, const float* rightSource, const float scale)
  {
    for (std::int32_t sampleIndex = 0; sampleIndex < kM2aPcmWindowSampleCount; ++sampleIndex) {
      destination[sampleIndex] += (leftSource[sampleIndex] + rightSource[sampleIndex]) * scale;
    }
  }

  [[nodiscard]] std::int32_t M2aSumScalefactorBandWidths(
    const std::int32_t* bandWidths,
    const std::int32_t startBand,
    const std::int32_t endBand
  )
  {
    std::int32_t totalLines = 0;
    for (std::int32_t band = startBand; band < endBand; ++band) {
      totalLines += bandWidths[band];
    }
    return totalLines;
  }

  void M2aBuildTnsFilterCoefficients(float* coefficients, const float* decodedCoefficients, const std::int32_t order)
  {
    float scratch[kM2aTnsCoefficientLaneCount]{};
    coefficients[0] = 1.0f;

    for (std::int32_t coefficientIndex = 1; coefficientIndex <= order; ++coefficientIndex) {
      scratch[0] = coefficients[0];
      if (coefficientIndex > 1) {
        const auto reflectionCoefficient = decodedCoefficients[coefficientIndex - 1];
        for (std::int32_t lane = 1; lane < coefficientIndex; ++lane) {
          scratch[lane] =
            reflectionCoefficient * coefficients[coefficientIndex - lane] + coefficients[lane];
        }
      }

      scratch[coefficientIndex] = decodedCoefficients[coefficientIndex - 1];
      std::memcpy(coefficients, scratch, static_cast<std::size_t>(coefficientIndex + 1) * sizeof(float));
    }
  }

  void M2aApplyTnsFilter(
    float* spectralCoefficients,
    const std::int32_t lineCount,
    const float* filterCoefficients,
    const std::int32_t filterOrder,
    const bool reverseDirection
  )
  {
    float filterHistory[kM2aTnsCoefficientLaneCount]{};
    m2adec_clear(filterHistory, sizeof(filterHistory));

    if (!reverseDirection) {
      for (std::int32_t line = 0; line < lineCount; ++line) {
        double filteredValue = spectralCoefficients[line];
        for (std::int32_t lane = 0; lane < filterOrder; ++lane) {
          filteredValue -= static_cast<double>(filterHistory[lane]) * static_cast<double>(filterCoefficients[lane]);
        }

        for (std::int32_t lane = filterOrder - 1; lane > 0; --lane) {
          filterHistory[lane] = filterHistory[lane - 1];
        }

        filterHistory[0] = static_cast<float>(filteredValue);
        spectralCoefficients[line] = static_cast<float>(filteredValue);
      }
      return;
    }

    for (std::int32_t line = lineCount - 1; line > 0; --line) {
      double filteredValue = spectralCoefficients[line];
      for (std::int32_t lane = 0; lane < filterOrder; ++lane) {
        filteredValue -= static_cast<double>(filterHistory[lane]) * static_cast<double>(filterCoefficients[lane]);
      }

      for (std::int32_t lane = filterOrder - 1; lane > 0; --lane) {
        filterHistory[lane] = filterHistory[lane - 1];
      }

      filterHistory[0] = static_cast<float>(filteredValue);
      spectralCoefficients[line] = static_cast<float>(filteredValue);
    }
  }

  constexpr std::size_t kXeficObjectCount = 16;
  constexpr std::size_t kAdxrnaTimingPoolCount = 32;
  constexpr double kMicrosToSamples = 0.0441;
  constexpr double kMicrosToNegativeSamples = -0.0441;
  constexpr std::uint32_t kXeficWorkerSleepMilliseconds = 10;

  // Banner string lane mirrored by adxrna_Init startup reads.
  constexpr const char* kRnaVersionBanner = "\nRNADMY Ver.3.06 Build:Feb 28 2005 21:53:03\n";
  constexpr const char* kXeficEventNameFormat = "%s%s";
  constexpr const char* kXeficEventOpenedFormat = "%s is opened.\n";
  constexpr const char* kXeficEventClosedFormat = "%s is closed.\n";
  constexpr const char* kInitializeCriticalSectionFailedMessage = "E2005020901 : InitializeCriticalSection function has failed.";
  constexpr const char* kDeleteCriticalSectionFailedMessage = "E2005020902 : DeleteCriticalSection function has failed.";
  constexpr const char* kEnterCriticalSectionFailedMessage = "E2005020903 : EnterCriticalSection function has failed.";
  constexpr const char* kLeaveCriticalSectionFailedMessage = "E2005020904 : LeaveCriticalSection function has failed.";
  constexpr const char* kM2asjdInitializeCriticalSectionFailedMessage = "InitializeCriticalSection function has failed.";
  constexpr const char* kM2asjdDeleteCriticalSectionFailedMessage = "DeleteCriticalSection function has failed.";
  constexpr const char* kM2asjdEnterCriticalSectionFailedMessage = "EnterCriticalSection function has failed.";
  constexpr const char* kM2asjdLeaveCriticalSectionFailedMessage = "LeaveCriticalSection function has failed.";
  constexpr const char* kM2asjdResetNullPointerMessage = "E2004012904 : Null pointer is specified.";
  constexpr const char* kM2asjdNullDecoderHandleMessage = "E2004012905 : Null pointer is specified.";
  constexpr const char* kM2asjdStartNullPointerMessage = "E2004012907 : Null pointer is specified.";
  constexpr const char* kM2asjdStopNullPointerMessage = "E2004012908 : Null pointer is specified.";
  constexpr const char* kM2asjdGetStatusNullPointerMessage = "E2004012909 : Null pointer is specified.";
  constexpr const char* kM2asjdGetNumChannelsNullPointerMessage = "E2004012910 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetChannelConfigNullPointerMessage = "E2004012911 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetFrequencyNullPointerMessage = "E2004012912 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetNumBitsNullPointerMessage = "E2004012913 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetNumSmplsDcdNullPointerMessage = "E02092701 : Null pointer is specified.";
  constexpr const char* kM2asjdGetNumBytesDcdNullPointerMessage = "E02092702 : Null pointer is specified.";
  constexpr const char* kM2asjdGenericNullPointerMessage = "Null pointer is specified.";
  constexpr const char* kM2asjdAllocateDecoderMemoryMessage = "E2004012920 : Can not allocate memory for decoder.";
  constexpr const char* kM2asjdResumeAdifDecodeMessage = "E2004012921 : Can not resume decoding in ADIF format.";
  constexpr const char* kM2asjdUnknownDecoderErrorMessage = "E2004012922 : Unknown error occurred in decoder.";
  constexpr std::int32_t kM2asjdBitsPerSample = 16;
  constexpr std::int32_t kM2asjdStatePrimed = 1;
  constexpr std::int32_t kM2asjdStateRunning = 2;
  constexpr std::int32_t kM2asjdStateFlushed = 3;
  constexpr std::int32_t kM2asjdStateError = 4;
  constexpr std::int32_t kM2asjdDecoderStatusFlushed = 2;
  constexpr std::int32_t kM2asjdDecoderStatusError = 3;
  constexpr std::int32_t kM2asjdDecoderErrorOutOfMemory = 1;
  constexpr std::int32_t kM2asjdDecoderErrorAdifResume = 2;
  constexpr std::int32_t kM2asjdOutputModeStereo = 1;
  constexpr std::int32_t kM2asjdOutputModeSurround = 2;
  constexpr std::int32_t kM2asjdOutputModeAdx = 0xFF;
  constexpr std::int32_t kM2asjdLaneSource = 1;
  constexpr std::int32_t kM2asjdLaneOutput = 0;
  constexpr std::int32_t kM2asjdMinimumProcessBytes = 0x800;
  constexpr std::int32_t kM2asjdProcessWindowBytes = 0x2000;
  constexpr std::int32_t kM2asjdTermSupplyEnabled = 1;
  constexpr const char* kCreateThreadFailedMessage = "E2005021001 : CreateThread function has failed.";
  constexpr const char* kResumeThreadFailedMessage = "E2005021002 : ResumeThread function has failed.";
  constexpr std::size_t kAdxerrCopyLimit = 0xFFu;
  constexpr const char* kAdxerrSeparator = " ";
  constexpr const char* kXeciFileNameNullMessage = "E0092901:fname is null.(wxCiGetFileSize)";
  constexpr const char* kXeciOpenNullFileNameMessage = "E0092908:fname is null.(wxCiOpen)";
  constexpr const char* kXeciOpenInvalidRwMessage = "E0092909:rw is illigal.(wxCiOpen)";
  constexpr const char* kXeciOpenNoHandleMessage = "E0092910:not enough handle resource.(wxCiOpen)";
  constexpr const char* kXeciNullHandleMessage = "E0092912:handl is null.";
  constexpr const char* kXeciReqReadNegativeCountMessage = "E0092913:nsct < 0.(wxCiReqRd)";
  constexpr const char* kXeciReqReadNullBufferMessage = "E0092914:buf is null.(wxCiReqRd)";
  constexpr const char* kXeciReqReadIllegalSizeMessage = "E0109151:illegal read size.";
  constexpr const char* kXeciReqReadIllegalSeekMessage = "E0109152:illegal seek position.";
  constexpr const char* kXeciReqReadIllegalBufferAlignmentMessage = "E0109153:illegal buffer alignment.";
  constexpr const char* kXeciGetSctLenNullHandleMessage = "E0040301:handl is null.";
  constexpr const char* kXeciGetFileSizeOpenErrorFormat = "E0040201:can not open '%s'.(wxCiGetFileSize)";
  constexpr const char* kXeciOpenFileFailedFormat = "E0092911:can not open '%s'.(err:%d)";
  constexpr const char* kXeciReadZeroByteSyncMessage = "E02052101:The reading start position is invalid for synchronous read.";
  constexpr const char* kXeciReadInvalidStartMessage = "E02052001:The reading start position is invalid.";
  constexpr const char* kXeciReadInvalidHandleMessage = "E02040401:The reading error occurred.";
  constexpr const char* kXeciReadFaultMessage = "E02040901:The reading error occurred.";
  constexpr const char* kXeciReadQueueOverflowMessage = "E02050801:Too many I/O requests.";
  constexpr const char* kXeciReadLastErrorFormat = "E02052002:The reading error occurred. (%d)\n";
  constexpr const char* kXeciCloseWaitTimeoutMessage = "E02082801:Timeout. (Waiting for close handle)";
  constexpr const char* kXeciForceUnlockedMessage = "E02082301 : force unlocked.\n";
  constexpr const char* kXeciReadAbortedMessage = "E02052004:The file reading was aborted.\n";
  constexpr const char* kXeciReadReachedEofMessage = "E02052003:Reached the end of the file during asynchronous operation.\n";
  constexpr const char* kXeciReadErrorFormat = "E02052005:The reading error occurred. (%d)\n";
  constexpr const char* kXeciUnlockBeforeLockMessage = "E2003062702 : Unlock was performed before lock.";
  constexpr const char* kXeciWaitTimeoutMessage = "E0109232:Timeout. (Waiting for transmission)";
  constexpr std::int64_t kXeciInvalidFileSizeSentinel = 0x7FFFFFFFFFFFF800LL;
  constexpr std::int32_t kXeciObjectCount = 80;
  constexpr std::int32_t kXeciStateError = 3;
  constexpr std::int32_t kXeciStateTransferring = 2;
  constexpr std::int32_t kXeciTimeoutPollLimit = 25000;
  constexpr std::int64_t kXeciWaitOneMilliDivisor = 1000;
  constexpr const char* kAdxtNullWorkPointerMessage = "E03090101 : NULL pointer is specified.";
  constexpr const char* kAdxtShortWorkBufferMessage = "E03090102 : Work size is too short.";
  constexpr const char* kAdxtShortAlignedWorkBufferMessage = "E03091001 : Work size is too short.";
  constexpr const char* kAdxtDestroyParameterErrorMessage = "E02080805 adxt_Destroy: parameter error";
  constexpr const char* kAdxtStopParameterErrorMessage = "E02080813 adxt_Stop: parameter error";
  constexpr const char* kAdxtSetOutPanNullRuntimeMessage = "E02080825 adxt_SetOutPan: parameter error";
  constexpr const char* kAdxtSetOutPanLaneRangeMessage = "E8101208 adxt_SetOutPan: parameter error";
  constexpr const char* kAdxtNullMatrixStateMessage = "E03090306 : NULL pointer is specified.";
  constexpr const char* kAdxtIllegalMatrixParameterMessage = "E03090307 : Illegal parameter is specified.";
  constexpr const char* kAdxtNullRateStateMessage = "E03091601 : NULL pointer is specified.";
  constexpr const char* kAdxtIllegalRateParameterMessage = "E03091602 : Illegal parameter is specified.";
  constexpr const char* kMparbdNullPointerMessage = "NULL pointer is specified.";
  constexpr const char* kMparbdCreateFunctionName = "MPARBD_Create";
  constexpr const char* kMparbdDestroyFunctionName = "MPARBD_Destroy";
  constexpr const char* kMparbdResetFunctionName = "MPARBD_Reset";
  constexpr const char* kMparbdExecHandleFunctionName = "MPARBD_ExecHndl";
  constexpr const char* kMparbdGetDecodeStatusFunctionName = "MPARBD_GetDecStat";
  constexpr const char* kMparbfGetEndStatusFunctionName = "MPARBF_GetEndStat";
  constexpr const char* kMparbdDecodeSamplesProcFunctionName = "mparbd_decsmpl_proc";
  constexpr const char* kMparbdGetNumSamplesDecodedFunctionName = "MPARBD_GetNumSmplDcd";
  constexpr const char* kMparbdGetNumBytesDecodedFunctionName = "MPARBD_GetNumByteDcd";
  constexpr const char* kMparbdGetSampleRateFunctionName = "MPARBD_GetSfreq";
  constexpr const char* kMparbdGetNumChannelFunctionName = "MPARBD_GetNumChannel";
  constexpr const char* kMparbdGetNumBitFunctionName = "MPARBD_GetNumBit";
  constexpr const char* kMpardTermSupplyFunctionName = "MPARD_TermSupply";
  constexpr std::int32_t kMparbdCreateNullPointerLine = 182;
  constexpr std::int32_t kMparbdDestroyNullPointerLine = 253;
  constexpr std::int32_t kMparbdResetNullPointerLine = 308;
  constexpr std::int32_t kMparbdExecHandleNullPointerLine = 389;
  constexpr std::int32_t kMparbdGetDecodeStatusNullPointerLine = 747;
  constexpr std::int32_t kMparbfGetEndStatusNullPointerLine = 771;
  constexpr std::int32_t kMparbfSetEndStatusNullPointerLine = 794;
  constexpr std::int32_t kMparbdGetNumSamplesDecodedNullPointerLine = 816;
  constexpr std::int32_t kMparbdGetNumBytesDecodedNullPointerLine = 840;
  constexpr std::int32_t kMparbdGetSampleRateNullPointerLine = 863;
  constexpr std::int32_t kMparbdGetNumChannelNullPointerLine = 894;
  constexpr std::int32_t kMparbdGetNumBitNullPointerLine = 925;
  constexpr std::int32_t kMpardTermSupplyNullPointerLine = 951;
  constexpr std::int32_t kMparbdDecodeSamplesOverrunLine = 697;
  constexpr const char* kMparbdNullPointerSentenceCaseMessage = "Null pointer is specified.";
  constexpr const char* kMparbdDecodeSamplesOverrunMessage =
    "The terminus of a buffer was exceeded while decoding frame sample data.";
  constexpr std::size_t kMparbdSyncStateBaseIndex = 436;
  constexpr std::size_t kMparbdSyncStateCount = 15;
  constexpr std::size_t kMparbdHeaderScratchBaseIndex = 3;
  constexpr std::size_t kMparbdHeaderScratchBytes = 0x6C4;
  constexpr std::size_t kMparbdBitAllocBaseIndex = 451;
  constexpr std::size_t kMparbdBitAllocBytes = 0x100;
  constexpr std::size_t kMparbdScaleFactorSelectBaseIndex = 515;
  constexpr std::size_t kMparbdScaleFactorSelectBytes = 0x100;
  constexpr std::size_t kMparbdScaleFactorBaseIndex = 579;
  constexpr std::size_t kMparbdScaleFactorBytes = 0x300;
  constexpr std::size_t kMparbdDecodeTableDirectBaseIndex = 771;
  constexpr std::size_t kMparbdDecodeTableDirectBytes = 0x80;
  constexpr std::size_t kMparbdDecodeTableGroupedBitsBaseIndex = 803;
  constexpr std::size_t kMparbdDecodeTableGroupedBitsBytes = 0x80;
  constexpr std::size_t kMparbdDecodeTableGroupedBaseIndex = 835;
  constexpr std::size_t kMparbdDecodeTableGroupedBytes = 0x80;
  constexpr std::size_t kMparbdSampleBaseIndex = 867;
  constexpr std::size_t kMparbdSampleBytes = 0x300;
  constexpr std::size_t kMparbdDequantizedSampleBaseIndex = 1059;
  constexpr std::size_t kMparbdDequantizedSampleBytes = 0x300;
  constexpr std::size_t kMparbdSynthesisHistoryBaseIndex = 3301;
  constexpr std::size_t kMparbdSynthesisHistoryBytes = 0x180;
  constexpr std::size_t kMparbdSynthesisInputBaseIndex = 1251;
  constexpr std::size_t kMparbdSynthesisInputBytes = 0x2000;
  constexpr std::size_t kMparbdSynthesisRingCursorIndex0 = 3299;
  constexpr std::size_t kMparbdSynthesisRingCursorIndex1 = 3300;
  constexpr std::size_t kMparbdExecErrorIndex = 3399;
  constexpr std::size_t kMparbdSynthesisScaleCursorIndex = 3400;
  constexpr std::size_t kMparbdPendingFrameIndex = 3401;
  constexpr std::size_t kMparbdPendingReloadFlagIndex = 3403;
  constexpr std::size_t kMparbdPendingReturnBytesIndex = 3404;
  constexpr std::size_t kMparbdRunStateIndex = 0;
  constexpr std::size_t kMparbdSuspendFlagIndex = 1;
  constexpr std::size_t kMparbdLastErrorCodeIndex = 2;
  constexpr std::size_t kMparbdSampleRateIndex = 442;
  constexpr std::size_t kMparbdChannelCountIndex = 445;
  constexpr std::size_t kMparbdDecodedByteCountIndex = 3399;
  constexpr std::size_t kMparbdDecodedBlockCountIndex = 3400;
  constexpr std::size_t kMparbdDecodedFrameCountIndex = 3401;
  constexpr std::int32_t kMparbdStateStartup = 0;
  constexpr std::int32_t kMparbdStatePrepare = 1;
  constexpr std::int32_t kMparbdStateDecodeHeader = 2;
  constexpr std::int32_t kMparbdStateDecodeSamples = 3;
  constexpr std::int32_t kMparbdStateDecodeEnd = 4;
  constexpr std::int32_t kMparbdStateNeedMoreData = 5;
  constexpr std::int32_t kMparbdStateError = 6;
  constexpr std::int32_t kMparbdErrorMalformedFrame = -21;
  constexpr std::int32_t kMparbdErrorSampleOverrun = -22;
  constexpr std::int32_t kMparbdErrorNoDecodedSamples = -31;
  constexpr std::int32_t kMparbdBitsPerSample = 16;
  constexpr std::uint32_t kMparbdHeaderPrefixBytes = 4;
  constexpr std::uint32_t kMparbdMinimumFramePayloadBytes = 0x90;
  constexpr std::uint32_t kMparbdSamplesPerFrameBlock = 192;
  constexpr std::uint32_t kMparbdDecodeBlocksPerFrame = 12;

  void* gSofDecVirtualDispatchTable[27]{};
  [[nodiscard]] void* const* GetSofDecVirtualDispatchTable();

  [[nodiscard]] std::int16_t GenerateKeyLane(const char* sourceBytes, const std::int32_t sourceLength, std::int16_t seed)
  {
    for (std::int32_t index = 0; index < sourceLength; ++index) {
      const auto symbolIndex = static_cast<std::int32_t>(static_cast<signed char>(sourceBytes[index])) + 128;
      const auto lhs = static_cast<std::int32_t>(seed);
      const auto rhs = static_cast<std::int32_t>(skg_prim_tbl[symbolIndex]);
      std::int32_t tableIndex = (lhs * rhs) % 1024;
      if (tableIndex < 0) {
        tableIndex += 1024;
      }
      seed = skg_prim_tbl[tableIndex];
    }

    return seed;
  }

  [[nodiscard]] std::int32_t ConvertMicrosToSamples(const std::int32_t micros, const double scale)
  {
    return static_cast<std::int32_t>(static_cast<double>(static_cast<std::uint32_t>(micros)) * scale);
  }

  [[nodiscard]] MparbfRuntimeBuffer* AsMparbfRuntimeBuffer(const std::int32_t handleAddress)
  {
    return reinterpret_cast<MparbfRuntimeBuffer*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handleAddress))
    );
  }

  void M2aFreeHeapAllocation(const std::int32_t heapManagerHandle, void* allocation)
  {
    if (allocation != nullptr) {
      HEAPMNG_Free(heapManagerHandle, M2aPtrToWord(allocation));
    }
  }

  [[nodiscard]] moho::AdxrnaTimingState* ResetAdxrnaTimingPoolActiveFlags()
  {
    for (auto& timingState : adxrna_timing_pool) {
      timingState.activeFlag = 0;
    }
    return adxrna_timing_pool + kAdxrnaTimingPoolCount;
  }

  [[nodiscard]] moho::AdxrnaTimingState* AcquireFreeAdxrnaTimingState()
  {
    for (auto& timingState : adxrna_timing_pool) {
      if (timingState.activeFlag == 0) {
        return &timingState;
      }
    }
    return nullptr;
  }

  void XeficDumpQueuedEntriesForObject(XeficObject* object)
  {
    char outputString[520]{};
    const auto queuedEntryCount = object->queuedEntryCount;
    object->queueCursor = object->queueHead;

    if (queuedEntryCount <= 0) {
      return;
    }

    for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
      XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
      std::sprintf(outputString, kXeficEventNameFormat, object->pathPrefix, queueEntry->relativePath);
      if (queueEntry->fileHandle != nullptr) {
        std::sprintf(outputString, kXeficEventOpenedFormat, outputString);
      } else {
        std::sprintf(outputString, kXeficEventClosedFormat, outputString);
      }
      OutputDebugStringA(outputString);
    }
  }

  void XeficInvokeCriticalSectionApi(
    void(WINAPI* criticalSectionApi)(LPCRITICAL_SECTION),
    const char* const errorMessage
  )
  {
#if defined(_MSC_VER)
    __try {
      criticalSectionApi(&xefic_lock_obj);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      xeci_error(0, errorMessage);
    }
#else
    criticalSectionApi(&xefic_lock_obj);
#endif
  }
}

extern "C"
{
  void xefic_lock();
  void xefic_unlock();
  void xefic_DebugDumpQueueForObjectUnlocked(XeficObject* object);
  void xefic_DebugDumpAllQueuesUnlocked();

  /**
   * Address: 0x00B2BB20 (_M2ABSR_Tell)
   *
   * What it does:
   * Returns current bit cursor position for one M2A bitstream lane.
   */
  std::int32_t M2ABSR_Tell(const std::int32_t bitstreamHandle, std::int32_t* const outBitPosition)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outBitPosition == nullptr) {
      return -1;
    }

    *outBitPosition = static_cast<std::int32_t>(bitstream->bitPosition);
    return 0;
  }

  /**
   * Address: 0x00B2BB40 (_M2ABSR_IsEndOfBuffer)
   *
   * What it does:
   * Writes whether current bit cursor reached/exceeded the bit-end position.
   */
  std::int32_t M2ABSR_IsEndOfBuffer(const std::int32_t bitstreamHandle, std::int32_t* const outIsEndOfBuffer)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outIsEndOfBuffer == nullptr) {
      return -1;
    }

    *outIsEndOfBuffer = bitstream->bitPosition >= bitstream->bitEndPosition ? 1 : 0;
    return 0;
  }

  /**
   * Address: 0x00B2BB70 (_M2ABSR_Overruns)
   *
   * What it does:
   * Returns overrun counter/status lane from one M2A bitstream context.
   */
  std::int32_t M2ABSR_Overruns(const std::int32_t bitstreamHandle, std::int32_t* const outOverrunCount)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outOverrunCount == nullptr) {
      return -1;
    }

    *outOverrunCount = static_cast<std::int32_t>(bitstream->overrunCount);
    return 0;
  }

  /**
   * Address: 0x00B2BB90 (_m2absr_malloc)
   *
   * What it does:
   * Allocates one M2A bitstream/runtime block from heap manager lane when
   * present, otherwise from process heap.
   */
  void* m2absr_malloc(const std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    if (heapManagerHandle != 0) {
      int allocatedPointer = 0;
      HEAPMNG_Allocate(heapManagerHandle, byteCount, &allocatedPointer);
      return reinterpret_cast<void*>(allocatedPointer);
    }

    return HeapAlloc(GetProcessHeap(), 0, byteCount);
  }

  /**
   * Address: 0x00B2BBE0 (_m2absr_free)
   *
   * What it does:
   * Frees one M2A bitstream/runtime block through heap-manager or process-heap
   * lane.
   */
  void m2absr_free(const std::int32_t heapManagerHandle, LPVOID memoryBlock)
  {
    if (heapManagerHandle != 0) {
      HEAPMNG_Free(heapManagerHandle, reinterpret_cast<int>(memoryBlock));
      return;
    }

    HeapFree(GetProcessHeap(), 0, memoryBlock);
  }

  /**
   * Address: 0x00B2BC20 (_m2absr_clear)
   *
   * What it does:
   * Zeroes one memory block for M2A runtime paths.
   */
  std::int32_t m2absr_clear(void* const destination, const unsigned int byteCount)
  {
    std::memset(destination, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B2B910 (M2ABSR_Initialize)
   *
   * What it does:
   * Initializes M2A bitstream runtime lane.
   */
  std::int32_t M2ABSR_Initialize()
  {
    return 0;
  }

  /**
   * Address: 0x00B2B920 (M2ABSR_Finalize)
   *
   * What it does:
   * Finalizes M2A bitstream runtime lane.
   */
  std::int32_t M2ABSR_Finalize()
  {
    return 0;
  }

  /**
   * Address: 0x00B2B930 (M2ABSR_Create)
   *
   * What it does:
   * Allocates and zero-initializes one M2A bitstream state object.
   */
  std::int32_t M2ABSR_Create(const std::int32_t heapManagerHandle, std::int32_t** const outBitstream)
  {
    if (outBitstream == nullptr) {
      return -1;
    }

    auto* const bitstream = static_cast<M2aBitstreamRuntimeView*>(m2absr_malloc(heapManagerHandle, 0x18u));
    if (bitstream == nullptr) {
      return -1;
    }

    m2absr_clear(bitstream, 0x18u);
    *reinterpret_cast<std::int32_t*>(bitstream) = heapManagerHandle;
    *outBitstream = reinterpret_cast<std::int32_t*>(bitstream);
    return 0;
  }

  /**
   * Address: 0x00B2B980 (M2ABSR_Destroy)
   *
   * What it does:
   * Clears one M2A bitstream state object and frees its storage.
   */
  std::int32_t M2ABSR_Destroy(std::int32_t* const bitstreamHandle)
  {
    if (bitstreamHandle == nullptr) {
      return -1;
    }

    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    const auto heapManagerHandle = *reinterpret_cast<std::int32_t*>(bitstream);
    m2absr_clear(bitstream, 0x18u);
    m2absr_free(heapManagerHandle, bitstream);
    return 0;
  }

  /**
   * Address: 0x00B2B9B0 (M2ABSR_Reset)
   *
   * What it does:
   * Clears cursor/end/overrun lanes for one M2A bitstream state.
   */
  std::int32_t M2ABSR_Reset(std::uint32_t* const bitstreamState)
  {
    if (bitstreamState == nullptr) {
      return -1;
    }

    bitstreamState[1] = 0;
    bitstreamState[2] = 0;
    bitstreamState[3] = 0;
    bitstreamState[4] = 0;
    bitstreamState[5] = 0;
    return 0;
  }

  /**
   * Address: 0x00B2B9D0 (M2ABSR_SetBuffer)
   *
   * What it does:
   * Binds one source buffer and byte size to the M2A bitstream state.
   */
  std::int32_t M2ABSR_SetBuffer(
    std::uint32_t* const bitstreamState,
    const std::int32_t sourceBuffer,
    const std::int32_t sourceBytes
  )
  {
    if (bitstreamState == nullptr) {
      return -1;
    }

    bitstreamState[4] = 0;
    bitstreamState[1] = static_cast<std::uint32_t>(sourceBuffer);
    bitstreamState[2] = static_cast<std::uint32_t>(sourceBytes);
    bitstreamState[5] = 0;
    bitstreamState[3] = static_cast<std::uint32_t>(8 * sourceBytes);
    return 0;
  }

  /**
   * Address: 0x00B2BA00 (M2ABSR_Read)
   *
   * What it does:
   * Reads one bounded bit range and advances current bit cursor.
   */
  std::int32_t M2ABSR_Read(
    const std::int32_t bitstreamHandle,
    const std::int32_t bitCount,
    void* const outBits
  )
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    auto* const outBitsValue = static_cast<std::int32_t*>(outBits);
    if (bitstream == nullptr || outBitsValue == nullptr) {
      return -1;
    }

    const auto currentBitPosition = static_cast<std::int32_t>(bitstream->bitPosition);
    const auto newBitPosition = currentBitPosition + bitCount;
    if (newBitPosition > static_cast<std::int32_t>(bitstream->bitEndPosition)) {
      bitstream->overrunCount = 1;
      *outBitsValue = 0;
      return -1;
    }

    std::int32_t readValue = 0;
    std::int32_t remainingBits = bitCount;
    auto currentByteIndex = currentBitPosition >> 3;
    auto currentBitOffset = currentBitPosition & 7;

    if (remainingBits > 0) {
      const auto sourceBase = reinterpret_cast<std::uint8_t*>(
        static_cast<std::uintptr_t>(
          *reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(bitstream) + 0x04)
        )
      );

      auto* sourceCursor = sourceBase + currentByteIndex;
      while (remainingBits > 0) {
        auto chunkBits = 8 - currentBitOffset;
        if (remainingBits < chunkBits) {
          chunkBits = remainingBits;
        }

        remainingBits -= chunkBits;

        const auto byteValue = static_cast<std::uint8_t>(*sourceCursor++);
        const auto shiftedRight = static_cast<std::uint32_t>(byteValue) >> (8 - currentBitOffset - chunkBits);
        const auto chunkMask = static_cast<std::uint32_t>(0xFFu >> (8 - chunkBits));

        readValue = static_cast<std::int32_t>(shiftedRight & chunkMask) + (readValue << chunkBits);
        currentBitOffset = 0;
      }
    }

    *outBitsValue = readValue;
    bitstream->bitPosition = static_cast<std::uint32_t>(newBitPosition);
    return 0;
  }

  /**
   * Address: 0x00B2BAB0 (M2ABSR_AlignToByteBoundary)
   *
   * What it does:
   * Advances bit cursor to next byte boundary.
   */
  std::int32_t M2ABSR_AlignToByteBoundary(const std::int32_t bitstreamHandle)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr) {
      return -1;
    }

    bitstream->bitPosition = (bitstream->bitPosition + 7u) & 0xFFFFFFF8u;
    return 0;
  }

  /**
   * Address: 0x00B2BAD0 (M2ABSR_Seek)
   *
   * What it does:
   * Sets or offsets the bit cursor using begin/current/end origins.
   */
  std::int32_t M2ABSR_Seek(
    const std::int32_t bitstreamHandle,
    const std::int32_t bitOffset,
    const std::int32_t origin
  )
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr) {
      return -1;
    }

    if (origin == 0) {
      bitstream->bitPosition = static_cast<std::uint32_t>(bitOffset);
      return 0;
    }

    if (origin == 1) {
      bitstream->bitPosition = static_cast<std::uint32_t>(static_cast<std::int32_t>(bitstream->bitPosition) + bitOffset);
      return 0;
    }

    if (origin == 2) {
      bitstream->bitPosition = static_cast<std::uint32_t>(bitOffset + static_cast<std::int32_t>(bitstream->bitEndPosition));
      return 0;
    }

    return -1;
  }

  /**
   * Address: 0x00B2C5A0 (_ADX_SetDecodeSteAsMonoSw)
   *
   * What it does:
   * Sets stereo-float decode output mode lane (`mono` or `stereo`).
   */
  std::int32_t ADX_SetDecodeSteAsMonoSw(const std::int32_t outputAsMono)
  {
    adx_decode_output_mono_flag = outputAsMono;
    return outputAsMono;
  }

  /**
   * Address: 0x00B2CC90 (_ADX_DecodeSteFloat)
   *
   * What it does:
   * Dispatches stereo-float ADX decode to mono or stereo path based on runtime
   * switch lane.
   */
  std::int32_t ADX_DecodeSteFloat(
    char* sourceBytes,
    const std::int32_t blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    const std::int16_t decodeScale,
    const float scaleFactor
  )
  {
    if (adx_decode_output_mono_flag != 0) {
      return ADX_DecodeSteFloatAsMono(
        sourceBytes,
        blockCount,
        outLeftSamples,
        leftHistory,
        outRightSamples,
        rightHistory,
        decodeScale,
        scaleFactor
      );
    }

    return ADX_DecodeSteFloatAsSte(
      sourceBytes,
      blockCount,
      outLeftSamples,
      leftHistory,
      outRightSamples,
      rightHistory,
      decodeScale,
      scaleFactor
    );
  }

  /**
   * Address: 0x00B20200 (sub_B20200)
   *
   * What it does:
   * Iterates queued entries on all active XEFIC objects and invokes one
   * visitor callback per queued entry until callback aborts with `-1`.
   */
  void xefic_ForEachQueuedEntryAcrossObjects(XeficQueueVisitor visitor, const std::int32_t contextValue)
  {
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0) {
        continue;
      }

      const auto queuedEntryCount = object->queuedEntryCount;
      object->queueCursor = object->queueHead;

      if (queuedEntryCount <= 0) {
        continue;
      }

      for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
        XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
        if (visitor(queueEntry, contextValue) == -1) {
          return;
        }
      }
    }
  }

  /**
   * Address: 0x00B20260 (sub_B20260)
   *
   * What it does:
   * Locks XEFIC global critical section, dumps one object's queued entries to
   * debug output, then unlocks.
   */
  void xefic_DebugDumpQueueForObjectLocked(XeficObject* object)
  {
    xefic_lock();
    xefic_DebugDumpQueueForObjectUnlocked(object);
    xefic_unlock();
  }

  /**
   * Address: 0x00B20280 (sub_B20280)
   *
   * What it does:
   * Dumps one object's queued entry names and opened/closed status to debug
   * output.
   */
  void xefic_DebugDumpQueueForObjectUnlocked(XeficObject* object)
  {
    XeficDumpQueuedEntriesForObject(object);
  }

  /**
   * Address: 0x00B20310 (sub_B20310)
   *
   * What it does:
   * Locks XEFIC global critical section, dumps all objects' queued entries to
   * debug output, then unlocks.
   */
  void xefic_DebugDumpAllQueuesLocked()
  {
    xefic_lock();
    xefic_DebugDumpAllQueuesUnlocked();
    xefic_unlock();
  }

  /**
   * Address: 0x00B20320 (sub_B20320)
   *
   * What it does:
   * Dumps queued entry names/status for all active XEFIC objects to debug
   * output.
   */
  void xefic_DebugDumpAllQueuesUnlocked()
  {
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0) {
        continue;
      }
      XeficDumpQueuedEntriesForObject(object);
    }
  }

  /**
   * Address: 0x00B203C0 (sub_B203C0)
   *
   * What it does:
   * Returns one XEFIC object state lane (`+0x04`).
   */
  std::int32_t xefic_GetObjectState(const XeficObject* object)
  {
    return object->state;
  }

  /**
   * Address: 0x00B203D0 (sub_B203D0)
   *
   * What it does:
   * Returns one XEFIC object state-signal lane (`+0x08`).
   */
  std::int32_t xefic_GetObjectStateSignal(const XeficObject* object)
  {
    return object->stateSignal;
  }

  /**
   * Address: 0x00B203E0 (sub_B203E0)
   *
   * What it does:
   * Clears state lanes when state-reset guard lane is active.
   */
  XeficObject* xefic_ResetObjectStateIfGuarded(XeficObject* object)
  {
    if (object->stateResetGuard != nullptr) {
      if (object->state == 6) {
        object->state = 0;
      }
      object->stateSignal = 0;
    }
    return object;
  }

  /**
   * Address: 0x00B1C040 (_m2asjd_default_callback)
   *
   * What it does:
   * Default M2ASJD error callback lane; reports success/no-op.
   */
  std::int32_t __cdecl m2asjd_default_callback(
    [[maybe_unused]] const std::int32_t callbackObject,
    [[maybe_unused]] const char* const errorMessage
  )
  {
    return 0;
  }

  /**
   * Address: 0x00B1BFD0 (_M2ASJD_SetCbErr)
   *
   * What it does:
   * Installs M2ASJD error callback lane; falls back to default callback when
   * caller provides null.
   */
  std::int32_t __cdecl M2ASJD_SetCbErr(M2asjdErrorCallback callback, const std::int32_t callbackObject)
  {
    if (callback != nullptr) {
      m2asjd_err_func = callback;
    } else {
      m2asjd_err_func = &m2asjd_default_callback;
    }
    m2asjd_err_obj = callbackObject;
    return 0;
  }

  /**
   * Address: 0x00B1C020 (_m2asjd_SetCbDcd)
   *
   * What it does:
   * Stores M2ASJD decode callback/object lanes used by decode server updates.
   */
  std::int32_t __cdecl m2asjd_SetCbDcd(M2asjdDecodeCallback decodeCallback, const std::int32_t callbackObject)
  {
    m2asjd_dcd_func = decodeCallback;
    m2asjd_dcd_obj = callbackObject;
    return 0;
  }

  /**
   * Address: 0x00B1C0C0 (_m2asjd_call_err_func)
   *
   * What it does:
   * Forwards one M2ASJD error message lane to the registered callback lane.
   */
  std::int32_t __cdecl m2asjd_call_err_func(const char* const errorMessage)
  {
    if (m2asjd_err_func != nullptr) {
      m2asjd_err_func(m2asjd_err_obj, errorMessage);
    }
    return 0;
  }

  /**
   * Address: 0x00B1B200 (FUN_00B1B200, _mpasjd_lock)
   *
   * What it does:
   * Enters the MPASJD decoder critical section lane.
   */
  void __cdecl mpasjd_lock()
  {
    EnterCriticalSection(&mpasjd_crs);
  }

  /**
   * Address: 0x00B1B210 (FUN_00B1B210, _mpasjd_unlock)
   *
   * What it does:
   * Leaves the MPASJD decoder critical section lane.
   */
  void __cdecl mpasjd_unlock()
  {
    LeaveCriticalSection(&mpasjd_crs);
  }

  /**
   * Address: 0x00B1C050 (_m2asjd_lock)
   *
   * What it does:
   * Enters the M2ASJD decoder critical section and reports trapped failures.
   */
  std::int32_t __cdecl m2asjd_lock()
  {
#if defined(_MSC_VER)
    __try {
      EnterCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdEnterCriticalSectionFailedMessage);
    }
#else
    EnterCriticalSection(&m2asjd_crs);
#endif
    return 0;
  }

  /**
   * Address: 0x00B1C0E0 (_m2asjd_unlock)
   *
   * What it does:
   * Leaves the M2ASJD decoder critical section and reports trapped failures.
   */
  std::int32_t __cdecl m2asjd_unlock()
  {
#if defined(_MSC_VER)
    __try {
      LeaveCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdLeaveCriticalSectionFailedMessage);
    }
#else
    LeaveCriticalSection(&m2asjd_crs);
#endif
    return 0;
  }

  /**
   * Address: 0x00B1C1F0 (_m2asjd_Init)
   *
   * What it does:
   * Initializes the shared M2A decoder backend for the M2ASJD lane.
   */
  std::int32_t __cdecl m2asjd_Init()
  {
    M2ADEC_Initialize();
    return 0;
  }

  /**
   * Address: 0x00B1C150 (_M2ASJD_Init)
   *
   * What it does:
   * First-user startup for M2ASJD runtime: bumps init refcount, initializes
   * lock, then enters lane lock to run shared decoder initialization.
   */
  std::int32_t __cdecl M2ASJD_Init()
  {
    if (InterlockedIncrement(&m2asjd_init_count) != 1) {
      return 0;
    }

#if defined(_MSC_VER)
    __try {
      InitializeCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdInitializeCriticalSectionFailedMessage);
    }
#else
    InitializeCriticalSection(&m2asjd_crs);
#endif

    m2asjd_lock();
    const std::int32_t initResult = m2asjd_Init();
    m2asjd_unlock();
    return initResult;
  }

  /**
   * Address: 0x00B1C2A0 (_m2asjd_Finish)
   *
   * What it does:
   * Destroys all active M2ASJD decoder entries then finalizes shared M2A
   * decoder backend state.
   */
  std::int32_t __cdecl m2asjd_Finish()
  {
    while (m2asjd_entry != nullptr) {
      m2asjd_Destroy(m2asjd_entry);
    }
    M2ADEC_Finalize();
    return 0;
  }

  /**
   * Address: 0x00B1C200 (_M2ASJD_Finish)
   *
   * What it does:
   * Last-user shutdown for M2ASJD runtime: decrements init refcount, runs
   * decoder finish under lock, then deletes the critical section lane.
   */
  std::int32_t __cdecl M2ASJD_Finish()
  {
    if (InterlockedDecrement(&m2asjd_init_count) != 0) {
      return 0;
    }

    m2asjd_lock();
    const std::int32_t finishResult = m2asjd_Finish();
    m2asjd_unlock();

#if defined(_MSC_VER)
    __try {
      DeleteCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdDeleteCriticalSectionFailedMessage);
    }
#else
    DeleteCriticalSection(&m2asjd_crs);
#endif

    return finishResult;
  }

  /**
   * Address: 0x00B1C000 (_M2ASJD_SetCbDcd)
   *
   * What it does:
   * Updates M2ASJD decode callback/object lanes under global M2ASJD lock.
   */
  std::int32_t __cdecl M2ASJD_SetCbDcd(
    const M2asjdDecodeCallback decodeCallback,
    const std::int32_t callbackObject
  )
  {
    m2asjd_lock();
    m2asjd_SetCbDcd(decodeCallback, callbackObject);
    m2asjd_unlock();
    return 0;
  }

  /**
   * Address: 0x00B1C5F0 (_m2asjd_ExecHndl)
   *
   * What it does:
   * Executes one M2ASJD decode lane step: pulls staged input, runs M2A decode,
   * updates callback/state lanes, and dispatches output path by downmix mode.
   */
  std::int32_t __cdecl m2asjd_ExecHndl(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdNullDecoderHandleMessage);
      return -1;
    }

    if (decoder->runState != kM2asjdStatePrimed && decoder->runState != kM2asjdStateRunning) {
      return 0;
    }

    if (
      decoder->termSupplyFlag == kM2asjdTermSupplyEnabled
      && decoder->sourceStream->QueryAvailableBytes(kM2asjdLaneSource) < kM2asjdProcessWindowBytes
    ) {
      M2ADEC_BeginFlush(decoder->decoderContext);
    }

    if (decoder->runState == kM2asjdStatePrimed) {
      decoder->runState = kM2asjdStateRunning;
    }

    m2asjd_input_proc(decoder);

    SjChunkRange outputChunk{};
    decoder->outputStreams[0]->AcquireChunk(kM2asjdLaneOutput, kM2asjdProcessWindowBytes, &outputChunk);
    if (outputChunk.byteCount < kM2asjdMinimumProcessBytes) {
      decoder->outputStreams[0]->ReturnChunk(kM2asjdLaneOutput, &outputChunk);
      return 0;
    }
    decoder->outputStreams[0]->ReturnChunk(kM2asjdLaneOutput, &outputChunk);

    SjChunkRange inputChunk{};
    decoder->stagingStream->AcquireChunk(kM2asjdLaneSource, kM2asjdProcessWindowBytes, &inputChunk);
    if (
      decoder->termSupplyFlag != kM2asjdTermSupplyEnabled
      && inputChunk.byteCount < kM2asjdProcessWindowBytes
    ) {
      decoder->stagingStream->ReturnChunk(kM2asjdLaneSource, &inputChunk);
      return 0;
    }

    const std::int32_t previousDecodedSampleCount = decoder->decodedSampleCount;
    std::int32_t consumedInputBytes = 0;
    M2ADEC_Process(decoder->decoderContext, inputChunk.bufferAddress, inputChunk.byteCount, &consumedInputBytes);

    decoder->decodedByteCount += consumedInputBytes;
    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, &decoder->decodedSampleCount);

    if (m2asjd_dcd_func != nullptr) {
      std::int32_t decodedChannelCount = 0;
      M2ADEC_GetNumChannels(decoder->decoderContext, &decodedChannelCount);
      const std::int32_t producedSampleCount = decoder->decodedSampleCount - previousDecodedSampleCount;
      const std::int32_t producedByteCount = 2 * decodedChannelCount * producedSampleCount;
      m2asjd_dcd_func(m2asjd_dcd_obj, decoder, consumedInputBytes, producedByteCount);
    }

    SjChunkRange unreadChunk{};
    SJ_SplitChunk(&inputChunk, consumedInputBytes, &inputChunk, &unreadChunk);
    decoder->stagingStream->ReturnChunk(kM2asjdLaneSource, &unreadChunk);
    decoder->stagingStream->CommitChunk(kM2asjdLaneOutput, &inputChunk);

    std::int32_t decoderStatus = 0;
    M2ADEC_GetStatus(decoder->decoderContext, &decoderStatus);
    if (decoderStatus == kM2asjdDecoderStatusError) {
      std::int32_t decoderErrorCode = 0;
      M2ADEC_GetErrorCode(decoder->decoderContext, &decoderErrorCode);
      if (decoderErrorCode == kM2asjdDecoderErrorOutOfMemory) {
        m2asjd_call_err_func(kM2asjdAllocateDecoderMemoryMessage);
      } else if (decoderErrorCode == kM2asjdDecoderErrorAdifResume) {
        m2asjd_call_err_func(kM2asjdResumeAdifDecodeMessage);
      } else {
        m2asjd_call_err_func(kM2asjdUnknownDecoderErrorMessage);
      }
      decoder->runState = kM2asjdStateError;
      return -1;
    }

    M2ADEC_GetStatus(decoder->decoderContext, &decoderStatus);
    if (decoderStatus == kM2asjdDecoderStatusFlushed) {
      decoder->runState = kM2asjdStateFlushed;
    }

    std::int32_t decodedSampleCount = 0;
    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, &decodedSampleCount);
    if (decodedSampleCount == 0) {
      return 0;
    }

    std::int32_t decodedFrameCount = 0;
    M2ADEC_GetNumFramesDecoded(decoder->decoderContext, &decodedFrameCount);
    if (decoder->lastOutputFrameCount == decodedFrameCount) {
      return 0;
    }

    if (decoder->downmixMode == kM2asjdOutputModeStereo) {
      m2asjd_output_stereo(decoder);
    } else if (decoder->downmixMode == kM2asjdOutputModeSurround) {
      m2asjd_output_surround(decoder);
    } else if (decoder->downmixMode == kM2asjdOutputModeAdx) {
      m2asjd_output_adx(decoder);
    } else {
      m2asjd_output_proc(decoder);
    }

    decoder->lastOutputFrameCount = decodedFrameCount;
    return 0;
  }

  /**
   * Address: 0x00B1C5B0 (_m2asjd_ExecServer)
   *
   * What it does:
   * Iterates active M2ASJD decoder entries from newest to older lane and
   * executes one handle step per entry.
   */
  std::int32_t __cdecl m2asjd_ExecServer()
  {
    for (M2asjdDecoderState* decoder = m2asjd_entry; decoder != nullptr; decoder = decoder->nextOlder) {
      m2asjd_ExecHndl(decoder);
    }
    return 0;
  }

  /**
   * Address: 0x00B1C590 (_M2ASJD_ExecServer)
   *
   * What it does:
   * Runs one M2ASJD server tick under global lock and returns inner exec code.
   */
  std::int32_t __cdecl M2ASJD_ExecServer()
  {
    m2asjd_lock();
    const std::int32_t execResult = m2asjd_ExecServer();
    m2asjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1C5D0 (_M2ASJD_ExecHndl)
   *
   * What it does:
   * Runs one M2ASJD decoder handle step under global lock.
   */
  std::int32_t __cdecl M2ASJD_ExecHndl(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t execResult = m2asjd_ExecHndl(decoder);
    m2asjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1C520 (_M2ASJD_Reset)
   *
   * What it does:
   * Runs one M2ASJD decoder reset lane under the global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_Reset(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t resetResult = m2asjd_Reset(decoder);
    m2asjd_unlock();
    return resetResult;
  }

  /**
   * Address: 0x00B1C540 (_m2asjd_Reset)
   *
   * What it does:
   * Resets one decoder lane state, including staged I/O reset and decode counters.
   */
  std::int32_t __cdecl m2asjd_Reset(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdResetNullPointerMessage);
      return -1;
    }

    if (decoder->decoderContext != nullptr) {
      M2ADEC_Reset(decoder->decoderContext);
    }

    if (decoder->stagingStream != nullptr) {
      decoder->stagingStream->Reset();
    }

    decoder->decodedByteCount = 0;
    decoder->decodedSampleCount = 0;
    decoder->lastOutputFrameCount = 0;
    decoder->termSupplyFlag = 0;
    return 0;
  }

  /**
   * Address: 0x00B1CD80 (_M2ASJD_Start)
   *
   * What it does:
   * Runs one decoder start lane under lock.
   */
  std::int32_t __cdecl M2ASJD_Start(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t startResult = m2asjd_Start(decoder);
    m2asjd_unlock();
    return startResult;
  }

  /**
   * Address: 0x00B1CDA0 (_m2asjd_Start)
   *
   * What it does:
   * Starts one decoder lane; if stopped/flushed it first resets runtime counters.
   */
  std::int32_t __cdecl m2asjd_Start(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdStartNullPointerMessage);
      return -1;
    }

    if (decoder->runState == 0 || decoder->runState == kM2asjdStateFlushed) {
      m2asjd_Reset(decoder);
      decoder->runState = kM2asjdStatePrimed;
    }

    M2ADEC_Start(decoder->decoderContext);
    return 0;
  }

  /**
   * Address: 0x00B1CDF0 (_M2ASJD_Stop)
   *
   * What it does:
   * Runs one decoder stop lane under lock.
   */
  std::int32_t __cdecl M2ASJD_Stop(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t stopResult = m2asjd_Stop(decoder);
    m2asjd_unlock();
    return stopResult;
  }

  /**
   * Address: 0x00B1CE10 (_m2asjd_Stop)
   *
   * What it does:
   * Stops one decoder lane and clears run-state lane.
   */
  std::int32_t __cdecl m2asjd_Stop(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdStopNullPointerMessage);
      return -1;
    }

    M2ADEC_Stop(decoder->decoderContext);
    decoder->runState = 0;
    return 0;
  }

  /**
   * Address: 0x00B1CE50 (_M2ASJD_GetStat)
   *
   * What it does:
   * Runs one status query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetStat(M2asjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    m2asjd_lock();
    const std::int32_t statusResult = m2asjd_GetStat(decoder, outStatus);
    m2asjd_unlock();
    return statusResult;
  }

  /**
   * Address: 0x00B1CE80 (_m2asjd_GetStat)
   *
   * What it does:
   * Returns current decoder run-state lane.
   */
  std::int32_t __cdecl m2asjd_GetStat(M2asjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGetStatusNullPointerMessage);
      return -1;
    }

    *outStatus = decoder->runState;
    return 0;
  }

  /**
   * Address: 0x00B1CEB0 (_M2ASJD_GetNumChannels)
   *
   * What it does:
   * Runs one channel-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumChannels(M2asjdDecoderState* const decoder, std::int32_t* const outChannelCount)
  {
    m2asjd_lock();
    const std::int32_t channelResult = m2asjd_GetNumChannels(decoder, outChannelCount);
    m2asjd_unlock();
    return channelResult;
  }

  /**
   * Address: 0x00B1CEE0 (_m2asjd_GetNumChannels)
   *
   * What it does:
   * Fetches decoded channel count from the M2A decoder context.
   */
  std::int32_t __cdecl m2asjd_GetNumChannels(M2asjdDecoderState* const decoder, std::int32_t* const outChannelCount)
  {
    if (decoder == nullptr || outChannelCount == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumChannelsNullPointerMessage);
      return -1;
    }

    M2ADEC_GetNumChannels(decoder->decoderContext, outChannelCount);
    return 0;
  }

  /**
   * Address: 0x00B1CF20 (_M2ASJD_GetChannelConfig)
   *
   * What it does:
   * Runs one channel-configuration query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetChannelConfig(
    M2asjdDecoderState* const decoder,
    std::int32_t* const outChannelConfiguration
  )
  {
    m2asjd_lock();
    const std::int32_t configurationResult = m2asjd_GetChannelConfig(decoder, outChannelConfiguration);
    m2asjd_unlock();
    return configurationResult;
  }

  /**
   * Address: 0x00B1CF50 (_m2asjd_GetChannelConfig)
   *
   * What it does:
   * Fetches decoded channel-configuration lane from the M2A context.
   */
  std::int32_t __cdecl m2asjd_GetChannelConfig(
    M2asjdDecoderState* const decoder,
    std::int32_t* const outChannelConfiguration
  )
  {
    if (decoder == nullptr || outChannelConfiguration == nullptr) {
      m2asjd_call_err_func(kM2asjdGetChannelConfigNullPointerMessage);
      return -1;
    }

    M2ADEC_GetChannelConfiguration(decoder->decoderContext, outChannelConfiguration);
    return 0;
  }

  /**
   * Address: 0x00B1CF90 (_M2ASJD_GetFrequency)
   *
   * What it does:
   * Runs one sampling-frequency query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetFrequency(M2asjdDecoderState* const decoder, std::int32_t* const outFrequency)
  {
    m2asjd_lock();
    const std::int32_t frequencyResult = m2asjd_GetFrequency(decoder, outFrequency);
    m2asjd_unlock();
    return frequencyResult;
  }

  /**
   * Address: 0x00B1CFC0 (_m2asjd_GetFrequency)
   *
   * What it does:
   * Fetches current decoder output frequency lane from M2A context.
   */
  std::int32_t __cdecl m2asjd_GetFrequency(M2asjdDecoderState* const decoder, std::int32_t* const outFrequency)
  {
    if (decoder == nullptr || outFrequency == nullptr) {
      m2asjd_call_err_func(kM2asjdGetFrequencyNullPointerMessage);
      return -1;
    }

    M2ADEC_GetFrequency(decoder->decoderContext, outFrequency);
    return 0;
  }

  /**
   * Address: 0x00B1D000 (_M2ASJD_GetNumBits)
   *
   * What it does:
   * Runs one output bit-depth query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumBits(M2asjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    m2asjd_lock();
    const std::int32_t bitResult = m2asjd_GetNumBits(decoder, outBitsPerSample);
    m2asjd_unlock();
    return bitResult;
  }

  /**
   * Address: 0x00B1D030 (_m2asjd_GetNumBits)
   *
   * What it does:
   * Returns fixed output PCM bit depth for M2ASJD decode lane.
   */
  std::int32_t __cdecl m2asjd_GetNumBits(M2asjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    if (decoder == nullptr || outBitsPerSample == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumBitsNullPointerMessage);
      return -1;
    }

    *outBitsPerSample = kM2asjdBitsPerSample;
    return 0;
  }

  /**
   * Address: 0x00B1D060 (_M2ASJD_GetNumSmplsDcd)
   *
   * What it does:
   * Runs one decoded-sample-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumSmplsDcd(M2asjdDecoderState* const decoder, std::int32_t* const outSampleCount)
  {
    m2asjd_lock();
    const std::int32_t sampleResult = m2asjd_GetNumSmplsDcd(decoder, outSampleCount);
    m2asjd_unlock();
    return sampleResult;
  }

  /**
   * Address: 0x00B1D090 (_m2asjd_GetNumSmplsDcd)
   *
   * What it does:
   * Fetches total decoded sample count from M2A context.
   */
  std::int32_t __cdecl m2asjd_GetNumSmplsDcd(M2asjdDecoderState* const decoder, std::int32_t* const outSampleCount)
  {
    if (decoder == nullptr || outSampleCount == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumSmplsDcdNullPointerMessage);
      return -1;
    }

    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, outSampleCount);
    return 0;
  }

  /**
   * Address: 0x00B1D0D0 (_M2ASJD_GetNumBytesDcd)
   *
   * What it does:
   * Runs one decoded-byte-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumBytesDcd(M2asjdDecoderState* const decoder, std::int32_t* const outDecodedBytes)
  {
    m2asjd_lock();
    const std::int32_t byteResult = m2asjd_GetNumBytesDcd(decoder, outDecodedBytes);
    m2asjd_unlock();
    return byteResult;
  }

  /**
   * Address: 0x00B1D100 (_m2asjd_GetNumBytesDcd)
   *
   * What it does:
   * Returns accumulated consumed-input byte count lane.
   */
  std::int32_t __cdecl m2asjd_GetNumBytesDcd(M2asjdDecoderState* const decoder, std::int32_t* const outDecodedBytes)
  {
    if (decoder == nullptr || outDecodedBytes == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumBytesDcdNullPointerMessage);
      return -1;
    }

    *outDecodedBytes = decoder->decodedByteCount;
    return 0;
  }

  /**
   * Address: 0x00B1D1C0 (_M2ASJD_GetDownmixMode)
   *
   * What it does:
   * Runs one downmix-mode query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetDownmixMode(M2asjdDecoderState* const decoder, std::int32_t* const outDownmixMode)
  {
    m2asjd_lock();
    const std::int32_t downmixResult = m2asjd_GetDownmixMode(decoder, outDownmixMode);
    m2asjd_unlock();
    return downmixResult;
  }

  /**
   * Address: 0x00B1D1F0 (_m2asjd_GetDownmixMode)
   *
   * What it does:
   * Returns one decoder lane downmix-mode setting.
   */
  std::int32_t __cdecl m2asjd_GetDownmixMode(M2asjdDecoderState* const decoder, std::int32_t* const outDownmixMode)
  {
    if (decoder == nullptr || outDownmixMode == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    *outDownmixMode = decoder->downmixMode;
    return 0;
  }

  /**
   * Address: 0x00B1D2C0 (_M2ASJD_SetDownmixMode)
   *
   * What it does:
   * Runs one downmix-mode update lane under lock.
   */
  std::int32_t __cdecl M2ASJD_SetDownmixMode(M2asjdDecoderState* const decoder, const std::int32_t downmixMode)
  {
    m2asjd_lock();
    const std::int32_t setResult = m2asjd_SetDownmixMode(decoder, downmixMode);
    m2asjd_unlock();
    return setResult;
  }

  /**
   * Address: 0x00B1D2F0 (_m2asjd_SetDownmixMode)
   *
   * What it does:
   * Stores one decoder lane downmix-mode setting.
   */
  std::int32_t __cdecl m2asjd_SetDownmixMode(M2asjdDecoderState* const decoder, const std::int32_t downmixMode)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    decoder->downmixMode = downmixMode;
    return 0;
  }

  /**
   * Address: 0x00B1D320 (_M2ASJD_TermSupply)
   *
   * What it does:
   * Runs one term-supply toggle lane under lock.
   */
  std::int32_t __cdecl M2ASJD_TermSupply(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t termResult = m2asjd_TermSupply(decoder);
    m2asjd_unlock();
    return termResult;
  }

  /**
   * Address: 0x00B1D340 (_m2asjd_TermSupply)
   *
   * What it does:
   * Enables end-of-supply flush mode for one decoder lane.
   */
  std::int32_t __cdecl m2asjd_TermSupply(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    decoder->termSupplyFlag = kM2asjdTermSupplyEnabled;
    return 0;
  }

  /**
   * Address: 0x00B20400 (xefic_init_lock)
   *
   * What it does:
   * Initializes XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_init_lock()
  {
    XeficInvokeCriticalSectionApi(&InitializeCriticalSection, kInitializeCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B20470 (xefic_delete_lock)
   *
   * What it does:
   * Deletes XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_delete_lock()
  {
    XeficInvokeCriticalSectionApi(&DeleteCriticalSection, kDeleteCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B204E0 (xefic_lock)
   *
   * What it does:
   * Enters XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_lock()
  {
    XeficInvokeCriticalSectionApi(&EnterCriticalSection, kEnterCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B20550 (xefic_unlock)
   *
   * What it does:
   * Leaves XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_unlock()
  {
    XeficInvokeCriticalSectionApi(&LeaveCriticalSection, kLeaveCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B10B30 (_xeci_assert)
   *
   * What it does:
   * Dispatches one XECI error callback lane when registered.
   */
  void __cdecl xeci_assert(const std::int32_t errorCode, const char* const errorMessage)
  {
    if (xeci_err_func != nullptr) {
      xeci_err_func(xeci_err_obj, errorMessage, errorCode);
    }
  }

  /**
   * Address: 0x00B11B50 (xeci_error)
   *
   * What it does:
   * Forwards one XECI error message through `xeci_assert`.
   */
  int __cdecl xeci_error(const std::int32_t callbackObject, const char* const errorMessage)
  {
    xeci_assert(callbackObject, errorMessage);
    return 0;
  }

  /**
   * Address: 0x00B11990 (FUN_00B11990, _xeci_GetFileSizeFromPath)
   *
   * What it does:
   * Queries one path file-size lane through Win32 find APIs under wxCi lock
   * and restores caller XECI lock depth on all exits.
   */
  std::uint64_t __cdecl xeci_GetFileSizeFromPath(const char* const fileName)
  {
    WIN32_FIND_DATAA findFileData{};
    const std::int32_t removedLockCount = xeci_lock_count();
    wxCiLock();
    const HANDLE findHandle = FindFirstFileA(fileName, &findFileData);
    wxCiUnLock();

    if (findHandle == INVALID_HANDLE_VALUE) {
      std::sprintf(wxfic_cache_file, kXeciGetFileSizeOpenErrorFormat, fileName);
      xeci_assert(0, wxfic_cache_file);
      xeci_lock_n(removedLockCount);
      return 0;
    }

    wxCiLock();
    FindClose(findHandle);
    wxCiUnLock();

    const std::uint64_t fileSize = (static_cast<std::uint64_t>(findFileData.nFileSizeHigh) << 32u)
      | static_cast<std::uint64_t>(findFileData.nFileSizeLow);
    xeci_lock_n(removedLockCount);
    return fileSize;
  }

  /**
   * Address: 0x00B10F30 (FUN_00B10F30)
   *
   * What it does:
   * Returns one file-size lane using optional XEFIC probe callback first, then
   * falls back to direct path query when the callback is absent or returns a
   * negative value.
   */
  std::int64_t __cdecl xeci_GetFileSizeResolved(const char* const fileName)
  {
    if (xeci_file_size_probe_callback != nullptr) {
      const std::int32_t callbackFileSize = xeci_file_size_probe_callback(fileName);
      if (callbackFileSize >= 0) {
        return static_cast<std::int64_t>(callbackFileSize);
      }
    }

    const std::int64_t fileSize = static_cast<std::int64_t>(xeci_GetFileSizeFromPath(fileName));
    if (fileSize < 0) {
      return kXeciInvalidFileSizeSentinel;
    }
    return fileSize;
  }

  /**
   * Address: 0x00B10F70 (FUN_00B10F70, _xeCiGetFileSize)
   *
   * What it does:
   * Resolves one XECI path against current root directory and returns the
   * low 32-bit file-size lane.
   */
  std::int32_t __cdecl xeCiGetFileSize(const char* const fileName)
  {
    if (fileName == nullptr) {
      xeci_assert(0, kXeciFileNameNullMessage);
      return 0;
    }

    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    return static_cast<std::int32_t>(xeci_GetFileSizeResolved(rootedFileName));
  }

  /**
   * Address: 0x00B10FC0 (FUN_00B10FC0, _xeCiOptionFunc)
   *
   * What it does:
   * Dispatches XECI option-query IDs to transfer-count and file-size accessors.
   */
  std::int32_t __cdecl xeCiOptionFunc(const void* const optionTarget, const std::int32_t optionCode)
  {
    switch (optionCode) {
    case 200:
      return static_cast<std::int32_t>(xeCiGetNumTrUpper(static_cast<const XeciObject*>(optionTarget)));
    case 201:
      return xeCiGetNumTrLower(static_cast<const XeciObject*>(optionTarget));
    case 202:
    case 204:
      return xeCiGetFileSizeUpper(static_cast<const XeciObject*>(optionTarget));
    case 203:
    case 205:
      return xeCiGetFileSizeLower(static_cast<const char*>(optionTarget));
    case 299:
      return 1;
    case 300:
      return static_cast<std::int32_t>(xeCiGetFileSizeByHndl(static_cast<const XeciObject*>(optionTarget)));
    default:
      return -1;
    }
  }

  /**
   * Address: 0x00B110F0 (FUN_00B110F0, xedir_new_handle)
   *
   * What it does:
   * Returns the first free XECI object lane in the fixed global object pool.
   */
  XeciObject* xedir_new_handle()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      if (xedir_work[objectIndex].used == 0) {
        return &xedir_work[objectIndex];
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B111C0 (FUN_00B111C0, _xeCiOpen)
   *
   * What it does:
   * Allocates one XECI object, resolves file handle/size, and initializes
   * chunk geometry for subsequent read requests.
   */
  XeciObject* __cdecl xeCiOpen(const char* const fileName, const std::int32_t /*openMode*/, const std::int32_t readWriteFlag)
  {
    if (fileName == nullptr) {
      xeci_assert(0, kXeciOpenNullFileNameMessage);
      return nullptr;
    }
    if (readWriteFlag != 0) {
      xeci_assert(0, kXeciOpenInvalidRwMessage);
      return nullptr;
    }

    XeciObject* const object = xedir_new_handle();
    if (object == nullptr) {
      xeci_assert(0, kXeciOpenNoHandleMessage);
      return nullptr;
    }

    std::memset(object, 0, sizeof(XeciObject));

    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    std::strcpy(object->fileName, rootedFileName);

    std::int32_t callbackFileSizeLow = 0;
    std::int32_t callbackFileSizeHighUnused = 0;
    HANDLE openedFile = nullptr;
    if (xeci_open_probe_callback != nullptr) {
      openedFile = xeci_open_probe_callback(rootedFileName, &callbackFileSizeLow, &callbackFileSizeHighUnused);
      if (openedFile != nullptr) {
        object->fileHandleOwnedExternally = 1;
      }
    }

    if (openedFile != nullptr) {
      object->fileHandle = openedFile;
      object->fileSizeLow = static_cast<std::uint32_t>(callbackFileSizeLow);
      object->fileSizeHigh = (callbackFileSizeLow < 0) ? -1 : 0;
    } else {
      object->fileHandle = nullptr;
      object->fileSizeLow = static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel);
      object->fileSizeHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u);
    }

    (void)xeci_obj_init(object);
    if (object->fileHandle == nullptr) {
      object->fileHandle = xeci_create_func(object->fileName);
      if (object->fileHandle == nullptr) {
        object->state = static_cast<std::int8_t>(kXeciStateError);
        object->updateLockFlag = 0;
        xeci_obj_overlap_cleanup(object);
        return nullptr;
      }

      const std::uint64_t openedFileSize = xeUtyGetFileSizeEx(object->fileHandle);
      object->fileSizeLow = static_cast<std::uint32_t>(openedFileSize);
      object->fileSizeHigh = static_cast<std::int32_t>(openedFileSize >> 32u);

      const std::uint32_t chunkSize = object->readChunkSizeBytes;
      const std::uint64_t chunkCount = openedFileSize / static_cast<std::uint64_t>(chunkSize);
      object->transferChunkCount = static_cast<std::uint32_t>(chunkCount);
      if ((openedFileSize % static_cast<std::uint64_t>(chunkSize)) != 0u) {
        ++object->transferChunkCount;
      }
    }

    return object;
  }

  /**
   * Address: 0x00B11390 (FUN_00B11390, _xeCiSeek)
   *
   * What it does:
   * Updates one XECI chunk-cursor lane using absolute/current/end origin modes
   * and clamps it to `[0, transferChunkCount]`.
   */
  std::int32_t __cdecl xeCiSeek(XeciObject* const object, const std::int32_t offset, const std::int32_t originMode)
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return 0;
    }

    xeci_lock();
    switch (originMode) {
    case 0:
      object->currentChunkIndex = offset;
      break;
    case 1:
      object->currentChunkIndex += offset;
      break;
    case 2:
      object->currentChunkIndex = static_cast<std::int32_t>(object->transferChunkCount) + offset;
      break;
    default:
      break;
    }

    const std::int32_t maxChunkIndex = static_cast<std::int32_t>(object->transferChunkCount);
    if (object->currentChunkIndex >= maxChunkIndex) {
      object->currentChunkIndex = maxChunkIndex;
    }
    if (object->currentChunkIndex <= 0) {
      object->currentChunkIndex = 0;
    }

    xeci_unlock();
    return object->currentChunkIndex;
  }

  /**
   * Address: 0x00B11410 (FUN_00B11410, _xeCiTell)
   *
   * What it does:
   * Returns one XECI chunk-cursor lane.
   */
  std::int32_t __cdecl xeCiTell(const XeciObject* const object)
  {
    if (object != nullptr) {
      return object->currentChunkIndex;
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11440 (FUN_00B11440, _xeCiReqRead)
   *
   * What it does:
   * Queues one chunked XECI read request and validates read-size, seek, and
   * destination-buffer alignment constraints.
   */
  std::int32_t __cdecl xeCiReqRead(
    XeciObject* const object,
    std::int32_t requestedChunkCount,
    void* const readBuffer
  )
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return 0;
    }
    if (requestedChunkCount < 0) {
      xeci_assert(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(object)), kXeciReqReadNegativeCountMessage);
      return 0;
    }
    if (requestedChunkCount == 0) {
      object->state = 1;
      return 0;
    }

    xeci_lock();
    if (xeci_has_active_transfer() == 1) {
      xeci_unlock();
      return 0;
    }

    if (
      object->fileSizeLow == static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel)
      && object->fileSizeHigh == static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u)
    ) {
      const std::int64_t resolvedFileSize = xeci_GetFileSizeResolved(object->fileName);
      object->fileSizeLow = static_cast<std::uint32_t>(resolvedFileSize);
      object->fileSizeHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(resolvedFileSize) >> 32u);

      const std::int32_t chunkSize = static_cast<std::int32_t>(object->readChunkSizeBytes);
      const std::int64_t totalChunkCount = resolvedFileSize / chunkSize;
      object->transferChunkCount = static_cast<std::uint32_t>(totalChunkCount);
      if ((static_cast<std::uint64_t>(resolvedFileSize) % static_cast<std::uint64_t>(chunkSize)) != 0u) {
        ++object->transferChunkCount;
      }
    }

    if (
      object->fileSizeLow == static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel)
      && object->fileSizeHigh == static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u)
    ) {
      requestedChunkCount = 0;
    }

    object->transferCountLow = 0;
    object->transferCountHigh = 0;
    object->readBufferPtr = readBuffer;

    const std::int32_t remainingChunkCount = static_cast<std::int32_t>(object->transferChunkCount) - object->currentChunkIndex;
    std::int32_t transferChunkCount = (requestedChunkCount < remainingChunkCount) ? requestedChunkCount : remainingChunkCount;
    object->readChunkCount = transferChunkCount;
    if (transferChunkCount >= 0x200) {
      transferChunkCount = 0x200;
    }
    object->readChunkCount = transferChunkCount;

    const std::int64_t readOffsetBytes =
      static_cast<std::int64_t>(object->readChunkSizeBytes) * static_cast<std::int64_t>(object->currentChunkIndex);
    const std::int32_t transferSizeBytes = transferChunkCount * static_cast<std::int32_t>(object->readChunkSizeBytes);
    if (transferSizeBytes == 0) {
      if (object->state != kXeciStateError) {
        object->state = 1;
      }
      xeci_unlock();
      return 0;
    }

    object->readOffsetLow = static_cast<std::int32_t>(readOffsetBytes);
    object->readOffsetHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(readOffsetBytes) >> 32u);
    object->transferSizeBytes = static_cast<std::uint32_t>(transferSizeBytes);
    object->state = static_cast<std::int8_t>(kXeciStateTransferring);
    object->wantsRead = 1;
    object->wantsUpdate = 0;
    xeci_unlock();

    if (xeci_read_file_mode == 0) {
      if ((transferSizeBytes < 0) || ((transferSizeBytes % 0x800) != 0)) {
        xeci_assert(0, kXeciReqReadIllegalSizeMessage);
        return 0;
      }
      if ((static_cast<std::uint64_t>(readOffsetBytes) % 0x800u) != 0u) {
        xeci_assert(0, kXeciReqReadIllegalSeekMessage);
        return 0;
      }
      if ((reinterpret_cast<std::uintptr_t>(readBuffer) & 3u) != 0u) {
        xeci_assert(0, kXeciReqReadIllegalBufferAlignmentMessage);
        return 0;
      }
    }

    if (readBuffer != nullptr) {
      return object->readChunkCount;
    }
    xeci_assert(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(object)), kXeciReqReadNullBufferMessage);
    return 0;
  }

  /**
   * Address: 0x00B11720 (FUN_00B11720, _xeCiGetStat)
   *
   * What it does:
   * Returns one signed XECI state-byte lane.
   */
  std::int32_t __cdecl xeCiGetStat(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->state);
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11770 (FUN_00B11770, _xeCiGetSctLen)
   *
   * What it does:
   * Returns current XECI chunk-size lane.
   */
  std::int32_t __cdecl xeCiGetSctLen(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->readChunkSizeBytes);
    }

    xeci_assert(0, kXeciGetSctLenNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11B60 (FUN_00B11B60, j__xeDirAppendRootDir)
   *
   * What it does:
   * Thunk alias that forwards to `xeDirAppendRootDir`.
   */
  char* __cdecl xeDirAppendRootDirThunk(char* const outputPath, const char* const relativeOrAbsolutePath)
  {
    return xeDirAppendRootDir(outputPath, relativeOrAbsolutePath);
  }

  /**
   * Address: 0x00B11BB0 (FUN_00B11BB0, _xeCiGetFileSizeLower)
   *
   * What it does:
   * Returns low 32-bit file-size lane for one XECI path.
   */
  std::int32_t __cdecl xeCiGetFileSizeLower(const char* const fileName)
  {
    return xeCiGetFileSize(fileName);
  }

  /**
   * Address: 0x00B110E0 (FUN_00B110E0, _xeCiGetFileSizeByHndl)
   *
   * What it does:
   * Returns the signed 64-bit file-size lane cached in one XECI object.
   */
  std::int64_t __cdecl xeCiGetFileSizeByHndl(const XeciObject* const object)
  {
    const std::uint64_t lowPart = static_cast<std::uint64_t>(object->fileSizeLow);
    const std::uint64_t highPart = static_cast<std::uint64_t>(static_cast<std::uint32_t>(object->fileSizeHigh)) << 32;
    return static_cast<std::int64_t>(highPart | lowPart);
  }

  /**
   * Address: 0x00B11120 (FUN_00B11120, xeci_obj_init)
   *
   * What it does:
   * Reinitializes one XECI object lane, rebuilds overlapped event state, and
   * computes transfer chunk count from current file-size lane.
   */
  HANDLE __cdecl xeci_obj_init(XeciObject* const object)
  {
    if (object->overlapped.hEvent != nullptr) {
      CloseHandle(object->overlapped.hEvent);
    }

    const std::int64_t roundedSize = xeCiGetFileSizeByHndl(object) + 0x7FF;
    object->readChunkSizeBytes = 0x800u;
    object->transferChunkCount = static_cast<std::uint32_t>(roundedSize / 0x800);
    object->currentChunkIndex = 0;
    object->readBufferPtr = nullptr;
    object->readChunkCount = 0;
    object->transferCountLow = 0;
    object->transferCountHigh = 0;
    object->state = 0;
    object->wantsRead = 0;
    object->wantsUpdate = 0;
    object->overlapped = {};
    object->overlapped.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    object->used = 1;
    return object->overlapped.hEvent;
  }

  /**
   * Address: 0x00B111A0 (FUN_00B111A0, xeci_obj_overlap_cleanup)
   *
   * What it does:
   * Closes one XECI object overlapped event lane then clears the full object.
   */
  std::int32_t __cdecl xeci_obj_overlap_cleanup(XeciObject* const object)
  {
    if (object->overlapped.hEvent != nullptr) {
      CloseHandle(object->overlapped.hEvent);
    }

    std::memset(object, 0, sizeof(XeciObject));
    return 0;
  }

  /**
   * Address: 0x00B11850 (FUN_00B11850, _xeCiGetNumTr)
   *
   * What it does:
   * Returns low transfer-count lane from one XECI object handle.
   */
  std::int32_t __cdecl xeCiGetNumTr(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->transferCountLow);
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11870 (FUN_00B11870, xeci_obj_cleanup)
   *
   * What it does:
   * Cleans up one XECI object lane, closing owned file handles and zeroing the
   * full object state under XECI lock.
   */
  void __cdecl xeci_obj_cleanup(XeciObject* const object)
  {
    if (object->fileHandleOwnedExternally == 0 && object->fileHandle != nullptr) {
      xeci_obj_handle_cleanup(object->fileHandle);
      object->fileHandle = nullptr;
    }

    xeci_lock();
    object->used = 0;
    xeci_obj_overlap_cleanup(object);
    xeci_unlock();
  }

  /**
   * Address: 0x00B118B0 (FUN_00B118B0, _xeci_create_func)
   *
   * What it does:
   * Opens one file handle for XECI object reads and restores caller lock depth.
   */
  HANDLE __cdecl xeci_create_func(LPCSTR fileName)
  {
    const std::int32_t removedLockCount = xeci_lock_count();
    const char* errorPath = fileName;

    HANDLE openedHandle = INVALID_HANDLE_VALUE;
    if (xeci_read_file_mode != 0) {
      wxCiLock();
      openedHandle = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0x10000000u,
        nullptr
      );
      wxCiUnLock();
    } else {
      openedHandle = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0x70000000u,
        nullptr
      );
    }

    if (openedHandle == INVALID_HANDLE_VALUE) {
      const DWORD lastError = GetLastError();
      std::sprintf(wxfic_cache_file, kXeciOpenFileFailedFormat, errorPath, lastError);
      xeci_assert(0, wxfic_cache_file);
      xeci_lock_n(removedLockCount);
      return nullptr;
    }

    xeci_lock_n(removedLockCount);
    return openedHandle;
  }

  /**
   * Address: 0x00B11960 (FUN_00B11960, xeci_obj_handle_cleanup)
   *
   * What it does:
   * Closes one handle through wxCi lock while preserving caller XECI lock depth.
   */
  void __cdecl xeci_obj_handle_cleanup(const HANDLE objectHandle)
  {
    const std::int32_t removedLockCount = xeci_lock_count();
    wxCiLock();
    CloseHandle(objectHandle);
    wxCiUnLock();
    xeci_lock_n(removedLockCount);
  }

  /**
   * Address: 0x00B11A40 (FUN_00B11A40, _xeUtyGetFileSizeEx)
   *
   * What it does:
   * Reads one file size lane under wxCi lock and returns the 64-bit byte count.
   */
  std::uint64_t __cdecl xeUtyGetFileSizeEx(const HANDLE fileHandle)
  {
    DWORD fileSizeHigh = 0;
    wxCiLock();
    const DWORD fileSizeLow = GetFileSize(fileHandle, &fileSizeHigh);
    wxCiUnLock();
    return (static_cast<std::uint64_t>(fileSizeHigh) << 32) | static_cast<std::uint64_t>(fileSizeLow);
  }

  /**
   * Address: 0x00B11B70 (FUN_00B11B70, _xeCiGetNumTrUpper)
   *
   * What it does:
   * Returns upper 32 bits from one XECI transfer-count lane.
   */
  std::uint64_t __cdecl xeCiGetNumTrUpper(const XeciObject* const object)
  {
    const std::uint64_t transferCount = (static_cast<std::uint64_t>(object->transferCountHigh) << 32)
      | static_cast<std::uint64_t>(object->transferCountLow);
    return transferCount >> 32;
  }

  /**
   * Address: 0x00B11B90 (FUN_00B11B90, _xeCiGetNumTrLower)
   *
   * What it does:
   * Returns lower 32 bits from one XECI transfer-count lane.
   */
  std::int32_t __cdecl xeCiGetNumTrLower(const XeciObject* const object)
  {
    return static_cast<std::int32_t>(object->transferCountLow);
  }

  /**
   * Address: 0x00B11BA0 (FUN_00B11BA0, _xeCiGetFileSizeUpper)
   *
   * What it does:
   * Returns constant zero for the legacy file-size-upper option lane.
   */
  std::int32_t __cdecl xeCiGetFileSizeUpper(const XeciObject* const /*object*/)
  {
    return 0;
  }

  /**
   * Address: 0x00B11A80 (FUN_00B11A80, sub_B11A80)
   *
   * What it does:
   * Updates the global XECI read-mode lane used by file-read dispatch.
   */
  void __cdecl xeci_set_read_mode(
    const std::int32_t /*unusedOptionA*/,
    const std::int32_t /*unusedOptionB*/,
    const std::int32_t /*unusedOptionC*/,
    const std::int32_t readMode
  )
  {
    xeci_read_file_mode = readMode;
  }

  /**
   * Address: 0x00B11BC0 (FUN_00B11BC0, sub_B11BC0)
   *
   * What it does:
   * Requests asynchronous read-abort handling for the active XECI transfer lane.
   */
  void __cdecl xeci_request_async_abort()
  {
    xeci_async_abort_requested = 1;
  }

  /**
   * Address: 0x00B11BD0 (FUN_00B11BD0, wxCiLock_init)
   *
   * What it does:
   * Initializes the wxCi file lock lane and routes read dispatch through chunked reads.
   */
  void wxCiLock_init()
  {
    if (InterlockedIncrement(&wxCiLock_inited) == 1) {
      xeci_set_read_mode(0, 0, 0, 1);
      InitializeCriticalSection(&wxCiLock_obj);
      wxCiLock_fn = &xeci_read_amt_from_file;
    }
  }

  /**
   * Address: 0x00B11C10 (FUN_00B11C10, wxCiLock_destroy)
   *
   * What it does:
   * Tears down the wxCi file lock lane once the final lock user releases it.
   */
  void wxCiLock_destroy()
  {
    if (InterlockedDecrement(&wxCiLock_inited) == 0) {
      wxCiLock_fn = nullptr;
      DeleteCriticalSection(&wxCiLock_obj);
    }
  }

  /**
   * Address: 0x00B11C30 (FUN_00B11C30, wxCiLock)
   *
   * What it does:
   * Enters the wxCi file critical section and increments nested lock depth.
   */
  std::int32_t wxCiLock()
  {
    const std::int32_t lockInitCount = static_cast<std::int32_t>(wxCiLock_inited);
    if (lockInitCount > 0) {
      EnterCriticalSection(&wxCiLock_obj);
      ++wxCiLock_count;
      return wxCiLock_count;
    }

    return lockInitCount;
  }

  /**
   * Address: 0x00B11C50 (FUN_00B11C50, wxCiUnLock)
   *
   * What it does:
   * Leaves the wxCi file critical section and reports unbalanced unlocks.
   */
  void wxCiUnLock()
  {
    if (wxCiLock_inited > 0) {
      --wxCiLock_count;
      if (wxCiLock_count >= 0) {
        LeaveCriticalSection(&wxCiLock_obj);
      } else {
        xeci_assert(0, kXeciUnlockBeforeLockMessage);
      }
    }
  }

  /**
   * Address: 0x00B11C90 (FUN_00B11C90, sub_B11C90)
   *
   * What it does:
   * Returns current nested wxCi lock depth.
   */
  std::int32_t wxCiLock_get_count()
  {
    return wxCiLock_count;
  }

  /**
   * Address: 0x00B11CA0 (FUN_00B11CA0, sub_B11CA0)
   *
   * What it does:
   * Returns current XECI chunk size used by chunked read dispatch.
   */
  DWORD xeci_get_chunk_size()
  {
    return xeci_chunk_size;
  }

  /**
   * Address: 0x00B11CB0 (FUN_00B11CB0, sub_B11CB0)
   *
   * What it does:
   * Updates XECI chunk size used by chunked read dispatch.
   */
  DWORD __cdecl xeci_set_chunk_size(const DWORD chunkSizeBytes)
  {
    xeci_chunk_size = chunkSizeBytes;
    return chunkSizeBytes;
  }

  /**
   * Address: 0x00B11CC0 (FUN_00B11CC0, xeci_read_file)
   *
   * What it does:
   * Dispatches one XECI file-read request through the current read callback lane.
   */
  BOOL __cdecl xeci_read_file(
    const HANDLE fileHandle,
    LPVOID buffer,
    const DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  )
  {
    if (wxCiLock_fn != nullptr) {
      return wxCiLock_fn(fileHandle, buffer, bytesToRead, outBytesRead, overlapped);
    }

    return ReadFile(fileHandle, buffer, bytesToRead, outBytesRead, overlapped);
  }

  /**
   * Address: 0x00B11CF0 (FUN_00B11CF0, xeci_read_amt_from_file)
   *
   * What it does:
   * Reads one file lane in fixed-size chunks under wxCi lock, then reads the tail.
   */
  BOOL __cdecl xeci_read_amt_from_file(
    const HANDLE fileHandle,
    LPVOID buffer,
    const DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  )
  {
    DWORD bytesReadThisCall = 0;
    *outBytesRead = 0;

    std::int32_t fullChunkCount = static_cast<std::int32_t>(bytesToRead / xeci_chunk_size);
    const std::int32_t trailingBytes = static_cast<std::int32_t>(bytesToRead % xeci_chunk_size);
    std::int32_t chunkIndex = 0;
    if (fullChunkCount > 0) {
      while (true) {
        wxCiLock();
        const DWORD offsetBytes = static_cast<DWORD>(chunkIndex) * xeci_chunk_size;
        const BOOL readResult = ReadFile(
          fileHandle,
          static_cast<std::uint8_t*>(buffer) + offsetBytes,
          xeci_chunk_size,
          &bytesReadThisCall,
          overlapped
        );
        wxCiUnLock();

        *outBytesRead += bytesReadThisCall;
        if (readResult == FALSE) {
          return FALSE;
        }

        ++chunkIndex;
        if (chunkIndex >= fullChunkCount) {
          break;
        }
      }
    }

    if (trailingBytes > 0) {
      wxCiLock();
      const DWORD offsetBytes = static_cast<DWORD>(chunkIndex) * xeci_chunk_size;
      const BOOL readResult = ReadFile(
        fileHandle,
        static_cast<std::uint8_t*>(buffer) + offsetBytes,
        static_cast<DWORD>(trailingBytes),
        &bytesReadThisCall,
        overlapped
      );
      wxCiUnLock();

      *outBytesRead += bytesReadThisCall;
      if (readResult == FALSE) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Address: 0x00B1F250 (xeci_lock)
   *
   * What it does:
   * Enters the shared SVM lock lane used by XECI operations.
   */
  void __cdecl xeci_lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B1F260 (xeci_unlock)
   *
   * What it does:
   * Leaves the shared SVM lock lane used by XECI operations.
   */
  void __cdecl xeci_unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B1F290 (xeci_is_locked)
   *
   * What it does:
   * Detects whether current thread runs at XECI lock priority.
   */
  BOOL xeci_is_locked()
  {
    return GetThreadPriority(GetCurrentThread()) == THREAD_PRIORITY_TIME_CRITICAL;
  }

  /**
   * Address: 0x00B1F2B0 (xeci_lock_count)
   *
   * What it does:
   * Force-unlocks nested XECI lock depth and returns removed count.
   */
  std::int32_t xeci_lock_count()
  {
    std::int32_t removedLocks = 0;
    while (xeci_is_locked() == TRUE) {
      xeci_unlock();
      ++removedLocks;
      xeci_error(0, kXeciForceUnlockedMessage);
    }
    return removedLocks;
  }

  /**
   * Address: 0x00B1F2E0 (xeci_lock_n)
   *
   * What it does:
   * Re-applies XECI lock nesting depth removed by `xeci_lock_count`.
   */
  void __cdecl xeci_lock_n(std::int32_t lockCount)
  {
    while (lockCount > 0) {
      xeci_lock();
      --lockCount;
    }
  }

  /**
   * Address: 0x00B10910 (FUN_00B10910, _xeCiInit)
   *
   * What it does:
   * Resets XECI root-path/object pools and forces synchronous read mode.
   */
  void xeCiInit()
  {
    std::memset(gXeDirRootDirectory.data(), 0, gXeDirRootDirectory.size());
    std::memset(xedir_work, 0, sizeof(xedir_work));
    xeci_set_read_mode(0, 0, 0, 1);
  }

  /**
   * Address: 0x00B10940 (FUN_00B10940, _xeCiFinish)
   *
   * What it does:
   * Drains XECI server work until every transfer object is released or timeout
   * is reached.
   */
  char* xeCiFinish()
  {
    std::int32_t spinCount = 0;
    char* firstUsedObject = reinterpret_cast<char*>(crierr_err_msg);

    for (; spinCount < kXeciTimeoutPollLimit; ++spinCount) {
      xeCiExecServer();

      std::int32_t clearedObjectCount = 0;
      firstUsedObject = reinterpret_cast<char*>(crierr_err_msg);
      for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
        XeciObject* const object = &xedir_work[objectIndex];
        if (object->used != 0) {
          firstUsedObject = reinterpret_cast<char*>(object);
          break;
        }
        ++clearedObjectCount;
      }

      if (clearedObjectCount == kXeciObjectCount) {
        break;
      }
    }

    if (spinCount == kXeciTimeoutPollLimit) {
      xeci_assert(0, kXeciCloseWaitTimeoutMessage);
    }
    return firstUsedObject;
  }

  /**
   * Address: 0x00B10A40 (xeci_wait_one_milli)
   *
   * What it does:
   * Waits about one millisecond while preserving XECI lock nesting.
   */
  void xeci_wait_one_milli()
  {
    std::int32_t forcedLockCount = xeci_lock_count();
    LARGE_INTEGER startCounter{};
    LARGE_INTEGER currentCounter{};
    LARGE_INTEGER frequency{};

    QueryPerformanceCounter(&startCounter);
    forcedLockCount += xeci_lock_count();
    QueryPerformanceCounter(&currentCounter);
    QueryPerformanceFrequency(&frequency);
    frequency.QuadPart /= kXeciWaitOneMilliDivisor;

    while ((currentCounter.QuadPart - startCounter.QuadPart) <= frequency.QuadPart) {
      if (currentCounter.QuadPart <= startCounter.QuadPart) {
        break;
      }

      forcedLockCount += xeci_lock_count();
      QueryPerformanceCounter(&currentCounter);
      QueryPerformanceFrequency(&frequency);
      frequency.QuadPart /= kXeciWaitOneMilliDivisor;
    }

    xeci_lock_n(forcedLockCount);
  }

  /**
   * Address: 0x00B10B90 (xeci_obj_update_overlapped)
   *
   * What it does:
   * Polls one overlapped read lane, updates transfer/error state, and reports
   * read failures through XECI error callback.
   */
  std::int32_t __cdecl xeci_obj_update_overlapped(XeciObject* const object)
  {
    if (xeci_read_file_mode != 0) {
      object->wantsUpdate = xeci_obj_currently_reading;
      return xeci_read_file_mode;
    }

    DWORD transferredBytes = 0;
    if (GetOverlappedResult(object->fileHandle, &object->overlapped, &transferredBytes, FALSE) != FALSE) {
      if (xeci_async_abort_requested == 1) {
        xeci_async_abort_requested = 0;
        object->wantsUpdate = 0;
        object->state = kXeciStateError;
        return TRUE;
      }

      object->wantsUpdate = 0;
      object->transferSizeBytes = transferredBytes;
      return static_cast<std::int32_t>(transferredBytes);
    }

    const DWORD lastError = GetLastError();
    if (lastError == ERROR_OPERATION_ABORTED) {
      xeci_assert(0, kXeciReadAbortedMessage);
      object->state = kXeciStateError;
    } else if (lastError == ERROR_HANDLE_EOF) {
      xeci_assert(0, kXeciReadReachedEofMessage);
      object->state = kXeciStateError;
    } else if (lastError != ERROR_IO_PENDING && lastError != ERROR_IO_INCOMPLETE) {
      std::sprintf(wxfic_cache_file, kXeciReadErrorFormat, lastError);
      xeci_assert(0, wxfic_cache_file);
      object->state = kXeciStateError;
    }

    if (object->state == kXeciStateError) {
      object->wantsUpdate = 0;
    }

    return object->state;
  }

  /**
   * Address: 0x00B10C70 (FUN_00B10C70, xeci_obj_update)
   *
   * What it does:
   * Services one XECI object transfer lane, finalizing completed reads into the
   * buffered chunk state.
   */
  void __cdecl xeci_obj_update(XeciObject* const object)
  {
    std::int32_t* const updateLockFlag = &object->updateLockFlag;
    if (SofdecSetTrueThunk(updateLockFlag) == TRUE) {
      if (object->state == kXeciStateTransferring) {
        if (object->wantsRead == 1) {
          (void)xeci_obj_read_from_file(object);
        }

        if (object->wantsUpdate == 1) {
          (void)xeci_obj_update_overlapped(object);
          if (object->wantsUpdate == 0 && object->state != kXeciStateError) {
            xeci_lock();

            const std::uint32_t chunkSizeBytes = object->readChunkSizeBytes;
            const std::uint32_t transferredBytes = object->transferSizeBytes;
            const std::uint32_t remainderBytes = transferredBytes % chunkSizeBytes;
            if (remainderBytes != 0u) {
              auto* const readBufferBase = static_cast<std::uint8_t*>(object->readBufferPtr);
              std::memset(readBufferBase + transferredBytes, 0, chunkSizeBytes - remainderBytes);
            }

            const std::int32_t chunkAdvance = object->readChunkCount;
            const std::int64_t transferBytes
              = static_cast<std::int64_t>(chunkAdvance) * static_cast<std::int64_t>(object->readChunkSizeBytes);
            object->transferCountLow = static_cast<std::uint32_t>(transferBytes);
            object->transferCountHigh = static_cast<std::uint32_t>(static_cast<std::uint64_t>(transferBytes) >> 32);
            object->currentChunkIndex += chunkAdvance;
            object->state = 1;
            xeci_unlock();
          }
        }
      }
      *updateLockFlag = 0;
    }
  }

  /**
   * Address: 0x00B10D20 (FUN_00B10D20, xeci_obj_read_from_file)
   *
   * What it does:
   * Starts one synchronous/asynchronous file read for the current XECI object
   * lane and maps Win32 read failures to XECI error codes.
   */
  BOOL __cdecl xeci_obj_read_from_file(XeciObject* const object)
  {
    DWORD numberOfBytesRead = 0;
    BOOL readResult = FALSE;

    xeci_lock();
    object->wantsRead = 0;
    object->wantsUpdate = 1;
    xeci_obj_currently_reading = 1;
    xeci_unlock();

    if (xeci_read_file_mode != 0) {
      LONG distanceToMoveHigh = object->readOffsetHigh;
      const LONG distanceToMove = object->readOffsetLow;
      wxCiLock();
      SetFilePointer(object->fileHandle, distanceToMove, &distanceToMoveHigh, FILE_BEGIN);
      wxCiUnLock();

      readResult = xeci_read_file(object->fileHandle, object->readBufferPtr, object->transferSizeBytes, &numberOfBytesRead, nullptr);
      if (readResult != FALSE && numberOfBytesRead == 0u) {
        xeci_assert(0, kXeciReadZeroByteSyncMessage);
        object->state = kXeciStateError;
      }

      object->transferSizeBytes = numberOfBytesRead;
    } else {
      object->overlapped.Offset = static_cast<DWORD>(object->readOffsetLow);
      object->overlapped.OffsetHigh = static_cast<DWORD>(object->readOffsetHigh);
      readResult = ReadFile(
        object->fileHandle,
        object->readBufferPtr,
        object->transferSizeBytes,
        nullptr,
        &object->overlapped
      );
    }

    xeci_obj_currently_reading = 0;
    if (readResult == FALSE) {
      xeci_lock();
      const DWORD lastError = GetLastError();

      if (lastError > ERROR_HANDLE_EOF) {
        if (lastError != ERROR_IO_PENDING) {
          if (lastError == ERROR_INVALID_USER_BUFFER) {
            xeci_assert(0, kXeciReadQueueOverflowMessage);
            object->state = kXeciStateError;
          } else {
            std::sprintf(wxfic_cache_file, kXeciReadLastErrorFormat, lastError);
            xeci_assert(0, wxfic_cache_file);
            object->state = kXeciStateError;
          }
        }
      } else if (lastError == ERROR_HANDLE_EOF) {
        xeci_assert(0, kXeciReadInvalidStartMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_INVALID_HANDLE) {
        xeci_assert(0, kXeciReadInvalidHandleMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_NOT_ENOUGH_MEMORY) {
        xeci_assert(0, kXeciReadQueueOverflowMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_READ_FAULT) {
        xeci_assert(0, kXeciReadFaultMessage);
        object->state = kXeciStateError;
      } else {
        std::sprintf(wxfic_cache_file, kXeciReadLastErrorFormat, lastError);
        xeci_assert(0, wxfic_cache_file);
        object->state = kXeciStateError;
      }

      if (object->state == kXeciStateError) {
        object->wantsUpdate = 0;
      }
      xeci_unlock();
    }

    return readResult;
  }

  /**
   * Address: 0x00B10EA0 (FUN_00B10EA0, sub_B10EA0)
   *
   * What it does:
   * Returns whether any XECI object is still in active transfer state.
   */
  std::int32_t __cdecl xeci_has_active_transfer()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      const XeciObject& object = xedir_work[objectIndex];
      if (object.used != 0 && object.state == kXeciStateTransferring) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00B10ED0 (FUN_00B10ED0, _xeCiExecServer)
   *
   * What it does:
   * Updates every used XECI object, then fires idle callback when no active
   * transfer remains.
   */
  void __cdecl xeCiExecServer()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      XeciObject& object = xedir_work[objectIndex];
      if (object.used == 1) {
        xeci_obj_update(&object);
      }
    }

    if (xeci_has_active_transfer() != 1) {
      if (xeci_server_idle_callback != nullptr) {
        xeci_server_idle_callback(0);
      }
    }
  }

  /**
   * Address: 0x00B116D0 (xeci_obj_wait_until_done)
   *
   * What it does:
   * Waits until one XECI object completes pending transfer/update state.
   */
  void __cdecl xeci_obj_wait_until_done(XeciObject* const object)
  {
    std::int32_t pollCount = 0;
    while (object->wantsUpdate != 0) {
      xeci_obj_update_overlapped(object);
      xeci_wait_one_milli();

      ++pollCount;
      if (pollCount >= kXeciTimeoutPollLimit) {
        xeci_assert(0, kXeciWaitTimeoutMessage);
        xeci_lock();
        object->state = kXeciStateError;
        object->wantsUpdate = 0;
        xeci_unlock();
        return;
      }
    }
  }

  /**
   * Address: 0x00B11660 (_xeCiStopTr)
   *
   * What it does:
   * Stops one active transfer lane and clears pending read request state.
   */
  void __cdecl xeCiStopTr(XeciObject* const object)
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return;
    }

    if (object->state == 0) {
      return;
    }

    if (object->state == kXeciStateTransferring) {
      xeci_obj_wait_until_done(object);
      object->state = 0;
    }

    object->wantsRead = 0;
  }

  /**
   * Address: 0x00B116A0 (xeci_wait_until_all_done)
   *
   * What it does:
   * Waits for completion on every used XECI transfer object in the global pool.
   */
  void xeci_wait_until_all_done()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      XeciObject& object = xedir_work[objectIndex];
      if (object.used != 0) {
        xeci_obj_wait_until_done(&object);
      }
    }
  }

  /**
   * Address: 0x00B205C0 (xeci_create_thread)
   *
   * What it does:
   * Starts suspended XECI worker thread, applies priority settings, then
   * resumes it.
   */
  void xeci_create_thread()
  {
    xeci_thread = CreateThread(nullptr, 0x3000u, xeci_thread_server, nullptr, CREATE_SUSPENDED, nullptr);
    if (xeci_thread == nullptr) {
      xeci_error(0, kCreateThreadFailedMessage);
      return;
    }

    SetThreadPriority(xeci_thread, 1);
    SetThreadPriorityBoost(xeci_thread, TRUE);
    if (ResumeThread(xeci_thread) == 0xFFFFFFFFu) {
      xeci_error(0, kResumeThreadFailedMessage);
    }
  }

  /**
   * Address: 0x00B20630 (xeci_destroy_thread)
   *
   * What it does:
   * Signals worker shutdown, waits for thread exit, closes handle, and clears
   * global thread handle lane.
   */
  BOOL xeci_destroy_thread()
  {
    xeci_is_done = 1;
    WaitForSingleObject(xeci_thread, INFINITE);
    const BOOL closeResult = CloseHandle(xeci_thread);
    xeci_thread = nullptr;
    return closeResult;
  }

  /**
   * Address: 0x00B20660 (xeci_thread_server)
   *
   * What it does:
   * Polls active XEFIC objects for queued work, processes work items, runs
   * completion callback lane, and advances object state lanes.
   */
  DWORD __stdcall xeci_thread_server(LPVOID /*threadParameter*/)
  {
    while (xeci_is_done == 0) {
      for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
        if (object->used != 0 && object->hasWork == 1) {
          sub_B1F9D0(object);
          object->queueCursor = object->queueHead;

          if (xefic_work_complete_callback != nullptr) {
            xefic_work_complete_callback(object);
          }

          if (object->state != 6) {
            object->state = 2;
          }

          object->hasWork = 0;
          Sleep(kXeficWorkerSleepMilliseconds);
        }
      }
      Sleep(kXeficWorkerSleepMilliseconds);
    }

    return 0;
  }

  /**
   * Address: 0x00B206E0 (xeci_save_thread_prio)
   *
   * What it does:
   * Saves current thread priority and elevates current thread to priority `2`.
   */
  BOOL xeci_save_thread_prio()
  {
    HANDLE currentThread = GetCurrentThread();
    xeci_old_thread_prio = GetThreadPriority(currentThread);
    return SetThreadPriority(currentThread, 2);
  }

  /**
   * Address: 0x00B20700 (xeci_set_thread_prio)
   *
   * What it does:
   * Restores current thread priority from saved XECI priority lane.
   */
  BOOL xeci_set_thread_prio()
  {
    return SetThreadPriority(GetCurrentThread(), xeci_old_thread_prio);
  }

  /**
   * Address: 0x00B20720 (_CRIERR_SetCbErr)
   *
   * What it does:
   * Sets or clears CRIERR callback function/object lanes and clears last error
   * message buffer.
   */
  std::int32_t CRIERR_SetCbErr(moho::AdxmErrorCallback callbackFunction, const std::int32_t callbackObject)
  {
    if (callbackFunction != nullptr) {
      crierr_callback_func = callbackFunction;
      crierr_callback_obj = callbackObject;
    } else {
      crierr_callback_func = nullptr;
      crierr_callback_obj = 0;
    }

    std::memset(crierr_err_msg, 0, sizeof(crierr_err_msg));
    return 0;
  }

  /**
   * Address: 0x00B10790 (FUN_00B10790, _ADXERR_CallErrFunc1_)
   *
   * What it does:
   * Copies one ADX error message lane, dispatches registered callback, then
   * forwards the same text through `SVM_CallErr`.
   */
  int ADXERR_CallErrFunc1_(const char* const message)
  {
    std::strncpy(crierr_err_msg, message, kAdxerrCopyLimit);
    if (crierr_callback_func != nullptr) {
      crierr_callback_func(static_cast<std::uint32_t>(crierr_callback_obj), crierr_err_msg);
    }
    SVM_CallErr(crierr_err_msg);
    return 0;
  }

  /**
   * Address: 0x00B107D0 (FUN_00B107D0, _ADXERR_CallErrFunc2_)
   *
   * What it does:
   * Builds one combined ADX error string from prefix + detail text, dispatches
   * callback, and forwards through `SVM_CallErr`.
   */
  int ADXERR_CallErrFunc2_(const char* const prefix, const char* const message)
  {
    std::strncpy(crierr_err_msg, prefix, kAdxerrCopyLimit);
    std::strncat(crierr_err_msg, message, kAdxerrCopyLimit);
    if (crierr_callback_func != nullptr) {
      crierr_callback_func(static_cast<std::uint32_t>(crierr_callback_obj), crierr_err_msg);
    }
    SVM_CallErr(crierr_err_msg);
    return 0;
  }

  /**
   * Address: 0x00B10830 (FUN_00B10830, _ADXERR_ItoA)
   *
   * What it does:
   * Converts one integer lane to decimal text inside caller-provided buffer.
   */
  std::int32_t ADXERR_ItoA(const std::int32_t value, char* const outText, const std::int32_t outBytes)
  {
    if (outText == nullptr || outBytes <= 0) {
      return 0;
    }

    std::snprintf(outText, static_cast<std::size_t>(outBytes), "%d", value);
    return static_cast<std::int32_t>(std::strlen(outText));
  }

  /**
   * Address: 0x00B10890 (FUN_00B10890, _ADXERR_ItoA2)
   *
   * What it does:
   * Formats two integer lanes into one compact ADX error-text payload.
   */
  void ADXERR_ItoA2(
    const std::int32_t highWord,
    const std::int32_t lowWord,
    char* const outText,
    const std::int32_t outBytes
  )
  {
    (void)ADXERR_ItoA(highWord, outText, outBytes);
    std::strncat(outText, kAdxerrSeparator, outBytes - (static_cast<std::int32_t>(std::strlen(outText)) + 1));
    const std::int32_t usedBytes = static_cast<std::int32_t>(std::strlen(outText));
    const std::int32_t lowWordBytes = 4 - usedBytes;
    if (lowWordBytes > 0) {
      (void)ADXERR_ItoA(lowWord, outText + usedBytes, lowWordBytes);
    }
  }

  /**
   * Address: 0x00B207B0 (_crierr_default_callback)
   *
   * What it does:
   * Default CRIERR callback stub (no-op).
   */
  void crierr_default_callback()
  {
  }

  /**
   * Address: 0x00B207C0 (nullsub_41)
   *
   * What it does:
   * ADX RNA finalize hook stub (no-op).
   */
  void adxrna_NoOpFinalizeHook()
  {
  }

  /**
   * Address: 0x00B207D0 (_CRICRS_Enter)
   *
   * What it does:
   * Enters Sofdec RNA global critical section.
   */
  void CRICRS_Enter()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B207E0 (_CRICRS_Leave)
   *
   * What it does:
   * Leaves Sofdec RNA global critical section.
   */
  void CRICRS_Leave()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B15860 (FUN_00B15860, sub_B15860)
   *
   * What it does:
   * Returns ADXRNA play-flag bit (`stateFlags bit1`) for one RNA handle.
   */
  std::int32_t ADXRNA_IsPlaySwEnabled(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    const auto* const runtime = AsAdxrnaPlaySwitchRuntimeView(rnaHandle);
    return static_cast<std::int32_t>((runtime->stateFlags >> 1) & 1u);
  }

  /**
   * Address: 0x00B14E40 (FUN_00B14E40, _ADXRNA_SetPlaySw)
   *
   * What it does:
   * Updates ADXRNA play-switch lane and transition flags under RNA lock.
   */
  void ADXRNA_SetPlaySw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaPlaySwitchRuntimeView(rnaHandle);
    CRICRS_Enter();
    runtime->playSwitch = enabled;

    if (enabled != 0) {
      if (enabled == 1 && ADXRNA_IsPlaySwEnabled(rnaHandle) != 1) {
        runtime->stateFlags = static_cast<std::uint8_t>(runtime->stateFlags | 0x02u);
      }
    } else if (ADXRNA_IsPlaySwEnabled(rnaHandle) != 0) {
      runtime->stateFlags = static_cast<std::uint8_t>(runtime->stateFlags & 0x05u);
      runtime->stopTransitionPending = 1;
      CRICRS_Leave();
      return;
    }

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B17C60 (FUN_00B17C60, j__ADXRNA_SetPlaySw)
   *
   * What it does:
   * Thunk wrapper to `ADXRNA_SetPlaySw`.
   */
  void j__ADXRNA_SetPlaySw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    ADXRNA_SetPlaySw(rnaHandle, enabled);
  }

  /**
   * Address: 0x00B17B90 (FUN_00B17B90, _ADXCRS_Lock)
   */
  void ADXCRS_Lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B17BA0 (FUN_00B17BA0, _ADXCRS_Unlock)
   */
  void ADXCRS_Unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B17BB0 (FUN_00B17BB0, _ADXCRS_Enter)
   *
   * What it does:
   * No-op enter shim used by legacy ADX server wrappers.
   */
  void ADXCRS_Enter()
  {
  }

  /**
   * Address: 0x00B17BC0 (FUN_00B17BC0, _ADXCRS_Leave)
   *
   * What it does:
   * No-op leave shim used by legacy ADX server wrappers.
   */
  void ADXCRS_Leave()
  {
  }

  namespace
  {
    constexpr std::int32_t kSofdecSjRingBufferPoolSize = 0x300;
    constexpr std::int32_t kSofdecSjMemoryPoolSize = 0x60;
    constexpr std::int32_t kSofdecSjUnifyPoolSize = 0xC0;
    constexpr const char* kSofdecNullPointerSuffix = " : NULL pointer is specified.";
    constexpr const char* kSofdecInvalidHandleSuffix = " : Specified handle is invalid.";
    constexpr const char* kSjrBufferErrorTag = "SJRBF_Error";
    constexpr const char* kSjMemoryErrorTag = "SJMEM_Error";
    constexpr const char* kSjUnifyErrorTag = "SJUNI_Error";

    [[nodiscard]] std::int8_t* SjAddressToPointer(const std::int32_t addressWord)
    {
      return reinterpret_cast<std::int8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(addressWord)));
    }

    [[nodiscard]] std::int8_t* SjChunkBuffer(moho::SjChunkRange* const chunkRange)
    {
      return SjAddressToPointer(chunkRange->bufferAddress);
    }

    [[nodiscard]] std::int32_t SjPointerToAddress(const void* const pointer)
    {
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(pointer));
    }

    [[nodiscard]] std::int32_t SjFlowCounterOffset(const std::int32_t lane, const std::int32_t counterIndex)
    {
      return counterIndex + (lane * 2);
    }

    [[nodiscard]] std::int32_t SjRoundTowardZeroDivide16(const std::int32_t value)
    {
      const std::int32_t adjust = (value < 0) ? 0xF : 0;
      return (value + adjust) >> 4;
    }

    [[nodiscard]] std::int32_t AdxmComputeSpinThresholdMicroseconds(
      const std::uint32_t interval, const std::uint32_t screenHeight
    )
    {
      return static_cast<std::int32_t>((100000000u / (screenHeight + 50u)) / interval);
    }

    [[nodiscard]] std::int32_t AdxmComputeSleepMilliseconds(
      const std::uint32_t interval, const std::uint32_t screenHeight, const std::uint32_t scanline
    )
    {
      const std::uint32_t numerator = (100000u * screenHeight) - (100000u * scanline);
      return static_cast<std::int32_t>((numerator / (screenHeight + 50u)) / interval);
    }

    [[nodiscard]] std::int64_t AdxmElapsedMicroseconds(
      const LARGE_INTEGER& startCounter, const LARGE_INTEGER& endCounter, const std::int64_t frequency
    )
    {
      return (1000000LL * (endCounter.QuadPart - startCounter.QuadPart)) / frequency;
    }
  } // namespace

  /**
   * Address: 0x00B177F0 (FUN_00B177F0, _SJCRS_Lock)
   */
  void SJCRS_Lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B17800 (FUN_00B17800, _SJCRS_Unlock)
   */
  void SJCRS_Unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B07CA0 (FUN_00B07CA0, _SJRBF_Error)
   */
  void SJRBF_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjrBufferErrorTag);
  }

  /**
   * Address: 0x00B07CB0 (FUN_00B07CB0, _SJRBF_Init)
   */
  void SJRBF_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjrbf_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07CD0 (FUN_00B07CD0, _sjrbf_Init)
   */
  std::int32_t sjrbf_Init()
  {
    const std::int32_t previousCount = gSofdecSjRingBufferInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjRingBufferPool, 0, sizeof(gSofdecSjRingBufferPool));
    }

    ++gSofdecSjRingBufferInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B07CF0 (FUN_00B07CF0, _SJRBF_Finish)
   */
  std::int32_t SJRBF_Finish()
  {
    SJCRS_Lock();
    (void)sjrbf_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B07D10 (FUN_00B07D10, _sjrbf_Finish)
   */
  std::int32_t sjrbf_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjRingBufferInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjRingBufferPool, 0, sizeof(gSofdecSjRingBufferPool));
      return 0;
    }

    return nextCount;
  }

  /**
   * Address: 0x00B07D30 (FUN_00B07D30, _SJRBF_Create)
   */
  moho::SofdecSjRingBufferHandle* SJRBF_Create(
    const std::int32_t bufferAddress, const std::int32_t bufferSize, const std::int32_t extraSize
  )
  {
    SJCRS_Lock();
    moho::SofdecSjRingBufferHandle* const handle = sjrbf_Create(bufferAddress, bufferSize, extraSize);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B07D60 (FUN_00B07D60, _sjrbf_Create)
   */
  moho::SofdecSjRingBufferHandle* sjrbf_Create(
    const std::int32_t bufferAddress, const std::int32_t bufferSize, const std::int32_t extraSize
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjRingBufferPoolSize) {
      if (gSofdecSjRingBufferPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjRingBufferPoolSize) {
      return nullptr;
    }

    moho::SofdecSjRingBufferHandle* const handle = &gSofdecSjRingBufferPool[slotIndex];
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjRingBufferVtableTag);
    handle->bufferBase = SjAddressToPointer(bufferAddress);
    handle->bufferSize = bufferSize;
    handle->extraSize = extraSize;
    handle->uuid = SjPointerToAddress(&gSofdecSjRingBufferUuidTag);
    handle->errFunc = SJRBF_Error;
    handle->errObj = SjPointerToAddress(handle);
    (void)sjrbf_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B07DD0 (FUN_00B07DD0, _SJRBF_Destroy)
   */
  void SJRBF_Destroy(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    sjrbf_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07E40 (FUN_00B07E40, _SJRBF_CallErr_)
   */
  void SJRBF_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B07DF0 (FUN_00B07DF0, _sjrbf_Destroy)
   */
  void sjrbf_Destroy(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        std::memset(handle, 0, sizeof(*handle));
        handle->used = 0;
      } else {
        SJRBF_CallErr_("E2004090202", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090201", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B07EC0 (FUN_00B07EC0, _sjrbf_GetUuid)
   */
  std::int32_t sjrbf_GetUuid(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJRBF_CallErr_("E2004090204", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090203", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B07EA0 (FUN_00B07EA0, _SJRBF_GetUuid)
   */
  std::int32_t SJRBF_GetUuid(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjrbf_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B07F30 (FUN_00B07F30, _sjrbf_EntryErrFunc)
   */
  void sjrbf_EntryErrFunc(
    moho::SofdecSjRingBufferHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJRBF_CallErr_("E2004090206", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090205", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B07F00 (FUN_00B07F00, _SJRBF_EntryErrFunc)
   */
  void SJRBF_EntryErrFunc(
    moho::SofdecSjRingBufferHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjrbf_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07F80 (FUN_00B07F80, _SJRBF_Reset)
   */
  void SJRBF_Reset(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjrbf_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07FA0 (FUN_00B07FA0, _sjrbf_Reset)
   */
  moho::SofdecSjRingBufferHandle* sjrbf_Reset(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090207", kSofdecNullPointerSuffix);
      return nullptr;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090208", kSofdecInvalidHandleSuffix);
      return handle;
    }

    handle->pendingLane1Bytes = 0;
    handle->pendingLane0Bytes = handle->bufferSize;
    handle->lane0Cursor = 0;
    handle->lane1Cursor = 0;
    handle->flowCounters[0] = 0;
    handle->flowCounters[1] = 0;
    handle->flowCounters[2] = 0;
    handle->flowCounters[3] = 0;
    return handle;
  }

  /**
   * Address: 0x00B08000 (FUN_00B08000, _SJRBF_GetNumData)
   */
  std::int32_t SJRBF_GetNumData(moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t value = sjrbf_GetNumData(handle, lane);
    SJCRS_Unlock();
    return value;
  }

  /**
   * Address: 0x00B08030 (FUN_00B08030, _sjrbf_GetNumData)
   */
  std::int32_t sjrbf_GetNumData(moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (lane == 1) {
          return handle->pendingLane1Bytes;
        }
        if (lane == 0) {
          return handle->pendingLane0Bytes;
        }

        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        return 0;
      }

      SJRBF_CallErr_("E2004090210", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090209", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B080A0 (FUN_00B080A0, _SJRBF_GetChunk)
   */
  void SJRBF_GetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B080D0 (FUN_00B080D0, _sjrbf_GetChunk)
   */
  void sjrbf_GetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090211", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090212", kSofdecInvalidHandleSuffix);
      return;
    }
    if (handle->bufferSize == 0) {
      SJRBF_CallErr_("E2004090219", " : Illegal buffer size.");
      return;
    }

    if (lane == 0) {
      std::int32_t readableBytes = handle->bufferSize + handle->extraSize - handle->lane0Cursor;
      if (handle->pendingLane0Bytes < readableBytes) {
        readableBytes = handle->pendingLane0Bytes;
      }

      std::int32_t grantedBytes = requestedBytes;
      outChunkRange->byteCount = readableBytes;
      if (readableBytes < grantedBytes) {
        grantedBytes = readableBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = SjPointerToAddress(handle->bufferBase + handle->lane0Cursor);
      handle->lane0Cursor = (handle->lane0Cursor + grantedBytes) % handle->bufferSize;
      handle->pendingLane0Bytes -= outChunkRange->byteCount;
      handle->flowCounters[SjFlowCounterOffset(0, 0)] += outChunkRange->byteCount;
      return;
    }

    if (lane == 1) {
      std::int32_t readableBytes = handle->bufferSize + handle->extraSize - handle->lane1Cursor;
      if (handle->pendingLane1Bytes < readableBytes) {
        readableBytes = handle->pendingLane1Bytes;
      }

      std::int32_t grantedBytes = requestedBytes;
      outChunkRange->byteCount = readableBytes;
      if (readableBytes < grantedBytes) {
        grantedBytes = readableBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = SjPointerToAddress(handle->bufferBase + handle->lane1Cursor);
      handle->lane1Cursor = (handle->lane1Cursor + grantedBytes) % handle->bufferSize;
      handle->pendingLane1Bytes -= outChunkRange->byteCount;
      handle->flowCounters[SjFlowCounterOffset(1, 0)] += outChunkRange->byteCount;
      return;
    }

    outChunkRange->byteCount = 0;
    outChunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B08210 (FUN_00B08210, _SJRBF_PutChunk)
   */
  void SJRBF_PutChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08240 (FUN_00B08240, _sjrbf_PutChunk)
   */
  void sjrbf_PutChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        const std::int32_t chunkBytes = chunkRange->byteCount;
        if (chunkBytes > 0) {
          std::int8_t* const chunkBuffer = SjChunkBuffer(chunkRange);
          if (chunkBuffer != nullptr) {
            if (lane == 1) {
              const std::int32_t extraSize = handle->extraSize;
              const std::int32_t relativeStart =
                SjPointerToAddress(chunkBuffer) - SjPointerToAddress(handle->bufferBase);
              if (relativeStart < extraSize) {
                std::int32_t mirroredBytes = extraSize - relativeStart;
                if (chunkBytes < mirroredBytes) {
                  mirroredBytes = chunkBytes;
                }
                std::memcpy(
                  chunkBuffer + handle->bufferSize, chunkBuffer, static_cast<std::size_t>(mirroredBytes)
                );
              }

              std::int32_t spillCopyBytes = chunkBytes;
              const std::int32_t relativeEnd = relativeStart + spillCopyBytes;
              if (relativeEnd > handle->bufferSize) {
                const std::int32_t requiredBytes = relativeEnd - handle->bufferSize;
                if (spillCopyBytes >= requiredBytes) {
                  spillCopyBytes = requiredBytes;
                }
                std::memcpy(
                  handle->bufferBase,
                  chunkBuffer + (chunkBytes - spillCopyBytes),
                  static_cast<std::size_t>(spillCopyBytes)
                );
              }

              handle->pendingLane1Bytes += chunkBytes;
              handle->flowCounters[3] += chunkBytes;
              return;
            }

            if (lane != 0) {
              chunkRange->byteCount = 0;
              chunkRange->bufferAddress = 0;
              if (handle->errFunc != nullptr) {
                handle->errFunc(handle->errObj, -3);
              }
              return;
            }

            handle->pendingLane0Bytes += chunkBytes;
            handle->flowCounters[1] += chunkBytes;
          }
        }
      } else {
        SJRBF_CallErr_("E2004090214", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090213", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B08360 (FUN_00B08360, _SJRBF_UngetChunk)
   */
  void SJRBF_UngetChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08390 (FUN_00B08390, _sjrbf_UngetChunk)
   */
  void sjrbf_UngetChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090215", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090216", kSofdecInvalidHandleSuffix);
      return;
    }
    if (handle->bufferSize == 0) {
      SJRBF_CallErr_("E2004090220", " : Illegal buffer size.");
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    if (lane == 0) {
      const std::int32_t expectedCursor = (chunkAddress - SjPointerToAddress(handle->bufferBase)) % handle->bufferSize;
      const std::int32_t rewindCursor = (handle->bufferSize + handle->lane0Cursor - chunkBytes) % handle->bufferSize;
      if (rewindCursor == expectedCursor) {
        handle->lane0Cursor = rewindCursor;
        handle->pendingLane0Bytes += chunkBytes;
        handle->flowCounters[SjFlowCounterOffset(0, 0)] -= chunkBytes;
      } else {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        handle->flowCounters[SjFlowCounterOffset(0, 0)] -= chunkBytes;
      }
      return;
    }

    if (lane == 1) {
      const std::int32_t expectedCursor = (chunkAddress - SjPointerToAddress(handle->bufferBase)) % handle->bufferSize;
      const std::int32_t rewindCursor = (handle->bufferSize + handle->lane1Cursor - chunkBytes) % handle->bufferSize;
      if (rewindCursor == expectedCursor) {
        handle->lane1Cursor = rewindCursor;
        handle->pendingLane1Bytes += chunkBytes;
        handle->flowCounters[SjFlowCounterOffset(1, 0)] -= chunkBytes;
      } else {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        handle->flowCounters[SjFlowCounterOffset(1, 0)] -= chunkBytes;
      }
      return;
    }

    chunkRange->byteCount = 0;
    chunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B084F0 (FUN_00B084F0, _SJRBF_IsGetChunk)
   */
  std::int32_t SJRBF_IsGetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t canGet = sjrbf_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return canGet;
  }

  /**
   * Address: 0x00B08520 (FUN_00B08520, _sjrbf_IsGetChunk)
   */
  std::int32_t sjrbf_IsGetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090217", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090218", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::int32_t grantedBytes = 0;
    if (lane != 0) {
      if (lane == 1) {
        grantedBytes = handle->pendingLane1Bytes;
        const std::int32_t maxReadableBytes = handle->bufferSize + handle->extraSize - handle->lane1Cursor;
        if (grantedBytes >= maxReadableBytes) {
          grantedBytes = maxReadableBytes;
        }
        if (grantedBytes >= requestedBytes) {
          *outGrantedBytes = requestedBytes;
          return 1;
        }
      } else {
        grantedBytes = 0;
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
      }
    } else {
      grantedBytes = handle->pendingLane0Bytes;
      const std::int32_t maxReadableBytes = handle->bufferSize + handle->extraSize - handle->lane0Cursor;
      if (grantedBytes >= maxReadableBytes) {
        grantedBytes = maxReadableBytes;
      }
      if (grantedBytes >= requestedBytes) {
        *outGrantedBytes = requestedBytes;
        return 1;
      }
    }

    *outGrantedBytes = grantedBytes;
    return (grantedBytes == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B085F0 (FUN_00B085F0, _SJRBF_GetBufPtr)
   */
  std::int32_t SJRBF_GetBufPtr(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferAddress = sjrbf_GetBufPtr(handle);
    SJCRS_Unlock();
    return bufferAddress;
  }

  /**
   * Address: 0x00B08610 (FUN_00B08610, _sjrbf_GetBufPtr)
   */
  std::int32_t sjrbf_GetBufPtr(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return SjPointerToAddress(handle->bufferBase);
      }

      SJRBF_CallErr_("E2004090222", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090221", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B08650 (FUN_00B08650, _SJRBF_GetBufSize)
   */
  std::int32_t SJRBF_GetBufSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferSize = sjrbf_GetBufSize(handle);
    SJCRS_Unlock();
    return bufferSize;
  }

  /**
   * Address: 0x00B08670 (FUN_00B08670, _sjrbf_GetBufSize)
   */
  std::int32_t sjrbf_GetBufSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->bufferSize;
      }

      SJRBF_CallErr_("E2004090224", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090223", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B086B0 (FUN_00B086B0, _SJRBF_GetXtrSize)
   */
  std::int32_t SJRBF_GetXtrSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t extraSize = sjrbf_GetXtrSize(handle);
    SJCRS_Unlock();
    return extraSize;
  }

  /**
   * Address: 0x00B086D0 (FUN_00B086D0, _sjrbf_GetXtrSize)
   */
  std::int32_t sjrbf_GetXtrSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->extraSize;
      }

      SJRBF_CallErr_("E2004090226", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090225", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B08710 (FUN_00B08710, _SJRBF_SetFlowCnt)
   */
  void SJRBF_SetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t counterIndex,
    const std::int32_t value
  )
  {
    SJCRS_Lock();
    sjrbf_SetFlowCnt(handle, lane, counterIndex, value);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08740 (FUN_00B08740, _sjrbf_SetFlowCnt)
   */
  void sjrbf_SetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t counterIndex,
    const std::int32_t value
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->flowCounters[SjFlowCounterOffset(lane, counterIndex)] = value;
      } else {
        SJRBF_CallErr_("E2004090228", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090227", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B08790 (FUN_00B08790, _SJRBF_GetFlowCnt)
   */
  std::int32_t SJRBF_GetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, const std::int32_t counterIndex
  )
  {
    SJCRS_Lock();
    const std::int32_t value = sjrbf_GetFlowCnt(handle, lane, counterIndex);
    SJCRS_Unlock();
    return value;
  }

  /**
   * Address: 0x00B087C0 (FUN_00B087C0, _sjrbf_GetFlowCnt)
   */
  std::int32_t sjrbf_GetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, const std::int32_t counterIndex
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->flowCounters[SjFlowCounterOffset(lane, counterIndex)];
      }

      SJRBF_CallErr_("E2004090230", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090229", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09030 (FUN_00B09030, _SJMEM_Error)
   */
  void SJMEM_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjMemoryErrorTag);
  }

  /**
   * Address: 0x00B09040 (FUN_00B09040, _SJMEM_Init)
   */
  void SJMEM_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjmem_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09060 (FUN_00B09060, _sjmem_Init)
   */
  std::int32_t sjmem_Init()
  {
    const std::int32_t previousCount = gSofdecSjMemoryInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjMemoryPool, 0, sizeof(gSofdecSjMemoryPool));
    }

    ++gSofdecSjMemoryInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B09080 (FUN_00B09080, _SJMEM_Finish)
   */
  std::int32_t SJMEM_Finish()
  {
    SJCRS_Lock();
    (void)sjmem_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B090A0 (FUN_00B090A0, _sjmem_Finish)
   */
  std::int32_t sjmem_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjMemoryInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjMemoryPool, 0, sizeof(gSofdecSjMemoryPool));
      return 0;
    }

    return nextCount;
  }

  /**
   * Address: 0x00B090C0 (FUN_00B090C0, _SJMEM_Create)
   */
  moho::SofdecSjMemoryHandle* SJMEM_Create(const std::int32_t bufferAddress, const std::int32_t bufferSize)
  {
    SJCRS_Lock();
    moho::SofdecSjMemoryHandle* const handle = sjmem_Create(bufferAddress, bufferSize);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B090F0 (FUN_00B090F0, _sjmem_Create)
   */
  moho::SofdecSjMemoryHandle* sjmem_Create(const std::int32_t bufferAddress, const std::int32_t bufferSize)
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjMemoryPoolSize) {
      if (gSofdecSjMemoryPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjMemoryPoolSize) {
      return nullptr;
    }

    moho::SofdecSjMemoryHandle* const handle = &gSofdecSjMemoryPool[slotIndex];
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjMemoryVtableTag);
    handle->produceOffset = bufferAddress;
    handle->bufferSize = bufferSize;
    handle->uuid = SjPointerToAddress(&gSofdecSjMemoryUuidTag);
    handle->errFunc = SJMEM_Error;
    handle->errObj = SjPointerToAddress(handle);
    (void)sjmem_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B091D0 (FUN_00B091D0, _SJMEM_CallErr_)
   */
  void SJMEM_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B09180 (FUN_00B09180, _sjmem_Destroy)
   */
  std::int32_t sjmem_Destroy(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090231", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090232", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::memset(handle, 0, sizeof(*handle));
    handle->used = 0;
    return 0;
  }

  /**
   * Address: 0x00B09160 (FUN_00B09160, _SJMEM_Destroy)
   */
  void SJMEM_Destroy(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjmem_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09250 (FUN_00B09250, _sjmem_GetUuid)
   */
  std::int32_t sjmem_GetUuid(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJMEM_CallErr_("E2004090234", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090233", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09230 (FUN_00B09230, _SJMEM_GetUuid)
   */
  std::int32_t SJMEM_GetUuid(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjmem_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B092C0 (FUN_00B092C0, _sjmem_EntryErrFunc)
   */
  void sjmem_EntryErrFunc(
    moho::SofdecSjMemoryHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJMEM_CallErr_("E2004090236", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJMEM_CallErr_("E2004090235", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09290 (FUN_00B09290, _SJMEM_EntryErrFunc)
   */
  void SJMEM_EntryErrFunc(
    moho::SofdecSjMemoryHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjmem_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09310 (FUN_00B09310, _SJMEM_Reset)
   */
  void SJMEM_Reset(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjmem_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09330 (FUN_00B09330, _sjmem_Reset)
   */
  moho::SofdecSjMemoryHandle* sjmem_Reset(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090237", kSofdecNullPointerSuffix);
      return nullptr;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090238", kSofdecInvalidHandleSuffix);
      return handle;
    }

    handle->consumeOffset = 0;
    handle->pendingBytes = handle->bufferSize;
    return handle;
  }

  /**
   * Address: 0x00B09380 (FUN_00B09380, _SJMEM_GetNumData)
   *
   * What it does:
   * Lock-wrapper that queries one SJMEM lane readable-byte count.
   */
  std::int32_t SJMEM_GetNumData(moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t readableBytes = sjmem_GetNumData(handle, lane);
    SJCRS_Unlock();
    return readableBytes;
  }

  /**
   * Address: 0x00B093B0 (FUN_00B093B0, _sjmem_GetNumData)
   *
   * What it does:
   * Returns lane-1 readable bytes (`pendingBytes`); lane 0 reports empty.
   */
  std::int32_t sjmem_GetNumData(moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (lane == 1) {
          return handle->pendingBytes;
        }

        if (lane != 0) {
          if (handle->errFunc != nullptr) {
            handle->errFunc(handle->errObj, -3);
          }
        }
        return 0;
      }

      SJMEM_CallErr_("E2004090240", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090239", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09410 (FUN_00B09410, _SJMEM_GetChunk)
   *
   * What it does:
   * Lock-wrapper that fetches one SJMEM chunk descriptor.
   */
  void SJMEM_GetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjmem_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09440 (FUN_00B09440, _sjmem_GetChunk)
   *
   * What it does:
   * Emits chunk range for lane `1` and advances SJMEM read state.
   */
  void sjmem_GetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090241", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090242", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane == 0) {
      outChunkRange->byteCount = 0;
      outChunkRange->bufferAddress = 0;
      return;
    }

    if (lane == 1) {
      std::int32_t grantedBytes = handle->pendingBytes;
      if (grantedBytes >= requestedBytes) {
        grantedBytes = requestedBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = handle->consumeOffset + handle->produceOffset;
      handle->consumeOffset += grantedBytes;
      handle->pendingBytes -= outChunkRange->byteCount;
      return;
    }

    outChunkRange->byteCount = 0;
    outChunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B094E0 (FUN_00B094E0, _SJMEM_PutChunk)
   *
   * What it does:
   * Lock-wrapper for SJMEM put-chunk validation semantics.
   */
  void SJMEM_PutChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjmem_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09510 (FUN_00B09510, _sjmem_PutChunk)
   *
   * What it does:
   * Rejects non-supported SJMEM lanes when chunk data is non-empty.
   */
  void sjmem_PutChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (chunkRange->byteCount > 0 && chunkRange->bufferAddress != 0) {
          if (lane != 0 && lane != 1) {
            chunkRange->byteCount = 0;
            chunkRange->bufferAddress = 0;
            if (handle->errFunc != nullptr) {
              handle->errFunc(handle->errObj, -3);
            }
          }
        }
      } else {
        SJMEM_CallErr_("E2004090244", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJMEM_CallErr_("E2004090243", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09590 (FUN_00B09590, _SJMEM_UngetChunk)
   *
   * What it does:
   * Lock-wrapper that attempts to rewind one SJMEM chunk.
   */
  void SJMEM_UngetChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjmem_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B095C0 (FUN_00B095C0, _sjmem_UngetChunk)
   *
   * What it does:
   * Rewinds lane `1` if chunk origin matches expected read cursor.
   */
  void sjmem_UngetChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090245", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090246", kSofdecInvalidHandleSuffix);
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    if (chunkRange->bufferAddress == 0) {
      return;
    }

    if (lane == 1) {
      std::int32_t rewindOffset = handle->consumeOffset - chunkBytes;
      if (rewindOffset <= 0) {
        rewindOffset = 0;
      }
      handle->consumeOffset = rewindOffset;

      std::int32_t readableBytes = handle->pendingBytes + chunkBytes;
      if (handle->bufferSize < readableBytes) {
        readableBytes = handle->bufferSize;
      }
      handle->pendingBytes = readableBytes;

      const std::int32_t expectedOffset = chunkRange->bufferAddress - handle->produceOffset;
      if (rewindOffset != expectedOffset) {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
      }
      return;
    }

    if (lane != 0) {
      chunkRange->byteCount = 0;
      chunkRange->bufferAddress = 0;
    }

    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B09680 (FUN_00B09680, _SJMEM_IsGetChunk)
   *
   * What it does:
   * Lock-wrapper that checks SJMEM chunk availability.
   */
  std::int32_t SJMEM_IsGetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t available = sjmem_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return available;
  }

  /**
   * Address: 0x00B096B0 (FUN_00B096B0, _sjmem_IsGetChunk)
   *
   * What it does:
   * Writes granted-byte count and returns whether request can be satisfied.
   */
  std::int32_t sjmem_IsGetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090247", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090248", kSofdecInvalidHandleSuffix);
      return 0;
    }

    if (lane == 0) {
      *outGrantedBytes = 0;
      return (requestedBytes == 0) ? 1 : 0;
    }

    std::int32_t grantedBytes = 0;
    if (lane == 1) {
      grantedBytes = handle->pendingBytes;
      if (grantedBytes >= requestedBytes) {
        *outGrantedBytes = requestedBytes;
        return 1;
      }
    } else {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
    }

    *outGrantedBytes = grantedBytes;
    return (grantedBytes == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B09760 (FUN_00B09760, _SJMEM_GetBufPtr)
   *
   * What it does:
   * Lock-wrapper returning SJMEM base buffer address lane.
   */
  std::int32_t SJMEM_GetBufPtr(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferAddress = sjmem_GetBufPtr(handle);
    SJCRS_Unlock();
    return bufferAddress;
  }

  /**
   * Address: 0x00B09780 (FUN_00B09780, _sjmem_GetBufPtr)
   *
   * What it does:
   * Returns configured SJMEM base buffer address for one valid handle.
   */
  std::int32_t sjmem_GetBufPtr(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->produceOffset;
      }

      SJMEM_CallErr_("E2004090250", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090249", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B097C0 (FUN_00B097C0, _SJMEM_GetBufSize)
   *
   * What it does:
   * Lock-wrapper returning SJMEM buffer size lane.
   */
  std::int32_t SJMEM_GetBufSize(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferSize = sjmem_GetBufSize(handle);
    SJCRS_Unlock();
    return bufferSize;
  }

  /**
   * Address: 0x00B097E0 (FUN_00B097E0, _sjmem_GetBufSize)
   *
   * What it does:
   * Returns configured SJMEM buffer size for one valid handle.
   */
  std::int32_t sjmem_GetBufSize(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->bufferSize;
      }

      SJMEM_CallErr_("E2004090252", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090251", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09960 (FUN_00B09960, _SJUNI_Error)
   */
  void SJUNI_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjUnifyErrorTag);
  }

  /**
   * Address: 0x00B09970 (FUN_00B09970, _SJUNI_Init)
   */
  void SJUNI_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjuni_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09990 (FUN_00B09990, _sjuni_Init)
   */
  std::int32_t sjuni_Init()
  {
    const std::int32_t previousCount = gSofdecSjUnifyInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjUnifyPool, 0, sizeof(gSofdecSjUnifyPool));
    }
    ++gSofdecSjUnifyInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B099B0 (FUN_00B099B0, _SJUNI_Finish)
   */
  std::int32_t SJUNI_Finish()
  {
    SJCRS_Lock();
    (void)sjuni_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B099D0 (FUN_00B099D0, _sjuni_Finish)
   */
  std::int32_t sjuni_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjUnifyInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjUnifyPool, 0, sizeof(gSofdecSjUnifyPool));
      return 0;
    }
    return nextCount;
  }

  /**
   * Address: 0x00B099F0 (FUN_00B099F0, _SJUNI_Create)
   */
  moho::SofdecSjUnifyHandle* SJUNI_Create(
    const std::uint8_t mergeAdjacentChunks, const std::int32_t chainPoolAddress, const std::int32_t chainPoolBytes
  )
  {
    SJCRS_Lock();
    moho::SofdecSjUnifyHandle* const handle = sjuni_Create(mergeAdjacentChunks, chainPoolAddress, chainPoolBytes);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B09A20 (FUN_00B09A20, _sjuni_Create)
   */
  moho::SofdecSjUnifyHandle* sjuni_Create(
    const std::uint8_t mergeAdjacentChunks, const std::int32_t chainPoolAddress, const std::int32_t chainPoolBytes
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjUnifyPoolSize) {
      if (gSofdecSjUnifyPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjUnifyPoolSize) {
      return nullptr;
    }

    moho::SofdecSjUnifyHandle* const handle = &gSofdecSjUnifyPool[slotIndex];
    handle->mergeAdjacentChunks = mergeAdjacentChunks;
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjUnifyVtableTag);
    handle->uuid = SjPointerToAddress(&gSofdecSjUnifyUuidTag);
    handle->chainPoolBase = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(SjAddressToPointer(chainPoolAddress));
    handle->chainPoolCount = SjRoundTowardZeroDivide16(chainPoolBytes);
    handle->errFunc = SJUNI_Error;
    handle->errObj = SjPointerToAddress(handle);
    sjuni_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B09AA0 (FUN_00B09AA0, _SJUNI_Destroy)
   */
  void SJUNI_Destroy(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    sjuni_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09AC0 (FUN_00B09AC0, _sjuni_Destroy)
   */
  void sjuni_Destroy(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        std::memset(handle, 0, sizeof(*handle));
        handle->used = 0;
      } else {
        SJUNI_CallErr_("E2004090262", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJUNI_CallErr_("E2004090261", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09B10 (FUN_00B09B10, _SJUNI_CallErr_)
   */
  void SJUNI_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B09B70 (FUN_00B09B70, _SJUNI_GetUuid)
   */
  std::int32_t SJUNI_GetUuid(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjuni_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B09B90 (FUN_00B09B90, _sjuni_GetUuid)
   */
  std::int32_t sjuni_GetUuid(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJUNI_CallErr_("E2004090264", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJUNI_CallErr_("E2004090263", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09BD0 (FUN_00B09BD0, _SJUNI_EntryErrFunc)
   */
  void SJUNI_EntryErrFunc(
    moho::SofdecSjUnifyHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjuni_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09C00 (FUN_00B09C00, _sjuni_EntryErrFunc)
   */
  void sjuni_EntryErrFunc(
    moho::SofdecSjUnifyHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJUNI_CallErr_("E2004090266", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJUNI_CallErr_("E2004090265", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09C50 (FUN_00B09C50, _SJUNI_Reset)
   */
  void SJUNI_Reset(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    sjuni_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09C70 (FUN_00B09C70, _sjuni_Reset)
   */
  void sjuni_Reset(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090267", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090268", kSofdecInvalidHandleSuffix);
      return;
    }

    std::int32_t nodeIndex = 0;
    moho::SofdecSjUnifyChunkNode* const chainPoolBase = handle->chainPoolBase;
    const std::int32_t nodeCountMinusOne = handle->chainPoolCount - 1;
    handle->chainPoolFreeList = chainPoolBase;

    const std::uintptr_t chainPoolBaseAddress = reinterpret_cast<std::uintptr_t>(chainPoolBase);
    if (nodeCountMinusOne > 0) {
      do {
        auto* const currentNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
          chainPoolBaseAddress
          + (static_cast<std::uintptr_t>(nodeIndex) * sizeof(moho::SofdecSjUnifyChunkNode))
        );
        auto* const nextNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
          chainPoolBaseAddress
          + (static_cast<std::uintptr_t>(nodeIndex + 1) * sizeof(moho::SofdecSjUnifyChunkNode))
        );
        currentNode->bufferAddress = 0;
        currentNode->next = nextNode;
        currentNode->byteCount = 0;
        ++nodeIndex;
      } while (nodeIndex < (handle->chainPoolCount - 1));
    }

    auto* const lastNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
      chainPoolBaseAddress + (static_cast<std::uintptr_t>(nodeIndex) * sizeof(moho::SofdecSjUnifyChunkNode))
    );
    lastNode->next = nullptr;
    lastNode->bufferAddress = 0;
    lastNode->byteCount = 0;

    handle->laneHeads[0] = nullptr;
    handle->laneHeads[1] = nullptr;
    handle->laneHeads[2] = nullptr;
    handle->laneHeads[3] = nullptr;
  }

  /**
   * Address: 0x00B09D00 (FUN_00B09D00, _SJUNI_GetNumData)
   */
  std::int32_t SJUNI_GetNumData(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t readableBytes = sjuni_GetNumData(handle, lane);
    SJCRS_Unlock();
    return readableBytes;
  }

  /**
   * Address: 0x00B09D30 (FUN_00B09D30, _sjuni_GetNumData)
   */
  std::int32_t sjuni_GetNumData(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090269", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090270", kSofdecInvalidHandleSuffix);
      return 0;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return 0;
    }

    std::int32_t totalBytes = 0;
    moho::SofdecSjUnifyChunkNode* chunkNode = handle->laneHeads[lane];
    while (chunkNode != nullptr) {
      totalBytes += chunkNode->byteCount;
      chunkNode = chunkNode->next;
    }
    return totalBytes;
  }

  /**
   * Address: 0x00B09DB0 (FUN_00B09DB0, _SJUNI_GetChunk)
   */
  void SJUNI_GetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjuni_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09DE0 (FUN_00B09DE0, _sjuni_GetChunk)
   */
  void sjuni_GetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090271", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090272", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane >= 0 && lane < 4) {
      moho::SofdecSjUnifyChunkNode* const headNode = handle->laneHeads[lane];
      if (headNode != nullptr) {
        moho::SjChunkRange headChunk{};
        headChunk.bufferAddress = headNode->bufferAddress;
        headChunk.byteCount = headNode->byteCount;

        if (headChunk.byteCount <= requestedBytes) {
          outChunkRange->bufferAddress = headChunk.bufferAddress;
          outChunkRange->byteCount = headChunk.byteCount;
          handle->laneHeads[lane] = headNode->next;
          headNode->next = handle->chainPoolFreeList;
          handle->chainPoolFreeList = headNode;
          return;
        }

        if (handle->mergeAdjacentChunks == 1) {
          moho::SjChunkRange tailChunk{};
          SJ_SplitChunk(&headChunk, requestedBytes, &headChunk, &tailChunk);
          outChunkRange->bufferAddress = headChunk.bufferAddress;
          outChunkRange->byteCount = headChunk.byteCount;
          headNode->bufferAddress = tailChunk.bufferAddress;
          headNode->byteCount = tailChunk.byteCount;
          return;
        }
      }
    } else {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
    }

    outChunkRange->bufferAddress = 0;
    outChunkRange->byteCount = 0;
  }

  /**
   * Address: 0x00B09EF0 (FUN_00B09EF0, _SJUNI_PutChunk)
   */
  void SJUNI_PutChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjuni_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09F20 (FUN_00B09F20, _sjuni_PutChunk)
   */
  void sjuni_PutChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090273", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090274", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    moho::SofdecSjUnifyChunkNode** tailLink = &handle->laneHeads[lane];
    moho::SofdecSjUnifyChunkNode* tailNode = nullptr;
    for (moho::SofdecSjUnifyChunkNode* node = *tailLink; node != nullptr; node = node->next) {
      tailLink = &node->next;
      tailNode = node;
    }

    if (handle->mergeAdjacentChunks == 1 && tailNode != nullptr) {
      const std::int32_t tailEndAddress = tailNode->bufferAddress + tailNode->byteCount;
      if (tailEndAddress == chunkAddress) {
        tailNode->byteCount += chunkBytes;
        return;
      }
    }

    moho::SofdecSjUnifyChunkNode* const freeNode = handle->chainPoolFreeList;
    if (freeNode == nullptr) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    handle->chainPoolFreeList = freeNode->next;
    freeNode->next = nullptr;
    freeNode->bufferAddress = chunkAddress;
    freeNode->byteCount = chunkBytes;
    *tailLink = freeNode;
  }

  /**
   * Address: 0x00B0A020 (FUN_00B0A020, _SJUNI_UngetChunk)
   */
  void SJUNI_UngetChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjuni_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B0A050 (FUN_00B0A050, _sjuni_UngetChunk)
   */
  void sjuni_UngetChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090275", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090276", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    moho::SofdecSjUnifyChunkNode* const laneHead = handle->laneHeads[lane];
    if (handle->mergeAdjacentChunks == 1 && laneHead != nullptr) {
      if ((chunkAddress + chunkBytes) == laneHead->bufferAddress) {
        laneHead->bufferAddress = chunkAddress;
        laneHead->byteCount += chunkBytes;
        return;
      }
    }

    moho::SofdecSjUnifyChunkNode* const freeNode = handle->chainPoolFreeList;
    if (freeNode == nullptr) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    handle->chainPoolFreeList = freeNode->next;
    freeNode->next = handle->laneHeads[lane];
    freeNode->bufferAddress = chunkAddress;
    freeNode->byteCount = chunkBytes;
    handle->laneHeads[lane] = freeNode;
  }

  /**
   * Address: 0x00B0A140 (FUN_00B0A140, _SJUNI_IsGetChunk)
   */
  std::int32_t SJUNI_IsGetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t available = sjuni_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return available;
  }

  /**
   * Address: 0x00B0A170 (FUN_00B0A170, _sjuni_IsGetChunk)
   */
  std::int32_t sjuni_IsGetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090277", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090278", kSofdecInvalidHandleSuffix);
      return 0;
    }

    *outGrantedBytes = 0;
    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return 0;
    }

    moho::SofdecSjUnifyChunkNode* const headNode = handle->laneHeads[lane];
    if (headNode == nullptr) {
      return 0;
    }

    *outGrantedBytes = headNode->byteCount;
    if (handle->mergeAdjacentChunks == 1) {
      return (headNode->byteCount >= requestedBytes) ? 1 : 0;
    }
    return (headNode->byteCount == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B0A230 (FUN_00B0A230, _SJUNI_GetNumChunk)
   */
  std::int32_t SJUNI_GetNumChunk(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t chunkCount = sjuni_GetNumChunk(handle, lane);
    SJCRS_Unlock();
    return chunkCount;
  }

  /**
   * Address: 0x00B0A260 (FUN_00B0A260, _sjuni_GetNumChunk)
   */
  std::int32_t sjuni_GetNumChunk(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090279", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090280", kSofdecInvalidHandleSuffix);
      return 0;
    }

    const std::intptr_t laneSlotAddress = reinterpret_cast<std::intptr_t>(&handle->laneHeads[0])
      + (static_cast<std::intptr_t>(lane) * static_cast<std::intptr_t>(sizeof(handle->laneHeads[0])));
    auto* const laneHeadSlot = reinterpret_cast<moho::SofdecSjUnifyChunkNode* const*>(laneSlotAddress);

    std::int32_t chunkCount = 0;
    for (moho::SofdecSjUnifyChunkNode* chunkNode = *laneHeadSlot; chunkNode != nullptr; chunkNode = chunkNode->next) {
      ++chunkCount;
    }
    return chunkCount;
  }

  /**
   * Address: 0x00B0A2B0 (FUN_00B0A2B0, _SJUNI_GetNumChainPool)
   */
  std::int32_t SJUNI_GetNumChainPool(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t chainNodeCount = sjuni_GetNumChainPool(handle);
    SJCRS_Unlock();
    return chainNodeCount;
  }

  /**
   * Address: 0x00B0A2D0 (FUN_00B0A2D0, _sjuni_GetNumChainPool)
   */
  std::int32_t sjuni_GetNumChainPool(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090281", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090282", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::int32_t chainNodeCount = 0;
    for (
      moho::SofdecSjUnifyChunkNode* chainNode = handle->chainPoolFreeList;
      chainNode != nullptr;
      chainNode = chainNode->next
    ) {
      ++chainNodeCount;
    }
    return chainNodeCount;
  }

  /**
   * Address: 0x00B07B80 (FUN_00B07B80, _adxpc_err_dvd)
   *
   * What it does:
   * Forwards one DVD/file-system error-text lane to ADX error reporter.
   */
  std::int32_t ADXPC_ReportDvdError(const std::int32_t errorCode, char* const errorText)
  {
    (void)errorCode;
    return ADXERR_CallErrFunc1_(errorText);
  }

  constexpr std::size_t kCvFsDeviceSlotCount = 32;
  constexpr std::size_t kCvFsHandlePoolCount = 80;
  constexpr std::size_t kCvFsDeviceNameBytes = 12;
  constexpr std::size_t kCvFsPathScratchBytes = 300;
  std::array<CvFsDeviceSlot, kCvFsDeviceSlotCount> gCvFsDeviceSlots{};
  std::array<CvFsHandleView, kCvFsHandlePoolCount> gCvFsHandlePool{};
  std::array<char, kCvFsDeviceNameBytes> gCvFsDefaultDeviceName{};
  std::array<char, kCvFsPathScratchBytes> gCvFsAddDevicePathScratch{};
  std::int32_t gCvFsErrorObject = 0;
  std::array<char, MAX_PATH> gXeDirRootDirectory{};

  /**
   * Address: 0x00B12000 (FUN_00B12000, _toUpperStr)
   *
   * What it does:
   * Uppercases one zero-terminated CVFS lane in place.
   */
  std::int32_t toUpperStr(char* const text)
  {
    if (text == nullptr) {
      return 0;
    }

    std::int32_t lastSymbol = 0;
    const std::size_t symbolCount = std::strlen(text) + 1u;
    for (std::size_t index = 0; index < symbolCount; ++index) {
      lastSymbol = static_cast<unsigned char>(text[index]);
      if (lastSymbol >= 'a' && lastSymbol <= 'z') {
        lastSymbol -= ('a' - 'A');
        text[index] = static_cast<char>(lastSymbol);
      }
    }
    return lastSymbol;
  }

  /**
   * Address: 0x00B12110 (FUN_00B12110, _isExistDev)
   *
   * What it does:
   * Returns whether one CVFS device-name prefix is registered.
   */
  std::int32_t isExistDev(const char* const deviceName, const std::size_t compareLength)
  {
    if (deviceName == nullptr) {
      return 0;
    }

    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength) == 0) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00B10990 (FUN_00B10990, _xeDirAppendRootDir)
   *
   * What it does:
   * Appends one relative/absolute path onto the configured CVFS root lane.
   */
  char* __cdecl xeDirAppendRootDir(char* const outputPath, const char* const relativeOrAbsolutePath)
  {
    if (relativeOrAbsolutePath != nullptr) {
      if (relativeOrAbsolutePath[0] != '\0') {
        if (relativeOrAbsolutePath[0] == '\\') {
          outputPath[0] = gXeDirRootDirectory[0];
          outputPath[1] = gXeDirRootDirectory[1];
          outputPath[2] = '\0';
        } else if (relativeOrAbsolutePath[1] == ':') {
          outputPath[0] = '\0';
        } else {
          std::strcpy(outputPath, gXeDirRootDirectory.data());
        }
      } else {
        std::strcpy(outputPath, gXeDirRootDirectory.data());
      }

      std::strcat(outputPath, relativeOrAbsolutePath);
      return nullptr;
    }

    const char* readCursor = gXeDirRootDirectory.data();
    char copiedLane = '\0';
    do {
      copiedLane = *readCursor;
      outputPath[readCursor - gXeDirRootDirectory.data()] = copiedLane;
      ++readCursor;
    } while (copiedLane != '\0');
    return const_cast<char*>(readCursor);
  }

  /**
   * Address: 0x00B11A90 (FUN_00B11A90, _xeDirSetRootDir)
   *
   * What it does:
   * Stores one full CVFS root-directory path and guarantees a trailing
   * backslash separator.
   */
  std::int32_t xeDirSetRootDir(const char* const rootDirectory)
  {
    char fileName[MAX_PATH]{};
    if (rootDirectory != nullptr) {
      std::snprintf(fileName, sizeof(fileName), "%s", rootDirectory);
    }

    if (std::strlen(fileName) == 0u) {
      std::strcpy(fileName, ".");
    }

    std::memset(gXeDirRootDirectory.data(), 0, gXeDirRootDirectory.size());
    ::GetFullPathNameA(
      fileName,
      static_cast<DWORD>(gXeDirRootDirectory.size()),
      gXeDirRootDirectory.data(),
      nullptr
    );

    const std::size_t rootLength = std::strlen(gXeDirRootDirectory.data());
    if (rootLength == 0u || gXeDirRootDirectory[rootLength - 1u] != '\\') {
      if (rootLength + 1u < gXeDirRootDirectory.size()) {
        gXeDirRootDirectory[rootLength] = '\\';
        gXeDirRootDirectory[rootLength + 1u] = '\0';
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B11DE0 (FUN_00B11DE0, _cvFsError_)
   *
   * What it does:
   * Bridges one CVFS error text to the registered user error callback lane.
   */
  extern "C" std::int32_t cvFsError_(const char* const message)
  {
    cvFsCallUsrErrFn(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&gCvFsErrorObject)), message);
    return 0;
  }

  /**
   * Address: 0x00B12330 (FUN_00B12330, _releaseCvFsHn)
   *
   * What it does:
   * Clears one CVFS handle lane (`interface`, `handleAddress`) and returns the
   * original handle pointer.
   */
  extern "C" CvFsHandleView* releaseCvFsHn(CvFsHandleView* const handle)
  {
    handle->handleAddress = 0;
    handle->interfaceView = nullptr;
    return handle;
  }

  /**
   * Address: 0x00B12440 (FUN_00B12440, _cvFsClose)
   *
   * What it does:
   * Validates one CVFS handle lane, invokes vtable close callback when
   * available, and releases the handle bookkeeping.
   */
  extern "C" std::int32_t cvFsClose(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      return cvFsError_(kCvFsErrCloseHandle);
    }

    if (handle->interfaceView == nullptr) {
      return cvFsError_(kCvFsErrCloseVtable);
    }

    CvFsCloseBridgeFn const closeBridge = handle->interfaceView->closeFile;
    if (closeBridge == nullptr) {
      return cvFsError_(kCvFsErrCloseVtable);
    }

    closeBridge(handle->handleAddress);
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(releaseCvFsHn(handle)));
  }

  /**
   * Address: 0x00B120A0 (FUN_00B120A0, _cvFsSetDefDev)
   *
   * What it does:
   * Validates one default CVFS device lane, uppercases it, and stores it as
   * active default when registered.
   */
  extern "C" std::int32_t cvFsSetDefDev(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return cvFsError_(kCvFsErrSetDefDevInvalidDeviceName);
    }

    const std::size_t nameLength = std::strlen(deviceName);
    if (nameLength == 0u) {
      gCvFsDefaultDeviceName[0] = '\0';
      return 0;
    }

    std::array<char, kCvFsPathScratchBytes> upperName{};
    std::strncpy(upperName.data(), deviceName, upperName.size() - 1u);
    (void)toUpperStr(upperName.data());

    if (isExistDev(upperName.data(), nameLength) != 1) {
      return cvFsError_(kCvFsErrSetDefDevUnknownDeviceName);
    }

    std::memset(gCvFsDefaultDeviceName.data(), 0, gCvFsDefaultDeviceName.size());
    const std::size_t bytesToCopy = (nameLength + 1u < gCvFsDefaultDeviceName.size())
      ? (nameLength + 1u)
      : gCvFsDefaultDeviceName.size();
    std::memcpy(gCvFsDefaultDeviceName.data(), upperName.data(), bytesToCopy);
    return static_cast<std::int32_t>(nameLength + 1u);
  }

  /**
   * Address: 0x00B11FB0 (FUN_00B11FB0, _getDevice)
   *
   * What it does:
   * Returns the CVFS interface lane for one device-name prefix match.
   */
  CvFsDeviceInterfaceView* getDevice(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return nullptr;
    }

    const std::size_t compareLength = std::strlen(deviceName);
    for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength) == 0) {
        return deviceSlot.interfaceView;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B11F40 (FUN_00B11F40, _addDevice)
   *
   * What it does:
   * Adds one device-interface lane to the fixed CVFS device table when absent.
   */
  CvFsDeviceInterfaceView* addDevice(const char* const deviceName, void* (__cdecl* const deviceFactory)())
  {
    std::array<char, kCvFsDeviceNameBytes> upperDeviceName{};
    if (deviceName != nullptr) {
      std::strncpy(upperDeviceName.data(), deviceName, upperDeviceName.size() - 1u);
    }
    (void)toUpperStr(upperDeviceName.data());

    auto* const deviceInterface = reinterpret_cast<CvFsDeviceInterfaceView*>(deviceFactory());
    if (getDevice(upperDeviceName.data()) != nullptr) {
      return deviceInterface;
    }

    std::size_t freeSlotIndex = 0;
    for (; freeSlotIndex < gCvFsDeviceSlots.size(); ++freeSlotIndex) {
      if (gCvFsDeviceSlots[freeSlotIndex].deviceName[0] == '\0') {
        break;
      }
    }

    if (freeSlotIndex == gCvFsDeviceSlots.size()) {
      return nullptr;
    }

    gCvFsDeviceSlots[freeSlotIndex].interfaceView = deviceInterface;
    std::strcpy(gCvFsDeviceSlots[freeSlotIndex].deviceName.data(), upperDeviceName.data());
    return deviceInterface;
  }

  /**
   * Address: 0x00B12040 (FUN_00B12040, _cvFsDelDev)
   *
   * What it does:
   * Clears one device slot by matching the requested CVFS device prefix.
   */
  std::int32_t cvFsDelDev(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return cvFsError_(kCvFsErrDelDevInvalidDeviceName);
    }

    const std::size_t compareLength = std::strlen(deviceName);
    std::int32_t compareResult = 1;
    for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      compareResult = std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength);
      if (compareResult == 0) {
        deviceSlot.deviceName[0] = '\0';
        return compareResult;
      }
    }
    return compareResult;
  }

  /**
   * Address: 0x00B12300 (FUN_00B12300, _allocCvFsHn)
   *
   * What it does:
   * Returns one free CVFS handle from the fixed handle pool.
   */
  CvFsHandleView* allocCvFsHn()
  {
    for (CvFsHandleView& handle : gCvFsHandlePool) {
      if (handle.handleAddress == 0) {
        return &handle;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B12350 (FUN_00B12350, _getDevName)
   *
   * What it does:
   * Splits `DEV:path` into uppercase device prefix + path buffer.
   */
  void getDevName(char* const outDeviceName, char* const outFilePath, const char* const fileName)
  {
    if (fileName == nullptr) {
      return;
    }

    std::int32_t splitIndex = 0;
    while (splitIndex < 297) {
      const char symbol = fileName[splitIndex];
      if (symbol == ':' || symbol == '\0') {
        break;
      }
      outDeviceName[splitIndex] = symbol;
      ++splitIndex;
    }

    const char delimiter = fileName[splitIndex];
    outDeviceName[splitIndex] = '\0';
    if (delimiter == '\0') {
      std::strcpy(outFilePath, outDeviceName);
      outDeviceName[0] = '\0';
      return;
    }

    std::int32_t pathSourceIndex = splitIndex + 1;
    if (pathSourceIndex == 2) {
      pathSourceIndex = 0;
      outDeviceName[0] = '\0';
    }

    std::int32_t pathWriteIndex = 0;
    while (pathSourceIndex < 297) {
      const char symbol = fileName[pathSourceIndex];
      if (symbol == '\0') {
        break;
      }
      outFilePath[pathWriteIndex] = symbol;
      ++pathWriteIndex;
      ++pathSourceIndex;
    }
    outFilePath[pathWriteIndex] = '\0';
    (void)toUpperStr(outDeviceName);
  }

  /**
   * Address: 0x00B12400 (FUN_00B12400, _getDefDev)
   *
   * What it does:
   * Copies the current default CVFS device name into caller storage.
   */
  char getDefDev(char* const outDeviceName)
  {
    const char firstChar = gCvFsDefaultDeviceName[0];
    if (firstChar != '\0') {
      const std::size_t byteCount = std::strlen(gCvFsDefaultDeviceName.data()) + 1u;
      std::memcpy(outDeviceName, gCvFsDefaultDeviceName.data(), byteCount);
      return firstChar;
    }

    outDeviceName[0] = '\0';
    return firstChar;
  }

  /**
   * Address: 0x00B133B0 (FUN_00B133B0, _isNeedDevName)
   *
   * What it does:
   * Returns whether a CVFS device requires `DEV:` name prefixes.
   */
  std::int32_t isNeedDevName(char* const deviceName)
  {
    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface != nullptr && deviceInterface->option != nullptr) {
      return deviceInterface->option(nullptr, 100, 0, 0);
    }
    return 0;
  }

  /**
   * Address: 0x00B133E0 (FUN_00B133E0, _addDevName)
   *
   * What it does:
   * Prefixes one file path with `DEV:` when the resolved device requires it.
   */
  std::int32_t addDevName(char* const deviceName, char* const filePath)
  {
    char* resolvedDeviceName = deviceName;
    if (resolvedDeviceName == nullptr) {
      resolvedDeviceName = gCvFsDefaultDeviceName.data();
    }

    const std::int32_t needsPrefix = isNeedDevName(resolvedDeviceName);
    if (needsPrefix == 1) {
      std::strcpy(gCvFsAddDevicePathScratch.data(), filePath);
      return std::sprintf(filePath, "%s:%s", resolvedDeviceName, gCvFsAddDevicePathScratch.data());
    }
    return needsPrefix;
  }

  /**
   * Address: 0x00B12290 (FUN_00B12290, _variousProc)
   *
   * What it does:
   * Resolves effective open-device and rewritten file path for CVFS operations.
   */
  CvFsDeviceInterfaceView* variousProc(char* const deviceName, char* const filePath, const char* const originalPath)
  {
    if (deviceName[0] == '\0') {
      (void)getDefDev(deviceName);
      if (deviceName[0] == '\0') {
        return nullptr;
      }
    }

    (void)addDevName(deviceName, filePath);
    CvFsDeviceInterfaceView* deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)getDefDev(deviceName);
      deviceInterface = getDevice(deviceName);
      if (deviceInterface != nullptr) {
        std::strcpy(filePath, originalPath);
      }
    }
    return deviceInterface;
  }

  /**
   * Address: 0x00B12160 (FUN_00B12160, _cvFsOpen)
   *
   * What it does:
   * Opens one CVFS handle through the resolved device interface.
   */
  extern "C" CvFsHandleView* cvFsOpen(char* const fileName, const std::int32_t openMode, const std::int32_t openFlags)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrOpenIllegalFileName);
      return nullptr;
    }

    char pathBuffer[kCvFsPathScratchBytes]{};
    char deviceBuffer[kCvFsPathScratchBytes]{};
    getDevName(deviceBuffer, pathBuffer, fileName);
    if (pathBuffer[0] == '\0') {
      (void)cvFsError_(kCvFsErrOpenIllegalFileName);
      return nullptr;
    }

    CvFsHandleView* const handle = allocCvFsHn();
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrOpenHandleAllocFailed);
      return nullptr;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceBuffer, pathBuffer, fileName);
    handle->interfaceView = deviceInterface;
    if (deviceInterface == nullptr) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenDeviceNotFound);
      return nullptr;
    }

    if (deviceInterface->openFile == nullptr) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenVtableError);
      return nullptr;
    }

    const std::int32_t openedHandle = deviceInterface->openFile(pathBuffer, openMode, openFlags);
    handle->handleAddress = openedHandle;
    if (openedHandle == 0) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenFailed);
      return nullptr;
    }

    return handle;
  }

  /**
   * Address: 0x00B13320 (FUN_00B13320, _cvFsSetDefVol)
   *
   * What it does:
   * Pushes one default-volume option packet to the selected CVFS device.
   */
  void cvFsSetDefVol(char* const deviceName, const std::int32_t volumeName)
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrSetDefVolInvalidDeviceName);
      return;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrSetDefVolInvalidVolumeName);
      return;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrSetDefVolDeviceNotFound);
      return;
    }

    std::int32_t optionValues[5]{};
    optionValues[1] = volumeName;
    if (deviceInterface->option != nullptr) {
      (void)deviceInterface->option(optionValues, 6, 0, 0);
    }
  }

  /**
   * Address: 0x00B11ED0 (FUN_00B11ED0, _cvFsAddDev)
   *
   * What it does:
   * Validates and registers one CVFS device interface, then installs the
   * shared user-error bridge callback when the device supports it.
   */
  void cvFsAddDev(const char* const deviceName, void* (__cdecl* const deviceFactory)())
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevInvalidDeviceName);
      return;
    }
    if (deviceFactory == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevInvalidInterfaceFn);
      return;
    }

    auto* const deviceInterface = addDevice(deviceName, deviceFactory);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevFailed);
      return;
    }

    if (deviceInterface->registerUserErrorBridge != nullptr) {
      deviceInterface->registerUserErrorBridge(&cvFsCallUsrErrFn, 0);
    }
  }

  /**
   * Address: 0x00B07B90 (FUN_00B07B90, _ADXPC_SetupFileSystem)
   *
   * What it does:
   * Initializes ADXPC file-device lanes and applies optional root-directory
   * override from `rootDirArgv[0]`.
   */
  int ADXPC_SetupFileSystem(const char** const rootDirArgv)
  {
    (void)ADXPC_GetVersion();
    (void)cvFsEntryErrFunc(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&ADXPC_ReportDvdError)), 0);

    cvFsAddDev(kCvFsDeviceMf, &mfCiGetInterface);
    xeCiInit();
    cvFsAddDev(kCvFsDeviceWx, &xeCiGetInterface);
    (void)cvFsSetDefDev(kCvFsDeviceWx);

    const char* const rootDir = (rootDirArgv != nullptr) ? *rootDirArgv : nullptr;
    return xeDirSetRootDir(rootDir);
  }

  /**
   * Address: 0x00B07C10 (FUN_00B07C10, _ADXPC_ShutdownFileSystem)
   *
   * What it does:
   * Shuts down ADXPC file-system lanes, finalizing ADXFIC first when ADXT is initialized.
   */
  char* ADXPC_ShutdownFileSystem()
  {
    if (ADXT_IsInitialized() > 0) {
      ADXFIC_Finish();
    }
    cvFsFinish();
    return xeCiFinish();
  }

  /**
   * Address: 0x00B07C30 (FUN_00B07C30, j__ADXPC_ShutdownFileSystem)
   *
   * What it does:
   * Thunk alias that jumps to `ADXPC_ShutdownFileSystem`.
   */
  char* ADXPC_ShutdownFileSystemThunk()
  {
    return ADXPC_ShutdownFileSystem();
  }

  /**
   * Address: 0x00B07C50 (FUN_00B07C50, nullsub_31)
   *
   * What it does:
   * No-op ADXPC callback lane.
   */
  void ADXPC_NoOpShutdownCallback()
  {
  }

  /**
   * Address: 0x00B07C60 (FUN_00B07C60, sub_B07C60)
   *
   * What it does:
   * Enables ADXPC DVD-error reporting mode lane.
   */
  std::int32_t ADXPC_EnableDvdErrorReporting()
  {
    return ADXPC_SetDvdErrorReportingEnabled(1);
  }

  /**
   * Address: 0x00B07C70 (FUN_00B07C70, sub_B07C70)
   *
   * What it does:
   * Disables ADXPC DVD-error reporting mode lane.
   */
  std::int32_t ADXPC_DisableDvdErrorReporting()
  {
    return ADXPC_SetDvdErrorReportingEnabled(0);
  }

  /**
   * Address: 0x00B15FB0 (FUN_00B15FB0, func_SofDec_DefaultWaveFormat)
   *
   * What it does:
   * Writes one default 44.1kHz/16-bit PCM wave-format block.
   */
  moho::SofdecPcmWaveFormat* SofdecBuildDefaultPcmWaveFormat(
    const std::uint16_t channels,
    moho::SofdecPcmWaveFormat* const outWaveFormat
  )
  {
    std::memset(outWaveFormat, 0, sizeof(*outWaveFormat));
    outWaveFormat->channelCount = channels;
    outWaveFormat->blockAlignBytes = static_cast<std::uint16_t>(2u * channels);
    outWaveFormat->formatTag = 1;
    outWaveFormat->samplesPerSecond = 44100;
    outWaveFormat->bitsPerSample = 16;
    outWaveFormat->extraBytes = 0;
    outWaveFormat->averageBytesPerSecond =
      outWaveFormat->samplesPerSecond * static_cast<std::uint32_t>(outWaveFormat->blockAlignBytes);
    return outWaveFormat;
  }

  /**
   * Address: 0x00B164E0 (FUN_00B164E0, func_DirectSoundBuffer_Restore)
   *
   * What it does:
   * Returns success for no-error or `DSERR_BUFFERLOST` after calling `Restore`.
   */
  std::int32_t SofdecRestoreBufferIfLost(IDirectSoundBuffer* const soundBuffer, const std::int32_t operationResult)
  {
    if (operationResult == 0) {
      return 1;
    }
    if (operationResult != static_cast<std::int32_t>(DSERR_BUFFERLOST)) {
      return 0;
    }
    soundBuffer->lpVtbl->Restore(soundBuffer);
    return 1;
  }

  /**
   * Address: 0x00B16010 (FUN_00B16010, sub_B16010)
   *
   * What it does:
   * Starts one DirectSound buffer and polls status until playback bit sets
   * or timeout/error path triggers.
   */
  std::int32_t SofdecStartBufferAndWaitForPlaying(IDirectSoundBuffer* const soundBuffer)
  {
    const std::int32_t playResult = soundBuffer->lpVtbl->Play(soundBuffer, 0, 0, DSBPLAY_LOOPING);
    if (playResult != 0 && SofdecRestoreBufferIfLost(soundBuffer, playResult) == 0) {
      return ADXERR_CallErrFunc1_(kSofdecErrPlayFailed);
    }

    SofdecPollBufferPlaybackState(soundBuffer, true);

    DWORD status = 0;
    return static_cast<std::int32_t>(soundBuffer->lpVtbl->GetStatus(soundBuffer, &status));
  }

  /**
   * Address: 0x00B160F0 (FUN_00B160F0, _mwSndStop)
   *
   * What it does:
   * Stops one DirectSound buffer and polls until playback bit clears.
   */
  void SofdecStopBufferAndWaitForIdle(IDirectSoundBuffer* const soundBuffer)
  {
    if (soundBuffer->lpVtbl->Stop(soundBuffer) != DS_OK) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrStopFailed);
      return;
    }

    SofdecPollBufferPlaybackState(soundBuffer, false);
  }

  /**
   * Address: 0x00B161C0 (FUN_00B161C0, func_SofDec_RestoreSoundBuffer)
   *
   * What it does:
   * Creates and zero-fills the global restore-probe DirectSound buffer.
   */
  std::int32_t SofdecCreateRestoreProbeBuffer()
  {
    moho::SofdecPcmWaveFormat waveFormat{};
    SofdecBuildDefaultPcmWaveFormat(1u, &waveFormat);

    DSBUFFERDESC bufferDesc{};
    bufferDesc.dwSize = sizeof(bufferDesc);
    bufferDesc.dwFlags = 0x8u;
    bufferDesc.dwBufferBytes = waveFormat.averageBytesPerSecond / 10u;
    bufferDesc.lpwfxFormat = reinterpret_cast<WAVEFORMATEX*>(&waveFormat);

    if (gSofdecDirectSound->lpVtbl->CreateSoundBuffer(gSofdecDirectSound, &bufferDesc, &gSofdecRestoreProbeBuffer, nullptr)
        < 0) {
      return 0;
    }

    void* lockBase = nullptr;
    DWORD lockBytes = 0;
    const std::int32_t lockResult = gSofdecRestoreProbeBuffer->lpVtbl->Lock(
      gSofdecRestoreProbeBuffer, 0, 0, &lockBase, &lockBytes, nullptr, nullptr, DSBLOCK_ENTIREBUFFER
    );

    if (lockResult < 0 && SofdecRestoreBufferIfLost(gSofdecRestoreProbeBuffer, lockResult) == 0) {
      return 0;
    }

    if (lockBase != nullptr && lockBytes != 0) {
      std::memset(lockBase, 0, lockBytes);
    }

    gSofdecRestoreProbeBuffer->lpVtbl->Unlock(gSofdecRestoreProbeBuffer, lockBase, lockBytes, nullptr, 0);
    return 1;
  }

  /**
   * Address: 0x00B162B0 (FUN_00B162B0, func_SofDec_Stop)
   *
   * What it does:
   * Stops/releases the global restore-probe DirectSound buffer.
   */
  void SofdecShutdownRestoreProbeBuffer()
  {
    if (gSofdecRestoreProbeBuffer == nullptr) {
      return;
    }

    SofdecStopBufferAndWaitForIdle(gSofdecRestoreProbeBuffer);
    gSofdecRestoreProbeBuffer->lpVtbl->Release(gSofdecRestoreProbeBuffer);
    gSofdecRestoreProbeBuffer = nullptr;
  }

  /**
   * Address: 0x00B164A0 (FUN_00B164A0, sub_B164A0)
   *
   * What it does:
   * Mirrors current play cursor from primary to secondary port buffer.
   */
  std::int32_t SofdecMirrorPrimaryCursorToSecondaryBuffer(moho::SofdecSoundPort* const soundPort)
  {
    const std::int32_t defaultResult = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort->primaryBuffer));
    if (soundPort->primaryBuffer == nullptr || soundPort->secondaryBuffer == nullptr) {
      return defaultResult;
    }

    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    soundPort->primaryBuffer->lpVtbl->GetCurrentPosition(soundPort->primaryBuffer, &playCursor, &writeCursor);
    return static_cast<std::int32_t>(soundPort->secondaryBuffer->lpVtbl->SetCurrentPosition(soundPort->secondaryBuffer, playCursor));
  }

  /**
   * Address: 0x00B16510 (FUN_00B16510, SofDecVirt::Init)
   *
   * What it does:
   * Captures DirectSound runtime lane and clears sound-port slot activity.
   */
  IDirectSoundBuffer** SofdecInitSoundPortRuntime(IDirectSound* const directSound)
  {
    IDirectSound8* directSound8 = nullptr;
    if (directSound->lpVtbl->QueryInterface(directSound, IID_IDirectSound8, reinterpret_cast<void**>(&directSound8)) >= 0
        && directSound8 != nullptr) {
      gSofdecDirectSoundVersionTag = kSofdecLegacyDx8CapabilityTag;
      directSound8->lpVtbl->Release(directSound8);
    } else {
      gSofdecDirectSoundVersionTag = kSofdecLegacyDx7CapabilityTag;
    }

    gSofdecDirectSound = directSound;
    for (auto& soundPort : gSofdecSoundPortPool) {
      soundPort.used = 0;
      soundPort.primaryBuffer = nullptr;
    }
    gSofdecOpenPortCount = 0;

    return reinterpret_cast<IDirectSoundBuffer**>(
      reinterpret_cast<std::uint8_t*>(gSofdecSoundPortPool) + sizeof(gSofdecSoundPortPool) + offsetof(moho::SofdecSoundPort, primaryBuffer)
    );
  }

  /**
   * Address: 0x00B16580 (FUN_00B16580, SofDecVirt::Func2)
   *
   * What it does:
   * Stops sound-port runtime and clears global mode/slot lanes.
   */
  std::uint32_t* SofdecShutdownSoundPortRuntime()
  {
    SofdecShutdownRestoreProbeBuffer();
    gSofdecOpenPortCount = 0;
    gSofdecFrequencyMode = 0;
    gSofdecGlobalFocusMode = 0;
    gSofdecBufferPlacementMode = 0;
    gSofdecDirectSound = nullptr;

    for (auto& soundPort : gSofdecSoundPortPool) {
      soundPort.used = 0;
      soundPort.primaryBuffer = nullptr;
    }

    gSofdecMonoRoutingMode = 0;
    gSofdecPortBufferBytesPerChannel = 0x10000u;

    return reinterpret_cast<std::uint32_t*>(
      reinterpret_cast<std::uint8_t*>(gSofdecSoundPortPool) + sizeof(gSofdecSoundPortPool) + offsetof(moho::SofdecSoundPort, primaryBuffer)
    );
  }

  /**
   * Address: 0x00B165E0 (FUN_00B165E0, func_SofDec_NextUnk3)
   *
   * What it does:
   * Finds first free sound-port slot in the fixed 32-entry pool.
   */
  moho::SofdecSoundPort* SofdecAcquireFreeSoundPort()
  {
    for (auto& soundPort : gSofdecSoundPortPool) {
      if (soundPort.used == 0) {
        return &soundPort;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B16610 (FUN_00B16610, sub_B16610)
   *
   * What it does:
   * Resets one sound-port slot to zeroed state.
   */
  std::int32_t SofdecResetSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    std::memset(soundPort, 0, sizeof(*soundPort));
    soundPort->used = 0;
    return 0;
  }

  /**
   * Address: 0x00B16630 (FUN_00B16630, func_SofDec_CreateSoundBuffer)
   *
   * What it does:
   * Creates one DirectSound playback buffer using current Sofdec mode flags.
   */
  IDirectSoundBuffer* SofdecCreatePlaybackBuffer(const std::int32_t channels, const std::uint32_t bufferBytes)
  {
    if (gSofdecDirectSound == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrDirectSoundMissing);
      return nullptr;
    }

    DSBUFFERDESC bufferDesc{};
    moho::SofdecPcmWaveFormat waveFormat{};
    SofdecBuildDefaultPcmWaveFormat(static_cast<std::uint16_t>(channels), &waveFormat);
    bufferDesc.lpwfxFormat = reinterpret_cast<WAVEFORMATEX*>(&waveFormat);
    bufferDesc.dwBufferBytes = bufferBytes;
    bufferDesc.dwSize = sizeof(bufferDesc);

    DWORD flags = kSofdecPrimaryBufferFlagsLegacy;
    if (gSofdecBufferPlacementMode == 1) {
      if (gSofdecDirectSoundVersionTag >= kSofdecLegacyDx8CapabilityTag) {
        flags = kSofdecPrimaryBufferFlagsDx8;
      }
    } else {
      flags = kSofdecPrimaryBufferFlagsAlt;
    }

    if (gSofdecGlobalFocusMode == 1) {
      flags |= 0x8000u;
    }

    if (gSofdecMonoRoutingMode == 1 && channels == 1) {
      flags |= 0x10u;
    } else {
      flags |= 0x40u;
    }

    switch (gSofdecFrequencyMode) {
    case 1:
      flags |= 0x4u;
      break;
    case 2:
      break;
    case 3:
      flags |= 0x40000u;
      break;
    default:
      flags |= 0x8u;
      break;
    }

    bufferDesc.dwFlags = flags;

    IDirectSoundBuffer* soundBuffer = nullptr;
    const std::int32_t createResult =
      gSofdecDirectSound->lpVtbl->CreateSoundBuffer(gSofdecDirectSound, &bufferDesc, &soundBuffer, nullptr);
    if (createResult < 0 || soundBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreateBuffer);
      return nullptr;
    }

    return soundBuffer;
  }

  /**
   * Address: 0x00B16750 (FUN_00B16750, mwSndOpenPort)
   *
   * What it does:
   * Opens/configures one Sofdec sound-port handle from the slot pool.
   */
  moho::SofdecSoundPort* SofdecOpenSoundPort(const std::int32_t channels)
  {
    if (channels < 1 || channels > 2) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrChannelCountRange);
      return nullptr;
    }

    moho::SofdecSoundPort* const soundPort = SofdecAcquireFreeSoundPort();
    if (soundPort == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNoFreeSoundPort);
      return nullptr;
    }

    std::memset(soundPort, 0, sizeof(*soundPort));
    soundPort->dispatchTable = &gSofdecSoundPortVtable2Tag;
    soundPort->primaryBuffer = SofdecCreatePlaybackBuffer(
      channels, static_cast<std::uint32_t>(channels) * gSofdecPortBufferBytesPerChannel
    );

    if (soundPort->primaryBuffer == nullptr) {
      (void)SofdecResetSoundPort(soundPort);
      return nullptr;
    }

    soundPort->monoRoutingMode = gSofdecMonoRoutingMode;
    soundPort->bufferPlacementMode = gSofdecBufferPlacementMode;

    if (gSofdecOpenPortCount == 0 && SofdecCreateRestoreProbeBuffer() != 1) {
      SofdecShutdownRestoreProbeBuffer();
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreatePlaybackFailed);
    }

    ++gSofdecOpenPortCount;

    moho::SofdecPcmWaveFormat defaultWaveFormat{};
    SofdecBuildDefaultPcmWaveFormat(static_cast<std::uint16_t>(channels), &defaultWaveFormat);
    soundPort->channelCountPrimary = channels;
    soundPort->channelModeFlag = channels;
    soundPort->format = defaultWaveFormat;
    soundPort->used = 1;
    return soundPort;
  }

  /**
   * Address: 0x00B16870 (FUN_00B16870, SofDecVirt2_Func1)
   *
   * What it does:
   * Closes one sound-port handle, releasing buffers and pool slot state.
   */
  std::int32_t SofdecCloseSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    const std::int32_t inUseState = soundPort->used;
    if (inUseState == 0) {
      return inUseState;
    }

    SofdecStopSoundPortBuffers(soundPort);

    if (soundPort->primaryBuffer != nullptr) {
      soundPort->primaryBuffer->lpVtbl->Release(soundPort->primaryBuffer);
      soundPort->primaryBuffer = nullptr;
    }

    if (soundPort->secondaryBuffer != nullptr) {
      soundPort->secondaryBuffer->lpVtbl->Release(soundPort->secondaryBuffer);
      soundPort->secondaryBuffer = nullptr;
    }

    if (--gSofdecOpenPortCount == 0) {
      SofdecShutdownRestoreProbeBuffer();
    }

    return SofdecResetSoundPort(soundPort);
  }

  /**
   * Address: 0x00B168D0 (FUN_00B168D0, SofDecVirt2_Func2)
   *
   * What it does:
   * Stops/drains active sound-port buffers and re-synchronizes dual-buffer
   * cursor state when secondary buffer exists.
   */
  std::int32_t SofdecDrainAndSyncSoundPort(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return soundPort->used;
    }

    IDirectSoundBuffer* const primaryBuffer = soundPort->primaryBuffer;
    if (primaryBuffer == nullptr) {
      return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }

    if (soundPort->bufferPlacementMode == 0
        && primaryBuffer->lpVtbl->SetFrequency(primaryBuffer, soundPort->format.samplesPerSecond) != DS_OK) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetFrequencyFailed);
    }

    if (soundPort->playbackCursorResetPending == 1) {
      if (primaryBuffer->lpVtbl->SetCurrentPosition(primaryBuffer, 0) != DS_OK) {
        (void)ADXERR_CallErrFunc1_(kSofdecErrSetCurrentPositionFailed);
      }
      soundPort->playbackCursorResetPending = 0;
    }

    (void)SofdecStartBufferAndWaitForPlaying(primaryBuffer);
    if (soundPort->secondaryBuffer == nullptr) {
      return soundPort->used;
    }

    SofdecStopBufferAndWaitForIdle(primaryBuffer);
    SofdecStopBufferAndWaitForIdle(soundPort->secondaryBuffer);
    (void)SofdecStartBufferAndWaitForPlaying(primaryBuffer);
    (void)SofdecStartBufferAndWaitForPlaying(soundPort->secondaryBuffer);
    return SofdecMirrorPrimaryCursorToSecondaryBuffer(soundPort);
  }

  /**
   * Address: 0x00B16990 (FUN_00B16990, SofDecVirt2_Func3)
   *
   * What it does:
   * Stops one sound-port's primary/secondary buffers and validates the global
   * restore-probe lane when present.
   */
  void SofdecStopSoundPortBuffers(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return;
    }

    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return;
    }

    if (gSofdecRestoreProbeBuffer != nullptr) {
      gSofdecRestoreProbeBuffer->lpVtbl->SetCurrentPosition(gSofdecRestoreProbeBuffer, 0);
      const std::int32_t playResult = gSofdecRestoreProbeBuffer->lpVtbl->Play(gSofdecRestoreProbeBuffer, 0, 0, 0);
      if (playResult != 0 && SofdecRestoreBufferIfLost(gSofdecRestoreProbeBuffer, playResult) == 0) {
        (void)ADXERR_CallErrFunc1_(kSofdecErrPlayFailed);
        return;
      }
    }

    SofdecStopBufferAndWaitForIdle(soundPort->primaryBuffer);
    if (soundPort->secondaryBuffer != nullptr) {
      SofdecStopBufferAndWaitForIdle(soundPort->secondaryBuffer);
    }
  }

  namespace
  {
    constexpr std::int32_t kSofdecTagNameBytes = 7;
    constexpr std::int32_t kSofdecTagHeaderBytes = 16;
    constexpr std::int32_t kSofdecFileTypeVideoElementary = 2;
    constexpr char kSofdecTagCritags[] = "CRITAGS";
    constexpr char kSofdecTagCritage[] = "CRITAGE";
    constexpr char kSofdecTagSfxz[] = "SFXZ";
    constexpr char kSofdecTagSfxinfs[] = "SFXINFS";
    constexpr char kSofdecTagSfxinfe[] = "SFXINFE";
    constexpr char kSofdecTagZmhdr[] = "ZMHDR";
    constexpr char kSofdecTagZmvfrm[] = "ZMVFRM";
    constexpr char kSofdecTagUsrinfe[] = "USRINFE";
    constexpr char kSofdecTagTunit[] = "TUNIT";
    constexpr char kSofdecTagTimedat[] = "TIMEDAT";
    constexpr char kSofdecTagIntime[] = "INTIME";
    constexpr char kSofdecTagDurtime[] = "DURTIME";

    struct MwsfdTagInfoRuntimeView
    {
      std::uint8_t mUnknown00_A7[0xA8]{};
      void* sfxHandle = nullptr; // +0xA8
      std::uint8_t mUnknownAC_17B[0xD0]{};
      moho::SofdecSjRingBufferHandle* sjTagRingHandle = nullptr; // +0x17C
      std::int8_t* ainfSearchBuffer = nullptr; // +0x180
      std::uint8_t mUnknown184_187[0x04]{};
      std::int8_t* ainfUserBuffer = nullptr; // +0x188
      std::uint8_t mUnknown18C_18F[0x04]{};
      std::int32_t ainfTagInfoSlot0 = 0; // +0x190
      std::int32_t ainfTagInfoReady = 0; // +0x194
      std::int32_t ainfTagInfoDataAddress = 0; // +0x198
      std::int32_t ainfTagInfoLength = 0; // +0x19C
    };

    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, sfxHandle) == 0xA8, "MwsfdTagInfoRuntimeView::sfxHandle offset must be 0xA8"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, sjTagRingHandle) == 0x17C,
      "MwsfdTagInfoRuntimeView::sjTagRingHandle offset must be 0x17C"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfSearchBuffer) == 0x180,
      "MwsfdTagInfoRuntimeView::ainfSearchBuffer offset must be 0x180"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfUserBuffer) == 0x188,
      "MwsfdTagInfoRuntimeView::ainfUserBuffer offset must be 0x188"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoReady) == 0x194,
      "MwsfdTagInfoRuntimeView::ainfTagInfoReady offset must be 0x194"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoDataAddress) == 0x198,
      "MwsfdTagInfoRuntimeView::ainfTagInfoDataAddress offset must be 0x198"
    );
    static_assert(
      offsetof(MwsfdTagInfoRuntimeView, ainfTagInfoLength) == 0x19C,
      "MwsfdTagInfoRuntimeView::ainfTagInfoLength offset must be 0x19C"
    );

    struct SfxzTagGroupRuntimeView
    {
      std::uint8_t mUnknown00_07[0x8]{};
      std::int32_t hasTagPayload = 0; // +0x08
      std::int32_t tagPayloadAddress = 0; // +0x0C
      std::int32_t tagPayloadLength = 0; // +0x10
      std::uint8_t mUnknown14_17[0x4]{};
      std::int32_t zmhdrReady = 0; // +0x18
      std::int32_t zmhdrPayloadAddress = 0; // +0x1C
      std::int32_t zmhdrPayloadLength = 0; // +0x20
      std::uint8_t mUnknown24_27[0x4]{};
      std::int32_t zmvfrmReady = 0; // +0x28
      std::int32_t zmvfrmPayloadAddress = 0; // +0x2C
      std::int32_t zmvfrmPayloadLength = 0; // +0x30
    };

    static_assert(
      offsetof(SfxzTagGroupRuntimeView, hasTagPayload) == 0x08,
      "SfxzTagGroupRuntimeView::hasTagPayload offset must be 0x08"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, tagPayloadAddress) == 0x0C,
      "SfxzTagGroupRuntimeView::tagPayloadAddress offset must be 0x0C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, tagPayloadLength) == 0x10,
      "SfxzTagGroupRuntimeView::tagPayloadLength offset must be 0x10"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrReady) == 0x18,
      "SfxzTagGroupRuntimeView::zmhdrReady offset must be 0x18"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrPayloadAddress) == 0x1C,
      "SfxzTagGroupRuntimeView::zmhdrPayloadAddress offset must be 0x1C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmhdrPayloadLength) == 0x20,
      "SfxzTagGroupRuntimeView::zmhdrPayloadLength offset must be 0x20"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmReady) == 0x28,
      "SfxzTagGroupRuntimeView::zmvfrmReady offset must be 0x28"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmPayloadAddress) == 0x2C,
      "SfxzTagGroupRuntimeView::zmvfrmPayloadAddress offset must be 0x2C"
    );
    static_assert(
      offsetof(SfxzTagGroupRuntimeView, zmvfrmPayloadLength) == 0x30,
      "SfxzTagGroupRuntimeView::zmvfrmPayloadLength offset must be 0x30"
    );

    struct SfxTagInfoRuntimeView
    {
      std::uint8_t mUnknown00_13[0x14]{};
      std::int32_t tagInfoReady = 0; // +0x14
      std::int32_t tagDataAddress = 0; // +0x18
      std::int32_t tagDataLength = 0; // +0x1C
      std::uint8_t mUnknown20_23[0x4]{};
      SfxzTagGroupRuntimeView* sfxzTagGroup = nullptr; // +0x24
    };

    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagInfoReady) == 0x14,
      "SfxTagInfoRuntimeView::tagInfoReady offset must be 0x14"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagDataAddress) == 0x18,
      "SfxTagInfoRuntimeView::tagDataAddress offset must be 0x18"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, tagDataLength) == 0x1C,
      "SfxTagInfoRuntimeView::tagDataLength offset must be 0x1C"
    );
    static_assert(
      offsetof(SfxTagInfoRuntimeView, sfxzTagGroup) == 0x24,
      "SfxTagInfoRuntimeView::sfxzTagGroup offset must be 0x24"
    );

    [[nodiscard]] constexpr std::int32_t SofdecDecodeHexNibble(const char digit) noexcept
    {
      if (digit >= '0' && digit <= '9') {
        return digit - '0';
      }
      if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
      }
      if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
      }
      return 0;
    }
  } // namespace

  /**
   * Address: 0x00B088E0 (FUN_00B088E0, _sj_hexstr_to_val)
   *
   * What it does:
   * Decodes one 7-digit hex-length lane used by Sofdec tag headers.
   */
  std::int32_t sj_hexstr_to_val(const char* const hexString)
  {
    if (hexString == nullptr) {
      return 0;
    }

    std::int32_t value = 0;
    for (std::int32_t i = 0; i < kSofdecTagNameBytes; ++i) {
      value = (value << 4) + SofdecDecodeHexNibble(hexString[i]);
    }
    return value;
  }

  /**
   * Address: 0x00B089B0 (FUN_00B089B0, _SJ_GetTagContent)
   *
   * What it does:
   * Expands one tag-header pointer into payload `(data,size)` window lanes.
   */
  std::int32_t SJ_GetTagContent(std::int8_t* const tagHeader, moho::MwsfTagWindow* const outWindow)
  {
    if (tagHeader == nullptr || outWindow == nullptr) {
      return 0;
    }

    outWindow->data = tagHeader + kSofdecTagHeaderBytes;
    outWindow->size = sj_hexstr_to_val(reinterpret_cast<const char*>(tagHeader + 8));
    return outWindow->size;
  }

  /**
   * Address: 0x00B089D0 (FUN_00B089D0, _SJ_SearchTag)
   *
   * What it does:
   * Scans one tag stream for `beginTagName` and optionally early-outs on
   * `endTagName`, returning the matched tag header address when found.
   */
  const char* SJ_SearchTag(
    const moho::MwsfTagWindow* const inputWindow,
    const char* const beginTagName,
    const char* const endTagName,
    moho::MwsfTagWindow* const outWindow
  )
  {
    if (inputWindow == nullptr || outWindow == nullptr || beginTagName == nullptr) {
      return nullptr;
    }

    outWindow->data = nullptr;
    outWindow->size = 0;
    if (inputWindow->data == nullptr || inputWindow->size <= 0) {
      return nullptr;
    }

    std::int8_t* cursor = inputWindow->data;
    const std::int8_t* const end = inputWindow->data + inputWindow->size;
    if (cursor >= end) {
      return nullptr;
    }

    while (std::strncmp(reinterpret_cast<const char*>(cursor), beginTagName, kSofdecTagNameBytes) != 0) {
      if (endTagName == nullptr
          || std::strncmp(reinterpret_cast<const char*>(cursor), endTagName, kSofdecTagNameBytes) != 0) {
        cursor += sj_hexstr_to_val(reinterpret_cast<const char*>(cursor + 8)) + kSofdecTagHeaderBytes;
        if (cursor < end) {
          continue;
        }
      }
      return nullptr;
    }

    (void)SJ_GetTagContent(cursor, outWindow);
    if (cursor >= end) {
      return nullptr;
    }
    return reinterpret_cast<const char*>(cursor);
  }

  /**
   * Address: 0x00AC66E0 (FUN_00AC66E0, _MWSFSFX_GetSfxHn)
   *
   * What it does:
   * Returns one playback object's bound SFX handle lane.
   */
  void* MWSFSFX_GetSfxHn(const moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return ply->sfxHandle;
  }

  /**
   * Address: 0x00AC6CF0 (FUN_00AC6CF0, _mwPlyFxGetCompoMode)
   *
   * What it does:
   * Reads the active SFX composition mode for one playback handle and
   * normalizes dynamic-B/C modes to dynamic-A.
   */
  std::int32_t mwPlyFxGetCompoMode(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetCompoModeInvalidHandle);
      return 0;
    }

    std::int32_t compositionMode = SFX_GetCompoMode(MWSFSFX_GetSfxHn(ply));
    if (compositionMode == kSfxCompoModeDynamicB || compositionMode == kSfxCompoModeDynamicC) {
      compositionMode = kSfxCompoModeDynamicA;
    }
    return compositionMode;
  }

  /**
   * Address: 0x00AC6D40 (FUN_00AC6D40, _mwPlyFxSetOutBufSize)
   *
   * What it does:
   * Sets SFX output pitch/height with default unit-width lane.
   */
  void mwPlyFxSetOutBufSize(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight
  )
  {
    MWSFSFX_SetOutBufSize(ply, outputPitch, outputHeight, 0);
  }

  /**
   * Address: 0x00AC6DA0 (FUN_00AC6DA0, _mwPlyFxSetOutBufPitchHeight)
   *
   * What it does:
   * Alias wrapper for `mwPlyFxSetOutBufSize`.
   */
  void mwPlyFxSetOutBufPitchHeight(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight
  )
  {
    MWSFSFX_SetOutBufSize(ply, outputPitch, outputHeight, 0);
  }

  /**
   * Address: 0x00AC6DD0 (FUN_00AC6DD0, _MWSFSFX_SetOutBufSize)
   *
   * What it does:
   * For valid playback handles, applies output dimensions and unit-width lanes
   * on the bound SFX runtime handle.
   */
  void MWSFSFX_SetOutBufSize(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t outputPitch,
    const std::int32_t outputHeight,
    const std::int32_t unitWidth
  )
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      void* const sfxHandle = MWSFSFX_GetSfxHn(ply);
      SFX_SetOutBufSize(sfxHandle, outputPitch, outputHeight);
      SFX_SetUnitWidth(sfxHandle, unitWidth);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrSetOutBufSizeInvalidHandle);
  }

  /**
   * Address: 0x00AC6FF0 (FUN_00AC6FF0, _mwsftag_IsPlayVideoElementary)
   *
   * What it does:
   * Returns `1` when playback is configured for elementary-video mode.
   */
  std::int32_t mwsftag_IsPlayVideoElementary(const moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }
    return (ply->fileType == kSofdecFileTypeVideoElementary) ? 1 : 0;
  }

  /**
   * Address: 0x00AC70A0 (FUN_00AC70A0, _mwsftag_GetAinfFromSj)
   *
   * What it does:
   * Reads `CRITAGS` AINF payload from SJ lane-1 data and updates cached tag
   * info lanes for the playback object.
   */
  const char* mwsftag_GetAinfFromSj(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return nullptr;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    moho::SofdecSjRingBufferHandle* const sjRingHandle = runtimeView->sjTagRingHandle;
    const std::int32_t availableAinfBytes = (sjRingHandle != nullptr) ? SJRBF_GetNumData(sjRingHandle, 1) : 0;
    const char* result = reinterpret_cast<const char*>(static_cast<std::intptr_t>(availableAinfBytes));

    moho::MwsfTagWindow inputWindow{};
    moho::MwsfTagWindow outputWindow{};
    if (availableAinfBytes != 0) {
      inputWindow.data = runtimeView->ainfSearchBuffer;
      inputWindow.size = availableAinfBytes;
      result = SJ_SearchTag(&inputWindow, kSofdecTagCritags, kSofdecTagCritage, &outputWindow);
    }

    if (result != nullptr) {
      if (runtimeView->ainfUserBuffer != nullptr) {
        std::memcpy(runtimeView->ainfUserBuffer, outputWindow.data, static_cast<std::size_t>(outputWindow.size));
        runtimeView->ainfTagInfoDataAddress = static_cast<std::int32_t>(
          reinterpret_cast<std::intptr_t>(runtimeView->ainfUserBuffer)
        );
        runtimeView->ainfTagInfoLength = outputWindow.size;
        runtimeView->ainfTagInfoReady = 1;

        moho::SjChunkRange lane1Chunk{};
        SJRBF_GetChunk(sjRingHandle, 1, 0x7FFFFFFF, &lane1Chunk);
        SJRBF_PutChunk(sjRingHandle, 0, &lane1Chunk);
        return reinterpret_cast<const char*>(sjrbf_Reset(sjRingHandle));
      }

      runtimeView->ainfTagInfoDataAddress = static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(outputWindow.data)
      );
      runtimeView->ainfTagInfoLength = outputWindow.size;
      runtimeView->ainfTagInfoReady = 1;
      return reinterpret_cast<const char*>(
        static_cast<std::intptr_t>(MWSFTAG_ClearUsrSj(ply))
      );
    }

    runtimeView->ainfTagInfoReady = 1;
    runtimeView->ainfTagInfoDataAddress = 0;
    runtimeView->ainfTagInfoLength = 0;
    return result;
  }

  /**
   * Address: 0x00ACD6C0 (FUN_00ACD6C0, _sfxzmv_SetTagGrp)
   *
   * What it does:
   * Parses one SFXZ payload block and caches ZMHDR/ZMVFRM child-tag windows in
   * the SFXZ tag-group runtime lane.
   */
  const char* sfxzmv_SetTagGrp(SfxzTagGroupRuntimeView* const tagGroup)
  {
    if (tagGroup == nullptr) {
      return nullptr;
    }

    const char* result = reinterpret_cast<const char*>(static_cast<std::intptr_t>(tagGroup->tagPayloadAddress));
    if (tagGroup->tagPayloadAddress != 0) {
      moho::MwsfTagWindow sourceWindow{};
      sourceWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(tagGroup->tagPayloadAddress));
      sourceWindow.size = tagGroup->tagPayloadLength;

      moho::MwsfTagWindow tagWindow{};
      (void)SJ_SearchTag(&sourceWindow, kSofdecTagZmhdr, kSofdecTagSfxinfe, &tagWindow);
      tagGroup->zmhdrReady = 1;
      tagGroup->zmhdrPayloadAddress = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(tagWindow.data));
      tagGroup->zmhdrPayloadLength = tagWindow.size;

      result = SJ_SearchTag(&sourceWindow, kSofdecTagZmvfrm, kSofdecTagSfxinfe, &tagWindow);
      tagGroup->zmvfrmReady = 1;
      tagGroup->zmvfrmPayloadAddress = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(tagWindow.data));
      tagGroup->zmvfrmPayloadLength = tagWindow.size;
      return result;
    }

    tagGroup->zmhdrReady = 1;
    tagGroup->zmhdrPayloadAddress = 0;
    tagGroup->zmhdrPayloadLength = 0;
    tagGroup->zmvfrmReady = 1;
    tagGroup->zmvfrmPayloadAddress = 0;
    tagGroup->zmvfrmPayloadLength = 0;
    return result;
  }

  /**
   * Address: 0x00ACD690 (FUN_00ACD690, _SFXZ_SetTagInf)
   *
   * What it does:
   * Records one raw SFXZ payload window in the target SFXZ tag-group lane and
   * refreshes derived ZMHDR/ZMVFRM child-tag windows.
   */
  const char* SFXZ_SetTagInf(
    SfxzTagGroupRuntimeView* const tagGroup,
    const std::int32_t tagPayloadAddress,
    const std::int32_t tagPayloadLength
  )
  {
    if (tagGroup == nullptr) {
      return nullptr;
    }

    tagGroup->hasTagPayload = 1;
    tagGroup->tagPayloadAddress = tagPayloadAddress;
    tagGroup->tagPayloadLength = tagPayloadLength;
    return sfxzmv_SetTagGrp(tagGroup);
  }

  /**
   * Address: 0x00ACCDF0 (FUN_00ACCDF0, _SFX_SetTagInf)
   *
   * What it does:
   * Stores the latest SFXINFS payload lane on one SFX runtime object, extracts
   * nested SFXZ content when present, and marks tag-info readiness.
   */
  std::int32_t SFX_SetTagInf(void* const sfxHandle, const std::int32_t tagDataAddress, const std::int32_t tagDataLength)
  {
    auto* const runtimeView = reinterpret_cast<SfxTagInfoRuntimeView*>(sfxHandle);
    runtimeView->tagDataAddress = tagDataAddress;
    runtimeView->tagDataLength = tagDataLength;

    moho::MwsfTagWindow sourceWindow{};
    sourceWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(tagDataAddress));
    sourceWindow.size = tagDataLength;

    moho::MwsfTagWindow sfxzWindow{};
    const char* const searchResult = SJ_SearchTag(&sourceWindow, kSofdecTagSfxz, kSofdecTagSfxinfe, &sfxzWindow);

    const char* result = nullptr;
    if (searchResult != nullptr) {
      result = SFXZ_SetTagInf(
        runtimeView->sfxzTagGroup,
        static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(sfxzWindow.data)),
        sfxzWindow.size
      );
    } else {
      result = SFXZ_SetTagInf(runtimeView->sfxzTagGroup, 0, 0);
    }

    runtimeView->tagInfoReady = 1;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00AC7210 (FUN_00AC7210, _mwsftag_GetSFXinfFromAinf)
   *
   * What it does:
   * Extracts `SFXINFS` tag payload from cached AINF lanes and applies it to
   * the current SFX handle.
   */
  std::int32_t mwsftag_GetSFXinfFromAinf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    if (runtimeView->ainfTagInfoDataAddress == 0) {
      return SFX_SetTagInf(runtimeView->sfxHandle, 0, 0);
    }

    moho::MwsfTagWindow inputWindow{};
    inputWindow.data = reinterpret_cast<std::int8_t*>(static_cast<std::intptr_t>(runtimeView->ainfTagInfoDataAddress));
    inputWindow.size = runtimeView->ainfTagInfoLength;

    moho::MwsfTagWindow outputWindow{};
    if (SJ_SearchTag(&inputWindow, kSofdecTagSfxinfs, kSofdecTagSfxinfe, &outputWindow) != nullptr) {
      return SFX_SetTagInf(
        runtimeView->sfxHandle,
        static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(outputWindow.data)),
        outputWindow.size
      );
    }
    return SFX_SetTagInf(runtimeView->sfxHandle, 0, 0);
  }

  /**
   * Address: 0x00AC7050 (FUN_00AC7050, _MWSFTAG_SetTagInf)
   *
   * What it does:
   * Populates playback AINF/SFX tag lanes once when SJ ring input exists and
   * cached tag state is not yet marked ready.
   */
  std::int32_t MWSFTAG_SetTagInf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    const std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtimeView->sjTagRingHandle));
    if (result != 0 && runtimeView->ainfTagInfoReady != 1) {
      (void)mwsftag_GetAinfFromSj(ply);
      return mwsftag_GetSFXinfFromAinf(ply);
    }
    return result;
  }

  /**
   * Address: 0x00AC7080 (FUN_00AC7080, _MWSFTAG_UpdateTagInf)
   *
   * What it does:
   * Refreshes playback AINF/SFX tag lanes from the current SJ ring input.
   */
  std::int32_t MWSFTAG_UpdateTagInf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    const std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(runtimeView->sjTagRingHandle));
    if (result != 0) {
      (void)mwsftag_GetAinfFromSj(ply);
      return mwsftag_GetSFXinfFromAinf(ply);
    }
    return result;
  }

  /**
   * Address: 0x00AC7290 (FUN_00AC7290, _MWSFTAG_ClearUsrSj)
   *
   * What it does:
   * Clears SFD user-SJ lane for non-elementary playback objects with active
   * SJ ring ownership.
   */
  std::int32_t MWSFTAG_ClearUsrSj(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr || mwsftag_IsPlayVideoElementary(ply) == 1) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<MwsfdTagInfoRuntimeView*>(ply);
    if (runtimeView->sjTagRingHandle != nullptr) {
      return -(SFD_SetUsrSj(static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(ply->handle)), 2, 0, 0) != 0);
    }
    return 0;
  }

  /**
   * Address: 0x00AC9A70 (FUN_00AC9A70, _mwsftag_GetTag)
   *
   * What it does:
   * Searches one source tag window for a named tag span and writes the
   * matching child window (`data,size`) to `outWindow`.
   */
  moho::MwsfTagWindow* mwsftag_GetTag(
    moho::MwsfTagWindow* const sourceWindow,
    const char* const tagName,
    const char* const userInfoTag,
    moho::MwsfTagWindow* const outWindow
  )
  {
    if (outWindow == nullptr) {
      return nullptr;
    }

    if (sourceWindow != nullptr && sourceWindow->data != nullptr) {
      moho::MwsfTagWindow inputWindow{};
      inputWindow.data = sourceWindow->data;
      inputWindow.size = sourceWindow->size;
      (void)SJ_SearchTag(&inputWindow, tagName, userInfoTag, outWindow);
      return outWindow;
    }

    outWindow->data = nullptr;
    outWindow->size = 0;
    return outWindow;
  }

  /**
   * Address: 0x00AC9AD0 (FUN_00AC9AD0, _mwsftag_GetIntVal)
   *
   * What it does:
   * Reads one decimal integer payload from a named child tag and writes it to
   * `outValue`; returns `-1` when the target tag is missing.
   */
  std::int32_t mwsftag_GetIntVal(
    moho::MwsfTagWindow* const sourceWindow,
    const char* const tagName,
    const char* const userInfoTag,
    std::int32_t* const outValue
  )
  {
    moho::MwsfTagWindow valueWindow{};
    (void)mwsftag_GetTag(sourceWindow, tagName, userInfoTag, &valueWindow);
    if (valueWindow.data == nullptr) {
      if (outValue != nullptr) {
        *outValue = -1;
      }
      return -1;
    }

    long parsedValue = 0;
    (void)std::sscanf(reinterpret_cast<const char*>(valueWindow.data), "%ld", &parsedValue);
    if (outValue != nullptr) {
      *outValue = static_cast<std::int32_t>(parsedValue);
    }
    return static_cast<std::int32_t>(parsedValue);
  }

  /**
   * Address: 0x00AC9C20 (FUN_00AC9C20, _mwsftag_MoveNextTag)
   *
   * What it does:
   * Advances from one current child tag to the remaining source window span.
   */
  std::int32_t mwsftag_MoveNextTag(
    const moho::MwsfTagWindow* const sourceWindow,
    const moho::MwsfTagWindow* const currentTagWindow,
    moho::MwsfTagWindow* const outRemainingWindow
  )
  {
    if (sourceWindow == nullptr || currentTagWindow == nullptr || outRemainingWindow == nullptr) {
      return 0;
    }

    outRemainingWindow->data = currentTagWindow->data + currentTagWindow->size;
    outRemainingWindow->size =
      static_cast<std::int32_t>((sourceWindow->data + sourceWindow->size) - currentTagWindow->data - currentTagWindow->size);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(sourceWindow->data));
  }

  /**
   * Address: 0x00AC9ED0 (FUN_00AC9ED0, _MWSFD_CmpTime)
   *
   * What it does:
   * Clamps negative left/right time lanes to zero and forwards to
   * `UTY_CmpTime`.
   */
  std::int32_t MWSFD_CmpTime(
    std::int32_t leftTime,
    const std::int32_t timeUnit,
    std::int32_t rightTime,
    const std::int32_t currentTime
  )
  {
    if (leftTime < 0) {
      leftTime = 0;
    }
    if (rightTime < 0) {
      rightTime = 0;
    }
    return UTY_CmpTime(leftTime, timeUnit, rightTime, currentTime);
  }

  /**
   * Address: 0x00AC9D00 (FUN_00AC9D00, _MWSFTAG_SearchTimedatFromChdat)
   *
   * What it does:
   * Selects the active `TIMEDAT` child span from one chapter-data window based
   * on current playback time and writes that window into `outTimedatWindow`.
   */
  std::int8_t* MWSFTAG_SearchTimedatFromChdat(
    moho::MwsfTagWindow* const chapterDataWindow,
    const std::int32_t compareArg0,
    const std::int32_t compareArg1,
    const std::int32_t baseTime,
    moho::MwsfTagWindow* const outTimedatWindow
  )
  {
    if (chapterDataWindow == nullptr || outTimedatWindow == nullptr) {
      return nullptr;
    }

    moho::MwsfTagWindow remainingWindow{};
    remainingWindow.data = chapterDataWindow->data;
    remainingWindow.size = chapterDataWindow->size;
    outTimedatWindow->data = nullptr;
    outTimedatWindow->size = 0;

    std::int32_t timeUnit = -1;
    (void)mwsftag_GetIntVal(chapterDataWindow, kSofdecTagTunit, kSofdecTagUsrinfe, &timeUnit);

    moho::MwsfTagWindow selectedTimedatWindow{};
    std::int8_t* result = reinterpret_cast<std::int8_t*>(mwsftag_GetTag(
      &remainingWindow, kSofdecTagTimedat, kSofdecTagUsrinfe, &selectedTimedatWindow
    ));
    if (selectedTimedatWindow.data == nullptr) {
      return result;
    }

    std::int32_t currentInTime = -1;
    moho::MwsfTagWindow workingTimedatWindow = selectedTimedatWindow;
    (void)mwsftag_GetIntVal(&workingTimedatWindow, kSofdecTagIntime, kSofdecTagUsrinfe, &currentInTime);
    (void)mwsftag_MoveNextTag(chapterDataWindow, &workingTimedatWindow, &remainingWindow);

    result = reinterpret_cast<std::int8_t*>(
      static_cast<std::intptr_t>(MWSFD_CmpTime(baseTime + currentInTime, timeUnit, compareArg0, compareArg1))
    );
    if (result == reinterpret_cast<std::int8_t*>(1)) {
      while (remainingWindow.size >= kSofdecTagHeaderBytes) {
        moho::MwsfTagWindow nextTimedatWindow{};
        (void)mwsftag_GetTag(&remainingWindow, kSofdecTagTimedat, kSofdecTagUsrinfe, &nextTimedatWindow);
        if (nextTimedatWindow.data == nullptr) {
          break;
        }

        std::int32_t nextInTime = -1;
        moho::MwsfTagWindow nextTimedatCopy = nextTimedatWindow;
        (void)mwsftag_GetIntVal(&nextTimedatCopy, kSofdecTagIntime, kSofdecTagUsrinfe, &nextInTime);
        (void)mwsftag_MoveNextTag(chapterDataWindow, &nextTimedatCopy, &remainingWindow);

        if (MWSFD_CmpTime(baseTime + nextInTime, timeUnit, compareArg0, compareArg1) != 1) {
          break;
        }

        selectedTimedatWindow = nextTimedatWindow;
        currentInTime = nextInTime;
      }

      std::int32_t duration = -1;
      moho::MwsfTagWindow selectedTimedatCopy = selectedTimedatWindow;
      (void)mwsftag_GetIntVal(&selectedTimedatCopy, kSofdecTagDurtime, kSofdecTagUsrinfe, &duration);

      result = reinterpret_cast<std::int8_t*>(
        static_cast<std::intptr_t>(MWSFD_CmpTime(baseTime + currentInTime + duration, timeUnit, compareArg0, compareArg1))
      );
      if (result != reinterpret_cast<std::int8_t*>(1)) {
        *outTimedatWindow = selectedTimedatWindow;
        result = reinterpret_cast<std::int8_t*>(outTimedatWindow);
      }
    }

    return result;
  }

  /**
   * Address: 0x00AC8D10 (FUN_00AC8D10, _mwply_Destroy)
   *
   * What it does:
   * Stops active decode lanes, tears down all linked playback resources,
   * checks allocation leak counters, and clears the playback object.
   */
  void mwply_Destroy(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply == nullptr) {
      return;
    }

    mwSfdStopDec(ply);
    ply->compoMode = 0;
    MWSFTAG_DestroyAinfSj(ply);

    if (ply->sfxHandle != nullptr) {
      MWSFSFX_Destroy(ply->sfxHandle);
    }
    if (ply->lscHandle != nullptr) {
      LSC_Destroy(ply->lscHandle);
    }
    if (ply->adxStreamHandle != nullptr) {
      MWSTM_Destroy(ply->adxStreamHandle);
    }
    if (ply->sjRingBufferHandle != nullptr) {
      sjrbf_Destroy(ply->sjRingBufferHandle);
    }
    if (ply->sjMemoryHandle != nullptr) {
      sjmem_Destroy(ply->sjMemoryHandle);
    }
    if (ply->handle != nullptr) {
      MWSFCRE_DestroySfd(static_cast<char*>(ply->handle));
    }

    MWSST_Destroy(&ply->streamState);
    mwsfcre_AllFree(ply);
    if (mwsfcre_GetMallocCnt(ply) != 0) {
      (void)MWSFSVM_Error(kMwsfdErrForgotFree);
    }

    std::memset(ply, 0, sizeof(*ply));
    ply->compoMode = 0;
  }

  /**
   * Address: 0x00AC8F60 (FUN_00AC8F60, _MWSFD_Malloc)
   *
   * What it does:
   * Allocates one playback-owned work block through arena/user alloc path and
   * records the allocation pointer in the playback allocation table.
   */
  void* MWSFD_Malloc(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t size)
  {
    if (ply->mwsfcreAllocationCount >= static_cast<std::int32_t>(ply->mwsfcreAllocations.size())) {
      (void)MWSFSVM_Error(kMwsfdErrMallocCountOver);
      return nullptr;
    }

    if (size < 0) {
      return nullptr;
    }

    void* allocation = nullptr;
    if (ply->mwsfcreWorkSizeBytes != 0) {
      allocation = mwsfcre_OrgMalloc(ply, size);
    } else {
      allocation = mwsfcre_UsrMalloc(size);
    }

    if (allocation != nullptr) {
      ply->mwsfcreAllocations[static_cast<std::size_t>(ply->mwsfcreAllocationCount)] = allocation;
      mwsfcre_IncMallocCnt(ply);
    }
    return allocation;
  }

  /**
   * Address: 0x00AC9120 (FUN_00AC9120, _MWSFLIB_GetLibWorkPtr)
   */
  moho::MwsfdLibWork* MWSFLIB_GetLibWorkPtr()
  {
    return &gMwsfdLibWork;
  }

  /**
   * Address: 0x00AC9280 (FUN_00AC9280, _mwsflib_LscErrFunc)
   *
   * What it does:
   * Forwards one LSC runtime error message into the shared MWSFSVM error lane.
   */
  void mwsflib_LscErrFunc(const std::int32_t callbackObject, const char* const message)
  {
    (void)callbackObject;
    (void)MWSFSVM_Error(message);
  }

  /**
   * Address: 0x00AC92D0 (FUN_00AC92D0, _mwsflib_InitLibWork)
   *
   * What it does:
   * Clears global MWSFD library work state and applies startup/default display
   * condition lanes.
   */
  void mwsflib_InitLibWork(moho::MwsfdInitPrm* const initParams)
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    std::memset(libWork, 0, sizeof(*libWork));

    MWSFSVR_SetMwsfdSvrFlg(0);
    libWork->initLatch = 0;

    if (initParams != nullptr) {
      libWork->displayRefreshHz = initParams->vhz;
      libWork->displayCycle = initParams->disp_cycle;
      libWork->displayLatency = initParams->disp_latency;
      libWork->decodeServerSelection = static_cast<std::int32_t>(initParams->dec_svr);
    } else {
      libWork->displayRefreshHz = std::bit_cast<float>(0x426FC28Fu);
      libWork->displayCycle = 1;
      libWork->displayLatency = 1;
      libWork->decodeServerSelection = 0;
    }

    libWork->defaultConditionReserved = 0;
    libWork->defaultConditionInitialized = 1;
  }

  /**
   * Address: 0x00AC9380 (FUN_00AC9380, _mwsflib_SetDefCond)
   *
   * What it does:
   * Applies default playback condition lanes (`27`, `7`) in MWSFD runtime.
   */
  std::int32_t mwsflib_SetDefCond(const float* const startupConditionValue)
  {
    (void)MWSFD_SetCond(0, 27, static_cast<std::int32_t>(*startupConditionValue));
    return MWSFD_SetCond(0, 7, 1);
  }

  /**
   * Address: 0x00AC9470 (FUN_00AC9470, _MWSFLIB_SetErrCode)
   *
   * What it does:
   * Stores the current MWSFD library error-code lane and returns written value.
   */
  std::int32_t MWSFLIB_SetErrCode(const std::int32_t errorCode)
  {
    MWSFLIB_GetLibWorkPtr()->lastErrorCode = errorCode;
    return errorCode;
  }

  /**
   * Address: 0x00AC9490 (FUN_00AC9490, _mwPlySfdInit)
   */
  std::int32_t mwPlySfdInit(const std::int32_t requestedVersion)
  {
    moho::MwsfdInitSfdParams initParams{};
    initParams.callbacks = gMwsfdInitSfdParams.callbacks;
    initParams.version = requestedVersion;

    if (SFD_IsVersionCompatible(kMwsfdRequiredVersion, kMwsfdRequiredVersionTag) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrIncompatibleVersion);
      return -1;
    }

    if (SFD_Init(&initParams) != 0) {
      return MWSFLIB_SetErrCode(kMwsfdErrInitFailed);
    }

    const auto callbackAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFLIB_SfdErrFunc));
    if (SFD_SetErrFn(0, callbackAddress, 0) != 0) {
      return MWSFLIB_SetErrCode(kMwsfdErrSetErrFnFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00AC9530 (FUN_00AC9530, _mwPlySfdFinish)
   *
   * What it does:
   * Runs one SFD global shutdown pass and returns success.
   */
  std::int32_t mwPlySfdFinish()
  {
    (void)SFD_Finish();
    return 0;
  }

  /**
   * Address: 0x00AC9540 (FUN_00AC9540, _MWSFLIB_SfdErrFunc)
   */
  std::int32_t MWSFLIB_SfdErrFunc(const std::int32_t mwsfdHandle, const std::int32_t errorCode)
  {
    if (mwsfdHandle != 0) {
      auto* const playbackHandle = reinterpret_cast<moho::MwsfdPlaybackStateSubobj*>(
        static_cast<std::uintptr_t>(mwsfdHandle)
      );
      gMwsfdLastSfdHandle = mwPlyGetSfdHn(playbackHandle);
      gMwsfdLastMwsfdHandle = mwsfdHandle;
    } else {
      gMwsfdLastMwsfdHandle = 0;
      gMwsfdLastSfdHandle = 0;
    }

    if (errorCode != 0) {
      const std::int32_t historyIndex = gMwsfdErrorCount;
      gMwsfdErrorCodeHistory[historyIndex] = errorCode;
      if (historyIndex < kMwsfdErrorHistoryMaxIndex) {
        gMwsfdErrorCount = historyIndex + 1;
      }
    }

    if (errorCode > kMwsfdErrFramePoolSize) {
      if (errorCode > kMwsfdErrRelFrameDoubleRelease) {
        if (errorCode >= kMwsfdErrDataLowerBound && errorCode <= kMwsfdErrDataUpperBound) {
          std::snprintf(
            gMwsfdErrorString,
            sizeof(gMwsfdErrorString),
            kMwsfdFmtDataError,
            static_cast<unsigned int>(errorCode)
          );
          return MWSFSVM_Error(gMwsfdErrorString);
        }
      } else if (errorCode == kMwsfdErrRelFrameDoubleRelease) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgRelFrameDoubleRelease,
          static_cast<unsigned int>(kMwsfdErrRelFrameDoubleRelease)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      } else if (errorCode >= kMwsfdErrMaxWidthHeightSmallMin && errorCode <= kMwsfdErrMaxWidthHeightSmallMax) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgMaxWidthHeightSmall,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      } else if (errorCode == kMwsfdErrReadBufferSmallA) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgReadBufferSmall,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      }
    } else if (errorCode == kMwsfdErrFramePoolSize) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdMsgFramePoolSize,
        static_cast<unsigned int>(kMwsfdErrFramePoolSize)
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    } else if (errorCode > kMwsfdErrLibraryMessage) {
      if (errorCode == kMwsfdErrAdxtHandleLimit) {
        std::snprintf(
          gMwsfdErrorString,
          sizeof(gMwsfdErrorString),
          kMwsfdMsgAdxtHandleLimit,
          static_cast<unsigned int>(errorCode)
        );
        return MWSFSVM_Error(gMwsfdErrorString);
      }
    } else if (errorCode == kMwsfdErrLibraryMessage) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdFmtSfdErrorWithText,
        static_cast<unsigned int>(kMwsfdErrLibraryMessage),
        gMwsfdBackendErrorText
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    } else if (errorCode == kMwsfdErrReadBufferSmallB || errorCode == kMwsfdErrReadBufferSmallC) {
      std::snprintf(
        gMwsfdErrorString,
        sizeof(gMwsfdErrorString),
        kMwsfdMsgReadBufferSmall,
        static_cast<unsigned int>(errorCode)
      );
      return MWSFSVM_Error(gMwsfdErrorString);
    }

    std::snprintf(gMwsfdErrorString, sizeof(gMwsfdErrorString), kMwsfdFmtSfdError, static_cast<unsigned int>(errorCode));
    return MWSFSVM_Error(gMwsfdErrorString);
  }

  /**
   * Address: 0x00AC96A0 (FUN_00AC96A0, _MWSFLIB_SetSeekFlg)
   *
   * What it does:
   * Stores global MWSFD seek-flag lane.
   */
  void MWSFLIB_SetSeekFlg(const std::int32_t enabled)
  {
    MWSFLIB_GetLibWorkPtr()->seekFlag = enabled;
  }

  /**
   * Address: 0x00AC96B0 (FUN_00AC96B0, _MWSFLIB_GetSeekFlg)
   *
   * What it does:
   * Returns global MWSFD seek-flag lane.
   */
  std::int32_t MWSFLIB_GetSeekFlg()
  {
    return MWSFLIB_GetLibWorkPtr()->seekFlag;
  }

  /**
   * Address: 0x00ACA090 (FUN_00ACA090, _mwPlyGetCurFrm)
   *
   * What it does:
   * Fetches the current SFD frame into one runtime frame-info object and
   * updates playback frame counters/concat tracking lanes.
   */
  moho::MwsfdFrameInfo*
  mwPlyGetCurFrm(moho::MwsfdPlaybackStateSubobj* const ply, moho::MwsfdFrameInfo* const outFrameInfo)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetCurFrmInvalidHandle);
      std::memset(outFrameInfo, 0, sizeof(*outFrameInfo));
      outFrameInfo->bufferAddress = 0;
      return nullptr;
    }

    mwsffrm_SetFrmApi(ply, 1);
    const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
    if (sfdHandleAddress == 0) {
      std::memset(outFrameInfo, 0, sizeof(*outFrameInfo));
      outFrameInfo->bufferAddress = 0;
      return nullptr;
    }

    void* sfdFrame = nullptr;
    SFD_GetFrm(sfdHandleAddress, &sfdFrame);

    if (sfdFrame == nullptr) {
      outFrameInfo->bufferAddress = 0;
      return outFrameInfo;
    }

    if (ply->disableIntermediateFrameDrop == 0) {
      const std::int32_t framePoolSize = ply->framePoolSize;
      for (std::int32_t droppedFrames = 0; droppedFrames < framePoolSize; ++droppedFrames) {
        if (mwPlyIsNextFrmReady(ply) != 1) {
          break;
        }

        SFD_RelFrm(sfdHandleAddress, sfdFrame);
        ++ply->releasedFrameCount;
        SFD_GetFrm(sfdHandleAddress, &sfdFrame);
      }
    }

    if (sfdFrame != nullptr) {
      ++ply->retrievedFrameCount;
      ply->lastSfdFrame = sfdFrame;

      mwsffrm_SaveFrmDetail(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfdFrame))
      );
      mwl_convFrmInfFromSFD(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfdFrame)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrameInfo))
      );

      outFrameInfo->frameId = outFrameInfo->frameNumber;
      ply->lastFrameConcatCount = outFrameInfo->concatCount;
      return reinterpret_cast<moho::MwsfdFrameInfo*>(mwsffrm_CheckAinf(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply)),
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outFrameInfo))
      ));
    }

    outFrameInfo->bufferAddress = 0;
    return outFrameInfo;
  }

  /**
   * Address: 0x00ACA760 (FUN_00ACA760, _mwPlyRelCurFrm)
   *
   * What it does:
   * Releases one current SFD frame lane and advances playback frame cursors
   * when one unreleased frame is still pending.
   */
  void mwPlyRelCurFrm(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      void* const currentFrame = ply->lastSfdFrame;
      const std::int32_t releasedFrameCursor = ply->mUnknown80;
      const std::int32_t retrievedFrameCursor = ply->retrievedFrameCount;

      mwsffrm_SetFrmApi(ply, 1);
      const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
      if (retrievedFrameCursor > releasedFrameCursor) {
        SFD_RelFrm(sfdHandleAddress, currentFrame);
        const std::int32_t nextFrameCursor = ply->mUnknown80 + 1;
        ply->mUnknown80 = nextFrameCursor;
        ply->retrievedFrameCount = nextFrameCursor;
      }
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrRelCurFrmInvalidHandle);
  }

  /**
   * Address: 0x00ACA8A0 (FUN_00ACA8A0, _mwPlyGetNumSkipDisp)
   *
   * What it does:
   * Returns display-skip frame counter lane from playback state.
   */
  std::int32_t mwPlyGetNumSkipDisp(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetNumSkipDispInvalidHandle);
      return 0;
    }
    return ply->releasedFrameCount;
  }

  /**
   * Address: 0x00ACB5C0 (FUN_00ACB5C0, _mwPlyGetSfdHn)
   *
   * What it does:
   * Returns active SFD handle-address lane when playback handle is valid.
   */
  std::int32_t mwPlyGetSfdHn(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->handle));
    }

    (void)MWSFSVM_Error(kMwsfdErrGetSfdHandleInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACB620 (FUN_00ACB620, _mwPlyGetNumDropFrm)
   *
   * What it does:
   * Returns aggregate dropped-frame count (decode-skip + display-skip).
   */
  std::int32_t mwPlyGetNumDropFrm(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      return mwPlyGetNumSkipDec(ply) + mwPlyGetNumSkipDisp(ply);
    }

    (void)MWSFSVM_Error(kMwsfdErrGetNumDropFrmInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACB660 (FUN_00ACB660, _mwPlyGetNumSkipDec)
   *
   * What it does:
   * Returns decode-skip count as the delta of two SFD playback-info lanes.
   */
  std::int32_t mwPlyGetNumSkipDec(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetNumSkipDecInvalidHandle);
      return 0;
    }

    const std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
    if (sfdHandleAddress == 0) {
      return sfdHandleAddress;
    }

    MwsfdRawPlaybackInfo playbackInfo{};
    (void)SFD_GetPlyInf(sfdHandleAddress, &playbackInfo);
    return playbackInfo.dropFrameAccumulator - playbackInfo.skipEmptyBFrameCount;
  }

  /**
   * Address: 0x00ACB8E0 (FUN_00ACB8E0, _MWSFD_GetPlyInf)
   *
   * What it does:
   * Copies one SFD playback-info snapshot into caller output memory.
   */
  std::int32_t MWSFD_GetPlyInf(moho::MwsfdPlaybackStateSubobj* const ply, void* const outPlyInfo)
  {
    const std::int32_t sfdHandleAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->handle));
    if (sfdHandleAddress != 0) {
      return SFD_GetPlyInf(sfdHandleAddress, outPlyInfo);
    }

    std::memset(outPlyInfo, 0, sizeof(MwsfdRawPlaybackInfo));
    return sfdHandleAddress;
  }

  /**
   * Address: 0x00ACB950 (FUN_00ACB950, _MWSFD_GetCond)
   *
   * What it does:
   * Reads one condition lane from playback SFD handle when present, otherwise
   * from process-global default condition storage.
   */
  std::int32_t MWSFD_GetCond(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t conditionId,
    std::int32_t* const outConditionValue
  )
  {
    if (ply != nullptr) {
      return SFD_GetCond(
        reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle),
        conditionId,
        outConditionValue
      );
    }

    return SFD_GetCond(nullptr, conditionId, outConditionValue);
  }

  /**
   * Address: 0x00ACBA90 (FUN_00ACBA90, _mwPlyGetStat)
   *
   * What it does:
   * Returns playback status lane directly from composition mode, with special
   * streaming-mode mapping based on current SFD handle status.
   */
  std::int32_t mwPlyGetStat(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    constexpr std::int32_t kMwsfdCompoModeStreaming = 2;
    constexpr std::int32_t kSfdHandleStatusEos = 4;
    constexpr std::int32_t kSfdHandleStatusEnded = 6;
    constexpr std::int32_t kMwsfdPlaybackStatusRunning = 1;
    constexpr std::int32_t kMwsfdPlaybackStatusHold = 2;
    constexpr std::int32_t kMwsfdPlaybackStatusError = 4;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFLIB_SetErrCode(kMwsfdErrCodeInvalidHandle);
      (void)MWSFSVM_Error(kMwsfdErrGetStatInvalidHandle);
      return 0;
    }

    std::int32_t status = ply->compoMode;
    if (status == kMwsfdCompoModeStreaming) {
      status = SFD_GetHnStat(ply->handle);
      if (status == kSfdHandleStatusEos || status == kSfdHandleStatusEnded) {
        return kMwsfdPlaybackStatusHold;
      }
      return (status >= 0) ? kMwsfdPlaybackStatusRunning : kMwsfdPlaybackStatusError;
    }
    return status;
  }

  /**
   * Address: 0x00ACBBC0 (FUN_00ACBBC0, _mwPlyGetSyncMode)
   *
   * What it does:
   * Reads sync-mode condition lane (`15`) and returns normalized sync mode
   * (`0`, `1`, `2`) or `-1` on invalid handle/mode.
   */
  std::int32_t mwPlyGetSyncMode(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    constexpr std::int32_t kMwsfdConditionSyncMode = 15;
    constexpr std::int32_t kMwsfdSyncModeExternal = 1;
    constexpr std::int32_t kMwsfdSyncModeInternal = 2;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetSyncModeInvalidHandle);
      return -1;
    }

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    if (workctrlSubobj == nullptr) {
      return 0;
    }

    // Binary writes condition output into stack slot that originally held `ply`.
    std::int32_t syncMode = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply));
    (void)SFD_GetCond(workctrlSubobj, kMwsfdConditionSyncMode, &syncMode);

    if (syncMode == 0) {
      return 0;
    }
    if (syncMode == kMwsfdSyncModeExternal) {
      return kMwsfdSyncModeExternal;
    }
    if (syncMode == kMwsfdSyncModeInternal) {
      return kMwsfdSyncModeInternal;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetSyncModeInvalidMode);
    return -1;
  }

  /**
   * Address: 0x00ACBFC0 (FUN_00ACBFC0, _mwPlyGetNumSkipEmptyB)
   *
   * What it does:
   * Returns empty-B skip counter lane from playback-info snapshot.
   */
  std::int32_t mwPlyGetNumSkipEmptyB(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      MwsfdRawPlaybackInfo playbackInfo{};
      (void)MWSFD_GetPlyInf(ply, &playbackInfo);
      return playbackInfo.skipEmptyBFrameCount;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetNumSkipEmptyBInvalidHandle);
    return 0;
  }

  /**
   * Address: 0x00ACC080 (FUN_00ACC080, _mwPlyGetPlyInf)
   *
   * What it does:
   * Builds six playback-debug counters for movie debug output.
   */
  std::int32_t mwPlyGetPlyInf(moho::MwsfdPlaybackStateSubobj* const ply, std::int32_t* const outInfoWords)
  {
    auto* const playbackSummary = reinterpret_cast<MwsfdPlaybackInfoSummary*>(outInfoWords);
    if (MWSFD_IsEnableHndl(ply) == 1) {
      std::int32_t sfdHandleAddress = mwPlyGetSfdHn(ply);
      if (sfdHandleAddress != 0) {
        MwsfdRawPlaybackInfo playbackInfo{};
        MwsfdRawTimerInfo timerInfo{};
        (void)SFD_GetPlyInf(sfdHandleAddress, &playbackInfo);

        playbackSummary->dropFrameCount = mwPlyGetNumDropFrm(ply);
        playbackSummary->skipDecodeCount = mwPlyGetNumSkipDec(ply);
        playbackSummary->skipDisplayCount = mwPlyGetNumSkipDisp(ply);
        playbackSummary->skipEmptyBCount = mwPlyGetNumSkipEmptyB(ply);
        playbackSummary->noSupplyCount = playbackInfo.noSupplyFrameCount;

        (void)SFD_GetTmrInf(sfdHandleAddress, &timerInfo);
        sfdHandleAddress = timerInfo.timerEndSample;
        playbackSummary->timerSample = timerInfo.timerEndSample;
      } else {
        std::memset(playbackSummary, 0, sizeof(*playbackSummary));
      }
      return sfdHandleAddress;
    }

    (void)MWSFSVM_Error(kMwsfdErrGetPlyInfInvalidHandle);
    std::memset(playbackSummary, 0, sizeof(*playbackSummary));
    return 0;
  }

  /**
   * Address: 0x00ACC6C0 (FUN_00ACC6C0, _mwPlyGetTimerCh)
   *
   * What it does:
   * Returns default timer-channel lane from global condition slot `61`.
   */
  void* mwPlyGetTimerCh(void* const timerChannelFallback)
  {
    constexpr std::int32_t kMwsfdConditionTimerChannel = 61;
    std::int32_t timerChannel = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(timerChannelFallback));
    (void)SFD_GetCond(nullptr, kMwsfdConditionTimerChannel, &timerChannel);
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(timerChannel)));
  }

  /**
   * Address: 0x00ACE9A0 (FUN_00ACE9A0, _SFX_CnvFrmByCbFunc)
   */
  void SFX_CnvFrmByCbFunc(
    moho::SfxCallbackFrameContext* const conversionState,
    moho::SfxStreamState* const streamState,
    const std::int32_t callbackArg
  )
  {
    const std::int32_t compositionCode = conversionState->compositionCode;
    if (compositionCode == 0) {
      conversionState->compositionCode = SFXINF_GetStmInf(streamState, kSfxTagCompo);
    }

    if (compositionCode > kSfxCompoModeDynamicB) {
      if (compositionCode == kSfxCompoModeDynamicC) {
        const std::int32_t tableMode = SFX_DecideTableAlph3(conversionState, streamState);
        SFX_MakeTable(conversionState, streamState, tableMode);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      }

      if (compositionCode == kSfxCompoModeDirect) {
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 0);
        return;
      }

      if (compositionCode == kSfxCompoModeForcedLookup) {
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableForced);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      }

      SFXLIB_Error(conversionState, streamState, kSfxErrUnsupportedCompo);
      return;
    }

    if (compositionCode == kSfxCompoModeDynamicB || compositionCode == kSfxCompoModeDynamicA) {
      const std::int32_t tableMode = SFX_DecideTableAlph3(conversionState, streamState);
      SFX_MakeTable(conversionState, streamState, tableMode);
      sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
      return;
    }

    switch (compositionCode) {
      case kSfxCompoModeHalfAlpha:
        if (streamState->fieldTransformMode == 1) {
          SFX_MakeTable(conversionState, streamState, kSfxCompoTableForced);
          sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        } else {
          sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 0);
        }
        return;
      case kSfxCompoModeFullAlpha:
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableFullAlpha);
        sfxcnv_ExecFullAlphaByCbFunc(conversionState, streamState, callbackArg);
        return;
      case kSfxCompoModeLookup:
        SFX_MakeTable(conversionState, streamState, kSfxCompoTableLookup);
        sfxcnv_ExecCnvFrmByCbFunc(conversionState, streamState, callbackArg, 1);
        return;
      default:
        SFXLIB_Error(conversionState, streamState, kSfxErrUnsupportedCompo);
        return;
    }
  }

  [[nodiscard]] moho::MwsfdPlaybackStateSubobj*
  GetMwsfdDecodeServerPlaybackSlot(moho::MwsfdLibWork* const libWork, const std::int32_t slotIndex)
  {
    auto* const slotBase = reinterpret_cast<std::uint8_t*>(libWork->playbackSlotsRaw);
    return reinterpret_cast<moho::MwsfdPlaybackStateSubobj*>(
      slotBase + (static_cast<std::size_t>(slotIndex) * sizeof(moho::MwsfdPlaybackStateSubobj))
    );
  }

  /**
   * Address: 0x00ACCCB0 (FUN_00ACCCB0, _MWSFSVM_TestAndSet)
   *
   * What it does:
   * Forwards one signal lane to `_SVM_TestAndSet`.
   */
  BOOL MWSFSVM_TestAndSet(std::int32_t* const signalLane)
  {
    return SVM_TestAndSet(signalLane);
  }

  /**
   * Address: 0x00AD93D0 (FUN_00AD93D0, _mwsfsvr_ExecCbFnDecSvrTop)
   *
   * What it does:
   * Invokes optional decode-server "top" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnDecSvrTop()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerTopCallback != nullptr) {
      (void)libWork->decodeServerTopCallback(libWork->decodeServerTopContext);
    }
  }

  /**
   * Address: 0x00AD93F0 (FUN_00AD93F0, _mwsfsvr_ExecCbFnDecSvrEnd)
   *
   * What it does:
   * Invokes optional decode-server "end" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnDecSvrEnd()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerEndCallback != nullptr) {
      (void)libWork->decodeServerEndCallback(libWork->decodeServerEndContext);
    }
  }

  /**
   * Address: 0x00AD9410 (FUN_00AD9410, _mwsfsvr_ExecCbFnRestDecSvr)
   *
   * What it does:
   * Invokes optional decode-server "rest" callback lane from global MWSFD
   * library work.
   */
  void mwsfsvr_ExecCbFnRestDecSvr()
  {
    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (libWork->decodeServerRestCallback != nullptr) {
      (void)libWork->decodeServerRestCallback(libWork->decodeServerRestContext);
    }
  }

  /**
   * Address: 0x00AD9430 (FUN_00AD9430, _mwPlyExecSvrHndl)
   *
   * What it does:
   * Thin thunk to `mwply_ExecSvrHndl`.
   */
  std::int32_t mwPlyExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return mwply_ExecSvrHndl(ply);
  }

  /**
   * Address: 0x00AD9440 (FUN_00AD9440, _mwply_ExecSvrHndl)
   *
   * What it does:
   * Validates one playback object for decode-server execution and dispatches
   * into per-handle server execution when server gates are clear.
   */
  std::int32_t mwply_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (mwsfd_init_flag != 1) {
      return 0;
    }

    if (ply == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrExecSvrNullHandle);
      return 0;
    }

    if (ply->used != 1) {
      return 0;
    }
    if (MWSFSVR_GetHnMwplySvrFlg(ply) == 1) {
      return 0;
    }
    if (MWSFD_GetReqSvrBdrLib() == 1) {
      return 0;
    }

    return mwsfd_ExecSvrHndl(ply);
  }

  /**
   * Address: 0x00AD94A0 (FUN_00AD94A0, _mwsfd_ExecSvrHndl)
   *
   * What it does:
   * Executes one SFD server tick for a playback handle and runs decode-server
   * side lanes when composition mode is active.
   */
  std::int32_t mwsfd_ExecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    (void)MWSFSVR_SetHnMwplySvrFlg(ply, 1);

    if (ply->used != 1) {
      (void)MWSFSVR_SetHnMwplySvrFlg(ply, 0);
      return FALSE;
    }

    mwsfd_hn_last = ply;
    (void)MWSFSVR_SetHnSfdSvrFlg(ply, 1);
    SFD_ExecOne(workctrlSubobj);
    (void)MWSFSVR_SetHnSfdSvrFlg(ply, 0);

    if (ply->compoMode != 0) {
      ply->decodeServerDispatchFlag = 1;
      (void)mwSfdExecDecSvrHndl(ply);
    } else {
      ply->decodeServerDispatchFlag = 0;
    }

    (void)MWSFSVR_SetHnMwplySvrFlg(ply, 0);
    return (SFD_IsHnSvrWait(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj))) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD9530 (FUN_00AD9530, _mwSfdExecDecSvrHndl)
   *
   * What it does:
   * Dispatches one decode-server tick for prep/playing composition lanes, then
   * runs file-system and supply checks.
   */
  std::int32_t mwSfdExecDecSvrHndl(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->compoMode == 1) {
      (void)mwlSfdExecDecSvrPrep(ply);
    } else if (ply->compoMode == 2) {
      (void)mwlSfdExecDecSvrPlaying(ply);
    }

    (void)mwsfd_CheckFsErr(ply);
    mwsfsvr_CheckSupply();
    return 0;
  }

  /**
   * Address: 0x00AD9570 (FUN_00AD9570, _mwlSfdExecDecSvrPrep)
   *
   * What it does:
   * Runs prep-state decode-server step: executes pending stream start request,
   * starts playback lanes, and transitions into playing composition mode when
   * handle status reaches active/ready states.
   */
  std::int32_t mwlSfdExecDecSvrPrep(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);

    if (ply->pendingStartRequestType == 1 && mwsfsvr_StartStream(ply) == 1) {
      ply->pendingStartRequestType = 0;
    }

    mwsfsvr_StartPlayback(ply);
    const std::int32_t status = SFD_GetHnStat(workctrlSubobj);
    if (status == 4 || status == 6) {
      ply->compoMode = 2;
    }
    return status;
  }

  /**
   * Address: 0x00AD9790 (FUN_00AD9790, _mwlSfdExecDecSvrPlaying)
   *
   * What it does:
   * Runs one playing-state decode-server step: terminates prepared supply lane
   * when seamless list is empty, checks supply starvation, and transitions to
   * hold state on SFD status `6`.
   */
  std::int32_t mwlSfdExecDecSvrPlaying(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);

    if (ply->isPrepared == 1 && LSC_GetNumStm(ply->lscHandle) == 0) {
      if (sfply_TermSupply(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj))) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrExecSvrPlayingTermFailed);
      }
      ply->isPrepared = 0;
    }

    if (ply->concatPlayArmed == 0 && ply->isPrepared == 0 && LSC_GetNumStm(ply->lscHandle) == 0) {
      (void)mwPlyChkSupply(ply);
    }

    const std::int32_t status = SFD_GetHnStat(workctrlSubobj);
    if (status == 6) {
      ply->compoMode = 3;
    }
    return status;
  }

  /**
   * Address: 0x00AD9810 (FUN_00AD9810, _mwsfd_CheckFsErr)
   *
   * What it does:
   * Maps stream and seamless-link filesystem error states to composition-mode
   * error state (`4`).
   */
  std::int32_t mwsfd_CheckFsErr(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->adxStreamHandle != nullptr && MWSTM_IsFsStatErr(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(ply->adxStreamHandle)))) {
      ply->compoMode = 4;
    }

    if (ply->lscHandle != nullptr) {
      const bool hasFsError = MWSFLSC_IsFsStatErr(ply->lscHandle);
      if (hasFsError) {
        ply->compoMode = 4;
      }
      return hasFsError ? 1 : 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADDB40 (FUN_00ADDB40, _mwsfsvr_CheckSupply)
   *
   * What it does:
   * Reserved supply-check lane (no-op in this build).
   */
  void mwsfsvr_CheckSupply()
  {
  }

  /**
   * Address: 0x00AD9890 (FUN_00AD9890, _MWSFSVR_SetHnMwplySvrFlg)
   *
   * What it does:
   * Sets one playback "mwply server active" flag lane.
   */
  std::int32_t MWSFSVR_SetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    ply->mwplyServerFlag = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD98A0 (FUN_00AD98A0, _MWSFSVR_GetHnMwplySvrFlg)
   *
   * What it does:
   * Returns one playback "mwply server active" flag lane.
   */
  std::int32_t MWSFSVR_GetHnMwplySvrFlg(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return ply->mwplyServerFlag;
  }

  /**
   * Address: 0x00AD98B0 (FUN_00AD98B0, _MWSFSVR_SetHnSfdSvrFlg)
   *
   * What it does:
   * Sets one playback "sfd server active" flag lane.
   */
  std::int32_t MWSFSVR_SetHnSfdSvrFlg(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    ply->sfdServerFlag = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD9940 (FUN_00AD9940, _MWSFD_GetReqSvrBdrLib)
   *
   * What it does:
   * Returns global "request server bridge" control flag from MWSFD library
   * work lane.
   */
  std::int32_t MWSFD_GetReqSvrBdrLib()
  {
    return MWSFLIB_GetLibWorkPtr()->requestServerBridgeFlag;
  }

  /**
   * Address: 0x00ACB360 (FUN_00ACB360, _mwPlyChkSupply)
   *
   * What it does:
   * Terminates SFD supply when bound stream lane reaches status `3`.
   */
  std::int32_t mwPlyChkSupply(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(ply->handle);
    if (ply->adxStreamHandle != nullptr) {
      const std::int32_t status = MWSTM_GetStat(ply->adxStreamHandle);
      if (status == 3) {
        return sfply_TermSupply(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj)));
      }
      return status;
    }
    return 0;
  }

  /**
   * Address: 0x00AD83A0 (FUN_00AD83A0, _sfply_TermSupply)
   *
   * What it does:
   * Marks one SFD SFBUF transfer lane as terminated and latches term-request
   * flag in work-control runtime state.
   */
  std::int32_t sfply_TermSupply(const std::int32_t sfdHandleAddress)
  {
    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sfdHandleAddress))
    );
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleTermSupply);
    }

    struct SfplyTermSupplyRuntimeView
    {
      std::uint8_t mUnknown00[0x44]{};
      std::int32_t termRequestedFlag = 0; // +0x44
      std::uint8_t mUnknown48[0x1EFC]{};
      std::int32_t sfbufLaneIndex = 0; // +0x1F44
    };
    static_assert(
      offsetof(SfplyTermSupplyRuntimeView, termRequestedFlag) == 0x44,
      "SfplyTermSupplyRuntimeView::termRequestedFlag offset must be 0x44"
    );
    static_assert(
      offsetof(SfplyTermSupplyRuntimeView, sfbufLaneIndex) == 0x1F44,
      "SfplyTermSupplyRuntimeView::sfbufLaneIndex offset must be 0x1F44"
    );

    auto* const runtime = reinterpret_cast<SfplyTermSupplyRuntimeView*>(workctrlSubobj);
    const std::int32_t laneIndex = runtime->sfbufLaneIndex;
    if (SFBUF_GetTermFlg(sfdHandleAddress, laneIndex) != 1) {
      (void)SFBUF_SetTermFlg(sfdHandleAddress, laneIndex, 1);
      runtime->termRequestedFlag = 1;
    }
    return 0;
  }

  /**
   * Address: 0x00AD9340 (FUN_00AD9340, _mwsfsvr_DecodeServer)
   *
   * What it does:
   * Runs one global decode-server tick: acquires server gate, executes
   * per-playback server handles, clears server flag, and dispatches server
   * lifecycle callbacks.
   */
  std::int32_t mwsfsvr_DecodeServer()
  {
    if (mwsfd_init_flag != 1) {
      return 0;
    }

    auto* const libWork = MWSFLIB_GetLibWorkPtr();
    if (MWSFSVM_TestAndSet(&libWork->decodeServerSignal) != TRUE) {
      return 0;
    }

    mwsfsvr_ExecCbFnDecSvrTop();
    for (std::int32_t slotIndex = 0; slotIndex < moho::kMwsfdDecodeServerSlotCount; ++slotIndex) {
      auto* const playbackSlot = GetMwsfdDecodeServerPlaybackSlot(libWork, slotIndex);
      if (playbackSlot != nullptr) {
        (void)mwPlyExecSvrHndl(playbackSlot);
      }
    }

    MWSFSVR_SetMwsfdSvrFlg(0);

    const BOOL hasPendingSvrWait = (SFD_IsSvrWait() == 1) ? TRUE : FALSE;
    const BOOL decodePassFinished = (hasPendingSvrWait == FALSE) ? TRUE : FALSE;

    mwsfsvr_ExecCbFnDecSvrEnd();
    if (decodePassFinished == FALSE && MWSFD_GetReqSvrBdrLib() != 1) {
      mwsfsvr_ExecCbFnRestDecSvr();
    }

    return decodePassFinished;
  }

  /**
   * Address: 0x00AD95C0 (FUN_00AD95C0, _mwsfsvr_StartPlayback)
   */
  void mwsfsvr_StartPlayback(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (ply->streamState.state == 1) {
      const std::int32_t handleStatus = SFD_GetHnStat(ply->handle);
      const std::int32_t streamStatus = MWSST_GetStat(&ply->streamState);
      const std::int32_t pauseGateResult = ply->streamState.pauseGate->dispatchTable->queryStart(ply->streamState.pauseGate, 1);
      if (handleStatus == 3 && (streamStatus == 2 || pauseGateResult == 0)) {
        mwPlySfdStart(ply);
        if (ply->paused == 0) {
          mwPlyPause(ply, 0);
        }
        if (ply->concatPlayArmed == 1 && SFD_SetConcatPlay(ply->handle) != 0) {
          (void)MWSFSVM_Error(kMwsfdErrConcatPlayFailed);
        }
        if (ply->paused == 0) {
          (void)MWSST_Pause(&ply->streamState, 0);
        }
      }
      return;
    }

    if (SFD_GetHnStat(ply->handle) == 3) {
      mwPlySfdStart(ply);
      if (ply->paused == 0) {
        mwPlyPause(ply, 0);
      }
      if (ply->concatPlayArmed == 1 && SFD_SetConcatPlay(ply->handle) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrConcatPlayFailed);
      }
    }
  }

  /**
   * Address: 0x00AD96E0 (FUN_00AD96E0, _mwsfsvr_StartStream)
   *
   * What it does:
   * Starts one pending MWSTM lane for playback object after applying stored
   * filename/range request and arming SJ supply state.
   */
  [[maybe_unused]] std::int32_t mwsfsvr_StartStream(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSTM_GetStat(ply->adxStreamHandle) == 2) {
      return -1;
    }

    if (ply->sjSupplyHandle != nullptr) {
      ply->sjSupplyHandle->dispatchTable->onStart(ply->sjSupplyHandle);
    }

    MWSTM_SetFileRange(
      ply->adxStreamHandle,
      ply->fname,
      ply->pendingStartRequestReserved,
      ply->pendingStartRangeStart,
      ply->pendingStartRangeEnd
    );

    if (MWSTM_ReqStart(ply->adxStreamHandle) == -1) {
      ply->compoMode = 4;
      (void)MWSFLIB_SetErrCode(-102);
      (void)MWSFSVM_Error(kMwsfdErrStartStreamReqStartFailedFmt, ply->fname);
      ply->pendingStartRequestType = 0;
      return -1;
    }

    (void)MWSFCRE_SetSupplySj(ply);
    return 1;
  }

  /**
   * Address: 0x00ACB020 (FUN_00ACB020, _mwPlyStartMem)
   */
  std::int32_t mwPlyStartMem(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t bufferAddress,
    const std::int32_t bufferSize
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      return MWSFSVM_Error(kMwsfdErrStartMemInvalidHandle);
    }
    if (ply->fileType == kMwsfdFileTypeMpv) {
      return MWSFSVM_Error(kMwsfdErrStartMemUnsupportedMpv);
    }

    mwSfdStopDec(ply);
    sjmem_Destroy(ply->sjMemoryHandle);

    auto* const memoryHandle = SJMEM_Create(bufferAddress, bufferSize);
    ply->sjMemoryHandle = memoryHandle;
    ply->sjSupplyHandle = reinterpret_cast<moho::SofdecSjSupplyHandle*>(memoryHandle);
    ply->sjMemoryBufferAddress = bufferAddress;
    ply->sjMemoryBufferSize = bufferSize;

    mw_sfd_start_ex(ply);
    return MWSFCRE_SetSupplySj(ply);
  }

  /**
   * Address: 0x00ACB0C0 (FUN_00ACB0C0, _mwPlyStartSj)
   */
  std::int32_t mwPlyStartSj(moho::MwsfdPlaybackStateSubobj* const ply, moho::SofdecSjSupplyHandle* const supplyHandle)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      return MWSFSVM_Error(kMwsfdErrStartSjInvalidHandle);
    }

    mwSfdStopDec(ply);
    ply->sjSupplyHandle = supplyHandle;
    ply->sjSupplyMode = 2;
    ply->sjSupplyArg0 = 0;
    ply->sjSupplyArg1 = 0;
    ply->sjSupplyArg2 = 0;
    mw_sfd_start_ex(ply);
    return MWSFCRE_SetSupplySj(ply);
  }

  /**
   * Address: 0x00ACB1D0 (FUN_00ACB1D0, _mwply_Stop)
   *
   * What it does:
   * Stops SFD decode, unlinks seamless-stream lane, resets seamless-entry
   * counter lane, and stops the linked LSC handle.
   */
  void mwply_Stop(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      mwSfdStopDec(ply);
      mwPlyLinkStm(ply, 0);
      void* const lscHandle = ply->lscHandle;
      ply->seamlessEntryCount = 0;
      lsc_Stop(lscHandle);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrStopInvalidHandle);
  }

  /**
   * Address: 0x00ACB1C0 (FUN_00ACB1C0, _mwPlyStop)
   *
   * What it does:
   * Thunk wrapper to `mwply_Stop`.
   */
  void mwPlyStop(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    mwply_Stop(ply);
  }

  /**
   * Address: 0x00ADDB20 (FUN_00ADDB20, _MWSFSEE_StartFnameSub1)
   *
   * What it does:
   * Reserved filename-start hook lane (no-op in this build).
   */
  void MWSFSEE_StartFnameSub1()
  {
  }

  /**
   * Address: 0x00ADDB30 (FUN_00ADDB30, _MWSFSEE_StartFnameSub2)
   *
   * What it does:
   * Reserved filename-start hook lane (no-op in this build).
   */
  void MWSFSEE_StartFnameSub2()
  {
  }

  /**
   * Address: 0x00ACB3F0 (FUN_00ACB3F0, _MWSFPLY_ReqStartFname)
   *
   * What it does:
   * Requests one filename start with default full-range bounds.
   */
  std::int32_t MWSFPLY_ReqStartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    MWSFPLY_ReqStartFnameRange(ply, fname, 0, 0xFFFFF);
    return 0;
  }

  /**
   * Address: 0x00ACAEF0 (FUN_00ACAEF0, _mwSfdStartFnameSub)
   *
   * What it does:
   * Switches playback to ring-buffer supply lane, resets decode/start state,
   * then queues one filename start request.
   */
  void mwSfdStartFnameSub(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t /*rangeStart*/,
    const std::int32_t /*rangeEnd*/
  )
  {
    ply->sjSupplyHandle = reinterpret_cast<moho::SofdecSjSupplyHandle*>(ply->sjRingBufferHandle);
    mwSfdStopDec(ply);
    mw_sfd_start_ex(ply);
    (void)MWSFPLY_ReqStartFname(ply, fname);
    MWSFSEE_StartFnameSub1();
    MWSFSEE_StartFnameSub2();
  }

  /**
   * Address: 0x00ACAEA0 (FUN_00ACAEA0, _mwply_StartFname)
   *
   * What it does:
   * Validates one playback handle + filename, then forwards into internal
   * filename-start setup path.
   */
  void mwply_StartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      if (fname != nullptr) {
        mwSfdStartFnameSub(ply, fname, 0, -1);
      } else {
        (void)MWSFSVM_Error(kMwsfdErrStartFnameNullFileName);
      }
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrStartFnameInvalidHandle);
  }

  /**
   * Address: 0x00ACAE90 (FUN_00ACAE90, _mwPlyStartFname)
   *
   * What it does:
   * Public filename-start entry that forwards to `mwply_StartFname`.
   */
  void mwPlyStartFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    mwply_StartFname(ply, fname);
  }

  /**
   * Address: 0x00ACB390 (FUN_00ACB390, _MWSFPLY_RecordFname)
   */
  void MWSFPLY_RecordFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (static_cast<std::int32_t>(std::strlen(fname)) <= ply->fnameCapacity) {
      std::strcpy(ply->fname, fname);
      return;
    }

    (void)MWSFSVM_Error(kMwsfdErrFileNameTooLong);
    std::strncpy(ply->fname, fname, static_cast<std::size_t>(ply->fnameCapacity));
  }

  /**
   * Address: 0x00ACB410 (FUN_00ACB410, _MWSFPLY_ReqStartFnameRange)
   */
  void MWSFPLY_ReqStartFnameRange(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    MWSFPLY_RecordFname(ply, fname);
    ply->pendingStartRequestReserved = 0;
    ply->pendingStartRangeStart = rangeStart;
    ply->pendingStartRangeEnd = rangeEnd;
    ply->pendingStartRequestType = 1;
  }

  struct SofdecFeatureHeaderRuntimeView
  {
    std::int32_t state = 0; // +0x00
    std::uint8_t* elementInfoBuffer = nullptr; // +0x04
    std::int32_t version = 0; // +0x08
  };

  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, state) == 0x00,
    "SofdecFeatureHeaderRuntimeView::state offset must be 0x00"
  );
  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, elementInfoBuffer) == 0x04,
    "SofdecFeatureHeaderRuntimeView::elementInfoBuffer offset must be 0x04"
  );
  static_assert(
    offsetof(SofdecFeatureHeaderRuntimeView, version) == 0x08,
    "SofdecFeatureHeaderRuntimeView::version offset must be 0x08"
  );

  constexpr std::int32_t kSfhElementTableOffset = 0x180;
  constexpr std::int32_t kSfhElementStrideBytes = 0x40;
  constexpr std::int32_t kSfhElementTableEntryCount = 26;
  constexpr std::int32_t kSfhElementStreamIdOffset = 0x18;

  /**
   * Address: 0x00ADC9B0 (FUN_00ADC9B0, _isEffectiveObj)
   *
   * What it does:
   * Validates the feature-header state lane against the accepted range.
   */
  [[nodiscard]] bool SfhIsObjectStateEffective(const SofdecFeatureHeaderRuntimeView* const featureHeader) noexcept
  {
    return featureHeader->state < -1 || featureHeader->state > 1;
  }

  /**
   * Address: 0x00ADC980 (FUN_00ADC980, _isEffectiveVer)
   *
   * What it does:
   * Applies object-state validation and accepts parser versions `107` and
   * `>=110`.
   */
  [[nodiscard]] bool SfhIsVersionEffective(const SofdecFeatureHeaderRuntimeView* const featureHeader) noexcept
  {
    if (!SfhIsObjectStateEffective(featureHeader)) {
      return false;
    }

    const std::int32_t version = featureHeader->version;
    return version == 107 || version >= 110;
  }

  /**
   * Address: 0x00ADCA60 (FUN_00ADCA60, _searchStmId)
   *
   * What it does:
   * Scans the fixed feature-element table for one stream-id lane match.
   */
  [[nodiscard]] std::uint8_t* SfhSearchStreamId(std::uint8_t* const elementInfoBuffer, const std::int32_t streamId)
  {
    std::uint8_t* elementInfo = elementInfoBuffer + kSfhElementTableOffset;
    for (std::int32_t index = 0; index < kSfhElementTableEntryCount; ++index) {
      if (elementInfo[kSfhElementStreamIdOffset] == static_cast<std::uint8_t>(streamId)) {
        return elementInfo;
      }
      elementInfo += kSfhElementStrideBytes;
    }

    return nullptr;
  }

  /**
   * Address: 0x00ADD110 (FUN_00ADD110, _getElemInfPtr)
   *
   * What it does:
   * Returns matching feature-element info pointer when state/version lanes are
   * accepted; otherwise returns null.
   */
  [[nodiscard]]
  std::uint8_t* SfhGetElementInfoPtr(SofdecFeatureHeaderRuntimeView* const featureHeader, const std::int32_t streamId)
  {
    if (!SfhIsVersionEffective(featureHeader)) {
      return nullptr;
    }

    return SfhSearchStreamId(featureHeader->elementInfoBuffer, streamId);
  }

  struct LscStreamEntryRuntimeView
  {
    std::int32_t streamId = 0; // +0x00
    const char* fileName = nullptr; // +0x04
    std::int32_t fileNameChecksum = 0; // +0x08
    std::int32_t startOffset = 0; // +0x0C
    std::int32_t rangeStart = 0; // +0x10
    std::int32_t rangeEnd = 0; // +0x14
    std::int32_t streamStatus = 0; // +0x18
    std::int32_t readSector = 0; // +0x1C
  };

  static_assert(
    offsetof(LscStreamEntryRuntimeView, streamId) == 0x00, "LscStreamEntryRuntimeView::streamId offset must be 0x00"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, fileName) == 0x04, "LscStreamEntryRuntimeView::fileName offset must be 0x04"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, fileNameChecksum) == 0x08,
    "LscStreamEntryRuntimeView::fileNameChecksum offset must be 0x08"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, startOffset) == 0x0C, "LscStreamEntryRuntimeView::startOffset offset must be 0x0C"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, rangeStart) == 0x10, "LscStreamEntryRuntimeView::rangeStart offset must be 0x10"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, rangeEnd) == 0x14, "LscStreamEntryRuntimeView::rangeEnd offset must be 0x14"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, streamStatus) == 0x18,
    "LscStreamEntryRuntimeView::streamStatus offset must be 0x18"
  );
  static_assert(
    offsetof(LscStreamEntryRuntimeView, readSector) == 0x1C, "LscStreamEntryRuntimeView::readSector offset must be 0x1C"
  );
  static_assert(sizeof(LscStreamEntryRuntimeView) == 0x20, "LscStreamEntryRuntimeView size must be 0x20");

  struct LscRuntimeView
  {
    std::uint8_t used = 0; // +0x00
    std::int8_t status = 0; // +0x01
    std::uint8_t streamHandleActive = 0; // +0x02
    std::uint8_t loopEnabled = 0; // +0x03
    std::uint8_t paused = 0; // +0x04
    std::uint8_t mUnknown05_07[0x03]{}; // +0x05
    void* sjHandle = nullptr; // +0x08
    std::uint8_t mUnknown0C_13[0x08]{}; // +0x0C
    std::int32_t flowLimit = 0; // +0x14
    std::int32_t flowLimitMax = 0; // +0x18
    std::int32_t streamWriteCursor = 0; // +0x1C
    std::int32_t streamReadCursor = 0; // +0x20
    std::int32_t streamCount = 0; // +0x24
    void* streamHandle = nullptr; // +0x28
    std::int32_t activeStreamId = 0; // +0x2C
    std::int32_t mUnknown30 = 0; // +0x30
    std::int32_t activeReadSector = 0; // +0x34
    LscStreamEntryRuntimeView streamEntries[16]{}; // +0x38
  };

  static_assert(offsetof(LscRuntimeView, used) == 0x00, "LscRuntimeView::used offset must be 0x00");
  static_assert(offsetof(LscRuntimeView, status) == 0x01, "LscRuntimeView::status offset must be 0x01");
  static_assert(
    offsetof(LscRuntimeView, streamHandleActive) == 0x02, "LscRuntimeView::streamHandleActive offset must be 0x02"
  );
  static_assert(offsetof(LscRuntimeView, loopEnabled) == 0x03, "LscRuntimeView::loopEnabled offset must be 0x03");
  static_assert(offsetof(LscRuntimeView, paused) == 0x04, "LscRuntimeView::paused offset must be 0x04");
  static_assert(offsetof(LscRuntimeView, sjHandle) == 0x08, "LscRuntimeView::sjHandle offset must be 0x08");
  static_assert(offsetof(LscRuntimeView, flowLimit) == 0x14, "LscRuntimeView::flowLimit offset must be 0x14");
  static_assert(offsetof(LscRuntimeView, flowLimitMax) == 0x18, "LscRuntimeView::flowLimitMax offset must be 0x18");
  static_assert(
    offsetof(LscRuntimeView, streamWriteCursor) == 0x1C, "LscRuntimeView::streamWriteCursor offset must be 0x1C"
  );
  static_assert(
    offsetof(LscRuntimeView, streamReadCursor) == 0x20, "LscRuntimeView::streamReadCursor offset must be 0x20"
  );
  static_assert(offsetof(LscRuntimeView, streamCount) == 0x24, "LscRuntimeView::streamCount offset must be 0x24");
  static_assert(
    offsetof(LscRuntimeView, streamHandle) == 0x28, "LscRuntimeView::streamHandle offset must be 0x28"
  );
  static_assert(
    offsetof(LscRuntimeView, activeStreamId) == 0x2C, "LscRuntimeView::activeStreamId offset must be 0x2C"
  );
  static_assert(
    offsetof(LscRuntimeView, activeReadSector) == 0x34, "LscRuntimeView::activeReadSector offset must be 0x34"
  );
  static_assert(
    offsetof(LscRuntimeView, streamEntries) == 0x38, "LscRuntimeView::streamEntries offset must be 0x38"
  );
  static_assert(sizeof(LscRuntimeView) == 0x238, "LscRuntimeView size must be 0x238");

  constexpr std::int32_t kLscRingCapacity = 16;
  constexpr std::int32_t kLscObjectPoolCapacity = 64;
  constexpr std::int32_t kLscRangeEndAll = 0xFFFFF;
  constexpr std::int32_t kLscStatusStarted = 1;
  constexpr std::int32_t kLscStatusQueued = 2;
  constexpr std::int32_t kLscMaxStreamId = 0x7FFFFFFF;
  constexpr std::size_t kLscErrorMessageCapacity = 0x400;
  constexpr char kLscErrInvalidSjHandle[] = "E2005012801: Illigal parameter=sj (LSC_Create)\n";
  constexpr char kLscErrNoFreeLscInstance[] = "E2005012802: Not enough instance (LSC_Create)\n";
  constexpr char kLscErrLscNull[] = "E2005012803: Illigal parameter lsc=NULL";
  constexpr char kLscErrFileNameNullFmt[] = "E2005012804: Illigal parameter fname=%s\n";
  constexpr char kLscErrLscNullReset[] = "E2005012805: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullStart[] = "E2005012806: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullStop[] = "E2005012807: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullPause[] = "E2005012808: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetStat[] = "E2005012809: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetNumStm[] = "E2005012810: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullGetStmId[] = "E2005012811: Illigal parameter lsc=NULL";
  constexpr char kLscErrInvalidStmIndexFmt[] = "E2005012812: Illigal parameter no=%d\n";
  constexpr char kLscErrLscNullGetStmFname[] = "E2005012813: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundFnameFmt[] = "E2005012814: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullGetStmStat[] = "E2005012815: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundStatFmt[] = "E2005012816: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullGetStmRdSct[] = "E2005012817: Illigal parameter lsc=NULL";
  constexpr char kLscErrStreamNotFoundRdSctFmt[] = "E2005012818: Can not find stream ID =%d\n";
  constexpr char kLscErrLscNullSetFlowLimit[] = "E2005012819: Illigal parameter lsc=NULL";
  constexpr char kLscErrInvalidFlowLimitFmt[] = "E2005012820: Illigal parameter min_val=%d\n";
  constexpr char kLscErrLscNullGetFlowLimit[] = "E2005012821: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscNullSetLoopFlag[] = "E2005012822: Illigal parameter lsc=NULL";
  constexpr char kLscErrLscFilePointerNull[] = "E0007: lsc->fp=NULL\n";
  constexpr char kLscErrEntryFileMismatchFmt[] = "E0013: '%s' is different from entry file name.(LSC_ExecServer)\n";
  constexpr char kAdxtErrCannotEntryFilePrefix[] = "E4063001:Can't entry file ";
  constexpr char kAdxtErrEntryAfsCannotEntryPrefix[] = "E0071301 adxt_EntryAfs: can't entry ";
  constexpr char kAdxtErrSetSeamlessLpParameter[] = "E02080851 adxt_SetSeamlessLp: parameter error";
  constexpr char kAdxtErrStartSjParameter[] = "E02080812 adxt_StartSj: parameter error";
  constexpr char kAdxtErrStartFnameRangeLpParameter[] = "E02080852 adxt_StartFnameRangeLp: parameter error";
  constexpr char kAdxtErrStartAfsLpParameter[] = "E0405100 adxt_StartAfsLp: parameter error";
  constexpr char kAdxtErrGetNumFilesParameter[] = "E02080854 adxt_GetNumFiles: parameter error";
  constexpr char kAdxtErrResetEntryParameter[] = "E02080849 adxt_ResetEntry: parameter error";

  using LscErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* message);
  std::array<LscRuntimeView, kLscObjectPoolCapacity> gLscObjectPool{};
  std::array<char, kLscErrorMessageCapacity> gLscErrorMessage{};
  LscErrorCallback gLscErrorCallback = nullptr;
  std::int32_t gLscErrorObject = 0;
  std::int32_t gLscInitCount = 0;

  struct LscSjRuntimeInterfaceVtable
  {
    std::uint8_t mUnknown00_23[0x24]{};
    std::int32_t(__cdecl* getNumData)(void* sjHandle, std::int32_t lane) = nullptr; // +0x24
  };

  struct LscSjRuntimeHandleView
  {
    std::int32_t runtimeSlot = 0; // +0x00
  };

  static_assert(sizeof(gLscObjectPool) == 0x8E00, "LSC object pool size must be 0x8E00");
  static_assert(
    offsetof(LscSjRuntimeInterfaceVtable, getNumData) == 0x24,
    "LscSjRuntimeInterfaceVtable::getNumData offset must be 0x24"
  );
  static_assert(sizeof(LscSjRuntimeHandleView) == 0x04, "LscSjRuntimeHandleView size must be 0x04");

  using LscStatusChangeCallback = std::int32_t(__cdecl*)(std::int32_t callbackObjectPrimary, std::int32_t callbackObjectSecondary);
  LscStatusChangeCallback gLscStatusChangeCallback = nullptr;
  std::int32_t gLscStatusChangeObjectPrimary = 0;
  std::int32_t gLscStatusChangeObjectSecondary = 0;

  [[nodiscard]] LscRuntimeView* AsLscRuntimeView(void* const lscHandle) noexcept
  {
    return reinterpret_cast<LscRuntimeView*>(lscHandle);
  }

  [[nodiscard]] constexpr std::int32_t LscWrapRingIndex(std::int32_t value) noexcept
  {
    value %= kLscRingCapacity;
    if (value < 0) {
      value += kLscRingCapacity;
    }
    return value;
  }

  [[nodiscard]] std::int32_t LscFindStreamEntryIndex(const LscRuntimeView* const lsc, const std::int32_t streamId) noexcept
  {
    for (std::int32_t i = 0; i < kLscRingCapacity; ++i) {
      if (lsc->streamEntries[i].streamId == streamId) {
        return i;
      }
    }
    return -1;
  }

  [[nodiscard]] std::int32_t LscComputeFileNameChecksum(const char* const fileName) noexcept
  {
    std::int32_t checksum = 0;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(fileName); *cursor != 0; ++cursor) {
      checksum += static_cast<std::int32_t>(*cursor);
    }
    return checksum;
  }

  [[nodiscard]] std::int32_t LscGetSjNumData(void* const sjHandle, const std::int32_t lane)
  {
    const auto* const sjRuntime = reinterpret_cast<const LscSjRuntimeHandleView*>(sjHandle);
    const auto* const runtimeInterface =
      reinterpret_cast<const LscSjRuntimeInterfaceVtable*>(SjAddressToPointer(sjRuntime->runtimeSlot));
    return runtimeInterface->getNumData(sjHandle, lane);
  }

  [[nodiscard]] LscStreamEntryRuntimeView& LscCurrentStreamEntry(LscRuntimeView* const lsc) noexcept
  {
    return lsc->streamEntries[LscWrapRingIndex(lsc->streamReadCursor)];
  }

  /**
   * Address: 0x00B08A60 (FUN_00B08A60, _lsc_Alloc)
   *
   * What it does:
   * Returns first free LSC object lane from the global fixed pool.
   */
  [[maybe_unused]] [[nodiscard]] LscRuntimeView* lsc_Alloc() noexcept
  {
    for (LscRuntimeView& lscObject : gLscObjectPool) {
      if (lscObject.used == 0) {
        return &lscObject;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B08A90 (FUN_00B08A90, _LSC_Create)
   *
   * What it does:
   * Allocates one LSC object from the global pool and binds it to an SJ
   * provider handle for seamless stream scheduling.
   */
  [[maybe_unused]] void* LSC_Create(void* const sjHandle)
  {
    if (sjHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrInvalidSjHandle);
      return nullptr;
    }

    SJCRS_Lock();
    LscRuntimeView* const lsc = lsc_Alloc();
    if (lsc == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrNoFreeLscInstance);
      SJCRS_Unlock();
      return nullptr;
    }

    lsc->sjHandle = sjHandle;
    lsc->status = 0;
    lsc->flowLimitMax = LscGetSjNumData(sjHandle, 1) + LscGetSjNumData(sjHandle, 0);
    lsc->flowLimit = (lsc->flowLimitMax * 8) / 10;

    for (LscStreamEntryRuntimeView& entry : lsc->streamEntries) {
      entry.streamStatus = 0;
    }

    lsc->used = 1;
    SJCRS_Unlock();
    return lsc;
  }

  /**
   * Address: 0x00B09820 (FUN_00B09820, _LSC_EntryErrFunc)
   *
   * What it does:
   * Registers or clears the LSC error callback lane and callback object.
   */
  [[maybe_unused]] std::int32_t LSC_EntryErrFunc(const LscErrorCallback callback, const std::int32_t callbackObject)
  {
    if (callback != nullptr) {
      gLscErrorCallback = callback;
      gLscErrorObject = callbackObject;
      return callbackObject;
    }

    gLscErrorCallback = nullptr;
    gLscErrorObject = 0;
    return 0;
  }

  /**
   * Address: 0x00B09850 (FUN_00B09850, _LSC_CallErrFunc_)
   *
   * What it does:
   * Formats one LSC error message into the global message buffer and calls the
   * registered error callback when present.
   */
  [[maybe_unused]] std::int32_t LSC_CallErrFunc_(const char* const format, ...)
  {
    va_list argumentList{};
    va_start(argumentList, format);
    std::vsprintf(gLscErrorMessage.data(), format, argumentList);
    va_end(argumentList);

    if (gLscErrorCallback == nullptr) {
      return 0;
    }
    return gLscErrorCallback(gLscErrorObject, gLscErrorMessage.data());
  }

  /**
   * Address: 0x00B09890 (FUN_00B09890, _lsc_EntrySvrInt)
   *
   * What it does:
   * Legacy server-interface entry hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void lsc_EntrySvrInt()
  {
  }

  /**
   * Address: 0x00B098A0 (FUN_00B098A0, _lsc_DeleteSvrInt)
   *
   * What it does:
   * Legacy server-interface delete hook for this build; no runtime behavior.
   */
  [[maybe_unused]] void lsc_DeleteSvrInt()
  {
  }

  /**
   * Address: 0x00B098B0 (FUN_00B098B0, _LSC_Init)
   *
   * What it does:
   * Initializes shared LSC runtime state on first entry and increments init
   * reference count under SJ critical-section lock.
   */
  [[maybe_unused]] void LSC_Init()
  {
    SJCRS_Lock();
    if (gLscInitCount == 0) {
      std::memset(gLscObjectPool.data(), 0, sizeof(gLscObjectPool));
      (void)LSC_EntryErrFunc(nullptr, 0);
    }

    ++gLscInitCount;
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09910 (FUN_00B09910, _LSC_Finish)
   *
   * What it does:
   * Decrements LSC init reference count; on final release destroys active pool
   * objects, clears pool memory, and clears error callback state.
   */
  [[maybe_unused]] std::int32_t LSC_Finish()
  {
    const std::int32_t result = --gLscInitCount;
    if (gLscInitCount != 0) {
      return result;
    }

    for (LscRuntimeView& lscObject : gLscObjectPool) {
      if (lscObject.used == 1) {
        LSC_Destroy(&lscObject);
      }
    }

    std::memset(gLscObjectPool.data(), 0, sizeof(gLscObjectPool));
    return LSC_EntryErrFunc(nullptr, 0);
  }

  /**
   * Address: 0x00B08B70 (FUN_00B08B70, _LSC_SetStmHndl)
   *
   * What it does:
   * Stores one ADX stream-handle lane in the LSC runtime object.
   */
  void* LSC_SetStmHndl(void* const lscHandle, void* const streamHandle)
  {
    AsLscRuntimeView(lscHandle)->streamHandle = streamHandle;
    return streamHandle;
  }

  /**
   * Address: 0x00B08B80 (FUN_00B08B80, _LSC_EntryFname)
   *
   * What it does:
   * Queues one filename with full-range playback bounds.
   */
  std::int32_t LSC_EntryFname(void* const lscHandle, const char* const fileName)
  {
    return lsc_EntryFileRange(lscHandle, fileName, 0, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B08BA0 (FUN_00B08BA0, _lsc_EntryFileRange)
   *
   * What it does:
   * Enqueues one seamless-stream entry lane and returns its generated stream ID.
   */
  std::int32_t lsc_EntryFileRange(
    void* const lscHandle,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNull);
      return -1;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamCount >= kLscRingCapacity) {
      return -1;
    }

    if (fileName == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrFileNameNullFmt, fileName);
      return -1;
    }

    const std::int32_t previousSlot = LscWrapRingIndex(lsc->streamWriteCursor + (kLscRingCapacity - 1));
    const std::int32_t previousStreamId = lsc->streamEntries[previousSlot].streamId;
    const std::int32_t streamId = (previousStreamId == kLscMaxStreamId) ? 0 : previousStreamId + 1;

    LscStreamEntryRuntimeView& entry = lsc->streamEntries[LscWrapRingIndex(lsc->streamWriteCursor)];
    entry.streamId = streamId;
    entry.fileName = fileName;
    entry.fileNameChecksum = LscComputeFileNameChecksum(fileName);
    entry.startOffset = startOffset;
    entry.rangeStart = rangeStart;
    entry.rangeEnd = rangeEnd;
    entry.streamStatus = 0;
    entry.readSector = 0;

    ++lsc->streamCount;
    lsc->streamWriteCursor = LscWrapRingIndex(lsc->streamWriteCursor + 1);
    if (lsc->status == kLscStatusStarted) {
      lsc->status = kLscStatusQueued;
    }
    return streamId;
  }

  /**
   * Address: 0x00B08C90 (FUN_00B08C90, _LSC_ResetEntry)
   *
   * What it does:
   * Clears stream queue cursors/count when LSC is not in started state.
   */
  void LSC_ResetEntry(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullReset);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status == 0) {
      lsc->streamWriteCursor = 0;
      lsc->streamReadCursor = 0;
      lsc->streamCount = 0;
    }
  }

  /**
   * Address: 0x00B08CC0 (FUN_00B08CC0, _lsc_Start)
   *
   * What it does:
   * Starts LSC playback state and upgrades status when queued streams exist.
   */
  void lsc_Start(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullStart);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status != 0) {
      lsc_Stop(lscHandle);
    }

    lsc->status = static_cast<std::int8_t>((lsc->streamCount > 0) ? kLscStatusQueued : kLscStatusStarted);
  }

  /**
   * Address: 0x00B08D00 (FUN_00B08D00, _lsc_Stop)
   *
   * What it does:
   * Stops active LSC stream state, resets queue cursors, and clears active
   * stream-tracking lanes.
   */
  void lsc_Stop(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullStop);
      return;
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->status == 0) {
      return;
    }

    void* const streamHandle = lsc->streamHandle;
    lsc->status = 0;
    if (streamHandle != nullptr && lsc->streamHandleActive == 1) {
      ADXSTM_Stop(streamHandle);
      lsc->streamHandleActive = 0;
    }

    lsc->activeStreamId = 0;
    LSC_ResetEntry(lscHandle);
    lsc->activeReadSector = 0;
  }

  /**
   * Address: 0x00B08D50 (FUN_00B08D50, _lsc_Pause)
   *
   * What it does:
   * Updates one pause-byte lane in the LSC runtime.
   */
  std::int32_t lsc_Pause(void* const lscHandle, const std::int32_t paused)
  {
    if (lscHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscNullPause);
    }

    AsLscRuntimeView(lscHandle)->paused = static_cast<std::uint8_t>(paused == 1);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(lscHandle));
  }

  /**
   * Address: 0x00B08B50 (FUN_00B08B50, _LSC_Destroy)
   *
   * What it does:
   * Stops one LSC handle and clears its full runtime lane.
   */
  void LSC_Destroy(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      return;
    }

    lsc_Stop(lscHandle);
    std::memset(lscHandle, 0, sizeof(LscRuntimeView));
  }

  /**
   * Address: 0x00B08DB0 (FUN_00B08DB0, _LSC_GetStat)
   *
   * What it does:
   * Returns current LSC status lane.
   */
  std::int32_t LSC_GetStat(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStat);
      return -1;
    }

    return static_cast<std::int32_t>(AsLscRuntimeView(lscHandle)->status);
  }

  /**
   * Address: 0x00B08DD0 (FUN_00B08DD0, _LSC_GetNumStm)
   *
   * What it does:
   * Returns queued seamless-stream count.
   */
  std::int32_t LSC_GetNumStm(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetNumStm);
      return -1;
    }

    return AsLscRuntimeView(lscHandle)->streamCount;
  }

  /**
   * Address: 0x00B08DF0 (FUN_00B08DF0, _lsc_GetStmId)
   *
   * What it does:
   * Returns stream ID by queue index relative to the current read cursor.
   */
  std::int32_t lsc_GetStmId(void* const lscHandle, const std::int32_t streamIndex)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmId);
      return -1;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (streamIndex < 0 || streamIndex >= lsc->streamCount) {
      (void)LSC_CallErrFunc_(kLscErrInvalidStmIndexFmt, streamIndex);
      return -1;
    }

    const std::int32_t slot = LscWrapRingIndex(lsc->streamReadCursor + streamIndex);
    return lsc->streamEntries[slot].streamId;
  }

  /**
   * Address: 0x00B08E50 (FUN_00B08E50, _lsc_GetStmFname)
   *
   * What it does:
   * Resolves file name lane by stream ID.
   */
  const char* lsc_GetStmFname(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmFname);
      return nullptr;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundFnameFmt, streamId);
      return nullptr;
    }

    return lsc->streamEntries[index].fileName;
  }

  /**
   * Address: 0x00B08EA0 (FUN_00B08EA0, _lsc_GetStmStat)
   *
   * What it does:
   * Resolves stream-status lane by stream ID.
   */
  std::int32_t lsc_GetStmStat(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmStat);
      return -1;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundStatFmt, streamId);
      return -1;
    }

    return lsc->streamEntries[index].streamStatus;
  }

  /**
   * Address: 0x00B08F00 (FUN_00B08F00, _lsc_GetStmRdSct)
   *
   * What it does:
   * Resolves current read-sector lane by stream ID.
   */
  std::int32_t lsc_GetStmRdSct(void* const lscHandle, const std::int32_t streamId)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetStmRdSct);
      return 0;
    }

    const LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    const std::int32_t index = LscFindStreamEntryIndex(lsc, streamId);
    if (index < 0) {
      (void)LSC_CallErrFunc_(kLscErrStreamNotFoundRdSctFmt, streamId);
      return 0;
    }

    return lsc->streamEntries[index].readSector;
  }

  /**
   * Address: 0x00B08F50 (FUN_00B08F50, _lsc_SetFlowLimit)
   *
   * What it does:
   * Updates per-LSC minimum flow limit when inside valid range.
   */
  std::int32_t lsc_SetFlowLimit(void* const lscHandle, const std::int32_t flowLimit)
  {
    if (lscHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscNullSetFlowLimit);
    }

    LscRuntimeView* const lsc = AsLscRuntimeView(lscHandle);
    if (flowLimit < 0 || flowLimit > lsc->flowLimitMax) {
      return LSC_CallErrFunc_(kLscErrInvalidFlowLimitFmt, flowLimit);
    }

    lsc->flowLimit = flowLimit;
    return flowLimit;
  }

  /**
   * Address: 0x00B08F90 (FUN_00B08F90, _lsc_GetFlowLimit)
   *
   * What it does:
   * Returns current LSC flow-limit lane.
   */
  std::int32_t lsc_GetFlowLimit(void* const lscHandle)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullGetFlowLimit);
      return -1;
    }

    return AsLscRuntimeView(lscHandle)->flowLimit;
  }

  /**
   * Address: 0x00B09010 (FUN_00B09010, _LSC_SetLpFlg)
   *
   * What it does:
   * Stores one seamless-loop enabled flag byte in the LSC runtime.
   */
  void LSC_SetLpFlg(void* const lscHandle, const std::int32_t enabled)
  {
    if (lscHandle == nullptr) {
      (void)LSC_CallErrFunc_(kLscErrLscNullSetLoopFlag);
      return;
    }

    AsLscRuntimeView(lscHandle)->loopEnabled = static_cast<std::uint8_t>(enabled);
  }

  /**
   * Address: 0x00B08FB0 (FUN_00B08FB0, _LSC_EntryChgStatFunc)
   *
   * What it does:
   * Registers or clears one LSC status-change callback lane.
   */
  std::int32_t LSC_EntryChgStatFunc(
    LscStatusChangeCallback callback,
    const std::int32_t callbackObjectPrimary,
    const std::int32_t callbackObjectSecondary
  )
  {
    if (callback == nullptr) {
      gLscStatusChangeCallback = nullptr;
      gLscStatusChangeObjectPrimary = 0;
      gLscStatusChangeObjectSecondary = 0;
      return 0;
    }

    gLscStatusChangeCallback = callback;
    gLscStatusChangeObjectSecondary = callbackObjectSecondary;
    gLscStatusChangeObjectPrimary = callbackObjectPrimary;
    return callbackObjectPrimary;
  }

  /**
   * Address: 0x00B08FF0 (FUN_00B08FF0, _LSC_CallStatFunc)
   *
   * What it does:
   * Calls registered LSC status callback with stored callback objects.
   */
  std::int32_t LSC_CallStatFunc()
  {
    if (gLscStatusChangeCallback == nullptr) {
      return 0;
    }

    return gLscStatusChangeCallback(gLscStatusChangeObjectPrimary, gLscStatusChangeObjectSecondary);
  }

  /**
   * Address: 0x00B17810 (FUN_00B17810, _LSC_LockCrs)
   *
   * What it does:
   * LSC lock wrapper over the shared Sofdec critical section.
   */
  [[maybe_unused]] void LSC_LockCrs()
  {
    SJCRS_Lock();
  }

  /**
   * Address: 0x00B17820 (FUN_00B17820, _LSC_UnlockCrs)
   *
   * What it does:
   * LSC unlock wrapper over the shared Sofdec critical section.
   */
  [[maybe_unused]] void LSC_UnlockCrs()
  {
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B17830 (FUN_00B17830, _lsc_StatWait)
   *
   * What it does:
   * Binds the current queued entry to the ADX stream and starts non-blocking
   * playback when queue data is available.
   */
  [[maybe_unused]] std::int32_t lsc_StatWait(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);

    if (lsc->streamCount <= 0) {
      return lsc->streamCount;
    }

    ADXSTM_StopNw(lsc->streamHandle);
    ADXSTM_ReleaseFileNw(lsc->streamHandle);

    const std::int32_t checksum = LscComputeFileNameChecksum(entry.fileName);
    if (checksum != entry.fileNameChecksum) {
      return LSC_CallErrFunc_(kLscErrEntryFileMismatchFmt, entry.fileName);
    }

    ADXSTM_BindFileNw(lsc->streamHandle, entry.fileName, entry.startOffset, entry.rangeStart, entry.rangeEnd);
    ADXSTM_SetEos(lsc->streamHandle, entry.rangeEnd);
    lsc->activeStreamId = entry.rangeEnd;
    entry.readSector = 0;

    lsc->streamHandleActive = 0;
    ADXSTM_SetBufSize(lsc->streamHandle, lsc->flowLimit, lsc->flowLimitMax);
    ADXSTM_Seek(lsc->streamHandle, 0);
    ADXSTM_Start(lsc->streamHandle);
    lsc->streamHandleActive = 1;

    entry.streamStatus = 1;
    return 1;
  }

  /**
   * Address: 0x00B17910 (FUN_00B17910, _lsc_StatRead)
   *
   * What it does:
   * Polls ADX stream state for the current entry and updates queued stream
   * status/read-sector lanes.
   */
  [[maybe_unused]] std::int32_t lsc_StatRead(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamHandle == nullptr) {
      return LSC_CallErrFunc_(kLscErrLscFilePointerNull);
    }

    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);
    const std::int32_t statClass = ADXSTM_GetStat(lsc->streamHandle) - 2;
    if (statClass == 0) {
      entry.readSector = ADXSTM_Tell(lsc->streamHandle);
      return entry.readSector;
    }

    if (statClass == 1) {
      entry.streamStatus = 2;
      entry.readSector = lsc->activeStreamId;
      return 0;
    }

    if (statClass == 2) {
      lsc->status = 3;
      return 0;
    }

    return statClass - 2;
  }

  /**
   * Address: 0x00B17980 (FUN_00B17980, _lsc_StatEnd)
   *
   * What it does:
   * Finalizes current stream entry, advances the read cursor, triggers status
   * callback on queue depletion, and re-enqueues looped entries.
   */
  [[maybe_unused]] std::int32_t lsc_StatEnd(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    if (lsc->streamHandle == nullptr) {
      return 0;
    }

    const bool loopEnabled = (lsc->loopEnabled == 1);
    const LscStreamEntryRuntimeView entrySnapshot = loopEnabled ? LscCurrentStreamEntry(lsc) : LscStreamEntryRuntimeView{};

    --lsc->streamCount;
    std::int32_t result = lsc->streamCount;
    lsc->streamReadCursor = LscWrapRingIndex(lsc->streamReadCursor + 1);

    if (result <= 0) {
      result = LSC_CallStatFunc();
      lsc->status = 1;
    }

    if (loopEnabled) {
      return lsc_EntryFileRange(
        lscHandle,
        entrySnapshot.fileName,
        entrySnapshot.startOffset,
        entrySnapshot.rangeStart,
        entrySnapshot.rangeEnd
      );
    }

    return result;
  }

  /**
   * Address: 0x00B17A10 (FUN_00B17A10, _lsc_ExecHndl)
   *
   * What it does:
   * Runs one LSC handle tick lane: read poll, end handling, then wait/start.
   */
  [[maybe_unused]] std::int32_t lsc_ExecHndl(void* const lscHandle)
  {
    auto* const lsc = AsLscRuntimeView(lscHandle);
    std::int32_t result = 1;

    if (lsc->paused == 1 || lsc->status != 2 || lsc->streamCount <= 0) {
      return result;
    }

    LscStreamEntryRuntimeView& entry = LscCurrentStreamEntry(lsc);
    if (entry.streamStatus == 1) {
      (void)lsc_StatRead(lscHandle);
    }

    if (entry.streamStatus == 2) {
      (void)lsc_StatEnd(lscHandle);
    }

    result = entry.streamStatus;
    if (result == 0) {
      return lsc_StatWait(lscHandle);
    }

    return result;
  }

  /**
   * Address: 0x00B08D80 (FUN_00B08D80, _lsc_ExecServer)
   *
   * What it does:
   * Ticks all active LSC object lanes in the fixed object pool.
   */
  [[maybe_unused]] std::int32_t lsc_ExecServer()
  {
    std::int32_t result = 0;
    for (LscRuntimeView& lsc : gLscObjectPool) {
      if (lsc.used == 1) {
        result = lsc_ExecHndl(&lsc);
      }
    }
    return result;
  }

  /**
   * Address: 0x00B193D0 (FUN_00B193D0, _LSC_ExecServer)
   *
   * What it does:
   * Public wrapper for the LSC server execution tick.
   */
  [[maybe_unused]] std::int32_t LSC_ExecServer()
  {
    return lsc_ExecServer();
  }

  /**
   * Address: 0x00B0A350 (FUN_00B0A350, _adxini_lscerr_cbfn)
   *
   * What it does:
   * Bridges LSC error callback messages into the shared ADX error reporter.
   */
  [[maybe_unused]] void adxini_lscerr_cbfn(const std::int32_t /*errorObject*/, const char* const message)
  {
    (void)ADXERR_CallErrFunc1_(message);
  }

  /**
   * Address: 0x00B18FD0 (FUN_00B18FD0, _adxt_EntryFnameRange)
   *
   * What it does:
   * Enqueues one filename range into ADXT seamless LSC queue.
   */
  [[maybe_unused]] std::int32_t adxt_EntryFnameRange(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t result = lsc_EntryFileRange(runtime->SeamlessLscHandle(), fileName, 0, rangeStart, rangeEnd);
    if (result < 0) {
      return ADXERR_CallErrFunc2_(kAdxtErrCannotEntryFilePrefix, fileName);
    }
    return result;
  }

  /**
   * Address: 0x00B18F80 (FUN_00B18F80, _adxt_EntryFname)
   *
   * What it does:
   * Enqueues one filename with full-range seamless playback bounds.
   */
  [[maybe_unused]] std::int32_t adxt_EntryFname(void* const adxtRuntime, const char* const fileName)
  {
    return adxt_EntryFnameRange(adxtRuntime, fileName, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B19040 (FUN_00B19040, _adxt_EntryAfs)
   *
   * What it does:
   * Resolves one AFS entry into filename/range and enqueues it into seamless
   * LSC queue.
   */
  [[maybe_unused]] std::int32_t adxt_EntryAfs(
    void* const adxtRuntime,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    std::int32_t startOffset = 0;
    std::int32_t rangeStart = 0;
    std::int32_t rangeEnd = 0;
    if (ADXF_GetFnameRangeEx(
          afsHandle,
          fileIndex,
          runtime->SeamlessAfsNameBuffer(),
          &startOffset,
          &rangeStart,
          &rangeEnd
        ) == 0) {
      const char* const fileName = ADXF_GetFnameFromPt(afsHandle);
      return lsc_EntryFileRange(runtime->SeamlessLscHandle(), fileName, startOffset, rangeStart, rangeEnd);
    }

    char entryIdText[16]{};
    ADXERR_ItoA2(afsHandle, fileIndex, entryIdText, static_cast<std::int32_t>(sizeof(entryIdText)));
    return ADXERR_CallErrFunc2_(kAdxtErrEntryAfsCannotEntryPrefix, entryIdText);
  }

  /**
   * Address: 0x00B190F0 (FUN_00B190F0, _adxt_StartSeamless)
   *
   * What it does:
   * Starts ADXT seamless path by resetting non-LSC playback, preparing SJ input
   * path, and starting LSC queue playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartSeamless(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    void* const lscHandle = runtime->SeamlessLscHandle();

    ADXT_StopWithoutLsc(runtime);
    ADXCRS_Lock();
    adxt_start_sj(runtime, runtime->sourceRingHandle);
    if (runtime->streamJoinInputHandle != nullptr) {
      runtime->streamJoinInputHandle->OnSeamlessStart();
    }

    const std::int32_t flowLimit = static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint()) << 11;
    runtime->mUnknown02 = 4;
    (void)lsc_SetFlowLimit(lscHandle, flowLimit);
    ADXCRS_Unlock();

    lsc_Start(lscHandle);
    return ADXT_SetLnkSw(runtime, 1);
  }

  /**
   * Address: 0x00B0EA70 (FUN_00B0EA70, _ADXT_GetLnkSw)
   *
   * What it does:
   * Internal ADXT link-switch lane: stores requested switch byte in runtime
   * state and forwards it to SJD lane when available.
   */
  std::int32_t adxt_SetLnkSwInternal(void* const adxtRuntime, const std::int32_t enabled)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    runtime->linkSwitchRequested = static_cast<std::uint8_t>(enabled);
    if (runtime->sjdHandle != 0) {
      return ADXSJD_SetLnkSw(runtime->sjdHandle, enabled);
    }
    return runtime->sjdHandle;
  }

  /**
   * Address: 0x00B0EA50 (FUN_00B0EA50, _ADXT_SetLnkSw)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT link-switch update lane.
   */
  std::int32_t ADXT_SetLnkSw(void* const adxtRuntime, const std::int32_t enabled)
  {
    ADXCRS_Enter();
    const std::int32_t result = adxt_SetLnkSwInternal(adxtRuntime, enabled);
    ADXCRS_Leave();
    return result;
  }

  /**
   * Address: 0x00B0CAE0 (FUN_00B0CAE0, _ADXT_GetEosSct)
   *
   * What it does:
   * Returns current ADXT stream end-sector override used by `_adxt_start_stm`.
   */
  [[maybe_unused]] std::int32_t ADXT_GetEosSct()
  {
    return gAdxtStreamEosSector;
  }

  /**
   * Address: 0x00B0CAF0 (FUN_00B0CAF0, _ADXT_SetEosSct)
   *
   * What it does:
   * Updates ADXT stream end-sector override used by `_adxt_start_stm`.
   */
  [[maybe_unused]] std::int32_t ADXT_SetEosSct(const std::int32_t eosSector)
  {
    gAdxtStreamEosSector = eosSector;
    return eosSector;
  }

  /**
   * Address: 0x00B0D090 (FUN_00B0D090, _adxt_start_sj)
   *
   * What it does:
   * Starts ADXT decode from one SJ input object, resets playback timing lanes,
   * and starts optional channel-expansion lane when present.
   */
  std::int32_t adxt_start_sj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const std::int32_t maxChannels = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < maxChannels; ++lane) {
      runtime->SourceChannelRingLane(lane)->Destroy();
    }

    ADXSJD_SetInSj(runtime->sjdHandle, sourceJoinHandle);
    runtime->streamJoinInputHandle = static_cast<AdxtStreamJoinHandle*>(sourceJoinHandle);

    const std::int32_t startResult = ADXSJD_Start(runtime->sjdHandle);
    runtime->mUnknown01 = 1;
    runtime->StreamStartScratchWord() = 0;
    runtime->StreamStartLatchByte() = 0;
    runtime->StreamEndSector() = 0x7FFFFFFF;
    runtime->StreamLoopStartSample() = -1;
    runtime->PlaybackTimeBaseFrames() = 0;
    runtime->PlaybackTimeDeltaFrames() = 0;
    runtime->PlaybackTimeVsyncAnchor() = gAdxtVsyncCount;
    runtime->StreamDecodeWindowState() = 0;

    if (runtime->channelExpandHandle != nullptr) {
      return ADXAMP_Start(runtime->channelExpandHandle);
    }

    return startResult;
  }

  /**
   * Address: 0x00B0D130 (FUN_00B0D130, _adxt_start_stm)
   *
   * What it does:
   * Rebinds ADXT stream file range and starts stream + SJ decode chain for one
   * runtime object.
   */
  [[maybe_unused]] std::int32_t adxt_start_stm(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t startOffset,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    ADXSTM_SetBufSize(
      runtime->streamHandle,
      static_cast<std::int32_t>(runtime->SeamlessFlowSectorHint()) << 11,
      static_cast<std::int32_t>(runtime->StreamBufferSectorLimitHint()) << 11
    );
    ADXSTM_SetEos(runtime->streamHandle, gAdxtStreamEosSector);
    ADXSTM_EntryEosFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime->streamHandle)),
      0,
      0
    );
    ADXSTM_Seek(runtime->streamHandle, 0);
    ADXSTM_StopNw(runtime->streamHandle);
    ADXSTM_ReleaseFileNw(runtime->streamHandle);
    ADXSTM_BindFileNw(runtime->streamHandle, fileName, startOffset, rangeStart, rangeEnd);
    ADXSTM_Start(runtime->streamHandle);
    return adxt_start_sj(runtime, runtime->sourceRingHandle);
  }

  /**
   * Address: 0x00B0D1C0 (FUN_00B0D1C0, _ADXT_StartSj)
   *
   * What it does:
   * Lock-guarded wrapper for ADXT SJ-start lane.
   */
  [[maybe_unused]] void ADXT_StartSj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    ADXCRS_Enter();
    adxt_StartSj(adxtRuntime, sourceJoinHandle);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D1E0 (FUN_00B0D1E0, _adxt_StartSj)
   *
   * What it does:
   * Validates runtime + SJ handle, stops current ADXT lane, starts SJ input
   * path, sets ADXT mode byte to SJ mode (`3`), and enables link-switch lane.
   */
  [[maybe_unused]] void adxt_StartSj(void* const adxtRuntime, void* const sourceJoinHandle)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr || sourceJoinHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrStartSjParameter);
      return;
    }

    adxt_Stop(runtime);
    ADXCRS_Lock();
    adxt_start_sj(runtime, sourceJoinHandle);
    runtime->mUnknown02 = 3;
    (void)adxt_SetLnkSwInternal(runtime, 1);
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0D230 (FUN_00B0D230, _ADXT_StopWithoutLsc)
   *
   * What it does:
   * Guard wrapper for the internal non-LSC ADXT stop lane.
   */
  void ADXT_StopWithoutLsc(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_StopWithoutLsc(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D250 (FUN_00B0D250, _adxt_StopWithoutLsc)
   *
   * What it does:
   * Stops ADXT decode/transfer lanes while keeping seamless LSC queue owner
   * alive.
   */
  void adxt_StopWithoutLsc(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    ADXCRS_Lock();
    j__ADXRNA_Stop(runtime->rnaHandle);
    j__ADXRNA_SetTransSw(runtime->rnaHandle, 0);
    j__ADXRNA_SetPlaySw(runtime->rnaHandle, 0);
    ADXSJD_Stop(runtime->sjdHandle);

    if (runtime->mUnknown02 == 2 && runtime->streamJoinInputHandle != nullptr) {
      AdxtStreamJoinHandle* const streamJoinHandle = runtime->streamJoinInputHandle;
      runtime->streamJoinInputHandle = nullptr;
      streamJoinHandle->Reserved0C();
    }

    if (runtime->channelExpandHandle != nullptr) {
      ADXAMP_Stop(runtime->channelExpandHandle);
    }

    runtime->streamJoinInputHandle = nullptr;
    runtime->mUnknown01 = 0;
    runtime->linkSwitchActive = 0;
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0D2D0 (FUN_00B0D2D0, _ADXT_Stop)
   *
   * What it does:
   * Guard wrapper for the ADXT stop lane.
   */
  void ADXT_Stop(void* const adxtRuntime)
  {
    ADXCRS_Enter();
    adxt_Stop(adxtRuntime);
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0D2F0 (FUN_00B0D2F0, _adxt_Stop)
   *
   * What it does:
   * Stops one ADXT runtime lane, including optional codec-side stop callbacks,
   * seamless LSC lane stop, and shared non-LSC stop cleanup.
   */
  void adxt_Stop(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtStopParameterErrorMessage);
      return;
    }

    if (mpastopfunc != nullptr) {
      ADXSJD_Stop(runtime->sjdHandle);
      mpastopfunc(runtime);
    }
    if (m2astopfunc != nullptr) {
      ADXSJD_Stop(runtime->sjdHandle);
      m2astopfunc(runtime);
    }

    if (runtime->streamHandle != nullptr) {
      ADXSTM_ReleaseFileNw(runtime->streamHandle);
    }

    if (runtime->mUnknown02 == 4) {
      lsc_Stop(runtime->SeamlessLscHandle());
      if (runtime->streamJoinInputHandle != nullptr) {
        runtime->streamJoinInputHandle->OnSeamlessStart();
      }
    }

    adxt_StopWithoutLsc(runtime);
  }

  /**
   * Address: 0x00B1ABF0 (FUN_00B1ABF0, _adxt_RcvrReplay)
   *
   * What it does:
   * Performs ADXT replay recovery by quiescing RNA/SJD lanes, resetting channel
   * source handles, restarting stream playback from sector 0 when present, and
   * restarting SJ decode on the retained stream-input handle.
   */
  void adxt_RcvrReplay(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);

    ADXCRS_Lock();
    j__ADXRNA_SetTransSw(runtime->rnaHandle, 0);
    j__ADXRNA_SetPlaySw(runtime->rnaHandle, 0);
    ADXSJD_Stop(runtime->sjdHandle);
    ADXCRS_Unlock();

    if (runtime->streamHandle != nullptr) {
      ADXSTM_Stop(runtime->streamHandle);
      runtime->streamJoinInputHandle->OnSeamlessStart();
    }

    ADXCRS_Lock();

    const auto channelCount = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < channelCount; ++lane) {
      runtime->SourceChannelRingLane(lane)->Destroy();
    }

    if (runtime->streamHandle != nullptr) {
      ADXSTM_Seek(runtime->streamHandle, 0);
      ADXSTM_Start(runtime->streamHandle);
    }

    (void)adxt_start_sj(runtime, runtime->streamJoinInputHandle);
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B1ACA0 (FUN_00B1ACA0, _ADXT_ExecErrChk)
   *
   * What it does:
   * Executes one ADXT error-monitor tick and applies configured stop/recover
   * behavior when decode progression, SJ backlog, or stream status indicates a
   * fault condition.
   */
  void ADXT_ExecErrChk(void* const adxtRuntime)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    const auto playbackState = static_cast<std::int32_t>(runtime->mUnknown01);

    const auto dispatchRecoveryAction = [&]() {
      const auto action = runtime->ErrorRecoveryMode();
      if (action == 1u) {
        ADXT_Stop(runtime);
      } else if (action == 2u) {
        adxt_RcvrReplay(runtime);
      }
    };

    if (
      playbackState != 3
      || runtime->ErrorCheckSuppressedFlag() != 0u
      || ADXSJD_GetStat(runtime->sjdHandle) == 3
    ) {
      runtime->DecodeStallCounter() = 0;
      if (playbackState < 1 || playbackState > 3) {
        runtime->RecoveryWatchdogCounter() = 0;
      }
    } else {
      const auto decodedSamples = ADXSJD_GetDecNumSmpl(runtime->sjdHandle);
      if (runtime->LastDecodedSampleCount() == decodedSamples) {
        const auto stallCounter = static_cast<std::int32_t>(++runtime->DecodeStallCounter());
        if (stallCounter > (5 * runtime->ErrorCheckFrameWindow())) {
          runtime->ErrorStateCode() = -2;
        }
      } else {
        runtime->DecodeStallCounter() = 0;
      }

      runtime->LastDecodedSampleCount() = decodedSamples;
      if (runtime->ErrorStateCode() != 0) {
        const auto action = runtime->ErrorRecoveryMode();
        if (action == 1u || action == 2u) {
          ADXT_Stop(runtime);
        }
        if (runtime->ErrorRecoveryMode() != 0u) {
          runtime->ErrorStateCode() = 0;
          runtime->DecodeStallCounter() = 0;
        }
      }
    }

    const bool hasBacklogFault =
      runtime->streamJoinInputHandle != nullptr
      && runtime->streamJoinInputHandle->QueryDecodeBacklog(1) >= 64;
    if (
      runtime->ErrorCheckSuppressedFlag() != 0u
      || ADXSJD_GetStat(runtime->sjdHandle) == 3
      || hasBacklogFault
    ) {
      runtime->RecoveryWatchdogCounter() = 0;
    } else {
      const auto watchdog = static_cast<std::int32_t>(++runtime->RecoveryWatchdogCounter());
      const auto watchdogLimit =
        (playbackState == 3) ? (5 * runtime->ErrorCheckFrameWindow()) : (20 * runtime->ErrorCheckFrameWindow());
      if (watchdog > watchdogLimit) {
        runtime->ErrorStateCode() = -1;
      }

      if (runtime->ErrorStateCode() != 0) {
        dispatchRecoveryAction();
        if (runtime->ErrorRecoveryMode() != 0u) {
          runtime->ErrorStateCode() = 0;
          runtime->RecoveryWatchdogCounter() = 0;
        }
      }
    }

    if (runtime->streamHandle != nullptr && ADXSTM_GetStat(runtime->streamHandle) == 4) {
      dispatchRecoveryAction();
      if (runtime->ErrorRecoveryMode() != 0u) {
        runtime->ErrorStateCode() = 0;
        runtime->RecoveryWatchdogCounter() = 0;
      }
    }
  }

  /**
   * Address: 0x00B19170 (FUN_00B19170, _adxt_SetSeamlessLp)
   *
   * What it does:
   * Sets seamless-loop flag for ADXT-owned LSC queue.
   */
  [[maybe_unused]] void adxt_SetSeamlessLp(void* const adxtRuntime, const std::int32_t enabled)
  {
    if (adxtRuntime != nullptr) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      LSC_SetLpFlg(runtime->SeamlessLscHandle(), enabled);
      return;
    }

    (void)ADXERR_CallErrFunc1_(kAdxtErrSetSeamlessLpParameter);
  }

  [[maybe_unused]] std::int32_t adxt_StartFnameRangeLp(
    void* adxtRuntime,
    const char* fileName,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );

  /**
   * Address: 0x00B191C0 (FUN_00B191C0, _adxt_StartFnameLp)
   *
   * What it does:
   * Starts seamless loop playback for full filename range.
   */
  [[maybe_unused]] std::int32_t adxt_StartFnameLp(void* const adxtRuntime, const char* const fileName)
  {
    return adxt_StartFnameRangeLp(adxtRuntime, fileName, 0, kLscRangeEndAll);
  }

  /**
   * Address: 0x00B19210 (FUN_00B19210, _adxt_StartFnameRangeLp)
   *
   * What it does:
   * Rebuilds seamless queue with one filename range, enables loop, and starts
   * seamless playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartFnameRangeLp(
    void* const adxtRuntime,
    const char* const fileName,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (adxtRuntime != nullptr && fileName != nullptr) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      void* const lscHandle = runtime->SeamlessLscHandle();
      lsc_Stop(lscHandle);
      (void)adxt_EntryFnameRange(runtime, fileName, rangeStart, rangeEnd);
      LSC_SetLpFlg(lscHandle, 1);
      return adxt_StartSeamless(runtime);
    }

    return ADXERR_CallErrFunc1_(kAdxtErrStartFnameRangeLpParameter);
  }

  /**
   * Address: 0x00B192A0 (FUN_00B192A0, _adxt_StartAfsLp)
   *
   * What it does:
   * Rebuilds seamless queue from one AFS entry, enables loop, and starts
   * seamless playback.
   */
  [[maybe_unused]] std::int32_t adxt_StartAfsLp(
    void* const adxtRuntime,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (adxtRuntime != nullptr && afsHandle <= 0 && afsHandle < 0x100 && fileIndex >= 0 && fileIndex <= 0x10000) {
      auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
      void* const lscHandle = runtime->SeamlessLscHandle();
      lsc_Stop(lscHandle);
      (void)adxt_EntryAfs(runtime, afsHandle, fileIndex);
      LSC_SetLpFlg(lscHandle, 1);
      return adxt_StartSeamless(runtime);
    }

    return ADXERR_CallErrFunc1_(kAdxtErrStartAfsLpParameter);
  }

  /**
   * Address: 0x00B19340 (FUN_00B19340, _adxt_GetNumFiles)
   *
   * What it does:
   * Returns number of queued seamless files for ADXT runtime.
   */
  [[maybe_unused]] std::int32_t adxt_GetNumFiles(void* const adxtRuntime)
  {
    if (adxtRuntime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrGetNumFilesParameter);
      return -1;
    }

    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    return LSC_GetNumStm(runtime->SeamlessLscHandle());
  }

  /**
   * Address: 0x00B19390 (FUN_00B19390, _adxt_ResetEntry)
   *
   * What it does:
   * Clears ADXT seamless queue when runtime is idle.
   */
  [[maybe_unused]] void adxt_ResetEntry(void* const adxtRuntime)
  {
    if (adxtRuntime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtErrResetEntryParameter);
      return;
    }

    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime->mUnknown01 == 0) {
      LSC_ResetEntry(runtime->SeamlessLscHandle());
    }
  }

  /**
   * Address: 0x00B193C0 (FUN_00B193C0, _adxt_ExecLscSvr)
   *
   * What it does:
   * Runs one ADXT seamless LSC server tick under ADX server enter/leave guards.
   */
  [[maybe_unused]] void adxt_ExecLscSvr()
  {
    ADXCRS_Enter();
    (void)LSC_ExecServer();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00ACBD00 (FUN_00ACBD00, _mwPlyGetTime)
   *
   * What it does:
   * Returns current playback time from SFD handle, clamping negative values
   * to `(0,1)` fallback.
   */
  void mwPlyGetTime(
    moho::MwsfdPlaybackStateSubobj* const ply,
    std::int32_t* const outTime,
    std::int32_t* const outTimeScale
  )
  {
    *outTime = 0;
    *outTimeScale = 1;

    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetTimeInvalidHandle);
      return;
    }

    if (ply->handle == nullptr) {
      return;
    }

    if (SFD_GetTime(ply->handle, outTime, outTimeScale) != 0) {
      (void)MWSFLIB_SetErrCode(-309);
      (void)MWSFSVM_Error(kMwsfdErrGetTimeFailed);
    }

    if (*outTime < 0) {
      *outTime = 0;
      *outTimeScale = 1;
    }
  }

  /**
   * Address: 0x00ADE020 (FUN_00ADE020, _mwPlyLinkStm)
   *
   * What it does:
   * Toggles seamless-concat stream linkage and arms restart-on-next-start when
   * dropping from linked to unlinked playback.
   */
  void mwPlyLinkStm(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t linkMode)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrLinkStmInvalidHandle);
      return;
    }

    const std::uint8_t wasLinked = ply->concatPlayArmed;
    if (wasLinked == 1 && linkMode == 0) {
      ply->isPrepared = 1;
    }

    if (wasLinked == 0 && linkMode == 1) {
      if (SFD_SetConcatPlay(ply->handle) != 0) {
        (void)MWSFSVM_Error(kMwsfdErrLinkStmConcatPlayFailed);
      }
    }

    ply->concatPlayArmed = static_cast<std::uint8_t>(linkMode);
  }

  /**
   * Address: 0x00AC7ED0 (FUN_00AC7ED0, _mwsfcre_AttachPicUsrBuf)
   *
   * What it does:
   * Validates optional external picture-user buffer lane and binds it to the
   * current SFD handle when global user-buffer mode is enabled.
   */
  [[maybe_unused]] void mwsfcre_AttachPicUsrBuf(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    const auto* const playbackView = reinterpret_cast<const MwsfdPlaybackPicUserView*>(ply);
    const MwsfdPicUserBufferDescriptor* const userBuffer = playbackView->picUserBuffer;
    if (userBuffer == nullptr) {
      (void)MWSFSVM_Error(kMwsfcreErrAttachPicUsrBufInternal);
      return;
    }

    const std::int32_t frameSlotCount = ply->framePoolSize + 3;
    if (userBuffer->bufferBytes < (userBuffer->bytesPerFrame * frameSlotCount)) {
      (void)MWSFSVM_Error(kMwsfcreErrAttachPicUsrBufShort);
      return;
    }

    if (MWSFD_GetUsePicUsr() == 1) {
      (void)SFD_SetPicUsrBuf(ply->handle, userBuffer->bufferAddress, frameSlotCount, userBuffer->bytesPerFrame);
    }
  }

  /**
   * Address: 0x00B0C1B0 (FUN_00B0C1B0, _adxf_enter)
   *
   * What it does:
   * Enters the ADX critical-section shim lane for ADXF API wrappers.
   */
  [[maybe_unused]] void adxf_enter()
  {
    ADXCRS_Enter();
  }

  /**
   * Address: 0x00B0C1C0 (FUN_00B0C1C0, _adxf_leave)
   *
   * What it does:
   * Leaves the ADX critical-section shim lane for ADXF API wrappers.
   */
  [[maybe_unused]] void adxf_leave()
  {
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0C1D0 (FUN_00B0C1D0, _SVM_Lock)
   *
   * What it does:
   * Enters SVM lock lane with the default lock-domain type.
   */
  void SVM_Lock()
  {
    svm_lock(1);
  }

  /**
   * Address: 0x00B0C1E0 (FUN_00B0C1E0, _svm_lock)
   *
   * What it does:
   * Invokes registered SVM lock callback and tracks nested lock level/type.
   */
  void svm_lock(const std::int32_t lockType)
  {
    if (gSvmLockCallback.fn == nullptr) {
      return;
    }

    gSvmLockCallback.fn(gSvmLockCallback.callbackObject);
    if (gSvmLockLevel == 0) {
      gSvmLockingType = lockType;
    }
    ++gSvmLockLevel;
  }

  /**
   * Address: 0x00B0C220 (FUN_00B0C220, _SVM_Unlock)
   *
   * What it does:
   * Leaves SVM lock lane with the default lock-domain type.
   */
  void SVM_Unlock()
  {
    svm_unlock(1);
  }

  /**
   * Address: 0x00B0C230 (FUN_00B0C230, _svm_unlock)
   *
   * What it does:
   * Invokes registered SVM unlock callback, decrements nested lock level,
   * validates final unlock type, and clears lock-type lane when fully released.
   */
  void svm_unlock(const std::int32_t lockType)
  {
    if (gSvmUnlockCallback.fn == nullptr) {
      return;
    }

    if (--gSvmLockLevel == 0) {
      if (gSvmLockingType != lockType) {
        SVM_CallErr(kSvmErrUnlockTypeMismatch, gSvmLockingType, lockType);
      }
      gSvmLockingType = 0;
    }

    gSvmUnlockCallback.fn(gSvmUnlockCallback.callbackObject);
  }

  /**
   * Address: 0x00B0C330 (FUN_00B0C330, _SVM_GetLockType)
   *
   * What it does:
   * Returns current SVM lock-domain type lane.
   */
  [[nodiscard]] std::int32_t SVM_GetLockType()
  {
    return gSvmLockingType;
  }

  /**
   * Address: 0x00B0C340 (FUN_00B0C340, _SVM_CallErr)
   *
   * What it does:
   * Formats one SVM error message and dispatches it through registered
   * SVM error callback lane.
   */
  void SVM_CallErr(const char* const format, ...)
  {
    va_list args;
    va_start(args, format);
    std::memset(gSvmErrorBuffer, 0, sizeof(gSvmErrorBuffer));
    (void)std::vsprintf(gSvmErrorBuffer, format, args);
    va_end(args);

    if (gSvmErrorCallback.fn != nullptr) {
      gSvmErrorCallback.fn(gSvmErrorCallback.callbackObject, gSvmErrorBuffer);
    }
  }

  /**
   * Address: 0x00B0C390 (FUN_00B0C390, _SVM_CallErr1)
   *
   * What it does:
   * Copies one raw error text lane into SVM error buffer and dispatches the
   * callback without format expansion.
   */
  void SVM_CallErr1(const char* const message)
  {
    std::strncpy(gSvmErrorBuffer, message, 0x7Fu);
    if (gSvmErrorCallback.fn != nullptr) {
      gSvmErrorCallback.fn(gSvmErrorCallback.callbackObject, gSvmErrorBuffer);
    }
  }

  /**
   * Address: 0x00B0C530 (FUN_00B0C530, _svm_SetCbSvr)
   *
   * What it does:
   * Registers one server callback lane in the `8 x 6` SVM callback table and
   * returns slot index, or `-1` on error/full table.
   */
  std::int32_t SVM_SetCbSvr(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrSetCbSvrIllegalSvType);
      return -1;
    }

    std::int32_t slotIndex = 0;
    SvmServerCallbackSlot* slot = &gSvmServerCallbackTable[svtype * kSvmServerSlotsPerType];
    while (slot->callbackFn != nullptr) {
      ++slotIndex;
      ++slot;
      if (slotIndex >= kSvmServerSlotsPerType) {
        break;
      }
    }

    if (slotIndex >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrSetCbSvrTooManyServerFuncs);
      return -1;
    }

    slot->callbackFn = reinterpret_cast<SvmServerCallbackFn>(static_cast<std::uintptr_t>(callbackAddress));
    slot->callbackObject = callbackObject;
    slot->callbackName = (callbackName != nullptr) ? callbackName : kSvmUnknownServerCallbackName;
    return slotIndex;
  }

  /**
   * Address: 0x00B0C500 (FUN_00B0C500, _SVM_SetCbSvrWithString)
   *
   * What it does:
   * Acquires SVM lock, writes one server callback-table entry, and returns
   * selected slot index or error status.
   */
  std::int32_t SVM_SetCbSvrWithString(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_Lock();
    const std::int32_t result = SVM_SetCbSvr(svtype, callbackAddress, callbackObject, callbackName);
    SVM_Unlock();
    return result;
  }

  /**
   * Address: 0x00B0C4E0 (FUN_00B0C4E0, _SVM_SetCbSvr)
   *
   * What it does:
   * Registers one callback lane with default null callback-name lane.
   */
  std::int32_t SVM_SetCbSvrNoName(
    const std::int32_t svtype,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    return SVM_SetCbSvrWithString(svtype, callbackAddress, callbackObject, nullptr);
  }

  /**
   * Address: 0x00B0C680 (FUN_00B0C680, SVM_SetCbSvrId)
   *
   * What it does:
   * Registers or overwrites one exact `(svtype,id)` callback-table entry.
   */
  void SVM_SetCbSvrId(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrSetCbSvrIdIllegalId);
      return;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrSetCbSvrIdIllegalSvType);
      return;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    if (slot.callbackFn != nullptr) {
      SVM_CallErr1(kSvmErrSetCbSvrIdOverwrite);
    }

    slot.callbackFn = reinterpret_cast<SvmServerCallbackFn>(static_cast<std::uintptr_t>(callbackAddress));
    slot.callbackObject = callbackObject;
    slot.callbackName = (callbackName != nullptr) ? callbackName : kSvmUnknownServerCallbackName;
  }

  /**
   * Address: 0x00B0C650 (FUN_00B0C650, _SVM_SetCbSvrIdWithString)
   *
   * What it does:
   * Acquires SVM lock and writes one exact callback-table entry.
   */
  void SVM_SetCbSvrIdWithString(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_Lock();
    SVM_SetCbSvrId(svtype, id, callbackAddress, callbackObject, callbackName);
    SVM_Unlock();
  }

  /**
   * Address: 0x00B0C630 (FUN_00B0C630, _SVM_SetCbSvrId)
   *
   * What it does:
   * Writes one exact callback-table entry with default null callback-name lane.
   */
  void SVM_SetCbSvrIdNoName(
    const std::int32_t svtype,
    const std::int32_t id,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    SVM_SetCbSvrIdWithString(svtype, id, callbackAddress, callbackObject, nullptr);
  }

  /**
   * Address: 0x00B0C830 (FUN_00B0C830, _SVM_ExecSvrFuncId)
   *
   * What it does:
   * Executes one registered callback-table lane by `(svtype,id)` and returns
   * callback result, or `0` on validation/missing-callback paths.
   */
  std::int32_t SVM_ExecSvrFuncId(const std::int32_t svtype, const std::int32_t id)
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrExecSvrFuncIdIllegalId);
      return 0;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrExecSvrFuncIdIllegalSvType);
      return 0;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    if (slot.callbackFn == nullptr) {
      return 0;
    }

    return slot.callbackFn(slot.callbackObject);
  }

  /**
   * Address: 0x00B0C5D0 (FUN_00B0C5D0, SVM_DelCbSvr)
   *
   * What it does:
   * Clears one server callback-table slot by `(svtype, id)` with strict
   * range validation and SVM error reporting.
   */
  void SVM_DelCbSvr(const std::int32_t svtype, const std::int32_t id)
  {
    if (id < 0 || id >= kSvmServerSlotsPerType) {
      SVM_CallErr1(kSvmErrDelCbSvrIllegalId);
      return;
    }

    if (svtype < 0 || svtype >= kSvmServerTypeCount) {
      SVM_CallErr1(kSvmErrDelCbSvrIllegalSvType);
      return;
    }

    SvmServerCallbackSlot& slot = gSvmServerCallbackTable[(svtype * kSvmServerSlotsPerType) + id];
    slot.callbackFn = nullptr;
    slot.callbackObject = 0;
    slot.callbackName = nullptr;
  }

  /**
   * Address: 0x00B0C5B0 (FUN_00B0C5B0, _SVM_DelCbSvr)
   *
   * What it does:
   * Acquires SVM lock, clears one callback-table entry, and releases the lock.
   */
  void SVM_DelCbSvrWithLock(const std::int32_t svtype, const std::int32_t id)
  {
    SVM_Lock();
    SVM_DelCbSvr(svtype, id);
    SVM_Unlock();
  }

  /**
   * Address: 0x00ACCAE0 (FUN_00ACCAE0, _MWSFSVM_EntryVint)
   *
   * What it does:
   * Registers one VINT callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryVint(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(0, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVintSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB20 (FUN_00ACCB20, _MWSFSVM_EntryVfunc)
   *
   * What it does:
   * Registers one VSYNC callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryVfunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(2, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVsyncSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB40 (FUN_00ACCB40, _MWSFSVM_EntryIdVfunc)
   *
   * What it does:
   * Registers one VSYNC callback lane at explicit slot id and updates cached
   * VSYNC slot-id lane.
   */
  std::int32_t MWSFSVM_EntryIdVfunc(
    const std::int32_t laneId,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_SetCbSvrIdWithString(2, laneId, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVsyncSlotId = laneId;
    return laneId;
  }

  /**
   * Address: 0x00ACCBD0 (FUN_00ACCBD0, _MWSFSVM_EntryMainFunc)
   *
   * What it does:
   * Registers one MAIN callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryMainFunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(5, callbackAddress, callbackObject, callbackName);
    gMwsfsvmMainSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB90 (FUN_00ACCB90, _MWSFSVM_EntryIdleFunc)
   *
   * What it does:
   * Registers one IDLE callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryIdleFunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(6, callbackAddress, callbackObject, callbackName);
    gMwsfsvmIdleSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB00 (FUN_00ACCB00, _MWSFSVM_DeleteVint)
   *
   * What it does:
   * Deletes cached VINT callback lane from SVM table.
   */
  void MWSFSVM_DeleteVint()
  {
    SVM_DelCbSvrWithLock(0, gMwsfsvmVintSlotId);
  }

  /**
   * Address: 0x00ACCB70 (FUN_00ACCB70, _MWSFSVM_DeleteVfunc)
   *
   * What it does:
   * Deletes cached VSYNC callback lane from SVM table.
   */
  void MWSFSVM_DeleteVfunc()
  {
    SVM_DelCbSvrWithLock(2, gMwsfsvmVsyncSlotId);
  }

  /**
   * Address: 0x00ACCBB0 (FUN_00ACCBB0, _MWSFSVM_DeleteIdleFunc)
   *
   * What it does:
   * Deletes cached IDLE callback lane from SVM table.
   */
  void MWSFSVM_DeleteIdleFunc()
  {
    SVM_DelCbSvrWithLock(6, gMwsfsvmIdleSlotId);
  }

  /**
   * Address: 0x00ACCBF0 (FUN_00ACCBF0, _MWSFSVM_DeleteMainFunc)
   *
   * What it does:
   * Deletes cached MAIN callback lane from SVM table.
   */
  void MWSFSVM_DeleteMainFunc()
  {
    SVM_DelCbSvrWithLock(5, gMwsfsvmMainSlotId);
  }

  /**
   * Address: 0x00B0C760 (FUN_00B0C760, _SVM_SetCbErr)
   *
   * What it does:
   * Publishes one process-global SVM error callback lane under SVM lock.
   */
  void SVM_SetCbErr(moho::AdxmErrorCallback callback, const std::int32_t callbackParam)
  {
    SVM_Lock();
    gSvmErrorCallback.fn = callback;
    gSvmErrorCallback.callbackObject = callbackParam;
    SVM_Unlock();
  }

  /**
   * Address: 0x00B06C00 (FUN_00B06C00, _ADXM_SetCbErr)
   * Body: 0x00B0C760 (_SVM_SetCbErr)
   *
   * What it does:
   * Forwards ADXM error callback registration to SVM callback lane owner.
   */
  void ADXM_SetCbErr(moho::AdxmErrorCallback callback, const std::int32_t callbackParam)
  {
    SVM_SetCbErr(callback, callbackParam);
  }

  /**
   * Address: 0x00B0B680 (FUN_00B0B680, _adxf_read_sj32)
   *
   * What it does:
   * Configures one ADXF stream window for SJ-backed read and starts ADXSTM
   * sector transfer.
   */
  [[maybe_unused]] std::int32_t adxf_read_sj32(
    AdxfRuntimeHandleView* const adxfHandle,
    const std::int32_t requestedSectors,
    void* const sourceJoinObject
  )
  {
    if (ADXSTM_GetStat(adxfHandle->streamHandle) != 1) {
      ADXSTM_Stop(adxfHandle->streamHandle);
    }

    ADXCRS_Lock();
    const std::int32_t readStartSector = adxfHandle->readStartSector;
    std::int32_t sectorsToRead = adxfHandle->fileSectorCount - readStartSector;
    adxfHandle->requestSectorStart = adxfHandle->fileStartSector + readStartSector;
    if (requestedSectors < sectorsToRead) {
      sectorsToRead = requestedSectors;
    }
    adxfHandle->requestSectorCount = sectorsToRead;
    adxfHandle->requestBuffer = nullptr;
    if (sectorsToRead != 0) {
      ADXSTM_SetEos(adxfHandle->streamHandle, -1);
      ADXSTM_SetSj(adxfHandle->streamHandle, sourceJoinObject);
      ADXSTM_SetReqRdSize(adxfHandle->streamHandle, adxfHandle->requestedReadSizeSectors);
      adxfHandle->status = 2;
      adxfHandle->stopWithoutNetworkFlag = 0;
      ADXSTM_SetPause(adxfHandle->streamHandle, 0);
      ADXSTM_Seek(adxfHandle->streamHandle, adxfHandle->readStartSector);
      ADXSTM_Start2(adxfHandle->streamHandle, adxfHandle->requestSectorCount);

      const std::int32_t startedSectorCount = adxfHandle->requestSectorCount;
      ADXCRS_Unlock();
      return startedSectorCount;
    }

    adxfHandle->status = 3;
    ADXCRS_Unlock();
    return 0;
  }

  /**
   * Address: 0x00B0B170 (FUN_00B0B170, _adxf_CreateAdxFs)
   *
   * What it does:
   * Allocates one ADXF runtime handle and wires a fresh ADX stream owner with
   * default sector-window state.
   */
  [[maybe_unused]] AdxfRuntimeHandleView* adxf_CreateAdxFs()
  {
    auto* const handle = static_cast<AdxfRuntimeHandleView*>(adxf_AllocAdxFs());
    if (handle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfErrCreateNoHandles);
      return nullptr;
    }

    handle->streamHandle = ADXSTM_Create(0, 0x100);
    if (handle->streamHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfErrCreateCannotCreateStream);
      return nullptr;
    }

    handle->status = 1;
    handle->requestSectorStart = 0;
    handle->requestSectorCount = 0;
    handle->requestBuffer = nullptr;
    handle->requestedReadSizeSectors = 0x200;
    handle->sjFlag = 0;
    handle->boundAfsHandle = 0;
    handle->stopWithoutNetworkFlag = 0;
    handle->used = 1;
    return handle;
  }

  /**
   * Address: 0x00ADDB50 (FUN_00ADDB50, _mwPlyEntryFname)
   */
  void mwPlyEntryFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameInvalidHandle);
      return;
    }
    if (fname == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameNullFileName);
      return;
    }

    if (LSC_EntryFname(ply->lscHandle, fname) >= 0) {
      ++ply->seamlessEntryCount;
      return;
    }

    ply->compoMode = 4;
    (void)MWSFSVM_Error(kMwsfdErrEntryFnameCannotEntryFmt, fname);
  }

  /**
   * Address: 0x00ADDBC0 (FUN_00ADDBC0, _mwPlyStartSeamless)
   */
  void mwPlyStartSeamless(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartSeamlessInvalidHandle);
      return;
    }

    mwPlyLinkStm(ply, 1);
    MWSFD_StartInternalSj(ply, ply->sjRingBufferHandle);
    MWSFPLY_SetFlowLimit(ply);
    lsc_Start(ply->lscHandle);
    if (ply->sjSupplyHandle != nullptr) {
      ply->sjSupplyHandle->dispatchTable->onStart(ply->sjSupplyHandle);
    }
    (void)MWSFCRE_SetSupplySj(ply);
    ply->apiType = 0;
  }

  /**
   * Address: 0x00ADDC30 (FUN_00ADDC30, _mwPlySetSeamlessLp)
   */
  void mwPlySetSeamlessLp(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      LSC_SetLpFlg(ply->lscHandle, enabled);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrSetLpFlagInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDCE0 (FUN_00ADDCE0, _mwPlyReleaseLp)
   */
  void mwPlyReleaseLp(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrReleaseLpInvalidHandle);
      return;
    }

    mwPlySetSeamlessLp(ply, 0);
    mwPlyReleaseSeamless(ply);
  }

  /**
   * Address: 0x00ADDD20 (FUN_00ADDD20, _mwPlyReleaseSeamless)
   */
  void mwPlyReleaseSeamless(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      mwPlyLinkStm(ply, 0);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrReleaseSeamlessInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDD60 (FUN_00ADDD60, _mwPlyEntryAfs)
   */
  void mwPlyEntryAfs(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrEntryAfsInvalidHandle);
      return;
    }

    std::int32_t startOffset = 0;
    std::int32_t rangeStart = 0;
    std::int32_t rangeEnd = 0;
    if (ADXF_GetFnameRangeEx(afsHandle, fileIndex, ply->fname, &startOffset, &rangeStart, &rangeEnd) != 0) {
      (void)MWSFSVM_Error(kMwsfdErrEntryAfsCannotEntryFmt, afsHandle, fileIndex);
      return;
    }

    const char* const afsFileName = ADXF_GetFnameFromPt(afsHandle);
    (void)lsc_EntryFileRange(ply->lscHandle, afsFileName, startOffset, rangeStart, rangeEnd);
  }

  /**
   * Address: 0x00ADDE00 (FUN_00ADDE00, _mwPlyStartAfsLp)
   */
  void mwPlyStartAfsLp(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartAfsLpInvalidHandle);
      return;
    }

    lsc_Stop(ply->lscHandle);
    mwPlyEntryAfs(ply, afsHandle, fileIndex);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00ADDE50 (FUN_00ADDE50, _mwPlyEntryFnameRange)
   */
  void mwPlyEntryFnameRange(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      (void)lsc_EntryFileRange(ply->lscHandle, fname, 0, rangeStart, rangeEnd);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameRangeInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDEA0 (FUN_00ADDEA0, _mwPlyStartFnameRangeLp)
   */
  void mwPlyStartFnameRangeLp(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartFnameRangeLpInvalidHandle);
      return;
    }

    lsc_Stop(ply->lscHandle);
    mwPlyEntryFnameRange(ply, fname, rangeStart, rangeEnd);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00ADDD50 (FUN_00ADDD50, _mwPlyGetNumSlFiles)
   */
  std::int32_t mwPlyGetNumSlFiles(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return LSC_GetNumStm(ply->lscHandle);
  }

  /**
   * Address: 0x00ADDF00 (FUN_00ADDF00, _mwPlyGetSlFname)
   */
  const char* mwPlyGetSlFname(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamIndex)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetSlFnameInvalidHandle);
      return nullptr;
    }

    if (streamIndex < mwPlyGetNumSlFiles(ply)) {
      if (streamIndex >= 0) {
        const std::int32_t streamId = MWSFLSC_GetStmId(ply, streamIndex);
        return MWSFLSC_GetStmFname(ply, streamId);
      }
      (void)MWSFSVM_Error(kMwsfdErrInvalidStreamIndexFmt, streamIndex);
      return nullptr;
    }

    return nullptr;
  }

  /**
   * Address: 0x00ADDF70 (FUN_00ADDF70, _MWSFLSC_GetStat)
   */
  std::int32_t MWSFLSC_GetStat(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return LSC_GetStat(ply->lscHandle);
  }

  /**
   * Address: 0x00ADDF80 (FUN_00ADDF80, _MWSFLSC_GetStmId)
   */
  std::int32_t MWSFLSC_GetStmId(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamIndex)
  {
    return lsc_GetStmId(ply->lscHandle, streamIndex);
  }

  /**
   * Address: 0x00ADDF90 (FUN_00ADDF90, _MWSFLSC_GetStmFname)
   */
  const char* MWSFLSC_GetStmFname(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmFname(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFA0 (FUN_00ADDFA0, _MWSFLSC_GetStmStat)
   */
  std::int32_t MWSFLSC_GetStmStat(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmStat(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFB0 (FUN_00ADDFB0, _MWSFLSC_GetStmRdSct)
   */
  std::int32_t MWSFLSC_GetStmRdSct(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmRdSct(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFC0 (FUN_00ADDFC0, _MWSFLSC_IsFsStatErr)
   */
  bool MWSFLSC_IsFsStatErr(void* const lscHandle)
  {
    return LSC_GetStat(lscHandle) == 3;
  }

  /**
   * Address: 0x00ADDFE0 (FUN_00ADDFE0, _MWSFLSC_SetFlowLimit)
   */
  std::int32_t MWSFLSC_SetFlowLimit(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t flowLimit)
  {
    if (ply->lscHandle == nullptr) {
      return 0;
    }
    return lsc_SetFlowLimit(ply->lscHandle, flowLimit);
  }

  /**
   * Address: 0x00ADE0D0 (FUN_00ADE0D0, _MWSFRNA_SetOutVol)
   */
  std::int32_t MWSFRNA_SetOutVol(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t volumeLevel)
  {
    return SFD_SetOutVol(ply->handle, volumeLevel);
  }

  /**
   * Address: 0x00ADE0E0 (FUN_00ADE0E0, _MWSFRNA_GetOutVol)
   */
  std::int32_t MWSFRNA_GetOutVol(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return SFD_GetOutVol(ply->handle);
  }

  /**
   * Address: 0x00ADE0F0 (FUN_00ADE0F0, _MWSFRNA_SetOutPan)
   */
  std::int32_t MWSFRNA_SetOutPan(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t laneIndex,
    const std::int32_t panLevel
  )
  {
    return SFD_SetOutPan(ply->handle, laneIndex, panLevel);
  }

  /**
   * Address: 0x00ADE100 (FUN_00ADE100, _MWSFRNA_GetOutPan)
   */
  std::int32_t MWSFRNA_GetOutPan(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t laneIndex)
  {
    return SFD_GetOutPan(ply->handle, laneIndex);
  }

  /**
   * Address: 0x00ADE400 (FUN_00ADE400, _CFT_Init)
   */
  void CFT_Init()
  {
    gCriVerstrPtrCft = kCriCftVersionString;
    CFT_Ycc420plnToArgb8888Init();
    CFT_Ycc420plnToArgb8888IntInit();
    CFT_Ycc420plnToArgb8888PrgInit();
    CFT_Ycc420plnToRgb565Init();
    CFT_Ycc420plnToRgb555Init();
  }

  /**
   * Address: 0x00B03CE0 (FUN_00B03CE0, _UTY_SupportSse)
   *
   * What it does:
   * Lazily initializes process-global SSE availability lane and returns it.
   */
  std::int32_t UTY_SupportSse()
  {
    if (gUtySseSupportState == -1) {
      _mm_empty();
      gUtySseSupportState = 1;
    }
    return gUtySseSupportState;
  }

  /**
   * Address: 0x00AEE730 (FUN_00AEE730, _CFT_Ycc420plnToArgb8888IntInit)
   *
   * What it does:
   * Builds CFT integer lookup tables used by YCC420 planar -> ARGB8888
   * conversion lanes (packed intermediate, red, blue, and green tables).
   */
  void CFT_Ycc420plnToArgb8888IntInit()
  {
    auto clamp_round_to_byte = [](const double value) -> std::uint8_t {
      if (value < 0.0) {
        return 0;
      }
      if (value >= 255.0) {
        return 255;
      }
      return static_cast<std::uint8_t>(static_cast<std::int32_t>(value + 0.5));
    };

    std::size_t packedIndex = 0;
    for (std::int32_t yLane = -128; yLane < 128; ++yLane) {
      const double scaledY = static_cast<double>(yLane) * 1.596;
      for (std::int32_t cLane = -128; cLane < 128; ++cLane) {
        const double packedValue = static_cast<double>(cLane) * 2.017 + scaledY + 0.5;
        yuv_to_tmp[packedIndex] = static_cast<std::int16_t>(static_cast<std::int32_t>(std::floor(packedValue)) + 0x134);
        ++packedIndex;
      }
    }

    std::size_t redBlueIndex = 0;
    std::size_t greenIndex = 0;
    for (std::int32_t luma = 0; luma < 256; ++luma) {
      const double yTerm = static_cast<double>(luma - 16) * 1.164;
      for (std::int32_t chroma = -128; chroma < 128; ++chroma) {
        const std::uint8_t red = clamp_round_to_byte(static_cast<double>(chroma) * 1.596 + yTerm);
        yuv_to_r[redBlueIndex] = static_cast<std::uint32_t>(red) << 16;

        const std::uint8_t blue = clamp_round_to_byte(static_cast<double>(chroma) * 2.017 + yTerm);
        yuv_to_b[redBlueIndex] = blue;
        ++redBlueIndex;
      }

      const double doubledY = yTerm * 2.0;
      for (std::int32_t greenSource = -308; greenSource < 716; ++greenSource) {
        const std::uint8_t green = clamp_round_to_byte((doubledY - static_cast<double>(greenSource)) * 0.5);
        tmp_to_g[greenIndex] = static_cast<std::uint16_t>(static_cast<std::uint16_t>(green) << 8);
        ++greenIndex;
      }
    }
  }

  [[nodiscard]] std::int32_t buildBitcutClipTable32(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    const std::int32_t droppedBits = 8 - componentBits;
    std::memset(table, 0, 0x400u);

    for (std::uint32_t source = 0; source < 0x100u; ++source) {
      const std::int32_t clippedLane =
        static_cast<std::int32_t>(static_cast<std::int32_t>(source >> droppedBits) << bitShift);
      table[0x100u + source] = clippedLane | (clippedLane << 16);
    }

    const std::int32_t maxLane = static_cast<std::int32_t>((0xFF >> droppedBits) << bitShift);
    for (std::size_t index = 0; index < 0x100u; ++index) {
      table[0x200u + index] = maxLane;
    }

    return maxLane;
  }

  void buildBitcut5GradPatternDitherClipTable32(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    const std::int32_t droppedBits = 8 - componentBits;
    const std::int32_t maxLane = (1 << componentBits) - 1;
    std::memset(table, 0, 0x400u);

    for (std::int32_t source = 0; source < 0x100; ++source) {
      std::int32_t clippedLane = source >> droppedBits;
      if (clippedLane != maxLane) {
        const std::int32_t laneSpan = 1 << droppedBits;
        const std::int32_t threshold =
          static_cast<std::int32_t>(static_cast<double>((laneSpan * kCftDitherPatternWeights[ditherPatternIndex]) / 5) + 0.5);
        if ((source & (laneSpan - 1)) > threshold) {
          ++clippedLane;
        }
      }

      const std::int32_t shiftedLane = clippedLane << bitShift;
      table[0x100u + static_cast<std::size_t>(source)] = shiftedLane | (shiftedLane << 16);
    }

    const std::int32_t clippedMaxLane = static_cast<std::int32_t>((0xFF >> droppedBits) << bitShift);
    const std::int32_t clippedMaxPacked = clippedMaxLane | (clippedMaxLane << 16);
    for (std::size_t index = 0; index < 0x100u; ++index) {
      table[0x200u + index] = clippedMaxPacked;
    }
  }

  /**
   * Address: 0x00AF45F0 (FUN_00AF45F0, _createBitcutClipTable32_555)
   *
   * What it does:
   * Builds one RGB555 clip lookup table lane used by CFT color conversion.
   */
  std::int32_t createBitcutClipTable32_555(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    return buildBitcutClipTable32(table, componentBits, bitShift);
  }

  /**
   * Address: 0x00AF4660 (FUN_00AF4660, _createBitcut5GradPtnDitherClipTable32_555)
   *
   * What it does:
   * Builds one RGB555 dithered clip lookup lane for one 5-step pattern phase.
   */
  void createBitcut5GradPtnDitherClipTable32_555(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    buildBitcut5GradPatternDitherClipTable32(table, componentBits, bitShift, ditherPatternIndex);
  }

  /**
   * Address: 0x00AF56A0 (FUN_00AF56A0, _createBitcutClipTable32_565)
   *
   * What it does:
   * Builds one RGB565 clip lookup table lane used by CFT color conversion.
   */
  std::int32_t createBitcutClipTable32_565(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    return buildBitcutClipTable32(table, componentBits, bitShift);
  }

  /**
   * Address: 0x00AF5710 (FUN_00AF5710, _createBitcut5GradPtnDitherClipTable32_565)
   *
   * What it does:
   * Builds one RGB565 dithered clip lookup lane for one 5-step pattern phase.
   */
  void createBitcut5GradPtnDitherClipTable32_565(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    buildBitcut5GradPatternDitherClipTable32(table, componentBits, bitShift, ditherPatternIndex);
  }

  /**
   * Address: 0x00AF36B0 (FUN_00AF36B0, _CFT_Ycc420plnToRgb555Init)
   *
   * What it does:
   * Builds CFT RGB555 conversion and dither lookup tables used by YCC420
   * planar conversion paths.
   */
  void CFT_Ycc420plnToRgb555Init()
  {
    for (std::int32_t luma = 0; luma < 0x100; ++luma) {
      const double yTerm = (static_cast<double>(luma - 16) * 1.164 + 256.5) * kCftFixedPointScale;
      y_to_y2_555[static_cast<std::size_t>(luma)] = static_cast<std::int32_t>(yTerm);
    }

    for (std::int32_t index = 0; index < 0x100; ++index) {
      const double chromaLane = static_cast<double>(index - 128);
      cr_to_r_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(1.596 * chromaLane * kCftFixedPointScale);
      cb_to_g_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.392 * chromaLane * kCftFixedPointScale);
      cr_to_g_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.813 * chromaLane * kCftFixedPointScale);
      cb_to_b_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(2.017 * chromaLane * kCftFixedPointScale);
    }

    (void)createBitcutClipTable32_555(r_to_pix_555.data(), 5, 10);
    (void)createBitcutClipTable32_555(g_to_pix_555.data(), 5, 5);
    (void)createBitcutClipTable32_555(b_to_pix_555.data(), 5, 0);

    for (std::int32_t phase = 0; phase < 4; ++phase) {
      const std::size_t tableOffset = static_cast<std::size_t>(phase) * 0x300u;
      createBitcut5GradPtnDitherClipTable32_555(r_to_pix32_dither_555.data() + tableOffset, 5, 10, phase);
      createBitcut5GradPtnDitherClipTable32_555(g_to_pix32_dither_555.data() + tableOffset, 5, 5, phase);
      createBitcut5GradPtnDitherClipTable32_555(b_to_pix32_dither_555.data() + tableOffset, 5, 0, phase);
    }
  }

  /**
   * Address: 0x00AF4760 (FUN_00AF4760, _CFT_Ycc420plnToRgb565Init)
   *
   * What it does:
   * Builds CFT RGB565 conversion and dither lookup tables used by YCC420
   * planar conversion paths.
   */
  void CFT_Ycc420plnToRgb565Init()
  {
    for (std::int32_t luma = 0; luma < 0x100; ++luma) {
      const double yTerm = (static_cast<double>(luma - 16) * 1.164 + 256.5) * kCftFixedPointScale;
      y_to_y2_565[static_cast<std::size_t>(luma)] = static_cast<std::int32_t>(yTerm);
    }

    for (std::int32_t index = 0; index < 0x100; ++index) {
      const double chromaLane = static_cast<double>(index - 128);
      cr_to_r_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(1.596 * chromaLane * kCftFixedPointScale);
      cb_to_g_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.392 * chromaLane * kCftFixedPointScale);
      cr_to_g_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.813 * chromaLane * kCftFixedPointScale);
      cb_to_b_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(2.017 * chromaLane * kCftFixedPointScale);
    }

    (void)createBitcutClipTable32_565(r_to_pix_565.data(), 5, 11);
    (void)createBitcutClipTable32_565(g_to_pix_565.data(), 6, 5);
    (void)createBitcutClipTable32_565(b_to_pix_565.data(), 5, 0);

    for (std::int32_t phase = 0; phase < 4; ++phase) {
      const std::size_t tableOffset = static_cast<std::size_t>(phase) * 0x300u;
      createBitcut5GradPtnDitherClipTable32_565(r_to_pix32_dither_565.data() + tableOffset, 5, 11, phase);
      createBitcut5GradPtnDitherClipTable32_565(g_to_pix32_dither_565.data() + tableOffset, 6, 5, phase);
      createBitcut5GradPtnDitherClipTable32_565(b_to_pix32_dither_565.data() + tableOffset, 5, 0, phase);
    }
  }

  /**
   * Address: 0x00ADE430 (FUN_00ADE430, _CFT_Finish)
   */
  void CFT_Finish()
  {
  }

  /**
   * Address: 0x00ADE440 (FUN_00ADE440, _CFTCOM_SetCftFunctionName)
   */
  const char* CFTCOM_SetCftFunctionName(const char* const functionName)
  {
    gCftcomFunctionName = functionName;
    return functionName;
  }

  /**
   * Address: 0x00ADE450 (FUN_00ADE450, _CFTCOM_GetCftFunctionName)
   */
  const char* CFTCOM_GetCftFunctionName()
  {
    return gCftcomFunctionName;
  }

  /**
   * Address: 0x00ADE460 (FUN_00ADE460, _CFT_OptimizeSpeed)
   */
  std::int32_t CFT_OptimizeSpeed(const std::int32_t optimizeSpeedMode)
  {
    gCftcomOptimizeSpeed = optimizeSpeedMode;
    return optimizeSpeedMode;
  }

  /**
   * Address: 0x00ADE470 (FUN_00ADE470, _CFTCOM_GetOptimizeSpeed)
   */
  std::int32_t CFTCOM_GetOptimizeSpeed()
  {
    return gCftcomOptimizeSpeed;
  }

  /**
   * Address: 0x00ADE480 (FUN_00ADE480, _SFXINF_GetStmInf)
   */
  std::int32_t SFXINF_GetStmInf(moho::SfxStreamState* const streamState, const char* const tagName)
  {
    (void)streamState;
    (void)tagName;
    return kSfxCompoModeHalfAlpha;
  }

  /**
   * Address: 0x00ADE490 (FUN_00ADE490, _SFBUF_Init)
   */
  std::int32_t SFBUF_Init()
  {
    return sfbuf_InitSjUuid();
  }

  /**
   * Address: 0x00ADE4A0 (FUN_00ADE4A0, _SFBUF_Finish)
   */
  void SFBUF_Finish()
  {
  }

  /**
   * Address: 0x00ADE1F0 (FUN_00ADE1F0, _SFXA_Finish)
   */
  void SFXA_Finish()
  {
  }

  /**
   * Address: 0x00ADE1D0 (FUN_00ADE1D0, _sfxalp_InitLibWork)
   */
  std::int32_t sfxalp_InitLibWork()
  {
    std::memset(&gSfxaLibWork, 0, sizeof(gSfxaLibWork));
    gSfxaLibWork.last = 0x20;
    return 0;
  }

  /**
   * Address: 0x00ADE230 (FUN_00ADE230, _sfxamv_SearchFreeHn)
   */
  std::int32_t sfxamv_SearchFreeHn()
  {
    const std::int32_t maxHandleCount = gSfxaLibWork.last;
    if (maxHandleCount <= 0) {
      return 0;
    }

    auto* handleView = gSfxaLibWork.objects.data();
    for (std::int32_t index = 0; index < maxHandleCount; ++index, ++handleView) {
      if (handleView->used == 0) {
        return SjPointerToAddress(handleView);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00ADE200 (FUN_00ADE200, _SFXA_Create)
   */
  std::int32_t SFXA_Create()
  {
    const std::int32_t sfxaHandleAddress = sfxamv_SearchFreeHn();
    if (sfxaHandleAddress == 0) {
      return 0;
    }

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    (void)sfxamv_InitHn(sfxaHandleAddress);
    ++gSfxaLibWork.cur;
    handleView->used = 1;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE260 (FUN_00ADE260, _sfxamv_InitHn)
   */
  std::int32_t sfxamv_InitHn(const std::int32_t sfxaHandleAddress)
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->luminancePivot = 0;
    handleView->luminanceMin = 31;
    handleView->luminanceMax = 100;
    handleView->needsLumiTableUpdate = 1;
    handleView->alpha0 = 0;
    handleView->alpha1 = 127;
    handleView->alpha2 = -1;
    handleView->luminanceBuilder = nullptr;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE290 (FUN_00ADE290, _SFXA_Destroy)
   */
  void SFXA_Destroy(const std::int32_t sfxaHandleAddress)
  {
    if (sfxaHandleAddress == 0) {
      return;
    }

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->used = 0;
    --gSfxaLibWork.cur;
  }

  /**
   * Address: 0x00ADE2B0 (FUN_00ADE2B0, _SFXA_MakeAlpLumiTbl)
   */
  std::int32_t SFXA_MakeAlpLumiTbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = 0;
    if (handleView->luminanceBuilder != nullptr) {
      callbackResult = handleView->luminanceBuilder(
        handleView->luminancePivot,
        handleView->luminanceMin,
        handleView->luminanceMax,
        tableAddress
      );
    }
    handleView->needsLumiTableUpdate = 0;
    return callbackResult;
  }

  /**
   * Address: 0x00ADE2E0 (FUN_00ADE2E0, _SFXA_MakeAlp3110Tbl)
   */
  std::int32_t SFXA_MakeAlp3110Tbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = sfxaHandleAddress;
    if (handleView->alpha3110Builder != nullptr) {
      callbackResult = handleView->alpha3110Builder(
        tableAddress,
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha0)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha1)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha2))
      );
    }
    return callbackResult;
  }

  /**
   * Address: 0x00ADE310 (FUN_00ADE310, _SFXA_MakeAlp3211Tbl)
   */
  std::int32_t SFXA_MakeAlp3211Tbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = sfxaHandleAddress;
    if (handleView->alpha3211Builder != nullptr) {
      callbackResult = handleView->alpha3211Builder(
        tableAddress,
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha0)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha1)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha2))
      );
    }
    return callbackResult;
  }

  /**
   * Address: 0x00ADE340 (FUN_00ADE340, _SFXA_IsNeedUpdateLumiTbl)
   */
  std::int32_t SFXA_IsNeedUpdateLumiTbl(const std::int32_t sfxaHandleAddress)
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    return handleView->needsLumiTableUpdate;
  }

  /**
   * Address: 0x00ADE350 (FUN_00ADE350, _SFXA_SetLumiPrm)
   */
  std::int32_t SFXA_SetLumiPrm(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t luminanceMin,
    const std::int32_t luminanceMax,
    const std::int32_t luminancePivot
  )
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->luminancePivot = luminancePivot;
    handleView->luminanceMin = luminanceMin;
    handleView->luminanceMax = luminanceMax;
    handleView->needsLumiTableUpdate = 1;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE380 (FUN_00ADE380, _SFXA_GetLumiPrm)
   */
  std::int32_t SFXA_GetLumiPrm(
    const std::int32_t sfxaHandleAddress,
    std::int32_t* const outLuminanceMin,
    std::int32_t* const outLuminanceMax,
    std::int32_t* const outLuminancePivot
  )
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    *outLuminancePivot = handleView->luminancePivot;
    *outLuminanceMin = handleView->luminanceMin;
    *outLuminanceMax = handleView->luminanceMax;
    return handleView->luminanceMax;
  }

  /**
   * Address: 0x00ADE3A0 (FUN_00ADE3A0, _SFXA_SetAlp3Prm)
   */
  std::int32_t SFXA_SetAlp3Prm(
    const std::int32_t sfxaHandleAddress,
    const std::int8_t alpha0,
    const std::int8_t alpha1,
    const std::int8_t alpha2
  )
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->alpha0 = alpha0;
    handleView->alpha1 = alpha1;
    handleView->alpha2 = alpha2;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE3C0 (FUN_00ADE3C0, _SFXA_GetAlp3Prm)
   */
  std::int32_t SFXA_GetAlp3Prm(
    const std::int32_t sfxaHandleAddress,
    std::int8_t* const outAlpha0,
    std::int8_t* const outAlpha1,
    std::int8_t* const outAlpha2
  )
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    *outAlpha0 = handleView->alpha0;
    *outAlpha1 = handleView->alpha1;
    *outAlpha2 = handleView->alpha2;
    return handleView->alpha2;
  }

  /**
   * Address: 0x00ADE3E0 (FUN_00ADE3E0, _SFXSUD_Init)
   */
  void SFXSUD_Init()
  {
    SUD_Init();
  }

  /**
   * Address: 0x00ADE3F0 (FUN_00ADE3F0, _SFXSUD_Finish)
   */
  std::int32_t SFXSUD_Finish()
  {
    return SUD_Finish();
  }

  /**
   * Address: 0x00ADE580 (FUN_00ADE580, _sfbuf_MakeBufPtr)
   */
  std::int32_t sfbuf_MakeBufPtr(
    std::int32_t* const outBufferPointers,
    const std::int32_t* const ringBufferSizes,
    std::int32_t baseBufferAddress
  )
  {
    constexpr std::int32_t kSfbufRingLaneCount = 8;
    for (std::int32_t lane = 0; lane < kSfbufRingLaneCount; ++lane) {
      outBufferPointers[lane] = baseBufferAddress;
      baseBufferAddress += ringBufferSizes[lane];
    }
    return baseBufferAddress;
  }

  /**
   * Address: 0x00ADE8E0 (FUN_00ADE8E0, _sfbuf_InitBufData)
   */
  std::int32_t* sfbuf_InitBufData(
    std::int32_t* const sfbufLaneWords,
    const std::int32_t laneType,
    const std::int32_t setupState
  )
  {
    auto* const laneView = reinterpret_cast<SfbufSupplyLaneView*>(sfbufLaneWords);
    laneView->laneType = laneType;
    laneView->isSetup = setupState;
    laneView->prepFlag = 0;
    laneView->termFlag = 0;
    laneView->runtimeState0 = 9;
    laneView->runtimeState1 = 9;
    return sfbufLaneWords;
  }

  /**
   * Address: 0x00ADE910 (FUN_00ADE910, _sfbuf_InitUoSj)
   */
  std::int32_t* sfbuf_InitUoSj(std::int32_t* const uoSjStateWords)
  {
    std::int32_t* cursor = uoSjStateWords + 2;
    for (std::int32_t block = 0; block < 3; ++block) {
      cursor[-2] = 0;
      cursor[-1] = 0;
      cursor[0] = 0;
      cursor[1] = 0;
      cursor += 4;
    }
    return cursor;
  }

  /**
   * Address: 0x00ADE8B0 (FUN_00ADE8B0, _sfbuf_InitUoSjBuf)
   */
  std::int32_t* sfbuf_InitUoSjBuf(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    (void)bufferAddressTable;
    (void)bufferSizeTable;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 3, 1);
    return sfbuf_InitUoSj(&laneView->sourceBufferAddress);
  }

  /**
   * Address: 0x00ADE7D0 (FUN_00ADE7D0, _sfbuf_InitAringBuf)
   */
  std::int32_t sfbuf_InitAringBuf(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t setupState = (bufferSizeTable[laneIndex] != 0) ? 1 : 0;
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 2, setupState);
    laneView->sourceBufferAddress = bufferAddressTable[laneIndex];
    const std::int32_t sourceBufferBytes = bufferSizeTable[laneIndex];
    laneView->laneParam18 = 0;
    laneView->queuedDataBytes = 0;
    laneView->laneParam20 = 0;
    laneView->laneParam24 = 0;
    laneView->delimiterPrimaryAddress = 0;
    laneView->delimiterSecondaryAddress = 0;
    laneView->writeTotalBytes = 0;
    laneView->readTotalBytes = 0;
    laneView->laneParam38 = 0;
    laneView->laneParam3C = 0;
    laneView->sourceBufferBytes = sourceBufferBytes;
    return sourceBufferBytes;
  }

  /**
   * Address: 0x00ADE740 (FUN_00ADE740, _sfbuf_InitVfrmBuf)
   */
  std::int32_t sfbuf_InitVfrmBuf(
    const std::int32_t vfrmOwnerAddress,
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    constexpr std::int32_t kVfrmScratchBaseOffset = 0x16B0;
    constexpr std::int32_t kVfrmScratchClearSpan = 0x880;
    constexpr std::int32_t kVfrmScratchStride = 0x88;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t setupState = (bufferSizeTable[laneIndex] != 0) ? 1 : 0;
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 1, setupState);
    laneView->sourceBufferAddress = bufferAddressTable[laneIndex];
    laneView->sourceBufferBytes = bufferSizeTable[laneIndex];
    laneView->laneParam18 = 0;
    laneView->queuedDataBytes = 0;
    laneView->laneParam20 = vfrmOwnerAddress + kVfrmScratchBaseOffset;

    std::int32_t scratchOffset = 0;
    while (scratchOffset < kVfrmScratchClearSpan) {
      auto* const scratchWord = reinterpret_cast<std::int32_t*>(SjAddressToPointer(laneView->laneParam20 + scratchOffset));
      *scratchWord = 0;
      scratchOffset += kVfrmScratchStride;
    }
    return scratchOffset;
  }

  /**
   * Address: 0x00ADE650 (FUN_00ADE650, _sfbuf_CreateSj)
   */
  std::int32_t sfbuf_CreateSj(
    std::int32_t* const outSjCreateStateWords,
    const std::int32_t sourceBufferAddress,
    const std::int32_t sourceBufferBytes,
    const std::int32_t extraBufferBytes
  )
  {
    constexpr std::int32_t kSfbufErrInvalidBufferSpan = -16776180;
    constexpr std::int32_t kSfbufErrCreateSjFailed = -16776182;

    auto* const createState = reinterpret_cast<SfbufSjCreateStateView*>(outSjCreateStateWords);
    createState->ownerTag = 0;
    createState->sourceBufferAddress = sourceBufferAddress;

    const std::int32_t sjBufferBytes = sourceBufferBytes - extraBufferBytes;
    createState->sourceBufferBytes = sjBufferBytes;
    if (sjBufferBytes <= 0) {
      return SFLIB_SetErr(0, kSfbufErrInvalidBufferSpan);
    }

    createState->extraBufferBytes = extraBufferBytes;
    createState->mUnknown14 = 0;
    createState->sjHandle = SJRBF_Create(sourceBufferAddress, sjBufferBytes, extraBufferBytes);
    if (createState->sjHandle != nullptr) {
      return 0;
    }
    return SFLIB_SetErr(0, kSfbufErrCreateSjFailed);
  }

  /**
   * Address: 0x00ADE5B0 (FUN_00ADE5B0, _sfbuf_InitRingSj)
   */
  std::int32_t sfbuf_InitRingSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex,
    const std::int32_t extraBufferBytes
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t laneBufferBytes = bufferSizeTable[laneIndex];
    if (laneBufferBytes == 0) {
      (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 4, 0);
      return 0;
    }

    SfbufSjCreateStateView createState{};
    const std::int32_t status = sfbuf_CreateSj(
      reinterpret_cast<std::int32_t*>(&createState),
      bufferAddressTable[laneIndex],
      laneBufferBytes,
      extraBufferBytes
    );
    if (status != 0) {
      return status;
    }

    (void)sfbuf_SetSupSj(
      &laneView->sourceBufferAddress,
      reinterpret_cast<const std::int32_t*>(&createState),
      SjPointerToAddress(laneView),
      1
    );
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 5, 1);
    return 0;
  }

  /**
   * Address: 0x00ADE4B0 (FUN_00ADE4B0, _SFBUF_InitHn)
   */
  std::int32_t SFBUF_InitHn(
    const std::int32_t vfrmOwnerAddress,
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const sfbufInitConfigWords
  )
  {
    constexpr std::int32_t kSfbufRingLane0 = 0;
    constexpr std::int32_t kSfbufRingLane1 = 1;
    constexpr std::int32_t kSfbufRingLane2 = 2;
    constexpr std::int32_t kSfbufVfrmLane0 = 3;
    constexpr std::int32_t kSfbufAringLane0 = 4;
    constexpr std::int32_t kSfbufVfrmLane1 = 5;
    constexpr std::int32_t kSfbufAringLane1 = 6;
    constexpr std::int32_t kSfbufUoSjLane = 7;

    const auto* const initConfig = reinterpret_cast<const SfbufInitLayoutConfigView*>(sfbufInitConfigWords);
    const std::int32_t* const laneBufferSizes = initConfig->laneBufferSizes.data();
    std::array<std::int32_t, 8> laneBufferAddresses{};
    (void)sfbuf_MakeBufPtr(laneBufferAddresses.data(), laneBufferSizes, initConfig->baseBufferAddress);

    std::int32_t status = sfbuf_InitRingSj(
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufRingLane0,
      laneBufferSizes[0] % initConfig->lane0ExtraModuloDivisor
    );
    if (status != 0) {
      return status;
    }

    status = sfbuf_InitRingSj(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufRingLane1, 0x800);
    if (status != 0) {
      return status;
    }

    status = sfbuf_InitRingSj(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufRingLane2, 0);
    if (status != 0) {
      return status;
    }

    (void)sfbuf_InitVfrmBuf(
      vfrmOwnerAddress,
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufVfrmLane0
    );
    (void)sfbuf_InitAringBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufAringLane0);
    (void)sfbuf_InitVfrmBuf(
      vfrmOwnerAddress,
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufVfrmLane1
    );
    (void)sfbuf_InitAringBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufAringLane1);
    (void)sfbuf_InitUoSjBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufUoSjLane);
    return 0;
  }

  /**
   * Address: 0x00ADE9C0 (FUN_00ADE9C0, _sfbuf_ChkSupSj)
   */
  std::int32_t sfbuf_ChkSupSj(const std::int32_t* const supplyDescriptorWords)
  {
    if (supplyDescriptorWords[1] == 0) {
      return -1;
    }
    if (supplyDescriptorWords[0] != 0) {
      return 0;
    }
    if (supplyDescriptorWords[2] == 0) {
      return -1;
    }
    if (supplyDescriptorWords[3] <= 0) {
      return -1;
    }
    if (supplyDescriptorWords[5] <= 0) {
      return 0;
    }
    return -1;
  }

  /**
   * Address: 0x00ADEAC0 (FUN_00ADEAC0, _sfbuf_InitConti)
   */
  std::int32_t* sfbuf_InitConti(std::int32_t* const continuityStateWords)
  {
    continuityStateWords[0] = 0;
    continuityStateWords[1] = 0;
    return continuityStateWords;
  }

  /**
   * Address: 0x00ADEA60 (FUN_00ADEA60, _sfbuf_SetSupSj)
   */
  void sfbuf_SetSupSj(
    std::int32_t* const supplyLaneWords,
    const std::int32_t* const supplyDescriptorWords,
    const std::int32_t ownerLaneAddress,
    const std::int32_t setupState
  )
  {
    SFLIB_LockCs();
    auto* const laneOwner = reinterpret_cast<SfbufSupplyLaneView*>(SjAddressToPointer(ownerLaneAddress));
    laneOwner->isSetup = setupState;

    for (std::int32_t laneWord = 0; laneWord < 6; ++laneWord) {
      supplyLaneWords[laneWord] = supplyDescriptorWords[laneWord];
    }
    (void)sfbuf_InitConti(supplyLaneWords + 6);
    supplyLaneWords[8] = 0;
    supplyLaneWords[9] = 0;
    for (std::int32_t laneWord = 0; laneWord < 5; ++laneWord) {
      supplyLaneWords[10 + laneWord] = 0;
    }

    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEA00 (FUN_00ADEA00, _sfbuf_SetSupplySjSub)
   */
  std::int32_t sfbuf_SetSupplySjSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const supplyDescriptorWords,
    const std::int32_t transferLaneIndex
  )
  {
    constexpr std::int32_t kSfbufLaneStateAwaitingSupply = 4;
    constexpr std::int32_t kSfbufErrLaneNotAwaitingSupply = -16776183;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[transferLaneIndex];
    if (laneView->laneType != kSfbufLaneStateAwaitingSupply) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrLaneNotAwaitingSupply);
    }

    const std::int32_t setupState = (supplyDescriptorWords[1] != 0) ? 1 : 0;
    sfbuf_SetSupSj(
      &laneView->sourceBufferAddress,
      supplyDescriptorWords,
      SjPointerToAddress(laneView),
      setupState
    );
    return 0;
  }

  /**
   * Address: 0x00ADE930 (FUN_00ADE930, _SFBUF_SetSupplySj)
   */
  std::int32_t SFBUF_SetSupplySj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const supplyDescriptorWords
  )
  {
    constexpr std::int32_t kSfbufErrInvalidSupplyDescriptor = -16776184;

    const std::int32_t sfbufHandleAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    if (sfbuf_ChkSupSj(supplyDescriptorWords) != 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrInvalidSupplyDescriptor);
    }

    if (SFTRN_IsSetup(workctrlSubobj, 1) != 0) {
      return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, 0);
    }
    if (SFTRN_IsSetup(workctrlSubobj, 2) != 0) {
      return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, 1);
    }

    const std::int32_t transferLaneIndex = (SFTRN_IsSetup(workctrlSubobj, 3) != 0) ? 2 : 0;
    return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, transferLaneIndex);
  }

  /**
   * Address: 0x00ADEAE0 (FUN_00ADEAE0, _SFBUF_SetUoch)
   */
  std::int32_t* SFBUF_SetUoch(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t uochSlotIndex,
    const std::int32_t* const chunkDescriptorWords
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    auto* const uochEntry = reinterpret_cast<SfbufUochDescriptorView*>(
      &laneView->sourceBufferAddress + (uochSlotIndex * 4)
    );
    uochEntry->word0 = chunkDescriptorWords[0];
    uochEntry->word1 = chunkDescriptorWords[1];
    uochEntry->word2 = chunkDescriptorWords[2];
    uochEntry->word3 = chunkDescriptorWords[3];
    return &uochEntry->word0;
  }

  /**
   * Address: 0x00ADEB30 (FUN_00ADEB30, _SFBUF_GetUoch)
   */
  std::int32_t SFBUF_GetUoch(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t uochSlotIndex,
    std::int32_t* const outChunkDescriptorWords
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const auto* const uochEntry = reinterpret_cast<const SfbufUochDescriptorView*>(
      &laneView->sourceBufferAddress + (uochSlotIndex * 4)
    );
    outChunkDescriptorWords[0] = uochEntry->word0;
    outChunkDescriptorWords[1] = uochEntry->word1;
    outChunkDescriptorWords[2] = uochEntry->word2;
    outChunkDescriptorWords[3] = uochEntry->word3;
    return uochEntry->word3;
  }

  /**
   * Address: 0x00ADEB80 (FUN_00ADEB80, _SFBUF_GetRingSj)
   */
  std::int32_t SFBUF_GetRingSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    std::int32_t* const outRingHandleAddress
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    *outRingHandleAddress = runtimeView->lanes[laneIndex].sourceBufferBytes;
    return sfbufHandleAddress;
  }

  /**
   * Address: 0x00ADEBF0 (FUN_00ADEBF0, _sfbuf_RingGetSub)
   */
  std::int32_t sfbuf_RingGetSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursorWords,
    const std::int32_t laneMode
  )
  {
    auto* const outCursor = reinterpret_cast<SfbufRingCursorSnapshotView*>(outCursorWords);
    outCursor->firstChunk = {};
    outCursor->secondChunk = {};
    outCursor->reservedWords = {0, 0, 0};

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if ((laneView->isSetup != 0) && (laneView->sourceBufferBytes != 0)) {
      (void)sfbuf_PeekChunk(
        laneView->sourceBufferBytes,
        laneMode,
        &outCursor->firstChunk,
        &outCursor->secondChunk
      );
    }
    return 0;
  }

  /**
   * Address: 0x00ADECB0 (FUN_00ADECB0, _sfbuf_RingAddSub)
   */
  std::int32_t sfbuf_RingAddSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount,
    const std::int32_t laneMode
  )
  {
    constexpr std::int32_t kSfbufErrAdvanceMismatch = -16776181;

    std::int32_t status = 0;
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if ((advanceCount == 0) || (laneView->isSetup == 0) || (laneView->sourceBufferBytes == 0)) {
      return 0;
    }

    const std::int32_t movedBytes = sfbuf_MoveChunk(laneView->sourceBufferBytes, laneMode, advanceCount);
    if (movedBytes < advanceCount) {
      const std::int32_t remainingBytes = advanceCount - movedBytes;
      if (sfbuf_MoveChunk(laneView->sourceBufferBytes, laneMode, remainingBytes) < remainingBytes) {
        status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAdvanceMismatch);
      }
    }

    if (laneMode == 1) {
      if (ringIndex == 1) {
        (void)sfbuf_ResetConti(&laneView->sourceBufferAddress);
      }
      if (laneView->readTotalBytes >= 0) {
        laneView->readTotalBytes += advanceCount;
      }
    } else if (laneView->writeTotalBytes >= 0) {
      laneView->writeTotalBytes += advanceCount;
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return status;
  }

  /**
   * Address: 0x00ADEDA0 (FUN_00ADEDA0, _sfbuf_ResetConti)
   */
  std::uint32_t sfbuf_ResetConti(std::int32_t* const supplyStateWords)
  {
    auto* const supplyState = reinterpret_cast<SfbufSupplyStateWindowView*>(supplyStateWords);
    moho::SjChunkRange firstChunk{};
    moho::SjChunkRange secondChunk{};
    (void)sfbuf_PeekChunk(supplyState->ringHandleAddress, 1, &firstChunk, &secondChunk);

    const std::uint32_t delimiterAddress = static_cast<std::uint32_t>(supplyState->delimiterPrimaryAddress);
    if (
      !SfbufContainsAddress(firstChunk, delimiterAddress)
      && !SfbufContainsAddress(secondChunk, delimiterAddress)
    ) {
      supplyState->delimiterPrimaryAddress = 0;
      supplyState->delimiterSecondaryAddress = 0;
      return 0;
    }
    return delimiterAddress;
  }

  /**
   * Address: 0x00ADEE00 (FUN_00ADEE00, _sfbuf_PeekChunk)
   */
  std::int32_t sfbuf_PeekChunk(
    const std::int32_t ringHandleAddress,
    const std::int32_t laneMode,
    moho::SjChunkRange* const outFirstChunk,
    moho::SjChunkRange* const outSecondChunk
  )
  {
    constexpr std::int32_t kSfbufPeekAllBytes = 0x7FFFFFFF;

    auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(ringHandleAddress));
    const std::int32_t availableBytes = SJRBF_GetNumData(ringHandle, laneMode);
    SJRBF_GetChunk(ringHandle, laneMode, kSfbufPeekAllBytes, outFirstChunk);
    if (outFirstChunk->byteCount >= availableBytes) {
      outSecondChunk->bufferAddress = 0;
      outSecondChunk->byteCount = 0;
    } else {
      SJRBF_GetChunk(ringHandle, laneMode, kSfbufPeekAllBytes, outSecondChunk);
      SJRBF_UngetChunk(ringHandle, laneMode, outSecondChunk);
    }
    SJRBF_UngetChunk(ringHandle, laneMode, outFirstChunk);
    return availableBytes;
  }

  /**
   * Address: 0x00ADEE90 (FUN_00ADEE90, _sfbuf_MoveChunk)
   */
  std::int32_t sfbuf_MoveChunk(
    const std::int32_t ringHandleAddress,
    const std::int32_t laneMode,
    const std::int32_t requestedBytes
  )
  {
    auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(ringHandleAddress));
    moho::SjChunkRange chunk{};
    SJRBF_GetChunk(ringHandle, laneMode, requestedBytes, &chunk);
    const std::int32_t outputLane = (laneMode == 0) ? 1 : 0;
    SJRBF_PutChunk(ringHandle, outputLane, &chunk);
    return chunk.byteCount;
  }

  /**
   * Address: 0x00ADEBB0 (FUN_00ADEBB0, _SFBUF_RingGetWrite)
   */
  std::int32_t SFBUF_RingGetWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursor
  )
  {
    return sfbuf_RingGetSub(sfbufHandleAddress, ringIndex, outCursor, 0);
  }

  /**
   * Address: 0x00ADEBD0 (FUN_00ADEBD0, _SFBUF_RingGetRead)
   */
  std::int32_t SFBUF_RingGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursor
  )
  {
    return sfbuf_RingGetSub(sfbufHandleAddress, ringIndex, outCursor, 1);
  }

  /**
   * Address: 0x00ADEC80 (FUN_00ADEC80, _SFBUF_RingAddWrite)
   */
  std::int32_t SFBUF_RingAddWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount
  )
  {
    return sfbuf_RingAddSub(sfbufHandleAddress, ringIndex, advanceCount, 0);
  }

  /**
   * Address: 0x00ADEC90 (FUN_00ADEC90, _SFBUF_RingAddRead)
   */
  std::int32_t SFBUF_RingAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount
  )
  {
    return sfbuf_RingAddSub(sfbufHandleAddress, ringIndex, advanceCount, 1);
  }

  /**
   * Address: 0x00ADEED0 (FUN_00ADEED0, _SFBUF_RingGetDlm)
   */
  void SFBUF_RingGetDlm(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outPrimaryDelimiterAddress,
    std::int32_t* const outSecondaryDelimiterAddress
  )
  {
    SFLIB_LockCs();
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    *outPrimaryDelimiterAddress = laneView->delimiterPrimaryAddress;
    *outSecondaryDelimiterAddress = laneView->delimiterSecondaryAddress;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEF20 (FUN_00ADEF20, _SFBUF_RingSetDlm)
   */
  void SFBUF_RingSetDlm(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t primaryDelimiterAddress,
    const std::int32_t secondaryDelimiterAddress
  )
  {
    SFLIB_LockCs();
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    laneView->delimiterPrimaryAddress = primaryDelimiterAddress;
    laneView->delimiterSecondaryAddress = secondaryDelimiterAddress;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEFB0 (FUN_00ADEFB0, _SFBUF_GetWTot)
   */
  std::int32_t SFBUF_GetWTot(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    constexpr std::int32_t kSfbufTotalSaturated = 0x7FFFFFFF;

    SFLIB_LockCs();
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];

    std::int32_t totalWriteBytes = laneView->writeTotalBytes;
    const std::int32_t totalReadBytes = laneView->readTotalBytes;
    if (totalWriteBytes == 0) {
      if (totalReadBytes != 0) {
        auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(laneView->sourceBufferBytes));
        totalWriteBytes = totalReadBytes + SJRBF_GetNumData(ringHandle, 1);
      }
    }
    if (totalWriteBytes < 0) {
      totalWriteBytes = kSfbufTotalSaturated;
    }

    SFLIB_UnlockCs();
    return totalWriteBytes;
  }

  /**
   * Address: 0x00ADF020 (FUN_00ADF020, _SFBUF_RingGetSj)
   */
  std::int32_t SFBUF_RingGetSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outRingHandleAddress
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    *outRingHandleAddress = 0;
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }
    *outRingHandleAddress = laneView->sourceBufferBytes;
    return 0;
  }

  /**
   * Address: 0x00ADF070 (FUN_00ADF070, _SFBUF_AddRtotSj)
   */
  std::int32_t* SFBUF_AddRtotSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addBytes
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->readTotalBytes >= 0) {
      laneView->readTotalBytes += addBytes;
    }
    return &laneView->sourceBufferAddress;
  }

  /**
   * Address: 0x00ADF0A0 (FUN_00ADF0A0, _SFBUF_AringGetWrite)
   */
  std::int32_t SFBUF_AringGetWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outAringSnapshotWords
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    SFLIB_LockCs();
    const auto* const aringState = reinterpret_cast<const SfbufAringLaneStateView*>(&laneView->laneParam18);
    const std::int32_t transferParam0 = aringState->transferParam0;
    const std::int32_t sampleMode = aringState->sampleMode;
    const std::int32_t transferParam2 = aringState->transferParam2;
    const std::int32_t primarySampleBaseAddress = aringState->primarySampleBaseAddress;
    const std::int32_t secondarySampleBaseAddress = aringState->secondarySampleBaseAddress;
    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    const std::int32_t writeCursorSamples = aringState->writeCursorSamples;
    const std::int32_t readCursorSamples = aringState->readCursorSamples;
    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t readTotalSamples = aringState->readTotalSamples;
    SFLIB_UnlockCs();

    auto* const outSnapshot = reinterpret_cast<SfbufAringTransferSnapshotView*>(outAringSnapshotWords);
    outSnapshot->transferParam0 = transferParam0;
    outSnapshot->sampleMode = sampleMode;
    outSnapshot->transferParam2 = transferParam2;
    outSnapshot->writeTotalSamples = writeTotalSamples;
    outSnapshot->readTotalSamples = readTotalSamples;

    if (writeTotalSamples < (ringCapacitySamples + readTotalSamples)) {
      if (writeCursorSamples >= readCursorSamples) {
        outSnapshot->chunkSampleCount = ringCapacitySamples - writeCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, writeCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, writeCursorSamples);
        outSnapshot->wrapCursorSample = readCursorSamples;
        outSnapshot->primaryWrapAddress = primarySampleBaseAddress;
        outSnapshot->secondaryWrapAddress = secondarySampleBaseAddress;
      } else {
        outSnapshot->chunkSampleCount = readCursorSamples - writeCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, writeCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, writeCursorSamples);
        outSnapshot->wrapCursorSample = 0;
        outSnapshot->primaryWrapAddress = 0;
        outSnapshot->secondaryWrapAddress = 0;
      }
    } else {
      outSnapshot->chunkSampleCount = 0;
      outSnapshot->primaryChunkAddress = 0;
      outSnapshot->secondaryChunkAddress = 0;
      outSnapshot->wrapCursorSample = 0;
      outSnapshot->primaryWrapAddress = 0;
      outSnapshot->secondaryWrapAddress = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADF220 (FUN_00ADF220, _SFBUF_AringAddWrite)
   */
  std::int32_t SFBUF_AringAddWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addSamples
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;
    constexpr std::int32_t kSfbufErrAringWriteOverflow = -16776186;

    if (addSamples == 0) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    std::int32_t status = 0;
    SFLIB_LockCs();
    auto* const aringState = reinterpret_cast<SfbufAringLaneStateView*>(&laneView->laneParam18);

    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    std::int32_t nextWriteCursor = addSamples + aringState->writeCursorSamples;
    if (nextWriteCursor >= ringCapacitySamples) {
      nextWriteCursor -= ringCapacitySamples;
    }
    aringState->writeCursorSamples = nextWriteCursor;

    const std::int32_t nextWriteTotal = addSamples + aringState->writeTotalSamples;
    const std::int32_t maxWriteTotal = ringCapacitySamples + aringState->readTotalSamples;
    aringState->writeTotalSamples = nextWriteTotal;
    if (nextWriteTotal > maxWriteTotal) {
      status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAringWriteOverflow);
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    SFLIB_UnlockCs();
    return status;
  }

  /**
   * Address: 0x00ADF2D0 (FUN_00ADF2D0, _SFBUF_AringGetRead)
   */
  std::int32_t SFBUF_AringGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outAringSnapshotWords
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    SFLIB_LockCs();
    const auto* const aringState = reinterpret_cast<const SfbufAringLaneStateView*>(&laneView->laneParam18);
    const std::int32_t transferParam0 = aringState->transferParam0;
    const std::int32_t sampleMode = aringState->sampleMode;
    const std::int32_t transferParam2 = aringState->transferParam2;
    const std::int32_t primarySampleBaseAddress = aringState->primarySampleBaseAddress;
    const std::int32_t secondarySampleBaseAddress = aringState->secondarySampleBaseAddress;
    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    const std::int32_t writeCursorSamples = aringState->writeCursorSamples;
    const std::int32_t readCursorSamples = aringState->readCursorSamples;
    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t readTotalSamples = aringState->readTotalSamples;
    SFLIB_UnlockCs();

    auto* const outSnapshot = reinterpret_cast<SfbufAringTransferSnapshotView*>(outAringSnapshotWords);
    outSnapshot->transferParam0 = transferParam0;
    outSnapshot->sampleMode = sampleMode;
    outSnapshot->transferParam2 = transferParam2;
    outSnapshot->writeTotalSamples = writeTotalSamples;
    outSnapshot->readTotalSamples = readTotalSamples;

    if (writeTotalSamples > readTotalSamples) {
      if (readCursorSamples >= writeCursorSamples) {
        outSnapshot->chunkSampleCount = ringCapacitySamples - readCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, readCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, readCursorSamples);
        outSnapshot->wrapCursorSample = writeCursorSamples;
        outSnapshot->primaryWrapAddress = primarySampleBaseAddress;
        outSnapshot->secondaryWrapAddress = secondarySampleBaseAddress;
      } else {
        outSnapshot->chunkSampleCount = writeCursorSamples - readCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, readCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, readCursorSamples);
        outSnapshot->wrapCursorSample = 0;
        outSnapshot->primaryWrapAddress = 0;
        outSnapshot->secondaryWrapAddress = 0;
      }
    } else {
      outSnapshot->chunkSampleCount = 0;
      outSnapshot->primaryChunkAddress = 0;
      outSnapshot->secondaryChunkAddress = 0;
      outSnapshot->wrapCursorSample = 0;
      outSnapshot->primaryWrapAddress = 0;
      outSnapshot->secondaryWrapAddress = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADF450 (FUN_00ADF450, _SFBUF_AringAddRead)
   */
  std::int32_t SFBUF_AringAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addSamples
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;
    constexpr std::int32_t kSfbufErrAringReadOverflow = -16776185;

    if (addSamples == 0) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    std::int32_t status = 0;
    SFLIB_LockCs();
    auto* const aringState = reinterpret_cast<SfbufAringLaneStateView*>(&laneView->laneParam18);

    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    std::int32_t nextReadCursor = addSamples + aringState->readCursorSamples;
    if (nextReadCursor >= ringCapacitySamples) {
      nextReadCursor -= ringCapacitySamples;
    }
    aringState->readCursorSamples = nextReadCursor;

    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t nextReadTotal = addSamples + aringState->readTotalSamples;
    aringState->readTotalSamples = nextReadTotal;
    if (nextReadTotal > writeTotalSamples) {
      status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAringReadOverflow);
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    SFLIB_UnlockCs();
    return status;
  }

  /**
   * Address: 0x00ADF500 (FUN_00ADF500, _SFBUF_VfrmGetWrite)
   */
  std::int32_t SFBUF_VfrmGetWrite()
  {
    return 0;
  }

  /**
   * Address: 0x00ADF510 (FUN_00ADF510, _SFBUF_VfrmAddWrite)
   */
  std::int32_t SFBUF_VfrmAddWrite(const std::int32_t sfbufHandleAddress)
  {
    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00ADF520 (FUN_00ADF520, _SFBUF_VfrmGetRead)
   */
  std::int32_t SFBUF_VfrmGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    if (laneView->isSetup != 0) {
      return 0;
    }
    return SFTRN_CallTrtTrif(sfbufHandleAddress, laneView->runtimeState0, 11, arg0, arg1);
  }

  /**
   * Address: 0x00ADF570 (FUN_00ADF570, _SFBUF_VfrmAddRead)
   */
  std::int32_t SFBUF_VfrmAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    std::int32_t result = 0;
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    if (laneView->isSetup == 0) {
      result = SFTRN_CallTrtTrif(sfbufHandleAddress, laneView->runtimeState0, 12, arg0, arg1);
    }
    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return result;
  }

  /**
   * Address: 0x00ADF5C0 (FUN_00ADF5C0, _SFBUF_SetPrepFlg)
   */
  std::int32_t SFBUF_SetPrepFlg(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t prepFlag
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeView->lanes[laneIndex].prepFlag = prepFlag;
    return prepFlag;
  }

  /**
   * Address: 0x00ADF5E0 (FUN_00ADF5E0, _SFBUF_GetPrepFlg)
   */
  std::int32_t SFBUF_GetPrepFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[laneIndex].prepFlag;
  }

  /**
   * Address: 0x00ADF600 (FUN_00ADF600, _SFBUF_SetTermFlg)
   */
  std::int32_t SFBUF_SetTermFlg(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t termFlag
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeView->lanes[laneIndex].termFlag = termFlag;
    return termFlag;
  }

  /**
   * Address: 0x00ADF620 (FUN_00ADF620, _SFBUF_GetTermFlg)
   */
  std::int32_t SFBUF_GetTermFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[laneIndex].termFlag;
  }

  /**
   * Address: 0x00ADF640 (FUN_00ADF640, _SFBUF_GetRingBufSiz)
   */
  std::int32_t SFBUF_GetRingBufSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    SfbufRingCursorSnapshotView ringSnapshot{};
    (void)SFBUF_RingGetRead(sfbufHandleAddress, ringIndex, reinterpret_cast<std::int32_t*>(&ringSnapshot));
    return ringSnapshot.firstChunk.byteCount + ringSnapshot.secondChunk.byteCount;
  }

  /**
   * Address: 0x00ADF670 (FUN_00ADF670, _SFBUF_RingGetFreeSiz)
   */
  std::int32_t SFBUF_RingGetFreeSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    SfbufRingCursorSnapshotView ringSnapshot{};
    (void)SFBUF_RingGetWrite(sfbufHandleAddress, ringIndex, reinterpret_cast<std::int32_t*>(&ringSnapshot));
    return ringSnapshot.firstChunk.byteCount + ringSnapshot.secondChunk.byteCount;
  }

  /**
   * Address: 0x00ADF720 (FUN_00ADF720, _sfbuf_InitSjUuid)
   */
  std::int32_t sfbuf_InitSjUuid()
  {
    constexpr std::int32_t kProbeBufferBytes = 8;
    std::array<std::int32_t, 2> probeBufferWords{};

    auto* const ringBufferHandle =
      SJRBF_Create(SjPointerToAddress(probeBufferWords.data()), kProbeBufferBytes, 0);
    gSfbufSjRingBufferUuid = SJRBF_GetUuid(ringBufferHandle);
    SJRBF_Destroy(ringBufferHandle);

    auto* const memoryHandle = SJMEM_Create(SjPointerToAddress(probeBufferWords.data()), kProbeBufferBytes);
    gSfbufSjMemoryUuid = SJMEM_GetUuid(memoryHandle);
    SJMEM_Destroy(memoryHandle);
    return 0;
  }

  /**
   * Address: 0x00ADF770 (FUN_00ADF770, _sfbuf_IsSjRbf)
   */
  std::int32_t sfbuf_IsSjRbf(const std::int32_t sjHandleAddress)
  {
    auto* const ringBufferHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(sjHandleAddress));
    return (SJRBF_GetUuid(ringBufferHandle) == gSfbufSjRingBufferUuid) ? 1 : 0;
  }

  /**
   * Address: 0x00ADF790 (FUN_00ADF790, _sfbuf_IsSjMem)
   */
  std::int32_t sfbuf_IsSjMem(const std::int32_t sjHandleAddress)
  {
    auto* const memoryHandle = reinterpret_cast<moho::SofdecSjMemoryHandle*>(SjAddressToPointer(sjHandleAddress));
    return (SJMEM_GetUuid(memoryHandle) == gSfbufSjMemoryUuid) ? 1 : 0;
  }

  /**
   * Address: 0x00ADF6A0 (FUN_00ADF6A0, _SFBUF_GetFlowCnt)
   */
  std::int32_t SFBUF_GetFlowCnt(
    const std::int32_t sjHandleAddress,
    std::int32_t* const outLane1FlowCount,
    std::int32_t* const outLane0FlowCount
  )
  {
    if (sfbuf_IsSjRbf(sjHandleAddress) != 0) {
      auto* const ringBufferHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(sjHandleAddress));
      *outLane1FlowCount = SJRBF_GetFlowCnt(ringBufferHandle, 1, 1);
      const std::int32_t lane0FlowCount = SJRBF_GetFlowCnt(ringBufferHandle, 0, 1);
      *outLane0FlowCount = lane0FlowCount;
      return lane0FlowCount;
    }

    if (sfbuf_IsSjMem(sjHandleAddress) != 0) {
      auto* const memoryHandle = reinterpret_cast<moho::SofdecSjMemoryHandle*>(SjAddressToPointer(sjHandleAddress));
      *outLane1FlowCount = SJMEM_GetBufSize(memoryHandle);
      const std::int32_t pendingBytes = SJMEM_GetNumData(memoryHandle, 1);
      *outLane0FlowCount = *outLane1FlowCount - pendingBytes;
      return pendingBytes;
    }

    *outLane1FlowCount = 0;
    *outLane0FlowCount = 0;
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outLane1FlowCount));
  }

  /**
   * Address: 0x00ADF7B0 (FUN_00ADF7B0, _SFBUF_UpdateFlowCnt)
   */
  std::int64_t SFBUF_UpdateFlowCnt(
    const std::int32_t previousFlowLow,
    const std::int32_t previousFlowHigh,
    const std::int32_t nextFlowLow
  )
  {
    const std::uint32_t previousLow = static_cast<std::uint32_t>(previousFlowLow);
    const std::uint32_t nextLow = static_cast<std::uint32_t>(nextFlowLow);
    const std::uint32_t nextHigh = static_cast<std::uint32_t>(previousFlowHigh) + ((nextLow < previousLow) ? 1u : 0u);
    return static_cast<std::int64_t>((static_cast<std::uint64_t>(nextHigh) << 32u) | nextLow);
  }

  /**
   * Address: 0x00ADF7F0 (FUN_00ADF7F0, _SFTRN_Init)
   */
  std::int32_t SFTRN_Init(void* const outTransferEntryTable, void* const transferEntryTable)
  {
    auto* const outEntryList = reinterpret_cast<SftrnEntryListView*>(outTransferEntryTable);
    auto* const sourceEntryList = reinterpret_cast<SftrnEntryListView*>(transferEntryTable);
    std::memcpy(outEntryList, sourceEntryList, sizeof(SftrnEntryListView));
    return sftrn_CallTrEntry(sourceEntryList, 0);
  }

  /**
   * Address: 0x00ADF820 (FUN_00ADF820, _SFTRN_Finish)
   */
  std::int32_t SFTRN_Finish(void* const transferEntryTable)
  {
    return sftrn_CallTrEntry(transferEntryTable, 1);
  }

  /**
   * Address: 0x00ADF830 (FUN_00ADF830, _sftrn_CallTrEntry)
   */
  std::int32_t sftrn_CallTrEntry(void* const transferEntryTable, const std::int32_t entrySelector)
  {
    auto* const entryList = reinterpret_cast<SftrnEntryListView*>(transferEntryTable);
    std::int32_t result = 0;
    for (std::int32_t entryIndex = 0; entryIndex < static_cast<std::int32_t>(entryList->entries.size()); ++entryIndex) {
      SftrnEntryDispatchView* const entryDispatch = entryList->entries[entryIndex];
      if (entryDispatch == nullptr) {
        break;
      }
      result = entryDispatch->entryCallbacks[entrySelector](0, 0, 0, 0);
      if (result != 0) {
        break;
      }
    }
    return result;
  }

  /**
   * Address: 0x00ADF870 (FUN_00ADF870, _SFTRN_InitHn)
   */
  std::int32_t SFTRN_InitHn(
    const std::int32_t workctrlAddress,
    const std::int32_t transferDataArrayAddress,
    const std::int32_t* const transferBuildConfigAddressPtr
  )
  {
    constexpr std::int32_t kSftrnTransferLaneCount = 9;
    constexpr std::int32_t kSftrnErrBuildFailed = -16776446;

    const std::int32_t transferBuildConfigAddress = *transferBuildConfigAddressPtr;
    auto* const transferLanes = reinterpret_cast<SftrnTransferDataLaneView*>(SjAddressToPointer(transferDataArrayAddress));
    const auto* const transferBuildConfigWords =
      reinterpret_cast<const std::int32_t*>(SjAddressToPointer(transferBuildConfigAddress));

    for (std::int32_t laneIndex = 0; laneIndex < kSftrnTransferLaneCount; ++laneIndex) {
      transferLanes[laneIndex].setupState = 0;
      (void)sftrn_InitTrData(
        reinterpret_cast<std::int32_t*>(&transferLanes[laneIndex]),
        transferBuildConfigWords[laneIndex]
      );
    }

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (sftrn_BuildAll(workctrlSubobj, transferBuildConfigWords) != 0) {
      return SFLIB_SetErr(workctrlAddress, kSftrnErrBuildFailed);
    }
    return 0;
  }

  /**
   * Address: 0x00ADF8D0 (FUN_00ADF8D0, _sftrn_InitTrData)
   */
  std::int32_t* sftrn_InitTrData(std::int32_t* const transferDataWords, const std::int32_t transferDescriptorAddress)
  {
    auto* const transferLane = reinterpret_cast<SftrnTransferDataLaneView*>(transferDataWords);
    transferLane->termFlag = 0;
    transferLane->prepFlag = 0;
    transferLane->transferDescriptorAddress = transferDescriptorAddress;
    transferLane->sourceLaneIndex = 8;
    transferLane->targetLaneIndex0 = 8;
    transferLane->targetLaneIndex1 = 8;
    transferLane->targetLaneIndex2 = 8;
    transferLane->transferEndState = -1;
    return transferDataWords;
  }

  /**
   * Address: 0x00ADF910 (FUN_00ADF910, _sftrn_BuildAll)
   */
  std::int32_t sftrn_BuildAll(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;

    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    auto* const workctrlState = reinterpret_cast<SftrnWorkctrlStateView*>(workctrlSubobj);

    if (transferBuildConfig->hasSystemLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 0);
      (void)sftrn_BuildSystem(workctrlSubobj, transferBuildConfigWords);
      return 0;
    }
    if (transferBuildConfig->hasAudioLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 1);
      (void)sftrn_BuildAudio(workctrlSubobj, transferBuildConfigWords);
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      workctrlState->videoConditionState = 0;
      return 0;
    }
    if (transferBuildConfig->hasVideoLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 2);
      (void)sftrn_BuildVideo(workctrlSubobj, transferBuildConfigWords);
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
      return 0;
    }
    if (transferBuildConfig->hasUserLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 7);
      (void)sftrn_BuildUsr(workctrlSubobj);
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
      workctrlState->videoConditionState = 0;
      return 0;
    }
    return -1;
  }

  /**
   * Address: 0x00ADF9F0 (FUN_00ADF9F0, _sftrn_BuildSystem)
   */
  std::int32_t sftrn_BuildSystem(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;

    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    auto* const workctrlState = reinterpret_cast<SftrnWorkctrlStateView*>(workctrlSubobj);

    (void)sftrn_ConnBufTrn(workctrlSubobj, 0, 1);
    if (transferBuildConfig->hasAudioLane != 0) {
      (void)sftrn_ConnTrnBufV(workctrlSubobj, 1, 1);
      (void)sftrn_BuildAudio(workctrlSubobj, transferBuildConfigWords);
    } else {
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
    }

    if (transferBuildConfig->hasVideoLane != 0) {
      (void)sftrn_ConnTrnBufA(workctrlSubobj, 1, 2);
      (void)sftrn_BuildVideo(workctrlSubobj, transferBuildConfigWords);
    } else {
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      workctrlState->videoConditionState = 0;
    }

    const std::int32_t hasUserLane = transferBuildConfig->hasUserLane;
    if (hasUserLane != 0) {
      (void)sftrn_ConnTrnBufU(workctrlSubobj, 1, 7);
      return sftrn_BuildUsr(workctrlSubobj);
    }
    return hasUserLane;
  }

  /**
   * Address: 0x00ADFA90 (FUN_00ADFA90, _sftrn_BuildAudio)
   */
  std::int32_t sftrn_BuildAudio(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    (void)sftrn_ConnBufTrn(workctrlSubobj, 1, 2);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 2, 3);
    if (transferBuildConfig->hasAudioExtendedLane == 0) {
      return sftrn_ConnBufTrn(workctrlSubobj, 3, 6);
    }
    (void)sftrn_ConnBufTrn(workctrlSubobj, 3, 4);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 4, 5);
    return sftrn_ConnBufTrn(workctrlSubobj, 5, 6);
  }

  /**
   * Address: 0x00ADFAF0 (FUN_00ADFAF0, _sftrn_BuildVideo)
   */
  std::int32_t sftrn_BuildVideo(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    (void)sftrn_ConnBufTrn(workctrlSubobj, 2, 3);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 3, 4);
    if (transferBuildConfig->hasVideoExtendedLane == 0) {
      return sftrn_ConnBufTrn(workctrlSubobj, 4, 7);
    }
    (void)sftrn_ConnBufTrn(workctrlSubobj, 4, 5);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 5, 6);
    return sftrn_ConnBufTrn(workctrlSubobj, 6, 7);
  }

  /**
   * Address: 0x00ADFB50 (FUN_00ADFB50, _sftrn_BuildUsr)
   */
  std::int32_t sftrn_BuildUsr(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return sftrn_ConnBufTrn(workctrlSubobj, 7, 8);
  }

  /**
   * Address: 0x00AD88A0 (FUN_00AD88A0, _sfset_IsCondValid)
   *
   * What it does:
   * Validates condition updates that require transfer-lane setup and returns
   * non-zero when the condition write is allowed.
   */
  std::int32_t sfset_IsCondValid(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;
    constexpr std::int32_t kSfsetConditionEnabled = 1;

    if (conditionId == kSfsetVideoCondition && value == kSfsetConditionEnabled) {
      return SFTRN_IsSetup(workctrlSubobj, 3) != 0 ? 1 : 0;
    }
    if (conditionId == kSfsetAudioCondition && value == kSfsetConditionEnabled) {
      return SFTRN_IsSetup(workctrlSubobj, 2) != 0 ? 1 : 0;
    }
    return 1;
  }

  /**
   * Address: 0x00AD8840 (FUN_00AD8840, _SFSET_SetCond)
   *
   * What it does:
   * Validates one condition write and stores it in the work-control condition
   * array when allowed.
   */
  std::int32_t SFSET_SetCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    const std::int32_t valid = sfset_IsCondValid(workctrlSubobj, conditionId, value);
    if (valid != 0) {
      auto* const conditionState = reinterpret_cast<SfsetConditionStateView*>(workctrlSubobj);
      conditionState->setConditions[conditionId] = value;
    }
    return valid;
  }

  /**
   * Address: 0x00AD8940 (FUN_00AD8940, _SFSET_GetCond)
   *
   * What it does:
   * Returns one stored condition value from the work-control condition array.
   */
  std::int32_t SFSET_GetCond(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t conditionId)
  {
    const auto* const conditionState = reinterpret_cast<const SfsetConditionStateView*>(workctrlSubobj);
    return conditionState->setConditions[conditionId];
  }

  /**
   * Address: 0x00AD88E0 (FUN_00AD88E0, _SFD_GetCond)
   *
   * What it does:
   * Reads one condition lane from a valid SFD work-control handle, or from
   * process-global default conditions when handle is null.
   */
  std::int32_t SFD_GetCond(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    std::int32_t* const outConditionValue
  )
  {
    if (workctrlSubobj != nullptr) {
      if (SFLIB_CheckHn(workctrlSubobj) != 0) {
        return SFLIB_SetErr(0, kSflibErrInvalidHandleGetCond);
      }

      *outConditionValue = SFSET_GetCond(workctrlSubobj, conditionId);
      return 0;
    }

    *outConditionValue = static_cast<std::int32_t>(gSflibLibWork.defaultConditions[conditionId]);
    return 0;
  }

  /**
   * Address: 0x00ADFB70 (FUN_00ADFB70, _sftrn_ConnTrnBuf0)
   */
  std::int32_t sftrn_ConnTrnBuf0(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 0, targetLane);
  }

  /**
   * Address: 0x00ADFB90 (FUN_00ADFB90, _sftrn_ConnTrnBufV)
   */
  std::int32_t sftrn_ConnTrnBufV(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 0, targetLane);
  }

  /**
   * Address: 0x00ADFBB0 (FUN_00ADFBB0, _sftrn_ConnTrnBufA)
   */
  std::int32_t sftrn_ConnTrnBufA(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 1, targetLane);
  }

  /**
   * Address: 0x00ADFBD0 (FUN_00ADFBD0, _sftrn_ConnTrnBufU)
   */
  std::int32_t sftrn_ConnTrnBufU(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    return sftrn_ConnTrnBuf(workctrlSubobj, sourceLane, 2, targetLane);
  }

  /**
   * Address: 0x00ADFBF0 (FUN_00ADFBF0, _sftrn_ConnTrnBuf)
   */
  std::int32_t sftrn_ConnTrnBuf(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t transferSlot,
    const std::int32_t targetLane
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(workctrlSubobj);
    auto* const sfbufRuntime = reinterpret_cast<SfbufRuntimeHandleView*>(workctrlSubobj);

    SftrnTransferDataLaneView* const sourceTransferLane = &transferRuntime->transferLanes[sourceLane];
    (&sourceTransferLane->targetLaneIndex0)[transferSlot] = targetLane;
    sfbufRuntime->lanes[targetLane].runtimeState0 = sourceLane;
    return 29 * targetLane;
  }

  /**
   * Address: 0x00ADFC30 (FUN_00ADFC30, _sftrn_ConnBufTrn)
   */
  std::int32_t sftrn_ConnBufTrn(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t sourceLane,
    const std::int32_t targetLane
  )
  {
    auto* const sfbufRuntime = reinterpret_cast<SfbufRuntimeHandleView*>(workctrlSubobj);
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(workctrlSubobj);

    sfbufRuntime->lanes[sourceLane].runtimeState1 = targetLane;
    transferRuntime->transferLanes[targetLane].sourceLaneIndex = sourceLane;
    return sourceLane;
  }

  /**
   * Address: 0x00ADFC60 (FUN_00ADFC60, _SFTRN_CallTrSetup)
   */
  std::int32_t SFTRN_CallTrSetup(const std::int32_t workctrlAddress, const std::int32_t callbackIndex)
  {
    using SftrnTransferCallback =
      std::int32_t(__cdecl*)(std::int32_t workctrlArg, std::int32_t arg0, std::int32_t arg1, std::int32_t arg2);

    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    std::int32_t result = 0;
    for (std::int32_t laneIndex = 0; laneIndex < static_cast<std::int32_t>(transferRuntime->transferLanes.size()); ++laneIndex) {
      const std::int32_t descriptorAddress = transferRuntime->transferLanes[laneIndex].transferDescriptorAddress;
      if (descriptorAddress != 0) {
        auto* const callbacks = reinterpret_cast<SftrnTransferCallback*>(SjAddressToPointer(descriptorAddress));
        result = callbacks[callbackIndex](workctrlAddress, 0, 0, 0);
        if (result != 0) {
          break;
        }
      }
    }
    return result;
  }

  /**
   * Address: 0x00ADFCA0 (FUN_00ADFCA0, _SFTRN_CallTrtTrif)
   */
  std::int32_t SFTRN_CallTrtTrif(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t callbackIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    using SftrnTransferCallback =
      std::int32_t(__cdecl*)(std::int32_t workctrlArg, std::int32_t arg0, std::int32_t arg1, std::int32_t arg2);

    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    const std::int32_t descriptorAddress = transferRuntime->transferLanes[transferLaneIndex].transferDescriptorAddress;
    if (descriptorAddress == 0) {
      return 0;
    }

    auto* const callbacks = reinterpret_cast<SftrnTransferCallback*>(SjAddressToPointer(descriptorAddress));
    return callbacks[callbackIndex](workctrlAddress, arg0, arg1, 0);
  }

  /**
   * Address: 0x00ADFCE0 (FUN_00ADFCE0, _SFTRN_SetPrepFlg)
   */
  std::int32_t SFTRN_SetPrepFlg(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t prepFlag
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    transferRuntime->transferLanes[transferLaneIndex].prepFlag = prepFlag;
    return workctrlAddress;
  }

  /**
   * Address: 0x00ADFD00 (FUN_00ADFD00, _SFTRN_GetPrepFlg)
   */
  std::int32_t SFTRN_GetPrepFlg(const std::int32_t workctrlAddress, const std::int32_t transferLaneIndex)
  {
    const auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return transferRuntime->transferLanes[transferLaneIndex].prepFlag;
  }

  /**
   * Address: 0x00ADFD20 (FUN_00ADFD20, _SFTRN_SetTermFlg)
   */
  std::int32_t SFTRN_SetTermFlg(
    const std::int32_t workctrlAddress,
    const std::int32_t transferLaneIndex,
    const std::int32_t termFlag
  )
  {
    auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    transferRuntime->transferLanes[transferLaneIndex].termFlag = termFlag;
    return workctrlAddress;
  }

  /**
   * Address: 0x00ADFD40 (FUN_00ADFD40, _SFTRN_GetTermFlg)
   */
  std::int32_t SFTRN_GetTermFlg(const std::int32_t workctrlAddress, const std::int32_t transferLaneIndex)
  {
    const auto* const transferRuntime = reinterpret_cast<SftrnTransferRuntimeView*>(SjAddressToPointer(workctrlAddress));
    return transferRuntime->transferLanes[transferLaneIndex].termFlag;
  }

  /**
   * Address: 0x00ADFD60 (FUN_00ADFD60, _SFTRN_IsSetup)
   */
  std::int32_t SFTRN_IsSetup(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj, const std::int32_t transferLaneType)
  {
    const auto* const transferRuntime = reinterpret_cast<const SftrnTransferRuntimeView*>(workctrlSubobj);
    return (transferRuntime->transferLanes[transferLaneType].prepFlag != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00ADEF70 (FUN_00ADEF70, _SFBUF_RingGetDataSiz)
   */
  std::int32_t SFBUF_RingGetDataSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[ringIndex].queuedDataBytes;
  }

  /**
   * Address: 0x00ADEF90 (FUN_00ADEF90, _SFBUF_GetRTot)
   */
  std::int32_t SFBUF_GetRTot(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[ringIndex].readTotalBytes;
  }

  /**
   * Address: 0x00ADDC70 (FUN_00ADDC70, _mwPlyStartFnameLp)
   */
  void mwPlyStartFnameLp(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrInvalidHandle);
      return;
    }

    if (fname == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrNullFileName);
      return;
    }

    MWSFPLY_RecordFname(ply, fname);
    lsc_Stop(ply->lscHandle);
    mwPlyEntryFname(ply, ply->fname);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00AC9290 (FUN_00AC9290, _mwsflib_SetSvrFunc)
   */
  void mwsflib_SetSvrFunc()
  {
    (void)MWSFSVM_EntryIdVfunc(
      2,
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_VsyncThrdProc)),
      0,
      "MWSFSVR_VsyncThrdProc"
    );
    (void)MWSFSVM_EntryMainFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_MainThrdProc)),
      0,
      "MWSFSVR_MainThrdProc"
    );
    (void)MWSFSVM_EntryIdleFunc(
      static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&MWSFSVR_IdleThrdProc)),
      0,
      "MWSFSVR_IdleThrdProc"
    );
  }

  /**
   * Address: 0x00ACB130 (FUN_00ACB130, _mwSfdStopDec)
   */
  void mwSfdStopDec(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    void* const handle = ply->handle;
    if (handle == nullptr) {
      return;
    }

    mwlSfdSleepDecSvr(ply);
    ply->compoMode = 0;
    ply->handle = nullptr;

    if (SFD_Stop(handle) != 0) {
      (void)MWSFLIB_SetErrCode(-308);
      (void)MWSFSVM_Error(kMwsfdErrStopFailed);
    }

    ply->handle = handle;
    MWSST_Stop(&ply->streamState);
    ply->streamState.decodeServerSleepState = 0;

    if (ply->adxStreamHandle != nullptr) {
      MWSTM_ReqStop(ply->adxStreamHandle);
    }
    if (ply->lscHandle != nullptr) {
      lsc_Stop(ply->lscHandle);
    }
  }

  /**
   * Address: 0x00AD8B90 (FUN_00AD8B90, _SFD_Init)
   *
   * What it does:
   * Initializes SFLIB base state and starts all subordinate init lanes.
   */
  std::int32_t SFD_Init(moho::MwsfdInitSfdParams* const initParams)
  {
    gSflibLibWork.versionTag = kMwsfdRequiredVersionTag;
    gCriVerstrPtrSfd = kCriSfdVersionString;

    sflib_InitBaseLib();
    const std::int32_t initResult = sflib_InitLibWork(initParams);
    if (initResult != 0) {
      return initResult;
    }

    sflib_InitSub();
    sflib_InitCs();
    return 0;
  }

  /**
   * Address: 0x00AD8BD0 (FUN_00AD8BD0, _sflib_InitLibWork)
   *
   * What it does:
   * Resets global SFLIB work state, installs default condition lanes, and
   * initializes timer/buffer/transfer subordinate lanes.
   */
  std::int32_t sflib_InitLibWork(const moho::MwsfdInitSfdParams* const initParams)
  {
    std::memset(&gSflibLibWork, 0, offsetof(SflibLibWorkRuntime, versionTag));
    gSflibLibWork.defaultConditions = kSfplyDefaultConditions;
    gSflibLibWork.initParams = *initParams;
    gSflibLibWork.initState = 0;

    (void)sflib_InitErr(&gSflibLibWork.errInfo);
    SFTIM_Init(gSflibLibWork.timeState, initParams->version);
    (void)SFBUF_Init();
    (void)sflib_InitResetPara(&gSflibLibWork);
    std::memset(gSflibLibWork.objectHandles.data(), 0, sizeof(gSflibLibWork.objectHandles));

    return SFTRN_Init(
      &gSflibLibWork.transferInitState,
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(initParams->callbacks))
    );
  }

  /**
   * Address: 0x00AD8C70 (FUN_00AD8C70, _sflib_InitResetPara)
   *
   * What it does:
   * Clears two reset/runtime lanes in one SFLIB work object.
   */
  SflibLibWorkRuntime* sflib_InitResetPara(SflibLibWorkRuntime* const libWork)
  {
    libWork->transferInitState.resetParameter = 0;
    libWork->transferInitState.adxtHandle = 0;
    return libWork;
  }

  /**
   * Address: 0x00AD8D10 (FUN_00AD8D10, _SFLIB_InitErrInf)
   *
   * What it does:
   * Clears one SFLIB error-info lane.
   */
  SflibErrorInfo* SFLIB_InitErrInf(SflibErrorInfo* const errInfo)
  {
    errInfo->callback = nullptr;
    errInfo->callbackObject = 0;
    errInfo->firstErrorCode = 0;
    errInfo->reserved0 = 0;
    errInfo->reserved1 = 0;
    return errInfo;
  }

  /**
   * Address: 0x00AD8D00 (FUN_00AD8D00, _sflib_InitErr)
   *
   * What it does:
   * Thunk to `SFLIB_InitErrInf`.
   */
  SflibErrorInfo* sflib_InitErr(SflibErrorInfo* const errInfo)
  {
    return SFLIB_InitErrInf(errInfo);
  }

  /**
   * Address: 0x00AD8D80 (FUN_00AD8D80, _sflib_SetErrSub)
   *
   * What it does:
   * Latches first error code and dispatches callback when configured.
   */
  std::int32_t sflib_SetErrSub(SflibErrorInfo* const errInfo, const std::int32_t errorCode)
  {
    if (errInfo->firstErrorCode == 0) {
      errInfo->firstErrorCode = errorCode;
    }

    if (errorCode != 0 && errInfo->callback != nullptr) {
      return errInfo->callback(errInfo->callbackObject, errorCode);
    }

    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(errInfo));
  }

  /**
   * Address: 0x00AD8D30 (FUN_00AD8D30, _SFLIB_SetErr)
   *
   * What it does:
   * Routes one non-zero error code into object-local or global SFLIB error
   * lanes and flips positive owner state into negative faulted state.
   */
  std::int32_t SFLIB_SetErr(const std::int32_t errorObjectAddress, const std::int32_t errorCode)
  {
    if (errorCode == 0) {
      return 0;
    }

    if (errorObjectAddress == 0) {
      (void)sflib_SetErrSub(&gSflibLibWork.errInfo, errorCode);
      return errorCode;
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    (void)sflib_SetErrSub(&errorOwner->errInfo, errorCode);

    if (errorOwner->handleState > 0) {
      errorOwner->handleState = -errorOwner->handleState;
    }

    return errorCode;
  }

  /**
   * Address: 0x00AD8DB0 (FUN_00AD8DB0, _SFD_SetErrFn)
   *
   * What it does:
   * Binds one SFLIB error callback to either one specific SFD handle or the
   * global SFLIB error lane.
   */
  std::int32_t SFD_SetErrFn(
    const std::int32_t errorObjectAddress,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject
  )
  {
    const auto callback = reinterpret_cast<SflibErrorCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );

    if (errorObjectAddress == 0) {
      (void)sflib_SetErrFnSub(&gSflibLibWork.errInfo, callback, callbackObject);
      return 0;
    }

    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(errorObjectAddress));
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleSetErrFn);
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    (void)sflib_SetErrFnSub(&errorOwner->errInfo, callback, callbackObject);
    return 0;
  }

  /**
   * Address: 0x00AD8E30 (FUN_00AD8E30, _SFD_GetErrInf)
   *
   * What it does:
   * Copies one SFLIB error-info lane from one specific SFD handle or the global
   * SFLIB lane into caller output storage.
   */
  std::int32_t SFD_GetErrInf(const std::int32_t errorObjectAddress, void* const outErrInfo)
  {
    auto* const outErrorInfo = static_cast<SflibErrorInfo*>(outErrInfo);

    if (errorObjectAddress == 0) {
      std::memcpy(outErrorInfo, &gSflibLibWork.errInfo, sizeof(SflibErrorInfo));
      return 0;
    }

    auto* const workctrlSubobj =
      reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(errorObjectAddress));
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleGetErrInf);
    }

    auto* const errorOwner =
      reinterpret_cast<SflibErrorOwnerRuntimeView*>(SjAddressToPointer(errorObjectAddress));
    std::memcpy(outErrorInfo, &errorOwner->errInfo, sizeof(SflibErrorInfo));
    return 0;
  }

  /**
   * Address: 0x00AD8E10 (FUN_00AD8E10, _sflib_SetErrFnSub)
   *
   * What it does:
   * Stores one SFLIB error callback and callback-object lanes.
   */
  SflibErrorInfo*
  sflib_SetErrFnSub(SflibErrorInfo* const errInfo, SflibErrorCallback const callback, const std::int32_t callbackObject)
  {
    errInfo->callback = callback;
    errInfo->callbackObject = callbackObject;
    return errInfo;
  }

  /**
   * Address: 0x00AD8E90 (FUN_00AD8E90, _SFLIB_CheckHn)
   *
   * What it does:
   * Validates one SFD work-control handle and records last validated handle.
   */
  std::int32_t SFLIB_CheckHn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (workctrlSubobj == nullptr || workctrlSubobj->handleState == 0) {
      return -1;
    }

    gSfdDebugLastHandle = workctrlSubobj;
    return 0;
  }

  /**
   * Address: 0x00AD6DE0 (FUN_00AD6DE0, _SFPLY_Init)
   *
   * What it does:
   * Initializes SFPLY runtime defaults and clears record-get-frame counter.
   */
  std::int32_t SFPLY_Init()
  {
    const std::int32_t result = sfply_ChkCondDfl();
    SFPLY_recordgetfrm = 0;
    return result;
  }

  /**
   * Address: 0x00AD6DF0 (FUN_00AD6DF0, _sfply_ChkCondDfl)
   *
   * What it does:
   * Latches default-condition validation error code in global SFLIB error lane.
   */
  std::int32_t sfply_ChkCondDfl()
  {
    return SFLIB_SetErr(0, kSflibErrDefaultConditionMissing);
  }

  /**
   * Address: 0x00AD6E00 (FUN_00AD6E00, _SFD_VbIn)
   *
   * What it does:
   * Forwards one SFD vertical-blank enter lane to timer runtime.
   */
  std::int32_t SFD_VbIn()
  {
    return SFTIM_VbIn();
  }

  /**
   * Address: 0x00AD6E10 (FUN_00AD6E10, _SFD_VbOut)
   *
   * What it does:
   * Reserved vertical-blank leave lane (no-op in this build).
   */
  void SFD_VbOut()
  {
  }

  /**
   * Address: 0x00AD6E20 (FUN_00AD6E20, _SFD_IsHnSvrWait)
   *
   * What it does:
   * Returns whether one SFD handle can proceed outside server-wait states.
   */
  std::int32_t SFD_IsHnSvrWait(const std::int32_t sfdHandleAddress)
  {
    struct SfdServerWaitView
    {
      std::uint8_t mUnknown00[0x44]{};
      std::int32_t serverWaitFlag = 0; // +0x44
      std::int32_t serverState = 0; // +0x48
    };
    static_assert(
      offsetof(SfdServerWaitView, serverWaitFlag) == 0x44,
      "SfdServerWaitView::serverWaitFlag offset must be 0x44"
    );
    static_assert(offsetof(SfdServerWaitView, serverState) == 0x48, "SfdServerWaitView::serverState offset must be 0x48");

    auto* const view = reinterpret_cast<SfdServerWaitView*>(SjAddressToPointer(sfdHandleAddress));
    const std::int32_t state = view->serverState;
    const bool isServerWaitState = (state == 1 || state == 2 || state == 3 || state == 4);
    if (!isServerWaitState) {
      return 1;
    }
    return (view->serverWaitFlag == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD6E90 (FUN_00AD6E90, _SFD_ExecOne)
   *
   * What it does:
   * Executes one SFD per-handle server step after handle validation.
   */
  std::int32_t SFD_ExecOne(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleExecOne);
    }
    (void)sfply_ExecOne(workctrlSubobj);
    return 0;
  }

  /**
   * Address: 0x00AD6FD0 (FUN_00AD6FD0, _sfply_ExecOneSub)
   *
   * What it does:
   * Executes transfer-server lane and SFSEE server lane for one SFD handle.
   */
  std::int32_t sfply_ExecOneSub(const std::int32_t workctrlAddress)
  {
    (void)sfply_TrExecServer(workctrlAddress);
    return SFSEE_ExecServer(workctrlAddress);
  }

  /**
   * Address: 0x00AD6FF0 (FUN_00AD6FF0, _sfply_TrExecServer)
   *
   * What it does:
   * Dispatches transfer setup callback lane `2` for one SFD handle.
   */
  std::int32_t sfply_TrExecServer(const std::int32_t workctrlAddress)
  {
    return SFTRN_CallTrSetup(workctrlAddress, 2);
  }

  /**
   * Address: 0x00AD7000 (FUN_00AD7000, _sfply_StatStop)
   *
   * What it does:
   * Resolves STOP state lane for one playback handle from current phase flags.
   */
  std::int32_t sfply_StatStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    const std::int32_t phaseLane = stateView->phaseLane;
    if (phaseLane >= 2 && (phaseLane <= 4 || phaseLane == 6)) {
      return 2;
    }
    return stateView->statusLane;
  }

  /**
   * Address: 0x00AD7020 (FUN_00AD7020, _sfply_StatPrep)
   *
   * What it does:
   * Resolves PREP state lane and dispatches transfer start when sync gate opens.
   */
  std::int32_t sfply_StatPrep(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t nextState = stateView->statusLane;
    const std::int32_t phaseLane = stateView->phaseLane;

    if (sfply_IsPrepEnd(workctrlSubobj) != 0) {
      (void)sfply_AdjustPrepEnd(workctrlSubobj);
      switch (phaseLane) {
      case 2:
        return 2;
      case 3:
        nextState = 3;
        break;
      case 4:
      case 6:
        if (sfply_IsStartSync(workctrlSubobj) != 0) {
          sfply_TrStart(workctrlSubobj);
          return 4;
        }
        nextState = 3;
        break;
      default:
        return nextState;
      }
    }

    return nextState;
  }

  /**
   * Address: 0x00AD70A0 (FUN_00AD70A0, _sfply_IsPrepEnd)
   *
   * What it does:
   * Checks whether audio/video transfer preparation lanes are completed.
   */
  std::int32_t sfply_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kTransferLane6 = 6;
    constexpr std::int32_t kTransferLane7 = 7;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));

    std::int32_t cond5Ready = 1;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) != 0) {
      const std::int32_t prepFlag = SFTRN_GetPrepFlg(workctrlAddress, kTransferLane6);
      cond5Ready = SFTRN_GetTermFlg(workctrlAddress, kTransferLane6) | prepFlag;
    }

    std::int32_t cond6Ready = 1;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) != 0) {
      const std::int32_t prepFlag = SFTRN_GetPrepFlg(workctrlAddress, kTransferLane7);
      cond6Ready = SFTRN_GetTermFlg(workctrlAddress, kTransferLane7) | prepFlag;
    }

    return (cond5Ready != 0 && cond6Ready != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7120 (FUN_00AD7120, _sfply_AdjustPrepEnd)
   *
   * What it does:
   * Finalizes PREP completion by fixing AV flags, sync mode, and ETRG lane.
   */
  std::int32_t sfply_AdjustPrepEnd(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    (void)sfply_FixAvPlay(workctrlSubobj);
    (void)sfply_AdjustSyncMode(workctrlSubobj);
    return sfply_AdjustEtrg(workctrlSubobj);
  }

  /**
   * Address: 0x00AD7140 (FUN_00AD7140, _sfply_FixAvPlay)
   *
   * What it does:
   * Clears stale AV condition lanes when ring-buffer totals are empty.
   */
  std::int32_t sfply_FixAvPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    if (
      stateView->setConditions[kSfsetCond5] == 1 && SFBUF_GetWTot(workctrlAddress, 1) == 0 &&
      SFBUF_GetRTot(workctrlAddress, 1) == 0
    ) {
      stateView->setConditions[kSfsetCond5] = 0;
    }

    if (
      stateView->setConditions[kSfsetCond6] == 1 && SFBUF_GetWTot(workctrlAddress, 2) == 0 &&
      SFBUF_GetRTot(workctrlAddress, 2) == 0
    ) {
      stateView->setConditions[kSfsetCond6] = 0;
    }

    return SFSEE_FixAvPlay(workctrlAddress, stateView->setConditions[kSfsetCond5], stateView->setConditions[kSfsetCond6]);
  }

  /**
   * Address: 0x00AD71C0 (FUN_00AD71C0, _sfply_AdjustSyncMode)
   *
   * What it does:
   * Normalizes sync-mode condition lane against current AV-enable conditions.
   */
  std::int32_t sfply_AdjustSyncMode(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondSyncMode = 15;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    if (stateView->setConditions[kSfsetCond6] == 0 && stateView->setConditions[kSfsetCondSyncMode] == 2) {
      SFSET_SetCond(workctrlSubobj, kSfsetCondSyncMode, 1);
    }

    const std::int32_t cond5Value = stateView->setConditions[kSfsetCond5];
    if (cond5Value == 0 && stateView->setConditions[kSfsetCondSyncMode] == 1) {
      return SFSET_SetCond(workctrlSubobj, kSfsetCondSyncMode, 2);
    }
    return cond5Value;
  }

  /**
   * Address: 0x00AD7210 (FUN_00AD7210, _sfply_AdjustEtrg)
   *
   * What it does:
   * Reconciles ETRG condition lane (`25`) from AV-enable lanes and timer policy.
   */
  std::int32_t sfply_AdjustEtrg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondEtrg = 25;
    constexpr std::int32_t kSfsetCondTimerPolicy = 72;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    std::int32_t etrgConditionValue = 1;
    std::int32_t avMask = (stateView->setConditions[kSfsetCond6] == 1) ? 1 : 0;
    if (stateView->setConditions[kSfsetCond5] == 1) {
      avMask |= 2;
    }

    std::int32_t adjustedMask = avMask - 1;
    if (adjustedMask != 0) {
      adjustedMask -= 1;
      if (adjustedMask != 0) {
        if (adjustedMask != 1) {
          return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, 3);
        }

        etrgConditionValue = SFSET_GetCond(workctrlSubobj, kSfsetCondEtrg);
        if (
          etrgConditionValue == 0 &&
          (UTY_IsTmrVoid() != 0 || SFSET_GetCond(workctrlSubobj, kSfsetCondTimerPolicy) == 0)
        ) {
          return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, 3);
        }
      } else {
        etrgConditionValue = 2;
      }
    }

    return SFSET_SetCond(workctrlSubobj, kSfsetCondEtrg, etrgConditionValue);
  }

  /**
   * Address: 0x00AD72A0 (FUN_00AD72A0, _sfply_StatStby)
   *
   * What it does:
   * Resolves STANDBY state lane and starts transfers once sync preconditions hold.
   */
  std::int32_t sfply_StatStby(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t nextState = stateView->statusLane;

    switch (stateView->phaseLane) {
    case 2:
      return 2;
    case 3:
      return 3;
    case 4:
    case 6:
      if (sfply_IsStartSync(workctrlSubobj) != 0) {
        sfply_TrStart(workctrlSubobj);
        nextState = 4;
      }
      break;
    default:
      break;
    }

    return nextState;
  }

  /**
   * Address: 0x00AD7310 (FUN_00AD7310, _sfply_StatPlay)
   *
   * What it does:
   * Resolves PLAY state lane with finish and BPA transition checks.
   */
  std::int32_t sfply_StatPlay(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (sfply_ChkFin(workctrlSubobj) != 0) {
      return stateView->statusLane;
    }

    if (sfply_ChkBpa(workctrlSubobj) == 0 && stateView->phaseLane == 6) {
      return 6;
    }
    return stateView->statusLane;
  }

  /**
   * Address: 0x00AD7350 (FUN_00AD7350, _sfply_StatFin)
   *
   * What it does:
   * Returns current FIN state lane from one playback work-control object.
   */
  std::int32_t sfply_StatFin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj)->statusLane;
  }

  /**
   * Address: 0x00AD7360 (FUN_00AD7360, _sfply_IsStartSync)
   *
   * What it does:
   * Evaluates whether transfer start is sync-safe for one playback handle.
   */
  std::int32_t sfply_IsStartSync(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond14 = 14;
    constexpr std::int32_t kSfsetCond45 = 45;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (stateView->setConditions[kSfsetCond14] == 0) {
      return 1;
    }
    if (stateView->setConditions[kSfsetCond5] == 0) {
      return 1;
    }
    if (stateView->startSyncBypassFlag != 0) {
      return 1;
    }
    if (stateView->startSyncCurrentTicks < stateView->setConditions[kSfsetCond45]) {
      return (sfply_IsEtrg(workctrlSubobj) != 0) ? 1 : 0;
    }
    return 1;
  }

  /**
   * Address: 0x00AD73C0 (FUN_00AD73C0, _sfply_ChkBpa)
   *
   * What it does:
   * Toggles BPA pause state under SFLIB critical section and dispatches pause op.
   */
  std::int32_t sfply_ChkBpa(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);

    SFLIB_LockCs();
    std::int32_t result = 0;
    if (stateView->bpaActiveFlag != 0) {
      if (sfply_IsBpaOff(workctrlSubobj) != 0) {
        stateView->bpaActiveFlag = 0;
        result = SFPL2_Pause(workctrlSubobj, 0);
      }
    } else if (sfply_IsBpaOn(workctrlSubobj) != 0) {
      stateView->bpaActiveFlag = 1;
      stateView->bpaToggleCount += 1;
      result = SFPL2_Pause(workctrlSubobj, 1);
    }
    SFLIB_UnlockCs();

    return result;
  }

  /**
   * Address: 0x00AD7440 (FUN_00AD7440, _sfply_IsBpaOn)
   *
   * What it does:
   * Decides whether BPA pause should be enabled from playback/data/timer lanes.
   */
  std::int32_t sfply_IsBpaOn(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCond15 = 15;
    constexpr std::int32_t kSfsetCond67 = 67;
    constexpr std::int32_t kSfsetCond68 = 68;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (
      SFSET_GetCond(workctrlSubobj, kSfsetCond67) == 0 || SFSET_GetCond(workctrlSubobj, kSfsetCond15) == 0 ||
      stateView->startupGateFlag != 0 || stateView->statusLane != 4 || sfply_IsAnyoneTerm(workctrlSubobj) != 0 ||
      (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && stateView->videoLaneReadyFlag == 0)
    ) {
      return 0;
    }

    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) == 1 && SFBUF_GetRingBufSiz(workctrlAddress, 2) > 0) {
      return 0;
    }
    if (SFTRN_IsSetup(workctrlSubobj, 1) != 0 && SFBUF_GetRingBufSiz(workctrlAddress, 0) > 0) {
      return 0;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && sfply_EnoughViData(workctrlSubobj) != 0) {
      return 0;
    }

    std::int32_t currentTimeInteger = 0;
    std::int32_t currentTimeFractional = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeInteger, &currentTimeFractional);

    const std::int32_t scaledWindow =
      stateView->bpaWindowTicks - UTY_MulDiv(SFSET_GetCond(workctrlSubobj, kSfsetCond68), stateView->bpaTickRate, 1000000);
    if (currentTimeInteger <= 0 || scaledWindow <= 0) {
      return 0;
    }
    return (SFD_CmpTime(currentTimeInteger, currentTimeFractional, scaledWindow, stateView->bpaTickRate) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7580 (FUN_00AD7580, _sfply_IsBpaOff)
   *
   * What it does:
   * Decides whether BPA pause should be released from playback/data/timer lanes.
   */
  std::int32_t sfply_IsBpaOff(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCond69 = 69;
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);

    if (sfply_IsAnyoneTerm(workctrlSubobj) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond5) == 1 && sfply_EnoughViData(workctrlSubobj) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, kSfsetCond6) == 1 && sfply_EnoughAiData(workctrlSubobj) != 0) {
      return 1;
    }

    std::int32_t currentTimeInteger = 0;
    std::int32_t currentTimeFractional = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeFractional, &currentTimeInteger);

    const std::int32_t scaledWindow =
      stateView->bpaWindowTicks - UTY_MulDiv(SFSET_GetCond(workctrlSubobj, kSfsetCond69), stateView->bpaTickRate, 1000000);
    return (SFD_CmpTime(currentTimeFractional, currentTimeInteger, scaledWindow, stateView->bpaTickRate) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7640 (FUN_00AD7640, _sfply_IsAnyoneTerm)
   *
   * What it does:
   * Checks transfer and buffer termination flags across active playback lanes.
   */
  std::int32_t sfply_IsAnyoneTerm(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    if (SFSET_GetCond(workctrlSubobj, 5) != 0 && SFTRN_GetTermFlg(workctrlAddress, 6) != 0) {
      return 1;
    }
    if (SFSET_GetCond(workctrlSubobj, 6) != 0 && SFTRN_GetTermFlg(workctrlAddress, 7) != 0) {
      return 1;
    }

    for (std::int32_t laneIndex = 0; laneIndex < 8; ++laneIndex) {
      if (SFBUF_GetTermFlg(workctrlAddress, laneIndex) != 0) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00AD76B0 (FUN_00AD76B0, _sfply_EnoughViData)
   *
   * What it does:
   * Checks whether the active video lane has enough buffered data for playback.
   */
  std::int32_t sfply_EnoughViData(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetVideoReadyThreshold = 70;
    const auto* const readinessView = reinterpret_cast<const SfplyDataReadinessIndexView*>(workctrlSubobj);
    const auto* const videoLane = SfplyGetDataLaneDescriptor(workctrlSubobj, readinessView->activeVideoLaneIndex);
    const std::int32_t availableBytes = SfplyQueryLaneReadyBytes(videoLane);
    const std::int32_t laneThreshold = (videoLane->readyThresholdBytes * 80) / 100;
    if (availableBytes >= laneThreshold) {
      return 1;
    }
    return (availableBytes >= SFSET_GetCond(workctrlSubobj, kSfsetVideoReadyThreshold)) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7720 (FUN_00AD7720, _sfply_EnoughAiData)
   *
   * What it does:
   * Checks whether the active audio lane has enough buffered data for playback.
   */
  std::int32_t sfply_EnoughAiData(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const readinessView = reinterpret_cast<const SfplyDataReadinessIndexView*>(workctrlSubobj);
    const auto* const audioLane = SfplyGetDataLaneDescriptor(workctrlSubobj, readinessView->activeAudioLaneIndex);
    const std::int32_t availableBytes = SfplyQueryLaneReadyBytes(audioLane);
    const std::int32_t laneThreshold = (audioLane->readyThresholdBytes * 80) / 100;
    return (availableBytes >= laneThreshold) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7780 (FUN_00AD7780, _sfply_ChkFin)
   *
   * What it does:
   * Evaluates all playback finish triggers and transitions to FIN when hit.
   */
  std::int32_t sfply_ChkFin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    if (sfply_IsEtime(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsEtrg(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsStagnant(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    if (sfply_IsPlayTimeAutoStop(workctrlSubobj) != 0) {
      return sfply_Fin(workctrlSubobj);
    }
    return 0;
  }

  /**
   * Address: 0x00AD77D0 (FUN_00AD77D0, _sfply_IsEtime)
   *
   * What it does:
   * Checks whether current playback time reached configured end time.
   */
  std::int32_t sfply_IsEtime(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kNoEndTimeSentinel = -4;
    const auto* const endTimeView = reinterpret_cast<const SfplyEndTimeView*>(workctrlSubobj);
    if (endTimeView->endTimeMajor == kNoEndTimeSentinel) {
      return 0;
    }

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    SFTIM_GetTime(workctrlAddress, &currentTimeMajor, &currentTimeMinor);
    if (currentTimeMajor < 0) {
      return 0;
    }

    return (UTY_CmpTime(currentTimeMajor, currentTimeMinor, endTimeView->endTimeMajor, endTimeView->endTimeMinor) == 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7830 (FUN_00AD7830, _sfply_IsEtrg)
   *
   * What it does:
   * Evaluates end-trigger condition policy from transfer termination flags.
   */
  std::int32_t sfply_IsEtrg(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCond5 = 5;
    constexpr std::int32_t kSfsetCond6 = 6;
    constexpr std::int32_t kSfsetCondEtrg = 25;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->setConditions[kSfsetCond6] == 0 && stateView->setConditions[kSfsetCond5] == 0) {
      return 1;
    }

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    const std::int32_t termFlag6 = SFTRN_GetTermFlg(workctrlAddress, 6);
    const std::int32_t termFlag7 = SFTRN_GetTermFlg(workctrlAddress, 7);

    switch (SFSET_GetCond(workctrlSubobj, kSfsetCondEtrg)) {
    case 0:
      return termFlag7 & termFlag6;
    case 1:
      return termFlag7;
    case 2:
      return termFlag6;
    case 3:
      return termFlag6 | termFlag7;
    default:
      return 0;
    }
  }

  /**
   * Address: 0x00AD78B0 (FUN_00AD78B0, _sfply_IsStagnant)
   *
   * What it does:
   * Checks playback stagnation under active-playing and non-paused conditions.
   */
  std::int32_t sfply_IsStagnant(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane != 4) {
      return 0;
    }
    if (stateView->startupGateFlag == 1) {
      return 0;
    }
    if (stateView->bpaActiveFlag == 1) {
      return 0;
    }
    return (SFTIM_IsStagnant(workctrlSubobj) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD78F0 (FUN_00AD78F0, _sfply_IsPlayTimeAutoStop)
   *
   * What it does:
   * Checks whether configured play-time auto-stop condition has been reached.
   */
  std::int32_t sfply_IsPlayTimeAutoStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    constexpr std::int32_t kSfsetCondAutoStopTime = 54;
    const auto* const stateView = reinterpret_cast<const SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane != 4) {
      return 0;
    }
    if (stateView->startupGateFlag == 1) {
      return 0;
    }
    if (stateView->bpaActiveFlag == 1) {
      return 0;
    }

    std::int32_t currentTimeMajor = 0;
    std::int32_t currentTimeMinor = 0;
    if (SFTIM_GetTimeSub(workctrlSubobj, &currentTimeMajor, &currentTimeMinor) != 0 || currentTimeMajor < 0) {
      return 0;
    }

    const std::int32_t autoStopTime = SFSET_GetCond(workctrlSubobj, kSfsetCondAutoStopTime);
    return (SFD_CmpTime(autoStopTime, 1000, currentTimeMajor, currentTimeMinor) != 0) ? 1 : 0;
  }

  /**
   * Address: 0x00AD7960 (FUN_00AD7960, _sfply_Fin)
   *
   * What it does:
   * Stops transfer lanes and transitions one playback handle to FIN phase.
   */
  std::int32_t sfply_Fin(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t stopResult = sfply_TrStop(workctrlSubobj);
    if (stopResult != 0) {
      return stopResult;
    }

    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->phaseLane = 6;
    SFPLY_MeasureFps(workctrlSubobj);
    return 0;
  }

  /**
   * Address: 0x00AD7A30 (FUN_00AD7A30, _sfply_Create)
   *
   * What it does:
   * Validates create parameters, allocates one free SFLIB slot, and initializes one SFPLY handle.
   */
  moho::SofdecSfdWorkctrlSubobj*
  sfply_Create(const moho::SfplyCreateParams* const createParams, const std::int32_t createContext)
  {
    if (sfply_ChkCrePara(createParams) != 0) {
      return nullptr;
    }

    const std::int32_t freeHandleIndex = sfply_SearchFreeHn();
    if (freeHandleIndex == -1) {
      (void)SFLIB_SetErr(0, kSflibErrCreateNoFreeHandle);
      return nullptr;
    }

    moho::SofdecSfdWorkctrlSubobj* const handle = sfply_InitHn(createParams, createContext);
    gSflibLibWork.objectHandles[static_cast<std::size_t>(freeHandleIndex)] = handle;
    return handle;
  }

  /**
   * Address: 0x00AD7A80 (FUN_00AD7A80, _sfply_ChkCrePara)
   *
   * What it does:
   * Validates SFPLY create parameters and reports SFLIB error lanes on invalid input.
   */
  std::int32_t sfply_ChkCrePara(const moho::SfplyCreateParams* const createParams)
  {
    if (createParams->workControlBuffer == nullptr) {
      return SFLIB_SetErr(0, kSflibErrCreateMissingWorkArea);
    }
    if (createParams->workControlSizeBytes >= 0x3660u) {
      return 0;
    }
    return SFLIB_SetErr(0, kSflibErrCreateWorkSizeTooSmall);
  }

  /**
   * Address: 0x00AD7AC0 (FUN_00AD7AC0, _sfply_SearchFreeHn)
   *
   * What it does:
   * Scans SFLIB object slots and returns first free handle index, or `-1`.
   */
  std::int32_t sfply_SearchFreeHn()
  {
    for (std::int32_t handleIndex = 0; handleIndex < static_cast<std::int32_t>(gSflibLibWork.objectHandles.size()); ++handleIndex) {
      if (gSflibLibWork.objectHandles[static_cast<std::size_t>(handleIndex)] == nullptr) {
        return handleIndex;
      }
    }
    return -1;
  }

  /**
   * Address: 0x00AD7C30 (FUN_00AD7C30, _sfply_InitMvInf)
   *
   * What it does:
   * Resets one SFPLY movie-info lane and restores default sentinel indices.
   */
  std::int32_t sfply_InitMvInf(moho::SfplyMovieInfo* const movieInfo)
  {
    *movieInfo = {};
    movieInfo->decodeDirection = 1;
    movieInfo->firstFrameIndex = -1;
    movieInfo->lastFrameIndex = -1;
    movieInfo->activeFrameIndex = -1;
    return -1;
  }

  /**
   * Address: 0x00AD7C80 (FUN_00AD7C80, _sfply_InitPlyInf)
   *
   * What it does:
   * Clears one playback-info lane and initializes all four embedded flow counters.
   */
  std::int32_t sfply_InitPlyInf(moho::SfplyPlaybackInfo* const playbackInfo)
  {
    *playbackInfo = {};
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter0);
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter1);
    (void)sfply_InitFlowCnt(&playbackInfo->flowCounter2);
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(sfply_InitFlowCnt(&playbackInfo->flowCounter3)));
  }

  /**
   * Address: 0x00AD7CF0 (FUN_00AD7CF0, _sfply_InitFlowCnt)
   *
   * What it does:
   * Clears one SFPLY flow-counter lane.
   */
  moho::SfplyFlowCount* sfply_InitFlowCnt(moho::SfplyFlowCount* const flowCount)
  {
    flowCount->producedBytes = 0;
    flowCount->consumedBytes = 0;
    flowCount->producedPackets = 0;
    flowCount->consumedPackets = 0;
    flowCount->producedFrames = 0;
    flowCount->consumedFrames = 0;
    return flowCount;
  }

  /**
   * Address: 0x00AD7D10 (FUN_00AD7D10, _sfply_InitTmrInf)
   *
   * What it does:
   * Clears one timer-info lane and initializes all timer-summary sub-lanes.
   */
  std::int32_t sfply_InitTmrInf(moho::SfplyTimerInfo* const timerInfo)
  {
    *timerInfo = {};

    for (std::size_t summaryIndex = 0; summaryIndex < 5; ++summaryIndex) {
      (void)SFTMR_InitTsum(&timerInfo->summaries[summaryIndex]);
    }

    const std::int32_t result = SFTMR_InitTsum(&timerInfo->summaries[5]);
    timerInfo->mUnknownC0.fill(0);
    return result;
  }

  /**
   * Address: 0x00AD7D80 (FUN_00AD7D80, _SFPLY_AddDecPic)
   *
   * What it does:
   * Adds decoded-picture count and calls optional condition callback `36`.
   */
  std::int32_t SFPLY_AddDecPic(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t decodedPictureDelta,
    const std::int32_t callbackContext
  )
  {
    constexpr std::int32_t kSfsetCondDecodedPicture = 36;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->pictureCounts.decodedPictureCount += decodedPictureDelta;

    const std::int32_t callbackAddress = SFSET_GetCond(workctrlSubobj, kSfsetCondDecodedPicture);
    if (callbackAddress == 0) {
      return 0;
    }

    const auto callback = reinterpret_cast<SfplyPictureCountCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );
    return callback(workctrlSubobj, callbackContext, &stateView->pictureCounts);
  }

  /**
   * Address: 0x00AD7DC0 (FUN_00AD7DC0, _SFPLY_AddSkipPic)
   *
   * What it does:
   * Adds skipped-picture count and calls optional condition callback `37`.
   */
  std::int32_t SFPLY_AddSkipPic(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t skippedPictureDelta,
    const std::int32_t callbackContext
  )
  {
    constexpr std::int32_t kSfsetCondSkippedPicture = 37;
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->pictureCounts.skippedPictureCount += skippedPictureDelta;

    const std::int32_t callbackAddress = SFSET_GetCond(workctrlSubobj, kSfsetCondSkippedPicture);
    if (callbackAddress == 0) {
      return 0;
    }

    const auto callback = reinterpret_cast<SfplyPictureCountCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackAddress))
    );
    return callback(workctrlSubobj, callbackContext, &stateView->pictureCounts);
  }

  /**
   * Address: 0x00AD7E00 (FUN_00AD7E00, _sfply_TrCreate)
   *
   * What it does:
   * Runs transfer setup callback lane `3` for one SFPLY handle.
   */
  std::int32_t sfply_TrCreate(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrSetup(workctrlAddress, 3);
  }

  /**
   * Address: 0x00AD7E10 (FUN_00AD7E10, _SFD_Destroy)
   *
   * What it does:
   * Stops and destroys one SFD handle, then clears every matching global slot.
   */
  std::int32_t SFD_Destroy(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleDestroy);
    }

    (void)SFPLY_Stop(workctrlSubobj);

    auto* const fileHeaderView = reinterpret_cast<SfplyFileHeaderLaneView*>(workctrlSubobj);
    (void)SFHDS_FinishFhd(fileHeaderView->fileHeaderState);
    SFBUF_DestroySj(workctrlSubobj);

    const std::int32_t destroyResult = sfply_TrDestroy(workctrlSubobj);
    for (void*& objectHandle : gSflibLibWork.objectHandles) {
      if (objectHandle == workctrlSubobj) {
        objectHandle = nullptr;
      }
    }

    return destroyResult;
  }

  /**
   * Address: 0x00AD7E70 (FUN_00AD7E70, _sfply_TrDestroy)
   *
   * What it does:
   * Clears transfer status lanes and runs transfer teardown callback lane `4`.
   */
  std::int32_t sfply_TrDestroy(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->statusLane = 0;
    stateView->phaseLane = 0;

    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrSetup(workctrlAddress, 4);
  }

  /**
   * Address: 0x00AD7E90 (FUN_00AD7E90, _SFD_Start)
   *
   * What it does:
   * Starts one SFD handle either in standby mode or immediate-play mode.
   */
  std::int32_t SFD_Start(void* const sfdHandle)
  {
    constexpr std::int32_t kSfsetCondStartMode = 47;
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStart);
    }

    std::int32_t result = 0;
    if (SFSET_GetCond(workctrlSubobj, kSfsetCondStartMode) == 1) {
      result = SFPL2_Standby(workctrlSubobj);
    } else {
      result = sfply_Start(workctrlSubobj);
    }

    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->serverWaitFlag = 1;
    return result;
  }

  /**
   * Address: 0x00AD7EF0 (FUN_00AD7EF0, _sfply_Start)
   *
   * What it does:
   * Transitions one SFPLY handle into PLAY phase.
   */
  std::int32_t sfply_Start(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->phaseLane = 4;
    return 0;
  }

  /**
   * Address: 0x00AD7F00 (FUN_00AD7F00, _sfply_TrStart)
   *
   * What it does:
   * Dispatches transfer start transition (`7 -> 6`) for one SFPLY handle.
   */
  std::int32_t sfply_TrStart(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    return SFTRN_CallTrtTrif(workctrlAddress, 7, 6, 0, 0);
  }

  /**
   * Address: 0x00AD7F20 (FUN_00AD7F20, _SFD_Stop)
   *
   * What it does:
   * Stops one SFD handle and sets server-wait/start gate lane.
   */
  std::int32_t SFD_Stop(void* const sfdHandle)
  {
    auto* const workctrlSubobj = static_cast<moho::SofdecSfdWorkctrlSubobj*>(sfdHandle);
    if (SFLIB_CheckHn(workctrlSubobj) != 0) {
      return SFLIB_SetErr(0, kSflibErrInvalidHandleStop);
    }

    const std::int32_t result = SFPLY_Stop(workctrlSubobj);
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    stateView->serverWaitFlag = 1;
    return result;
  }

  [[nodiscard]] static std::int32_t& SFPLY_ResetFlagLane()
  {
    return *reinterpret_cast<std::int32_t*>(&gSflibLibWork.objectHandles[0]);
  }

  /**
   * Address: 0x00AD7FA0 (FUN_00AD7FA0, _SFPLY_SetResetFlg)
   *
   * What it does:
   * Writes SFPLY global reset-guard flag and returns written value.
   */
  std::int32_t SFPLY_SetResetFlg(const std::int32_t enabled)
  {
    SFPLY_ResetFlagLane() = enabled;
    return enabled;
  }

  /**
   * Address: 0x00AD7FB0 (FUN_00AD7FB0, _SFPLY_GetResetFlg)
   *
   * What it does:
   * Reads SFPLY global reset-guard flag.
   */
  std::int32_t SFPLY_GetResetFlg()
  {
    return SFPLY_ResetFlagLane();
  }

  /**
   * Address: 0x00AD7F60 (FUN_00AD7F60, _SFPLY_Stop)
   *
   * What it does:
   * Stops transfer lanes and rebuilds/reset one SFPLY handle when needed.
   */
  std::int32_t SFPLY_Stop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    if (stateView->statusLane == 1) {
      return 0;
    }

    const std::int32_t stopResult = sfply_TrStop(workctrlSubobj);
    if (stopResult != 0) {
      return stopResult;
    }

    stateView->phaseLane = 0;
    stateView->statusLane = 0;
    (void)SFPLY_SetResetFlg(1);
    const std::int32_t resetResult = sfply_ResetHn(workctrlSubobj);
    (void)SFPLY_SetResetFlg(0);
    return resetResult;
  }

  /**
   * Address: 0x00AD7FC0 (FUN_00AD7FC0, _sfply_TrStop)
   *
   * What it does:
   * Dispatches transfer stop transition and updates local stop-state lanes.
   */
  std::int32_t sfply_TrStop(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    auto* const stateView = reinterpret_cast<SfplyRuntimeStateView*>(workctrlSubobj);
    std::int32_t result = 0;
    if (stateView->statusLane == 4) {
      const std::int32_t workctrlAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
      result = SFTRN_CallTrtTrif(workctrlAddress, 7, 7, 0, 0);
      if (result != 0) {
        return result;
      }
    }

    stateView->statusLane = 1;
    stateView->phaseLane = 1;
    return 0;
  }

  /**
   * Address: 0x00AD8EB0 (FUN_00AD8EB0, _sflib_InitBaseLib)
   *
   * What it does:
   * Initializes SFLIB base runtime lane.
   */
  void sflib_InitBaseLib()
  {
    SJRBF_Init();
  }

  /**
   * Address: 0x00AD8EC0 (FUN_00AD8EC0, _sflib_FinishBaseLib)
   *
   * What it does:
   * Finalizes SFLIB base runtime lane.
   */
  std::int32_t sflib_FinishBaseLib()
  {
    return SJRBF_Finish();
  }

  /**
   * Address: 0x00AD8ED0 (FUN_00AD8ED0, _sflib_InitSub)
   *
   * What it does:
   * Initializes SFLIB subordinate runtime lanes.
   */
  void sflib_InitSub()
  {
    SFPLY_Init();
    (void)SFHDS_Init();
  }

  /**
   * Address: 0x00AD8EE0 (FUN_00AD8EE0, _sflib_FinishSub)
   *
   * What it does:
   * Finalizes SFLIB subordinate runtime lanes.
   */
  std::int32_t sflib_FinishSub()
  {
    return SFHDS_Finish();
  }

  /**
   * Address: 0x00AD8EF0 (FUN_00AD8EF0, _sflib_InitCs)
   *
   * What it does:
   * No-op critical-section init lane for this binary build.
   */
  void sflib_InitCs()
  {
  }

  /**
   * Address: 0x00AD8F00 (FUN_00AD8F00, _sflib_FinishCs)
   *
   * What it does:
   * No-op critical-section finalize lane for this binary build.
   */
  void sflib_FinishCs()
  {
  }

  /**
   * Address: 0x00AD8C90 (FUN_00AD8C90, _SFD_Finish)
   *
   * What it does:
   * Destroys all active SFD object lanes, finalizes timer/buffer/transfer
   * subsystems, and returns transfer-finalize result when non-zero.
   */
  std::int32_t SFD_Finish()
  {
    std::int32_t destroyResult = 0;
    for (void* const objectHandle : gSflibLibWork.objectHandles) {
      if (objectHandle != nullptr) {
        destroyResult = SFD_Destroy(objectHandle);
      }
    }

    SFTIM_Finish(gSflibLibWork.timeState);
    SFBUF_Finish();
    const std::int32_t transferResult = SFTRN_Finish(&gSflibLibWork.transferInitState);

    sflib_FinishCs();
    sflib_FinishSub();
    sflib_FinishBaseLib();

    if (transferResult != 0) {
      return transferResult;
    }

    return destroyResult;
  }

  /**
   * Address: 0x00AD8F10 (FUN_00AD8F10, _SFLIB_LockCs)
   */
  void SFLIB_LockCs()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00AD8F20 (FUN_00AD8F20, _SFLIB_UnlockCs)
   */
  void SFLIB_UnlockCs()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00AD8F30 (FUN_00AD8F30, _MWSTM_Init)
   */
  std::int32_t MWSTM_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F40 (FUN_00AD8F40, _MWSTM_InitStatic)
   */
  std::int32_t MWSTM_InitStatic()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F50 (FUN_00AD8F50, _MWSTM_Finish)
   */
  std::int32_t MWSTM_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F60 (FUN_00AD8F60, _MWSTM_FinishStatic)
   */
  std::int32_t MWSTM_FinishStatic()
  {
    return 0;
  }

  /**
   * Address: 0x00AD8F70 (FUN_00AD8F70, _MWSTM_SetRdSct)
   */
  std::int32_t MWSTM_SetRdSct(const std::int32_t streamHandleAddress, const std::int32_t requestedSectorCount)
  {
    if (streamHandleAddress != 0) {
      ADXSTM_SetReqRdSize(SjAddressToPointer(streamHandleAddress), requestedSectorCount);
    }
    return 0;
  }

  /**
   * Address: 0x00AD8F90 (FUN_00AD8F90, _MWSTM_SetTrSct)
   */
  std::int32_t MWSTM_SetTrSct(const std::int32_t streamHandleAddress, const std::int32_t transferSectorCount)
  {
    (void)streamHandleAddress;
    (void)transferSectorCount;
    return 0;
  }

  /**
   * Address: 0x00AD9020 (FUN_00AD9020, _MWSTM_Start)
   */
  std::int32_t MWSTM_Start(const std::int32_t streamHandleAddress)
  {
    ADXSTM_Start(SjAddressToPointer(streamHandleAddress));
    return 0;
  }

  /**
   * Address: 0x00AD9030 (FUN_00AD9030, _MWSTM_IsFsStatErr)
   */
  bool MWSTM_IsFsStatErr(const std::int32_t streamHandleAddress)
  {
    return ADXSTM_GetStat(SjAddressToPointer(streamHandleAddress)) == kAdxstmStatusFilesystemError;
  }

  /**
   * Address: 0x00B165D0 (FUN_00B165D0, sub_B165D0)
   *
   * What it does:
   * Stores ADXPC DVD-error reporting mode flag and returns the written value.
   */
  std::int32_t ADXPC_SetDvdErrorReportingEnabled(const std::int32_t enabled)
  {
    gAdxpcDvdErrorReportingEnabled = enabled;
    return enabled;
  }

  /**
   * Address: 0x00B162E0 (FUN_00B162E0, sub_B162E0)
   */
  std::int32_t SofdecWarmRestoreProbePlayback()
  {
    if (SofdecCreateRestoreProbeBuffer() != 1) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrCreatePlaybackFailed);
      SofdecShutdownRestoreProbeBuffer();
      return 0;
    }

    const std::int32_t playResult = gSofdecRestoreProbeBuffer->lpVtbl->Play(
      gSofdecRestoreProbeBuffer,
      0,
      0,
      DSBPLAY_LOOPING
    );
    if (playResult == 0) {
      SofdecPollBufferPlaybackState(gSofdecRestoreProbeBuffer, true);
    }
    return playResult;
  }

  /**
   * Address: 0x00B163D0 (FUN_00B163D0, sub_B163D0)
   */
  void SofdecStopWarmRestoreProbeAndShutdown()
  {
    if (gSofdecRestoreProbeBuffer->lpVtbl->Stop(gSofdecRestoreProbeBuffer) == 0) {
      SofdecPollBufferPlaybackState(gSofdecRestoreProbeBuffer, false);
      SofdecShutdownRestoreProbeBuffer();
    }
  }

  /**
   * Address: 0x00B16A20 (FUN_00B16A20, SofDecVirt2_Func4)
   */
  std::int32_t SofdecLockProbeWindowAndGetFrameSpan(moho::SofdecSoundPort* const soundPort)
  {
    void* lockedPrimary = soundPort;
    DWORD lockedPrimaryBytes = 0;
    void* lockedSecondary = nullptr;
    DWORD lockedSecondaryBytes = 0;

    const std::int32_t lockResult = soundPort->primaryBuffer->lpVtbl->Lock(
      soundPort->primaryBuffer,
      0,
      8,
      &lockedPrimary,
      &lockedPrimaryBytes,
      &lockedSecondary,
      &lockedSecondaryBytes,
      0
    );
    if (lockResult != 0 && SofdecRestoreBufferIfLost(soundPort->primaryBuffer, lockResult) == 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrLockFailed);
      return 0;
    }

    soundPort->primaryBuffer->lpVtbl->Unlock(
      soundPort->primaryBuffer,
      lockedPrimary,
      lockedPrimaryBytes,
      lockedSecondary,
      lockedSecondaryBytes
    );
    if (lockResult != 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrUnlockFailed);
    }

    soundPort->playbackCursorByteOffset = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(lockedPrimary));
    return static_cast<std::int32_t>((static_cast<std::int32_t>(gSofdecPortBufferBytesPerChannel) / soundPort->format.bitsPerSample) * 8);
  }

  /**
   * Address: 0x00B16DE0 (FUN_00B16DE0, sub_B16DE0)
   */
  std::int32_t SofdecApplySpatialPresetInternal(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t channelLane,
    const std::int32_t presetIndex
  )
  {
    if (soundPort->monoRoutingMode == 1) {
      return 1;
    }

    if (channelLane != 0 || soundPort->channelModeFlag != 1) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetPanFailed);
    }

    soundPort->spatialPresetPrimaryIndex = presetIndex;
    const std::int32_t spatialOffset = SofdecLookupSpatialVolumeOffsetMillibel(presetIndex);
    soundPort->spatialPresetVolumeOffset = spatialOffset;
    const std::int32_t effectiveVolume = SofdecClampMillibel(soundPort->baseVolumeMilliBel + spatialOffset);

    soundPort->primaryBuffer->lpVtbl->SetPan(
      soundPort->primaryBuffer,
      SofdecLookupSpatialPanMillibel(presetIndex)
    );
    return soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, effectiveVolume);
  }

  /**
   * Address: 0x00B16E60 (FUN_00B16E60, sub_B16E60)
   */
  std::int32_t SofdecResetSpatialPreset(moho::SofdecSoundPort* const soundPort)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->monoRoutingMode != 1) {
      soundPort->spatialPresetVolumeOffset = 0;
      soundPort->primaryBuffer->lpVtbl->SetPan(soundPort->primaryBuffer, 0);
      result = soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, soundPort->baseVolumeMilliBel);
    }

    return result;
  }

  /**
   * Address: 0x00B16AD0 (FUN_00B16AD0, SofDecVirt2_Func5)
   */
  std::int32_t SofdecSetChannelMode(moho::SofdecSoundPort* const soundPort, const std::int32_t channelMode)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->used != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      soundPort->channelModeFlag = channelMode;
      if (soundPort->monoRoutingMode != 1 && soundPort->spatialPresetEnabled == 1) {
        if (channelMode == 1 && soundPort->channelCountPrimary == 1) {
          return SofdecApplySpatialPresetInternal(soundPort, 0, soundPort->spatialPresetPrimaryIndex);
        }
        return SofdecResetSpatialPreset(soundPort);
      }
    }

    return result;
  }

  /**
   * Address: 0x00B16B10 (FUN_00B16B10, SofDecVirt2_Func6)
   */
  std::int32_t SofdecGetPlaybackFrameCursor(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return 0;
    }
    if (soundPort->playbackCursorResetPending == 1) {
      return 0;
    }

    DWORD playCursor = 0;
    DWORD writeCursor = 0;
    if (soundPort->primaryBuffer->lpVtbl->GetCurrentPosition(soundPort->primaryBuffer, &playCursor, &writeCursor) != 0) {
      return 0;
    }

    const std::uint32_t bytesPerSample = static_cast<std::uint32_t>(soundPort->format.bitsPerSample >> 3);
    return static_cast<std::int32_t>(playCursor / bytesPerSample / static_cast<std::uint32_t>(soundPort->channelCountPrimary));
  }

  /**
   * Address: 0x00B16B80 (FUN_00B16B80, SofDecVirt2_Func7)
   */
  std::int32_t SofdecSetPlaybackFrequencyHz(moho::SofdecSoundPort* const soundPort, const std::int32_t frequencyHz)
  {
    std::int32_t result = soundPort->used;
    if (result != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      result = frequencyHz;
      if (frequencyHz > kSofdecFrequencyMaxHz) {
        result = kSofdecFrequencyMaxHz;
      } else if (frequencyHz < kSofdecFrequencyMinHz) {
        result = kSofdecFrequencyMinHz;
      }
      soundPort->format.samplesPerSecond = static_cast<std::uint32_t>(result);
    }
    return result;
  }

  /**
   * Address: 0x00B16BD0 (FUN_00B16BD0, SofDecVirt2_Func8)
   */
  std::int32_t SofdecGetPlaybackFrequencyHz(moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return static_cast<std::int32_t>(soundPort->format.samplesPerSecond);
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16C00 (FUN_00B16C00, SofDecVirt2_Func9)
   */
  std::int32_t SofdecSetOutputBitsPerSample(moho::SofdecSoundPort* const soundPort, const std::int16_t bitsPerSample)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(soundPort));
    if (soundPort->used != 0) {
      if (soundPort->primaryBuffer != nullptr) {
        soundPort->format.bitsPerSample = static_cast<std::uint16_t>(bitsPerSample);
      } else {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }
    }

    return result;
  }

  /**
   * Address: 0x00B16C30 (FUN_00B16C30, SofDecVirt2_Func10)
   */
  std::int32_t SofdecGetOutputBitsPerSample(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return soundPort->format.bitsPerSample;
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16C60 (FUN_00B16C60, SofDecVirt2_Func11)
   */
  std::int32_t SofdecSetBaseVolumeLevel(moho::SofdecSoundPort* const soundPort, const std::int32_t volumeLane)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer == nullptr) {
      return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }

    const std::int32_t baseVolume = SofdecClampMillibel(10 * volumeLane);
    soundPort->baseVolumeMilliBel = baseVolume;
    const std::int32_t effectiveVolume = SofdecClampMillibel(baseVolume + soundPort->spatialPresetVolumeOffset);
    if (soundPort->primaryBuffer->lpVtbl->SetVolume(soundPort->primaryBuffer, effectiveVolume) != 0) {
      return ADXERR_CallErrFunc1_(kSofdecErrSetVolumeFailed);
    }

    return 0;
  }

  /**
   * Address: 0x00B16CE0 (FUN_00B16CE0, SofDecVirt2_Func12)
   */
  std::int32_t SofdecValidatePrimaryBufferForVolumeOps(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used != 0 && soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }
    return 0;
  }

  /**
   * Address: 0x00B16D60 (FUN_00B16D60, SofDecVirt2_Func13)
   */
  moho::SofdecSoundPort* SofdecConfigureSpatialPreset(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t channelLane,
    const std::int32_t presetIndex
  )
  {
    if (soundPort->used == 0) {
      return soundPort;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return soundPort;
    }
    if (soundPort->monoRoutingMode == 1) {
      return soundPort;
    }

    soundPort->spatialPresetEnabled = 1;
    if (soundPort->channelCountPrimary == 1 && soundPort->channelModeFlag == 1) {
      (void)SofdecApplySpatialPresetInternal(soundPort, 0, presetIndex);
      return soundPort;
    }

    if (channelLane == 0) {
      soundPort->spatialPresetPrimaryIndex = presetIndex;
    } else if (channelLane == 1) {
      soundPort->spatialPresetSecondaryIndex = presetIndex;
    }
    soundPort->spatialPresetVolumeOffset = 0;
    return soundPort;
  }

  /**
   * Address: 0x00B16E90 (FUN_00B16E90, SofDecVirt2_Func14)
   */
  std::int32_t SofdecValidatePrimaryBufferForBalanceOps(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used != 0 && soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    }
    return 0;
  }

  /**
   * Address: 0x00B16EC0 (FUN_00B16EC0, SofDecVirt2_Func15)
   */
  void SofdecSetBalanceIndex(moho::SofdecSoundPort* const soundPort, std::int32_t balanceIndex)
  {
    if (soundPort->monoRoutingMode == 1 || soundPort->used == 0) {
      return;
    }
    if (soundPort->primaryBuffer == nullptr) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      return;
    }

    if (balanceIndex < kSofdecBalanceIndexMin) {
      balanceIndex = kSofdecBalanceIndexMin;
    } else if (balanceIndex > kSofdecBalanceIndexMax) {
      balanceIndex = kSofdecBalanceIndexMax;
    }
    soundPort->balanceIndex = balanceIndex;

    if (soundPort->primaryBuffer->lpVtbl->SetPan(soundPort->primaryBuffer, SofdecLookupBalancePanMillibel(balanceIndex)) != 0) {
      (void)ADXERR_CallErrFunc1_(kSofdecErrSetPanFailed);
    }
  }

  /**
   * Address: 0x00B16F30 (FUN_00B16F30, SofDecVirt2_Func16)
   */
  std::int32_t SofdecGetBalanceIndex(const moho::SofdecSoundPort* const soundPort)
  {
    if (soundPort->used == 0) {
      return 0;
    }
    if (soundPort->primaryBuffer != nullptr) {
      return soundPort->balanceIndex;
    }

    (void)ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
    return 0;
  }

  /**
   * Address: 0x00B16F60 (FUN_00B16F60, sub_B16F60)
   */
  std::int32_t SofdecApplyControlFrequencyInternal(moho::SofdecSoundPort* const soundPort, const std::int32_t frequencyHz)
  {
    std::int32_t result = soundPort->used;
    if (result != 0) {
      if (soundPort->primaryBuffer == nullptr) {
        return ADXERR_CallErrFunc1_(kSofdecErrNullPrimaryBuffer);
      }

      (void)SofdecSetPlaybackFrequencyHz(soundPort, frequencyHz);
      result = SofdecGetPlaybackFrequencyHz(soundPort);
      if (soundPort->bufferPlacementMode == 0) {
        result = soundPort->primaryBuffer->lpVtbl->SetFrequency(soundPort->primaryBuffer, result);
        if (result != 0) {
          return ADXERR_CallErrFunc1_(kSofdecErrControlSetFrequencyFailed);
        }
      }
    }
    return result;
  }

  /**
   * Address: 0x00B16FC0 (FUN_00B16FC0, SofDecVirt2_Func17)
   */
  std::int32_t SofdecControlSetValue(
    moho::SofdecSoundPort* const soundPort,
    const std::int32_t controlCode,
    const std::int32_t controlValue
  )
  {
    if (controlCode == 5) {
      return SofdecApplyControlFrequencyInternal(soundPort, controlValue);
    }
    return 0;
  }

  /**
   * Address: 0x00B16FE0 (FUN_00B16FE0, SofDecVirt2_Func18)
   */
  std::int32_t* SofdecQueryPendingWindow(
    const std::int32_t contextLane,
    const std::int32_t queryLane,
    std::int32_t* const outPrimary,
    std::int32_t* const outSecondary
  )
  {
    (void)contextLane;
    (void)queryLane;
    *outPrimary = 0;
    *outSecondary = 0;
    return outPrimary;
  }

  /**
   * Address: 0x00B0C9F0 (FUN_00B0C9F0, _SVM_TestAndSet)
   *
   * What it does:
   * Writes `1` into one signal lane under Sofdec lock semantics and returns
   * whether the lane was not already set.
   */
  BOOL SVM_TestAndSet(std::int32_t* const signalLane)
  {
    if (gSofdecTestAndSetOverride != nullptr) {
      return gSofdecTestAndSetOverride(signalLane);
    }

    SVM_Lock();
    const std::int32_t previousValue = *signalLane;
    *signalLane = 1;
    const BOOL changed = (previousValue != 1) ? TRUE : FALSE;
    SVM_Unlock();
    return changed;
  }

  /**
   * Address: 0x00B1F270 (FUN_00B1F270, j_func_SofdecSetTrue_1)
   *
   * What it does:
   * Forwards one signal lane to `_SVM_TestAndSet`.
   */
  BOOL SofdecSetTrueThunk(std::int32_t* const signalLane)
  {
    return SVM_TestAndSet(signalLane);
  }

  /**
   * Address: 0x00B07410 (FUN_00B07410, func_AdxmSetInterval1)
   *
   * What it does:
   * Sets ADXM interval lane #1 and returns the previous interval value.
   */
  std::int32_t ADXM_SetInterval1(const std::int32_t interval)
  {
    const std::int32_t previousValue = gAdxmInterval1;
    gAdxmInterval1 = interval;
    return previousValue;
  }

  /**
   * Address: 0x00B13F90 (FUN_00B13F90, j_func_sofdecSetInterval1)
   *
   * What it does:
   * Forwards interval update to `ADXM_SetInterval1`.
   */
  std::int32_t ADXM_SetInterval1Thunk(const std::int32_t interval)
  {
    return ADXM_SetInterval1(interval);
  }

  /**
   * Address: 0x00B07420 (FUN_00B07420, sub_B07420)
   *
   * What it does:
   * Returns current ADXM interval lane #1.
   */
  std::int32_t ADXM_GetInterval1()
  {
    return gAdxmInterval1;
  }

  /**
   * Address: 0x00B074B0 (FUN_00B074B0, func_SofdecSetFunc1)
   *
   * What it does:
   * Publishes frame-read callback after signal acquisition handshake.
   */
  std::int32_t SofdecSetFrameReadCallback(std::uint32_t(__cdecl* const callback)())
  {
    const std::int32_t acquired = SofdecWaitForSignal2(gSofdecSignalLane2);
    if (acquired == 0) {
      return 0;
    }

    gSofdecFrameReadCallback = callback;
    SofdecSignalReleaseNoOp(gSofdecSignalLane2);
    return 1;
  }

  /**
   * Address: 0x00B074F0 (FUN_00B074F0, sub_B074F0)
   *
   * What it does:
   * Sets ADXM interval lane #2 and returns the written value.
   */
  std::int32_t ADXM_SetInterval2(const std::int32_t interval)
  {
    gAdxmInterval2 = interval;
    return interval;
  }

  /**
   * Address: 0x00B07500 (FUN_00B07500, func_SofdecSetScreenHeight2)
   *
   * What it does:
   * Sets Sofdec secondary screen-height lane and returns the written value.
   */
  std::int32_t SofdecSetScreenHeight2(const std::int32_t screenHeight)
  {
    gSofdecScreenHeight2 = screenHeight;
    return screenHeight;
  }

  /**
   * Address: 0x00B07870 (FUN_00B07870, func_SofdecWaitForSignal2)
   *
   * What it does:
   * Repeatedly tests-and-sets one local signal lane for up to 1000 retries.
   */
  std::int32_t SofdecWaitForSignal2(const std::int32_t signalLaneValue)
  {
    std::int32_t retries = 0;
    std::int32_t signalLane = signalLaneValue;
    while (SVM_TestAndSet(&signalLane) != TRUE) {
      Sleep(1u);
      ++retries;
      if (retries >= 1000) {
        return 0;
      }
    }

    return 1;
  }

  /**
   * Address: 0x00B078B0 (FUN_00B078B0, nullsub_30)
   *
   * What it does:
   * No-op signal-release callback lane.
   */
  void SofdecSignalReleaseNoOp(const std::int32_t signalLaneValue)
  {
    (void)signalLaneValue;
  }

  /**
   * Address: 0x00B078C0 (FUN_00B078C0, sub_B078C0)
   *
   * What it does:
   * Applies global scanline offset with underflow handling used by timing lanes.
   */
  std::uint32_t SofdecApplyScanlineOffset(std::uint32_t* const valueInOut, const std::uint32_t clampMax)
  {
    std::uint32_t result = static_cast<std::uint32_t>(gSofdecScanlineOffset);
    if (gSofdecScanlineOffset != 0) {
      result = *valueInOut;
      if (*valueInOut < clampMax) {
        if (gSofdecScanlineOffset >= 0) {
          *valueInOut = result + static_cast<std::uint32_t>(gSofdecScanlineOffset);
        } else {
          const std::uint32_t offsetMagnitude = 0u - static_cast<std::uint32_t>(gSofdecScanlineOffset);
          if (result >= offsetMagnitude) {
            *valueInOut = result + static_cast<std::uint32_t>(gSofdecScanlineOffset);
          } else {
            *valueInOut = 0xFFFFFFFFu;
          }
        }
      }
    }

    return result;
  }

  /**
   * Address: 0x00B07900 (FUN_00B07900, sub_B07900)
   *
   * What it does:
   * Sets global scanline offset lane and returns the written value.
   */
  std::int32_t SofdecSetScanlineOffset(const std::int32_t offset)
  {
    gSofdecScanlineOffset = offset;
    return offset;
  }

  /**
   * Address: 0x00B07430 (FUN_00B07430, sub_B07430)
   *
   * What it does:
   * Arms ADXM multimedia-timer switch lanes and returns previous state.
   */
  std::int32_t ADXM_ArmMultimediaTimerSwitch()
  {
    const std::int32_t previousState = gAdxmTimerSwitchState;
    if (gAdxmTimerSwitchState == 0) {
      gAdxmTimerSwitchSignal = 1;
      gAdxmTimerSwitchState = 1;
      return 1;
    }

    return previousState;
  }

  /**
   * Address: 0x00B07450 (FUN_00B07450, sub_B07450)
   *
   * What it does:
   * Disarms ADXM multimedia-timer switch lanes and starts 1ms multimedia timer.
   */
  void ADXM_StartMultimediaTimer()
  {
    if (gAdxmTimerSwitchState == 1) {
      gAdxmTimerSwitchState = 0;
      gAdxmTimerSwitchSignal = 0;
      timeBeginPeriod(1u);
      gAdxmMultimediaTimerId = timeSetEvent(1u, 0u, gAdxmMultimediaTimerCallback, 0u, 0u);
    }
  }

  /**
   * Address: 0x00B07490 (FUN_00B07490, sub_B07490)
   *
   * What it does:
   * Pulses ADXM sync event lane when present and returns event handle/result.
   */
  void* ADXM_PulseSyncEvent()
  {
    HANDLE result = gAdxmSyncEventHandle;
    if (gAdxmSyncEventHandle != nullptr) {
      result = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(PulseEvent(gAdxmSyncEventHandle)));
    }
    return result;
  }

  /**
   * Address: 0x00B07750 (FUN_00B07750, sub_B07750)
   *
   * What it does:
   * Waits until current scanline reaches target window for one interval.
   */
  std::int32_t ADXM_WaitForScanlineTarget(const std::uint32_t interval, const std::uint32_t screenHeight)
  {
    std::uint32_t currentScanline = gSofdecFrameReadCallback();
    SofdecApplyScanlineOffset(&currentScanline, screenHeight);

    std::uint32_t boundedScanline = currentScanline;
    if (currentScanline > screenHeight) {
      boundedScanline = 0;
      currentScanline = 0;
    }

    const std::int32_t spinThresholdMicroseconds = AdxmComputeSpinThresholdMicroseconds(interval, screenHeight);
    const std::int32_t sleepMilliseconds = AdxmComputeSleepMilliseconds(interval, screenHeight, boundedScanline);
    if (sleepMilliseconds > 1) {
      timeBeginPeriod(1u);
      Sleep(static_cast<DWORD>(sleepMilliseconds));
      (void)timeEndPeriod(1u);
      boundedScanline = currentScanline;
    }

    if (boundedScanline < screenHeight) {
      LARGE_INTEGER spinStart{};
      LARGE_INTEGER spinEnd{};
      do {
        QueryPerformanceCounter(&spinStart);
        do {
          QueryPerformanceCounter(&spinEnd);
        } while (AdxmElapsedMicroseconds(spinStart, spinEnd, gAdxmPerformanceFrequency) < spinThresholdMicroseconds);

        currentScanline = gSofdecFrameReadCallback();
        SofdecApplyScanlineOffset(&currentScanline, screenHeight);
      } while (
        currentScanline <= screenHeight && currentScanline >= (screenHeight >> 1u) && currentScanline < screenHeight
      );
    }

    return static_cast<std::int32_t>(currentScanline);
  }

  /**
   * Address: 0x00B07A70 (FUN_00B07A70, sub_B07A70)
   *
   * What it does:
   * Waits until scanline drops to lower-half window for current interval.
   */
  std::uint32_t ADXM_WaitForScanlineHalfWindow(const std::uint32_t interval, const std::uint32_t screenHeight)
  {
    std::uint32_t currentScanline = gSofdecFrameReadCallback();
    SofdecApplyScanlineOffset(&currentScanline, screenHeight);

    std::uint32_t boundedScanline = currentScanline;
    if (currentScanline > screenHeight) {
      boundedScanline = 0;
    }

    const std::int32_t spinThresholdMicroseconds = AdxmComputeSpinThresholdMicroseconds(interval, screenHeight);
    const std::int32_t sleepMilliseconds = AdxmComputeSleepMilliseconds(interval, screenHeight, boundedScanline);
    if (sleepMilliseconds > 1) {
      timeBeginPeriod(1u);
      Sleep(static_cast<DWORD>(sleepMilliseconds));
      (void)timeEndPeriod(1u);
    }

    const std::uint32_t halfHeight = screenHeight >> 1u;
    LARGE_INTEGER spinStart{};
    LARGE_INTEGER spinEnd{};
    while (true) {
      currentScanline = gSofdecFrameReadCallback();
      SofdecApplyScanlineOffset(&currentScanline, screenHeight);
      if (currentScanline <= halfHeight) {
        break;
      }

      QueryPerformanceCounter(&spinStart);
      do {
        QueryPerformanceCounter(&spinEnd);
      } while (AdxmElapsedMicroseconds(spinStart, spinEnd, gAdxmPerformanceFrequency) < spinThresholdMicroseconds);
    }

    return currentScanline;
  }

  /**
   * Address: 0x00B07910 (FUN_00B07910, sub_B07910)
   *
   * What it does:
   * Updates ADXM scanline synchronization for active callback lane.
   */
  std::int32_t ADXM_UpdateScanlineSync()
  {
    if (gSofdecFrameReadCallback == nullptr) {
      if (gAdxmSyncEventHandle != nullptr) {
        WaitForSingleObject(gAdxmSyncEventHandle, INFINITE);
      }
      return static_cast<std::int32_t>(QueryPerformanceCounter(&gAdxmLastSyncCounter));
    }

    std::int32_t result = gAdxmInterval1;
    if (gAdxmInterval1 == 0) {
      return result;
    }

    if (gAdxmPerformanceFrequency == 0) {
      LARGE_INTEGER frequency{};
      QueryPerformanceFrequency(&frequency);
      gAdxmPerformanceFrequency = frequency.QuadPart;
    }

    result = SofdecWaitForSignal2(gSofdecSignalLane2);
    if (result == 0) {
      return result;
    }

    if (gSofdecFrameReadCallback != nullptr) {
      std::uint32_t currentScanline = gSofdecFrameReadCallback();
      SofdecApplyScanlineOffset(&currentScanline, static_cast<std::uint32_t>(gSofdecScreenHeight2));
      const std::uint32_t halfHeight = static_cast<std::uint32_t>(gSofdecScreenHeight2) >> 1u;

      if (currentScanline < halfHeight) {
        QueryPerformanceCounter(&gAdxmProbeCounter);
        const std::int64_t elapsedMicroseconds =
          (1000000LL * (gAdxmLastSyncCounter.QuadPart - gAdxmProbeCounter.QuadPart)) / gAdxmPerformanceFrequency;
        const std::int32_t halfIntervalMicroseconds = static_cast<std::int32_t>((100000000u / gAdxmInterval1) >> 1u);
        if (elapsedMicroseconds < halfIntervalMicroseconds) {
          (void)ADXM_WaitForScanlineHalfWindow(
            static_cast<std::uint32_t>(gAdxmInterval1), static_cast<std::uint32_t>(gSofdecScreenHeight2)
          );
        }
      } else {
        (void)ADXM_WaitForScanlineHalfWindow(
          static_cast<std::uint32_t>(gAdxmInterval1), static_cast<std::uint32_t>(gSofdecScreenHeight2)
        );
      }
    }

    return static_cast<std::int32_t>(QueryPerformanceCounter(&gAdxmLastSyncCounter));
  }

  /**
   * Address: 0x00B07C90 (FUN_00B07C90, j_func_NewThread)
   *
   * What it does:
   * Forwards thread creation to CRT `_beginthreadex`.
   */
  HANDLE ADXM_BeginThreadThunk(
    LPSECURITY_ATTRIBUTES threadAttributes,
    const SIZE_T stackSizeBytes,
    unsigned(__stdcall* threadEntry)(void*),
    void* threadArgument,
    const DWORD creationFlags,
    LPDWORD threadId
  )
  {
    return reinterpret_cast<HANDLE>(
      _beginthreadex(
        threadAttributes,
        static_cast<unsigned>(stackSizeBytes),
        threadEntry,
        threadArgument,
        static_cast<unsigned>(creationFlags),
        reinterpret_cast<unsigned*>(threadId)
      )
    );
  }

  /**
   * Address: 0x00B207F0 (adxrna_Init)
   *
   * What it does:
   * Clears active lanes for all fixed RNA timing-node pool slots.
   */
  moho::AdxrnaTimingState* adxrna_Init()
  {
    (void)kRnaVersionBanner;
    return ResetAdxrnaTimingPoolActiveFlags();
  }

  /**
   * Address: 0x00B20820 (SofDecVirt1::Func2)
   *
   * What it does:
   * Clears active lanes for all fixed RNA timing-node pool slots.
   */
  moho::AdxrnaTimingState* SofDecVirtual1ResetTimingPool()
  {
    return ResetAdxrnaTimingPoolActiveFlags();
  }

  /**
   * Address: 0x00B20840 (func_NewAdxbObj)
   *
   * What it does:
   * Returns first free RNA timing-node pool slot by active-lane scan.
   */
  moho::AdxrnaTimingState* SofDecAcquireTimingStateSlot()
  {
    return AcquireFreeAdxrnaTimingState();
  }

  /**
   * Address: 0x00B20870 (SofDecVirt::Func4 body)
   *
   * What it does:
   * Resets one RNA timing-node runtime state lane.
   */
  std::int32_t SofDecVirtualResetTimingState(moho::AdxrnaTimingState* timingState)
  {
    std::memset(timingState, 0, sizeof(*timingState));
    timingState->activeFlag = 0;
    return 0;
  }

  /**
   * Address: 0x00B20890 (SofDecVirt1::Func3)
   *
   * What it does:
   * Acquires one RNA timing-node slot and seeds default dispatch/time lanes.
   */
  moho::AdxrnaTimingState* SofDecVirtual1CreateTimingState()
  {
    auto* const timingState = SofDecAcquireTimingStateSlot();
    timingState->dispatchTable = const_cast<void*>(static_cast<const void*>(GetSofDecVirtualDispatchTable()));
    timingState->sampleRate = 44100;
    timingState->phaseModulo = 0x4000;
    timingState->playheadSample = 0;
    timingState->latchedSample = 0;
    timingState->wrapPosition = 0;
    timingState->mode = 0;
    timingState->activeFlag = 1;
    return timingState;
  }

  /**
   * Address: 0x00B208C0 (SofDecVirt::Func4)
   *
   * What it does:
   * Thunk slot forwarding to timing-state reset helper.
   */
  std::int32_t SofDecVirtualResetStateThunk(moho::AdxrnaTimingState* timingState)
  {
    return SofDecVirtualResetTimingState(timingState);
  }

  /**
   * Address: 0x00B208D0 (SofDecVirt::Func5)
   *
   * What it does:
   * Updates current playhead sample lane from RNA clock or latched sample.
   */
  std::int32_t SofDecVirtualUpdatePlayheadSample(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    if (timingState->mode == 1) {
      timingState->playheadSample = timingState->latchedSample;
      return timingState->playheadSample;
    }

    timingState->playheadSample = ConvertMicrosToSamples(micros, kMicrosToSamples);
    return timingState->playheadSample;
  }

  /**
   * Address: 0x00B20920 (SofDecVirt::Func6)
   *
   * What it does:
   * Captures RNA clock-derived sample lane into latched sample field.
   */
  std::int32_t SofDecVirtualCaptureLatchedSample(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    const auto sample = ConvertMicrosToSamples(micros, kMicrosToSamples);
    timingState->latchedSample = sample;
    return sample;
  }

  /**
   * Address: 0x00B20960 (SofDecVirt::Func7)
   *
   * What it does:
   * Returns default phase-modulo lane constant.
   */
  std::int32_t SofDecVirtualGetDefaultPhaseModulo()
  {
    return 0x4000;
  }

  /**
   * Address: 0x00B20970 (SofDecVirt::Func8)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotA()
  {
  }

  /**
   * Address: 0x00B20980 (SofDecVirt::Func9)
   *
   * What it does:
   * Recomputes wrap-position lane and returns phase modulo remainder.
   */
  std::int32_t SofDecVirtualUpdateWrapPosition(moho::AdxrnaTimingState* timingState)
  {
    std::int32_t micros = 0;
    if (adxrna_GetTime != nullptr) {
      micros = adxrna_GetTime();
    }

    const auto sampleDelta = ConvertMicrosToSamples(micros, kMicrosToNegativeSamples);
    const auto wrapPosition =
      static_cast<std::uint32_t>(-timingState->playheadSample - sampleDelta);
    timingState->wrapPosition = wrapPosition;
    return static_cast<std::int32_t>(wrapPosition % timingState->phaseModulo);
  }

  /**
   * Address: 0x00B209D0 (SofDecVirt::Func10)
   *
   * What it does:
   * Sets sample-rate lane and returns assigned value.
   */
  std::int32_t SofDecVirtualSetSampleRate(moho::AdxrnaTimingState* timingState, const std::int32_t sampleRate)
  {
    timingState->sampleRate = sampleRate;
    return sampleRate;
  }

  /**
   * Address: 0x00B209E0 (SofDecVirt::Func11)
   *
   * What it does:
   * Returns current sample-rate lane.
   */
  std::int32_t SofDecVirtualGetSampleRate(const moho::AdxrnaTimingState* timingState)
  {
    return timingState->sampleRate;
  }

  /**
   * Address: 0x00B209F0 (SofDecVirt::Func12)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotB()
  {
  }

  /**
   * Address: 0x00B20A00 (SofDecVirt::Func13)
   *
   * What it does:
   * Returns constant bit-depth lane used by RNA decoder runtime.
   */
  std::int32_t SofDecVirtualGetOutputBitDepth()
  {
    return 16;
  }

  /**
   * Address: 0x00B20A10 (SofDecVirt::Func14)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotC()
  {
  }

  /**
   * Address: 0x00B20A20 (SofDecVirt::Func15)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualReturnZeroSlotD()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A30 (SofDecVirt::Func16)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualNoOpSlotE()
  {
  }

  /**
   * Address: 0x00B20A40 (SofDecVirt::Func17)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroA()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A50 (SofDecVirt::Func18)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpA()
  {
  }

  /**
   * Address: 0x00B20A60 (SofDecVirt::Func19)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroB()
  {
    return 0;
  }

  /**
   * Address: 0x00B20A70 (SofDecVirt::Func20)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpB()
  {
  }

  /**
   * Address: 0x00B20A80 (SofDecVirt::Func21)
   *
   * What it does:
   * Stub virtual slot: clears both output lanes and returns first output lane.
   */
  std::int32_t* SofDecVirtualStubZeroRangeOutputs(
    std::int32_t /*self*/,
    std::int32_t /*unused*/,
    std::int32_t* outLane0,
    std::int32_t* outLane1
  )
  {
    *outLane0 = 0;
    *outLane1 = 0;
    return outLane0;
  }

  /**
   * Address: 0x00B20AA0 (SofDecVirt::Func22)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpC()
  {
  }

  /**
   * Address: 0x00B20AB0 (SofDecVirt::Func23)
   *
   * What it does:
   * Stub virtual slot: no-op.
   */
  void SofDecVirtualStubNoOpD()
  {
  }

  /**
   * Address: 0x00B20AC0 (SofDecVirt::Func24)
   *
   * What it does:
   * Stub virtual slot: returns one.
   */
  std::int32_t SofDecVirtualStubReturnOne()
  {
    return 1;
  }

  /**
   * Address: 0x00B20AD0 (SofDecVirt::Func25)
   *
   * What it does:
   * Marks `readyFlag` lane and returns zero.
   */
  std::int32_t SofDecVirtualStubSetReadyFlag(moho::SofDecVirtualStateSubobj* self)
  {
    self->readyFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00B20AE0 (SofDecVirt::Func26)
   *
   * What it does:
   * Stub virtual slot: returns zero.
   */
  std::int32_t SofDecVirtualStubReturnZeroC()
  {
    return 0;
  }

  /**
   * Address: 0x00B20AF0 (func_SofDecGetTime)
   *
   * What it does:
   * Returns monotonic performance-counter time in microseconds.
   */
  std::int32_t SofDecGetTimeMicroseconds()
  {
    LARGE_INTEGER frequency{};
    if (QueryPerformanceFrequency(&frequency) == 0) {
      return 0;
    }

    LARGE_INTEGER performanceCount{};
    QueryPerformanceCounter(&performanceCount);

    const double micros = static_cast<double>(performanceCount.QuadPart) / (static_cast<double>(frequency.QuadPart) * 0.000001);
    return static_cast<std::int32_t>(micros);
  }

  /**
   * Address: 0x00B20B30 (ADXB_SetDecErrMode)
   *
   * What it does:
   * Sets process-global ADXB decode-error mode lane.
   */
  std::int32_t ADXB_SetDecErrMode(const std::int32_t decodeErrorMode)
  {
    adxb_dec_err_mode = decodeErrorMode;
    return decodeErrorMode;
  }

  /**
   * Address: 0x00B20B40 (ADXB_GetDecErrMode)
   *
   * What it does:
   * Returns process-global ADXB decode-error mode lane.
   */
  std::int32_t ADXB_GetDecErrMode()
  {
    return adxb_dec_err_mode;
  }

  /**
   * Address: 0x00B20B50 (ADXB_Init)
   *
   * What it does:
   * Initializes ADXB runtime globals and clears decoder object pool.
   */
  std::int32_t ADXB_Init()
  {
    ADXPD_Init();
    SKG_Init();
    std::memset(adxb_obj, 0, sizeof(adxb_obj));
    return ADXB_SetDecErrMode(0);
  }

  /**
   * Address: 0x00B20B80 (ADXB_Finish)
   *
   * What it does:
   * Shuts down ADXB runtime globals and clears decoder object pool.
   */
  std::int32_t ADXB_Finish()
  {
    ADXPD_Finish();
    SKG_Finish();
    std::memset(adxb_obj, 0, sizeof(adxb_obj));
    return 0;
  }

  /**
   * Address: 0x00B20BA0 (adxb_DefGetWr)
   *
   * What it does:
   * Default ADXB write-lane getter callback for one decoder instance.
   */
  std::int32_t adxb_DefGetWr(
    moho::AdxBitstreamDecoderState* decoder,
    std::int32_t* outCommittedBytes,
    std::int32_t* outRemainingBufferBytes,
    std::int32_t* outRemainingSamples
  )
  {
    *outCommittedBytes = decoder->entryCommittedBytes;
    *outRemainingBufferBytes =
      static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder->pcmBuffer1)) - decoder->entryCommittedBytes;
    *outRemainingSamples = decoder->totalSampleCount - decoder->entrySubmittedBytes;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder->pcmBuffer0));
  }

  /**
   * Address: 0x00B20BE0 (adxb_DefAddWr)
   *
   * What it does:
   * Default ADXB write-lane advance callback for one decoder instance.
   */
  std::int32_t adxb_DefAddWr(
    moho::AdxBitstreamDecoderState* decoder,
    std::int32_t /*unused*/,
    const std::int32_t writtenBytes
  )
  {
    decoder->entryCommittedBytes += writtenBytes;
    decoder->entrySubmittedBytes += writtenBytes;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder));
  }

  /**
   * Address: 0x00B20C10 (adxb_ResetAinf)
   *
   * What it does:
   * Clears AINF metadata lanes and restores default pan values.
   */
  std::uint8_t* adxb_ResetAinf(moho::AdxBitstreamDecoderState* decoder)
  {
    decoder->ainfLength = 0;
    decoder->defaultOutputVolume = 0;
    decoder->defaultPanByChannel[0] = -128;
    decoder->defaultPanByChannel[1] = -128;
    std::memset(decoder->dataIdBytes, 0, sizeof(decoder->dataIdBytes));
    return decoder->dataIdBytes;
  }

  /**
   * Address: 0x00B20C50 (ADXB_Create)
   *
   * What it does:
   * Allocates one ADXB decoder object from fixed runtime pool and initializes core lanes.
   */
  moho::AdxBitstreamDecoderState* ADXB_Create(void* pcmBufferTag, void* pcmBuffer0, void* pcmBuffer1, void* pcmBuffer2)
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < 32 && adxb_obj[slotIndex].slotState != 0) {
      ++slotIndex;
    }

    if (slotIndex == 32) {
      return nullptr;
    }

    auto* const decoder = &adxb_obj[slotIndex];
    std::memset(decoder, 0, sizeof(*decoder));
    decoder->slotState = 1;

    decoder->adxPacketDecoder = ADXPD_Create();
    if (decoder->adxPacketDecoder == nullptr) {
      ADXB_Destroy(decoder);
      return nullptr;
    }

    decoder->pcmBufferTag = pcmBufferTag;
    decoder->pcmBuffer0 = pcmBuffer0;
    decoder->pcmBuffer1 = pcmBuffer1;
    decoder->pcmBuffer2 = pcmBuffer2;
    decoder->entryGetWriteFunc = reinterpret_cast<void*>(adxb_DefGetWr);
    decoder->entryGetWriteContext = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder));
    decoder->entryAddWriteFunc = reinterpret_cast<void*>(adxb_DefAddWr);
    decoder->entryAddWriteContext = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(decoder));
    adxb_ResetAinf(decoder);
    return decoder;
  }

  /**
   * Address: 0x00B20CF0 (ADXB_Destroy)
   *
   * What it does:
   * Destroys ADXB decoder backend and clears one runtime slot.
   */
  std::int32_t ADXB_Destroy(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder == nullptr) {
      return 0;
    }

    void* const adxPacketDecoder = decoder->adxPacketDecoder;
    decoder->adxPacketDecoder = nullptr;
    ADXPD_Destroy(adxPacketDecoder);
    std::memset(decoder, 0, sizeof(*decoder));
    decoder->slotState = 0;
    return 0;
  }

  /**
   * Address: 0x00B20D20 (SKG_Init)
   *
   * What it does:
   * Increments global SKG init reference count.
   */
  std::int32_t SKG_Init()
  {
    ++skg_init_count;
    return 0;
  }

  /**
   * Address: 0x00B20D30 (SKG_Finish)
   *
   * What it does:
   * Decrements global SKG init reference count.
   */
  std::int32_t SKG_Finish()
  {
    --skg_init_count;
    return 0;
  }

  /**
   * Address: 0x00B20D40 (ADXB_DecodeHeaderAdx)
   *
   * What it does:
   * Decodes one ADX/AHX header and seeds ADXB decoder state lanes.
   */
  std::int32_t ADXB_DecodeHeaderAdx(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    const std::int32_t headerSize
  )
  {
    constexpr const char* kDecodeHeaderAdxPrefix = "E1060101 ADXB_DecodeHeaderAdx: ";
    constexpr const char* kCantPlayAhxByHandle = "can't play AHX data by this handle";

    std::int32_t headerIdentity = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder));
    decoder->initState = 1;

    if (ADX_DecodeInfo(
          headerBytes,
          headerSize,
          &headerIdentity,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceChannels,
          &decoder->sourceBlockBytes,
          &decoder->sourceBlockSamples,
          &decoder->sampleRate,
          &decoder->totalSampleCount
        ) < 0)
    {
      return 0;
    }

    if (decoder->headerType <= 4) {
      std::int32_t encryptionMode = 0;
      std::int32_t headerVersion = 0;
      if (ADX_DecodeInfoExVer(headerBytes, headerSize, &encryptionMode, &headerVersion) < 0) {
        return 0;
      }

      std::int16_t extKey0 = 0;
      std::int16_t extKeyMultiplier = 0;
      std::int16_t extKeyAdder = 0;
      if (adxb_get_key(
            decoder,
            static_cast<std::uint8_t>(encryptionMode),
            static_cast<std::uint8_t>(headerVersion),
            decoder->totalSampleCount,
            &extKey0,
            &extKeyMultiplier,
            &extKeyAdder
          ) < 0)
      {
        return -1;
      }

      ADXPD_SetExtPrm(decoder->adxPacketDecoder, extKey0, extKeyMultiplier, extKeyAdder);

      if (ADX_DecodeInfoExADPCM2(headerBytes, headerSize, &decoder->adpcmCoefficientIndex) < 0) {
        return 0;
      }

      std::int16_t decodeDelay0 = 0;
      std::int16_t decodeDelay1 = 0;
      if (ADX_DecodeInfoExIdly(headerBytes, headerSize, &decodeDelay0, &decodeDelay1) < 0) {
        return 0;
      }

      ADXPD_SetCoef(decoder->adxPacketDecoder, decoder->sampleRate, decoder->adpcmCoefficientIndex);
      ADXPD_SetDly(decoder->adxPacketDecoder, &decodeDelay0, &decodeDelay1);

      ADX_DecodeInfoExLoop(
        headerBytes,
        headerSize,
        &decoder->loopInsertedSamples,
        &decoder->loopCount,
        &decoder->loopType,
        &decoder->loopStartSample,
        &decoder->loopStartOffset,
        &decoder->loopEndSample,
        &decoder->loopEndOffset
      );

      ADX_DecodeInfoAinf(
        headerBytes,
        headerSize,
        &decoder->ainfLength,
        decoder->dataIdBytes,
        &decoder->defaultOutputVolume,
        decoder->defaultPanByChannel
      );

      decoder->format = 0;
    } else {
      if (decoder->ahxDecoderHandle == nullptr) {
        ADXERR_CallErrFunc2_(kDecodeHeaderAdxPrefix, kCantPlayAhxByHandle);
        return -1;
      }

      const auto signedChannels = static_cast<std::int16_t>(static_cast<std::int8_t>(decoder->sourceChannels));
      decoder->sourceBlockBytes = static_cast<std::int8_t>(signedChannels * static_cast<std::int16_t>(-64));
      decoder->sourceSampleBits = 8;
      decoder->sourceBlockSamples = 96;
      decoder->format = 10;
      decoder->adpcmCoefficientIndex = 0;
      decoder->loopCount = 0;
      decoder->loopType = 0;
      decoder->loopInsertedSamples = 0;
      decoder->loopStartSample = 0;
      decoder->loopStartOffset = 0;
      decoder->loopEndSample = 0;
      decoder->loopEndOffset = 0;
      decoder->entrySubmittedBytes = 0;

      std::int32_t encryptionMode = 0;
      std::int32_t headerVersion = 0;
      if (ADX_DecodeInfoExVer(headerBytes, headerSize, &encryptionMode, &headerVersion) < 0) {
        return 0;
      }

      std::int16_t ahxExtParams[4]{};
      if (adxb_get_key(
            decoder,
            static_cast<std::uint8_t>(encryptionMode),
            static_cast<std::uint8_t>(headerVersion),
            decoder->totalSampleCount,
            &ahxExtParams[1],
            &ahxExtParams[2],
            &ahxExtParams[3]
          ) < 0)
      {
        return -1;
      }

      if (ahxsetextfunc != nullptr) {
        ahxsetextfunc(decoder->ahxDecoderHandle, ahxExtParams);
      }
    }

    decoder->outputChannels = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceChannels));
    decoder->outputBlockBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceBlockBytes));
    decoder->outputBlockSamples = decoder->sourceBlockSamples;
    decoder->entryCommittedBytes = 0;
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;

    return static_cast<std::int16_t>(headerIdentity);
  }

  /**
   * Address: 0x00B20FE0 (ADXB_SetDefFmt)
   *
   * What it does:
   * Selects default ADXB output format from requested codec family.
   */
  void ADXB_SetDefFmt(moho::AdxBitstreamDecoderState* decoder, const std::int32_t requestedFormat)
  {
    constexpr const char* kMpegAudioNotInitialized = "E20040217 : MPEG Audio decoding function is not initialized!";
    constexpr const char* kMpeg2AacNotInitialized = "E20040217 : MPEG2 AAC decoding function is not initialized!";

    if (requestedFormat < 3 || requestedFormat > 4) {
      if (requestedFormat == 15) {
        if (decoder->mpeg2AacDecoder != nullptr) {
          decoder->preferredFormat = 12;
        } else {
          ADXERR_CallErrFunc1_(kMpeg2AacNotInitialized);
        }
        return;
      }

      decoder->preferredFormat = 0;
      return;
    }

    if (decoder->mpegAudioDecoder != nullptr) {
      decoder->preferredFormat = 11;
    } else {
      ADXERR_CallErrFunc1_(kMpegAudioNotInitialized);
    }
  }

  /**
   * Address: 0x00B21050 (ADXB_SetDefPrm)
   *
   * What it does:
   * Resets ADXB runtime parameters to default decode lanes.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetDefPrm(moho::AdxBitstreamDecoderState* decoder)
  {
    decoder->sourceBlockSamples = 1024;
    decoder->outputBlockSamples = 1024;
    decoder->outputPcmBuffer0 = decoder->pcmBuffer0;
    decoder->sourceBlockBytes = 127;
    decoder->outputBlockBytes = 127;
    decoder->outputPcmBuffer2 = decoder->pcmBuffer2;
    decoder->format = decoder->preferredFormat;
    decoder->initState = 1;
    decoder->sampleRate = 48000;
    decoder->sourceChannels = 2;
    decoder->sourceSampleBits = 16;
    decoder->totalSampleCount = 0x7FFFFFFF;
    decoder->outputChannels = 2;
    decoder->outputPcmBuffer1 = decoder->pcmBuffer1;
    decoder->entryCommittedBytes = 0;
    decoder->adpcmCoefficientIndex = 0;
    decoder->loopCount = 0;
    decoder->loopType = 0;
    decoder->loopInsertedSamples = 0;
    decoder->loopStartSample = 0;
    decoder->loopStartOffset = 0;
    decoder->loopEndSample = 0;
    decoder->loopEndOffset = 0;
    decoder->entrySubmittedBytes = 0;
    return decoder;
  }

  /**
   * Address: 0x00B210E0 (ADXB_DecodeHeader)
   *
   * What it does:
   * Dispatches one input header to the matching ADXB decode path.
   */
  std::int32_t ADXB_DecodeHeader(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    const std::int32_t headerSize
  )
  {
    adxb_ResetAinf(decoder);

    const auto marker = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(headerBytes[0]) << 8 | static_cast<std::uint16_t>(headerBytes[1])
    );

    if (marker == 0x8000) {
      return ADXB_DecodeHeaderAdx(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckSpsd(headerBytes)) {
      return ADXB_DecodeHeaderSpsd(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckWav(headerBytes)) {
      return ADXB_DecodeHeaderWav(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckAiff(headerBytes)) {
      return ADXB_DecodeHeaderAiff(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckAu(headerBytes)) {
      return ADXB_DecodeHeaderAu(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckMpa(headerBytes)) {
      return ADXB_DecodeHeaderMpa(decoder, headerBytes, headerSize);
    }
    if (ADXB_CheckM2a(headerBytes)) {
      return ADXB_DecodeHeaderM2a(decoder, headerBytes, headerSize);
    }

    return -1;
  }

  /**
   * Address: 0x00B211E0 (ADXB_EntryGetWrFunc)
   *
   * What it does:
   * Registers entry-get write callback lane and context.
   */
  moho::AdxBitstreamDecoderState* ADXB_EntryGetWrFunc(
    moho::AdxBitstreamDecoderState* decoder,
    void* entryGetWriteFunc,
    const std::int32_t entryGetWriteContext
  )
  {
    decoder->entryGetWriteFunc = entryGetWriteFunc;
    decoder->entryGetWriteContext = entryGetWriteContext;
    return decoder;
  }

  /**
   * Address: 0x00B21200 (ADXB_EntryAddWrFunc)
   *
   * What it does:
   * Registers entry-add write callback lane and context.
   */
  moho::AdxBitstreamDecoderState* ADXB_EntryAddWrFunc(
    moho::AdxBitstreamDecoderState* decoder,
    void* entryAddWriteFunc,
    const std::int32_t entryAddWriteContext
  )
  {
    decoder->entryAddWriteFunc = entryAddWriteFunc;
    decoder->entryAddWriteContext = entryAddWriteContext;
    return decoder;
  }

  /**
   * Address: 0x00B21220 (ADXB_GetPcmBuf)
   *
   * What it does:
   * Returns primary PCM buffer lane.
   */
  void* ADXB_GetPcmBuf(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->pcmBuffer0;
  }

  /**
   * Address: 0x00B21230 (ADXB_GetFormat)
   *
   * What it does:
   * Returns active ADXB decode format lane.
   */
  std::int32_t ADXB_GetFormat(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->format);
  }

  /**
   * Address: 0x00B21240 (ADXB_GetSfreq)
   *
   * What it does:
   * Returns stream sample-rate lane.
   */
  std::int32_t ADXB_GetSfreq(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->sampleRate;
  }

  /**
   * Address: 0x00B21250 (ADXB_GetNumChan)
   *
   * What it does:
   * Returns effective output channel count with expand-handle override.
   */
  std::int32_t ADXB_GetNumChan(const moho::AdxBitstreamDecoderState* decoder)
  {
    const auto sourceChannels = static_cast<std::int8_t>(decoder->sourceChannels);
    if (sourceChannels == 1 && decoder->channelExpandHandle != 0) {
      return 2;
    }
    return sourceChannels;
  }

  /**
   * Address: 0x00B21270 (ADXB_GetFmtBps)
   *
   * What it does:
   * Returns source bit-depth lane.
   */
  std::int32_t ADXB_GetFmtBps(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int8_t>(decoder->sourceSampleBits);
  }

  /**
   * Address: 0x00B21280 (ADXB_GetOutBps)
   *
   * What it does:
   * Returns output sample packing bit-depth from format and packing lanes.
   */
  std::int32_t ADXB_GetOutBps(const moho::AdxBitstreamDecoderState* decoder)
  {
    const auto format = static_cast<std::int16_t>(decoder->format);
    if (format == 0) {
      return 16;
    }

    const auto outputPacking = static_cast<std::int16_t>(decoder->outputSamplePacking);

    if (format == 2) {
      if (outputPacking == 2) {
        return 4;
      }
      return (outputPacking == 1) ? 8 : 16;
    }

    if (format == 1) {
      return (outputPacking == 2) ? 4 : 16;
    }

    return 16;
  }

  /**
   * Address: 0x00B212E0 (ADXB_GetBlkSmpl)
   *
   * What it does:
   * Returns source block sample-count lane.
   */
  std::int32_t ADXB_GetBlkSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->sourceBlockSamples;
  }

  /**
   * Address: 0x00B212F0 (ADXB_GetBlkLen)
   *
   * What it does:
   * Returns source block byte-length lane.
   */
  std::int32_t ADXB_GetBlkLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int8_t>(decoder->sourceBlockBytes);
  }

  /**
   * Address: 0x00B21300 (ADXB_GetTotalNumSmpl)
   *
   * What it does:
   * Returns total decoded sample count.
   */
  std::int32_t ADXB_GetTotalNumSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->totalSampleCount;
  }

  /**
   * Address: 0x00B21310 (ADXB_GetCof)
   *
   * What it does:
   * Returns ADPCM coefficient index lane.
   */
  std::int32_t ADXB_GetCof(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->adpcmCoefficientIndex);
  }

  /**
   * Address: 0x00B21320 (ADXB_GetLpInsNsmpl)
   *
   * What it does:
   * Returns inserted sample count for active loop lane.
   */
  std::int32_t ADXB_GetLpInsNsmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopInsertedSamples;
  }

  /**
   * Address: 0x00B21330 (ADXB_GetNumLoop)
   *
   * What it does:
   * Returns loop count lane.
   */
  std::int32_t ADXB_GetNumLoop(const moho::AdxBitstreamDecoderState* decoder)
  {
    return static_cast<std::int16_t>(decoder->loopCount);
  }

  /**
   * Address: 0x00B21340 (ADXB_GetLpStartPos)
   *
   * What it does:
   * Returns loop-start sample index from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpStartPos(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopStartSample;
  }

  /**
   * Address: 0x00B21350 (ADXB_GetLpStartOfst)
   *
   * What it does:
   * Returns loop-start byte offset from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpStartOfst(const moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder == nullptr) {
      return 0;
    }
    return decoder->loopStartOffset;
  }

  /**
   * Address: 0x00B21360 (ADXB_GetLpEndPos)
   *
   * What it does:
   * Returns loop-end sample index from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpEndPos(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopEndSample;
  }

  /**
   * Address: 0x00B21370 (ADXB_GetLpEndOfst)
   *
   * What it does:
   * Returns loop-end byte offset from one ADXB decoder state object.
   */
  std::int32_t ADXB_GetLpEndOfst(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->loopEndOffset;
  }

  /**
   * Address: 0x00B21380 (ADXB_GetAinfLen)
   *
   * What it does:
   * Returns AINF extension payload length cached in the decoder state.
   */
  std::int32_t ADXB_GetAinfLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->ainfLength;
  }

  /**
   * Address: 0x00B21390 (ADXB_GetDefOutVol)
   *
   * What it does:
   * Returns default output volume from AINF metadata.
   */
  std::int16_t ADXB_GetDefOutVol(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->defaultOutputVolume;
  }

  /**
   * Address: 0x00B213A0 (ADXB_GetDefPan)
   *
   * What it does:
   * Returns one default pan lane from AINF metadata.
   */
  std::int16_t ADXB_GetDefPan(const moho::AdxBitstreamDecoderState* decoder, const std::int32_t channelIndex)
  {
    return decoder->defaultPanByChannel[channelIndex];
  }

  /**
   * Address: 0x00B213C0 (ADXB_GetDataId)
   *
   * What it does:
   * Returns pointer to cached AINF data-id bytes.
   */
  std::uint8_t* ADXB_GetDataId(moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->dataIdBytes;
  }

  /**
   * Address: 0x00B213D0 (ADXB_TakeSnapshot)
   *
   * What it does:
   * Captures ADX packet-decoder delay/ext-key lanes into ADXB snapshot fields.
   */
  std::int32_t ADXB_TakeSnapshot(moho::AdxBitstreamDecoderState* decoder)
  {
    ADXPD_GetDly(decoder->adxPacketDecoder, &decoder->snapshotDelay0, &decoder->snapshotDelay1);
    return ADXPD_GetExtPrm(
      decoder->adxPacketDecoder,
      &decoder->snapshotExtKey0,
      &decoder->snapshotExtKeyMultiplier,
      &decoder->snapshotExtKeyAdder
    );
  }

  /**
   * Address: 0x00B21410 (ADXB_RestoreSnapshot)
   *
   * What it does:
   * Restores ADX packet-decoder delay/ext-key lanes from ADXB snapshot fields.
   */
  std::int32_t ADXB_RestoreSnapshot(moho::AdxBitstreamDecoderState* decoder)
  {
    ADXPD_SetDly(decoder->adxPacketDecoder, &decoder->snapshotDelay0, &decoder->snapshotDelay1);
    const void* const result = ADXPD_SetExtPrm(
      decoder->adxPacketDecoder,
      decoder->snapshotExtKey0,
      decoder->snapshotExtKeyMultiplier,
      decoder->snapshotExtKeyAdder
    );
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21460 (ADXSJE_SetExtString)
   *
   * What it does:
   * Generates and stores per-stream ADX key triple from one extension string.
   */
  moho::AdxBitstreamDecoderState* ADXSJE_SetExtString(moho::AdxBitstreamDecoderState* decoder, const char* extString)
  {
    std::int16_t key0 = 0;
    std::int16_t keyMultiplier = 0;
    std::int16_t keyAdder = 0;
    SKG_GenerateKey(extString, static_cast<std::int32_t>(std::strlen(extString)), &key0, &keyMultiplier, &keyAdder);
    decoder->extKey0 = key0;
    decoder->extKeyMultiplier = keyMultiplier;
    decoder->extKeyAdder = keyAdder;
    return decoder;
  }

  /**
   * Address: 0x00B214C0 (SKG_GenerateKey)
   *
   * What it does:
   * Generates one ADX key triple (`k0, km, ka`) from input bytes.
   */
  std::int32_t SKG_GenerateKey(
    const char* sourceBytes,
    const std::int32_t sourceLength,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    if (skg_init_count == 0) {
      ++skg_init_count;
    }

    *outKey0 = 0;
    *outKeyMultiplier = 0;
    *outKeyAdder = 0;

    if (sourceBytes != nullptr || sourceLength > 0) {
      *outKey0 = GenerateKeyLane(sourceBytes, sourceLength, 18973);
      *outKeyMultiplier = GenerateKeyLane(sourceBytes, sourceLength, 21503);
      *outKeyAdder = GenerateKeyLane(sourceBytes, sourceLength, 24001);
    }

    return 0;
  }

  /**
   * Address: 0x00B215D0 (ADXB_SetDefExtString)
   *
   * What it does:
   * Updates process-global default ADX extension key triple from one string.
   */
  std::int32_t ADXB_SetDefExtString(const char* extString)
  {
    return SKG_GenerateKey(
      extString,
      static_cast<std::int32_t>(std::strlen(extString)),
      &adxb_def_k0,
      &adxb_def_km,
      &adxb_def_ka
    );
  }

  /**
   * Address: 0x00B21600 (ADXB_GetExtParams)
   *
   * What it does:
   * Returns decoder-local ADX extension key triple.
   */
  std::int16_t ADXB_GetExtParams(
    const moho::AdxBitstreamDecoderState* decoder,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    *outKey0 = decoder->extKey0;
    *outKeyMultiplier = decoder->extKeyMultiplier;
    *outKeyAdder = decoder->extKeyAdder;
    return decoder->extKeyAdder;
  }

  /**
   * Address: 0x00B21630 (ADXB_SetExtParams)
   *
   * What it does:
   * Stores decoder-local ADX extension key triple.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetExtParams(
    moho::AdxBitstreamDecoderState* decoder,
    const std::int16_t key0,
    const std::int16_t keyMultiplier,
    const std::int16_t keyAdder
  )
  {
    decoder->extKey0 = key0;
    decoder->extKeyMultiplier = keyMultiplier;
    decoder->extKeyAdder = keyAdder;
    return decoder;
  }

  /**
   * Address: 0x00B21660 (adxb_get_key)
   *
   * What it does:
   * Resolves runtime key triple based on ADX encryption mode/version lanes.
   */
  std::int32_t adxb_get_key(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t encryptionMode,
    const std::uint8_t headerVersion,
    const std::int32_t streamId,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    if (encryptionMode < 4) {
      *outKey0 = 0;
      *outKeyMultiplier = 0;
      *outKeyAdder = 0;
      return 0;
    }

    if (headerVersion >= 0x10) {
      char streamIdHex[16]{};
      std::snprintf(streamIdHex, sizeof(streamIdHex), "%08X", static_cast<unsigned int>(streamId));
      SKG_GenerateKey(streamIdHex, 8, outKey0, outKeyMultiplier, outKeyAdder);
      return 0;
    }

    if (headerVersion < 8) {
      *outKey0 = 0;
      *outKeyMultiplier = 0;
      *outKeyAdder = 0;
      return 0;
    }

    if (decoder->extKey0 == 0 && decoder->extKeyMultiplier == 0 && decoder->extKeyAdder == 0) {
      decoder->extKey0 = adxb_def_k0;
      decoder->extKeyMultiplier = adxb_def_km;
      decoder->extKeyAdder = adxb_def_ka;
    }

    *outKey0 = decoder->extKey0;
    *outKeyMultiplier = decoder->extKeyMultiplier;
    *outKeyAdder = decoder->extKeyAdder;
    return 0;
  }

  /**
   * Address: 0x00B21770 (ADXB_GetStat)
   *
   * What it does:
   * Returns decoder status lane.
   */
  std::int32_t ADXB_GetStat(const moho::AdxBitstreamDecoderState* decoder)
  {
    return decoder->status;
  }

  /**
   * Address: 0x00B21780 (ADXB_EntryData)
   *
   * What it does:
   * Seeds one decode-entry run and returns number of decode blocks.
   */
  std::int32_t ADXB_EntryData(
    moho::AdxBitstreamDecoderState* decoder,
    const std::int32_t streamDataOffset,
    const std::int32_t inputBytes
  )
  {
    decoder->decodeCursor = 0;

    std::int32_t unitBytes = 0;
    decoder->streamDataOffset = streamDataOffset;

    if (decoder->format == 0) {
      unitBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceBlockBytes));
    } else {
      const auto sampleBits = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceSampleBits));
      const auto roundedBytes = (sampleBits + ((sampleBits >> 31) & 7)) >> 3;
      unitBytes = static_cast<std::int32_t>(static_cast<std::int8_t>(decoder->sourceChannels)) * roundedBytes;
    }

    decoder->decodeProgress0 = 0;
    decoder->decodeProgress1 = 0;
    decoder->pendingConsumeBytes = 0;
    decoder->pendingSubmitBytes = 0;
    decoder->streamBlockCount = inputBytes / unitBytes;
    return decoder->streamBlockCount;
  }

  /**
   * Address: 0x00B217F0 (ADXB_Start)
   *
   * What it does:
   * Transitions one ADXB decoder to running state.
   */
  moho::AdxBitstreamDecoderState* ADXB_Start(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->status == 0) {
      decoder->status = 1;
    }
    return decoder;
  }

  /**
   * Address: 0x00B21810 (ADXB_Stop)
   *
   * What it does:
   * Runs optional post-process detach and stops one ADX packet decoder.
   */
  std::int32_t ADXB_Stop(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->channelExpandHandle != 0) {
      ADXB_OnStopPostProcess(decoder);
    }

    const void* const result = ADXPD_Stop(decoder->adxPacketDecoder);
    decoder->status = 0;
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21840 (ADXB_Reset)
   *
   * What it does:
   * Resets ADX packet-decode state when one decode pass reached done state.
   */
  std::int32_t ADXB_Reset(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->runState == 3) {
      ADXPD_Reset(runtime->adxPacketDecoder);
      runtime->entryCommittedBytes = 0;
      runtime->runState = 0;
    }

    return 0;
  }

  /**
   * Address: 0x00B21870 (ADXB_GetDecDtLen)
   *
   * What it does:
   * Returns decoded output-byte count from one ADXB runtime object.
   */
  std::int32_t ADXB_GetDecDtLen(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->producedByteCount;
  }

  /**
   * Address: 0x00B21880 (ADXB_GetDecNumSmpl)
   *
   * What it does:
   * Returns decoded output-sample count from one ADXB runtime object.
   */
  std::int32_t ADXB_GetDecNumSmpl(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->producedSampleCount;
  }

  /**
   * Address: 0x00B21890 (ADXB_SetCbDec)
   *
   * What it does:
   * Registers one decode-progress callback and callback context.
   */
  moho::AdxBitstreamDecoderState* ADXB_SetCbDec(
    moho::AdxBitstreamDecoderState* decoder,
    std::int32_t(__cdecl* callback)(std::int32_t, std::int32_t, std::int32_t),
    const std::int32_t callbackContext
  )
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    runtime->decodeCallback = callback;
    runtime->decodeCallbackContext = callbackContext;
    return decoder;
  }

  /**
   * Address: 0x00B218B0 (ADXB_GetAdxpd)
   *
   * What it does:
   * Returns attached ADX packet-decoder handle from one ADXB runtime object.
   */
  void* ADXB_GetAdxpd(const moho::AdxBitstreamDecoderState* decoder)
  {
    return AsAdxbRuntimeView(decoder)->adxPacketDecoder;
  }

  /**
   * Address: 0x00B218C0 (ADXB_EvokeExpandMono)
   *
   * What it does:
   * Queues one mono expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandMono(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;

    ADXPD_EntryMono(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      nullptr
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B218F0 (ADXB_EvokeExpandPl2)
   *
   * What it does:
   * Queues one PL2 expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandPl2(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;
    auto* const outputRight = outputLeft + runtime->outputSecondChannelOffset;

    ADXPD_EntryPl2(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount * 2,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      reinterpret_cast<std::uint16_t*>(outputRight)
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21930 (ADXB_EvokeExpandSte)
   *
   * What it does:
   * Queues one stereo expansion decode job into ADXPD and starts execution.
   */
  std::int32_t ADXB_EvokeExpandSte(moho::AdxBitstreamDecoderState* decoder, const std::int32_t blockCount)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputLeft = runtime->outputWordStream0 + runtime->entryWriteStartWordIndex;
    auto* const outputRight = outputLeft + runtime->outputSecondChannelOffset;

    ADXPD_EntrySte(
      runtime->adxPacketDecoder,
      runtime->sourceWordStream,
      blockCount,
      reinterpret_cast<std::uint16_t*>(outputLeft),
      reinterpret_cast<std::uint16_t*>(outputRight)
    );

    const auto result = ADXPD_Start(runtime->adxPacketDecoder);
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(result));
  }

  /**
   * Address: 0x00B21970 (ADXB_EvokeDecode)
   *
   * What it does:
   * Computes bounded decode-block count for current write window and dispatches
   * mono/stereo/PL2 expansion lane.
   */
  std::int32_t ADXB_EvokeDecode(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    const auto decodeUnitWords = runtime->entrySubmittedBytes;
    const auto outputChannelCount = runtime->outputChannels;

    const auto blockLimitByInput = runtime->sourceWordLimit / outputChannelCount;
    auto blockLimitByWindowCapacity = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords;

    const auto tailRemainder = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) % decodeUnitWords;
    const auto tailSlackWords = decodeUnitWords - tailRemainder - 1;

    auto blockLimitByOutputWindow =
      (runtime->outputWordLimit - runtime->entryWriteStartWordIndex + decodeUnitWords - 1) / decodeUnitWords;

    if (
      ((runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords) < blockLimitByOutputWindow
      && runtime->entryWriteStartWordIndex + decodeUnitWords * blockLimitByOutputWindow - tailSlackWords < runtime->outputWordLimit
    ) {
      ++blockLimitByOutputWindow;
    }

    auto pendingWriteWords = runtime->entryWriteUsedWordCount;
    if (runtime->entryWriteCapacityWords < pendingWriteWords) {
      pendingWriteWords += tailSlackWords;
    }

    auto decodeBlockCount = pendingWriteWords / decodeUnitWords;
    if (decodeBlockCount > blockLimitByInput) {
      decodeBlockCount = blockLimitByInput;
    }
    if (decodeBlockCount > ((runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords)) {
      decodeBlockCount = (runtime->entryWriteCapacityWords + decodeUnitWords - 1) / decodeUnitWords;
    }
    if (decodeBlockCount > blockLimitByWindowCapacity) {
      decodeBlockCount = blockLimitByWindowCapacity;
    }
    if (decodeBlockCount > blockLimitByOutputWindow) {
      decodeBlockCount = blockLimitByOutputWindow;
    }

    if (outputChannelCount == 2) {
      return ADXB_EvokeExpandPl2(decoder, decodeBlockCount);
    }
    if (runtime->channelExpandHandle != 0) {
      return ADXB_EvokeExpandSte(decoder, decodeBlockCount);
    }
    return ADXB_EvokeExpandMono(decoder, decodeBlockCount);
  }

  /**
   * Address: 0x00B21A50 (memcpy2)
   *
   * What it does:
   * Copies one signed-16 sample lane in word units.
   */
  std::int16_t* memcpy2(std::int16_t* destinationWords, const std::int16_t* sourceWords, std::int32_t wordCount)
  {
    if (wordCount <= 0) {
      return destinationWords;
    }

    while (wordCount > 0) {
      *destinationWords++ = *sourceWords++;
      --wordCount;
    }
    return destinationWords;
  }

  /**
   * Address: 0x00B21A80 (ADXB_CopyExtraBufSte)
   *
   * What it does:
   * Rolls and copies stereo tail words into wrap region and secondary lane.
   */
  std::int16_t* ADXB_CopyExtraBufSte(
    std::int16_t* sampleWords,
    const std::int32_t wrapBaseWord,
    const std::int32_t secondaryStartWord,
    const std::int32_t tailWordCount
  )
  {
    memcpy2(sampleWords + wrapBaseWord, sampleWords, tailWordCount);
    return memcpy2(
      sampleWords + secondaryStartWord,
      sampleWords + wrapBaseWord + secondaryStartWord,
      tailWordCount
    );
  }

  /**
   * Address: 0x00B21AC0 (ADXB_CopyExtraBufMono)
   *
   * What it does:
   * Rolls and copies mono tail words into wrap region.
   */
  std::int16_t* ADXB_CopyExtraBufMono(
    std::int16_t* sampleWords,
    const std::int32_t wrapBaseWord,
    const std::int32_t /*unusedSecondaryWord*/,
    const std::int32_t tailWordCount
  )
  {
    return memcpy2(sampleWords, sampleWords + wrapBaseWord, tailWordCount);
  }

  /**
   * Address: 0x00B21AE0 (ADXB_EndDecode)
   *
   * What it does:
   * Finalizes one ADXPD decode step, computes produced counts, and applies
   * wrap-buffer copy lanes when window overflows.
   */
  std::int16_t* ADXB_EndDecode(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    auto* const outputWords = runtime->outputWordStream0;
    const auto decodedBlockCount = ADXPD_GetNumBlk(runtime->adxPacketDecoder);

    std::int32_t producedSamples = runtime->outputBlockSamples * decodedBlockCount / runtime->outputChannels;
    if (
      ((runtime->entryWriteCapacityWords + runtime->outputBlockSamples - 1) / runtime->outputBlockSamples) * runtime->outputChannels
      <= decodedBlockCount
    ) {
      producedSamples +=
        ((runtime->entryWriteCapacityWords + runtime->outputBlockSamples - 1) % runtime->outputBlockSamples)
        - runtime->outputBlockSamples + 1;
    }

    runtime->producedSampleCount = producedSamples;
    runtime->producedByteCount = runtime->outputBlockBytes * decodedBlockCount;

    const auto windowTailWord = runtime->entryWriteStartWordIndex + producedSamples;
    if (windowTailWord >= runtime->pcmBufferSampleLimit) {
      const auto tailWordCount = windowTailWord - runtime->pcmBufferSampleLimit;
      if (runtime->outputChannels == 2 || runtime->channelExpandHandle != 0) {
        ADXB_CopyExtraBufSte(
          outputWords,
          runtime->pcmBufferSampleLimit,
          runtime->outputSecondChannelOffset,
          tailWordCount
        );
      } else {
        ADXB_CopyExtraBufMono(
          outputWords,
          runtime->pcmBufferSampleLimit,
          runtime->outputSecondChannelOffset,
          tailWordCount
        );
      }
    }

    return outputWords;
  }

  /**
   * Address: 0x00B21BC0 (ADXB_ExecOneAdx)
   *
   * What it does:
   * Executes one ADX decode step: acquires write window, runs ADXPD, handles
   * optional channel-expand callbacks, and commits produced output.
   */
  void ADXB_ExecOneAdx(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    if (runtime->runState == 1 && ADXPD_GetStat(runtime->adxPacketDecoder) == 0) {
      runtime->entryGetWriteFunc(
        runtime->entryGetWriteContext,
        &runtime->entryWriteStartWordIndex,
        &runtime->entryWriteUsedWordCount,
        &runtime->entryWriteCapacityWords
      );

      ADXB_EvokeDecode(decoder);
      runtime->runState = 2;
    }

    if (runtime->runState != 2) {
      return;
    }

    ADXPD_ExecHndl(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime->adxPacketDecoder)));
    if (ADXPD_GetStat(runtime->adxPacketDecoder) != 3) {
      return;
    }

    if (runtime->channelExpandHandle != 0) {
      auto* const packetState = reinterpret_cast<AdxPacketDecodeSampleView*>(runtime->adxPacketDecoder);
      ADXCRS_Lock();
      for (std::int32_t sampleIndex = 0; sampleIndex < 32 * packetState->sourceChannels; ++sampleIndex) {
        const auto sampleOffsetBytes = static_cast<std::size_t>(2 * sampleIndex);
        const auto* const leftSample =
          reinterpret_cast<const std::int16_t*>(packetState->primaryOutputBytes + sampleOffsetBytes);
        const auto* const rightSample =
          reinterpret_cast<const std::int16_t*>(packetState->secondaryOutputBytes + sampleOffsetBytes);
        const auto sampleValue = static_cast<std::int32_t>(*leftSample);
        ADXB_OnExpandSamplePair(decoder, sampleValue, leftSample, rightSample);
      }
      ADXCRS_Unlock();
    }

    ADXB_EndDecode(decoder);
    ADXPD_Reset(runtime->adxPacketDecoder);

    runtime->entryAddWriteFunc(
      runtime->entryAddWriteContext,
      runtime->producedByteCount,
      runtime->producedSampleCount
    );

    runtime->runState = 3;
  }

  std::int32_t adxb_dec_cb_proc(moho::AdxBitstreamDecoderState* decoder);

  /**
   * Address: 0x00B21CB0 (ADXB_ExecHndl)
   *
   * What it does:
   * Dispatches one ADXB execution lane by decoded format and runs optional
   * decode-progress callback hook.
   */
  std::int32_t ADXB_ExecHndl(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    switch (runtime->format) {
      case 0:
        ADXB_ExecOneAdx(decoder);
        break;
      case 10:
        ADXB_ExecOneAhx(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 2:
        ADXB_ExecOneSpsd(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 3:
        ADXB_ExecOneAiff(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 4:
        ADXB_ExecOneAu(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 1:
        ADXB_ExecOneWav(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 11:
        ADXB_ExecOneMpa(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      case 12:
        ADXB_ExecOneM2a(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoder)));
        break;
      default:
        break;
    }

    if (runtime->decodeCallback != nullptr) {
      return adxb_dec_cb_proc(decoder);
    }
    return 0;
  }

  /**
   * Address: 0x00B21D50 (adxb_dec_cb_proc)
   *
   * What it does:
   * Computes decode delta accounting and invokes ADXB decode callback.
   */
  std::int32_t adxb_dec_cb_proc(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);

    auto producedDelta = runtime->producedByteCount - runtime->decodeCallbackConsumedBytes;
    if (producedDelta < 0) {
      producedDelta += 0x7FFFFFFF;
    }

    const auto producedBytes =
      2 * runtime->producedSampleCount * static_cast<std::int32_t>(runtime->sourceChannels);

    const auto result = runtime->decodeCallback(runtime->decodeCallbackContext, producedDelta, producedBytes);
    runtime->decodeCallbackConsumedBytes = runtime->producedByteCount;
    return result;
  }

  /**
   * Address: 0x00B21DA0 (ADXB_ExecServer)
   *
   * What it does:
   * Iterates ADXB slot pool and executes active decoder lanes.
   */
  std::int32_t ADXB_ExecServer()
  {
    std::int32_t lastResult = 0;
    for (auto& decoder : adxb_obj) {
      if (decoder.slotState == 1) {
        lastResult = ADXB_ExecHndl(&decoder);
      }
    }
    return lastResult;
  }

  /**
   * Address: 0x00B21DD0 (ADXB_SetAhxInSj)
   *
   * What it does:
   * Forwards stream-join input setup into AHX runtime handle when attached.
   */
  std::int32_t ADXB_SetAhxInSj(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxsetsjifunc != nullptr) {
      return ahxsetsjifunc(runtime->ahxDecoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B21DF0 (ADXB_SetAhxDecSmpl)
   *
   * What it does:
   * Stores AHX max decode samples and derived 96-sample block count lane.
   */
  std::uint32_t ADXB_SetAhxDecSmpl(moho::AdxBitstreamDecoderState* decoder, const std::int32_t maxDecodeSamples)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxsetdecsmplfunc != nullptr) {
      ahxsetdecsmplfunc(runtime->ahxDecoderHandle, maxDecodeSamples);
    }

    runtime->ahxMaxDecodeSamples = maxDecodeSamples;

    const auto highProductWord = static_cast<std::int32_t>(
      (0x2AAAAAABLL * static_cast<long long>(maxDecodeSamples)) >> 32
    );
    auto divideBy96 = highProductWord >> 4;
    const auto signAdjust = static_cast<std::uint32_t>(divideBy96) >> 31;
    divideBy96 += static_cast<std::int32_t>(signAdjust);
    runtime->ahxMaxDecodeBlocks = divideBy96;
    return signAdjust;
  }

  /**
   * Address: 0x00B21E30 (ADXB_ExecOneAhx)
   *
   * What it does:
   * Executes AHX decode lane through registered runtime callback.
   */
  std::int32_t __cdecl ADXB_ExecOneAhx(const std::int32_t /*decoderAddress*/)
  {
    if (ahxexecfunc != nullptr) {
      return ahxexecfunc();
    }
    return 0;
  }

  /**
   * Address: 0x00B21E40 (ADXB_AhxTermSupply)
   *
   * What it does:
   * Forwards AHX terminate-supply request when AHX handle is attached.
   */
  std::int32_t ADXB_AhxTermSupply(moho::AdxBitstreamDecoderState* decoder)
  {
    auto* const runtime = AsAdxbRuntimeView(decoder);
    if (runtime->ahxDecoderHandle != nullptr && ahxtermsupplyfunc != nullptr) {
      return ahxtermsupplyfunc(runtime->ahxDecoderHandle);
    }
    return 0;
  }

  /**
   * Address: 0x00B21E60 (j_func_sofdec_EnterLock_7)
   *
   * What it does:
   * Enters Sofdec global lock lane.
   */
  void sofdec_EnterLock_7()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B21E70 (j_func_sofdec_LeaveLock_7)
   *
   * What it does:
   * Leaves Sofdec global lock lane.
   */
  void sofdec_LeaveLock_7()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B21EA0 (sub_B21EA0)
   *
   * What it does:
   * Stores global report callback and callback context lanes.
   */
  SofdecReportCallback ADXT_SetReportCallback(
    const SofdecReportCallback callback,
    const std::int32_t callbackContext
  )
  {
    gSofdecReportCallback = callback;
    gSofdecReportCallbackContext = callbackContext;
    return callback;
  }

  /**
   * Address: 0x00B21E80 (sub_B21E80)
   *
   * What it does:
   * Lock-guarded wrapper for report callback registration.
   */
  void ADXT_SetReportCallbackLocked(const SofdecReportCallback callback, const std::int32_t callbackContext)
  {
    sofdec_EnterLock_7();
    ADXT_SetReportCallback(callback, callbackContext);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B21EE0 (sub_B21EE0)
   *
   * What it does:
   * Increments global Dolby-attach reference counter lane.
   */
  void ADXT_IncrementAttachRef()
  {
    ++gSofdecDolbyAttachRefCount;
  }

  /**
   * Address: 0x00B21EC0 (sub_B21EC0)
   *
   * What it does:
   * Lock-guarded wrapper for incrementing attach-reference counter.
   */
  void ADXT_IncrementAttachRefLocked(const std::int32_t /*unused*/)
  {
    sofdec_EnterLock_7();
    ADXT_IncrementAttachRef();
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B21F10 (sub_B21F10)
   *
   * What it does:
   * Decrements global Dolby-attach reference counter lane.
   */
  void ADXT_DecrementAttachRef()
  {
    --gSofdecDolbyAttachRefCount;
  }

  /**
   * Address: 0x00B21EF0 (sub_B21EF0)
   *
   * What it does:
   * Lock-guarded wrapper for decrementing attach-reference counter.
   */
  void ADXT_DecrementAttachRefLocked(const std::int32_t /*unused*/)
  {
    sofdec_EnterLock_7();
    ADXT_DecrementAttachRef();
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B0D9C0 (_ADXT_SetOutPan)
   *
   * What it does:
   * Lock-guards one ADXT output-pan update and forwards to
   * `adxt_SetOutPan`.
   */
  void ADXT_SetOutPan(void* const adxtRuntime, const std::int32_t laneIndex, const std::int32_t panLevel)
  {
    ADXCRS_Lock();
    adxt_SetOutPan(adxtRuntime, laneIndex, panLevel);
    ADXCRS_Unlock();
  }

  /**
   * Address: 0x00B0D9F0 (_adxt_SetOutPan)
   *
   * What it does:
   * Resolves one effective channel pan (default/override/mono rules), stores
   * the caller pan lane, and applies output pan to ADX RNA.
   */
  void adxt_SetOutPan(void* const adxtRuntime, const std::int32_t laneIndex, const std::int32_t panLevel)
  {
    auto* const runtime = static_cast<AdxtRuntimeState*>(adxtRuntime);
    if (runtime == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetOutPanNullRuntimeMessage);
      return;
    }

    std::int32_t defaultPan = 0;
    if (runtime->used == 1u) {
      defaultPan = static_cast<std::int32_t>(ResolveAdxsjdDefaultPanLane(runtime->sjdHandle, laneIndex));
      if (defaultPan == -128) {
        defaultPan = 0;
      }
    }

    std::int32_t effectivePan = 0;
    if (adxt_output_mono_flag != 0) {
      effectivePan = 0;
    } else if (panLevel == -128) {
      if (ResolveAdxsjdChannelCount(runtime->sjdHandle) == 2) {
        effectivePan = defaultPan + (laneIndex != 0 ? 15 : -15);
      } else {
        effectivePan = defaultPan;
      }
    } else {
      effectivePan = defaultPan + panLevel;
    }

    auto* const panCacheView = reinterpret_cast<AdxtPanCacheRuntimeView*>(runtime);
    panCacheView->requestedPanByChannel[laneIndex] = static_cast<std::int16_t>(panLevel);

    if (laneIndex >= static_cast<std::int32_t>(runtime->maxChannelCount)) {
      (void)ADXERR_CallErrFunc1_(kAdxtSetOutPanLaneRangeMessage);
      return;
    }

    (void)SetAdxrnaOutputPan(runtime->rnaHandle, laneIndex, effectivePan);
  }

  [[nodiscard]] std::int32_t ADXT_InvokeDestroyCallbackIfPresent()
  {
    if (gAdxtDestroyCallback != nullptr) {
      return gAdxtDestroyCallback();
    }
    return 0;
  }

  void ADXT_ReleaseLaneHandle(AdxtDestroyableHandle*& laneHandle)
  {
    if (laneHandle == nullptr) {
      return;
    }

    auto* const handle = laneHandle;
    laneHandle = nullptr;
    handle->Destroy();
  }

  /**
   * Address: 0x00B0CEF0 (_adxt_Destroy)
   *
   * What it does:
   * Tears down one ADXT runtime object by detaching optional middleware
   * sub-lanes, destroying owned handles, clearing the runtime block, and
   * reporting null-parameter usage through ADXERR callback lane.
   */
  void adxt_Destroy(AdxtRuntimeState* const runtime)
  {
    if (runtime == nullptr) {
      ADXERR_CallErrFunc1_(kAdxtDestroyParameterErrorMessage);
      return;
    }

    adxt_detach_ahx();
    adxt_detach_mpa(runtime);
    adxt_detach_m2a(runtime);
    (void)ADXT_InvokeDestroyCallbackIfPresent();

    if (runtime->used == 1u) {
      adxt_Stop(runtime);
    }

    if (runtime->rnaHandle != 0) {
      const auto rnaHandle = runtime->rnaHandle;
      runtime->rnaHandle = 0;
      ADXRNA_Destroy(rnaHandle);
    }

    if (runtime->sjdHandle != 0) {
      const auto sjdHandle = runtime->sjdHandle;
      runtime->sjdHandle = 0;
      ADXSJD_Destroy(sjdHandle);
    }

    if (runtime->streamHandle != nullptr) {
      auto* const streamHandle = runtime->streamHandle;
      runtime->streamHandle = nullptr;
      ADXSTM_EntryEosFunc(
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(streamHandle)),
        0,
        0
      );
      ADXSTM_Destroy(streamHandle);
    }

    if (runtime->linkControlHandle != nullptr) {
      auto* const linkControlHandle = runtime->linkControlHandle;
      runtime->linkControlHandle = nullptr;
      LSC_Destroy(linkControlHandle);
    }

    ADXCRS_Lock();

    ADXT_ReleaseLaneHandle(runtime->sourceRingHandle);

    const auto channelCount = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t lane = 0; lane < channelCount; ++lane) {
      ADXT_ReleaseLaneHandle(runtime->SourceChannelRingLane(lane));
      ADXT_ReleaseLaneHandle(runtime->AuxReleaseLaneA(lane));
      ADXT_ReleaseLaneHandle(runtime->AuxReleaseLaneB(lane));
    }

    if (runtime->channelExpandHandle != nullptr) {
      auto* const channelExpandHandle = runtime->channelExpandHandle;
      runtime->channelExpandHandle = nullptr;
      ADXAMP_Destroy(channelExpandHandle);
    }

    std::memset(runtime, 0, sizeof(AdxtRuntimeState));
    runtime->used = 0;

    ADXCRS_Unlock();
  }

  std::int32_t ADXT_ReportMessage(const char* message);
  std::int32_t ADXT_ResetHistoryState(AdxtDolbyRuntimeState* state);

  /**
   * Address: 0x00B21F50 (sub_B21F50)
   *
   * What it does:
   * Initializes one Dolby runtime work-state object inside caller-provided work
   * memory with alignment and bounds checks.
   */
  AdxtDolbyRuntimeState* ADXT_AttachDolbyState(AdxtDolbyRuntimeState* workMemory, const std::int32_t workBytes)
  {
    if (workMemory == nullptr) {
      ADXT_ReportMessage(kAdxtNullWorkPointerMessage);
      return nullptr;
    }

    if (workBytes < 0x400) {
      ADXT_ReportMessage(kAdxtShortWorkBufferMessage);
      return nullptr;
    }

    auto* const alignedState =
      reinterpret_cast<AdxtDolbyRuntimeState*>(AlignPointerTo4Bytes(reinterpret_cast<std::uint8_t*>(workMemory)));
    std::memset(alignedState, 0, sizeof(AdxtDolbyRuntimeState));

    alignedState->workBufferBase = workMemory;
    alignedState->workBufferBytes = workBytes;

    auto* historyBase = AlignPointerTo4Bytes(reinterpret_cast<std::uint8_t*>(alignedState) + sizeof(AdxtDolbyRuntimeState));
    alignedState->historyLaneA = reinterpret_cast<std::int32_t*>(historyBase);
    alignedState->historyLaneB = alignedState->historyLaneA + 96;

    ADXT_ResetHistoryState(alignedState);

    auto* const workEnd = reinterpret_cast<std::uint8_t*>(workMemory) + workBytes;
    if (reinterpret_cast<std::uint8_t*>(alignedState->historyLaneA + 192) > workEnd) {
      ADXT_ReportMessage(kAdxtShortAlignedWorkBufferMessage);
      return nullptr;
    }

    return alignedState;
  }

  /**
   * Address: 0x00B21F20 (sub_B21F20)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby work-state attachment/initialization.
   */
  AdxtDolbyRuntimeState* ADXT_AttachDolbyStateLocked(AdxtDolbyRuntimeState* workMemory, const std::int32_t workBytes)
  {
    sofdec_EnterLock_7();
    auto* const result = ADXT_AttachDolbyState(workMemory, workBytes);
    sofdec_LeaveLock_7();
    return result;
  }

  /**
   * Address: 0x00B22000 (sub_B22000)
   *
   * What it does:
   * Dispatches one report message through registered callback lanes.
   */
  std::int32_t ADXT_ReportMessage(const char* message)
  {
    if (gSofdecReportCallback != nullptr) {
      return gSofdecReportCallback(gSofdecReportCallbackContext, message);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(gSofdecReportCallback));
  }

  /**
   * Address: 0x00B22040 (sub_B22040)
   *
   * What it does:
   * Clears one Dolby work-state control block.
   */
  std::int32_t ADXT_ClearControlState(AdxtDolbyRuntimeState* state)
  {
    std::memset(state, 0, sizeof(AdxtDolbyRuntimeState));
    return 0;
  }

  /**
   * Address: 0x00B22020 (sub_B22020)
   *
   * What it does:
   * Lock-guarded wrapper for clearing one Dolby control state block.
   */
  void ADXT_ClearControlStateLocked(AdxtDolbyRuntimeState* state)
  {
    sofdec_EnterLock_7();
    ADXT_ClearControlState(state);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22070 (sub_B22070)
   *
   * What it does:
   * Resets fixed history lanes and ring-buffer cursor for Dolby runtime state.
   */
  std::int32_t ADXT_ResetHistoryState(AdxtDolbyRuntimeState* state)
  {
    for (std::int32_t lane = 0; lane < 96; ++lane) {
      state->historyLaneA[lane] = 0;
      state->historyLaneB[lane] = 0;
    }
    state->historyWriteIndex = 0;
    state->historyWindowLength = 64;
    return 0x180;
  }

  /**
   * Address: 0x00B22050 (sub_B22050)
   *
   * What it does:
   * Lock-guarded wrapper for history-lane reset.
   */
  void ADXT_ResetHistoryStateLocked(AdxtDolbyRuntimeState* state)
  {
    sofdec_EnterLock_7();
    ADXT_ResetHistoryState(state);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B220E0 (sub_B220E0)
   *
   * What it does:
   * Processes one Dolby matrix sample through Q12 coefficient lanes and updates
   * circular history buffers.
   */
  AdxtDolbyRuntimeState* ADXT_ProcessSample(
    AdxtDolbyRuntimeState* state,
    const std::int16_t inputSample,
    std::int16_t* const outSampleA,
    std::int16_t* const outSampleB
  )
  {
    const auto sample = static_cast<std::int32_t>(inputSample);
    const auto coeffA = adxt_q12_mix_table[state->mixTableIndexA];
    const auto coeffB = adxt_q12_mix_table[state->mixTableIndexB];
    const auto coeffC = adxt_q12_mix_table[state->mixTableIndexC];
    const auto coeffD = adxt_q12_mix_table[state->mixTableIndexD];

    const auto laneA = (sample * coeffA) >> 12;
    const auto laneB = (sample * coeffB) >> 12;

    const auto feedbackCD = (laneB * coeffD) >> 12;
    const auto feedbackAC = (laneA * coeffD) >> 12;

    const auto feedbackLeft = state->historyLaneA[state->historyWriteIndex] + ((laneA * coeffC) >> 12);
    const auto feedbackRight = state->historyLaneB[state->historyWriteIndex] + ((laneB * coeffC) >> 12);

    auto clampA = feedbackLeft;
    if (clampA > 0x7FFF) {
      clampA = 0x7FFF;
    } else if (clampA < -32768) {
      clampA = -32768;
    }

    auto clampB = feedbackRight;
    if (clampB > 0x7FFF) {
      clampB = 0x7FFF;
    } else if (clampB < -32768) {
      clampB = -32768;
    }

    *outSampleA = static_cast<std::int16_t>(clampA);
    *outSampleB = static_cast<std::int16_t>(clampB);

    state->historyLaneA[state->historyWriteIndex] = (-2006 * feedbackCD - 3567 * feedbackAC) >> 12;
    state->historyLaneB[state->historyWriteIndex] = (3567 * feedbackCD + 2006 * feedbackAC) >> 12;

    ++state->historyWriteIndex;
    if (state->historyWriteIndex >= state->historyWindowLength) {
      state->historyWriteIndex = 0;
    }

    return state;
  }

  /**
   * Address: 0x00B220B0 (sub_B220B0)
   *
   * What it does:
   * Lock-guarded wrapper for single-sample Dolby matrix processing.
   */
  void ADXT_ProcessSampleLocked(
    AdxtDolbyRuntimeState* state,
    const std::int16_t inputSample,
    std::int16_t* outSampleA,
    std::int16_t* outSampleB
  )
  {
    sofdec_EnterLock_7();
    ADXT_ProcessSample(state, inputSample, outSampleA, outSampleB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22250 (sub_B22250)
   *
   * What it does:
   * Processes one 32-sample block through Dolby matrix lanes and updates the
   * first history window segment.
   */
  std::int32_t ADXT_ProcessSampleBlock(
    AdxtDolbyRuntimeState* state,
    const std::int16_t* inputSamples,
    std::int16_t* outputSamplesA,
    std::int16_t* outputSamplesB
  )
  {
    std::int32_t lastResult = 0;
    for (std::int32_t lane = 0; lane < 32; ++lane) {
      const auto sample = static_cast<std::int32_t>(inputSamples[lane]);
      const auto coeffA = adxt_q12_mix_table[state->mixTableIndexA];
      const auto coeffB = adxt_q12_mix_table[state->mixTableIndexB];
      const auto coeffC = adxt_q12_mix_table[state->mixTableIndexC];
      const auto coeffD = adxt_q12_mix_table[state->mixTableIndexD];

      auto laneA = (sample * coeffA) >> 12;
      auto laneB = (sample * coeffB) >> 12;

      const auto feedbackCD = (laneB * coeffD) >> 12;
      const auto feedbackAC = (laneA * coeffD) >> 12;

      const auto mixA = state->historyLaneA[lane] + ((laneA * coeffC) >> 12);
      const auto mixB = state->historyLaneB[lane] + ((laneB * coeffC) >> 12);

      auto clampA = mixA;
      if (clampA > 0x7FFF) {
        clampA = 0x7FFF;
      } else if (clampA < -32768) {
        clampA = -32768;
      }

      auto clampB = mixB;
      if (clampB > 0x7FFF) {
        clampB = 0x7FFF;
      } else if (clampB < -32768) {
        clampB = -32768;
      }

      outputSamplesA[lane] = static_cast<std::int16_t>(clampA);
      outputSamplesB[lane] = static_cast<std::int16_t>(clampB);

      state->historyLaneA[lane] = (-2006 * feedbackCD - 3567 * feedbackAC) >> 12;
      lastResult = 1003 * feedbackAC;
      state->historyLaneB[lane] = (3567 * feedbackCD + (2 * lastResult)) >> 12;
    }

    return lastResult;
  }

  /**
   * Address: 0x00B22220 (sub_B22220)
   *
   * What it does:
   * Lock-guarded wrapper for 32-sample Dolby block processing.
   */
  void ADXT_ProcessSampleBlockLocked(
    AdxtDolbyRuntimeState* state,
    const std::int16_t* inputSamples,
    std::int16_t* outputSamplesA,
    std::int16_t* outputSamplesB
  )
  {
    sofdec_EnterLock_7();
    ADXT_ProcessSampleBlock(state, inputSamples, outputSamplesA, outputSamplesB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B223D0 (sub_B223D0)
   *
   * What it does:
   * Updates Dolby matrix lookup-table index lanes from signed user parameters.
   */
  std::int32_t ADXT_SetMixTableIndices(
    AdxtDolbyRuntimeState* state,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    if (state == nullptr) {
      return ADXT_ReportMessage(kAdxtNullMatrixStateMessage);
    }

    if (
      matrixParamA < -127
      || matrixParamA > 127
      || matrixParamB < -127
      || matrixParamB > 127
    ) {
      return ADXT_ReportMessage(kAdxtIllegalMatrixParameterMessage);
    }

    const auto indexA = matrixParamA + 127;
    state->mixTableIndexA = indexA >= 0 ? indexA : (-127 - matrixParamA);

    const auto indexB = matrixParamA - 127;
    state->mixTableIndexB = indexB >= 0 ? indexB : (127 - matrixParamA);

    const auto indexC = matrixParamB + 127;
    state->mixTableIndexC = indexC >= 0 ? indexC : (-127 - matrixParamB);

    const auto indexD = matrixParamB - 127;
    state->mixTableIndexD = indexD >= 0 ? indexD : (127 - matrixParamB);
    return state->mixTableIndexD;
  }

  /**
   * Address: 0x00B223A0 (sub_B223A0)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby mix-table index updates.
   */
  void ADXT_SetMixTableIndicesLocked(
    AdxtDolbyRuntimeState* state,
    const std::int32_t matrixParamA,
    const std::int32_t matrixParamB
  )
  {
    sofdec_EnterLock_7();
    ADXT_SetMixTableIndices(state, matrixParamA, matrixParamB);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B22480 (sub_B22480)
   *
   * What it does:
   * Sets Dolby sample-rate lane and derives clamped history window length.
   */
  std::uint32_t ADXT_SetSampleRate(AdxtDolbyRuntimeState* state, const std::int32_t sampleRate)
  {
    if (state == nullptr) {
      return static_cast<std::uint32_t>(ADXT_ReportMessage(kAdxtNullRateStateMessage));
    }

    if (sampleRate <= 0) {
      return static_cast<std::uint32_t>(ADXT_ReportMessage(kAdxtIllegalRateParameterMessage));
    }

    const auto scaledRate = static_cast<std::int32_t>(sampleRate << 6);
    const auto highProductWord = static_cast<std::int32_t>(
      (0x57619F1LL * static_cast<long long>(scaledRate)) >> 32
    );
    auto normalizedWindow = highProductWord >> 10;
    const auto signAdjust = static_cast<std::uint32_t>(normalizedWindow) >> 31;
    normalizedWindow += static_cast<std::int32_t>(signAdjust);

    if (normalizedWindow > 96) {
      normalizedWindow = 96;
    } else if (normalizedWindow < 1) {
      normalizedWindow = 1;
    }

    state->sampleRate = sampleRate;
    state->historyWindowLength = normalizedWindow;
    return signAdjust;
  }

  /**
   * Address: 0x00B22460 (sub_B22460)
   *
   * What it does:
   * Lock-guarded wrapper for Dolby sample-rate configuration.
   */
  void ADXT_SetSampleRateLocked(AdxtDolbyRuntimeState* state, const std::int32_t sampleRate)
  {
    sofdec_EnterLock_7();
    ADXT_SetSampleRate(state, sampleRate);
    sofdec_LeaveLock_7();
  }

  /**
   * Address: 0x00B224F0 (_MPARBD_EntryErrFunc)
   *
   * What it does:
   * Installs MPARBD error callback and caller context lanes.
   */
  std::int32_t __cdecl MPARBD_EntryErrFunc(
    const std::int32_t callbackFunctionAddress,
    const std::int32_t callbackContext
  )
  {
    mparbd_err_func = reinterpret_cast<MparbdErrorCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(callbackFunctionAddress))
    );
    mparbd_err_param = callbackContext;
    return 0;
  }

  /**
   * Address: 0x00B22510 (_mparbd_call_err_func)
   *
   * What it does:
   * Emits one MPARBD error callback when registered by the owner.
   */
  std::int32_t __cdecl mparbd_call_err_func(
    const char* functionName,
    const std::int32_t sourceLine,
    const char* message
  )
  {
    if (mparbd_err_func != nullptr) {
      mparbd_err_func(functionName, sourceLine, message, mparbd_err_param);
    }
    return 0;
  }

  /**
   * Address: 0x00B22540 (_MPARBD_SetUsrMallocFunc)
   *
   * What it does:
   * Updates MPARBD allocator callback and mirrors it into MPARBF runtime.
   */
  std::int32_t __cdecl MPARBD_SetUsrMallocFunc(const std::int32_t allocatorFunctionAddress)
  {
    mparbd_malloc_func = reinterpret_cast<MparbdUserMallocCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(allocatorFunctionAddress))
    );
    MPARBF_SetUsrMallocFunc(allocatorFunctionAddress);
    return 0;
  }

  /**
   * Address: 0x00B22560 (_MPARBD_SetUsrFreeFunc)
   *
   * What it does:
   * Updates MPARBD free callback and mirrors it into MPARBF runtime.
   */
  std::int32_t __cdecl MPARBD_SetUsrFreeFunc(const std::int32_t freeFunctionAddress)
  {
    mparbd_free_func = reinterpret_cast<MparbdUserFreeCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(freeFunctionAddress))
    );
    MPARBF_SetUsrFreeFunc(freeFunctionAddress);
    return 0;
  }

  /**
   * Address: 0x00B22580 (_MPARBD_Init)
   *
   * What it does:
   * Increments MPARBD init refcount and initializes bit-reader tables once.
   */
  std::int32_t MPARBD_Init()
  {
    if (++mparbd_init_count == 1) {
      mpabdr_Init();
    }
    return 0;
  }

  /**
   * Address: 0x00B225A0 (_MPARBD_Finish)
   *
   * What it does:
   * Decrements MPARBD init refcount and tears down active entries on last
   * release.
   */
  std::int32_t MPARBD_Finish()
  {
    if (--mparbd_init_count == 0) {
      while (mparbd_entry != nullptr) {
        mparbd_Destroy(mparbd_entry);
      }
      mpabdr_Finish();
    }
    return 0;
  }

  /**
   * Address: 0x00B225D0 (_MPARBD_Create)
   *
   * What it does:
   * Validates create output lane and dispatches to MPARBD internal allocator.
   */
  std::int32_t __cdecl MPARBD_Create(MparbdDecoderState** outDecoder)
  {
    if (outDecoder != nullptr) {
      return mparbd_Create(outDecoder);
    }

    mparbd_call_err_func(
      kMparbdCreateFunctionName,
      kMparbdCreateNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22600 (_mparbd_Create)
   *
   * What it does:
   * Allocates one MPARBD decoder state, creates its two MPARBF bit-reader
   * handles, links it into global decoder chain, and resets runtime lanes.
   */
  std::int32_t __cdecl mparbd_Create(MparbdDecoderState** outDecoder)
  {
    MparbdDecoderState* decoder = nullptr;
    auto status = mparbd_malloc_func(
      static_cast<std::int32_t>(sizeof(MparbdDecoderState)),
      reinterpret_cast<void**>(&decoder)
    );
    if (status < 0) {
      return status;
    }

    std::int32_t primaryBitReaderHandle = 0;
    status = MPARBF_Create(0x2000, &primaryBitReaderHandle);
    if (status < 0) {
      mparbd_free_func(reinterpret_cast<void**>(&decoder));
      return status;
    }

    std::int32_t secondaryBitReaderHandle = 0;
    status = MPARBF_Create(0x2000, &secondaryBitReaderHandle);
    if (status < 0) {
      MPARBF_Destroy(&primaryBitReaderHandle);
      mparbd_free_func(reinterpret_cast<void**>(&decoder));
      return status;
    }

    std::memset(decoder, 0, sizeof(MparbdDecoderState));

    if (mparbd_entry != nullptr) {
      mparbd_entry->nextNewer = decoder;
      decoder->previousOlder = mparbd_entry;
    }

    decoder->bitReaderHandlePrimary = primaryBitReaderHandle;
    decoder->bitReaderHandleSecondary = secondaryBitReaderHandle;
    mparbd_Reset(decoder);
    mparbd_entry = decoder;
    *outDecoder = decoder;
    return 0;
  }

  /**
   * Address: 0x00B22700 (_MPARBD_Destroy)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches to destroy routine.
   */
  std::int32_t __cdecl MPARBD_Destroy(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_Destroy(decoder);
    }

    mparbd_call_err_func(
      kMparbdDestroyFunctionName,
      kMparbdDestroyNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22730 (_mparbd_Destroy)
   *
   * What it does:
   * Unlinks one MPARBD decoder from global list, destroys MPARBF handles, and
   * releases decoder memory through registered user free callback.
   */
  std::int32_t __cdecl mparbd_Destroy(MparbdDecoderState* decoder)
  {
    auto* const nextNewer = decoder->nextNewer;
    auto* const previousOlder = decoder->previousOlder;
    auto primaryHandle = decoder->bitReaderHandlePrimary;
    auto secondaryHandle = decoder->bitReaderHandleSecondary;

    if (nextNewer != nullptr) {
      nextNewer->previousOlder = previousOlder;
    } else {
      mparbd_entry = nullptr;
    }

    if (previousOlder != nullptr) {
      previousOlder->nextNewer = nextNewer;
    }

    MPARBF_Destroy(&primaryHandle);
    MPARBF_Destroy(&secondaryHandle);

    std::memset(decoder, 0, sizeof(MparbdDecoderState));
    mparbd_free_func(reinterpret_cast<void**>(&decoder));
    return 0;
  }

  /**
   * Address: 0x00B227C0 (_MPARBD_Reset)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches to state reset routine.
   */
  std::int32_t __cdecl MPARBD_Reset(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_Reset(decoder);
    }

    mparbd_call_err_func(
      kMparbdResetFunctionName,
      kMparbdResetNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B227F0 (_mparbd_Reset)
   *
   * What it does:
   * Clears MPARBD frame/decode work lanes and resets both MPARBF bit-reader
   * handles to initial read positions.
   */
  std::int32_t __cdecl mparbd_Reset(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::uint32_t*>(decoder);

    for (std::size_t index = 0; index < kMparbdSyncStateCount; ++index) {
      decoderWords[kMparbdSyncStateBaseIndex + index] = 0;
    }
    decoderWords[kMparbdPendingReturnBytesIndex] = 0;

    std::memset(decoderWords + kMparbdHeaderScratchBaseIndex, 0, kMparbdHeaderScratchBytes);
    std::memset(decoderWords + kMparbdBitAllocBaseIndex, 0, kMparbdBitAllocBytes);
    std::memset(decoderWords + kMparbdScaleFactorSelectBaseIndex, 0, kMparbdScaleFactorSelectBytes);
    std::memset(decoderWords + kMparbdScaleFactorBaseIndex, 0, kMparbdScaleFactorBytes);
    std::memset(decoderWords + kMparbdDecodeTableDirectBaseIndex, 0, kMparbdDecodeTableDirectBytes);
    std::memset(decoderWords + kMparbdDecodeTableGroupedBitsBaseIndex, 0, kMparbdDecodeTableGroupedBitsBytes);
    std::memset(decoderWords + kMparbdDecodeTableGroupedBaseIndex, 0, kMparbdDecodeTableGroupedBytes);
    std::memset(decoderWords + kMparbdSampleBaseIndex, 0, kMparbdSampleBytes);
    std::memset(decoderWords + kMparbdDequantizedSampleBaseIndex, 0, kMparbdDequantizedSampleBytes);
    std::memset(decoderWords + kMparbdSynthesisHistoryBaseIndex, 0, kMparbdSynthesisHistoryBytes);
    std::memset(decoderWords + kMparbdSynthesisInputBaseIndex, 0, kMparbdSynthesisInputBytes);

    decoderWords[kMparbdSynthesisRingCursorIndex0] = 0;
    decoderWords[kMparbdSynthesisRingCursorIndex1] = 0;

    MPARBF_Reset(decoder->bitReaderHandlePrimary);
    MPARBF_Reset(decoder->bitReaderHandleSecondary);

    decoderWords[kMparbdExecErrorIndex] = 0;
    decoderWords[kMparbdSynthesisScaleCursorIndex] = 0;
    decoderWords[kMparbdPendingFrameIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B22960 (_MPARBD_ExecHndl)
   *
   * What it does:
   * Validates MPARBD decoder pointer and dispatches one state-machine step.
   */
  std::int32_t __cdecl MPARBD_ExecHndl(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_ExecHndl(decoder);
    }

    mparbd_call_err_func(
      kMparbdExecHandleFunctionName,
      kMparbdExecHandleNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22990 (_mparbd_ExecHndl)
   *
   * What it does:
   * Executes one MPARBD decode-state transition, handling prep/header/sample/
   * end phases and reporting terminal errors.
   */
  std::int32_t __cdecl mparbd_ExecHndl(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);

    auto failWithErrorState = [&](const std::int32_t status) {
      decoderWords[kMparbdLastErrorCodeIndex] = status;
      decoderWords[kMparbdRunStateIndex] = kMparbdStateError;
      return status;
    };

    if (decoderWords[kMparbdSuspendFlagIndex] == 1) {
      return 0;
    }

    if (
      decoderWords[kMparbdRunStateIndex] == kMparbdStateStartup
      || decoderWords[kMparbdRunStateIndex] == kMparbdStateNeedMoreData
    ) {
      mparbd_start_proc(decoder);
    }

    if (decoderWords[kMparbdRunStateIndex] == kMparbdStatePrepare) {
      const auto prepareStatus = mparbd_prep_proc(decoder);
      if (prepareStatus < 0) {
        if (prepareStatus != kMparbdErrorMalformedFrame) {
          return failWithErrorState(prepareStatus);
        }

        std::uint32_t reloadedHeaderBytes = 0;
        MPARBF_ReturnData(
          decoder->bitReaderHandlePrimary,
          static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
          nullptr
        );
        MPARBF_ReadData(
          decoder->bitReaderHandlePrimary,
          reinterpret_cast<char*>(decoder) + 0x0C,
          static_cast<std::uint32_t>(kMparbdHeaderScratchBytes),
          &reloadedHeaderBytes
        );
        decoderWords[kMparbdLastErrorCodeIndex] = kMparbdErrorMalformedFrame;
        decoderWords[kMparbdSyncStateBaseIndex] = static_cast<std::int32_t>(reloadedHeaderBytes);
        decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeEnd;
      }
    } else {
      if (decoderWords[kMparbdRunStateIndex] == kMparbdStateDecodeHeader) {
        const auto decodeHeaderStatus = mparbd_dechdr_proc(decoder);
        if (decodeHeaderStatus < 0) {
          return failWithErrorState(decodeHeaderStatus);
        }
      }

      if (decoderWords[kMparbdRunStateIndex] == kMparbdStateDecodeSamples) {
        const auto decodeSampleStatus = mparbd_decsmpl_proc(decoder);
        if (decodeSampleStatus < 0) {
          return failWithErrorState(decodeSampleStatus);
        }
      }

      if (decoderWords[kMparbdRunStateIndex] != kMparbdStateDecodeEnd) {
        return 0;
      }
    }

    const auto decodeEndStatus = mparbd_decend_proc(decoder);
    if (decodeEndStatus < 0) {
      return failWithErrorState(decodeEndStatus);
    }
    return 0;
  }

  /**
   * Address: 0x00B22A80 (_mparbd_start_proc)
   *
   * What it does:
   * Advances MPARBD from idle to prepare when enough source bytes are queued,
   * or enters end-drain state after terminal supply.
   */
  std::int32_t __cdecl mparbd_start_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);

    if (availableBytes >= kMparbdHeaderPrefixBytes) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStatePrepare;
    } else if (decoderWords[kMparbdPendingReturnBytesIndex] == 1) {
      MPARBF_ReadData(
        decoder->bitReaderHandlePrimary,
        reinterpret_cast<char*>(decoder) + 0x0C,
        availableBytes,
        nullptr
      );
      decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
    }

    return 0;
  }

  /**
   * Address: 0x00B22AE0 (_mparbd_prep_proc)
   *
   * What it does:
   * Reads MPA frame header/payload into decoder scratch lanes and transitions
   * to header decode when a complete frame is available.
   */
  std::int32_t __cdecl mparbd_prep_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);

    if (availableBytes < kMparbdHeaderPrefixBytes) {
      if (decoderWords[kMparbdPendingReturnBytesIndex] == 1) {
        MPARBF_ReadData(
          decoder->bitReaderHandlePrimary,
          reinterpret_cast<char*>(decoder) + 0x0C,
          availableBytes,
          nullptr
        );
        decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
      }
      return 0;
    }

    MPARBF_ReadData(
      decoder->bitReaderHandlePrimary,
      reinterpret_cast<char*>(decoder) + 0x0C,
      kMparbdHeaderPrefixBytes,
      nullptr
    );
    decoderWords[kMparbdSyncStateBaseIndex] = static_cast<std::int32_t>(kMparbdHeaderPrefixBytes);

    const auto headerStatus = mpadcd_GetHdrInfo(reinterpret_cast<std::uint32_t*>(decoder));
    if (headerStatus < 0) {
      return headerStatus;
    }

    if (decoderWords[kMparbdSuspendFlagIndex] != 0) {
      return 0;
    }

    const auto framePayloadBytes = (
      (144000u * static_cast<std::uint32_t>(decoderWords[441]))
      / static_cast<std::uint32_t>(decoderWords[442])
    ) + static_cast<std::uint32_t>(decoderWords[443]) - kMparbdHeaderPrefixBytes;

    MPARBF_GetDataSize(decoder->bitReaderHandlePrimary, &availableBytes);
    if (availableBytes >= framePayloadBytes && framePayloadBytes >= kMparbdMinimumFramePayloadBytes) {
      MPARBF_ReadData(
        decoder->bitReaderHandlePrimary,
        reinterpret_cast<char*>(decoder) + 0x10,
        framePayloadBytes,
        nullptr
      );
      decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeHeader;
      decoderWords[kMparbdSyncStateBaseIndex] += static_cast<std::int32_t>(framePayloadBytes);
      return 0;
    }

    if (decoderWords[kMparbdPendingReturnBytesIndex] != 0) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;
    } else {
      MPARBF_ReturnData(
        decoder->bitReaderHandlePrimary,
        kMparbdHeaderPrefixBytes,
        nullptr
      );
      decoderWords[kMparbdSyncStateBaseIndex] = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B22C10 (_mparbd_dechdr_proc)
   *
   * What it does:
   * Runs bit-allocation/scalefactor/header decode passes and enters sample
   * decode phase.
   */
  std::int32_t __cdecl mparbd_dechdr_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::uint32_t*>(decoder);
    mpadcd_GetBitAllocInfo(decoderWords);
    mpadcd_GetScfInfo(decoderWords);
    mpadcd_GetSmpl(decoderWords);
    mpadcd_DequantizeSmpl(decoderWords);
    mpadcd_GetPcmSmpl(decoderWords);
    decoderWords[kMparbdRunStateIndex] = static_cast<std::uint32_t>(kMparbdStateDecodeSamples);
    return 0;
  }

  /**
   * Address: 0x00B22C40 (_mparbd_decsmpl_proc)
   *
   * What it does:
   * Streams decoded sample blocks into output ring buffer and verifies frame
   * terminus bounds before entering end phase.
   */
  std::int32_t __cdecl mparbd_decsmpl_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    const auto primaryBitReaderHandle = decoder->bitReaderHandlePrimary;
    const auto secondaryBitReaderHandle = decoder->bitReaderHandleSecondary;
    const auto requiredOutputBytes =
      kMparbdSamplesPerFrameBlock * static_cast<std::uint32_t>(decoderWords[445]);

    if (decoderWords[kMparbdPendingReloadFlagIndex] != 0) {
      MPARBF_ReadData(
        primaryBitReaderHandle,
        reinterpret_cast<char*>(decoder) + 0x0C,
        static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
        nullptr
      );
      decoderWords[kMparbdPendingReloadFlagIndex] = 0;
    }

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
    if (freeBytes < requiredOutputBytes) {
      MPARBF_ReturnData(
        primaryBitReaderHandle,
        static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
        nullptr
      );
      decoderWords[kMparbdPendingReloadFlagIndex] = 1;
      return 0;
    }

    while (true) {
      MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
      auto writeBytes = freeBytes;
      if (freeBytes >= requiredOutputBytes) {
        writeBytes = requiredOutputBytes;
      }

      MPARBF_WriteData(
        secondaryBitReaderHandle,
        static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(decoderWords + kMparbdSynthesisHistoryBaseIndex)),
        writeBytes,
        nullptr
      );

      const auto decodedBlockCount = static_cast<std::uint32_t>(++decoderWords[kMparbdSynthesisScaleCursorIndex]);
      if (decodedBlockCount >= kMparbdDecodeBlocksPerFrame) {
        break;
      }

      auto* const decodeState = reinterpret_cast<std::uint32_t*>(decoder);
      mpadcd_GetSmpl(decodeState);
      mpadcd_DequantizeSmpl(decodeState);
      mpadcd_GetPcmSmpl(decodeState);

      MPARBF_GetFreeSize(secondaryBitReaderHandle, &freeBytes);
      if (freeBytes < requiredOutputBytes) {
        MPARBF_ReturnData(
          primaryBitReaderHandle,
          static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex]),
          nullptr
        );
        decoderWords[kMparbdPendingReloadFlagIndex] = 1;
        return 0;
      }
    }

    if (decoderWords[438] <= decoderWords[kMparbdSyncStateBaseIndex]) {
      decoderWords[kMparbdRunStateIndex] = kMparbdStateDecodeEnd;
      return 0;
    }

    mparbd_call_err_func(
      kMparbdDecodeSamplesProcFunctionName,
      kMparbdDecodeSamplesOverrunLine,
      kMparbdDecodeSamplesOverrunMessage
    );
    return kMparbdErrorSampleOverrun;
  }

  /**
   * Address: 0x00B22D80 (_mparbd_decend_proc)
   *
   * What it does:
   * Finalizes one decoded frame, returns unread source bytes, and updates
   * frame completion counters/end status.
   */
  std::int32_t __cdecl mparbd_decend_proc(MparbdDecoderState* decoder)
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);

    mpadcd_SkipToNextFrm(reinterpret_cast<std::uint32_t*>(decoder));
    MPARBF_ReturnData(
      decoder->bitReaderHandlePrimary,
      static_cast<std::uint32_t>(decoderWords[kMparbdSyncStateBaseIndex] - decoderWords[438]),
      nullptr
    );

    const auto previousErrorCode = decoderWords[kMparbdLastErrorCodeIndex];
    decoderWords[kMparbdExecErrorIndex] += decoderWords[438];
    decoderWords[kMparbdSynthesisScaleCursorIndex] = 0;
    decoderWords[kMparbdRunStateIndex] = kMparbdStateNeedMoreData;

    if (previousErrorCode != 0) {
      decoderWords[kMparbdLastErrorCodeIndex] = 0;
    } else {
      ++decoderWords[kMparbdPendingFrameIndex];
    }

    return 0;
  }

  /**
   * Address: 0x00B22E00 (_MPARBD_GetDecStat)
   *
   * What it does:
   * Returns current MPARBD decode state machine status lane.
   */
  std::int32_t __cdecl MPARBD_GetDecStat(MparbdDecoderState* decoder, std::int32_t* outDecodeState)
  {
    if (decoder != nullptr && outDecodeState != nullptr) {
      *outDecodeState = *reinterpret_cast<std::int32_t*>(decoder);
      return 0;
    }

    mparbd_call_err_func(
      kMparbdGetDecodeStatusFunctionName,
      kMparbdGetDecodeStatusNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22E50 (_MPARBD_GetEndStat)
   *
   * What it does:
   * Returns MPARBD end-state lane used by caller-driven stream completion.
   */
  std::int32_t __cdecl MPARBD_GetEndStat(MparbdDecoderState* decoder, std::int32_t* outEndState)
  {
    if (decoder != nullptr && outEndState != nullptr) {
      *outEndState = reinterpret_cast<std::int32_t*>(decoder)[kMparbdSuspendFlagIndex];
      return 0;
    }

    mparbd_call_err_func(
      kMparbfGetEndStatusFunctionName,
      kMparbfGetEndStatusNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22EA0 (_MPARBD_SetEndStat)
   *
   * What it does:
   * Updates MPARBD end-state lane for external stream completion control.
   */
  std::int32_t __cdecl MPARBD_SetEndStat(MparbdDecoderState* decoder, const std::int32_t endState)
  {
    if (decoder != nullptr) {
      reinterpret_cast<std::int32_t*>(decoder)[kMparbdSuspendFlagIndex] = endState;
      return 0;
    }

    mparbd_call_err_func(
      kMparbfGetEndStatusFunctionName,
      kMparbfSetEndStatusNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22EE0 (_MPARBD_GetNumSmplDcd)
   *
   * What it does:
   * Validates output lanes and returns decoded frame/block counters.
   */
  std::int32_t __cdecl MPARBD_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  )
  {
    if (decoder != nullptr && outDecodedFrameCount != nullptr && outDecodedBlockCount != nullptr) {
      return mparbd_GetNumSmplDcd(decoder, outDecodedFrameCount, outDecodedBlockCount);
    }

    mparbd_call_err_func(
      kMparbdGetNumSamplesDecodedFunctionName,
      kMparbdGetNumSamplesDecodedNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22F30 (_mparbd_GetNumSmplDcd)
   *
   * What it does:
   * Returns total decoded-frame count and current decoded-block count.
   */
  std::int32_t __cdecl mparbd_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  )
  {
    auto* const decoderWords = reinterpret_cast<std::int32_t*>(decoder);
    *outDecodedFrameCount = decoderWords[kMparbdDecodedFrameCountIndex];
    *outDecodedBlockCount = decoderWords[kMparbdDecodedBlockCountIndex];
    return 0;
  }

  /**
   * Address: 0x00B22F50 (_MPARBD_GetNumByteDcd)
   *
   * What it does:
   * Returns accumulated decoded byte count from MPARBD state.
   */
  std::int32_t __cdecl MPARBD_GetNumByteDcd(MparbdDecoderState* decoder, std::int32_t* outDecodedBytes)
  {
    if (decoder != nullptr && outDecodedBytes != nullptr) {
      *outDecodedBytes = reinterpret_cast<std::int32_t*>(decoder)[kMparbdDecodedByteCountIndex];
      return 0;
    }

    mparbd_call_err_func(
      kMparbdGetNumBytesDecodedFunctionName,
      kMparbdGetNumBytesDecodedNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B22FB0 (_MPARBD_GetSfreq)
   *
   * What it does:
   * Returns decoded sample-rate only after at least one frame/block has been
   * produced.
   */
  std::int32_t __cdecl MPARBD_GetSfreq(MparbdDecoderState* decoder, std::int32_t* outSampleRate)
  {
    if (decoder == nullptr || outSampleRate == nullptr) {
      mparbd_call_err_func(
        kMparbdGetSampleRateFunctionName,
        kMparbdGetSampleRateNullPointerLine,
        kMparbdNullPointerMessage
      );
      return -1;
    }

    std::int32_t decodedFrameCount = 0;
    std::int32_t decodedBlockCount = 0;
    mparbd_GetNumSmplDcd(decoder, &decodedFrameCount, &decodedBlockCount);
    if (decodedFrameCount != 0 || decodedBlockCount != 0) {
      *outSampleRate = reinterpret_cast<std::int32_t*>(decoder)[kMparbdSampleRateIndex];
      return 0;
    }

    *outSampleRate = 0;
    return kMparbdErrorNoDecodedSamples;
  }

  /**
   * Address: 0x00B23040 (_MPARBD_GetNumChannel)
   *
   * What it does:
   * Validates channel-count output lane and dispatches to internal getter.
   */
  std::int32_t __cdecl MPARBD_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount)
  {
    if (decoder != nullptr && outChannelCount != nullptr) {
      return mparbd_GetNumChannel(decoder, outChannelCount);
    }

    mparbd_call_err_func(
      kMparbdGetNumChannelFunctionName,
      kMparbdGetNumChannelNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23080 (_mparbd_GetNumChannel)
   *
   * What it does:
   * Returns decoded channel count once decode progress counters are non-zero.
   */
  std::int32_t __cdecl mparbd_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount)
  {
    std::int32_t decodedFrameCount = 0;
    std::int32_t decodedBlockCount = 0;
    mparbd_GetNumSmplDcd(decoder, &decodedFrameCount, &decodedBlockCount);
    if (decodedFrameCount != 0 || decodedBlockCount != 0) {
      *outChannelCount = reinterpret_cast<std::int32_t*>(decoder)[kMparbdChannelCountIndex];
      return 0;
    }

    *outChannelCount = 0;
    return kMparbdErrorNoDecodedSamples;
  }

  /**
   * Address: 0x00B230D0 (_MPARBD_GetNumBit)
   *
   * What it does:
   * Validates output lane and returns fixed PCM output bit depth.
   */
  std::int32_t __cdecl MPARBD_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample)
  {
    if (decoder != nullptr && outBitsPerSample != nullptr) {
      return mparbd_GetNumBit(decoder, outBitsPerSample);
    }

    mparbd_call_err_func(
      kMparbdGetNumBitFunctionName,
      kMparbdGetNumBitNullPointerLine,
      kMparbdNullPointerMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23110 (_mparbd_GetNumBit)
   *
   * What it does:
   * Returns fixed 16-bit PCM output depth for MPARBD decode path.
   */
  std::int32_t __cdecl mparbd_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample)
  {
    (void)decoder;
    *outBitsPerSample = kMparbdBitsPerSample;
    return 0;
  }

  /**
   * Address: 0x00B23120 (_MPARBD_TermSupply)
   *
   * What it does:
   * Marks decoder input supply as terminated so partial frame drain is
   * permitted.
   */
  std::int32_t __cdecl MPARBD_TermSupply(MparbdDecoderState* decoder)
  {
    if (decoder != nullptr) {
      return mparbd_TermSupply(decoder);
    }

    mparbd_call_err_func(
      kMpardTermSupplyFunctionName,
      kMpardTermSupplyNullPointerLine,
      kMparbdNullPointerSentenceCaseMessage
    );
    return -1;
  }

  /**
   * Address: 0x00B23150 (_mparbd_TermSupply)
   *
   * What it does:
   * Sets terminal-supply latch consumed by start/prep states.
   */
  std::int32_t __cdecl mparbd_TermSupply(MparbdDecoderState* decoder)
  {
    reinterpret_cast<std::int32_t*>(decoder)[kMparbdPendingReturnBytesIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23170 (_MPARBF_SetUsrMallocFunc)
   *
   * What it does:
   * Updates MPARBF user allocation callback pointer.
   */
  std::int32_t __cdecl MPARBF_SetUsrMallocFunc(const std::int32_t allocatorFunctionAddress)
  {
    mparbf_malloc_func = reinterpret_cast<MparbdUserMallocCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(allocatorFunctionAddress))
    );
    return 0;
  }

  /**
   * Address: 0x00B23180 (_MPARBF_SetUsrFreeFunc)
   *
   * What it does:
   * Updates MPARBF user free callback pointer.
   */
  std::int32_t __cdecl MPARBF_SetUsrFreeFunc(const std::int32_t freeFunctionAddress)
  {
    mparbf_free_func = reinterpret_cast<MparbdUserFreeCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(freeFunctionAddress))
    );
    return 0;
  }

  /**
   * Address: 0x00B23190 (_MPARBF_Create)
   *
   * What it does:
   * Allocates one MPARBF ring-buffer object and backing byte storage.
   */
  std::int32_t __cdecl MPARBF_Create(const std::int32_t bufferBytes, std::int32_t* outHandle)
  {
    MparbfRuntimeBuffer* ringBuffer = nullptr;
    auto status = mparbf_malloc_func(
      static_cast<std::int32_t>(sizeof(MparbfRuntimeBuffer)),
      reinterpret_cast<void**>(&ringBuffer)
    );
    if (status < 0) {
      return status;
    }

    std::memset(ringBuffer, 0, sizeof(MparbfRuntimeBuffer));

    std::uint8_t* storage = nullptr;
    status = mparbf_malloc_func(bufferBytes, reinterpret_cast<void**>(&storage));
    if (status < 0) {
      mparbf_free_func(reinterpret_cast<void**>(&ringBuffer));
      return status;
    }

    ringBuffer->capacityBytes = static_cast<std::uint32_t>(bufferBytes);
    ringBuffer->data = storage;
    MPARBF_Reset(
      static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ringBuffer)))
    );

    *outHandle = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ringBuffer))
    );
    return 0;
  }

  /**
   * Address: 0x00B23220 (_MPARBF_Destroy)
   *
   * What it does:
   * Clears and releases MPARBF ring-buffer storage and object instance.
   */
  std::int32_t __cdecl MPARBF_Destroy(std::int32_t* handleAddress)
  {
    auto* ringBuffer = AsMparbfRuntimeBuffer(*handleAddress);
    void* storageAddress = ringBuffer->data;
    std::memset(storageAddress, 0, ringBuffer->capacityBytes);
    mparbf_free_func(&storageAddress);

    std::memset(ringBuffer, 0, sizeof(MparbfRuntimeBuffer));
    void* ringBufferAddress = ringBuffer;
    mparbf_free_func(&ringBufferAddress);
    *handleAddress = 0;
    return 0;
  }

  /**
   * Address: 0x00B23280 (_MPARBF_Reset)
   *
   * What it does:
   * Clears ring-buffer bytes and resets all cursor/size lanes.
   */
  std::int32_t __cdecl MPARBF_Reset(const std::int32_t handleAddress)
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);
    std::memset(ringBuffer->data, 0, ringBuffer->capacityBytes);
    ringBuffer->readOffsetBytes = 0;
    ringBuffer->dataBytes = 0;
    ringBuffer->writeOffsetBytes = 0;
    ringBuffer->freeBytes = ringBuffer->capacityBytes;
    return 0;
  }

  /**
   * Address: 0x00B232C0 (_MPARBF_GetDataSize)
   *
   * What it does:
   * Returns currently queued byte count in MPARBF ring-buffer.
   */
  std::int32_t __cdecl MPARBF_GetDataSize(const std::int32_t handleAddress, std::uint32_t* outDataBytes)
  {
    *outDataBytes = AsMparbfRuntimeBuffer(handleAddress)->dataBytes;
    return 0;
  }

  /**
   * Address: 0x00B232D0 (_MPARBF_GetFreeSize)
   *
   * What it does:
   * Returns currently free byte capacity in MPARBF ring-buffer.
   */
  std::int32_t __cdecl MPARBF_GetFreeSize(const std::int32_t handleAddress, std::uint32_t* outFreeBytes)
  {
    *outFreeBytes = AsMparbfRuntimeBuffer(handleAddress)->freeBytes;
    return 0;
  }

  /**
   * Address: 0x00B232E0 (_MPARBF_ReadData)
   *
   * What it does:
   * Reads up to requested bytes from ring-buffer and advances read cursor.
   */
  std::int32_t __cdecl MPARBF_ReadData(
    const std::int32_t handleAddress,
    char* destinationBytes,
    const std::uint32_t byteCount,
    std::uint32_t* outReadBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);

    std::uint32_t availableBytes = 0;
    MPARBF_GetDataSize(handleAddress, &availableBytes);
    const auto readBytes = (availableBytes < byteCount) ? availableBytes : byteCount;

    const auto readOffset = ringBuffer->readOffsetBytes;
    const auto capacity = ringBuffer->capacityBytes;
    const auto endOffset = readOffset + readBytes;

    std::uint32_t firstChunkBytes = readBytes;
    std::uint32_t wrapChunkBytes = 0;
    if (endOffset > capacity) {
      firstChunkBytes = capacity - readOffset;
      wrapChunkBytes = endOffset - capacity;
    }

    std::memcpy(destinationBytes, ringBuffer->data + readOffset, firstChunkBytes);
    std::memcpy(destinationBytes + firstChunkBytes, ringBuffer->data, wrapChunkBytes);

    ringBuffer->dataBytes -= readBytes;
    ringBuffer->freeBytes += readBytes;
    ringBuffer->readOffsetBytes = (capacity == 0) ? 0 : (endOffset % capacity);
    if (outReadBytes != nullptr) {
      *outReadBytes = readBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00B233A0 (_MPARBF_WriteData)
   *
   * What it does:
   * Writes up to available free bytes into ring-buffer and advances write
   * cursor.
   */
  std::int32_t __cdecl MPARBF_WriteData(
    const std::int32_t handleAddress,
    const std::int32_t sourceAddress,
    const std::uint32_t byteCount,
    std::uint32_t* outWrittenBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);
    const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceAddress))
    );

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(handleAddress, &freeBytes);
    const auto writeBytes = (freeBytes < byteCount) ? freeBytes : byteCount;

    const auto writeOffset = ringBuffer->writeOffsetBytes;
    const auto capacity = ringBuffer->capacityBytes;
    const auto endOffset = writeOffset + writeBytes;

    std::uint32_t firstChunkBytes = writeBytes;
    std::uint32_t wrapChunkBytes = 0;
    if (endOffset > capacity) {
      firstChunkBytes = capacity - writeOffset;
      wrapChunkBytes = endOffset - capacity;
    }

    std::memcpy(ringBuffer->data + writeOffset, sourceBytes, firstChunkBytes);
    std::memcpy(ringBuffer->data, sourceBytes + firstChunkBytes, wrapChunkBytes);

    ringBuffer->dataBytes += writeBytes;
    ringBuffer->freeBytes -= writeBytes;
    ringBuffer->writeOffsetBytes = (capacity == 0) ? 0 : (endOffset % capacity);
    if (outWrittenBytes != nullptr) {
      *outWrittenBytes = writeBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00B23460 (_MPARBF_ReturnData)
   *
   * What it does:
   * Returns consumed bytes back to ring-buffer by rewinding read cursor.
   */
  std::int32_t __cdecl MPARBF_ReturnData(
    const std::int32_t handleAddress,
    const std::uint32_t returnBytes,
    std::uint32_t* outReturnedBytes
  )
  {
    auto* const ringBuffer = AsMparbfRuntimeBuffer(handleAddress);

    std::uint32_t freeBytes = 0;
    MPARBF_GetFreeSize(handleAddress, &freeBytes);
    const auto rewoundBytes = (freeBytes < returnBytes) ? freeBytes : returnBytes;

    const auto capacity = ringBuffer->capacityBytes;
    std::uint32_t newReadOffset = capacity + ringBuffer->readOffsetBytes - rewoundBytes;
    if (newReadOffset > capacity) {
      newReadOffset = ringBuffer->readOffsetBytes - rewoundBytes;
    }

    ringBuffer->readOffsetBytes = newReadOffset;
    ringBuffer->freeBytes -= rewoundBytes;
    ringBuffer->dataBytes += rewoundBytes;

    if (outReturnedBytes != nullptr) {
      *outReturnedBytes = rewoundBytes;
    }
    return 0;
  }

  /**
   * Address: 0x00B23510 (_M2ADEC_Initialize)
   *
   * What it does:
   * Initializes M2A decoder dependency runtimes.
   */
  std::int32_t M2ADEC_Initialize()
  {
    M2ABSR_Initialize();
    M2AHUFFMAN_Initialize();
    M2AIMDCT_Initialize();
    return 0;
  }

  /**
   * Address: 0x00B23530 (_M2ADEC_Finalize)
   *
   * What it does:
   * Finalizes M2A decoder dependency runtimes.
   */
  std::int32_t M2ADEC_Finalize()
  {
    M2ABSR_Finalize();
    M2AHUFFMAN_Finalize();
    M2AIMDCT_Finalize();
    return 0;
  }

  /**
   * Address: 0x00B23550 (_M2ADEC_Create)
   *
   * What it does:
   * Allocates and initializes one M2A decoder context and bitstream object.
   */
  std::int32_t __cdecl M2ADEC_Create(const std::int32_t heapManagerHandle, M2aDecoderContext** outContext)
  {
    if (outContext == nullptr) {
      return -1;
    }

    *outContext = nullptr;

    auto* const context = static_cast<M2aDecoderContext*>(
      M2aAllocFromHeap(heapManagerHandle, kM2aDecoderContextSize)
    );
    if (context == nullptr) {
      return -1;
    }

    m2adec_clear(context, kM2aDecoderContextSize);

    std::int32_t* bitstream = nullptr;
    if (M2ABSR_Create(heapManagerHandle, &bitstream) >= 0 && bitstream != nullptr) {
      M2ADEC_Reset(context);
      auto* const contextWords = M2aContextWords(context);
      contextWords[kM2aContextHeapManagerIndex] = heapManagerHandle;
      contextWords[9] = M2aPtrToWord(bitstream);
      *outContext = context;
      return 0;
    }

    M2aFreeHeapAllocation(heapManagerHandle, context);
    return -1;
  }

  /**
   * Address: 0x00B235D0 (_M2ADEC_Destroy)
   *
   * What it does:
   * Destroys one M2A decoder context and releases all owned allocations.
   */
  std::int32_t __cdecl M2ADEC_Destroy(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    auto* const contextWords = M2aContextWords(context);
    const auto heapManagerHandle = contextWords[kM2aContextHeapManagerIndex];

    auto* const bitstream = M2aWordToPtr<std::int32_t>(contextWords[9]);
    if (bitstream != nullptr) {
      M2ABSR_Destroy(bitstream);
      contextWords[9] = 0;
    }

    M2ADEC_Reset(context);
    M2aFreeHeapAllocation(heapManagerHandle, context);
    return 0;
  }

  /**
   * Address: 0x00B23610 (_M2ADEC_Start)
   *
   * What it does:
   * Starts decoding by stopping any active run, resetting context, then
   * switching decoder state to running.
   */
  std::int32_t __cdecl M2ADEC_Start(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    std::int32_t currentStatus = 0;
    M2ADEC_GetStatus(context, &currentStatus);
    if (currentStatus != 0) {
      M2ADEC_Stop(context);
    }

    M2ADEC_Reset(context);
    M2aContextWords(context)[kM2aContextStatusIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23660 (_M2ADEC_Stop)
   *
   * What it does:
   * Stops decoding by clearing running status lane.
   */
  std::int32_t __cdecl M2ADEC_Stop(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    M2aContextWords(context)[kM2aContextStatusIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B23680 (_M2ADEC_Reset)
   *
   * What it does:
   * Releases all transient M2A decode allocations and restores base runtime
   * control lanes.
   */
  std::int32_t __cdecl M2ADEC_Reset(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    auto* const contextWords = M2aContextWords(context);
    const auto heapManagerHandle = contextWords[kM2aContextHeapManagerIndex];

    auto* scratchMapping = M2aWordToPtr<void>(contextWords[kM2aContextScratchMappingIndex]);
    if (scratchMapping != nullptr) {
      m2adec_clear(scratchMapping, kM2aScratchMappingBytes);
      M2aFreeHeapAllocation(heapManagerHandle, scratchMapping);
      contextWords[kM2aContextScratchMappingIndex] = 0;
    }

    auto* pceMap = M2aWordToPtr<void>(contextWords[kM2aContextPceMapIndex]);
    if (pceMap != nullptr) {
      m2adec_clear(pceMap, kM2aPceMapBytes);
      M2aFreeHeapAllocation(heapManagerHandle, pceMap);
      contextWords[kM2aContextPceMapIndex] = 0;
    }

    for (std::int32_t index = 0; index < kM2aLocationEntryCapacity; ++index) {
      const auto laneIndex = kM2aContextLocationEntryBaseIndex + index;
      auto* const locationEntry = M2aWordToPtr<void>(contextWords[laneIndex]);
      if (locationEntry != nullptr) {
        m2adec_clear(locationEntry, kM2aLocationEntrySize);
        M2aFreeHeapAllocation(heapManagerHandle, locationEntry);
        contextWords[laneIndex] = 0;
      }
    }

    for (std::int32_t slotIndex = 0; slotIndex < kM2aDecoderSlotCount; ++slotIndex) {
      const auto icsLaneIndex = kM2aContextIcsTableBaseIndex + slotIndex;
      auto* const icsLane = M2aWordToPtr<void>(contextWords[icsLaneIndex]);
      if (icsLane != nullptr) {
        m2adec_clear(icsLane, kM2aIcsInfoSize);
        M2aFreeHeapAllocation(heapManagerHandle, icsLane);
        contextWords[icsLaneIndex] = 0;
      }

      const auto decodeStateIndex = kM2aContextPrimaryStateBaseIndex + slotIndex;
      auto* const decodeState = M2aWordToPtr<void>(contextWords[decodeStateIndex]);
      if (decodeState != nullptr) {
        m2adec_clear(decodeState, kM2aDecodeStateSize);
        M2aFreeHeapAllocation(heapManagerHandle, decodeState);
        contextWords[decodeStateIndex] = 0;
      }
    }

    auto* const bitstream = M2aWordToPtr<std::uint32_t>(contextWords[9]);
    if (bitstream != nullptr) {
      M2ABSR_Reset(bitstream);
    }

    contextWords[kM2aContextStatusIndex] = 0;
    contextWords[kM2aContextErrorCodeIndex] = 0;
    contextWords[kM2aContextInputBufferIndex] = 0;
    contextWords[kM2aContextInputByteCountIndex] = 0;
    contextWords[kM2aContextElementIndex] = 0;
    contextWords[kM2aContextWindowGroupIndex] = 0;
    contextWords[kM2aContextElementCounterIndex] = 0;
    contextWords[kM2aContextElementCounterLimitIndex] = 0;
    contextWords[kM2aContextFrameCounterIndex] = 0;
    contextWords[kM2aContextEndModeIndex] = 0;
    contextWords[17] = 0;
    contextWords[kM2aContextAudioObjectTypeIndex] = 1;
    contextWords[kM2aContextSampleRateIndex] = 0;
    contextWords[kM2aContextSampleRateTableIndex] = 0;
    contextWords[22] = 0;
    contextWords[kM2aContextDecodedChannelCountIndex] = 0;
    contextWords[kM2aContextDecodeCountInitializedIndex] = 0;
    contextWords[24] = 0;
    return 0;
  }

  /**
   * Address: 0x00B237F0 (_M2ADEC_GetStatus)
   *
   * What it does:
   * Reads current M2A decoder run-state lane.
   */
  std::int32_t __cdecl M2ADEC_GetStatus(M2aDecoderContext* context, std::int32_t* outStatus)
  {
    if (context == nullptr || outStatus == nullptr) {
      return -1;
    }

    *outStatus = M2aContextWords(context)[kM2aContextStatusIndex];
    return 0;
  }

  /**
   * Address: 0x00B23810 (_M2ADEC_GetErrorCode)
   *
   * What it does:
   * Reads current M2A decoder error-code lane.
   */
  std::int32_t __cdecl M2ADEC_GetErrorCode(M2aDecoderContext* context, std::int32_t* outErrorCode)
  {
    if (context == nullptr || outErrorCode == nullptr) {
      return -1;
    }

    *outErrorCode = M2aContextWords(context)[kM2aContextErrorCodeIndex];
    return 0;
  }

  /**
   * Address: 0x00B23830 (_M2ADEC_Process)
   *
   * What it does:
   * Decodes one AAC packet payload, updates frame/end bookkeeping lanes, and
   * reports consumed source bytes.
   */
  std::int32_t __cdecl M2ADEC_Process(
    M2aDecoderContext* context,
    const std::int32_t sourceAddress,
    const std::int32_t sourceBytes,
    std::int32_t* outConsumedBytes
  )
  {
    if (context == nullptr || sourceAddress == 0 || outConsumedBytes == nullptr) {
      return -1;
    }

    *outConsumedBytes = 0;
    auto* const contextWords = M2aContextWords(context);
    if (contextWords[kM2aContextStatusIndex] != 1) {
      return 0;
    }

    if (contextWords[kM2aContextEndModeIndex] == 1 && sourceBytes < 2) {
      contextWords[kM2aContextStatusIndex] = 2;
    }

    contextWords[kM2aContextInputByteCountIndex] = sourceBytes;
    contextWords[kM2aContextInputBufferIndex] = sourceAddress;
    M2ABSR_SetBuffer(
      M2aWordToPtr<std::uint32_t>(contextWords[kM2aContextBitstreamHandleIndex]),
      sourceAddress,
      sourceBytes
    );

    if (m2adec_decode_header(context) < 0) {
      return m2adec_find_sync_offset(context, outConsumedBytes);
    }

    std::int32_t decodeStatus = m2adec_decode_elements(context);
    if (decodeStatus < 0) {
      return m2adec_find_sync_offset(context, outConsumedBytes);
    }

    std::int32_t overrunFlag = 0;
    M2ABSR_Overruns(contextWords[kM2aContextBitstreamHandleIndex], &overrunFlag);
    if (overrunFlag == 1) {
      if (contextWords[kM2aContextEndModeIndex] == 1) {
        *outConsumedBytes = contextWords[kM2aContextInputByteCountIndex];
        contextWords[kM2aContextStatusIndex] = 2;
      } else {
        contextWords[kM2aContextPendingSupplyIndex] = 1;
        std::int32_t bitPosition = 0;
        M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &bitPosition);
        *outConsumedBytes = bitPosition / 8;
        contextWords[kM2aContextInputBitRemainderIndex] = bitPosition % 8;
      }

      return decodeStatus;
    }

    contextWords[kM2aContextPendingSupplyIndex] = 0;
    if (contextWords[kM2aContextWindowGroupIndex] != kM2aElementIdEnd) {
      return 0;
    }

    decodeStatus = m2adec_decode_pcm(context);
    if (decodeStatus < 0) {
      return decodeStatus;
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);

    std::int32_t bitPosition = 0;
    M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &bitPosition);

    if (contextWords[kM2aContextHeaderTypeIndex] == 2) {
      if (contextWords[kM2aContextElementCounterLimitIndex] != 0) {
        contextWords[kM2aContextElementCounterIndex] += bitPosition / -8;
        --contextWords[kM2aContextElementCounterLimitIndex];
      } else {
        M2ABSR_Seek(
          contextWords[kM2aContextBitstreamHandleIndex],
          8 * contextWords[kM2aContextElementCounterIndex],
          0
        );
      }
    }

    ++contextWords[kM2aContextFrameCounterIndex];
    if (contextWords[kM2aContextLayoutInitializedIndex] == 0) {
      m2adec_specify_location(context);
      contextWords[kM2aContextLayoutInitializedIndex] = 1;
    }

    *outConsumedBytes = bitPosition / 8;
    if (contextWords[kM2aContextEndModeIndex] == 1) {
      std::int32_t isEndOfBuffer = 0;
      M2ABSR_IsEndOfBuffer(contextWords[kM2aContextBitstreamHandleIndex], &isEndOfBuffer);
      if (isEndOfBuffer == 1) {
        contextWords[kM2aContextStatusIndex] = 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B23A30 (sub_B23A30)
   *
   * What it does:
   * Returns pending input-supply flag for one M2A decode context.
   */
  std::int32_t __cdecl M2ADEC_GetPendingSupply(M2aDecoderContext* context, std::int32_t* outPendingSupply)
  {
    if (context == nullptr || outPendingSupply == nullptr) {
      return -1;
    }

    *outPendingSupply = M2aContextWords(context)[kM2aContextPendingSupplyIndex];
    return 0;
  }

  /**
   * Address: 0x00B23A50 (_M2ADEC_BeginFlush)
   *
   * What it does:
   * Enables end/flush mode for one M2A decode context.
   */
  std::int32_t __cdecl M2ADEC_BeginFlush(M2aDecoderContext* context)
  {
    if (context == nullptr) {
      return -1;
    }

    M2aContextWords(context)[kM2aContextEndModeIndex] = 1;
    return 0;
  }

  /**
   * Address: 0x00B23A70 (_M2ADEC_GetNumFramesDecoded)
   *
   * What it does:
   * Returns decoded-frame counter lane from one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetNumFramesDecoded(M2aDecoderContext* context, std::int32_t* outFrameCount)
  {
    if (context == nullptr || outFrameCount == nullptr) {
      return -1;
    }

    *outFrameCount = M2aContextWords(context)[kM2aContextFrameCounterIndex];
    return 0;
  }

  /**
   * Address: 0x00B23A90 (_M2ADEC_GetNumSamplesDecoded)
   *
   * What it does:
   * Returns decoded PCM sample count derived from decoded frame count.
   */
  std::int32_t __cdecl M2ADEC_GetNumSamplesDecoded(M2aDecoderContext* context, std::int32_t* outSampleCount)
  {
    if (context == nullptr || outSampleCount == nullptr) {
      return -1;
    }

    const auto frameCount = M2aContextWords(context)[kM2aContextFrameCounterIndex];
    if (frameCount > 2) {
      *outSampleCount = (frameCount - 2) << 10;
    } else {
      *outSampleCount = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B23AC0 (_M2ADEC_GetProfile)
   *
   * What it does:
   * Reports fixed AAC profile code used by this decoder lane.
   */
  std::int32_t __cdecl M2ADEC_GetProfile(M2aDecoderContext* context, std::int32_t* outProfile)
  {
    if (context == nullptr || outProfile == nullptr) {
      return -1;
    }

    *outProfile = kM2aMainProfile;
    return 0;
  }

  /**
   * Address: 0x00B23AE0 (_M2ADEC_GetFrequency)
   *
   * What it does:
   * Returns configured sample-rate lane for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetFrequency(M2aDecoderContext* context, std::int32_t* outFrequency)
  {
    if (context == nullptr || outFrequency == nullptr) {
      return -1;
    }

    *outFrequency = M2aContextWords(context)[kM2aContextSampleRateIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B00 (_M2ADEC_GetNumChannels)
   *
   * What it does:
   * Returns configured decoded-channel count for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetNumChannels(M2aDecoderContext* context, std::int32_t* outChannelCount)
  {
    if (context == nullptr || outChannelCount == nullptr) {
      return -1;
    }

    *outChannelCount = M2aContextWords(context)[kM2aContextDecodedChannelCountIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B20 (_M2ADEC_GetChannelConfiguration)
   *
   * What it does:
   * Returns ADTS channel-configuration lane for one M2A context.
   */
  std::int32_t __cdecl M2ADEC_GetChannelConfiguration(
    M2aDecoderContext* context,
    std::int32_t* outChannelConfiguration
  )
  {
    if (context == nullptr || outChannelConfiguration == nullptr) {
      return -1;
    }

    *outChannelConfiguration = M2aContextWords(context)[kM2aContextChannelConfigurationIndex];
    return 0;
  }

  /**
   * Address: 0x00B23B40 (_M2ADEC_GetPcm)
   *
   * What it does:
   * Exports one decoded PCM channel from active decode-state windows.
   */
  std::int32_t __cdecl M2ADEC_GetPcm(
    M2aDecoderContext* context,
    std::int32_t channelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0) {
      return -1;
    }

    std::int32_t selectedChannel = channelIndex;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 0) {
        if (selectedChannel == 0) {
          const auto groupedSlot = locationEntry->channelPairType + (32 * locationEntry->channelClass);
          auto* const decodeState = M2aGetPrimaryStateBySlot(context, groupedSlot);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        --selectedChannel;
        continue;
      }

      if (locationEntry->channelClass == 1) {
        if (selectedChannel == 0) {
          auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        if (selectedChannel == 1) {
          auto* const decodeState = M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          m2adec_convert_to_pcm16(M2aGetDecodeStatePcmWindow(decodeState), destinationAddress);
        }

        selectedChannel -= 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B23C20 (_M2ADEC_GetDownmixedPcm)
   *
   * What it does:
   * Builds one downmixed PCM lane from multi-channel decode-state windows.
   */
  std::int32_t __cdecl M2ADEC_GetDownmixedPcm(
    M2aDecoderContext* context,
    const std::int32_t outputChannelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0 || outputChannelIndex > 2) {
      return -1;
    }

    if (M2aContextWords(context)[kM2aContextDecodedChannelCountIndex] <= 2) {
      return M2ADEC_GetPcm(context, outputChannelIndex, destinationAddress);
    }

    float downmixScale = kM2aMonoDownmixScale;
    auto* const pceMapWords = M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPceMapIndex]);
    if (pceMapWords != nullptr) {
      downmixScale = m2asjd_downmix_table[pceMapWords[kM2aPceMixdownTableIndex]];
    }

    m2adec_clear(m2asjd_downmix_buffer, kM2aDownmixBufferBytes);

    const bool useSecondaryChannel = outputChannelIndex != 0;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 1) {
        auto* const decodeState = useSecondaryChannel
                                    ? M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType)
                                    : M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        const auto* const sourcePcm = M2aGetDecodeStatePcmWindow(decodeState);
        if (locationEntry->locationClass == 2) {
          M2aAccumulateScaledPcmWindow(m2asjd_downmix_buffer, sourcePcm, kM2aCenterDownmixScale);
        } else if (locationEntry->locationClass == 6) {
          M2aAccumulateScaledPcmWindow(m2asjd_downmix_buffer, sourcePcm, downmixScale);
        }
        continue;
      }

      if (locationEntry->channelClass == 0) {
        auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        M2aAccumulateScaledPcmWindow(
          m2asjd_downmix_buffer,
          M2aGetDecodeStatePcmWindow(decodeState),
          kM2aMonoDownmixScale
        );
      }
    }

    m2adec_convert_to_pcm16(m2asjd_downmix_buffer, destinationAddress);
    return 0;
  }

  /**
   * Address: 0x00B23DB0 (_M2ADEC_GetSurroundPcm)
   *
   * What it does:
   * Builds one surround-aware PCM lane using PCE surround mixdown metadata.
   */
  std::int32_t __cdecl M2ADEC_GetSurroundPcm(
    M2aDecoderContext* context,
    const std::int32_t outputChannelIndex,
    const std::int32_t destinationAddress
  )
  {
    if (context == nullptr || destinationAddress == 0 || outputChannelIndex > 2) {
      return -1;
    }

    if (M2aContextWords(context)[kM2aContextDecodedChannelCountIndex] <= 2) {
      return M2ADEC_GetPcm(context, outputChannelIndex, destinationAddress);
    }

    auto* const pceMapWords = M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPceMapIndex]);
    if (pceMapWords == nullptr || pceMapWords[kM2aPceSurroundMixdownEnabledIndex] == 0) {
      return M2ADEC_GetDownmixedPcm(context, outputChannelIndex, destinationAddress);
    }

    float surroundScale = m2asjd_downmix_table[pceMapWords[kM2aPceMixdownTableIndex]];
    if (outputChannelIndex == 0) {
      surroundScale *= -1.0f;
    }

    m2adec_clear(m2asjd_downmix_buffer, kM2aDownmixBufferBytes);

    const bool useSecondaryChannel = outputChannelIndex != 0;
    for (std::int32_t entryIndex = 0; entryIndex < kM2aLocationEntryCapacity; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      if (locationEntry->channelClass == 1) {
        if (locationEntry->locationClass == 2) {
          auto* const decodeState = useSecondaryChannel
                                      ? M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType)
                                      : M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(decodeState)) {
            return -1;
          }

          M2aAccumulateScaledPcmWindow(
            m2asjd_downmix_buffer,
            M2aGetDecodeStatePcmWindow(decodeState),
            kM2aCenterDownmixScale
          );
        } else if (locationEntry->locationClass == 6) {
          auto* const leftDecodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
          auto* const rightDecodeState = M2aGetSecondaryStateBySlot(context, locationEntry->channelPairType);
          if (!M2aHasReadyPcmWindow(leftDecodeState) || !M2aHasReadyPcmWindow(rightDecodeState)) {
            return -1;
          }

          M2aAccumulatePairedPcmWindow(
            m2asjd_downmix_buffer,
            M2aGetDecodeStatePcmWindow(leftDecodeState),
            M2aGetDecodeStatePcmWindow(rightDecodeState),
            surroundScale
          );
        }

        continue;
      }

      if (locationEntry->channelClass == 0) {
        auto* const decodeState = M2aGetPrimaryStateBySlot(context, locationEntry->channelPairType);
        if (!M2aHasReadyPcmWindow(decodeState)) {
          return -1;
        }

        M2aAccumulateScaledPcmWindow(
          m2asjd_downmix_buffer,
          M2aGetDecodeStatePcmWindow(decodeState),
          kM2aMonoDownmixScale
        );
      }
    }

    m2adec_convert_to_pcm16(m2asjd_downmix_buffer, destinationAddress);
    return 0;
  }

  /**
   * Address: 0x00B23FC0 (_m2adec_malloc)
   *
   * What it does:
   * Allocates one decode helper block from heap-manager lane or process heap.
   */
  HANDLE __cdecl m2adec_malloc(std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    if (heapManagerHandle != 0) {
      HEAPMNG_Allocate(heapManagerHandle, byteCount, &heapManagerHandle);
      return reinterpret_cast<HANDLE>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(heapManagerHandle))
      );
    }

    if (m2adec_global_heap != nullptr) {
      return HeapAlloc(m2adec_global_heap, 8u, byteCount);
    }

    m2adec_global_heap = GetProcessHeap();
    if (m2adec_global_heap != nullptr) {
      return HeapAlloc(m2adec_global_heap, 8u, byteCount);
    }

    return m2adec_global_heap;
  }

  /**
   * Address: 0x00B24010 (_m2adec_free)
   *
   * What it does:
   * Frees one decode helper block through heap-manager lane or process heap.
   */
  HANDLE __cdecl m2adec_free(const std::int32_t heapManagerHandle, LPVOID memoryBlock)
  {
    if (heapManagerHandle != 0) {
      return reinterpret_cast<HANDLE>(HEAPMNG_Free(heapManagerHandle, M2aPtrToWord(memoryBlock)));
    }

    if (m2adec_global_heap != nullptr) {
      return reinterpret_cast<HANDLE>(HeapFree(m2adec_global_heap, 0, memoryBlock));
    }

    m2adec_global_heap = GetProcessHeap();
    if (m2adec_global_heap != nullptr) {
      return reinterpret_cast<HANDLE>(HeapFree(m2adec_global_heap, 0, memoryBlock));
    }

    return m2adec_global_heap;
  }

  /**
   * Address: 0x00B24050 (_m2adec_clear)
   *
   * What it does:
   * Zero-fills one decode helper memory range.
   */
  std::int32_t __cdecl m2adec_clear(void* const destination, const std::uint32_t byteCount)
  {
    std::memset(destination, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B24070 (_m2adec_decode_header)
   *
   * What it does:
   * Identifies ADIF/ADTS header type and prepares per-stream header scratch
   * state.
   */
  std::int32_t __cdecl m2adec_decode_header(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);

    if (contextWords[kM2aContextPendingSupplyIndex] == 1 &&
        contextWords[kM2aContextWindowGroupIndex] != kM2aElementIdEnd) {
      M2ABSR_Seek(
        contextWords[kM2aContextBitstreamHandleIndex],
        contextWords[kM2aContextInputBitRemainderIndex],
        0
      );
      return 0;
    }

    if (contextWords[kM2aContextScratchMappingIndex] == 0) {
      const auto headerScratch = m2adec_malloc(
        contextWords[kM2aContextHeapManagerIndex],
        kM2aScratchMappingBytes
      );
      if (headerScratch == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      m2adec_clear(headerScratch, static_cast<std::uint32_t>(kM2aScratchMappingBytes));
      contextWords[kM2aContextScratchMappingIndex] = M2aPtrToWord(headerScratch);
    }

    const auto headerType = contextWords[kM2aContextHeaderTypeIndex];
    if (headerType == 1) {
      return 0;
    }

    if (headerType == 0) {
      m2adec_get_header_type(
        M2aWordToPtr<std::uint8_t>(contextWords[kM2aContextInputBufferIndex]),
        contextWords[kM2aContextInputByteCountIndex],
        contextWords + kM2aContextHeaderTypeIndex
      );
    }

    if (contextWords[kM2aContextHeaderTypeIndex] == 1) {
      return m2adec_get_adif_info(context);
    }
    if (contextWords[kM2aContextHeaderTypeIndex] == 2) {
      return m2adec_get_adts_info(context);
    }
    return -1;
  }

  /**
   * Address: 0x00B24130 (_m2adec_get_header_type)
   *
   * What it does:
   * Detects ADIF/ADTS header signature from source bytes.
   */
  std::int32_t __cdecl m2adec_get_header_type(
    const std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outHeaderType
  )
  {
    if (sourceLength < 4) {
      *outHeaderType = 0;
      return 0;
    }

    if (sourceBytes[0] == 0xFFu && (sourceBytes[1] == 0xF8u || sourceBytes[1] == 0xF9u)) {
      *outHeaderType = 2;
      return 0;
    }

    if (sourceBytes[0] == 'A' && sourceBytes[1] == 'D' && sourceBytes[2] == 'I' && sourceBytes[3] == 'F') {
      *outHeaderType = 1;
      return 0;
    }

    *outHeaderType = 0;
    return 0;
  }

  /**
   * Address: 0x00B241A0 (_m2adec_get_adif_info)
   *
   * What it does:
   * Parses ADIF stream header lanes and optional PCE payloads.
   */
  std::int32_t __cdecl m2adec_get_adif_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const headerWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);
    std::uint8_t copyIdScratch[4]{};

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], 32, 1);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 0);
    if (headerWords[0] != 0) {
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 8, headerWords + 1);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 32, headerWords + 2);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 32, headerWords + 3);
    }

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 11);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 12);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, headerWords + 4);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 23, headerWords + 5);

    std::int32_t programConfigCountMinusOne = 0;
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      &programConfigCountMinusOne
    );

    const auto programConfigCount = programConfigCountMinusOne + 1;
    if (programConfigCountMinusOne != -1) {
      for (std::int32_t programConfigIndex = 0;
           programConfigIndex < programConfigCount;
           ++programConfigIndex) {
        if (headerWords[4] == 0) {
          M2ABSR_Read(
            contextWords[kM2aContextBitstreamHandleIndex],
            20,
            copyIdScratch
          );
        }
        m2adec_decode_pce(context);
      }
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);
    return 0;
  }

  /**
   * Address: 0x00B242A0 (_m2adec_get_adts_info)
   *
   * What it does:
   * Parses ADTS fixed/variable header lanes and optional CRC lane.
   */
  std::int32_t __cdecl m2adec_get_adts_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    if (contextWords[kM2aContextAdtsRawBlockCountIndex] == 0) {
      auto* const adtsHeaderWords =
        M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);
      const auto status = m2adec_get_adts_fixed_info(context);
      if (status < 0) {
        return status;
      }

      m2adec_get_adts_variable_info(context);
      if (adtsHeaderWords[6] == 0) {
        m2adec_crc_check(context);
      }
    }

    M2ABSR_AlignToByteBoundary(contextWords[kM2aContextBitstreamHandleIndex]);
    return 0;
  }

  /**
   * Address: 0x00B24300 (_m2adec_get_adts_fixed_info)
   *
   * What it does:
   * Parses ADTS fixed header lanes and binds scalefactor-band tables.
   */
  std::int32_t __cdecl m2adec_get_adts_fixed_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const adtsHeaderWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], 15, 1);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 6);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      2,
      contextWords + kM2aContextAudioObjectTypeIndex
    );
    if (contextWords[kM2aContextAudioObjectTypeIndex] != kM2aMainProfile) {
      return -1;
    }

    std::int32_t sampleRateTableIndex = 0;
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      &sampleRateTableIndex
    );
    if (contextWords[kM2aContextSampleRateTableIndex] == 0) {
      contextWords[kM2aContextSampleRateTableIndex] = sampleRateTableIndex;
      contextWords[kM2aContextSampleRateIndex] = m2adec_frequency_table[sampleRateTableIndex];
    } else if (contextWords[kM2aContextSampleRateTableIndex] != sampleRateTableIndex) {
      return -1;
    }

    const auto configuredSampleRateIndex = contextWords[kM2aContextSampleRateTableIndex];
    contextWords[kM2aContextScalefactorBandShortPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb8[64 * configuredSampleRateIndex]);
    contextWords[kM2aContextScalefactorBandLongPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb[256 * configuredSampleRateIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 7);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      3,
      contextWords + kM2aContextChannelConfigurationIndex
    );
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 11);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 12);
    return 0;
  }

  /**
   * Address: 0x00B243F0 (_m2adec_get_adts_variable_info)
   *
   * What it does:
   * Parses ADTS variable header lanes for frame length and block count.
   */
  std::int32_t __cdecl m2adec_get_adts_variable_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const adtsHeaderWords =
      M2aWordToPtr<std::int32_t>(contextWords[kM2aContextScratchMappingIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 8);
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, adtsHeaderWords + 9);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      13,
      contextWords + kM2aContextAdtsFrameLengthIndex
    );
    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 11, adtsHeaderWords + 10);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      2,
      contextWords + kM2aContextAdtsRawBlockCountIndex
    );
    return 0;
  }

  /**
   * Address: 0x00B24450 (_m2adec_crc_check)
   *
   * What it does:
   * Skips ADTS CRC lane when protection field is present.
   */
  std::int32_t __cdecl m2adec_crc_check(M2aDecoderContext* context)
  {
    M2ABSR_Seek(M2aContextWords(context)[kM2aContextBitstreamHandleIndex], 16, 1);
    return 0;
  }

  /**
   * Address: 0x00B24470 (_m2adec_decode_elements)
   *
   * What it does:
   * Dispatches AAC element decode handlers until END tag or decode error.
   */
  std::int32_t __cdecl m2adec_decode_elements(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::int32_t elementStartBit = 0;
    auto status = M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      3,
      contextWords + kM2aContextWindowGroupIndex
    );

    if (status >= 0) {
      while (true) {
        M2ABSR_Tell(contextWords[kM2aContextBitstreamHandleIndex], &elementStartBit);
        elementStartBit -= 3;

        switch (contextWords[kM2aContextWindowGroupIndex]) {
          case 0:
          case 3:
            status = m2adec_decode_sce(context);
            break;
          case 1:
            status = m2adec_decode_cpe(context);
            break;
          case 4:
            status = m2adec_decode_dse(context);
            break;
          case 5:
            status = m2adec_decode_pce(context);
            break;
          case 6:
            status = m2adec_decode_fil(context);
            break;
          case 7:
            break;
          default:
            return -1;
        }

        if (status < 0 || contextWords[kM2aContextWindowGroupIndex] == kM2aElementIdEnd) {
          return status;
        }

        status = M2ABSR_Read(
          contextWords[kM2aContextBitstreamHandleIndex],
          3,
          contextWords + kM2aContextWindowGroupIndex
        );
        if (status < 0) {
          break;
        }
      }
    }

    M2ABSR_Seek(contextWords[kM2aContextBitstreamHandleIndex], elementStartBit, 0);
    return 0;
  }

  /**
   * Address: 0x00B24550 (_m2adec_decode_sce)
   *
   * What it does:
   * Decodes one SCE element and runs ICS payload decode for its state lane.
   */
  std::int32_t __cdecl m2adec_decode_sce(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      contextWords + kM2aContextElementIndex
    );

    const auto groupedStateLaneIndex =
      kM2aContextPrimaryStateBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    if (contextWords[groupedStateLaneIndex] == 0) {
      if (contextWords[kM2aContextFrameCounterIndex] != 0) {
        return -1;
      }

      const auto initStatus = m2adec_decode_sce_initialize(context);
      if (initStatus < 0) {
        return initStatus;
      }
    }

    m2adec_decode_ics(context);
    return 0;
  }

  /**
   * Address: 0x00B245B0 (_m2adec_decode_cpe)
   *
   * What it does:
   * Decodes one CPE element, including common-window/MS flags and twin ICS
   * payload lanes.
   */
  std::int32_t __cdecl m2adec_decode_cpe(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    M2ABSR_Read(
      contextWords[kM2aContextBitstreamHandleIndex],
      4,
      contextWords + kM2aContextElementIndex
    );

    const auto groupedStateLaneIndex =
      kM2aContextPrimaryStateBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    if (contextWords[groupedStateLaneIndex] == 0) {
      if (contextWords[kM2aContextFrameCounterIndex] != 0) {
        return -1;
      }

      const auto initStatus = m2adec_decode_cpe_initialize(context);
      if (initStatus < 0) {
        return initStatus;
      }
    }

    const auto groupedIcsLaneIndex =
      kM2aContextIcsTableBaseIndex +
      contextWords[kM2aContextElementIndex] +
      (32 * contextWords[kM2aContextWindowGroupIndex]);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(contextWords[groupedIcsLaneIndex]);

    M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 1, icsInfo + 0);
    if (icsInfo[0] == 1) {
      m2adec_get_ics_info(context);
      M2ABSR_Read(contextWords[kM2aContextBitstreamHandleIndex], 2, icsInfo + 1);
      if (icsInfo[1] != 0) {
        if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
          m2adec_get_ms_info8(context);
        } else {
          m2adec_get_ms_info(context);
        }
      }
    } else {
      icsInfo[1] = 0;
    }

    m2adec_decode_ics(context);
    contextWords[kM2aContextElementIndex] += 16;
    m2adec_decode_ics(context);
    return 0;
  }

  /**
   * Address: 0x00B25FB0 (_m2adec_inverse_transform)
   *
   * What it does:
   * Runs one M2A IMDCT inverse-transform lane and overlap-adds into current
   * PCM output window.
   */
  std::int32_t m2adec_inverse_transform(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    const auto overlapBufferIndex = decodeState[3640];

    void* const previousWindow =
      M2AIMDCT_GetWindow(icsInfo[kM2aIcsWindowSequenceIndex], decodeState[543]);
    void* const currentWindow =
      M2AIMDCT_GetWindow(icsInfo[kM2aIcsWindowSequenceIndex], icsInfo[kM2aIcsWindowShapeIndex]);

    auto* const spectralCoefficients = reinterpret_cast<float*>(decodeState + 2592);
    auto* const overlapBuffer = reinterpret_cast<float*>(decodeState + (2048 * overlapBufferIndex) + 3641);

    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      M2AIMDCT_TransformShort(spectralCoefficients, previousWindow, currentWindow, overlapBuffer);
    } else {
      M2AIMDCT_TransformLong(spectralCoefficients, previousWindow, currentWindow, overlapBuffer);
    }

    const auto historyOffsetA = static_cast<std::ptrdiff_t>(0x68E4 - (overlapBufferIndex << 13));
    const auto historyOffsetB = static_cast<std::ptrdiff_t>(0x38E4 + (overlapBufferIndex << 13));
    auto* const historyLaneA =
      reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + historyOffsetA);
    auto* const historyLaneB =
      reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + historyOffsetB);
    auto* const outputWindow = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + 0x78E4);

    for (std::int32_t sampleIndex = 0; sampleIndex < 1024; ++sampleIndex) {
      outputWindow[sampleIndex] = historyLaneA[sampleIndex] + historyLaneB[sampleIndex];
    }

    decodeState[3640] = 1 - overlapBufferIndex;
    decodeState[542] = icsInfo[kM2aIcsWindowSequenceIndex];
    decodeState[543] = icsInfo[kM2aIcsWindowShapeIndex];

    if (decodeState[8761] < 2048) {
      decodeState[8761] += 1024;
    } else {
      decodeState[8762] += 1024;
    }

    return 0;
  }

  /**
   * Address: 0x00B260E0 (_m2adec_get_pulse_data)
   *
   * What it does:
   * Reads AAC pulse-data lanes for current M2A decode state.
   */
  std::int32_t m2adec_get_pulse_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    M2ABSR_Read(context->bitstreamHandle, 2, &decodeState[243]);
    M2ABSR_Read(context->bitstreamHandle, 6, &decodeState[244]);

    for (std::uint32_t pulseIndex = 0; pulseIndex <= static_cast<std::uint32_t>(decodeState[243]); ++pulseIndex) {
      M2ABSR_Read(context->bitstreamHandle, 5, &decodeState[245 + pulseIndex]);
      M2ABSR_Read(context->bitstreamHandle, 4, &decodeState[249 + pulseIndex]);
    }

    return 0;
  }

  /**
   * Address: 0x00B26160 (_m2adec_pulse_proc)
   *
   * What it does:
   * Applies pulse-data offsets to current spectral coefficient lanes.
   */
  std::int32_t m2adec_pulse_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    std::int32_t spectralOffset = 0;

    for (std::int32_t bandIndex = 0; bandIndex < decodeState[244]; ++bandIndex) {
      spectralOffset += context->scalefactorBandWidthsLong[bandIndex];
    }

    for (std::uint32_t pulseIndex = 0; pulseIndex <= static_cast<std::uint32_t>(decodeState[243]); ++pulseIndex) {
      const auto pulseAmplitude = decodeState[249 + pulseIndex];
      spectralOffset += decodeState[245 + pulseIndex];

      auto& spectralCoefficient = decodeState[544 + spectralOffset];
      if (spectralCoefficient <= 0) {
        spectralCoefficient -= pulseAmplitude;
      } else {
        spectralCoefficient += pulseAmplitude;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B261E0 (_m2adec_get_tns_data)
   *
   * What it does:
   * Reads TNS metadata for long-window M2A lane and builds filter
   * coefficients.
   */
  std::int32_t m2adec_get_tns_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    M2ABSR_Read(context->bitstreamHandle, 2, &decodeState[254]);
    if (decodeState[254] == 0) {
      return 0;
    }

    std::int32_t coefficientResolution = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &coefficientResolution);

    for (std::int32_t filterIndex = 0; filterIndex < decodeState[254]; ++filterIndex) {
      M2ABSR_Read(context->bitstreamHandle, 6, &decodeState[262 + filterIndex]);
      M2ABSR_Read(context->bitstreamHandle, 5, &decodeState[270 + filterIndex]);

      auto& filterOrder = decodeState[270 + filterIndex];
      if (filterOrder == 0) {
        return 0;
      }
      if (filterOrder > 20) {
        filterOrder = 20;
      }

      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[278 + filterIndex]);

      std::int32_t coefficientCompression = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientCompression);

      float decodedCoefficients[kM2aTnsCoefficientLaneCount]{};
      for (std::int32_t coefficientIndex = 0; coefficientIndex < filterOrder; ++coefficientIndex) {
        std::int32_t coefficientCode = 0;
        M2ABSR_Read(
          context->bitstreamHandle,
          coefficientResolution - coefficientCompression + 3,
          &coefficientCode
        );

        const auto decodeTableIndex =
          (32 * coefficientResolution) + (16 * coefficientCompression) + coefficientCode;
        decodedCoefficients[coefficientIndex] = m2adec_tns_decode_table[decodeTableIndex];
      }

      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (filterIndex * kM2aTnsCoefficientLaneCount));
      M2aBuildTnsFilterCoefficients(filterCoefficients, decodedCoefficients, filterOrder);
    }

    return 0;
  }

  /**
   * Address: 0x00B263D0 (_m2adec_get_tns_data8)
   *
   * What it does:
   * Reads TNS metadata for short-window M2A lane and builds per-window filter
   * coefficients.
   */
  std::int32_t m2adec_get_tns_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[254 + windowIndex]);
      if (decodeState[254 + windowIndex] == 0) {
        continue;
      }

      std::int32_t coefficientResolution = 0;
      std::int32_t coefficientCompression = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientResolution);
      M2ABSR_Read(context->bitstreamHandle, 4, &decodeState[262 + windowIndex]);
      M2ABSR_Read(context->bitstreamHandle, 3, &decodeState[270 + windowIndex]);

      auto& filterOrder = decodeState[270 + windowIndex];
      if (filterOrder == 0) {
        continue;
      }
      if (filterOrder > 12) {
        filterOrder = 12;
      }

      M2ABSR_Read(context->bitstreamHandle, 1, &decodeState[278 + windowIndex]);
      M2ABSR_Read(context->bitstreamHandle, 1, &coefficientCompression);

      float decodedCoefficients[kM2aTnsCoefficientLaneCount]{};
      for (std::int32_t coefficientIndex = 0; coefficientIndex < filterOrder; ++coefficientIndex) {
        std::int32_t coefficientCode = 0;
        M2ABSR_Read(
          context->bitstreamHandle,
          coefficientResolution - coefficientCompression + 3,
          &coefficientCode
        );

        const auto decodeTableIndex =
          (32 * coefficientResolution) + (16 * coefficientCompression) + coefficientCode;
        decodedCoefficients[coefficientIndex] = m2adec_tns_decode_table[decodeTableIndex];
      }

      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (windowIndex * kM2aTnsCoefficientLaneCount));
      M2aBuildTnsFilterCoefficients(filterCoefficients, decodedCoefficients, filterOrder);
    }

    return 0;
  }

  /**
   * Address: 0x00B265F0 (_m2adec_tns_filter_proc)
   *
   * What it does:
   * Applies long-window TNS filter lanes to spectral coefficients.
   */
  std::int32_t m2adec_tns_filter_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    std::int32_t upperBand = kM2aMaxBandsLong;

    for (std::int32_t filterIndex = 0; filterIndex < decodeState[254]; ++filterIndex) {
      auto lowerBand = upperBand - decodeState[262 + filterIndex];
      const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

      if (lowerBand >= maxSfb) {
        lowerBand = maxSfb;
      }

      auto upperBandClamped = upperBand;
      if (upperBandClamped >= maxSfb) {
        upperBandClamped = maxSfb;
      }

      if (lowerBand < upperBandClamped) {
        const auto startLine = M2aSumScalefactorBandWidths(context->scalefactorBandWidthsLong, 0, lowerBand);
        const auto endLine =
          startLine + M2aSumScalefactorBandWidths(context->scalefactorBandWidthsLong, lowerBand, upperBandClamped);
        const auto lineCount = endLine - startLine;

        auto* const spectralCoefficients = reinterpret_cast<float*>(decodeState + 2592 + startLine);
        auto* const filterCoefficients =
          reinterpret_cast<float*>(decodeState + 286 + (filterIndex * kM2aTnsCoefficientLaneCount));
        const auto filterOrder = decodeState[270 + filterIndex];
        const auto reverseDirection = decodeState[278 + filterIndex] != 0;

        M2aApplyTnsFilter(spectralCoefficients, lineCount, filterCoefficients, filterOrder, reverseDirection);
      }

      upperBand = lowerBand;
    }

    return 0;
  }

  /**
   * Address: 0x00B267B0 (_m2adec_tns_filter_proc8)
   *
   * What it does:
   * Applies short-window TNS filter lanes to spectral coefficients.
   */
  std::int32_t m2adec_tns_filter_proc8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      if (decodeState[254 + windowIndex] == 0) {
        continue;
      }

      auto lowerBand = kM2aMaxBandsShort - decodeState[262 + windowIndex];
      if (lowerBand >= maxSfb) {
        lowerBand = maxSfb;
      }

      auto upperBand = kM2aMaxBandsShort;
      if (upperBand > maxSfb) {
        upperBand = maxSfb;
      }

      if (lowerBand >= upperBand) {
        continue;
      }

      const auto startLine = M2aSumScalefactorBandWidths(context->scalefactorBandWidthsShort, 0, lowerBand);
      const auto endLine =
        startLine + M2aSumScalefactorBandWidths(context->scalefactorBandWidthsShort, lowerBand, upperBand);
      const auto lineCount = endLine - startLine;

      auto* const windowSpectralBase = reinterpret_cast<float*>(static_cast<std::intptr_t>(decodeState[3632 + windowIndex]));
      auto* const spectralCoefficients = windowSpectralBase + startLine;
      auto* const filterCoefficients =
        reinterpret_cast<float*>(decodeState + 286 + (windowIndex * kM2aTnsCoefficientLaneCount));
      const auto filterOrder = decodeState[270 + windowIndex];
      const auto reverseDirection = decodeState[278 + windowIndex] != 0;

      M2aApplyTnsFilter(spectralCoefficients, lineCount, filterCoefficients, filterOrder, reverseDirection);
    }

    return 0;
  }

  /**
   * Address: 0x00B265A0 (_m2adec_tns_proc)
   *
   * What it does:
   * Dispatches TNS filter path for long/short-window decode lanes.
   */
  std::int32_t m2adec_tns_proc(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    if (decodeState[253] != 1) {
      return 0;
    }

    auto* const icsInfo = reinterpret_cast<std::int32_t*>(decodeState[0]);
    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_tns_filter_proc8(context);
    } else {
      m2adec_tns_filter_proc(context);
    }

    return 0;
  }

  /**
   * Address: 0x00B26950 (_m2adec_get_ms_info)
   *
   * What it does:
   * Reads M/S stereo flags for long-window decode lanes.
   */
  std::int32_t m2adec_get_ms_info(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    const auto msMaskMode = icsInfo[1];
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    if (msMaskMode == 0) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        icsInfo[2 + band] = 0;
      }
      return 0;
    }

    if (msMaskMode == 1) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        M2ABSR_Read(context->bitstreamHandle, 1, &icsInfo[2 + band]);
      }
      return 0;
    }

    if (msMaskMode == 2) {
      for (std::int32_t band = 0; band < maxSfb; ++band) {
        icsInfo[2 + band] = 1;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26A10 (_m2adec_get_ms_info8)
   *
   * What it does:
   * Reads M/S stereo flags for short-window decode lanes.
   */
  std::int32_t m2adec_get_ms_info8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto** const shortWindowMaskLanes = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const maskLane = shortWindowMaskLanes[windowIndex];
      if (icsInfo[124 + windowIndex] == 1) {
        m2adec_copy(maskLane, shortWindowMaskLanes[windowIndex - 1], static_cast<std::size_t>(maxSfb) * sizeof(std::int32_t));
        continue;
      }

      const auto msMaskMode = icsInfo[1];
      if (msMaskMode == 0) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          maskLane[band] = 0;
        }
      } else if (msMaskMode == 1) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          M2ABSR_Read(context->bitstreamHandle, 1, &maskLane[band]);
        }
      } else if (msMaskMode == 2) {
        for (std::int32_t band = 0; band < maxSfb; ++band) {
          maskLane[band] = 1;
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26B50 (_m2adec_ms_convert)
   *
   * What it does:
   * Applies long-window M/S stereo conversion to spectral coefficients.
   */
  std::int32_t m2adec_ms_convert(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);

    auto* primarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x2880);
    auto* secondarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x2880);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t band = 0; band < maxSfb; ++band) {
      const auto bandWidth = context->scalefactorBandWidthsLong[band];
      const auto sectionCodebook = secondaryState[2 + band];

      if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
        return -1;
      }

      if (sectionCodebook != 0xE && sectionCodebook != 0xF && icsInfo[2 + band] == 1 && bandWidth > 0) {
        for (std::int32_t line = 0; line < bandWidth; ++line) {
          const auto leftValue = primarySpectral[line];
          const auto rightValue = secondarySpectral[line];
          primarySpectral[line] = leftValue + rightValue;
          secondarySpectral[line] = leftValue - rightValue;
        }
      }

      primarySpectral += bandWidth;
      secondarySpectral += bandWidth;
    }

    return 0;
  }

  /**
   * Address: 0x00B26C60 (_m2adec_ms_convert8)
   *
   * What it does:
   * Applies short-window M/S stereo conversion to spectral coefficients.
   */
  std::int32_t m2adec_ms_convert8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto** const primaryWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x38C0);
    auto** const secondaryWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x38C0);
    auto** const sectionCodebooksByWindow = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x388);
    auto** const msMaskLanesByWindow = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* primarySpectral = primaryWindowSpectralLanes[windowIndex];
      auto* secondarySpectral = secondaryWindowSpectralLanes[windowIndex];
      auto* const sectionCodebookLane = sectionCodebooksByWindow[windowIndex];
      auto* const msMaskLane = msMaskLanesByWindow[windowIndex];

      for (std::int32_t band = 0; band < maxSfb; ++band) {
        const auto bandWidth = context->scalefactorBandWidthsShort[band];
        const auto sectionCodebook = sectionCodebookLane[band];

        if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
          return -1;
        }

        if (sectionCodebook != 0xE && sectionCodebook != 0xF && msMaskLane[band] == 1 && bandWidth > 0) {
          for (std::int32_t line = 0; line < bandWidth; ++line) {
            const auto leftValue = primarySpectral[line];
            const auto rightValue = secondarySpectral[line];
            primarySpectral[line] = leftValue + rightValue;
            secondarySpectral[line] = leftValue - rightValue;
          }
        }

        primarySpectral += bandWidth;
        secondarySpectral += bandWidth;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26B00 (_m2adec_ms_proc)
   *
   * What it does:
   * Dispatches M/S stereo conversion path for long/short-window decode lanes.
   */
  std::int32_t m2adec_ms_proc(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    if (icsInfo[0] == 0 || icsInfo[1] == 0) {
      return 0;
    }

    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_ms_convert8(context);
    } else {
      m2adec_ms_convert(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B26DD0 (_m2adec_intensity_convert)
   *
   * What it does:
   * Applies long-window AAC intensity stereo conversion to spectral
   * coefficients.
   */
  std::int32_t m2adec_intensity_convert(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto* primarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x2880);
    auto* secondarySpectral = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x2880);
    const auto* const intensityScaleLane = icsInfo + kM2aIcsIntensityScaleBaseIndex;
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t band = 0; band < maxSfb; ++band) {
      const auto bandWidth = context->scalefactorBandWidthsLong[band];
      const auto sectionCodebook = secondaryState[2 + band];

      if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
        return -1;
      }

      if (sectionCodebook == 0xE || sectionCodebook == 0xF) {
        double intensityFactor =
          std::pow(kM2aIntensityPowBase, static_cast<double>(intensityScaleLane[band]) * kM2aIntensityPowScale);

        if (icsInfo[1] == 1) {
          intensityFactor *= (1.0 - (2.0 * static_cast<double>(icsInfo[2 + band])));
        }
        if (sectionCodebook == 0xE) {
          intensityFactor *= -1.0;
        }

        for (std::int32_t line = 0; line < bandWidth; ++line) {
          secondarySpectral[line] = static_cast<float>(intensityFactor * static_cast<double>(primarySpectral[line]));
        }
      }

      primarySpectral += bandWidth;
      secondarySpectral += bandWidth;
    }

    return 0;
  }

  /**
   * Address: 0x00B26FB0 (_m2adec_intensity_convert8)
   *
   * What it does:
   * Applies short-window AAC intensity stereo conversion to spectral
   * coefficients.
   */
  std::int32_t m2adec_intensity_convert8(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    auto* const primaryState = M2aGetPrimaryStateLane(context);
    auto* const secondaryState = M2aGetSecondaryStateLane(context);
    auto** const sourceWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(primaryState) + 0x38C0);
    auto** const destinationWindowSpectralLanes = reinterpret_cast<float**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x38C0);
    auto** const sectionCodebookLanes = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x388);
    auto** const intensityScaleLanes = reinterpret_cast<std::int32_t**>(reinterpret_cast<std::uint8_t*>(secondaryState) + 0x3A8);
    auto** const signLanes = reinterpret_cast<std::int32_t**>(icsInfo + 114);
    const auto maxSfb = icsInfo[kM2aIcsMaxSfbIndex];

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* sourceSpectral = sourceWindowSpectralLanes[windowIndex];
      auto* destinationSpectral = destinationWindowSpectralLanes[windowIndex];
      auto* const sectionCodebookLane = sectionCodebookLanes[windowIndex];
      auto* const intensityScaleLane = intensityScaleLanes[windowIndex];
      auto* const signLane = signLanes[windowIndex];

      for (std::int32_t band = 0; band < maxSfb; ++band) {
        const auto bandWidth = context->scalefactorBandWidthsShort[band];
        const auto sectionCodebook = sectionCodebookLane[band];

        if (sectionCodebook == 0xC || sectionCodebook == 0xD) {
          return -1;
        }

        if (sectionCodebook == 0xE || sectionCodebook == 0xF) {
          double intensityFactor =
            std::pow(kM2aIntensityPowBase, static_cast<double>(intensityScaleLane[band]) * kM2aIntensityPowScale);

          if (icsInfo[1] == 1) {
            intensityFactor *= (1.0 - (2.0 * static_cast<double>(signLane[band])));
          }
          if (sectionCodebook == 0xE) {
            intensityFactor *= -1.0;
          }

          for (std::int32_t line = 0; line < bandWidth; ++line) {
            destinationSpectral[line] =
              static_cast<float>(intensityFactor * static_cast<double>(sourceSpectral[line]));
          }
        }

        sourceSpectral += bandWidth;
        destinationSpectral += bandWidth;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B26D90 (_m2adec_intensity_proc)
   *
   * What it does:
   * Dispatches intensity stereo conversion path for long/short-window decode
   * lanes.
   */
  std::int32_t m2adec_intensity_proc(M2aDecoderContext* context)
  {
    auto* const icsInfo = M2aGetIcsInfoLane(context);
    if (icsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_intensity_convert8(context);
    } else {
      m2adec_intensity_convert(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B271E0 (_m2adec_specify_location_from_pce)
   *
   * What it does:
   * Assigns per-entry channel location classes using active PCE map lanes.
   */
  std::int32_t m2adec_specify_location_from_pce(M2aDecoderContext* context)
  {
    auto* channelMapLane = reinterpret_cast<std::int32_t*>(context->pceMap);
    auto* frontPairLane = channelMapLane + 1;
    auto* pairLaneA = channelMapLane + 34;
    auto* pairLaneB = channelMapLane + 67;

    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0) {
        if (*frontPairLane != 0) {
          if (*pairLaneA == 0) {
            locationEntry->locationClass = 3;
            ++pairLaneA;
            ++context->locationCountClass3;
          } else if (*pairLaneB == 0) {
            locationEntry->locationClass = 5;
            ++pairLaneB;
            ++context->locationCountClass5;
          } else {
            locationEntry->locationClass = 1;
            ++context->locationCountClass0;
          }
        } else {
          locationEntry->locationClass = 1;
          ++context->locationCountClass0;
          ++frontPairLane;
        }
        continue;
      }

      if (channelClass == 1) {
        if (*frontPairLane == 1) {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
          ++frontPairLane;
        } else if (*pairLaneA == 1) {
          locationEntry->locationClass = 4;
          ++pairLaneA;
          ++context->locationCountClass4;
        } else if (*pairLaneB == 1) {
          locationEntry->locationClass = 6;
          ++pairLaneB;
          ++context->locationCountClass6;
        } else {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
          ++frontPairLane;
        }
        continue;
      }

      if (channelClass == 3) {
        locationEntry->locationClass = 7;
        ++context->locationCountClass7;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B27300 (_m2adec_infer_location)
   *
   * What it does:
   * Assigns per-entry channel location classes without PCE map, using
   * alternating class counters.
   */
  std::int32_t m2adec_infer_location(M2aDecoderContext* context)
  {
    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = context->channelPairLocationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0) {
        if ((context->locationCountClass0 & 1) != 0) {
          locationEntry->locationClass = 5;
          ++context->locationCountClass5;
        } else {
          locationEntry->locationClass = 1;
          ++context->locationCountClass0;
        }
      } else if (channelClass == 1) {
        if ((context->locationCountClass1 & 1) != 0) {
          locationEntry->locationClass = 6;
          ++context->locationCountClass6;
        } else {
          locationEntry->locationClass = 2;
          ++context->locationCountClass1;
        }
      } else if (channelClass == 3) {
        locationEntry->locationClass = 7;
        ++context->locationCountClass7;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B271B0 (_m2adec_specify_location)
   *
   * What it does:
   * Selects PCE-driven or inferred location assignment for channel entries.
   */
  std::int32_t m2adec_specify_location(M2aDecoderContext* context)
  {
    if (context->pceMap != nullptr) {
      m2adec_specify_location_from_pce(context);
    } else {
      m2adec_infer_location(context);
    }
    return 0;
  }

  /**
   * Address: 0x00B273A0 (_m2adec_get_extension_payload)
   *
   * What it does:
   * Advances extension payload bits on current bitstream lane.
   */
  std::int32_t m2adec_get_extension_payload(M2aDecoderContext* context, const std::int32_t payloadWordCount)
  {
    std::int32_t bitPosition = 0;
    M2ABSR_Tell(context->bitstreamHandle, &bitPosition);

    const auto payloadEndBit = bitPosition + (8 * payloadWordCount);
    while (bitPosition < payloadEndBit) {
      std::uint8_t discardBytes[4]{};
      M2ABSR_Read(context->bitstreamHandle, 4, discardBytes);
      M2ABSR_Seek(context->bitstreamHandle, payloadEndBit, 0);
      M2ABSR_Tell(context->bitstreamHandle, &bitPosition);
    }

    return 0;
  }

  /**
   * Address: 0x00B255A0 (_m2adec_copy)
   *
   * What it does:
   * Copies one M2A runtime buffer lane and returns copied byte count.
   */
  std::uint32_t m2adec_copy(void* const destination, const void* const source, const std::size_t byteCount)
  {
    std::memcpy(destination, source, byteCount);
    return static_cast<std::uint32_t>(byteCount);
  }

  /**
   * Address: 0x00B24690 (_m2adec_decode_dse)
   *
   * What it does:
   * Parses one DSE element payload and advances bitstream cursor by payload
   * size (with optional byte-align).
   */
  std::int32_t m2adec_decode_dse(M2aDecoderContext* context)
  {
    std::uint8_t elementTag = 0;
    std::int32_t alignFlag = 0;
    std::int32_t payloadByteCount = 0;
    std::int32_t extendedByteCount = 0;

    M2ABSR_Read(context->bitstreamHandle, 4, &elementTag);
    M2ABSR_Read(context->bitstreamHandle, 1, &alignFlag);
    M2ABSR_Read(context->bitstreamHandle, 8, &payloadByteCount);
    if (payloadByteCount == 255) {
      M2ABSR_Read(context->bitstreamHandle, 8, &extendedByteCount);
      payloadByteCount += extendedByteCount;
    }

    if (alignFlag == 1) {
      M2ABSR_AlignToByteBoundary(context->bitstreamHandle);
    }

    M2ABSR_Seek(context->bitstreamHandle, 8 * payloadByteCount, 1);
    return 0;
  }

  /**
   * Address: 0x00B24730 (_m2adec_decode_pce)
   *
   * What it does:
   * Parses one PCE element, updates sample-rate/scalefactor tables, and
   * validates discovered channel layout count.
   */
  std::int32_t m2adec_decode_pce(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::uint8_t elementTag = 0;

    M2ABSR_Read(context->bitstreamHandle, 4, &elementTag);

    auto* pceMapWords = static_cast<std::int32_t*>(context->pceMap);
    if (pceMapWords == nullptr) {
      pceMapWords = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), 0x2B8u));
      if (pceMapWords == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      m2adec_clear(pceMapWords, 0x2B8u);
      context->pceMap = pceMapWords;
      contextWords[kM2aContextPceMapIndex] = M2aPtrToWord(pceMapWords);
    }

    M2ABSR_Read(context->bitstreamHandle, 2, contextWords + kM2aContextAudioObjectTypeIndex);

    std::int32_t sampleRateTableIndex = 0;
    M2ABSR_Read(context->bitstreamHandle, 4, &sampleRateTableIndex);

    if (contextWords[kM2aContextSampleRateTableIndex] != 0) {
      if (contextWords[kM2aContextSampleRateTableIndex] != sampleRateTableIndex) {
        return -1;
      }
    } else {
      contextWords[kM2aContextSampleRateTableIndex] = sampleRateTableIndex;
      contextWords[kM2aContextSampleRateIndex] = m2adec_frequency_table[sampleRateTableIndex];
    }

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 0);
    std::int32_t totalChannelCount = pceMapWords[0];

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 33);
    totalChannelCount += pceMapWords[33];

    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 66);
    totalChannelCount += pceMapWords[66];

    M2ABSR_Read(context->bitstreamHandle, 2, pceMapWords + 99);
    totalChannelCount += pceMapWords[99];

    M2ABSR_Read(context->bitstreamHandle, 3, pceMapWords + 116);
    M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 133);

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 166);
    if (pceMapWords[166] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 167);
    } else {
      pceMapWords[167] = 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 168);
    if (pceMapWords[168] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 169);
    } else {
      pceMapWords[169] = 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 170);
    if (pceMapWords[170] == 1) {
      M2ABSR_Read(context->bitstreamHandle, 2, pceMapWords + 171);
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 172);
    } else {
      pceMapWords[171] = 0;
      pceMapWords[172] = 0;
    }

    for (std::int32_t frontIndex = 0; frontIndex < pceMapWords[0]; ++frontIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 1 + frontIndex);
      totalChannelCount += pceMapWords[1 + frontIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 17 + frontIndex);
    }

    for (std::int32_t sideIndex = 0; sideIndex < pceMapWords[33]; ++sideIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 34 + sideIndex);
      totalChannelCount += pceMapWords[34 + sideIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 50 + sideIndex);
    }

    for (std::int32_t backIndex = 0; backIndex < pceMapWords[66]; ++backIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 67 + backIndex);
      totalChannelCount += pceMapWords[67 + backIndex];
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 83 + backIndex);
    }

    for (std::int32_t lfeIndex = 0; lfeIndex < pceMapWords[99]; ++lfeIndex) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 100 + lfeIndex);
    }

    for (std::int32_t assocDataIndex = 0; assocDataIndex < pceMapWords[116]; ++assocDataIndex) {
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 117 + assocDataIndex);
    }

    for (std::int32_t ccIndex = 0; ccIndex < pceMapWords[133]; ++ccIndex) {
      M2ABSR_Read(context->bitstreamHandle, 1, pceMapWords + 134 + ccIndex);
      M2ABSR_Read(context->bitstreamHandle, 4, pceMapWords + 150 + ccIndex);
    }

    M2ABSR_AlignToByteBoundary(context->bitstreamHandle);

    M2ABSR_Read(context->bitstreamHandle, 8, pceMapWords + 173);
    M2ABSR_Seek(context->bitstreamHandle, 8 * pceMapWords[173], 1);

    const auto configuredSampleRateIndex = contextWords[kM2aContextSampleRateTableIndex];
    contextWords[kM2aContextScalefactorBandShortPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb8[64 * configuredSampleRateIndex]);
    contextWords[kM2aContextScalefactorBandLongPtrIndex] =
      M2aPtrToWord(&m2adec_num_spectra_per_sfb[256 * configuredSampleRateIndex]);

    if (contextWords[kM2aContextDecodeCountInitializedIndex] == 0) {
      contextWords[kM2aContextDecodedChannelCountIndex] = totalChannelCount;
      contextWords[kM2aContextDecodeCountInitializedIndex] = 1;
      return 0;
    }

    return contextWords[kM2aContextDecodedChannelCountIndex] == totalChannelCount ? 0 : -1;
  }

  /**
   * Address: 0x00B24B70 (_m2adec_decode_fil)
   *
   * What it does:
   * Parses FIL payload length and delegates extension payload skipping/parsing.
   */
  std::int32_t m2adec_decode_fil(M2aDecoderContext* context)
  {
    std::int32_t payloadWordCount = 0;
    M2ABSR_Read(context->bitstreamHandle, 4, &payloadWordCount);
    if (payloadWordCount == 15) {
      std::int32_t extraWordCount = 0;
      M2ABSR_Read(context->bitstreamHandle, 8, &extraWordCount);
      payloadWordCount = payloadWordCount + extraWordCount - 1;
    }

    m2adec_get_extension_payload(context, payloadWordCount);
    return 0;
  }

  /**
   * Address: 0x00B24BD0 (_m2adec_decode_sce_initialize)
   *
   * What it does:
   * Ensures SCE location entry + ICS/decode-state lanes exist and resets them
   * for one decode pass.
   */
  std::int32_t m2adec_decode_sce_initialize(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto locationEntryCount = contextWords[kM2aContextLocationEntryCountIndex];
    const auto activeElementIndex = contextWords[kM2aContextElementIndex];
    const auto activeWindowGroupIndex = contextWords[kM2aContextWindowGroupIndex];

    if (locationEntryCount == 0) {
      auto* const contextBytes = reinterpret_cast<std::uint8_t*>(context);
      const auto baseChannelPairTag = static_cast<std::uint8_t>(2 * (activeElementIndex + (16 * activeWindowGroupIndex)));
      contextBytes[72] = baseChannelPairTag;
      contextBytes[73] = static_cast<std::uint8_t>(baseChannelPairTag + 1);
    }

    auto* locationEntry = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextLocationAllocBaseIndex + locationEntryCount]);
    if (locationEntry == nullptr) {
      locationEntry = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aLocationEntrySize));
      if (locationEntry == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      const auto currentCount = contextWords[kM2aContextLocationEntryCountIndex];
      contextWords[kM2aContextLocationAllocBaseIndex + currentCount] = M2aPtrToWord(locationEntry);
      contextWords[kM2aContextLocationEntryCountIndex] = currentCount + 1;
    }

    m2adec_clear(locationEntry, kM2aLocationEntrySize);
    locationEntry[0] = activeElementIndex;
    locationEntry[1] = activeWindowGroupIndex;

    const auto slotIndex = M2aGetCurrentSlotIndex(context);

    auto* icsInfoLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
    if (icsInfoLane == nullptr) {
      icsInfoLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (icsInfoLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      contextWords[kM2aContextIcsTableBaseIndex + slotIndex] = M2aPtrToWord(icsInfoLane);
    }

    m2adec_clear(icsInfoLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(icsInfoLane);

    auto* decodeStateLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    if (decodeStateLane == nullptr) {
      decodeStateLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (decodeStateLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex] = M2aPtrToWord(decodeStateLane);
    }

    m2adec_clear(decodeStateLane, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(decodeStateLane);
    return 0;
  }

  /**
   * Address: 0x00B24D40 (_m2adec_decode_cpe_initialize)
   *
   * What it does:
   * Ensures CPE location entry + dual ICS/decode-state lanes exist and resets
   * them for one decode pass.
   */
  std::int32_t m2adec_decode_cpe_initialize(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto locationEntryCount = contextWords[kM2aContextLocationEntryCountIndex];
    const auto activeElementIndex = contextWords[kM2aContextElementIndex];
    const auto activeWindowGroupIndex = contextWords[kM2aContextWindowGroupIndex];

    if (locationEntryCount == 0) {
      auto* const contextBytes = reinterpret_cast<std::uint8_t*>(context);
      const auto baseChannelPairTag = static_cast<std::uint8_t>(2 * (activeElementIndex + (16 * activeWindowGroupIndex)));
      contextBytes[72] = baseChannelPairTag;
      contextBytes[73] = static_cast<std::uint8_t>(baseChannelPairTag + 1);
    }

    auto* locationEntry = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextLocationAllocBaseIndex + locationEntryCount]);
    if (locationEntry == nullptr) {
      locationEntry = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aLocationEntrySize));
      if (locationEntry == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }

      const auto currentCount = contextWords[kM2aContextLocationEntryCountIndex];
      contextWords[kM2aContextLocationAllocBaseIndex + currentCount] = M2aPtrToWord(locationEntry);
      contextWords[kM2aContextLocationEntryCountIndex] = currentCount + 1;
    }

    m2adec_clear(locationEntry, kM2aLocationEntrySize);
    locationEntry[0] = activeElementIndex;
    locationEntry[1] = activeWindowGroupIndex;

    const auto slotIndex = M2aGetCurrentSlotIndex(context);

    auto* primaryIcsLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
    if (primaryIcsLane == nullptr) {
      primaryIcsLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (primaryIcsLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextIcsTableBaseIndex + slotIndex] = M2aPtrToWord(primaryIcsLane);
    }

    m2adec_clear(primaryIcsLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(primaryIcsLane);

    auto* secondaryIcsLane = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextSecondaryIcsTableBaseIndex + slotIndex]);
    if (secondaryIcsLane == nullptr) {
      secondaryIcsLane = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aIcsInfoSize));
      if (secondaryIcsLane == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextSecondaryIcsTableBaseIndex + slotIndex] = M2aPtrToWord(secondaryIcsLane);
    }

    m2adec_clear(secondaryIcsLane, kM2aIcsInfoSize);
    M2aInitializeIcsWindowPointers(secondaryIcsLane);

    auto* primaryDecodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    if (primaryDecodeState == nullptr) {
      primaryDecodeState = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (primaryDecodeState == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex] = M2aPtrToWord(primaryDecodeState);
    }

    m2adec_clear(primaryDecodeState, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(primaryDecodeState);

    auto* secondaryDecodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextSecondaryStateBaseIndex + slotIndex]);
    if (secondaryDecodeState == nullptr) {
      secondaryDecodeState = static_cast<std::int32_t*>(M2aAllocFromHeap(M2aGetHeapManagerHandle(context), kM2aDecodeStateSize));
      if (secondaryDecodeState == nullptr) {
        contextWords[kM2aContextStatusIndex] = 3;
        contextWords[kM2aContextErrorCodeIndex] = 1;
        return -1;
      }
      contextWords[kM2aContextSecondaryStateBaseIndex + slotIndex] = M2aPtrToWord(secondaryDecodeState);
    }

    m2adec_clear(secondaryDecodeState, kM2aDecodeStateSize);
    M2aInitializeDecodeStateWindowPointers(secondaryDecodeState);
    return 0;
  }

  /**
   * Address: 0x00B25030 (_m2adec_get_ics_info)
   *
   * What it does:
   * Reads ICS window metadata, window groups, and predictor bits for current
   * channel lane.
   */
  std::int32_t m2adec_get_ics_info(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const icsInfoLane = M2aGetIcsInfoLane(context);

    M2ABSR_Seek(context->bitstreamHandle, 1, 1);
    M2ABSR_Read(context->bitstreamHandle, 2, icsInfoLane + kM2aIcsWindowSequenceIndex);
    M2ABSR_Read(context->bitstreamHandle, 1, icsInfoLane + kM2aIcsWindowShapeIndex);

    auto& maxSfb = icsInfoLane[kM2aIcsMaxSfbIndex];
    if (icsInfoLane[kM2aIcsWindowSequenceIndex] == 2) {
      M2ABSR_Read(context->bitstreamHandle, 4, &maxSfb);
      if (maxSfb > kM2aMaxBandsShort) {
        maxSfb = kM2aMaxBandsShort;
      }

      icsInfoLane[124] = 0;
      for (std::int32_t windowIndex = 0; windowIndex < 7; ++windowIndex) {
        M2ABSR_Read(context->bitstreamHandle, 1, icsInfoLane + 125 + windowIndex);
      }

      for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; windowIndex += icsInfoLane[132 + windowIndex]) {
        icsInfoLane[132 + windowIndex] = 1;
        std::int32_t groupedWindow = windowIndex;
        while (groupedWindow < 7 && icsInfoLane[125 + groupedWindow] == 1) {
          ++groupedWindow;
          ++icsInfoLane[132 + windowIndex];
          icsInfoLane[125 + groupedWindow - 1] = 0;
        }
      }

      return 0;
    }

    M2ABSR_Read(context->bitstreamHandle, 6, &maxSfb);
    if (maxSfb > kM2aMaxBandsLong) {
      maxSfb = kM2aMaxBandsLong;
    }

    std::int32_t predictorDataPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &predictorDataPresent);
    if (predictorDataPresent == 1) {
      std::int32_t predictorResetPresent = 0;
      M2ABSR_Read(context->bitstreamHandle, 1, &predictorResetPresent);

      std::int32_t predictorResetGroup = 0;
      if (predictorResetPresent == 1) {
        M2ABSR_Read(context->bitstreamHandle, 5, &predictorResetGroup);
      }

      const auto predictorBandCount = maxSfb <= 41 ? maxSfb : 41;
      for (std::int32_t predictorBand = 0; predictorBand < predictorBandCount; ++predictorBand) {
        std::int32_t predictorUsed = 0;
        M2ABSR_Read(context->bitstreamHandle, 1, &predictorUsed);
      }
    }

    icsInfoLane[132] = 1;
    return 0;
  }

  /**
   * Address: 0x00B25350 (_m2adec_get_section_data)
   *
   * What it does:
   * Decodes long-window section codebook ids for current ICS lane.
   */
  std::int32_t m2adec_get_section_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const sectionCodebooks = decodeState + 2;
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t consumedBands = 0;
    while (consumedBands < maxSfb) {
      std::int32_t sectionCodebook = 0;
      M2ABSR_Read(context->bitstreamHandle, 4, &sectionCodebook);

      std::int32_t sectionLength = 0;
      while (true) {
        std::int32_t sectionLengthDelta = 0;
        M2ABSR_Read(context->bitstreamHandle, 5, &sectionLengthDelta);
        sectionLength += sectionLengthDelta;

        std::int32_t overrunFlag = 0;
        M2ABSR_Overruns(context->bitstreamHandle, &overrunFlag);
        if (overrunFlag == 1) {
          return -1;
        }

        if (sectionLengthDelta != 31) {
          break;
        }
      }

      for (std::int32_t fillIndex = 0; fillIndex < sectionLength; ++fillIndex) {
        sectionCodebooks[consumedBands + fillIndex] = sectionCodebook;
      }
      consumedBands += static_cast<std::uint32_t>(sectionLength);
    }

    if (maxSfb < static_cast<std::uint32_t>(kM2aMaxBandsLong)) {
      std::memset(
        sectionCodebooks + maxSfb,
        0,
        static_cast<std::size_t>(kM2aMaxBandsLong - static_cast<std::int32_t>(maxSfb)) * sizeof(std::int32_t)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B25440 (_m2adec_get_section_data8)
   *
   * What it does:
   * Decodes short-window section codebook ids for each active window group.
   */
  std::int32_t m2adec_get_section_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    const auto* const windowGroupFlags = reinterpret_cast<const std::uint32_t*>(icsInfo + 124);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const sectionCodebooks = sectionCodebookWindows[windowIndex];
      if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
        m2adec_copy(sectionCodebooks, sectionCodebookWindows[windowIndex - 1], 0x38u);
      } else {
        std::uint32_t consumedBands = 0;
        while (consumedBands < maxSfb) {
          std::int32_t sectionCodebook = 0;
          M2ABSR_Read(context->bitstreamHandle, 4, &sectionCodebook);

          std::int32_t sectionLength = 0;
          while (true) {
            std::int32_t sectionLengthDelta = 0;
            M2ABSR_Read(context->bitstreamHandle, 3, &sectionLengthDelta);
            sectionLength += sectionLengthDelta;

            std::int32_t overrunFlag = 0;
            M2ABSR_Overruns(context->bitstreamHandle, &overrunFlag);
            if (overrunFlag == 1) {
              return -1;
            }

            if (sectionLengthDelta != 7) {
              break;
            }
          }

          for (std::int32_t fillIndex = 0; fillIndex < sectionLength; ++fillIndex) {
            sectionCodebooks[consumedBands + fillIndex] = sectionCodebook;
          }
          consumedBands += static_cast<std::uint32_t>(sectionLength);
        }
      }

      for (std::uint32_t band = maxSfb; band < static_cast<std::uint32_t>(kM2aMaxBandsShort); ++band) {
        sectionCodebooks[band] = 0;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B255C0 (_m2adec_get_scale_factor_data)
   *
   * What it does:
   * Huffman-decodes long-window scale-factor lanes for current channel.
   */
  std::int32_t m2adec_get_scale_factor_data(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);

    std::uintptr_t codebookHandle = 0;
    M2AHUFFMAN_GetCodebook(12, &codebookHandle);
    const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);

    std::int32_t globalGain = decodeState[1];
    std::int32_t intensityPosition = 0;
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      switch (decodeState[2 + band]) {
        case 0:
          break;
        case 12:
        case 13:
          return -1;
        case 14:
        case 15:
          intensityPosition += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
          decodeState[114 + band] = intensityPosition;
          break;
        default:
          globalGain += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
          decodeState[114 + band] = globalGain;
          break;
      }
    }

    if (maxSfb < static_cast<std::uint32_t>(kM2aMaxBandsLong)) {
      std::memset(
        decodeState + 114 + maxSfb,
        0,
        static_cast<std::size_t>(kM2aMaxBandsLong - static_cast<std::int32_t>(maxSfb)) * sizeof(std::int32_t)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B256E0 (_m2adec_get_scale_factor_data8)
   *
   * What it does:
   * Huffman-decodes short-window scale-factor lanes (with grouped-window copy
   * semantics).
   */
  std::int32_t m2adec_get_scale_factor_data8(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);

    std::uintptr_t codebookHandle = 0;
    M2AHUFFMAN_GetCodebook(12, &codebookHandle);
    const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);

    std::int32_t globalGain = decodeState[1];
    std::int32_t intensityPosition = 0;
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    auto** const scaleFactorWindows = reinterpret_cast<std::int32_t**>(decodeState + 234);
    const auto* const windowGroupFlags = reinterpret_cast<const std::uint32_t*>(icsInfo + 124);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      auto* const sectionCodebooks = sectionCodebookWindows[windowIndex];
      auto* const scaleFactors = scaleFactorWindows[windowIndex];

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        switch (sectionCodebooks[band]) {
          case 0:
            break;
          case 12:
          case 13:
            return -1;
          case 14:
          case 15:
            if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
              m2adec_copy(scaleFactors, scaleFactorWindows[windowIndex - 1], 0x38u);
            } else {
              intensityPosition += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
              scaleFactors[band] = intensityPosition;
            }
            break;
          default:
            if (windowIndex != 0 && windowGroupFlags[windowIndex] == 1) {
              m2adec_copy(scaleFactors, scaleFactorWindows[windowIndex - 1], 0x38u);
            } else {
              globalGain += M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle) - 60;
              scaleFactors[band] = globalGain;
            }
            break;
        }
      }

      for (std::uint32_t band = maxSfb; band < static_cast<std::uint32_t>(kM2aMaxBandsShort); ++band) {
        scaleFactors[band] = 0;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B25CA0 (_m2adec_inverse_quantization)
   *
   * What it does:
   * Applies inverse-quantization power law to decoded spectral integers.
   */
  std::int32_t m2adec_inverse_quantization(M2aDecoderContext* context)
  {
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const quantizedSpectra = decodeState + 544;
    auto* const inverseQuantizedSpectra = reinterpret_cast<float*>(decodeState + 1568);

    for (std::int32_t spectrumIndex = 0; spectrumIndex < 1024; ++spectrumIndex) {
      const auto quantizedValue = quantizedSpectra[spectrumIndex];
      const auto magnitude = static_cast<double>(quantizedValue >= 0 ? quantizedValue : -quantizedValue);
      const auto sign = quantizedValue >= 0 ? 1.0 : -1.0;
      inverseQuantizedSpectra[spectrumIndex] = static_cast<float>(std::pow(magnitude, 1.333333333333333) * sign);
    }

    return 0;
  }

  /**
   * Address: 0x00B25D10 (_m2adec_calc_spectra)
   *
   * What it does:
   * Applies long-window scale factors onto inverse-quantized spectra lanes.
   */
  std::int32_t m2adec_calc_spectra(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const scaledSpectra = reinterpret_cast<float*>(decodeState + 2592);
    auto* const inverseQuantizedSpectra = reinterpret_cast<float*>(decodeState + 1568);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandLongPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectrumIndex = 0;
    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      const auto scaleFactor = decodeState[114 + band];
      const auto scale = scaleFactor != 0
        ? std::pow(2.0, (static_cast<double>(scaleFactor) - 100.0) * 0.25)
        : 0.0;

      for (std::int32_t line = 0; line < bandWidths[band]; ++line) {
        scaledSpectra[spectrumIndex] = static_cast<float>(scale * inverseQuantizedSpectra[spectrumIndex]);
        ++spectrumIndex;
      }
    }

    if (spectrumIndex < 1024) {
      std::memset(
        scaledSpectra + spectrumIndex,
        0,
        static_cast<std::size_t>(1024u - spectrumIndex) * sizeof(float)
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B25E00 (_m2adec_calc_spectra8)
   *
   * What it does:
   * Applies short-window scale factors onto per-window inverse-quantized
   * spectra lanes.
   */
  std::int32_t m2adec_calc_spectra8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const scaleFactorWindows = reinterpret_cast<std::int32_t**>(decodeState + 234);
    auto** const inverseQuantizedWindows = reinterpret_cast<float**>(decodeState + 3624);
    auto** const scaledSpectraWindows = reinterpret_cast<float**>(decodeState + 3632);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandShortPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    for (std::uint32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      std::uint32_t spectrumIndex = 0;

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        const auto scaleFactor = scaleFactorWindows[windowIndex][band];
        const auto scale = scaleFactor != 0
          ? std::pow(2.0, (static_cast<double>(scaleFactor) - 100.0) * 0.25)
          : 0.0;

        for (std::int32_t line = 0; line < bandWidths[band]; ++line) {
          scaledSpectraWindows[windowIndex][spectrumIndex] =
            static_cast<float>(scale * inverseQuantizedWindows[windowIndex][spectrumIndex]);
          ++spectrumIndex;
        }
      }

      for (; spectrumIndex < 128; ++spectrumIndex) {
        scaledSpectraWindows[windowIndex][spectrumIndex] = 0.0f;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B25860 (_m2adec_get_spectra_data)
   *
   * What it does:
   * Decodes long-window Huffman spectra, applies pulse processing, and runs
   * inverse-quantization/scaling.
   */
  std::int32_t m2adec_get_spectra_data(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto* const quantizedSpectra = decodeState + 544;
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandLongPtrIndex]);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectrumCursor = 0;
    for (std::uint32_t band = 0; band < maxSfb; ++band) {
      const auto codebookIndex = static_cast<std::uint32_t>(decodeState[2 + band]);
      const auto lineCount = bandWidths[band];

      if (codebookIndex > 0 && codebookIndex <= 11) {
        std::uintptr_t codebookHandle = 0;
        M2AHUFFMAN_GetCodebook(static_cast<int>(codebookIndex), &codebookHandle);
        const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);
        auto* const codebookWords = reinterpret_cast<std::uint32_t*>(codebookHandle);

        std::int32_t decodedLines = 0;
        while (decodedLines < lineCount) {
          const auto packedValue = M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle);

          std::int32_t unpackedValues[4]{};
          std::int32_t unpackedDimension = 0;
          M2AHUFFMAN_Unpack(
            codebookWords,
            packedValue,
            unpackedValues,
            &unpackedDimension,
            context->bitstreamHandle
          );

          if (codebookIndex == 11) {
            M2AHUFFMAN_GetEscValue(
              static_cast<int>(reinterpret_cast<std::uintptr_t>(unpackedValues)),
              context->bitstreamHandle
            );
          }

          for (std::int32_t unpackedIndex = 0; unpackedIndex < unpackedDimension; ++unpackedIndex) {
            quantizedSpectra[spectrumCursor] = unpackedValues[unpackedIndex];
            ++spectrumCursor;
          }

          decodedLines += unpackedDimension;
        }
      } else {
        for (std::int32_t line = 0; line < lineCount; ++line) {
          quantizedSpectra[spectrumCursor] = 0;
          ++spectrumCursor;
        }
      }
    }

    if (spectrumCursor < 1024) {
      std::memset(
        quantizedSpectra + spectrumCursor,
        0,
        static_cast<std::size_t>(1024u - spectrumCursor) * sizeof(std::int32_t)
      );
    }

    if (decodeState[242] == 1) {
      m2adec_pulse_proc(context);
    }

    m2adec_inverse_quantization(context);
    m2adec_calc_spectra(context);
    return 0;
  }

  /**
   * Address: 0x00B25A00 (_m2adec_get_spectra_data8)
   *
   * What it does:
   * Decodes short-window Huffman spectra for grouped windows and runs
   * inverse-quantization/scaling.
   */
  std::int32_t m2adec_get_spectra_data8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);
    auto* const icsInfo = M2aWordToPtr<std::int32_t>(decodeState[0]);
    auto** const sectionCodebookWindows = reinterpret_cast<std::int32_t**>(decodeState + 226);
    auto** const quantizedSpectraWindows = reinterpret_cast<std::int32_t**>(decodeState + 3616);
    const auto* const bandWidths =
      M2aWordToPtr<const std::int32_t>(contextWords[kM2aContextScalefactorBandShortPtrIndex]);
    const auto* const windowGroupLengths = reinterpret_cast<const std::uint32_t*>(icsInfo + 132);
    const auto maxSfb = static_cast<std::uint32_t>(icsInfo[kM2aIcsMaxSfbIndex]);

    std::uint32_t spectraWriteCounts[kM2aShortWindowCount]{};

    for (std::uint32_t windowStart = 0; windowStart < kM2aShortWindowCount; ++windowStart) {
      const auto groupedWindowCount = windowGroupLengths[windowStart];

      for (std::uint32_t band = 0; band < maxSfb; ++band) {
        const auto codebookIndex = static_cast<std::uint32_t>(sectionCodebookWindows[windowStart][band]);
        const auto lineCount = bandWidths[band];

        if (codebookIndex > 0 && codebookIndex <= 11) {
          std::uintptr_t codebookHandle = 0;
          M2AHUFFMAN_GetCodebook(static_cast<int>(codebookIndex), &codebookHandle);
          const auto huffmanDecodeHandle = static_cast<int>(reinterpret_cast<const std::uint32_t*>(codebookHandle)[6]);
          auto* const codebookWords = reinterpret_cast<std::uint32_t*>(codebookHandle);

          for (std::uint32_t groupedOffset = 0; groupedOffset < groupedWindowCount; ++groupedOffset) {
            const auto targetWindow = windowStart + groupedOffset;
            std::int32_t decodedLines = 0;

            while (decodedLines < lineCount) {
              const auto packedValue = M2AHUFFMAN_Decode(huffmanDecodeHandle, context->bitstreamHandle);

              std::int32_t unpackedValues[4]{};
              std::int32_t unpackedDimension = 0;
              M2AHUFFMAN_Unpack(
                codebookWords,
                packedValue,
                unpackedValues,
                &unpackedDimension,
                context->bitstreamHandle
              );

              if (sectionCodebookWindows[targetWindow][band] == 11) {
                M2AHUFFMAN_GetEscValue(
                  static_cast<int>(reinterpret_cast<std::uintptr_t>(unpackedValues)),
                  context->bitstreamHandle
                );
              }

              auto& writeCount = spectraWriteCounts[targetWindow];
              for (std::int32_t unpackedIndex = 0; unpackedIndex < unpackedDimension; ++unpackedIndex) {
                quantizedSpectraWindows[targetWindow][writeCount] = unpackedValues[unpackedIndex];
                ++writeCount;
              }

              decodedLines += unpackedDimension;
            }
          }
        } else {
          for (std::uint32_t groupedOffset = 0; groupedOffset < groupedWindowCount; ++groupedOffset) {
            const auto targetWindow = windowStart + groupedOffset;
            auto& writeCount = spectraWriteCounts[targetWindow];
            for (std::int32_t line = 0; line < lineCount; ++line) {
              quantizedSpectraWindows[targetWindow][writeCount] = 0;
              ++writeCount;
            }
          }
        }
      }

      auto& writeCount = spectraWriteCounts[windowStart];
      while (writeCount < 128) {
        quantizedSpectraWindows[windowStart][writeCount] = 0;
        ++writeCount;
      }
    }

    m2adec_inverse_quantization(context);
    m2adec_calc_spectra8(context);
    return 0;
  }

  /**
   * Address: 0x00B251E0 (_m2adec_decode_spectra)
   *
   * What it does:
   * Runs long-window ICS spectral decode stages (section/scalefactor/pulse/tns)
   * then decodes spectral coefficients.
   */
  std::int32_t m2adec_decode_spectra(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    auto result = m2adec_get_section_data(context);
    if (result < 0) {
      return result;
    }

    result = m2adec_get_scale_factor_data(context);
    if (result < 0) {
      return result;
    }

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 242);
    if (decodeState[242] == 1) {
      m2adec_get_pulse_data(context);
    }

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 253);
    if (decodeState[253] == 1) {
      m2adec_get_tns_data(context);
    }

    std::int32_t gainControlPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &gainControlPresent);
    if (gainControlPresent == 1 && contextWords[kM2aContextAudioObjectTypeIndex] == 2) {
      return -1;
    }

    m2adec_get_spectra_data(context);
    return 0;
  }

  /**
   * Address: 0x00B252A0 (_m2adec_decode_spectra8)
   *
   * What it does:
   * Runs short-window ICS spectral decode stages then decodes grouped-window
   * spectral coefficients.
   */
  std::int32_t m2adec_decode_spectra8(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    auto* const decodeState = M2aGetPrimaryStateLane(context);

    auto result = m2adec_get_section_data8(context);
    if (result < 0) {
      return result;
    }

    result = m2adec_get_scale_factor_data8(context);
    if (result < 0) {
      return result;
    }

    decodeState[242] = 0;
    M2ABSR_Seek(context->bitstreamHandle, 1, 1);

    M2ABSR_Read(context->bitstreamHandle, 1, decodeState + 253);
    if (decodeState[253] == 1) {
      m2adec_get_tns_data8(context);
    }

    std::int32_t gainControlPresent = 0;
    M2ABSR_Read(context->bitstreamHandle, 1, &gainControlPresent);
    if (gainControlPresent == 1 && contextWords[kM2aContextAudioObjectTypeIndex] == 2) {
      return -1;
    }

    m2adec_get_spectra_data8(context);
    return 0;
  }

  /**
   * Address: 0x00B24F90 (_m2adec_decode_ics)
   *
   * What it does:
   * Decodes one ICS element payload and dispatches long/short spectra path.
   */
  std::int32_t m2adec_decode_ics(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    const auto slotIndex = M2aGetCurrentSlotIndex(context);
    const auto groupedSlotBase = 32 * contextWords[kM2aContextWindowGroupIndex];
    const auto groupedElementSlot = groupedSlotBase + (contextWords[kM2aContextElementIndex] & 0xF);

    auto* const decodeState = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextPrimaryStateBaseIndex + slotIndex]);
    auto* selectedIcsInfo = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + groupedElementSlot]);

    M2ABSR_Read(context->bitstreamHandle, 8, decodeState + 1);
    if (selectedIcsInfo[0] != 0) {
      decodeState[0] = contextWords[kM2aContextIcsTableBaseIndex + groupedElementSlot];
    } else {
      m2adec_get_ics_info(context);
      selectedIcsInfo = M2aWordToPtr<std::int32_t>(contextWords[kM2aContextIcsTableBaseIndex + slotIndex]);
      decodeState[0] = M2aPtrToWord(selectedIcsInfo);
    }

    if (selectedIcsInfo[kM2aIcsWindowSequenceIndex] == 2) {
      m2adec_decode_spectra8(context);
    } else {
      m2adec_decode_spectra(context);
    }

    return 0;
  }

  /**
   * Address: 0x00B25EF0 (_m2adec_decode_pcm)
   *
   * What it does:
   * Runs post-spectral decode pipeline (MS/intensity/TNS/IMDCT) for all
   * queued element-location entries and validates channel count.
   */
  std::int32_t m2adec_decode_pcm(M2aDecoderContext* context)
  {
    auto* const contextWords = M2aContextWords(context);
    std::int32_t decodedChannelCount = 0;
    auto** const locationEntries = reinterpret_cast<M2aChannelPairLocation**>(contextWords + kM2aContextLocationEntryBaseIndex);

    for (std::int32_t entryIndex = 0; entryIndex < 128; ++entryIndex) {
      auto* const locationEntry = locationEntries[entryIndex];
      if (locationEntry == nullptr) {
        continue;
      }

      const auto channelClass = locationEntry->channelClass;
      if (channelClass == 0 || channelClass == 3) {
        contextWords[kM2aContextElementIndex] = locationEntry->channelPairType;
        contextWords[kM2aContextWindowGroupIndex] = locationEntry->channelClass;
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);
        ++decodedChannelCount;
        continue;
      }

      if (channelClass == 1) {
        contextWords[kM2aContextElementIndex] = locationEntry->channelPairType;
        contextWords[kM2aContextWindowGroupIndex] = locationEntry->channelClass;
        m2adec_ms_proc(context);
        m2adec_intensity_proc(context);
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);

        contextWords[kM2aContextElementIndex] += 16;
        m2adec_tns_proc(context);
        m2adec_inverse_transform(context);
        decodedChannelCount += 2;
      }
    }

    if (contextWords[kM2aContextDecodeCountInitializedIndex] != 0) {
      return contextWords[kM2aContextDecodedChannelCountIndex] == decodedChannelCount ? 0 : -1;
    }

    contextWords[kM2aContextDecodedChannelCountIndex] = decodedChannelCount;
    contextWords[kM2aContextDecodeCountInitializedIndex] = 1;
    return 0;
  }
}

namespace
{
  [[nodiscard]] void* const* GetSofDecVirtualDispatchTable()
  {
    if (gSofDecVirtualDispatchTable[3] == nullptr) {
      gSofDecVirtualDispatchTable[3] = reinterpret_cast<void*>(&SofDecVirtualResetStateThunk);
      gSofDecVirtualDispatchTable[4] = reinterpret_cast<void*>(&SofDecVirtualUpdatePlayheadSample);
      gSofDecVirtualDispatchTable[5] = reinterpret_cast<void*>(&SofDecVirtualCaptureLatchedSample);
      gSofDecVirtualDispatchTable[6] = reinterpret_cast<void*>(&SofDecVirtualGetDefaultPhaseModulo);
      gSofDecVirtualDispatchTable[7] = reinterpret_cast<void*>(&SofDecVirtualNoOpSlotA);
      gSofDecVirtualDispatchTable[8] = reinterpret_cast<void*>(&SofDecVirtualUpdateWrapPosition);
      gSofDecVirtualDispatchTable[9] = reinterpret_cast<void*>(&SofDecVirtualSetSampleRate);
      gSofDecVirtualDispatchTable[10] = reinterpret_cast<void*>(&SofDecVirtualGetSampleRate);
      gSofDecVirtualDispatchTable[11] = reinterpret_cast<void*>(&SofDecVirtualNoOpSlotB);
      gSofDecVirtualDispatchTable[12] = reinterpret_cast<void*>(&SofDecVirtualGetOutputBitDepth);
      gSofDecVirtualDispatchTable[13] = reinterpret_cast<void*>(&SofDecVirtualNoOpSlotC);
      gSofDecVirtualDispatchTable[14] = reinterpret_cast<void*>(&SofDecVirtualReturnZeroSlotD);
      gSofDecVirtualDispatchTable[15] = reinterpret_cast<void*>(&SofDecVirtualNoOpSlotE);
      gSofDecVirtualDispatchTable[16] = reinterpret_cast<void*>(&SofDecVirtualStubReturnZeroA);
      gSofDecVirtualDispatchTable[17] = reinterpret_cast<void*>(&SofDecVirtualStubNoOpA);
      gSofDecVirtualDispatchTable[18] = reinterpret_cast<void*>(&SofDecVirtualStubReturnZeroB);
      gSofDecVirtualDispatchTable[19] = reinterpret_cast<void*>(&SofDecVirtualStubNoOpB);
      gSofDecVirtualDispatchTable[20] = reinterpret_cast<void*>(&SofDecVirtualStubZeroRangeOutputs);
      gSofDecVirtualDispatchTable[21] = reinterpret_cast<void*>(&SofDecVirtualStubNoOpC);
      gSofDecVirtualDispatchTable[22] = reinterpret_cast<void*>(&SofDecVirtualStubNoOpD);
      gSofDecVirtualDispatchTable[23] = reinterpret_cast<void*>(&SofDecVirtualStubReturnOne);
      gSofDecVirtualDispatchTable[24] = reinterpret_cast<void*>(&SofDecVirtualStubSetReadyFlag);
      gSofDecVirtualDispatchTable[25] = reinterpret_cast<void*>(&SofDecVirtualStubReturnZeroC);
    }

    return gSofDecVirtualDispatchTable;
  }
}
