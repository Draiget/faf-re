#include "Common.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <vector>

#include "CHostManager.h"
#include "CGpgNetInterface.h"
#include "CNetNullConnector.h"
#include "CNetTCPConnector.h"
#include "CNetUDPConnector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "NetConVars.h"
using namespace moho;

namespace moho
{
  msvc8::vector<msvc8::string> sProtocols{};
} // namespace moho

namespace
{
  void cleanup_sProtocols() noexcept
  {
    moho::sProtocols = msvc8::vector<msvc8::string>{};
  }

  struct ProtocolRegistryBootstrap
  {
    ProtocolRegistryBootstrap()
    {
      moho::register_sProtocols();
    }
  };

  [[maybe_unused]] ProtocolRegistryBootstrap gProtocolRegistryBootstrap;
} // namespace

/**
 * Address: 0x00485B60 (FUN_00485B60)
 *
 * What it does:
 * Initializes packet timing lane with zeroed source id and reset timer.
 */
NetPacketTime::NetPacketTime()
  : mSource(0)
  , mTime()
{}

NetSpeeds::NetSpeeds()
  : vals{}
  , mReserved0(0)
  , head(0)
  , tail(0)
{}

/**
 * Address: 0x0048C320 (FUN_0048C320, struct_RollingFloat_25 dtor lane)
 *
 * What it does:
 * Walks any live ring span and resets ring cursors to empty.
 */
NetSpeeds::~NetSpeeds()
{
  if (head != tail) {
    do {
      head = (head + 1) % 25;
    } while (head != tail);
  }
  head = 0;
  tail = 0;
}

/**
 * Address: 0x0048BEC0 (FUN_0048BEC0, struct_RollingFloat_25::roll)
 */
int NetSpeeds::Append(const float sample) noexcept
{
  const int next = (tail + 1) % 25;
  if (next == head) {
    head = (head + 1) % 25;
  }
  vals[tail] = sample;
  const int wrapped = (tail + 1) / 25;
  tail = next;
  return wrapped;
}

/**
 * Address: 0x0048BF00 (FUN_0048BF00, struct_RollingFloat_25::median)
 */
float NetSpeeds::Median() const noexcept
{
  float tmp[25];
  int i = 0;
  int h = head;
  const int t = tail;
  while (h != t) {
    tmp[i++] = vals[h];
    h = (h + 1) % 25;
  }
  if (i == 0) {
    return 0.0f;
  }
  std::sort(tmp, tmp + i);
  return tmp[i / 2];
}

/**
 * Address: 0x0048BF60 (FUN_0048BF60, struct_RollingFloat_25::jitter)
 */
float NetSpeeds::Jitter(const float center) const noexcept
{
  float tmp[25];
  int i = 0;
  int h = head;
  const int t = tail;
  while (h != t) {
    tmp[i++] = std::fabs(vals[h] - center);
    h = (h + 1) % 25;
  }
  if (i == 0) {
    return 0.0f;
  }
  std::sort(tmp, tmp + i);
  return tmp[i / 2];
}

/**
 * Address: 0x0047D1D0
 * NOTE: Inlined
 *
 * What it does:
 * Initializes a send-stamp view for the requested [start, end] time window.
 */
SSendStampView::SSendStampView(const uint64_t durationUs, const uint64_t endTimeUs)
  : items{}
  , windowDurationUs(durationUs)
  , windowEndTimeUs(endTimeUs)
{}

/**
 * Address: 0x0047D4D0 (FUN_0047D4D0, GetStampCount)
 */
uint32_t SSendStampView::StampCount() const noexcept
{
  return static_cast<uint32_t>(items.size());
}

/**
 * Address: 0x0047D3C0 (FUN_0047D3C0, ReserveStampCapacity)
 */
void SSendStampView::ReserveStamps(const uint32_t count)
{
  if (count <= static_cast<uint32_t>(items.capacity())) {
    return;
  }
  items.reserve(count);
}

/**
 * Address: 0x0047D500 (FUN_0047D500, AppendStamp)
 */
void SSendStampView::AppendStamp(const SSendStamp& stamp)
{
  items.push_back(stamp);
}

void moho::ENetworkPlayerStateToStr(const ENetworkPlayerState state, msvc8::string& out)
{
  if (state >= ENetworkPlayerState::_Last) {
    out = gpg::STR_Printf("%d", static_cast<int32_t>(state));
    return;
  }

  switch (state) {
  case ENetworkPlayerState::kUnknown:
    out = "Unknown";
    return;
  case ENetworkPlayerState::kConnecting:
    out = "Connecting";
    return;
  case ENetworkPlayerState::kConnected:
    out = "Connected";
    return;
  case ENetworkPlayerState::kPending:
    out = "Pending";
    return;
  case ENetworkPlayerState::kWaitingJoin:
    out = "WaitingJoin";
    return;
  case ENetworkPlayerState::kEstablished:
    out = "Established";
    return;
  case ENetworkPlayerState::kDisconnected:
    out = "Disconnected";
  default:;
  }
}

void moho::NetPacketTypeToStr(const EPacketType state, msvc8::string& out)
{
  switch (state) {
  case PT_Connect:
    out = "CONNECT";
    return;
  case PT_Answer:
    out = "ANSWER";
    return;
  case PT_ResetSerial:
    out = "RESETSERIAL";
    return;
  case PT_SerialReset:
    out = "SERIALRESET";
    return;
  case PT_Data:
    out = "DATA";
    return;
  case PT_Ack:
    out = "ACK";
    return;
  case PT_KeepAlive:
    out = "KEEPALIVE";
    return;
  case PT_Goodbye:
    out = "GOODBYE";
    return;
  case PT_NATTraversal:
    out = "NATTRAVERSAL";
    return;
  default:
    out = gpg::STR_Printf("%02x", static_cast<uint8_t>(state));
  }
}

const char* moho::NetConnectionStateToStr(const ENetConnectionState state)
{
  switch (state) {
  case kNetStatePending:
    return "PENDING";
  case kNetStateConnecting:
    return "CONNECTING";
  case kNetStateAnswering:
    return "ANSWERING";
  case kNetStateEstablishing:
    return "ESTABLISHING";
  case kNetStateTimedOut:
    return "TIMEDOUT";
  case kNetStateErrored:
    return "ERRORED";
  default:
    return "???";
  }
}

SSendStampView SSendStampBuffer::GetBetween(const uint64_t endTimeUs, const uint64_t startTimeUs)
{
  // Binary computes and stores duration as (end - start).
  const uint64_t durationUs = endTimeUs - startTimeUs;

  // Logical count in [mOldestIndex .. mNextWriteIndex) with 4096-cap ring.
  const unsigned int len = (mOldestIndex > mNextWriteIndex)
                             ? (mNextWriteIndex - mOldestIndex + cap)
                             : (mNextWriteIndex - mOldestIndex);

  // Lower_bound over [0, len): first stamp with timestampUs >= durationUs.
  unsigned int lo = 0, hi = len;
  while (lo < hi) {
    const unsigned int mid = (lo + hi) >> 1;
    if (Get(mid).timestampUs >= durationUs) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  SSendStampView out{durationUs, endTimeUs};

  // Reserve exactly the number of items we will push (len - lo)
  out.ReserveStamps(len - lo);

  // Emit tail [lo .. len)
  for (unsigned int i = lo; i < len; ++i) {
    out.AppendStamp(Get(i));
  }

  return out;
}

void SSendStampBuffer::Reset()
{
  mOldestIndex = 0;
  mNextWriteIndex = 0;
}

uint32_t SSendStampBuffer::Push(const int direction, const LONGLONG timeUs, const int payloadSizeBytes) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;

  // If advancing write index collides with oldest, drop oldest first.
  const std::uint32_t nextWriteIndex = (mNextWriteIndex + 1u) & kRingMask;
  if (nextWriteIndex == mOldestIndex) {
    AdvanceOldestIndex();
  }

  SSendStamp stamp{};
  stamp.timestampUs = static_cast<uint64_t>(timeUs);
  stamp.direction = static_cast<uint32_t>(direction);
  stamp.payloadSizeBytes = static_cast<uint32_t>(payloadSizeBytes);

  return EmplaceAndAdvance(stamp);
}

void SSendStampBuffer::Add(const int direction, const LONGLONG timeUs, const int payloadSizeBytes)
{
  (void)Push(direction, timeUs, payloadSizeBytes);
}

void SSendStampBuffer::Append(const SSendStamp* stamp)
{
  EmplaceAndAdvance(*stamp);
}

bool SSendStampBuffer::empty() const noexcept
{
  return mNextWriteIndex == mOldestIndex;
}

uint32_t SSendStampBuffer::size() const noexcept
{
  return (mNextWriteIndex - mOldestIndex) & (cap - 1u);
}

void SSendStampBuffer::push(const SSendStamp& stamp) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;
  mDat[mNextWriteIndex] = stamp;
  mNextWriteIndex = (mNextWriteIndex + 1u) & kRingMask;
  if (mNextWriteIndex == mOldestIndex) {
    AdvanceOldestIndex();
  }
}

SSendStamp& SSendStampBuffer::Get(const size_t logicalIndex) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;
  return mDat[(mOldestIndex + static_cast<uint32_t>(logicalIndex)) & kRingMask];
}

uint32_t SSendStampBuffer::EmplaceAndAdvance(const SSendStamp& stamp) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;
  mDat[mNextWriteIndex] = stamp;
  mNextWriteIndex = (mNextWriteIndex + 1u) & kRingMask;
  return mNextWriteIndex;
}

/**
 * Address: 0x0047D690 (FUN_0047D690, AdvanceOldestIndex)
 */
void SSendStampBuffer::AdvanceOldestIndex() noexcept
{
  mOldestIndex = (mOldestIndex + 1u) & (cap - 1u);
}

/**
 * Address: 0x0047D6E0 (FUN_0047D6E0, GetBandwidthSampleCount)
 */
uint32_t SBandwidthUsageSeries::SampleCount() const noexcept
{
  return static_cast<uint32_t>(samples.size());
}

/**
 * Address: 0x0047DA00 (FUN_0047DA00, ResizeBandwidthSamples)
 */
void SBandwidthUsageSeries::ResizeSamples(const uint32_t count)
{
  samples.resize(count);
}

/**
 * Address: 0x0047D6B0 (FUN_0047D6B0, EnsureBandwidthSampleCount)
 */
void SBandwidthUsageSeries::EnsureSampleCount(const uint32_t count)
{
  ResizeSamples(count);
}

namespace
{
  template <typename T>
  [[nodiscard]] T* VectorData(msvc8::vector<T>& values) noexcept
  {
    return values.empty() ? nullptr : &values[0];
  }

  template <typename T>
  [[nodiscard]] const T* VectorData(const msvc8::vector<T>& values) noexcept
  {
    return values.empty() ? nullptr : &values[0];
  }

  template <typename T>
  [[nodiscard]] constexpr uint32_t MaxLegacyVectorCount() noexcept
  {
    return 0xFFFFFFFFu / static_cast<uint32_t>(sizeof(T));
  }

  template <typename T>
  [[nodiscard]] size_t ClampVectorIndexFromPointer(const msvc8::vector<T>& values, const T* pointer) noexcept
  {
    const T* const base = VectorData(values);
    if (!base || !pointer) {
      return values.size();
    }
    if (pointer < base) {
      return values.size();
    }
    const size_t index = static_cast<size_t>(pointer - base);
    return (index <= values.size()) ? index : values.size();
  }

  template <typename T>
  [[nodiscard]] T* FillCopiesAndAdvance(T* destination, const uint32_t count, const T& value) noexcept
  {
    if (!destination || count == 0u) {
      return destination;
    }
    for (uint32_t i = 0; i < count; ++i) {
      destination[i] = value;
    }
    return destination + count;
  }

  template <typename T>
  [[nodiscard]] T* CopyRangeAndAdvance(T* destination, const T* sourceBegin, const T* sourceEnd) noexcept
  {
    const T* it = sourceBegin;
    while (it != sourceEnd) {
      if (destination) {
        *destination = *it;
      }
      ++it;
      ++destination;
    }
    return destination;
  }

  template <typename T>
  [[nodiscard]] T* FillRangeWithValue(T* first, T* const last, const T& value) noexcept
  {
    while (first != last) {
      *first = value;
      ++first;
    }
    return first;
  }

  template <typename T>
  [[nodiscard]] T* CopyRangeBackward(T* destinationEnd, const T* const sourceBegin, const T* sourceEnd) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  template <typename T>
  [[nodiscard]] T* EraseRangeShiftLeft(msvc8::vector<T>& values, T* const destination, const T* const source)
  {
    T* const base = VectorData(values);
    if (!base) {
      return destination;
    }

    T* const finish = base + values.size();
    if (!destination || !source || destination < base || destination > finish || source < base || source > finish) {
      return destination;
    }

    if (destination != source) {
      T* write = destination;
      const T* read = source;
      while (read != finish) {
        *write = *read;
        ++write;
        ++read;
      }
      values.resize(static_cast<size_t>(write - base));
    }

    return destination;
  }

  template <typename T>
  [[nodiscard]] T* InsertValueCopies(
    msvc8::vector<T>& values, T* const position, const uint32_t count, const T& value
  )
  {
    if (count == 0u) {
      return position;
    }

    const size_t index = ClampVectorIndexFromPointer(values, position);
    const size_t oldSize = values.size();
    values.resize(oldSize + static_cast<size_t>(count));

    T* const base = VectorData(values);
    for (size_t write = oldSize; write > index; --write) {
      base[(write - 1u) + count] = base[write - 1u];
    }

    for (uint32_t fill = 0; fill < count; ++fill) {
      base[index + static_cast<size_t>(fill)] = value;
    }

    return base + index;
  }

  template <typename T>
  [[nodiscard]] T** StorePointerOut(T** const result, T* const value) noexcept
  {
    *result = value;
    return result;
  }

  /**
   * Address: 0x0047D2D0 (FUN_0047D2D0, CopyStampVectorOnly)
   */
  [[maybe_unused]] void CopyStampVectorOnly(const SSendStampView& source, SSendStampView& destination)
  {
    destination.items = source.items;
  }

  /**
   * Address: 0x0047D290 (FUN_0047D290, CopyStampViewWithWindowMetadata)
   */
  [[maybe_unused]] void CopyStampViewWithWindowMetadata(
    const SSendStampView& source, SSendStampView& destination
  )
  {
    CopyStampVectorOnly(source, destination);
    destination.windowDurationUs = source.windowDurationUs;
    destination.windowEndTimeUs = source.windowEndTimeUs;
  }

  /**
   * Address: 0x0047D4F0 (FUN_0047D4F0, StampPointerAt)
   */
  [[maybe_unused]] const SSendStamp* StampPointerAt(const SSendStampView& view, const uint32_t index)
  {
    const SSendStamp* const base = VectorData(view.items);
    return base ? (base + index) : nullptr;
  }

  /**
   * Address: 0x0047D700 (FUN_0047D700, BandwidthSamplePointerAt)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSamplePointerAt(
    SBandwidthUsageSeries& series, const uint32_t index
  )
  {
    SBandwidthUsageSample* const base = VectorData(series.samples);
    return base ? (base + index) : nullptr;
  }

  /**
   * Address: 0x0047D730 (FUN_0047D730, BandwidthSampleBegin)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleBegin(SBandwidthUsageSeries& series)
  {
    return VectorData(series.samples);
  }

  /**
   * Address: 0x0047D740 (FUN_0047D740, BandwidthSampleBeginAlias)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleBeginAlias(SBandwidthUsageSeries& series)
  {
    return BandwidthSampleBegin(series);
  }

  /**
   * Address: 0x0047D750 (FUN_0047D750, BandwidthSampleEnd)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleEnd(SBandwidthUsageSeries& series)
  {
    SBandwidthUsageSample* const base = VectorData(series.samples);
    return base ? (base + series.samples.size()) : nullptr;
  }

  /**
   * Address: 0x0047D760 (FUN_0047D760, BandwidthSampleEndAlias)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleEndAlias(SBandwidthUsageSeries& series)
  {
    return BandwidthSampleEnd(series);
  }

  /**
   * Address: 0x0047D770 (FUN_0047D770, MaxStampVectorCount)
   */
  [[maybe_unused]] uint32_t MaxStampVectorCount()
  {
    return MaxLegacyVectorCount<SSendStamp>();
  }

  /**
   * Address: 0x0047DD10 (FUN_0047DD10, MaxStampVectorCountAlias)
   */
  [[maybe_unused]] uint32_t MaxStampVectorCountAlias()
  {
    return MaxStampVectorCount();
  }

  /**
   * Address: 0x0047D8A0 (FUN_0047D8A0, ThrowStampVectorTooLong)
   */
  [[noreturn]] [[maybe_unused]] void ThrowStampVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0047E090 (FUN_0047E090, ThrowBandwidthSampleVectorTooLong)
   */
  [[noreturn]] [[maybe_unused]] void ThrowBandwidthSampleVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x0047DA70 (FUN_0047DA70, InsertStampAt)
   */
  [[maybe_unused]] SSendStamp* InsertStampAt(
    SSendStampView& view, SSendStamp* const position, const SSendStamp& stamp
  )
  {
    return InsertValueCopies(view.items, position, 1u, stamp);
  }

  /**
   * Address: 0x0047D780 (FUN_0047D780, InsertStampAtAlias)
   */
  [[maybe_unused]] SSendStamp* InsertStampAtAlias(
    SSendStampView& view, SSendStamp* const position, const SSendStamp& stamp
  )
  {
    return InsertStampAt(view, position, stamp);
  }

  /**
   * Address: 0x0047D7F0 (FUN_0047D7F0, AllocateStampStorage)
   */
  [[maybe_unused]] bool AllocateStampStorage(SSendStampView& view, const uint32_t count)
  {
    if (count > MaxStampVectorCount()) {
      ThrowStampVectorTooLong();
    }

    view.items = msvc8::vector<SSendStamp>{};
    view.items.reserve(count);
    return true;
  }

  /**
   * Address: 0x0047D850 (FUN_0047D850, ClearStampStorage)
   */
  [[maybe_unused]] void ClearStampStorage(SSendStampView& view)
  {
    view.items = msvc8::vector<SSendStamp>{};
  }

  /**
   * Address: 0x0047D880 (FUN_0047D880, CopyStampAndAdvance)
   */
  [[maybe_unused]] SSendStamp* CopyStampAndAdvance(
    SSendStamp* destination, const uint32_t count, const SSendStamp& stamp
  ) noexcept
  {
    return FillCopiesAndAdvance(destination, count, stamp);
  }

  /**
   * Address: 0x0047DD20 (FUN_0047DD20, BandwidthSampleBeginAlias2)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleBeginAlias2(SBandwidthUsageSeries& series)
  {
    return BandwidthSampleBegin(series);
  }

  /**
   * Address: 0x0047DD30 (FUN_0047DD30, BandwidthSampleEndAlias2)
   */
  [[maybe_unused]] SBandwidthUsageSample* BandwidthSampleEndAlias2(SBandwidthUsageSeries& series)
  {
    return BandwidthSampleEnd(series);
  }

  /**
   * Address: 0x0047DD40 (FUN_0047DD40, EraseBandwidthSampleRange)
   */
  [[maybe_unused]] SBandwidthUsageSample* EraseBandwidthSampleRange(
    SBandwidthUsageSeries& series,
    SBandwidthUsageSample* const destination,
    const SBandwidthUsageSample* const source
  )
  {
    return EraseRangeShiftLeft(series.samples, destination, source);
  }

  /**
   * Address: 0x0047DD80 (FUN_0047DD80, InsertBandwidthSampleCopies)
   */
  [[maybe_unused]] SBandwidthUsageSample* InsertBandwidthSampleCopies(
    SBandwidthUsageSeries& series,
    SBandwidthUsageSample* const position,
    const uint32_t count,
    const SBandwidthUsageSample& value
  )
  {
    if (count > MaxLegacyVectorCount<SBandwidthUsageSample>()) {
      ThrowBandwidthSampleVectorTooLong();
    }
    return InsertValueCopies(series.samples, position, count, value);
  }

  /**
   * Address: 0x0047DFD0 (FUN_0047DFD0, StorePointerOut)
   */
  [[maybe_unused]] void** StorePointerOutVariant1(void** const result, void* const value) noexcept
  {
    return StorePointerOut(result, value);
  }

  /**
   * Address: 0x0047DFE0 (FUN_0047DFE0, StorePointerOutAlias)
   */
  [[maybe_unused]] void** StorePointerOutAlias(void** const result, void* const value) noexcept
  {
    return StorePointerOut(result, value);
  }

  /**
   * Address: 0x0047DFF0 (FUN_0047DFF0, StampPointerFromVectorBase)
   */
  [[maybe_unused]] SSendStamp** StampPointerFromVectorBase(
    SSendStamp** const result, SSendStamp* const* const base, const int index
  ) noexcept
  {
    *result = (base && *base) ? (*base + index) : nullptr;
    return result;
  }

  /**
   * Address: 0x0047E020 (FUN_0047E020, BandwidthPointerFromVectorBase)
   */
  [[maybe_unused]] SBandwidthUsageSample** BandwidthPointerFromVectorBase(
    SBandwidthUsageSample** const result, SBandwidthUsageSample* const* const base, const int index
  ) noexcept
  {
    *result = (base && *base) ? (*base + index) : nullptr;
    return result;
  }

  /**
   * Address: 0x0047E050 (FUN_0047E050, MaxBandwidthSampleVectorCount)
   */
  [[maybe_unused]] uint32_t MaxBandwidthSampleVectorCount()
  {
    return MaxLegacyVectorCount<SBandwidthUsageSample>();
  }

  /**
   * Address: 0x0047E160 (FUN_0047E160, StorePointerOutAlias2)
   */
  [[maybe_unused]] void** StorePointerOutAlias2(void** const result, void* const value) noexcept
  {
    return StorePointerOut(result, value);
  }

  /**
   * Address: 0x0047E190 (FUN_0047E190, MaxBandwidthSampleVectorCountAlias)
   */
  [[maybe_unused]] uint32_t MaxBandwidthSampleVectorCountAlias()
  {
    return MaxBandwidthSampleVectorCount();
  }

  /**
   * Address: 0x0047E1B0 (FUN_0047E1B0, StorePointerOutAlias3)
   */
  [[maybe_unused]] void** StorePointerOutAlias3(void** const result, void* const value) noexcept
  {
    return StorePointerOut(result, value);
  }

  /**
   * Address: 0x0047E700 (FUN_0047E700, CopyStampRangeForward)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForward(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyRangeAndAdvance(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E940 (FUN_0047E940, CopyStampRangeForwardAlias)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardAlias(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E990 (FUN_0047E990, CopyStampRangeForwardFromCurrent)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardFromCurrent(
    SSendStamp* destination, const SSendStamp* sourceEnd, const SSendStamp* sourceCurrent
  ) noexcept
  {
    return CopyRangeAndAdvance(destination, sourceCurrent, sourceEnd);
  }

  /**
   * Address: 0x0047E9D0 (FUN_0047E9D0, CopyBandwidthRangeForwardFromCurrent)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeForwardFromCurrent(
    SBandwidthUsageSample* destination,
    const SBandwidthUsageSample* sourceEnd,
    const SBandwidthUsageSample* sourceCurrent
  ) noexcept
  {
    return CopyRangeAndAdvance(destination, sourceCurrent, sourceEnd);
  }

  /**
   * Address: 0x0047E4D0 (FUN_0047E4D0, CopyStampCountFromValue)
   */
  [[maybe_unused]] SSendStamp* CopyStampCountFromValue(
    SSendStamp* destination, const SSendStamp& value, const uint32_t count
  ) noexcept
  {
    return FillCopiesAndAdvance(destination, count, value);
  }

  /**
   * Address: 0x0047E670 (FUN_0047E670, CopyBandwidthCountFromValue)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthCountFromValue(
    SBandwidthUsageSample* destination, const SBandwidthUsageSample& value, const uint32_t count
  ) noexcept
  {
    return FillCopiesAndAdvance(destination, count, value);
  }

  /**
   * Address: 0x0047E530 (FUN_0047E530, FillStampRangeWithValue)
   */
  [[maybe_unused]] SSendStamp* FillStampRangeWithValue(
    SSendStamp* first, SSendStamp* const last, const SSendStamp& value
  ) noexcept
  {
    return FillRangeWithValue(first, last, value);
  }

  /**
   * Address: 0x0047E7A0 (FUN_0047E7A0, CopyStampRangeBackward)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeBackward(
    SSendStamp* destinationEnd, const SSendStamp* const sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E1E0 (FUN_0047E1E0, CopyStampRangeForwardThunk)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardThunk(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E210 (FUN_0047E210, CopyStampRangeForwardThunkAlias)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardThunkAlias(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForwardAlias(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E250 (FUN_0047E250, CopyStampCountThunk)
   */
  [[maybe_unused]] SSendStamp* CopyStampCountThunk(
    SSendStamp* destination, const SSendStamp& value, const uint32_t count
  ) noexcept
  {
    return CopyStampCountFromValue(destination, value, count);
  }

  /**
   * Address: 0x0047E2D0 (FUN_0047E2D0, CopyStampRangeForwardFromCurrentThunk)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardFromCurrentThunk(
    SSendStamp* destination, const SSendStamp* sourceEnd, const SSendStamp* sourceCurrent
  ) noexcept
  {
    return CopyStampRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E310 (FUN_0047E310, CopyStampRangeBackwardThunk)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeBackwardThunk(
    SSendStamp* destinationEnd, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E360 (FUN_0047E360, CopyBandwidthRangeForwardFromCurrentThunk)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeForwardFromCurrentThunk(
    SBandwidthUsageSample* destination,
    const SBandwidthUsageSample* sourceEnd,
    const SBandwidthUsageSample* sourceCurrent
  ) noexcept
  {
    return CopyBandwidthRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E3E0 (FUN_0047E3E0, CopyBandwidthCountThunk)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthCountThunk(
    SBandwidthUsageSample* destination, const SBandwidthUsageSample& value, const uint32_t count
  ) noexcept
  {
    return CopyBandwidthCountFromValue(destination, value, count);
  }

  /**
   * Address: 0x0047E450 (FUN_0047E450, CopyStampRangeForwardThunkAlias2)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardThunkAlias2(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E480 (FUN_0047E480, CopyStampRangeForwardAliasThunk)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardAliasThunk(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForwardAlias(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E4B0 (FUN_0047E4B0, ExtractArgumentHighByte)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByte(const uint32_t value) noexcept
  {
    return static_cast<unsigned char>((value >> 8u) & 0xFFu);
  }

  /**
   * Address: 0x0047E510 (FUN_0047E510, CopyStampRangeForwardFromCurrentThunkAlias)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardFromCurrentThunkAlias(
    SSendStamp* destination, const SSendStamp* sourceEnd, const SSendStamp* sourceCurrent
  ) noexcept
  {
    return CopyStampRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E570 (FUN_0047E570, ExtractArgumentHighByteAlias)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByteAlias(const uint32_t value) noexcept
  {
    return ExtractArgumentHighByte(value);
  }

  /**
   * Address: 0x0047E580 (FUN_0047E580, CopyStampRangeBackwardThunkAlias)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeBackwardThunkAlias(
    SSendStamp* destinationEnd, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E5C0 (FUN_0047E5C0, ExtractArgumentHighByteAlias2)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByteAlias2(const uint32_t value) noexcept
  {
    return ExtractArgumentHighByte(value);
  }

  /**
   * Address: 0x0047E5F0 (FUN_0047E5F0, CopyBandwidthRangeForwardFromCurrentThunkAlias)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeForwardFromCurrentThunkAlias(
    SBandwidthUsageSample* destination,
    const SBandwidthUsageSample* sourceEnd,
    const SBandwidthUsageSample* sourceCurrent
  ) noexcept
  {
    return CopyBandwidthRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E630 (FUN_0047E630, ExtractArgumentHighByteAlias3)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByteAlias3(const uint32_t value) noexcept
  {
    return ExtractArgumentHighByte(value);
  }

  /**
   * Address: 0x0047E6F0 (FUN_0047E6F0, ExtractArgumentHighByteAlias4)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByteAlias4(const uint32_t value) noexcept
  {
    return ExtractArgumentHighByte(value);
  }

  /**
   * Address: 0x0047E750 (FUN_0047E750, CopyStampRangeForwardAliasThunk2)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardAliasThunk2(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForwardAlias(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E780 (FUN_0047E780, CopyStampRangeForwardFromCurrentThunkAlias2)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardFromCurrentThunkAlias2(
    SSendStamp* destination, const SSendStamp* sourceEnd, const SSendStamp* sourceCurrent
  ) noexcept
  {
    return CopyStampRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E7E0 (FUN_0047E7E0, CopyBandwidthRangeForwardFromCurrentThunkAlias2)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeForwardFromCurrentThunkAlias2(
    SBandwidthUsageSample* destination,
    const SBandwidthUsageSample* sourceEnd,
    const SBandwidthUsageSample* sourceCurrent
  ) noexcept
  {
    return CopyBandwidthRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E880 (FUN_0047E880, DereferenceUint32)
   */
  [[maybe_unused]] uint32_t DereferenceUint32(const uint32_t* const value)
  {
    return *value;
  }

  /**
   * Address: 0x0047E8C0 (FUN_0047E8C0, CopyStampRangeForwardAliasThunk3)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardAliasThunk3(
    SSendStamp* destination, const SSendStamp* sourceBegin, const SSendStamp* sourceEnd
  ) noexcept
  {
    return CopyStampRangeForwardAlias(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E8F0 (FUN_0047E8F0, CopyStampRangeForwardFromCurrentThunkAlias3)
   */
  [[maybe_unused]] SSendStamp* CopyStampRangeForwardFromCurrentThunkAlias3(
    SSendStamp* destination, const SSendStamp* sourceEnd, const SSendStamp* sourceCurrent
  ) noexcept
  {
    return CopyStampRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E910 (FUN_0047E910, CopyBandwidthRangeForwardFromCurrentThunkAlias3)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeForwardFromCurrentThunkAlias3(
    SBandwidthUsageSample* destination,
    const SBandwidthUsageSample* sourceEnd,
    const SBandwidthUsageSample* sourceCurrent
  ) noexcept
  {
    return CopyBandwidthRangeForwardFromCurrent(destination, sourceEnd, sourceCurrent);
  }

  /**
   * Address: 0x0047E930 (FUN_0047E930, ExtractArgumentHighByteAlias5)
   */
  [[maybe_unused]] unsigned char ExtractArgumentHighByteAlias5(const uint32_t value) noexcept
  {
    return ExtractArgumentHighByte(value);
  }

  /**
   * Address: 0x0047E390 (FUN_0047E390, FillBandwidthRangeWithValue)
   */
  [[maybe_unused]] SBandwidthUsageSample* FillBandwidthRangeWithValue(
    SBandwidthUsageSample* first, SBandwidthUsageSample* const last, const SBandwidthUsageSample& value
  ) noexcept
  {
    return FillRangeWithValue(first, last, value);
  }

  /**
   * Address: 0x0047E3B0 (FUN_0047E3B0, CopyBandwidthRangeBackward)
   */
  [[maybe_unused]] SBandwidthUsageSample* CopyBandwidthRangeBackward(
    SBandwidthUsageSample* destinationEnd,
    const SBandwidthUsageSample* const sourceBegin,
    const SBandwidthUsageSample* sourceEnd
  ) noexcept
  {
    return CopyRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0047E270 (FUN_0047E270, AllocateStampArray)
   */
  [[maybe_unused]] void* AllocateStampArray(const uint32_t count)
  {
    if (count > MaxStampVectorCount()) {
      throw std::bad_alloc{};
    }
    return ::operator new(static_cast<size_t>(count) * sizeof(SSendStamp));
  }

  /**
   * Address: 0x0047E400 (FUN_0047E400, AllocateBandwidthSampleArray)
   */
  [[maybe_unused]] void* AllocateBandwidthSampleArray(const uint32_t count)
  {
    if (count > MaxBandwidthSampleVectorCount()) {
      throw std::bad_alloc{};
    }
    return ::operator new(static_cast<size_t>(count) * sizeof(SBandwidthUsageSample));
  }

  [[nodiscard]] uint32_t FindFirstStampAtOrAfter(const SSendStampView& stamps, const uint64_t thresholdUs)
  {
    uint32_t index = 0;
    const uint32_t count = stamps.StampCount();
    while (index < count && stamps.items[index].timestampUs < thresholdUs) {
      ++index;
    }
    return index;
  }

  void AddStampToDirectionTotals(const SSendStamp& stamp, int totals[2])
  {
    GPG_ASSERT(stamp.direction < 2u);
    if (stamp.direction < 2u) {
      totals[stamp.direction] += static_cast<int>(stamp.payloadSizeBytes);
    }
  }

  void RemoveStampFromDirectionTotals(const SSendStamp& stamp, int totals[2])
  {
    GPG_ASSERT(stamp.direction < 2u);
    if (stamp.direction < 2u) {
      totals[stamp.direction] -= static_cast<int>(stamp.payloadSizeBytes);
    }
  }
} // namespace

/**
 * Address: 0x0047CC00 (FUN_0047CC00, BuildBandwidthUsageSeries)
 */
void moho::NET_BuildBandwidthUsageSeries(
  SBandwidthUsageSeries& outSeries,
  const SSendStampView& stamps,
  const int sampleCount,
  const uint64_t rangeStartUs,
  const uint64_t rangeEndUs,
  const uint64_t averagingWindowUs
)
{
  if (sampleCount <= 0 || averagingWindowUs == 0u) {
    outSeries.ResizeSamples(0u);
    return;
  }

  const uint32_t sampleCountU = static_cast<uint32_t>(sampleCount);
  outSeries.EnsureSampleCount(sampleCountU);

  const uint64_t sampleStepUs = static_cast<uint64_t>(
    static_cast<int64_t>(rangeEndUs - rangeStartUs) / static_cast<int64_t>(sampleCount)
  );
  const float bytesToBytesPerSec = 1000000.0f / static_cast<float>(averagingWindowUs);

  uint32_t addIndex = FindFirstStampAtOrAfter(stamps, rangeStartUs - averagingWindowUs);
  uint32_t removeIndex = addIndex;

  int directionTotals[2]{0, 0};

  const uint32_t stampCount = stamps.StampCount();
  while (addIndex < stampCount && stamps.items[addIndex].timestampUs < rangeStartUs) {
    AddStampToDirectionTotals(stamps.items[addIndex], directionTotals);
    ++addIndex;
  }

  for (uint32_t i = 0; i < sampleCountU; ++i) {
    const uint64_t sliceEndUs = rangeStartUs + static_cast<uint64_t>(i) * sampleStepUs;
    while (addIndex < stampCount && stamps.items[addIndex].timestampUs < sliceEndUs) {
      AddStampToDirectionTotals(stamps.items[addIndex], directionTotals);
      ++addIndex;
    }

    const uint64_t sliceStartUs = sliceEndUs - averagingWindowUs;
    while (removeIndex < addIndex && stamps.items[removeIndex].timestampUs < sliceStartUs) {
      RemoveStampFromDirectionTotals(stamps.items[removeIndex], directionTotals);
      ++removeIndex;
    }

    SBandwidthUsageSample& sample = outSeries.samples[i];
    sample.outboundBytesPerSec = static_cast<float>(directionTotals[0]) * bytesToBytesPerSec;
    sample.inboundBytesPerSec = static_cast<float>(directionTotals[1]) * bytesToBytesPerSec;
  }

  // Preserve binary smoothing behavior: 3-point moving average over interior
  // points, using original-neighbor values while storing back in-place.
  if (outSeries.SampleCount() < 3u) {
    return;
  }

  SBandwidthUsageSample previousOriginal = outSeries.samples[0];
  for (uint32_t i = 1; (i + 1u) < outSeries.SampleCount(); ++i) {
    const SBandwidthUsageSample currentOriginal = outSeries.samples[i];
    const SBandwidthUsageSample nextOriginal = outSeries.samples[i + 1u];

    outSeries.samples[i].outboundBytesPerSec = (
      previousOriginal.outboundBytesPerSec + currentOriginal.outboundBytesPerSec + nextOriginal.outboundBytesPerSec
    ) * (1.0f / 3.0f);
    outSeries.samples[i].inboundBytesPerSec = (
      previousOriginal.inboundBytesPerSec + currentOriginal.inboundBytesPerSec + nextOriginal.inboundBytesPerSec
    ) * (1.0f / 3.0f);

    previousOriginal = currentOriginal;
  }
}

msvc8::string moho::NET_ReadLengthPrefixedArgPayload(gpg::BinaryReader& reader)
{
  uint32_t payloadLen = 0;
  reader.ReadExact(payloadLen);

  msvc8::string payload;
  if (payloadLen != 0) {
    std::vector<char> payloadBuffer(payloadLen);
    reader.Read(payloadBuffer.data(), payloadLen);
    payload.assign(payloadBuffer.data(), payloadLen);
  }

  return payload;
}

SNetCommandArg moho::NET_DecodeSocketArg(gpg::BinaryReader& reader)
{
  uint8_t typeCode = 0;
  reader.ReadExact(typeCode);

  const auto wireType = static_cast<SNetCommandArg::EType>(typeCode);
  switch (wireType) {
  case SNetCommandArg::NETARG_Num: {
    int32_t value = 0;
    reader.ReadExact(value);
    return SNetCommandArg(value);
  }
  case SNetCommandArg::NETARG_String:
    return SNetCommandArg(NET_ReadLengthPrefixedArgPayload(reader));
  case SNetCommandArg::NETARG_Data: {
    SNetCommandArg arg(NET_ReadLengthPrefixedArgPayload(reader));
    arg.mType = SNetCommandArg::NETARG_Data;
    return arg;
  }
  default:
    throw std::runtime_error("invalid arg typecode");
  }
}

/**
 * Address: 0x0047F5A0 (FUN_0047F5A0, NET_Init)
 *
 * What it does:
 * Registers net convars and lazily initializes Winsock (WSA 1.1) once.
 */
bool moho::NET_Init()
{
  NET_RegisterConVarDefinitions();

#if defined(_WIN32)
  static bool sWinsockInitialized = false;
  if (!sWinsockInitialized) {
    WSAData wsaData;
    if (::WSAStartup(MAKEWORD(1, 1), &wsaData)) {
      gpg::Logf("Net_Init(): WSAStartup failed: %s", NET_GetWinsockErrorString());
    } else {
      sWinsockInitialized = true;
    }
  }
  return sWinsockInitialized;
#else
  return false;
#endif
}

/**
 * Address: 0x0047F540 (FUN_0047F540, NETMAIL_SendError)
 *
 * What it does:
 * Legacy no-op reporting hook kept for binary/API parity.
 */
void moho::NETMAIL_SendError(const char* const title, const char* const message)
{
  (void)title;
  (void)message;
}

/**
 * Address: 0x0047EBF0 (FUN_0047EBF0, NET_MakeConnector)
 *
 * What it does:
 * Dispatches protocol-specific connector creation for `port`.
 * `kTcp`/`kUdp` forward into protocol-specific factory paths and all other
 * values return a null-object connector instance.
 */
INetConnector* moho::NET_MakeConnector(
  const u_short port,
  const ENetProtocolType protocol,
  const boost::weak_ptr<INetNATTraversalProvider>& natTraversalProvider
)
{
  switch (protocol) {
  case ENetProtocolType::kTcp:
    return NET_MakeTCPConnector(port);
  case ENetProtocolType::kUdp:
    return NET_MakeUDPConnector(port, natTraversalProvider);
  case ENetProtocolType::kNone:
  default:
    return new (std::nothrow) CNetNullConnector();
  }
}

/**
 * Address: 0x0048BBE0 (FUN_0048BBE0)
 *
 * What it does:
 * Creates a non-blocking UDP socket bound to `port`, then constructs
 * `CNetUDPConnector`; returns null on any setup failure.
 */
INetConnector* moho::NET_MakeUDPConnector(const u_short port, boost::weak_ptr<INetNATTraversalProvider> prov)
{
  if (!NET_Init()) {
    return nullptr;
  }
  SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) {
    if (net_DebugLevel != 0) {
      gpg::Logf("NET_MakeUDPConnector: socket() failed: %s", NET_GetWinsockErrorString());
    }
    return nullptr;
  }
  u_long argp = 1;
  if (::ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR) {
    if (net_DebugLevel != 0) {
      gpg::Logf("NET_MakeUDPConnector: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
    }
    ::closesocket(sock);
    return nullptr;
  }
  sockaddr_in name;
  name.sin_family = AF_INET;
  name.sin_port = ::htons(port);
  name.sin_addr.S_un.S_addr = ::htonl(0);
  if (::bind(sock, (SOCKADDR*)&name, sizeof(name)) == SOCKET_ERROR) {
    if (net_DebugLevel != 0) {
      gpg::Logf("NET_MakeUDPConnector: bind(%d) failed: %s", port, NET_GetWinsockErrorString());
    }
    ::closesocket(sock);
    return nullptr;
  }
  return new CNetUDPConnector{sock, prov};
}

/**
 * Address: 0x004849A0 (FUN_004849A0)
 *
 * What it does:
 * Creates non-blocking TCP listening connector bound to `port`.
 */
INetConnector* moho::NET_MakeTCPConnector(const u_short port)
{
  if (!NET_Init()) {
    return nullptr;
  }

  const SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    gpg::Logf("NET_MakeConnector: socket() failed: %s", NET_GetWinsockErrorString());
    return nullptr;
  }

  u_long nonBlocking = 1;
  if (::ioctlsocket(sock, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = ::htons(port);
  name.sin_addr.s_addr = ::htonl(0);
  if (::bind(sock, reinterpret_cast<const sockaddr*>(&name), sizeof(name)) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: bind(%d) failed: %s", port, NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  if (::listen(sock, SOMAXCONN) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: listen() failed: %s", NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  const auto connector = new (std::nothrow) CNetTCPConnector(sock);
  if (!connector) {
    // FA/Moho behavior: allocation failure returns null without closing opened socket.
    return nullptr;
  }
  return connector;
}

/**
 * Address: 0x0047F990 (FUN_0047F990)
 *
 * What it does:
 * Returns process-global host-name cache manager, lazily initialized once.
 */
CHostManager* moho::NET_GetHostManager()
{
  static CHostManager manager;
  return &manager;
}

/**
 * Address: 0x0047FEE0 (FUN_0047FEE0)
 *
 * uint32_t
 *
 * What it does:
 * Resolves/caches a host-order IPv4 address through the global CHostManager cache.
 */
msvc8::string moho::NET_GetHostName(const u_long address)
{
  const auto manager = NET_GetHostManager();
  return manager->GetHostName(address);
}

/**
 * Address: 0x0047F5F0 (FUN_0047F5F0, NET_GetWinsockErrorString)
 *
 * What it does:
 * Maps current `WSAGetLastError()` code to stable symbolic string.
 */
const char* moho::NET_GetWinsockErrorString() noexcept
{
#if defined(_WIN32)
  const int e = ::WSAGetLastError();
  if (e == 0) {
    return "NOERROR";
  }

  // DNS/host resolution extended codes first (match original control flow)
  switch (e) {
  case WSAHOST_NOT_FOUND:
    return "WSAHOST_NOT_FOUND"; // 11001
  case WSATRY_AGAIN:
    return "WSATRY_AGAIN"; // 11002
  case WSANO_RECOVERY:
    return "WSANO_RECOVERY"; // 11003
  case WSANO_DATA:
    return "WSANO_DATA"; // 11004
  }

  // Core Winsock error set mirrored from the original switch
  switch (e) {
  case WSAEINTR:
    return "WSAEINTR"; // 10004 (0x2714)
  case WSAEBADF:
    return "WSAEBADF"; // 10009 (0x2719)
  case WSAEACCES:
    return "WSAEACCES"; // 10013 (0x271D)
  case WSAEFAULT:
    return "WSAEFAULT"; // 10014 (0x271E)
  case WSAEINVAL:
    return "WSAEINVAL"; // 10022 (0x2726)
  case WSAEMFILE:
    return "WSAEMFILE"; // 10024 (0x2728)
  case WSAEWOULDBLOCK:
    return "WSAEWOULDBLOCK"; // 10035 (0x2733)
  case WSAEINPROGRESS:
    return "WSAEINPROGRESS"; // 10036 (0x2734)
  case WSAEALREADY:
    return "WSAEALREADY"; // 10037 (0x2735)
  case WSAENOTSOCK:
    return "WSAENOTSOCK"; // 10038 (0x2736)
  case WSAEDESTADDRREQ:
    return "WSAEDESTADDRREQ"; // 10039 (0x2737)
  case WSAEMSGSIZE:
    return "WSAEMSGSIZE"; // 10040 (0x2738)
  case WSAEPROTOTYPE:
    return "WSAEPROTOTYPE"; // 10041 (0x2739)
  case WSAENOPROTOOPT:
    return "WSAENOPROTOOPT"; // 10042 (0x273A)
  case WSAEPROTONOSUPPORT:
    return "WSAEPROTONOSUPPORT"; // 10043 (0x273B)
  case WSAESOCKTNOSUPPORT:
    return "WSAESOCKTNOSUPPORT"; // 10044 (0x273C)
  case WSAEOPNOTSUPP:
    return "WSAEOPNOTSUPP"; // 10045 (0x273D)
  case WSAEPFNOSUPPORT:
    return "WSAEPFNOSUPPORT"; // 10046 (0x273E)
  case WSAEAFNOSUPPORT:
    return "WSAEAFNOSUPPORT"; // 10047 (0x273F)
  case WSAEADDRINUSE:
    return "WSAEADDRINUSE"; // 10048 (0x2740)
  case WSAEADDRNOTAVAIL:
    return "WSAEADDRNOTAVAIL"; // 10049 (0x2741)
  case WSAENETDOWN:
    return "WSAENETDOWN"; // 10050 (0x2742)
  case WSAENETUNREACH:
    return "WSAENETUNREACH"; // 10051 (0x2743)
  case WSAENETRESET:
    return "WSAENETRESET"; // 10052 (0x2744)
  case WSAECONNABORTED:
    return "WSAECONNABORTED"; // 10053 (0x2745)
  case WSAECONNRESET:
    return "WSAECONNRESET"; // 10054 (0x2746)
  case WSAENOBUFS:
    return "WSAENOBUFS"; // 10055 (0x2747)
  case WSAEISCONN:
    return "WSAEISCONN"; // 10056 (0x2748)
  case WSAENOTCONN:
    return "WSAENOTCONN"; // 10057 (0x2749)
  case WSAESHUTDOWN:
    return "WSAESHUTDOWN"; // 10058 (0x274A)
  case WSAETOOMANYREFS:
    return "WSAETOOMANYREFS"; // 10059 (0x274B)
  case WSAETIMEDOUT:
    return "WSAETIMEDOUT"; // 10060 (0x274C)
  case WSAECONNREFUSED:
    return "WSAECONNREFUSED"; // 10061 (0x274D)
  case WSAELOOP:
    return "WSAELOOP"; // 10062 (0x274E)
  case WSAENAMETOOLONG:
    return "WSAENAMETOOLONG"; // 10063 (0x274F)
  case WSAEHOSTDOWN:
    return "WSAEHOSTDOWN"; // 10064 (0x2750)
  case WSAEHOSTUNREACH:
    return "WSAEHOSTUNREACH"; // 10065 (0x2751)
  case WSAENOTEMPTY:
    return "WSAENOTEMPTY"; // 10066 (0x2752)
  case WSAEPROCLIM:
    return "WSAEPROCLIM"; // 10067 (0x2753)
  case WSAEUSERS:
    return "WSAEUSERS"; // 10068 (0x2754)
  case WSAEDQUOT:
    return "WSAEDQUOT"; // 10069 (0x2755)
  case WSAESTALE:
    return "WSAESTALE"; // 10070 (0x2756)
  case WSAEREMOTE:
    return "WSAEREMOTE"; // 10071 (0x2757)
  case WSASYSNOTREADY:
    return "WSASYSNOTREADY"; // 10091 (0x276B)
  case WSAVERNOTSUPPORTED:
    return "WSAVERNOTSUPPORTED"; // 10092 (0x276C)
  case WSANOTINITIALISED:
    return "WSANOTINITIALISED"; // 10093 (0x276D)
  case WSAEDISCON:
    return "WSAEDISCON"; // 10101 (0x2775)
  default:
    return "UNKNOWN";
  }
#else
  // Non-Windows build: no Winsock -> stable stub.
  return "NO_WINSOCK";
#endif
}

/**
 * Address: 0x004801C0 (FUN_004801C0)
 * Mangled: ?NET_GetDottedOctetFromUInt32@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
 *
 * uint32_t
 *
 * What it does:
 * Formats host-order IPv4 as "A.B.C.D".
 */
msvc8::string moho::NET_GetDottedOctetFromUInt32(const uint32_t number)
{
  return gpg::STR_Printf(
    "%d.%d.%d.%d", (number >> 24) & 0xFF, (number >> 16) & 0xFF, (number >> 8) & 0xFF, number & 0xFF
  );
}

/**
 * Address: 0x00480200 (FUN_00480200)
 * Mangled: ?NET_GetUInt32FromDottedOcted@Moho@@YAIV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
 *
 * msvc8::string
 *
 * What it does:
 * Splits dotted IPv4 text by '.' and folds tokens using (acc << 8) | atoi(token).
 */
uint32_t moho::NET_GetUInt32FromDottedOcted(const msvc8::string& host)
{
  uint32_t value = 0;
  const char* cursor = host.c_str();
  msvc8::string token;

  while (gpg::STR_GetToken(cursor, ".", token)) {
    value = (value << 8) | static_cast<uint32_t>(std::atoi(token.c_str()));
  }

  return value;
}

/**
 * Address: 0x0047EC90 (FUN_0047EC90, NET_GetProtocolName)
 *
 * What it does:
 * Converts `ENetProtocolType` to canonical display text.
 * Unsupported enum values throw `std::domain_error`.
 */
msvc8::string moho::NET_GetProtocolName(const ENetProtocolType protocol)
{
  switch (protocol) {
  case ENetProtocolType::kNone:
    return msvc8::string("None");
  case ENetProtocolType::kTcp:
    return msvc8::string("TCP");
  case ENetProtocolType::kUdp:
    return msvc8::string("UDP");
  default:
    break;
  }

  const msvc8::string msg = gpg::STR_Printf("invalid protocol (%d)", static_cast<int32_t>(protocol));
  throw std::domain_error(msg.c_str());
}

/**
 * Address: 0x0047ED50 (FUN_0047ED50, NET_ProtocolFromString)
 *
 * What it does:
 * Parses case-insensitive protocol names into enum values.
 * Unsupported values throw `std::domain_error`.
 */
ENetProtocolType moho::NET_ProtocolFromString(const char* str)
{
  if (_stricmp(str, "None") == 0) {
    return ENetProtocolType::kNone;
  }
  if (_stricmp(str, "TCP") == 0) {
    return ENetProtocolType::kTcp;
  }
  if (_stricmp(str, "UDP") == 0) {
    return ENetProtocolType::kUdp;
  }

  const msvc8::string msg = gpg::STR_Printf("invalid protocol (\"%s\")", str);
  throw std::domain_error(msg.c_str());
}

/**
 * Address: 0x00BC4690 (FUN_00BC4690, register_sProtocols)
 *
 * What it does:
 * Registers process-exit cleanup for startup-owned protocol vector storage.
 */
void moho::register_sProtocols()
{
  (void)std::atexit(&cleanup_sProtocols);
}
