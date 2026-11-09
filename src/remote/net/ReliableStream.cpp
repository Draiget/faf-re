#include "remote/net/ReliableStream.h"

#include <algorithm>
#include <iterator>

namespace faf::remote::net
{
  namespace
  {
    // Consumed bytes are dropped from the front of a buffer in steps of at least this.
    constexpr std::size_t kCompactStep = 64 * 1024;

    void WriteChunk(
      ByteWriter& out, const std::uint64_t offset, const std::uint8_t* const data, const std::size_t size
    )
    {
      out.Byte(kChunkReliable);
      out.Varint(offset);
      out.Varint(size);
      out.Bytes(data, size);
    }
  } // namespace

  // --- RangeSet -------------------------------------------------------------------------

  void RangeSet::Add(std::uint64_t begin, std::uint64_t end)
  {
    if (begin >= end) {
      return;
    }
    auto it = mRanges.upper_bound(begin);
    if (it != mRanges.begin()) {
      const auto previous = std::prev(it);
      if (previous->second >= begin) {
        begin = previous->first;
        end = std::max(end, previous->second);
        mRanges.erase(previous);
      }
    }
    while (it != mRanges.end() && it->first <= end) {
      end = std::max(end, it->second);
      it = mRanges.erase(it);
    }
    mRanges.emplace(begin, end);
  }

  void RangeSet::Remove(const std::uint64_t begin, const std::uint64_t end)
  {
    if (begin >= end) {
      return;
    }
    auto it = mRanges.upper_bound(begin);
    if (it != mRanges.begin()) {
      const auto previous = std::prev(it);
      if (previous->second > begin) {
        const std::uint64_t first = previous->first;
        const std::uint64_t last = previous->second;
        mRanges.erase(previous);
        if (first < begin) {
          mRanges.emplace(first, begin);
        }
        if (last > end) {
          mRanges.emplace(end, last);
        }
      }
    }
    it = mRanges.lower_bound(begin);
    while (it != mRanges.end() && it->first < end) {
      const std::uint64_t last = it->second;
      it = mRanges.erase(it);
      if (last > end) {
        mRanges.emplace(end, last);
        break;
      }
    }
  }

  void RangeSet::Missing(const std::uint64_t begin, const std::uint64_t end, std::vector<StreamRange>& out) const
  {
    std::uint64_t cursor = begin;
    auto it = mRanges.upper_bound(begin);
    if (it != mRanges.begin()) {
      cursor = std::max(cursor, std::prev(it)->second);
    }
    while (cursor < end) {
      if (it == mRanges.end() || it->first >= end) {
        out.push_back({cursor, end});
        break;
      }
      if (it->first > cursor) {
        out.push_back({cursor, it->first});
      }
      cursor = std::max(cursor, it->second);
      ++it;
    }
  }

  std::uint64_t RangeSet::PrefixEnd() const noexcept
  {
    return (mRanges.empty() || mRanges.begin()->first != 0) ? 0 : mRanges.begin()->second;
  }

  StreamRange RangeSet::First() const noexcept
  {
    return mRanges.empty() ? StreamRange{} : StreamRange{mRanges.begin()->first, mRanges.begin()->second};
  }

  // --- ReliableSender -------------------------------------------------------------------

  bool ReliableSender::Queue(const std::uint8_t* const data, const std::size_t size)
  {
    if (size > mMaxMessage) {
      return false;
    }
    ByteWriter out(mBuffer);
    out.Varint(size);
    out.Bytes(data, size);
    mEnd = mBase + mBuffer.size();
    return true;
  }

  void ReliableSender::Write(ByteWriter& out, std::size_t budget, std::vector<StreamRange>& sent)
  {
    // A chunk's header: type, offset and a length no larger than the budget.
    const auto headerSize = [&](const std::uint64_t offset) {
      return 1 + VarintSize(offset) + VarintSize(budget);
    };

    while (!mLost.Empty()) {
      const StreamRange range = mLost.First();
      const std::size_t header = headerSize(range.begin);
      if (budget <= header) {
        return;
      }
      const std::uint64_t size = std::min<std::uint64_t>(range.end - range.begin, budget - header);
      WriteChunk(out, range.begin, &mBuffer[static_cast<std::size_t>(range.begin - mBase)], static_cast<std::size_t>(size));
      mLost.Remove(range.begin, range.begin + size);
      sent.push_back({range.begin, range.begin + size});
      mBytesResent += size;
      budget -= header + static_cast<std::size_t>(size);
    }

    const std::uint64_t limit = std::min<std::uint64_t>(mEnd, mAcked.PrefixEnd() + mMaxInFlight);
    while (mNextNew < limit) {
      const std::size_t header = headerSize(mNextNew);
      if (budget <= header) {
        return;
      }
      const std::uint64_t size = std::min<std::uint64_t>(limit - mNextNew, budget - header);
      WriteChunk(out, mNextNew, &mBuffer[static_cast<std::size_t>(mNextNew - mBase)], static_cast<std::size_t>(size));
      sent.push_back({mNextNew, mNextNew + size});
      mNextNew += size;
      budget -= header + static_cast<std::size_t>(size);
    }
  }

  bool ReliableSender::HasPending() const noexcept
  {
    return !mLost.Empty() || mNextNew < std::min<std::uint64_t>(mEnd, mAcked.PrefixEnd() + mMaxInFlight);
  }

  void ReliableSender::OnAcked(const std::vector<StreamRange>& ranges)
  {
    for (const StreamRange& range : ranges) {
      mAcked.Add(range.begin, range.end);
      mLost.Remove(range.begin, range.end);
    }
    Compact();
  }

  void ReliableSender::OnLost(const std::vector<StreamRange>& ranges)
  {
    std::vector<StreamRange> missing;
    for (const StreamRange& range : ranges) {
      missing.clear();
      mAcked.Missing(range.begin, range.end, missing);
      for (const StreamRange& part : missing) {
        mLost.Add(part.begin, part.end);
      }
    }
  }

  void ReliableSender::Compact()
  {
    const std::uint64_t prefix = mAcked.PrefixEnd();
    const std::uint64_t consumed = prefix - mBase;
    // Moving what's left costs as much as there is left, so a long queue waits until half of it is gone.
    const std::uint64_t left = mEnd - prefix;
    if ((consumed >= kCompactStep && consumed >= left) || (consumed > 0 && prefix == mEnd)) {
      mBuffer.erase(mBuffer.begin(), mBuffer.begin() + static_cast<std::ptrdiff_t>(consumed));
      mBase = prefix;
    }
  }

  // --- ReliableReceiver -----------------------------------------------------------------

  bool ReliableReceiver::OnFragment(std::uint64_t offset, const std::uint8_t* data, std::size_t size)
  {
    if (size == 0) {
      return true;
    }
    if (offset > UINT64_MAX - size) {
      return false;
    }
    const std::uint64_t end = offset + size;
    if (end <= mDelivered || end > mDelivered + mWindow) {
      return true;
    }
    if (offset < mDelivered) {
      const auto skip = static_cast<std::size_t>(mDelivered - offset);
      data += skip;
      size -= skip;
      offset = mDelivered;
    }

    if (offset == mDelivered) {
      if (!Append(data, size)) {
        return false;
      }
      while (!mHeld.empty() && mHeld.begin()->first <= mDelivered) {
        const auto it = mHeld.begin();
        const std::vector<std::uint8_t>& bytes = it->second;
        const std::uint64_t heldEnd = it->first + bytes.size();
        if (heldEnd > mDelivered) {
          const auto skip = static_cast<std::size_t>(mDelivered - it->first);
          if (!Append(bytes.data() + skip, bytes.size() - skip)) {
            return false;
          }
        }
        mHeldBytes -= bytes.size();
        mHeld.erase(it);
      }
      return true;
    }

    // A gap before it: hold the parts no held fragment covers yet.
    std::uint64_t cursor = offset;
    auto it = mHeld.upper_bound(offset);
    if (it != mHeld.begin()) {
      const auto previous = std::prev(it);
      cursor = std::max(cursor, previous->first + previous->second.size());
    }
    while (cursor < end) {
      if (it != mHeld.end() && it->first <= cursor) {
        cursor = std::max(cursor, it->first + it->second.size());
        ++it;
        continue;
      }
      const std::uint64_t stop = (it == mHeld.end()) ? end : std::min(end, it->first);
      const std::uint8_t* const from = data + static_cast<std::size_t>(cursor - offset);
      mHeld.emplace_hint(it, cursor, std::vector<std::uint8_t>(from, from + static_cast<std::size_t>(stop - cursor)));
      mHeldBytes += static_cast<std::size_t>(stop - cursor);
      cursor = stop;
    }
    return true;
  }

  bool ReliableReceiver::Append(const std::uint8_t* const data, const std::size_t size)
  {
    mAssembly.insert(mAssembly.end(), data, data + size);
    mDelivered += size;
    return ParseMessages();
  }

  bool ReliableReceiver::ParseMessages()
  {
    for (;;) {
      const std::size_t available = mAssembly.size() - mAssemblyPos;
      std::uint64_t length = 0;
      std::size_t header = 0;
      bool complete = false;
      for (int shift = 0; header < available && header < 10; shift += 7) {
        const std::uint8_t byte = mAssembly[mAssemblyPos + header++];
        length |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
          complete = true;
          break;
        }
      }
      if (!complete) {
        if (header == 10) {
          return false;  // a length longer than any varint
        }
        break;
      }
      if (length > mMaxMessage) {
        return false;
      }
      if (available - header < length) {
        break;
      }
      const std::uint8_t* const begin = mAssembly.data() + mAssemblyPos + header;
      mMessages.emplace_back(begin, begin + static_cast<std::size_t>(length));
      mAssemblyPos += header + static_cast<std::size_t>(length);
    }
    if (mAssemblyPos >= kCompactStep || (mAssemblyPos > 0 && mAssemblyPos == mAssembly.size())) {
      mAssembly.erase(mAssembly.begin(), mAssembly.begin() + static_cast<std::ptrdiff_t>(mAssemblyPos));
      mAssemblyPos = 0;
    }
    return true;
  }

  bool ReliableReceiver::Take(std::vector<std::uint8_t>& out)
  {
    if (mMessages.empty()) {
      return false;
    }
    out = std::move(mMessages.front());
    mMessages.pop_front();
    return true;
  }
} // namespace faf::remote::net
